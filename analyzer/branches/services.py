"""Ветка анализа сетевых сервисов (TCP/UDP) без привязки к протоколу.

Для proprietary-трафика, который tshark не разбирает (циклическая
телеметрия, сердцебиения, обмен СКАДА с собственными шлюзами), ветка
строит статистику по сервисам: пары клиент→сервер, объёмы в обе
стороны, периодику запросов (медианный интервал и регулярность),
ретрансляции, «молчащие» и односторонние потоки — и формирует
рекомендации. Служебный трафик (ARP/STP/LLDP/NTP/DHCP…) учитывается
отдельно как фоновый шум.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Config
from ..tshark_runner import find_tshark, stream_fields
from ..report import components as C
from .base import (
    BaseBranch,
    BranchResult,
    KpiItem,
    ProgressCb,
    Recommendation,
    Reservoir,
    Section,
    epoch_to_str,
    percentile,
    sort_recommendations,
    to_float,
    to_int,
    truthy,
)


@dataclass
class ServiceStats:
    """Агрегат по сервису: (ip сервера, порт сервиса)."""

    port: int
    clients: set = field(default_factory=set)
    streams: int = 0                # TCP: число потоков
    syn: int = 0                    # TCP: попыток подключения
    req_pkts: int = 0               # сообщений клиент -> сервер (с данными)
    resp_pkts: int = 0              # сообщений сервер -> клиент
    req_bytes: int = 0
    resp_bytes: int = 0
    tiny_req: int = 0               # «сердцебиений» клиент -> сервер
    tiny_resp: int = 0
    retrans: int = 0
    silent_streams: int = 0         # потоков без единого байта ответа
    one_way_streams: int = 0        # потоков с перекосом направления ≥ порога
    intervals: Reservoir = field(default_factory=lambda: Reservoir(0))
    # UDP-переменные
    udp_pairs: int = 0


@dataclass
class GeneralStats:
    total_packets: int = 0
    total_bytes: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    ip_pkts: Counter = field(default_factory=Counter)
    ip_bytes_tx: Counter = field(default_factory=Counter)
    ip_bytes_rx: Counter = field(default_factory=Counter)
    proto_frames: Counter = field(default_factory=Counter)   # семейство -> кадров
    syn_total: int = 0
    rst_total: int = 0

    @property
    def duration(self) -> float:
        if self.first_ts is not None and self.last_ts is not None:
            return max(self.last_ts - self.first_ts, 0.0)
        return 0.0


# Семейства служебного трафика: ищем токены в frame.protocols
PROTO_WATCH = {
    "arp": "ARP",
    "stp": "STP (spanning tree)",
    "lldp": "LLDP",
    "igmp": "IGMP",
    "nbns": "NetBIOS Name Service",
    "browser": "SMB Browser",
    "ntp": "NTP",
    "dhcp": "DHCP",
    "bootp": "DHCP (bootp)",
    "mdns": "mDNS",
    "ssdp": "SSDP",
    "llc": "LLC (не-IP кадры)",
}


def cyclic_label(cv: float | None, cfg: Config) -> str:
    """Человекочитаемая оценка регулярности по коэффициенту вариации."""
    if cv is None:
        return "&mdash;"
    if cv < cfg.svc_cyclic_cv_strict:
        return f"строгий цикл (CV={cv:.2f})"
    if cv < cfg.svc_cyclic_cv_moderate:
        return f"умеренный (CV={cv:.2f})"
    return f"нерегулярный (CV={cv:.2f})"


def cv_of(values) -> float | None:
    vals = list(values)
    if len(vals) < 2:
        return None
    mean = sum(vals) / len(vals)
    if mean <= 0:
        return None
    var = sum((v - mean) ** 2 for v in vals) / (len(vals) - 1)
    return math.sqrt(var) / mean


class ServicesAnalyzer(BaseBranch):
    name = "services"
    title = "Анализ сетевых сервисов (TCP/UDP)"
    description = (
        "Трафик без привязки к протоколу: сервисы TCP/UDP, объёмы в обе "
        "стороны, периодика запросов, сердцебиения, ретрансляции, "
        "молчащие и односторонние потоки, служебный шум сети."
    )

    def analyze(
        self,
        pcap_path: Path,
        cfg: Config,
        progress: ProgressCb = lambda msg, pct=None: None,
        tshark_bin: str | None = None,
    ) -> BranchResult:
        self.cfg = cfg
        self.tshark = find_tshark(tshark_bin)
        self.pcap = pcap_path
        self.progress = progress
        self.pcap_str = str(pcap_path)

        result = BranchResult(
            branch_name=self.name,
            branch_title=self.title,
            pcap_path=pcap_path,
            pcap_size_bytes=pcap_path.stat().st_size,
        )
        self.sha256_short = self._sha256_short(pcap_path)

        progress("Проход 1/2: общий обзор и потоки…", pct=15)
        gen = self._pass_general()
        result.capture_start_ts = gen.first_ts

        # Цвета серверов — по узлам, у которых есть TCP-сервисы
        self._set_servers(ip for (ip, _port) in self._tcp_services)

        progress("Проход 2/2: агрегация сервисов…", pct=70)

        result.kpi = self._build_kpi(gen)
        result.sections = self._build_sections(gen)
        result.recommendations = self._build_recommendations(gen)
        result.server_colors = dict(self._srv_colors)
        return result

    # -- Проход 1: всё за один проход ----------------------------------------

    FIELDS_GENERAL = [
        "frame.time_epoch", "frame.len", "frame.protocols",
        "ip.src", "ip.dst",
        "tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.len",
        "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.reset", "tcp.flags.fin",
        "tcp.analysis.retransmission",
        "udp.srcport", "udp.dstport",
    ]

    def _pass_general(self) -> GeneralStats:
        g = GeneralStats()
        watch = set(PROTO_WATCH)
        streams: dict[str, dict] = {}
        udp_last: dict[tuple, float] = {}
        self._tcp_services: dict[tuple, ServiceStats] = {}
        self._udp_services: dict[tuple, ServiceStats] = {}
        tcp_svcs = self._tcp_services
        udp_svcs = self._udp_services
        tiny_max = self.cfg.svc_heartbeat_max_bytes

        def tcp_svc(ip: str, port: int) -> ServiceStats:
            st = tcp_svcs.get((ip, port))
            if st is None:
                st = tcp_svcs[(ip, port)] = ServiceStats(
                    port=port,
                    intervals=Reservoir(self.cfg.max_intervals_per_target))
            return st

        def udp_svc(ip: str, port: int) -> ServiceStats:
            st = udp_svcs.get((ip, port))
            if st is None:
                st = udp_svcs[(ip, port)] = ServiceStats(
                    port=port,
                    intervals=Reservoir(self.cfg.max_intervals_per_target))
            return st

        for r in stream_fields(self.tshark, self.pcap_str,
                               self.FIELDS_GENERAL):
            g.total_packets += 1
            plen = to_int(r.get("frame.len"), 0)
            g.total_bytes += plen
            ts = to_float(r.get("frame.time_epoch"))
            if ts is not None:
                if g.first_ts is None:
                    g.first_ts = ts
                g.last_ts = ts
            src = r.get("ip.src", "")
            dst = r.get("ip.dst", "")
            if src:
                g.ip_pkts[src] += 1
                g.ip_bytes_tx[src] += plen
            if dst:
                g.ip_bytes_rx[dst] += plen

            # семейства протоколов из frame.protocols
            protos = set((r.get("frame.protocols") or "").lower().split(":"))
            for fam in protos & watch:
                g.proto_frames[fam] += 1

            sport = to_int(r.get("tcp.srcport"), -1)
            dport = to_int(r.get("tcp.dstport"), -1)
            usport = to_int(r.get("udp.srcport"), -1)
            udport = to_int(r.get("udp.dstport"), -1)
            tlen = max(to_int(r.get("tcp.len"), 0), 0)

            if sport >= 0 and dport >= 0:
                is_syn = truthy(r.get("tcp.flags.syn", ""))
                if truthy(r.get("tcp.flags.reset", "")):
                    g.rst_total += 1
                st_id = r.get("tcp.stream", "")
                if is_syn and not truthy(r.get("tcp.flags.ack", "")):
                    g.syn_total += 1
                # роли: сервис — меньший порт; при равных портах клиентом
                # считается отправитель первого пакета потока
                # сервис — сторона с меньшим портом (102 < 49xxx);
                # при равных портах клиентом считается отправитель,
                # видимый первым в потоке
                if sport > dport:
                    client, server, svc_port = src, dst, dport
                elif sport < dport:
                    client, server, svc_port = dst, src, sport
                else:
                    client, server, svc_port = src, dst, sport

                info = None
                if st_id != "":
                    info = streams.setdefault(st_id, {
                        "client": client, "server": server,
                        "port": svc_port, "first": ts, "last": ts,
                        "req_pkts": 0, "req_bytes": 0,
                        "resp_pkts": 0, "resp_bytes": 0,
                        "retrans": 0, "last_c2s": None,
                        "syn": False,
                    })
                    if ts is not None:
                        if info["first"] is None or ts < info["first"]:
                            info["first"] = ts
                        info["last"] = ts
                if is_syn and not truthy(r.get("tcp.flags.ack", "")) \
                        and info is not None:
                    info["syn"] = True

                svc = tcp_svc(server, svc_port)
                svc.clients.add(client)

                if info is not None:
                    if src == info["client"]:
                        if tlen > 0:
                            info["req_pkts"] += 1
                            info["req_bytes"] += tlen
                            if tlen <= tiny_max:
                                svc.tiny_req += 1
                            last = info["last_c2s"]
                            if ts is not None:
                                if last is not None and 0 < ts - last <= 3600:
                                    svc.intervals.add(ts - last)
                                info["last_c2s"] = ts
                    elif tlen > 0:
                        info["resp_pkts"] += 1
                        info["resp_bytes"] += tlen
                        if tlen <= tiny_max:
                            svc.tiny_resp += 1
                    if truthy(r.get("tcp.analysis.retransmission", "")):
                        info["retrans"] += 1
                        svc.retrans += 1

            elif usport >= 0 and udport >= 0:
                # сервис — меньший порт (как у NTP 123 <-> эфемерный)
                if usport <= udport:
                    server, svc_port, client = src, usport, dst
                else:
                    server, svc_port, client = dst, udport, src
                svc = udp_svc(server, svc_port)
                svc.clients.add(client)
                svc.req_pkts += 1
                svc.req_bytes += plen
                pair_last_key = (src, dst, usport, udport)
                if ts is not None:
                    last = udp_last.get(pair_last_key)
                    if last is not None and 0 < ts - last <= 3600:
                        svc.intervals.add(ts - last)
                    udp_last[pair_last_key] = ts
                    if len(udp_last) > 50000:
                        udp_last.clear()

        # переносим накопленное по потокам в сервисы
        by_stream: dict[tuple, list[dict]] = {}
        for info in streams.values():
            key = (info["server"], info["port"])
            by_stream.setdefault(key, []).append(info)
        for key, lst in by_stream.items():
            svc = tcp_svc(*key)
            svc.streams = len(lst)
            svc.syn = sum(1 for i in lst if i["syn"])
            svc.req_pkts = sum(i["req_pkts"] for i in lst)
            svc.resp_pkts = sum(i["resp_pkts"] for i in lst)
            svc.req_bytes = sum(i["req_bytes"] for i in lst)
            svc.resp_bytes = sum(i["resp_bytes"] for i in lst)
            svc.retrans = sum(i["retrans"] for i in lst)
            svc.silent_streams = sum(
                1 for i in lst if i["resp_bytes"] == 0)
            kb = self.cfg.svc_one_way_min_kb << 10
            # односторонний поток: мажорное направление ≥ порога объёма,
            # а обратное — не больше (100 − pct)% от него
            keep_share = 100.0 - self.cfg.svc_one_way_pct
            svc.one_way_streams = sum(
                1 for i in lst
                if max(i["req_bytes"], i["resp_bytes"]) >= kb
                and min(i["req_bytes"], i["resp_bytes"]) * 100.0
                <= keep_share * max(max(i["req_bytes"], i["resp_bytes"]), 1))

        return g

    # -- KPI ------------------------------------------------------------------

    def _build_kpi(self, gen: GeneralStats) -> list[KpiItem]:
        dur = gen.duration
        tcp_ports = sorted({port for (_ip, port) in self._tcp_services})
        udp_ports = sorted({port for (_ip, port) in self._udp_services})
        noise = sum(cnt for fam, cnt in gen.proto_frames.items()
                    if fam in ("arp", "stp", "lldp", "igmp"))
        all_iv = sorted(iv for svc in list(self._tcp_services.values())
                        + list(self._udp_services.values())
                        for iv in svc.intervals)
        med_iv = percentile(all_iv, 50)
        return [
            KpiItem("Длительность захвата", C.fmt_dur(dur)),
            KpiItem("Всего пакетов", C.fmt_int(gen.total_packets),
                    f"{C.fmt_bytes(gen.total_bytes)} трафика"),
            KpiItem("Узлов активных", C.fmt_int(len(gen.ip_pkts))),
            KpiItem("TCP-сервисов", C.fmt_int(len(tcp_ports)),
                    ", ".join(f":{p}" for p in tcp_ports[:6])
                    + ("…" if len(tcp_ports) > 6 else "")),
            KpiItem("UDP-сервисов", C.fmt_int(len(udp_ports)),
                    ", ".join(f":{p}" for p in udp_ports[:6])
                    + ("…" if len(udp_ports) > 6 else "")),
            KpiItem("Соединений (потоков)",
                    C.fmt_int(sum(s.streams for s in
                                  self._tcp_services.values())),
                    f"SYN-попыток: {C.fmt_int(gen.syn_total)}"),
            KpiItem("Медиана интервала запросов",
                    f"{C.fmt_ms(med_iv)} мс" if med_iv is not None
                    else "&mdash;",
                    "по всем сервисам с периодикой"),
            KpiItem("Ретрансляций TCP",
                    C.fmt_int(sum(s.retrans for s in
                                  self._tcp_services.values()))),
            KpiItem("Служебных кадров", C.fmt_int(noise),
                    "ARP/STP/LLDP/IGMP"),
        ]

    # -- Секции ---------------------------------------------------------------

    def _build_sections(self, gen: GeneralStats) -> list[Section]:
        sections = [self._sec_summary(gen)]
        sections.append(self._sec_tcp(gen))
        sections.append(self._sec_periodicity(gen))
        sections.append(self._sec_udp(gen))
        sections.append(self._sec_noise(gen))
        return sections

    def _sec_summary(self, gen: GeneralStats) -> Section:
        rows = [
            ["Файл", C.esc(self.pcap.name)],
            ["Размер файла", C.fmt_bytes(self.pcap.stat().st_size)],
            ["SHA-256 (фрагмент)",
             f'<code class="inline">{self.sha256_short}&hellip;</code>'],
            ["Начало захвата", epoch_to_str(gen.first_ts)],
            ["Конец захвата", epoch_to_str(gen.last_ts)],
            ["Длительность", C.fmt_dur(gen.duration)],
            ["Всего пакетов", C.fmt_int(gen.total_packets)],
            ["Объём трафика", C.fmt_bytes(gen.total_bytes)],
            ["SYN/RST (TCP)", f'{C.fmt_int(gen.syn_total)} / '
                              f'{C.fmt_int(gen.rst_total)}'],
        ]
        top_rows = [
            [f"<code class=\"inline\">{C.esc(ip)}</code>",
             f'<span class="num">{C.fmt_int(cnt)}</span>',
             f'<span class="num">{C.fmt_bytes(gen.ip_bytes_tx.get(ip, 0))}</span>',
             f'<span class="num">{C.fmt_bytes(gen.ip_bytes_rx.get(ip, 0))}</span>']
            for ip, cnt in gen.ip_pkts.most_common(8)
        ]
        body = (
            C.table_html(["Параметр", "Значение"], rows)
            + '<h3 class="subhead">Самые активные узлы</h3>'
            + C.table_html(["Узел", "Пакетов", "Отправлено", "Получено"],
                           top_rows)
            + '<p class="note">Ветка не требует дизассемблера протокола: '
              'сервис определяется по порту-серверу (меньший из портов пары; '
              'при равных — по инициатору первого пакета потока). Такой '
              'подход подходит для проприетарной телеметрии и обмена АСУ ТП '
              'с собственными шлюзами.</p>'
        )
        cmds = [
            ("Общая статистика по файлу", self._cmd("-q -z io,stat,0")),
            ("Таблица TCP-соединений", self._cmd("-q -z conv,tcp")),
            ("Таблица UDP-обменов", self._cmd("-q -z conv,udp")),
        ]
        return Section("general", "Общая информация о захвате", body, cmds)

    @staticmethod
    def _port_note(port: int) -> str:
        known = {123: "NTP", 67: "DHCP-сервер", 68: "DHCP-клиент",
                 502: "Modbus/TCP", 102: "S7comm", 44818: "EtherNet/IP",
                 2222: "EtherNet/IP-2", 20000: "DNP3"}
        return known.get(port, "")

    def _sec_tcp(self, gen: GeneralStats) -> Section:
        rows = []
        svcs = [(ip, svc) for (ip, _p), svc in self._tcp_services.items()]
        svcs.sort(key=lambda kv: kv[1].req_pkts + kv[1].resp_pkts,
                  reverse=True)
        for ip, svc in svcs[: self.cfg.max_rows_per_table]:
            med_iv = percentile(sorted(svc.intervals), 50)
            cv = cv_of(svc.intervals)
            reg = (cyclic_label(cv, self.cfg)
                   if len(svc.intervals) >= self.cfg.svc_min_msgs_for_period
                   else "")
            note = self._port_note(svc.port)
            port_lbl = f":{svc.port}" + (f' ({note})' if note else "")
            retrans_pct = (100.0 * svc.retrans /
                           max(svc.req_pkts + svc.resp_pkts, 1))
            silent_cell = f'<span class="num">{C.fmt_int(svc.silent_streams)}</span>'
            if svc.silent_streams:
                silent_cell = (silent_cell, "cell-hot")
            rows.append([
                self._srv_cell(ip), f"<strong>{port_lbl}</strong>",
                f'<span class="num">{C.fmt_int(len(svc.clients))}</span>',
                f'<span class="num">{C.fmt_int(svc.streams)}</span>',
                f'<span class="num">{C.fmt_int(svc.syn)}</span>',
                f'<span class="num">{C.fmt_int(svc.req_pkts)}</span>',
                f'<span class="num">{C.fmt_bytes(svc.req_bytes)}</span>',
                f'<span class="num">{C.fmt_int(svc.resp_pkts)}</span>',
                f'<span class="num">{C.fmt_bytes(svc.resp_bytes)}</span>',
                f'<span class="num">{C.fmt_ms(med_iv)}</span>' if med_iv else "—",
                reg,
                f'<span class="num">{retrans_pct:.1f}%</span>',
                silent_cell,
            ])
        body = (
            "<p>TCP-сервисы, отсортированные по числу сообщений:</p>"
            + C.table_html(
                ["Сервер", "Порт", "Клиентов", "Потоков", "SYN",
                 "Сообщ. &rarr;", "Байты &rarr;", "Сообщ. &larr;",
                 "Байты &larr;", "Медиан. интервал", "Регулярность",
                 "Ретранс.", "Молчат"],
                rows)
            + '<p class="note"><strong>&rarr;</strong> — от клиентов к серверу, '
              '&larr; — обратно (только пакеты с полезной нагрузкой). '
              '<strong>Регулярность</strong> — коэффициент вариации интервалов '
              'между сообщениями клиента: низкий CV означает строгий цикл '
              'опроса. <strong>Молчат</strong> — потоки, где клиент отправлял '
              'данные или подключался, но от сервера не пришло ни одного байта '
              '<span class="hot-legend">подсвечено розовым</span>.</p>'
        )
        top = next(iter(svcs), None)
        cmds = []
        if top:
            ip, svc = top
            cmds.append((
                f"Все сообщения сервиса :{svc.port} к {ip}",
                self._cmd(f'-Y "tcp.port=={svc.port} && ip.addr=={ip}" '
                          "-T fields -e frame.time -e ip.src -e ip.dst "
                          "-e tcp.srcport -e tcp.dstport -e tcp.len")))
            cmds.append((
                "Кто и как часто подключается к этому сервису",
                self._cmd(f'-Y "tcp.flags.syn==1 && tcp.flags.ack==0 && '
                          f'tcp.dstport=={svc.port}" -T fields -e ip.dst '
                          "-e ip.src | sort | uniq -c | sort -rn")))
        cmds.append((
            "Диалоги по всем TCP-потокам",
            self._cmd("-q -z conv,tcp")))
        return Section("tcp", "TCP-сервисы", body, cmds)

    def _sec_periodicity(self, gen: GeneralStats) -> Section:
        bars = []
        all_svcs = list(self._tcp_services.items()) \
            + list(self._udp_services.items())
        for (ip, _port), svc in all_svcs:
            if len(svc.intervals) < self.cfg.svc_min_msgs_for_period:
                continue
            med = percentile(sorted(svc.intervals), 50)
            if med is None:
                continue
            label = f"{ip}:{svc.port}"
            bars.append((label, med * 1000))
        if not bars:
            return Section(
                "periodicity", "Периодика обмена",
                "<p>Сервисов с устойчивой цикличностью не обнаружено "
                f"(минимум {self.cfg.svc_min_msgs_for_period} сообщений "
                "клиента).</p>", [])
        bars.sort(key=lambda x: x[1])
        svg = ('<div class="chart-box">'
               + C.hbar_svg(bars[:12], value_fmt=lambda v: f"{v:.0f} мс")
               + "</div>")
        strict = sum(
            1 for _key, svc in all_svcs
            if len(svc.intervals) >= self.cfg.svc_min_msgs_for_period
            and (cv_of(svc.intervals) or 9) < self.cfg.svc_cyclic_cv_strict)
        body = (
            svg
            + f"<p>Медианные интервалы между сообщениями клиентов; сервисов "
              f"с выраженной периодикой: <strong>{len(bars)}</strong>, из них "
              f"со строгим циклом (CV&lt;{self.cfg.svc_cyclic_cv_strict:g}): "
              f"<strong>{strict}</strong>.</p>"
            + '<p class="note">Ровные короткие интервалы (десятки-сотни мс) — '
              'циклический опрос или телеизмерение. Дрейф медианы между '
              'сервисами показывает иерархию циклов опроса; слишком частый '
              'цикл при медленном отклике сервера создаёт очередь транзакций.</p>'
        )
        cmd = ("Интервалы между пакетами одного потока",
               self._cmd("-T fields -e tcp.stream -e frame.time_epoch "
                         "| awk '{if($1==s){print $2-t}{s=$1;t=$2}}' "
                         "| sort -rn | head -20"))
        return Section("periodicity", "Периодика обмена", body, [cmd])

    def _sec_udp(self, gen: GeneralStats) -> Section:
        if not self._udp_services:
            return Section("udp", "UDP-сервисы",
                           "<p>Значимого UDP-обмена не зафиксировано.</p>", [])
        rows = []
        svcs = sorted(self._udp_services.items(),
                      key=lambda kv: kv[1].req_pkts, reverse=True)
        for ip, svc in svcs[: self.cfg.max_rows_per_table]:
            med_iv = percentile(sorted(svc.intervals), 50)
            note = self._port_note(svc.port)
            port_lbl = f":{svc.port}" + (f' ({note})' if note else "")
            rows.append([
                self._srv_cell(ip), f"<strong>{port_lbl}</strong>",
                f'<span class="num">{C.fmt_int(len(svc.clients))}</span>',
                f'<span class="num">{C.fmt_int(svc.req_pkts)}</span>',
                f'<span class="num">{C.fmt_bytes(svc.req_bytes)}</span>',
                f'<span class="num">{C.fmt_ms(med_iv)}</span>'
                if med_iv else "—",
            ])
        body = (
            "<p>UDP-обмены по сервисам:</p>"
            + C.table_html(
                ["Сервер", "Порт", "Клиентов", "Датаграмм", "Байты",
                 "Медиан. интервал"],
                rows)
            + '<p class="note">Для UDP роль сервера определена по меньшему '
              'порту пары. Регулярный NTP-опрос — норма; проверьте, что все '
              'узлы сверяют время с согласованным источником: расхождение '
              'часов ломает хронологию журналов и квитирование протоколов.</p>'
        )
        top = svcs[0]
        cmds = [(
            f"Все датаграммы сервиса :{top[1].port} к {top[0]}",
            self._cmd(f'-Y "udp.port=={top[1].port}" -T fields -e frame.time '
                      "-e ip.src -e ip.dst -e udp.srcport -e udp.dstport"))]
        return Section("udp", "UDP-сервисы", body, cmds)

    def _sec_noise(self, gen: GeneralStats) -> Section:
        if not gen.proto_frames:
            return Section("noise", "Служебный трафик",
                           "<p>Служебного трафика не зафиксировано.</p>", [])
        names = {v: k for k, v in PROTO_WATCH.items()}
        rows = []
        for fam_ru, cnt in sorted(gen.proto_frames.items(),
                                  key=lambda kv: kv[1], reverse=True):
            key = names.get(fam_ru, fam_ru)
            per_min = cnt / (gen.duration / 60) if gen.duration else 0
            rows.append([
                f"<strong>{C.esc(fam_ru)}</strong>",
                f'<code class="inline">{C.esc(key)}</code>',
                f'<span class="num">{C.fmt_int(cnt)}</span>',
                f'<span class="num">{per_min:.1f}</span>',
            ])
        body = (
            C.table_html(["Семейство", "Идентификатор", "Кадров", "кадров/мин"],
                         rows)
            + '<p class="note">Это фоновые протоколы уровня канала и '
              'администрирования. Единичные ARP/STP/LLDP — норма. Массовый '
              'ARP-поток (сотни кадров в минуту) означает шторм запросов или '
              'сканирование; всплески NetBIOS/Browser характерны для Windows- '
              'сетей и обычно вреда АСУ ТП не наносят, но засоряют канал.</p>'
        )
        cmds = [("Все ARP-кадры",
                 self._cmd("-Y arp -T fields -e frame.time -e arp.opcode "
                           "-e ip.src -e ip.dst | head -40")),
                ("Кто рассылает LLDP",
                 self._cmd('-Y lldp -T fields -e lldp.chassis.id '
                           "| sort | uniq -c | sort -rn"))]
        return Section("noise", "Служебный трафик", body, cmds)

    # -- Рекомендации -----------------------------------------------------------

    def _build_recommendations(self, gen: GeneralStats) -> list[Recommendation]:
        recs: list[Recommendation] = []
        recs.extend(self._rule_dead_targets())
        recs.extend(self._rule_one_way())
        recs.extend(self._rule_retrans())
        recs.extend(self._rule_churn(gen))
        recs.extend(self._rule_arp_storm(gen))
        if not recs:
            recs.append(Recommendation(
                id="ok", severity="info",
                title="Явных проблем не обнаружено",
                problem="Ни одно правило оптимизации не сработало.",
                advice="Повторите анализ после изменений конфигурации сети "
                       "или появления новых сервисов.",
            ))
        return sort_recommendations(recs)

    def _rule_dead_targets(self) -> list[Recommendation]:
        out = []
        for key, svc in self._tcp_services.items():
            ip = key[0]
            if svc.silent_streams and svc.req_pkts == 0 \
                    and svc.syn >= self.cfg.s7_dead_min_syns:
                out.append(Recommendation(
                    id=f"svc-dead-{ip}-{svc.port}".replace(".", "-"),
                    severity="warning",
                    title=f"Подключения к {ip}:{svc.port} без ответа",
                    problem=(
                        f"{svc.syn} попыток подключения, {svc.silent_streams} "
                        "потоков без единого байта ответа."),
                    advice=(
                        "Клиент регулярно стучится в сервис, но тот не "
                        "отвечает даже handshake-данными: устройство "
                        "обесточено/в резерве, занят лимит подключений либо "
                        "адрес клиента фильтруется. Уберите узел из "
                        "конфигурации опроса или верните его в работу."),
                    commands=[self._cmd(
                        f'-Y "tcp.port=={svc.port} && ip.addr=={ip}" '
                        "-T fields -e frame.time -e ip.src -e ip.dst "
                        "-e tcp.flags | head -40")],
                ))
        return out

    def _rule_one_way(self) -> list[Recommendation]:
        out = []
        for key, svc in self._tcp_services.items():
            ip = key[0]
            if svc.one_way_streams:
                share = 100.0 * svc.one_way_streams / max(svc.streams, 1)
                out.append(Recommendation(
                    id=f"svc-one-way-{ip}-{svc.port}".replace(".", "-"),
                    severity="info",
                    title=f"Односторонний обмен: {ip}:{svc.port}",
                    problem=(
                        f"{svc.one_way_streams} из {svc.streams} потоков "
                        f"({share:.0f}%) передают данные только в одну "
                        "сторону при объёме выше порога."),
                    advice=(
                        "Если это сбор событий/логирование — норма. Если же "
                        "ожидался диалог (команды и квитирование) — проверьте "
                        "настройки партнёра и полноту захвата: односторонний "
                        "поток также возникает, когда ответный трафик уходит "
                        "другим маршрутом мимо точки съёма."),
                    commands=[self._cmd(
                        f'-Y "tcp.port=={svc.port} && ip.addr=={ip}" '
                        "-T fields -e ip.src -e tcp.len | sort | uniq -c "
                        "| sort -rn | head -20")],
                ))
        return out

    def _rule_retrans(self) -> list[Recommendation]:
        out = []
        for key, svc in self._tcp_services.items():
            ip = key[0]
            total = svc.req_pkts + svc.resp_pkts
            if total < 100:
                continue
            pct = 100.0 * svc.retrans / total
            if pct >= self.cfg.svc_retrans_warn_pct:
                out.append(Recommendation(
                    id=f"svc-retrans-{ip}-{svc.port}".replace(".", "-"),
                    severity="warning",
                    title=f"Много ретрансляций TCP: {ip}:{svc.port}",
                    problem=(
                        f"{svc.retrans} повторных передач "
                        f"({pct:.1f}% от сообщений сервиса)."),
                    advice=(
                        "Ретрансляции означают потери кадров в пути: "
                        "перегруженный линк, дуплексные рассогласования, "
                        "неисправный кабель/порт коммутатора или широковещательный "
                        "шторм. Для промышленной сети это первопричина таймаутов "
                        "опроса; локализуйте участок по точкам съёма. Важно: "
                        "если на другой точке съёма те же сессии показывают "
                        "доли на порядки меньше — подозревайте саму запись "
                        "(переполнение зеркала, дубли кадров), а не канал."),
                    commands=[self._cmd(
                        f'-Y "tcp.analysis.retransmission && '
                        f'tcp.port=={svc.port} && ip.addr=={ip}" '
                        "-T fields -e frame.number -e frame.time -e ip.src "
                        "-e ip.dst | head -40")],
                ))
        return out

    def _rule_churn(self, gen: GeneralStats) -> list[Recommendation]:
        out = []
        dur_min = max(gen.duration / 60.0, 1.0)
        for key, svc in self._tcp_services.items():
            ip = key[0]
            if svc.syn / dur_min >= self.cfg.conn_churn_per_min \
                    and svc.resp_bytes > 0:
                out.append(Recommendation(
                    id=f"svc-churn-{ip}-{svc.port}".replace(".", "-"),
                    severity="warning",
                    title=f"Частые переподключения к сервису "
                          f"{ip}:{svc.port}",
                    problem=(
                        f"{svc.syn} новых подключений "
                        f"({svc.syn / dur_min:.1f}/мин) при живом обмене "
                        "данными."),
                    advice=(
                        "Клиенты пересоздают соединения вместо одного "
                        "keep-alive: каждый раз заново handshake и прогрев "
                        "протокола, сервер тратит ресурсы на приём. Проверьте "
                        "таймауты простоя клиента и промежуточных устройств "
                        "(NAT, межсетевой экран)."),
                    commands=[self._cmd(
                        f'-Y "tcp.flags.syn==1 && tcp.flags.ack==0 && '
                        f'tcp.dstport=={svc.port}" -T fields -e frame.time '
                        "-e ip.src | sort | uniq -c | sort -rn")],
                ))
        return out

    def _rule_arp_storm(self, gen: GeneralStats) -> list[Recommendation]:
        n = gen.proto_frames.get("arp", 0)
        per_min = n / (gen.duration / 60) if gen.duration else 0
        if per_min < self.cfg.arp_storm_per_min:
            return []
        return [Recommendation(
            id="svc-arp-storm", severity="warning",
            title="Высокая интенсивность ARP-трафика",
            problem=f"{n} ARP-кадров ({per_min:.0f}/мин).",
            advice=(
                "Шторм ARP-запросов перегружает широковещательный домен и "
                "процессоры коммутаторов/хостов. Типовые причины: петля с "
                "зацикленным прокси-ARP, сканирование сети, неисправный "
                "хост. Найдите источники по MAC и изолируйте сегмент."),
            commands=[
                self._cmd("-Y arp -T fields -e arp.opcode -e eth.src "
                          "| sort | uniq -c | sort -rn | head -20"),
                self._cmd("-Y arp && !arp.is-gratuitous -T fields "
                          "-e frame.time -e eth.src | head -40"),
            ],
        )]
