"""Ветка анализа Modbus/TCP.

Собирает метрики работы клиентов и серверов Modbus по данным tshark:
частота подключений, состав команд (функциональные коды), карта читаемых/
записываемых регистров, времена отклика, исключения — и формирует
рекомендации по оптимизации опроса.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Config
from ..tshark_runner import find_tshark, stream_fields
from ..tshark_runner import OCCURRENCE_SEPARATOR as OCC_SEP
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
    fmt_ts_offset,
    percentile,
    to_float,
    to_int,
    truthy,
)

# Функциональные коды чтения/записи
READ_FCS = {1, 2, 3, 4}
WRITE_SINGLE_FCS = {5, 6}
WRITE_MULTI_FCS = {15, 16}
VALUE_READ_FCS = {3, 4}          # ответы содержат значения регистров (uint16)

FUNC_NAMES = {
    1: "Чтение катушек (Read Coils)",
    2: "Чтение дискретных входов (Read Discrete Inputs)",
    3: "Чтение регистров хранения (Read Holding Registers)",
    4: "Чтение регистров ввода (Read Input Registers)",
    5: "Запись одной катушки (Write Single Coil)",
    6: "Запись одного регистра (Write Single Register)",
    7: "Чтение статуса (Read Exception Status)",
    8: "Диагностика (Diagnostics)",
    11: "Счётчик событий (Get Comm Event Counter)",
    12: "Журнал событий (Get Comm Event Log)",
    15: "Запись нескольких катушек (Write Multiple Coils)",
    16: "Запись нескольких регистров (Write Multiple Registers)",
    17: "Отчёт об устройстве (Report Slave ID)",
    22: "Масочная запись регистра (Mask Write Register)",
    23: "Чтение/запись регистров (Read/Write Multiple Registers)",
    43: "Чтение идентификатора устройства (Read Device Identification)",
}

EXC_NAMES = {
    1: "ILLEGAL FUNCTION — функция не поддерживается устройством",
    2: "ILLEGAL DATA ADDRESS — адрес регистра вне карты устройства",
    3: "ILLEGAL DATA VALUE — некорректное значение параметра запроса",
    4: "SLAVE DEVICE FAILURE — сбой при выполнении операции",
    5: "ACKNOWLEDGE — запрос принят, выполняется долго",
    6: "SLAVE DEVICE BUSY — устройство занято",
    8: "MEMORY PARITY ERROR — ошибка чётности памяти",
    10: "GATEWAY PATH UNAVAILABLE — шлюз недоступен",
    11: "GATEWAY TARGET FAILED — целевое устройство за шлюзом не ответило",
}


def fc_name(fc: int) -> str:
    base = fc & 0x7F
    name = FUNC_NAMES.get(base, f"Неизвестный код {base}")
    return f"{name}"


# ---------------------------------------------------------------------------
# Структуры данных
# ---------------------------------------------------------------------------

class Req:
    """Modbus-запрос (для сопоставления с ответом)."""

    __slots__ = (
        "n", "ts", "src", "dst", "stream", "trans", "unit", "fc",
        "ref", "cnt", "answered", "rtt",
    )

    def __init__(self, n, ts, src, dst, stream, trans, unit, fc, ref, cnt):
        self.n = n
        self.ts = ts
        self.src = src
        self.dst = dst
        self.stream = stream
        self.trans = trans
        self.unit = unit
        self.fc = fc
        self.ref = ref
        self.cnt = cnt
        self.answered = False
        self.rtt = None


@dataclass
class PairStats:
    reqs: int = 0
    resps: int = 0
    excs: int = 0
    no_resp: int = 0
    bytes_: int = 0
    streams: set = field(default_factory=set)
    fcodes: Counter = field(default_factory=Counter)
    rtts: Reservoir = field(default_factory=lambda: Reservoir(0))
    first_ts: float | None = None
    last_ts: float | None = None


@dataclass
class PollTarget:
    """Цель опроса: клиент->сервер, unit, функция, диапазон регистров."""

    client: str
    server: str
    unit: int
    fc: int
    ref: int
    cnt: int
    n_req: int = 0
    last_ts: float | None = None
    intervals: Reservoir = field(default_factory=lambda: Reservoir(0))


@dataclass
class GeneralStats:
    total_packets: int = 0
    total_bytes: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    syn502: list = field(default_factory=list)          # (ts, client, server)
    rst502: int = 0
    fin502: int = 0
    streams502: dict = field(default_factory=dict)      # stream -> dict(client,server,first,last)
    ip_pkts: Counter = field(default_factory=Counter)
    ip_bytes_tx: Counter = field(default_factory=Counter)   # отправлено узлом
    ip_bytes_rx: Counter = field(default_factory=Counter)   # получено узлом

    @property
    def duration(self) -> float:
        if self.first_ts is not None and self.last_ts is not None:
            return max(self.last_ts - self.first_ts, 0.0)
        return 0.0


# ---------------------------------------------------------------------------
# Анализатор
# ---------------------------------------------------------------------------

class ModbusTcpAnalyzer(BaseBranch):
    name = "modbus"
    title = "Анализ Modbus/TCP"
    description = (
        "Клиенты и серверы, частота подключений, функциональные коды, "
        "карта регистров, времена отклика, исключения и рекомендации "
        "по оптимизации опроса."
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

        progress("Проход 1/3: общий обзор TCP/IP…", pct=17)
        gen = self._pass_general()
        duration = gen.duration

        result.capture_start_ts = gen.first_ts

        progress("Проход 2/3: разбор Modbus/TCP…", pct=50)
        mb = self._pass_modbus(gen)

        # тёплые цвета серверов (PLC): единая раскраска таблиц, диаграмм
        # и легенды шапки отчёта; порядок — по возрастанию IP
        self._set_servers(sv for (_c, sv) in mb["pairs"])

        # окна для диаграмм Ганта (только если есть что показывать)
        self._threads = []
        if mb["req_total"] and gen.duration > 0 and not cfg.skip_gantt:
            progress("Проход 3/3: подбор окон активности…", pct=83)
            self._threads = self._thread_windows(
                "mbtcp && tcp.dstport==502", gen.first_ts, gen.duration)

        # Если Modbus не найден — честно сообщаем в отчёте
        kpi = self._build_kpi(gen, mb)
        sections = self._build_sections(gen, mb)
        recs = self._build_recommendations(gen, mb)

        no_resp_total = sum(p.no_resp for p in mb["pairs"].values())
        rtts_all = sorted(r for ps in mb["pairs"].values() for r in ps.rtts)
        med_rtt = percentile(rtts_all, 50)
        clients_n = len({c for (c, _s) in mb["pairs"]})
        servers_n = len({s for (_c, s) in mb["pairs"]})
        result.metrics = {
            "reqs": float(mb["req_total"]),
            "resps": float(mb["resp_total"]),
            "no_resp_pct": (100.0 * no_resp_total / mb["req_total"]
                            if mb["req_total"] else 0.0),
            "exc_pct": (100.0 * mb["exc_total"] / mb["resp_total"]
                        if mb["resp_total"] else 0.0),
            "rtt_med_ms": med_rtt * 1000.0 if med_rtt is not None else 0.0,
            "syn": float(len(gen.syn502)),
            "conns": float(len(gen.streams502)),
            "clients": float(clients_n),
            "servers": float(servers_n),
        }
        result.kpi = kpi
        result.sections = sections
        result.recommendations = recs
        result.server_colors = dict(self._srv_colors)
        return result

    # -- вспомогательное ----------------------------------------------------

    @staticmethod
    def _max_concurrent(intervals) -> int:
        """Максимум одновременных соединений по перекрытию интервалов жизни."""
        evts = []
        for a, b in intervals:
            if a is None or b is None or b < a:
                continue
            evts.append((a, 1))
            evts.append((b, -1))
        evts.sort()          # при равном времени закрытие (-1) раньше открытия
        cur = mx = 0
        for _t, d in evts:
            cur += d
            if cur > mx:
                mx = cur
        return mx

    # -- Проход 1: общие сведения -------------------------------------------

    FIELDS_GENERAL = [
        "frame.time_epoch", "frame.len", "ip.src", "ip.dst",
        "tcp.stream", "tcp.srcport", "tcp.dstport",
        "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.reset", "tcp.flags.fin",
    ]

    def _pass_general(self) -> GeneralStats:
        g = GeneralStats()
        rows = stream_fields(self.tshark, self.pcap_str, self.FIELDS_GENERAL)
        for i, r in enumerate(rows):
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
            sport = to_int(r.get("tcp.srcport"), -1)
            dport = to_int(r.get("tcp.dstport"), -1)
            if sport < 0 and dport < 0:
                continue
            is_syn = truthy(r.get("tcp.flags.syn", ""))
            is_ack = truthy(r.get("tcp.flags.ack", ""))
            if truthy(r.get("tcp.flags.reset", "")) and (sport == 502 or dport == 502):
                g.rst502 += 1
            if truthy(r.get("tcp.flags.fin", "")) and (sport == 502 or dport == 502):
                g.fin502 += 1
            if is_syn and not is_ack and dport == 502 and src:
                g.syn502.append((ts or 0.0, src, dst))
            # Потоки, где участвует порт 502
            if sport == 502 or dport == 502:
                st = r.get("tcp.stream", "")
                if st != "":
                    info = g.streams502.setdefault(
                        st, {"client": dst if sport == 502 else src,
                             "server": src if sport == 502 else dst,
                             # эфемерный порт стороны клиента — различает потоки
                             "sport": dport if sport == 502 else sport,
                             "first": ts, "last": ts,
                             "rst_srv": False, "rst_cli": False}
                    )
                    if ts is not None:
                        if info["first"] is None or ts < info["first"]:
                            info["first"] = ts
                        if info["last"] is None or ts > info["last"]:
                            info["last"] = ts
                    # кто инициировал завершение соединения (первый FIN/RST)
                    if "closed_by" not in info and (
                            truthy(r.get("tcp.flags.fin", ""))
                            or truthy(r.get("tcp.flags.reset", ""))):
                        info["closed_by"] = src
                    # факт наличия RST с каждой стороны — независимо от того,
                    # кто закрыл соединение первым (RST часто идёт после FIN)
                    if truthy(r.get("tcp.flags.reset", "")):
                        if sport == 502:
                            info["rst_srv"] = True
                        else:
                            info["rst_cli"] = True
            if (i + 1) % 100000 == 0:
                self.progress(f"  обработано {i + 1} пакетов…", pct=17)
        return g

    # -- Проход 2: Modbus -----------------------------------------------------

    FIELDS_MODBUS = [
        "frame.number", "frame.time_epoch", "frame.len", "ip.src", "ip.dst",
        "tcp.srcport", "tcp.dstport", "tcp.stream",
        "mbtcp.trans_id", "mbtcp.unit_id",
        "modbus.func_code", "modbus.exception_code",
        "modbus.reference_num", "modbus.word_cnt",
        "modbus.write_reference_num", "modbus.write_word_cnt",
        "modbus.byte_cnt", "modbus.regval_uint16",
        "modbus.request_frame", "modbus.response_time",
    ]

    def _pass_modbus(self, gen: GeneralStats) -> dict:
        mb = {
            "total_pdu": 0,
            "req_total": 0,
            "resp_total": 0,
            "exc_total": 0,
            "pairs": {},                 # (client, server) -> PairStats
            "pair_order": [],            # порядок появления пар
            "fcode_counter": Counter(),  # fc -> число запросов
            "reads": {},                 # (server,unit,fc,start,len) -> [ops, words]
            "writes": {},                # (server,unit,fc,ref)     -> [ops, words]
            "range_clients": {},         # (server,unit,fc,start,len) -> set(client)
            "poll_targets": {},          # ключ -> PollTarget
            "valtrack": {},              # (server,unit,fc,reg) -> [last,changes,reads]
            "exc_counter": Counter(),    # (server,unit,code) -> count
            # кто какими запросами вызвал исключения:
            # (client,server,unit,fc,ref,cnt,code) -> раз
            "exc_targets": Counter(),
            "timeline": {},              # bucket -> [req,resp,exc]
            "stream_reqs": Counter(),    # tcp.stream -> число запросов
            "mb_streams": set(),
            "small_reads": {},           # (c,s,u) -> [(ts,ref,cnt)]
            "small_reads_total": Counter(),
            "all_reads_by_key": Counter(),   # (c,s,u) -> всего запросов чтения
            "writes_single": {},         # (c,s,u) -> [(ts,ref)]
            "writes_single_total": Counter(),
            "writes_coil": Counter(),    # (c,s,u) -> count FC5
            "unanswered_frames": [],
            "orphan_resps": 0,
        }
        req_by_frame: dict[int, Req] = {}
        pending_fifo: dict[tuple, list[Req]] = {}
        first_ts = gen.first_ts or 0.0
        bucket_sec = self.cfg.timeline_bucket_sec

        rows = stream_fields(self.tshark, self.pcap_str, self.FIELDS_MODBUS,
                             display_filter="mbtcp")
        for i, row in enumerate(rows):
            mb["total_pdu"] += 1
            n = to_int(row.get("frame.number"), 0)
            ts = to_float(row.get("frame.time_epoch")) or 0.0
            src = row.get("ip.src", "?")
            dst = row.get("ip.dst", "?")
            stream = row.get("tcp.stream", "")
            trans = to_int(row.get("mbtcp.trans_id"), -1)
            unit = to_int(row.get("mbtcp.unit_id"), -1)
            fc_raw = to_int(row.get("modbus.func_code"), -1)
            if fc_raw < 0:
                continue
            fc_base = fc_raw & 0x7F
            rf_field = row.get("modbus.request_frame", "").strip()

            # Направление: сначала порт 502, при нестандартных портах — наличие ссылки
            # на запрос (поле modbus.request_frame есть только у ответов).
            sport_row = to_int(row.get("tcp.srcport"), -1)
            dport_row = to_int(row.get("tcp.dstport"), -1)
            if sport_row == 502:
                is_response = True
            elif dport_row == 502:
                is_response = False
            else:
                is_response = bool(rf_field)

            if is_response:
                mb["resp_total"] += 1
                bucket = int((ts - first_ts) // bucket_sec)
                mb["timeline"].setdefault(bucket, [0, 0, 0])
                req = req_by_frame.get(to_int(rf_field, -1))
                if req is None and trans >= 0:
                    # Страховка: дизассемблер не дал request_frame
                    q = pending_fifo.get((stream, trans, unit))
                    if q and q[0].ts <= ts:
                        req = q.pop(0)
                rtt = to_float(row.get("modbus.response_time"))
                if req is not None and rtt is None:
                    rtt = max(ts - req.ts, 0.0)
                exc_field = row.get("modbus.exception_code", "").strip()
                is_exc = bool(exc_field) or (fc_raw >= 0x80)

                if req is not None:
                    req.answered = True
                    req.rtt = rtt
                    client, server, unit_p, fc, ref = req.src, req.dst, req.unit, req.fc, req.ref
                    ps = self._pair(mb, client, server)
                    ps.resps += 1
                    if rtt is not None:
                        ps.rtts.add(rtt)
                    if is_exc:
                        ps.excs += 1
                        mb["exc_total"] += 1
                        code = to_int(exc_field, -1)
                        mb["exc_counter"][(server, unit_p, code)] += 1
                        # привязка к конкретному запросу: клиент, функция,
                        # диапазон регистров (req.ref/req.cnt из запроса)
                        if req is not None:
                            mb["exc_targets"][
                                (req.src, server, unit_p, fc,
                                 req.ref, max(req.cnt, 1), code)] += 1
                        mb["timeline"][bucket][2] += 1
                    else:
                        # значения регистров FC3/FC4 -> трекинг изменений
                        vals_raw = row.get("modbus.regval_uint16", "").strip()
                        if fc in VALUE_READ_FCS and vals_raw and ref >= 0:
                            try:
                                vals = [int(v) for v in vals_raw.split(OCC_SEP)]
                            except ValueError:
                                vals = []
                            vt = mb["valtrack"]
                            for off, v in enumerate(vals):
                                key = (server, unit_p, fc, ref + off)
                                rec_ = vt.get(key)
                                if rec_ is None:
                                    if len(vt) < self.cfg.valtrack_max_registers:
                                        vt[key] = [v, 0, 1]
                                else:
                                    rec_[2] += 1
                                    if v != rec_[0]:
                                        rec_[0] = v
                                        rec_[1] += 1
                else:
                    mb["orphan_resps"] += 1
                mb["timeline"][bucket][1] += 1
            else:
                # --- Запрос -------------------------------------------------
                mb["req_total"] += 1
                bucket = int((ts - first_ts) // bucket_sec)
                tl = mb["timeline"].setdefault(bucket, [0, 0, 0])
                tl[0] += 1

                ref = to_int(row.get("modbus.reference_num"), -1)
                wcnt = to_int(row.get("modbus.word_cnt"), 0)
                wref = to_int(row.get("modbus.write_reference_num"), -1)
                wwcnt = to_int(row.get("modbus.write_word_cnt"), 0)
                if fc_base in WRITE_SINGLE_FCS:
                    ref = wref if wref >= 0 else ref
                    wcnt = 1
                elif fc_base in WRITE_MULTI_FCS:
                    ref = wref if wref >= 0 else ref
                    wcnt = wwcnt or wcnt
                elif ref < 0:
                    ref = wref

                req = Req(n, ts, src, dst, stream, trans, unit, fc_base, ref, wcnt)
                req_by_frame[n] = req
                # FIFO-страховка для дизассемблеров без request_frame
                if trans >= 0:
                    pending_fifo.setdefault((stream, trans, unit), []).append(req)
                    if len(pending_fifo) > self.cfg.pending_fifo_max_keys:
                        half = self.cfg.pending_fifo_max_keys // 2
                        for k in [k for k, v in pending_fifo.items() if not v][:half]:
                            del pending_fifo[k]

                client, server = src, dst
                ps = self._pair(mb, client, server)
                ps.reqs += 1
                ps.bytes_ += to_int(row.get("frame.len"), 0)
                ps.fcodes[fc_base] += 1
                if ps.first_ts is None:
                    ps.first_ts = ts
                ps.last_ts = ts
                if stream:
                    ps.streams.add(stream)
                    mb["stream_reqs"][stream] += 1
                    mb["mb_streams"].add(stream)
                mb["fcode_counter"][fc_base] += 1

                # Регистры: чтения
                if fc_base in READ_FCS and ref >= 0:
                    rk = (server, unit, fc_base, ref, max(wcnt, 0))
                    rec_ = mb["reads"].setdefault(rk, [0, 0])
                    rec_[0] += 1
                    rec_[1] += max(wcnt, 0)
                    mb["range_clients"].setdefault(rk, set()).add(client)
                    ck = (client, server, unit)
                    mb["all_reads_by_key"][ck] += 1
                    if 0 < wcnt <= self.cfg.small_read_max_words:
                        lst = mb["small_reads"].setdefault(ck, [])
                        if len(lst) < self.cfg.small_reads_max_items:
                            lst.append((ts, ref, wcnt))
                        mb["small_reads_total"][ck] += 1
                # Регистры: записи
                if fc_base in WRITE_SINGLE_FCS and ref >= 0:
                    wk = (server, unit, fc_base, ref)
                    rec_ = mb["writes"].setdefault(wk, [0, 0])
                    rec_[0] += 1
                    rec_[1] += 1
                    ck = (client, server, unit)
                    if fc_base == 5:
                        mb["writes_coil"][ck] += 1
                    else:
                        lst = mb["writes_single"].setdefault(ck, [])
                        if len(lst) < self.cfg.writes_single_max_items:
                            lst.append((ts, ref))
                        mb["writes_single_total"][ck] += 1
                elif fc_base in WRITE_MULTI_FCS and ref >= 0:
                    wk = (server, unit, fc_base, ref)
                    rec_ = mb["writes"].setdefault(wk, [0, 0])
                    rec_[0] += 1
                    rec_[1] += max(wcnt, 0)

                # Цели опроса
                if ref >= 0:
                    tk = (client, server, unit, fc_base, ref, wcnt)
                    pt = mb["poll_targets"].get(tk)
                    if pt is None:
                        pt = mb["poll_targets"][tk] = PollTarget(
                            client, server, unit, fc_base, ref, wcnt,
                            intervals=Reservoir(self.cfg.max_intervals_per_target),
                        )
                    pt.n_req += 1
                    if pt.last_ts is not None and ts > pt.last_ts:
                        iv = ts - pt.last_ts
                        if 0 < iv <= 3600:
                            pt.intervals.add(iv)
                    pt.last_ts = ts

            if (i + 1) % 100000 == 0:
                self.progress(f"  обработано {i + 1} PDU Modbus…", pct=50)

        # Неотвеченные запросы
        for nf, req in req_by_frame.items():
            if not req.answered:
                mb["pairs"][(req.src, req.dst)].no_resp += 1
                if len(mb["unanswered_frames"]) < self.cfg.unanswered_examples:
                    mb["unanswered_frames"].append(req.n)
        return mb

    def _pair(self, mb: dict, client: str, server: str) -> PairStats:
        ps = mb["pairs"].get((client, server))
        if ps is None:
            ps = mb["pairs"][(client, server)] = PairStats(
                rtts=Reservoir(self.cfg.max_rtts_per_pair))
            mb["pair_order"].append((client, server))
        return ps

    # -- KPI ------------------------------------------------------------------

    def _build_kpi(self, gen: GeneralStats, mb: dict) -> list[KpiItem]:
        dur = gen.duration
        clients = sorted({c for (c, _s) in mb["pairs"]})
        servers = sorted({s for (_c, s) in mb["pairs"]})
        all_rtts = sorted(r for ps in mb["pairs"].values() for r in ps.rtts)
        med_rtt = percentile(all_rtts, 50)
        conns = len(set(gen.streams502.keys())) or len(gen.syn502)
        return [
            KpiItem("Длительность захвата", C.fmt_dur(dur)),
            KpiItem("Всего пакетов", C.fmt_int(gen.total_packets),
                    f"{C.fmt_bytes(gen.total_bytes)} трафика"),
            KpiItem("PDU Modbus/TCP", C.fmt_int(mb["total_pdu"]),
                    C.fmt_pct(mb["total_pdu"], gen.total_packets) + " от всех пакетов"),
            KpiItem("Клиентов", C.fmt_int(len(clients)), ", ".join(clients[:3]) +
                    ("…" if len(clients) > 3 else "")),
            KpiItem("Серверов (:502)", C.fmt_int(len(servers))),
            KpiItem("TCP-соединений к :502", C.fmt_int(conns),
                    f"SYN-попыток: {len(gen.syn502)}"),
            KpiItem("Modbus-запросов", C.fmt_int(mb["req_total"]),
                    f"ответов: {C.fmt_int(mb['resp_total'])}"),
            KpiItem("Без ответа", C.fmt_int(sum(p.no_resp for p in mb['pairs'].values())),
                    C.fmt_pct(sum(p.no_resp for p in mb["pairs"].values()), mb["req_total"])),
            KpiItem("Исключения Modbus", C.fmt_int(mb["exc_total"]),
                    C.fmt_pct(mb["exc_total"], mb["resp_total"]) + " от ответов"),
            KpiItem("Медиана отклика серверов", f"{C.fmt_ms(med_rtt)} мс"
                    if med_rtt is not None else "&mdash;"),
        ]

    # -- Секции отчёта --------------------------------------------------------

    def _build_sections(self, gen: GeneralStats, mb: dict) -> list[Section]:
        sections = []
        sections.append(self._sec_summary(gen))
        if mb["total_pdu"]:
            sections.append(self._sec_timeline(gen, mb))
            sections.append(self._sec_pairs(gen, mb))
            sections.append(self._sec_connections(gen, mb))
            gantt = self._sec_threads(gen, mb)
            if gantt:
                sections.append(gantt)
            sections.append(self._sec_fcodes(mb))
            sections.append(self._sec_registers(gen, mb))
            sections.append(self._sec_response_times(mb))
            sections.append(self._sec_errors(gen, mb))
        else:
            sections.append(Section(
                "nomodbus", "Modbus/TCP не обнаружен",
                "<p>В файле нет пакетов с протоколом Modbus/TCP (фильтр "
                "<code class=\"inline\">mbtcp</code> пуст). Проверьте, тот ли "
                "файл выбран, и захватывался ли порт 502.</p>",
                [("Проверка наличия Modbus", self._cmd('-Y "mbtcp" -c 5'))],
            ))
        return sections

    def _sec_summary(self, gen: GeneralStats) -> Section:
        rows = [
            ["Файл", C.esc(self.pcap.name)],
            ["Размер файла", C.fmt_bytes(self.pcap.stat().st_size)],
            ["SHA-256 (фрагмент)", f'<code class="inline">{self.sha256_short}&hellip;</code>'],
            ["Начало захвата", epoch_to_str(gen.first_ts)],
            ["Конец захвата", epoch_to_str(gen.last_ts)],
            ["Длительность", C.fmt_dur(gen.duration)],
            ["Всего пакетов", C.fmt_int(gen.total_packets)],
            ["Объём трафика", C.fmt_bytes(gen.total_bytes)],
            ["RST на порту 502", C.fmt_int(gen.rst502)],
            ["FIN на порту 502", C.fmt_int(gen.fin502)],
        ]
        top_rows = [
            [self._srv_cell(ip) if ip in self._srv_colors
             else f"<code class=\"inline\">{C.esc(ip)}</code>",
             f'<span class="num">{C.fmt_int(cnt)}</span>',
             f'<span class="num">{C.fmt_bytes(gen.ip_bytes_tx.get(ip, 0))}</span>',
             f'<span class="num">{C.fmt_bytes(gen.ip_bytes_rx.get(ip, 0))}</span>']
            for ip, cnt in gen.ip_pkts.most_common(6)
        ]
        body = (
            C.table_html(["Параметр", "Значение"], rows)
            + '<h3 class="subhead">Самые активные узлы (по всем протоколам)</h3>'
            + C.table_html(["Узел", "Пакетов", "Отправлено", "Получено"], top_rows)
            + '<p class="note">Роли определяются по порту 502: инициатор соединения '
              "(кто шлёт SYN / запросы) — клиент, слушающая сторона — сервер. "
              "Объём считается по длине кадров (frame.len): отправлено — узел "
              "источник, получено — узел назначения.</p>"
        )
        cmds = [
            ("Общая статистика по файлу", self._cmd("-q -z io,stat,0")),
            ("Таблица TCP-соединений", self._cmd("-q -z conv,tcp")),
            ("Первые пакеты Modbus", self._cmd('-Y "mbtcp" -c 10')),
        ]
        return Section("general", "Общая информация о захвате", body, cmds)

    def _sec_timeline(self, gen: GeneralStats, mb: dict) -> Section:
        bucket_sec = self.cfg.timeline_bucket_sec
        first_ts = gen.first_ts or 0.0
        n_buckets = (max(mb["timeline"].keys(), default=0)) + 1
        reqs = [0] * n_buckets
        excs = [0] * n_buckets
        labels = []
        for b in range(n_buckets):
            r, _resp, e = mb["timeline"].get(b, [0, 0, 0])
            reqs[b], excs[b] = r, e
            labels.append(epoch_to_str(first_ts + b * bucket_sec, time_only=True))
        svg = C.timeline_svg(labels, [reqs, excs],
                             [C.PALETTE[0], C.PALETTE[3]],
                             [f"Modbus-запросы / {bucket_sec // 60 or 1} мин",
                              "Исключения"], height=230)
        peak_b = max(range(n_buckets), key=lambda b: reqs[b]) if reqs else 0
        rate = mb["req_total"] / gen.duration if gen.duration else 0
        body = (
            '<div class="chart-box">' + svg + "</div>"
            + "<p>Средняя интенсивность: <strong>"
            + f"{rate:.1f}</strong> запросов/с; пиковая минута: <strong>{labels[peak_b]}</strong> "
            + f"({C.fmt_int(reqs[peak_b])} запросов).</p>"
            + '<p class="note">Ровная «гребёнка» одинаковой высоты — типичный признак '
              "циклического опроса SCADA/контроллера. Провалы означают паузы или потерю связи.</p>"
        )
        cmds = [
            ("Интенсивность PDU Modbus поминутно",
             self._cmd(f'-q -z io,stat,{bucket_sec},"COUNT(mbtcp.trans_id)mbtcp"')),
            ("Поиск минут с исключениями",
             self._cmd('-Y "modbus.exception_code" -T fields -e frame.number '
                       "-e frame.time -e modbus.exception_code")),
        ]
        return Section("timeline", "Активность во времени", body, cmds)

    def _sec_pairs(self, gen: GeneralStats, mb: dict) -> Section:
        rows = []
        for (cl, sv), ps in sorted(mb["pairs"].items(),
                                   key=lambda kv: kv[1].reqs, reverse=True):
            rtts = sorted(ps.rtts)
            p50, p95 = percentile(rtts, 50), percentile(rtts, 95)
            top_fc = ps.fcodes.most_common(3)
            fc_str = ", ".join(
                f"FC{f}<span class='note'>×{n}</span>" for f, n in top_fc
            )
            # максимум одновременных соединений с этим PLC (разные потоки)
            ivs = [(i["first"], i["last"]) for i in gen.streams502.values()
                   if (i["client"], i["server"]) == (cl, sv)]
            nthr = self._max_concurrent(ivs)
            thr_cell = f'<span class="num">{nthr}</span>'
            if nthr > 1:
                thr_cell = (thr_cell, "cell-hot")
            rows.append([
                f"<strong>{C.esc(cl)}</strong>", self._srv_cell(sv), thr_cell,
                f'<span class="num">{C.fmt_int(ps.reqs)}</span>',
                f'<span class="num">{C.fmt_int(ps.resps)}</span>',
                f'<span class="num">{C.fmt_int(ps.excs)}</span>',
                f'<span class="num">{C.fmt_int(ps.no_resp)}</span>',
                f'<span class="num">{C.fmt_ms(p50)}</span>',
                f'<span class="num">{C.fmt_ms(p95)}</span>',
                C.fmt_bytes(ps.bytes_), fc_str,
            ])
        body = (
            C.table_html(
                ["Клиент", "Сервер", "Потоков", "Запросы", "Ответы", "Искл.",
                 "Нет отв.", "p50, мс", "p95, мс", "Байты", "Основные функции"],
                rows, cls="pairs")
            + '<p class="note"><strong>Цвет фона в колонке «Сервер»</strong> '
              'кодирует конкретный PLC — одинаковый во всех таблицах отчёта. '
              '<strong>Потоков</strong> — максимум одновременно открытых '
              'соединений с этим сервером: у каждого соединения свой эфемерный '
              'порт клиента; значение больше 1 '
              '<span class="hot-legend">подсвечено розовым</span> и означает '
              'параллельный опрос PLC из нескольких потоков.</p>'
            + '<p class="note"><strong>p50</strong> (медиана) — половина запросов '
              'получила ответ быстрее этого времени, половина — медленнее. '
              '<strong>p95</strong> — 95% запросов уложились в это время, лишь 5% '
              'были медленнее: если p50 маленький, а p95 большой, отклик обычно '
              'быстрый, но иногда «подвисает». «Нет отв.» — запросы без '
              'сопоставленного ответа до конца захвата.</p>'
        )
        cmds = [
            ("Диалоги клиент-сервер", self._cmd("-q -z conv,tcp")),
            ("Кто отправляет запросы (клиенты)",
             self._cmd('-Y "mbtcp && tcp.dstport==502" -T fields -e ip.src | sort | uniq -c | sort -rn')),
            ("Кому адресованы запросы (серверы)",
             self._cmd('-Y "mbtcp && tcp.dstport==502" -T fields -e ip.dst | sort | uniq -c | sort -rn')),
        ]
        return Section("pairs", "Клиенты и серверы (пары обмена)", body, cmds)

    def _sec_connections(self, gen: GeneralStats, mb: dict) -> Section:
        dur = gen.duration or 1
        syn_per_min = len(gen.syn502) / (dur / 60) if dur else 0
        # короткие соединения считаем по ВСЕМ потокам: таблица ниже показывает
        # только топ-N самых долгих, они почти всегда длиннее порога
        all_durations = [
            max((i["last"] or 0) - (i["first"] or 0), 0)
            for i in gen.streams502.values()
        ]
        short_cnt = sum(1 for d in all_durations
                        if d < self.cfg.short_stream_sec)
        st_rows = []
        for st, info in sorted(gen.streams502.items(),
                               key=lambda kv: (kv[1]["last"] or 0) - (kv[1]["first"] or 0),
                               reverse=True)[: self.cfg.max_rows_per_table]:
            d = max((info["last"] or 0) - (info["first"] or 0), 0)
            st_rows.append([
                f"<code class=\"inline\">{C.esc(st)}</code>",
                f"{C.esc(info['client'])} &rarr; {self._srv_cell(info['server'])}",
                fmt_ts_offset(info["first"] or 0, gen.first_ts or 0),
                C.fmt_dur(d),
                C.fmt_int(mb["stream_reqs"].get(st, 0)),
            ])
        head = (
            f"<p>Новых подключений к порту 502 (SYN): <strong>{len(gen.syn502)}</strong> "
            f"({syn_per_min:.1f}/мин); наблюдаемых потоков: <strong>{len(gen.streams502)}</strong>; "
            f"коротких (&lt;{C.fmt_dur(self.cfg.short_stream_sec)}): <strong>{short_cnt}</strong>.</p>"
        )
        syn_detail = ""
        if gen.syn502 or any(i.get("closed_by") for i in gen.streams502.values()):
            # подключения и разрывы по парам клиент → сервер
            per_pair = Counter((c, s) for _t, c, s in gen.syn502)
            close_by_srv, close_by_cli = Counter(), Counter()
            rst_by_srv, rst_by_cli = Counter(), Counter()
            for info in gen.streams502.values():
                key = (info["client"], info["server"])
                cb = info.get("closed_by")
                if cb == info["server"]:
                    close_by_srv[key] += 1
                elif cb == info["client"]:
                    close_by_cli[key] += 1
                # RST считаем независимо от «кто закрыл первым»:
                # сброс часто идёт уже после чужого FIN
                if info.get("rst_srv"):
                    rst_by_srv[key] += 1
                if info.get("rst_cli"):
                    rst_by_cli[key] += 1
            total_syn = len(gen.syn502)
            pair_rows = []
            keys = (set(per_pair) | set(close_by_srv) | set(close_by_cli)
                    | set(rst_by_srv) | set(rst_by_cli))
            for (c, s) in sorted(keys, key=lambda k: per_pair.get(k, 0),
                                 reverse=True)[: self.cfg.max_rows_per_table]:
                n = per_pair.get((c, s), 0)

                def _cell(cnt: int, hot: bool) -> str:
                    val = f'<span class="num">{C.fmt_int(cnt)}</span>'
                    return (val, "cell-hot") if hot and cnt > 0 else val

                pair_rows.append([
                    f"<strong>{C.esc(c)}</strong>",
                    self._srv_cell(s),
                    _cell(n, True),
                    _cell(close_by_srv.get((c, s), 0), True),
                    _cell(close_by_cli.get((c, s), 0), True),
                    _cell(rst_by_srv.get((c, s), 0), True),
                    _cell(rst_by_cli.get((c, s), 0), True),
                    f'<span class="num">{C.fmt_pct(n, total_syn)}</span>',
                ])
            syn_examples = "; ".join(
                f"{fmt_ts_offset(t, gen.first_ts or 0)} ({c})"
                for t, c, _s in gen.syn502[:8]
            )
            syn_detail = (
                '<h3 class="subhead">Подключения и разрывы по парам клиент &rarr; сервер</h3>'
                + C.table_html(
                    ["Клиент", "Сервер", "Подключений",
                     "Первым закрыл: сервер", "Первым закрыл: клиент",
                     "RST от сервера", "RST от клиента", "Доля подключений"],
                    pair_rows)
                + '<p class="note"><strong>Подключений</strong> — сколько раз клиент '
                  'устанавливал TCP-соединение с сервером (SYN к порту 502); больше 1 '
                  '<span class="hot-legend">подсвечено розовым</span>: соединение '
                  'пересоздавалось, для Modbus/TCP нормой считается одно долгоживущее '
                  '(keep-alive) соединение на пару. <strong>Первым закрыл</strong> — кто '
                  'послал первый FIN или RST. <strong>RST от сервера / от клиента</strong> — '
                  'число потоков со сбросом с этой стороны независимо от того, кто закрыл '
                  'соединение первым: частый рисунок «клиент закрыл FIN-ом, но RST от '
                  'сервера есть» означает, что сервер отвечает на полузакрытие сбросом; '
                  'одиночные такие RST обычно безвредны, а массовые сбросы вне процедуры '
                  'закрытия — повод проверить таймауты простоя на сервере и сетевых '
                  'устройствах (NAT, межсетевые экраны).'
                  + (f'</p><p class="note">Первые SYN: {syn_examples}.</p>'
                     if syn_examples else '</p>')
            )
        tbl = ""
        if st_rows:
            tbl = ('<h3 class="subhead">Самые долгие соединения</h3>'
                   + C.table_html(["Поток", "Направление", "Старт", "Длительность",
                                   "Modbus-запросов"], st_rows))
        body = head + syn_detail + tbl + (
            '<p class="note">Для Modbus/TCP нормой считается одно долгоживущее соединение '
            "на пару клиент-сервер. Частые SYN — признак агрессивного пересоздания "
            "соединений или нестабильности сети.</p>"
        )
        cmds = [
            ("Число подключений по парам (колонка «Подключений»)",
             self._cmd('-Y "tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.dstport==502" '
                       "-T fields -e ip.src -e ip.dst | sort | uniq -c")),
            ("Все попытки подключения к Modbus-серверам",
             self._cmd('-Y "tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.dstport==502" '
                       "-T fields -e frame.time -e ip.src -e ip.dst -e tcp.stream")),
            ("Полностью проследить одно соединение (подставьте номер потока)",
             self._cmd("-q -z follow,tcp,ascii,0")),
            ("Кто первым завершил соединение (колонки «Разрывов…»)",
             self._cmd('-Y "(tcp.flags.fin==1 || tcp.flags.reset==1) && tcp.port==502" '
                       '-T fields -e tcp.stream -e frame.time_epoch -e ip.src '
                       "| sort -k1,1n -k2,2g | awk '!seen[$1]++ {print $3}' "
                       "| sort | uniq -c")),
            ("Закрытия и сбросы соединений",
             self._cmd('-Y "(tcp.flags.reset==1 || tcp.flags.fin==1) && tcp.port==502" '
                       "-T fields -e frame.time -e ip.src -e ip.dst -e tcp.flags")),
        ]
        return Section("connections", "Соединения TCP (порт 502)", body, cmds)

    def _sec_threads(self, gen: GeneralStats, mb: dict) -> Section | None:
        """Диаграммы Ганта: окно 10 с, зум 1 с и пачка запросов (~0,1 с)."""
        tw_list = getattr(self, "_threads", [])
        body = self._gantt_section_body(tw_list)
        if not body:
            return None
        if not tw_list:
            busy_dst, busy_port = "", -1
        else:
            r0 = tw_list[0]["rows"]
            # цель примера — многопоточный опрос: берём PLC с наибольшим
            # числом РАЗНЫХ эфемерных портов в окне (при равенстве — по числу
            # запросов); порт для второй команды — самый активный у этого PLC
            ports_cnt: dict[str, int] = {}
            ticks_cnt: dict[str, int] = {}
            for (dst, _sp), e in r0.items():
                ports_cnt[dst] = ports_cnt.get(dst, 0) + 1
                ticks_cnt[dst] = ticks_cnt.get(dst, 0) + len(e["ticks"])
            busy_dst = max(ports_cnt,
                           key=lambda d: (ports_cnt[d], ticks_cnt.get(d, 0)))
            busy_port = max(
                (sp for (d, sp) in r0 if d == busy_dst),
                key=lambda sp: len(r0[(busy_dst, sp)]["ticks"]),
                default=-1)
        # самый плотный поток окна: больше всех запросов в секунду —
        # пример циклического опроса одним соединением
        fast_pair = ("", -1)
        fast_rate = 0.0
        if tw_list:
            r0 = tw_list[0]["rows"]
            if r0:
                fast_pair, fe = max(r0.items(), key=lambda kv: len(kv[1]["ticks"]))
                fast_rate = len(fe["ticks"]) / tw_list[0]["win"]
        cmds = [
            ("Многопоточный опрос: все запросы к самому загруженному PLC — "
             "в одну секунду строки с разными эфемерными портами клиента",
             self._cmd(f'-Y "mbtcp && tcp.dstport==502 && ip.dst=={busy_dst}" '
                       "-T fields -e frame.time -e tcp.srcport "
                       "-e mbtcp.trans_id -e mbtcp.unit_id "
                       "-e modbus.func_code -e modbus.reference_num "
                       "-e modbus.word_cnt")),
            ("Один поток: время, PLC, транзакция и какие регистры читаются "
             "(подставьте эфемерный порт)",
             self._cmd(f'-Y "mbtcp && tcp.dstport==502 && '
                       f'tcp.srcport=={busy_port}" -T fields -e frame.time '
                       "-e ip.dst -e mbtcp.trans_id -e mbtcp.unit_id "
                       "-e modbus.func_code -e modbus.reference_num "
                       "-e modbus.word_cnt")),
            ("Все соединения к порту 502 с эфемеральными портами",
             self._cmd('-Y "mbtcp && tcp.dstport==502" -T fields -e tcp.stream '
                       "-e tcp.srcport -e ip.dst | sort -u")),
        ]
        if fast_rate > 1:
            cmds.append(
                ("Самый быстрый поток: PLC "
                 f"{fast_pair[0]}, порт {fast_pair[1]} — около "
                 f"{fast_rate:.0f} зап./с; интервалы между строками — период "
                 "цикла опроса",
                 self._cmd(f'-Y "mbtcp && tcp.dstport==502 && ip.dst=='
                           f'{fast_pair[0]} && tcp.srcport=={fast_pair[1]}" '
                           "-T fields -e frame.time -e mbtcp.trans_id "
                           "-e mbtcp.unit_id -e modbus.func_code "
                           "-e modbus.reference_num -e modbus.word_cnt"))
            )
        return Section("threads", "Опрос по потокам (диаграмма Ганта)", body, cmds)

    def _sec_fcodes(self, mb: dict) -> Section:
        total_req = mb["req_total"]
        bars, rows = [], []
        for fc, cnt in mb["fcode_counter"].most_common():
            label = f"FC{fc}"
            bars.append((label, cnt))
            rows.append([f"<strong>FC{fc}</strong>", fc_name(fc),
                         f'<span class="num">{C.fmt_int(cnt)}</span>',
                         f'<span class="num">{C.fmt_pct(cnt, total_req)}</span>',
                         ("чтение" if fc in READ_FCS else
                          "запись" if fc in WRITE_SINGLE_FCS | WRITE_MULTI_FCS else "прочее")])
        svg = C.vbar_svg(bars, color=C.PALETTE[0]) if len(bars) <= 12 else ""
        chart = f'<div class="chart-box">{svg}</div>' if svg else ""
        body = (
            chart
            + "<p>Всего запросов: <strong>"
            + C.fmt_int(total_req) + "</strong>. Распределение по функциям:</p>"
            + C.table_html(["Код", "Операция", "Запросов", "Доля", "Тип"], rows)
            + '<p class="note"><strong>FC3/FC4</strong> — циклический опрос телеметрии; '
              "<strong>FC6/FC16</strong> — команды управления. Перевес мелких одиночных "
              "операций над пакетными — прямая возможность для оптимизации.</p>"
        )
        cmds = [
            ("Гистограмма функций одной командой",
             self._cmd('-Y "mbtcp" -T fields -e modbus.func_code | sort | uniq -c | sort -rn')),
            ("Примеры запросов конкретной функции (здесь FC3)",
             self._cmd('-Y "mbtcp && tcp.dstport==502 && modbus.func_code==3" -c 5 -V')),
        ]
        return Section("fcodes", "Выполняемые команды (функциональные коды)", body, cmds)

    def _sec_registers(self, gen: GeneralStats, mb: dict) -> Section:
        # захваты короче минуты считаем за минуту — иначе частота завышена
        dur_min = max(gen.duration / 60.0, 1.0)
        reads_rows = []
        top_reads = sorted(mb["reads"].items(), key=lambda kv: kv[1][1], reverse=True)
        for (sv, unit, fc, start, ln), (ops, words) in \
                top_reads[: self.cfg.max_rows_per_table]:
            clients = mb["range_clients"].get((sv, unit, fc, start, ln), set())
            reads_rows.append([
                self._srv_cell(sv), C.fmt_int(unit), f"FC{fc}",
                f"<strong>{start}</strong>&ndash;<strong>{start + max(ln - 1, 0)}</strong>",
                f'<span class="num">{C.fmt_int(ln)}</span>',
                f'<span class="num">{C.fmt_int(ops)}</span>',
                f'<span class="num">{ops / dur_min:.1f}</span>',
                f'<span class="num">{C.fmt_int(words)}</span>',
                C.fmt_int(len(clients)),
            ])
        writes_rows = []
        top_writes = sorted(mb["writes"].items(), key=lambda kv: kv[1][1], reverse=True)
        for (sv, unit, fc, reg), (ops, words) in \
                top_writes[: self.cfg.max_rows_per_table]:
            writes_rows.append([
                self._srv_cell(sv), C.fmt_int(unit), f"FC{fc}",
                f"<strong>{reg}</strong>",
                f'<span class="num">{C.fmt_int(ops)}</span>',
                f'<span class="num">{C.fmt_int(words)}</span>',
            ])
        cov_html = self._coverage_html(mb)

        # Статичные регистры
        static_info = self._static_registers_html(mb)

        body = '<h3 class="subhead">Карта читаемых диапазонов (по объёму опроса)</h3>'
        body += cov_html or "<p>Чтений регистров не зафиксировано.</p>"
        if reads_rows:
            body += (
                '<h3 class="subhead">Топ читаемых диапазонов</h3>'
                + C.table_html(
                    ["Сервер", "Unit", "Функция", "Диапазон", "Рег./запрос",
                     "Запросов", "Команд/мин", "Всего слов", "Клиентов"],
                    reads_rows)
                + '<p class="note"><strong>Команд/мин</strong> — частота опроса '
                  "конкретного диапазона: сколько запросов в минуту он "
                  "получает. Сравните её с требуемой свежестью данных и "
                  "временем отклика сервера: опрос чаще, чем данные успевают "
                  "меняться (см. «статичные» регистры ниже), тратит циклы PLC "
                  "впустую.</p>"
            )
        if writes_rows:
            body += (
                '<h3 class="subhead">Топ записываемых регистров</h3>'
                + C.table_html(
                    ["Сервер", "Unit", "Функция", "Регистр", "Операций", "Слов"],
                    writes_rows)
            )
        body += static_info
        cmds = [
            ("Какие диапазоны читают (стартовый регистр и количество)",
             self._cmd('-Y "mbtcp && tcp.dstport==502 && modbus.func_code==3" '
                       "-T fields -e ip.dst -e mbtcp.unit_id "
                       "-e modbus.reference_num -e modbus.word_cnt "
                       "| sort | uniq -c | sort -rn")),
            ("Все обращения к конкретному регистру (пример: регистр 35)",
             self._cmd('-Y "modbus.reference_num==35 && modbus.func_code==3" '
                       "-T fields -e frame.number -e frame.time -e ip.src "
                       "-e modbus.regval_uint16")),
            ("Что реально возвращается из регистров",
             self._cmd('-Y "mbtcp && tcp.srcport==502 && modbus.func_code==3" '
                       "-T fields -e frame.number -e mbtcp.unit_id "
                       "-e modbus.byte_cnt -e modbus.regval_uint16 -c 20")),
            ("Все записи регистров",
             self._cmd('-Y "mbtcp && tcp.dstport==502 && (modbus.func_code==6 || '
                       'modbus.func_code==16)" -T fields -e ip.src -e ip.dst '
                       "-e modbus.func_code -e modbus.write_reference_num "
                       "-e modbus.data -c 30")),
        ]
        return Section("registers", "Карта регистров: что читают и пишут клиенты",
                       body, cmds)

    def _coverage_html(self, mb: dict) -> str:
        groups: dict[tuple, dict] = {}
        for (sv, unit, fc, start, ln), (_ops, words) in mb["reads"].items():
            g = groups.setdefault((sv, unit, fc), {})
            g[(start, start + max(ln, 1))] = words
        if not groups:
            return ""
        ranked = sorted(groups.items(), key=lambda kv: sum(kv[1].values()), reverse=True)
        chunks = []
        for (sv, unit, fc, ), spans in ranked[:6]:
            merged = merge_ranges(spans)
            max_reg = merged[-1][1] if merged else 1
            weight_max = max(spans.values(), default=0) or 1
            rng = [(s, e, words / weight_max) for s, e, words in merged]
            label = (f"{sv} · unit {unit} · FC{fc}: "
                     f"{len(merged)} непрерывных зон, {sum(e - s for s, e, _w in merged)} рег.")
            chunks.append(
                f'<div class="chart-box">{C.coverage_svg(rng, max_reg, label=label)}</div>'
            )
        return "".join(chunks) + (
            '<p class="note">Яркость полосы пропорциональна интенсивности опроса. '
            "Много коротких разрывных зон — признак того, что клиент читает "
            "разрозненные регистры множеством мелких запросов.</p>"
        )

    def _static_registers_html(self, mb: dict) -> str:
        cfg = self.cfg
        candidates = [(k, v) for k, v in mb["valtrack"].items() if v[2] >= cfg.static_reg_min_reads]
        if not candidates:
            return ""
        static = [(k, v) for k, v in candidates
                  if 100.0 * v[1] / v[2] < cfg.static_reg_change_pct]
        static.sort(key=lambda kv: kv[1][2], reverse=True)
        pct_static = C.fmt_pct(len(static), len(candidates))
        rows = []
        for (sv, unit, fc, reg), (_lv, changes, reads) in static[:10]:
            rows.append([
                self._srv_cell(sv), C.fmt_int(unit), f"FC{fc}", f"<strong>{reg}</strong>",
                f'<span class="num">{C.fmt_int(reads)}</span>',
                f'<span class="num">{C.fmt_int(changes)}</span>',
                f'<span class="num">{C.fmt_pct(changes, reads)}</span>',
            ])
        html_parts = [
            '<h3 class="subhead">«Статичные» регистры (читаются, но не меняются)</h3>',
            f"<p>Из {C.fmt_int(len(candidates))} достаточно часто читаемых регистров "
            f"<strong>{C.fmt_int(len(static))} ({pct_static})</strong> практически не меняют "
            f"значение за весь захват (менее {cfg.static_reg_change_pct:.0f}% изменений).</p>",
        ]
        if rows:
            html_parts.append(C.table_html(
                ["Сервер", "Unit", "Функция", "Регистр", "Чтений", "Изменений", "% изм."],
                rows))
        html_parts.append(
            '<p class="note">Такие регистры можно опрашивать реже, выносить в отдельный '
            "медленный цикл или читать по изменению — это разгрузит сеть и сервер.</p>")
        return "".join(html_parts)

    def _sec_response_times(self, mb: dict) -> Section:
        per_server: dict[str, list] = {}
        for (cl, sv), ps in mb["pairs"].items():
            per_server.setdefault(sv, []).extend(ps.rtts)
        rows, bars = [], []
        for sv, rtts in sorted(per_server.items()):
            srtt = sorted(rtts)
            mn = srtt[0] if srtt else None
            p50 = percentile(srtt, 50)
            p90 = percentile(srtt, 90)
            p95 = percentile(srtt, 95)
            mx = srtt[-1] if srtt else None
            rows.append([
                f"<strong>{self._srv_cell(sv)}</strong>",
                f'<span class="num">{C.fmt_ms(mn)}</span>',
                f'<span class="num">{C.fmt_ms(p50)}</span>',
                f'<span class="num">{C.fmt_ms(p90)}</span>',
                f'<span class="num">{C.fmt_ms(p95)}</span>',
                f'<span class="num">{C.fmt_ms(mx)}</span>',
                C.fmt_int(len(srtt)),
            ])
            if p95 is not None:
                bars.append((sv, p95 * 1000))
        svg = ""
        if bars:
            svg = ('<div class="chart-box">'
                   + C.hbar_svg(sorted(bars, key=lambda x: x[1], reverse=True)[:12],
                                value_fmt=lambda v: f"{v:.0f} мс")
                   + "</div>")
        body = (
            svg + "<p>Перцентили времени «запрос&ndash;ответ» по каждому серверу:</p>"
            + C.table_html(
                ["Сервер", "мин, мс", "p50, мс", "p90, мс", "p95, мс", "макс, мс",
                 "Замеров"],
                rows)
            + '<p class="note">Ориентиры: p95 до 50&nbsp;мс — отлично; 50&ndash;150&nbsp;мс — '
              "приемлемо для технологических сетей; выше — сервер перегружен либо есть "
              "сетевые проблемы. Сравните p95 со средним интервалом опроса клиентов: если "
              "интервал сопоставим с RTT, очередь сервера «захлёбывается».</p>"
        )
        cmds = [
            ("Время отклика по каждому ответу",
             self._cmd('-Y "mbtcp && tcp.srcport==502" -T fields -e ip.src '
                       "-e modbus.response_time | sort -rn | head -25")),
            ("Самые медленные обмены с контекстом",
             self._cmd('-Y "modbus.response_time > 0.1" -T fields '
                       "-e frame.number -e ip.src -e ip.dst -e modbus.response_time "
                       "-e modbus.func_code")),
        ]
        return Section("response", "Время отклика серверов", body, cmds)

    def _sec_errors(self, gen: GeneralStats, mb: dict) -> Section:
        no_resp = sum(p.no_resp for p in mb["pairs"].values())
        rows = []
        for (sv, unit, code), cnt in mb["exc_counter"].most_common(15):
            desc = EXC_NAMES.get(code, f"Код {code}")
            rows.append([
                self._srv_cell(sv), C.fmt_int(unit),
                f"<strong>{code}</strong>", desc,
                f'<span class="num">{C.fmt_int(cnt)}</span>',
            ])
        exc_tbl = ""
        if rows:
            exc_tbl = ('<h3 class="subhead">Исключения Modbus</h3>'
                       + C.table_html(["Сервер", "Unit", "Код", "Расшифровка", "Кол-во"],
                                      rows))
        tgt_rows = []
        for (cl, sv, unit, fc, ref, cnt, code), n in sorted(
                mb["exc_targets"].items(),
                key=lambda kv: kv[1], reverse=True)[:10]:
            rng = (f"{ref}&ndash;{ref + cnt - 1}" if cnt > 1 else str(ref))
            tgt_rows.append([
                f"<strong>{C.esc(cl)}</strong>",
                self._srv_cell(sv),
                C.fmt_int(unit),
                f"FC{fc}",
                f"<code class=\"inline\">{rng}</code>",
                f"<strong>{code}</strong> "
                f'<span class="note">{EXC_NAMES.get(code, "")}</span>',
                f'<span class="num">{C.fmt_int(n)}</span>',
            ])
        tgt_tbl = ""
        if tgt_rows:
            tgt_tbl = (
                '<h3 class="subhead">Кто и какими запросами вызывает '
                "ошибки</h3>"
                + C.table_html(
                    ["Клиент", "Сервер", "Unit", "Функция", "Регистр(ы)",
                     "Код", "Раз"], tgt_rows)
                + '<p class="note">Диапазон восстановлен из запроса, вызвавшего '
                  'исключение: так видно, какой именно клиент читает/пишет '
                  'несуществующие регистры. Чинится на стороне клиента '
                  '(теги/карта опроса) либо расширением карты устройства.</p>')
        rst_note = (
            f"<p>RST на порту 502: <strong>{gen.rst502}</strong>, FIN: "
            f"<strong>{gen.fin502}</strong>, запросов без ответа: <strong>{no_resp}</strong> "
            f"({C.fmt_pct(no_resp, mb['req_total'])}).</p>"
        )
        unans = ""
        if mb["unanswered_frames"]:
            frames = ", ".join(f"#{n}" for n in mb["unanswered_frames"])
            unans = f'<p class="note">Примеры кадров без ответа: {frames}.</p>'
        body = rst_note + exc_tbl + tgt_tbl + unans + (
            '<p class="note">Исключение — это штатный отказ slave-устройства: неверный адрес '
            "регистра, неподдерживаемая функция, занятость. Регулярные исключения означают "
            "ошибку конфигурации клиента или перегрузку устройства.</p>"
        )
        cmds = [
            ("Все исключения Modbus",
             self._cmd("-Y \"modbus.exception_code\" -T fields -e frame.number "
                       "-e frame.time -e ip.src -e ip.dst -e mbtcp.unit_id "
                       "-e modbus.exception_code")),
            ("Ретрансмиссии и потери TCP на порту 502",
             self._cmd('-Y "tcp.analysis.retransmission && tcp.port==502" '
                       "-T fields -e frame.number -e ip.src -e ip.dst -c 30")),
            ("Обрывы без ответа: последние запросы каждой пары",
             self._cmd('-Y "mbtcp && tcp.dstport==502" -T fields -e frame.number '
                       "-e ip.dst -e mbtcp.trans_id | tail -20")),
        ]
        return Section("errors", "Исключения и ошибки обмена", body, cmds)

    # -- Рекомендации ----------------------------------------------------------

    def _build_recommendations(self, gen: GeneralStats, mb: dict) -> list[Recommendation]:
        recs: list[Recommendation] = []
        recs.extend(self._rule_merge_small_reads(mb))
        recs.extend(self._rule_write_batching(mb))
        recs.extend(self._rule_conn_churn(gen))
        recs.extend(self._rule_slow_servers(mb))
        recs.extend(self._rule_exceptions(mb))
        recs.extend(self._rule_no_response(mb))
        recs.extend(self._rule_poll_pressure(mb))
        recs.extend(self._rule_shared_registers(mb))
        recs.extend(self._rule_static_registers(mb))
        if not recs:
            recs.append(Recommendation(
                id="ok", severity="info",
                title="Явных проблем не обнаружено",
                problem="Ни одно правило оптимизации не сработало на текущих порогах.",
                advice="Сохраните текущий профиль опроса как эталонный и повторите анализ "
                       "после изменений в сети.",
            ))
        return recs

    def _rule_merge_small_reads(self, mb: dict) -> list[Recommendation]:
        out = []
        cfg = self.cfg
        for (cl, sv, unit), items in mb["small_reads"].items():
            orig = mb["small_reads_total"][(cl, sv, unit)]
            if orig < cfg.merge_reads_min_total:
                continue
            items_sorted = sorted(items)
            batches, span_lo, span_hi, t0 = 0, None, None, None
            for ts, ref, cnt in items_sorted:
                if t0 is None or ts - t0 > cfg.merge_window_sec:
                    batches += 1
                    t0, span_lo, span_hi = ts, ref, ref + cnt
                    continue
                new_lo, new_hi = min(span_lo, ref), max(span_hi, ref + cnt)
                if new_hi - new_lo <= cfg.batch_max_words:
                    span_lo, span_hi = new_lo, new_hi
                else:
                    batches += 1
                    t0, span_lo, span_hi = ts, ref, ref + cnt
            saving_pct = 100.0 * (orig - batches) / orig
            if saving_pct >= cfg.merge_saving_pct:
                example_refs = sorted({ref for _t, ref, _c in items_sorted[:200]})[:10]
                out.append(Recommendation(
                    id=f"merge-reads-{cl}-{sv}-u{unit}".replace(".", "-").replace("/", "_"),
                    severity="warning",
                    title=f"Объединить мелкие чтения: {cl} → {sv} (unit {unit})",
                    problem=(
                        f"За захват {orig} мелких запросов чтения "
                        f"(≤{cfg.small_read_max_words} рег.) могут быть свёрнуты примерно в "
                        f"{batches} пакетных запросов — сокращение ~{saving_pct:.0f}%."
                    ),
                    advice=(
                        "Читать соседние регистры одним запросом (до "
                        f"{cfg.batch_max_words} регистров за раз): сдвинуть границы цикла "
                        "опроса, использовать FC3/FC4 с расширенным word count вместо "
                        "цепочки одиночных обращений. Это снизит нагрузку на сеть и CPU "
                        "сервера при том же наборе данных."
                    ),
                    evidence=[f"Затрагиваемые стартовые регистры (примеры): {example_refs}"],
                    commands=[
                        self._cmd('-Y "mbtcp && tcp.dstport==502 && modbus.func_code==3 && '
                                  f"ip.src=={cl} && ip.dst=={sv}\" -T fields -e frame.number "
                                  "-e frame.time -e modbus.reference_num -e modbus.word_cnt "
                                  "| head -60"),
                    ],
                ))
        return out

    def _rule_write_batching(self, mb: dict) -> list[Recommendation]:
        out = []
        cfg = self.cfg
        for (cl, sv, unit), items in mb["writes_single"].items():
            total = mb["writes_single_total"][(cl, sv, unit)]
            coil = mb["writes_coil"].get((cl, sv, unit), 0)
            if total < cfg.write_spam_min_ops:
                continue
            items_sorted = sorted(items)
            batches, span_lo, span_hi, t0 = 0, None, None, None
            for ts, ref in items_sorted:
                if t0 is None or ts - t0 > cfg.merge_window_sec:
                    batches += 1
                    t0, span_lo, span_hi = ts, ref, ref + 1
                    continue
                new_lo, new_hi = min(span_lo, ref), max(span_hi, ref + 1)
                if new_hi - new_lo <= cfg.write_batch_max_words:
                    span_lo, span_hi = new_lo, new_hi
                else:
                    batches += 1
                    t0, span_lo, span_hi = ts, ref, ref + 1
            saving_pct = 100.0 * (total - batches) / total
            if saving_pct >= cfg.merge_saving_pct:
                extra = (f" Дополнительно зафиксировано {coil} записей катушек (FC5) — "
                         "их тоже можно объединять (FC15)." ) if coil else ""
                out.append(Recommendation(
                    id=f"write-batch-{cl}-{sv}-u{unit}".replace(".", "-").replace("/", "_"),
                    severity="info",
                    title=f"Группировать одиночные записи: {cl} → {sv} (unit {unit})",
                    problem=(
                        f"{total} одиночных записей регистров (FC6) укладываются примерно в "
                        f"{batches} пакетных записей — минус ~{saving_pct:.0f}% операций.{extra}"
                    ),
                    advice=(
                        "Использовать FC16 (Write Multiple Registers): собрать значения "
                        "смежных регистров в один кадр. Меньше транзакций — меньше нагрузка "
                        "на сервер и меньше шанс гонок записи."
                    ),
                    evidence=[
                        "Примеры записываемых регистров: "
                        + str(sorted({ref for _t, ref in items_sorted[:100]})[:10])
                    ],
                    commands=[
                        self._cmd('-Y "mbtcp && tcp.dstport==502 && modbus.func_code==6" '
                                  "-T fields -e frame.time -e ip.src -e ip.dst "
                                  "-e mbtcp.unit_id -e modbus.write_reference_num "
                                  "-e modbus.data | head -40"),
                    ],
                ))
        return out

    def _rule_conn_churn(self, gen: GeneralStats) -> list[Recommendation]:
        if not gen.syn502 or not gen.duration:
            return []
        # захваты короче минуты не масштабируем: иначе пара SYN за 5 секунд
        # даст ложную «частоту» 24/мин
        dur_min = max(gen.duration / 60, 1.0)
        per_pair = Counter((c, s) for _t, c, s in gen.syn502)
        rate = len(gen.syn502) / dur_min
        hot_pairs = {cs: n for cs, n in per_pair.items()
                     if n >= self.cfg.conn_churn_pair_min}
        by_rate = rate >= self.cfg.conn_churn_per_min
        if not by_rate and not hot_pairs:
            return []
        ev = [f"{c} → {s}: {n} подключ." for (c, s), n in per_pair.most_common(5)]
        sev = ("critical" if rate >= self.cfg.conn_churn_per_min * 3
               else "warning")
        repeat = ""
        if hot_pairs and not by_rate:
            top = max(hot_pairs.values())
            repeat = (f" Повторные подключения одной пары: "
                      f"{', '.join(f'{c} → {s} ({n} раз)' for (c, s), n in
                                   sorted(hot_pairs.items(),
                                          key=lambda kv: kv[1], reverse=True)[:3])}.")
        return [Recommendation(
            id="conn-churn",
            severity=sev,
            title="Частые переподключения к Modbus-серверам",
            problem=(
                f"Обнаружено {len(gen.syn502)} новых подключений к порту 502 "
                f"({rate:.1f}/мин за {C.fmt_dur(gen.duration)}).{repeat}"
            ),
            advice=(
                "Правильнее держать соединения постоянными: одно долгоживущее "
                "TCP-соединение (keep-alive) на пару клиент-сервер на весь срок "
                "жизни задачи опроса. Каждое переподключение — это handshake, "
                "задержка первого обмена и риск таймаутов. Если переподключения "
                "вызваны таймаутами приложения — увеличьте их порог; если "
                "сбросом NAT/балансировщика — настройте время простоя сессии "
                "больше цикла опроса."
            ),
            evidence=ev,
            commands=[
                self._cmd('-Y "tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.dstport==502" '
                          "-T fields -e frame.time -e ip.src -e ip.dst -e tcp.stream"),
                self._cmd('-Y "tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.dstport==502" '
                          "-T fields -e ip.src -e ip.dst | sort | uniq -c | sort -rn"),
            ],
        )]

    def _rule_slow_servers(self, mb: dict) -> list[Recommendation]:
        out = []
        per_server: dict[str, list] = {}
        for (_cl, sv), ps in mb["pairs"].items():
            per_server.setdefault(sv, []).extend(ps.rtts)
        slow = []
        for sv, rtts in per_server.items():
            p95 = percentile(sorted(rtts), 95)
            if p95 is not None and p95 * 1000 > self.cfg.slow_rtt_p95_ms:
                slow.append((sv, p95 * 1000))
        if not slow:
            return out
        slow.sort(key=lambda x: x[1], reverse=True)
        ev = [f"{sv}: p95 = {v:.0f} мс" for sv, v in slow[:6]]
        out.append(Recommendation(
            id="slow-servers",
            severity="warning",
            title="Медленный отклик серверов",
            problem=(
                f"У {len(slow)} сервера(ов) p95 времени отклика превышает "
                f"{self.cfg.slow_rtt_p95_ms:.0f} мс."
            ),
            advice=(
                "Проверить загрузку устройств и длину очередей запросов: уменьшить "
                "параллельные транзакции на один сервер, распределить опрос во времени "
                "(джиттер интервалов), убедиться, что клиент не шлёт новый запрос до "
                "получения ответа на предыдущий."
            ),
            evidence=ev,
            commands=[
                self._cmd('-Y "mbtcp && tcp.srcport==502" -T fields -e ip.src '
                          "-e modbus.response_time | sort -k2 -rn | head -30"),
            ],
        ))
        return out

    def _rule_exceptions(self, mb: dict) -> list[Recommendation]:
        rate = 100.0 * mb["exc_total"] / mb["resp_total"] if mb["resp_total"] else 0
        if rate < self.cfg.exception_rate_pct:
            return []
        codes = Counter()
        for (_sv, _u, code), n in mb["exc_counter"].items():
            codes[code] += n
        tgt_ev = [
            f"{cl} → {sv} u{u} FC{f} @{r}..{r + c - 1 if c > 1 else r}: "
            f"{n}× {code}"
            for (cl, sv, u, f, r, c, code), n in sorted(
                mb["exc_targets"].items(), key=lambda kv: kv[1],
                reverse=True)[:3]
        ]
        ev = [
            f"код {code}: {EXC_NAMES.get(code, '?')} — {n} раз"
            for code, n in codes.most_common(5)
        ]
        sev = "critical" if rate >= self.cfg.critical_rate_pct else "warning"
        return [Recommendation(
            id="exceptions",
            severity=sev,
            title="Регулярные исключения Modbus",
            problem=(
                f"{C.fmt_int(mb['exc_total'])} ответов с исключением "
                f"({rate:.1f}% от всех ответов)."
            ),
            advice=(
                "Устранить причину по кодам: ILLEGAL DATA ADDRESS (2) — клиент читает "
                "несуществующие регистры; ILLEGAL FUNCTION (1) — функция не поддерживается; "
                "SLAVE DEVICE BUSY (6) — снизить темп опроса или разбить на группы. "
                "Каждое исключение — бесполезная транзакция, тратящая цикл сервера."
            ),
            evidence=tgt_ev + ev,
            commands=[
                self._cmd("-Y \"modbus.exception_code\" -T fields -e ip.dst "
                          "-e mbtcp.unit_id -e modbus.func_code "
                          "-e modbus.exception_code | sort | uniq -c | sort -rn"),
            ],
        )]

    def _rule_no_response(self, mb: dict) -> list[Recommendation]:
        no_resp = sum(p.no_resp for p in mb["pairs"].values())
        rate = 100.0 * no_resp / mb["req_total"] if mb["req_total"] else 0
        if rate < self.cfg.no_response_rate_pct or mb["req_total"] == 0:
            return []
        ev = []
        for (cl, sv), ps in sorted(mb["pairs"].items(), key=lambda kv: kv[1].no_resp,
                                   reverse=True):
            if ps.no_resp:
                ev.append(f"{cl} → {sv}: {ps.no_resp} без ответа")
        sev = "critical" if rate >= self.cfg.critical_rate_pct else "warning"
        return [Recommendation(
            id="no-response",
            severity=sev,
            title="Часть запросов остаётся без ответа",
            problem=(
                f"{no_resp} запросов ({rate:.1f}%) не получили ответ до конца захвата."
            ),
            advice=(
                "Причины: перегрузка сервера (очередь транзакций), потери пакетов, "
                "слишком короткий таймаут клиента. Проверьте корреляцию с моментами "
                "ретрансмиссий TCP; добавьте повторную отправку с экспоненциальной "
                "задержкой и не наращивайте частоту опроса при таймаутах. Если "
                "разрывов TCP мало, а доля безответных велика — исключите эффект "
                "измерения: неполный дамп или асимметрию маршрута, когда запросы "
                "приходят на зеркало с одной стороны, а ответы уходят другой "
                "дорогой и в дамп не попадают (подробно разобрано в ветке "
                "S7comm, правило «Запросы остаются без ответа»)."
            ),
            evidence=ev[:6],
            commands=[
                self._cmd('-Y "tcp.analysis.retransmission && tcp.port==502" '
                          "-T fields -e frame.number -e frame.time -e ip.src -e ip.dst"),
                self._cmd('-Y "mbtcp && tcp.port==502 && !modbus" -c 20'),
            ],
        )]

    def _rule_poll_pressure(self, mb: dict) -> list[Recommendation]:
        out = []
        # медиана RTT по серверу
        server_rtt: dict[str, list] = {}
        for (_cl, sv), ps in mb["pairs"].items():
            server_rtt.setdefault(sv, []).extend(ps.rtts)
        med_by_server = {
            sv: percentile(sorted(vals), 50) for sv, vals in server_rtt.items()
        }
        offenders = []
        for target in mb["poll_targets"].values():
            if len(target.intervals) < self.cfg.poll_pressure_min_intervals:
                continue
            med_iv = percentile(sorted(target.intervals), 50)
            med_rtt = med_by_server.get(target.server)
            if med_iv is not None and med_rtt is not None and med_iv <= self.cfg.poll_pressure_factor * med_rtt:
                offenders.append((target, med_iv, med_rtt))
        if not offenders:
            return out
        offenders.sort(key=lambda x: x[1])
        t, iv, rtt = offenders[0]
        ev = [
            f"{tg.client} → {tg.server} u{tg.unit} FC{tg.fc} "
            f"[{tg.ref}..{tg.ref + max(tg.cnt - 1, 0)}]: интервал {iv_ms:.0f} мс при RTT {rt_ms:.0f} мс"
            for tg, iv_ms, rt_ms in offenders[:6]
        ]
        out.append(Recommendation(
            id="poll-pressure",
            severity="warning",
            title=f"Интервал опроса сопоставим со временем отклика ({len(offenders)} целей)",
            problem=(
                f"Например, цель {t.client} → {t.server} (unit {t.unit}, FC{t.fc}, "
                f"регистры {t.ref}+) опрашивается в среднем каждые "
                f"{C.fmt_ms(iv)} мс, а сервер отвечает медианно за {C.fmt_ms(rtt)} мс."
            ),
            advice=(
                f"Когда период опроса ≤ {self.cfg.poll_pressure_factor:g}×RTT, "
                "транзакции встают в очередь друг за другом: "
                "латентность растёт лавинообразно. Увеличьте интервал, сократите количество "
                "целей у этого клиента либо ускорьте сервер; полезен джиттер ±20%, чтобы "
                "развести клиентов по фазе."
            ),
            evidence=ev,
            commands=[
                self._cmd('-Y "mbtcp && tcp.dstport==502 && '
                          f"ip.src=={t.client} && ip.dst=={t.server}\" "
                          "-T fields -e frame.time -e modbus.reference_num "
                          "-e modbus.word_cnt | awk 'NR>1{print $1}' | head -30"),
                self._cmd('-Y "mbtcp && tcp.srcport==502 && '
                          f"ip.src=={t.server}\" -T fields -e frame.number "
                          "-e modbus.response_time | head -30"),
            ],
        ))
        return out

    def _rule_shared_registers(self, mb: dict) -> list[Recommendation]:
        shared = []
        for (sv, unit, fc, start, ln), clients in mb["range_clients"].items():
            if len(clients) >= 2:
                ops, words = mb["reads"][(sv, unit, fc, start, ln)]
                shared.append((sv, unit, fc, start, ln, len(clients), ops))
        if not shared:
            return []
        shared.sort(key=lambda x: x[5], reverse=True)
        sv, unit, fc, start, ln, ncli, ops = shared[0]
        ev = [
            f"{s} u{u} FC{f} [{st}..{st + max(l - 1, 0)}]: клиентов {nc}, запросов {o}"
            for s, u, f, st, l, nc, o in shared[:6]
        ]
        return [Recommendation(
            id="shared-registers",
            severity="info",
            title=f"Одни и те же данные опрашивают {ncli} и более клиентов",
            problem=(
                f"Диапазон [{start}..{start + max(ln - 1, 0)}] (FC{fc}, unit {unit}, "
                f"сервер {sv}) читают {ncli} разных клиентов, суммарно {ops} запросов."
            ),
            advice=(
                "Дублирующий опрос умножает нагрузку на устройство. Варианты: промежуточный "
                "агрегатор/кэш (gateway), публикация данных через брокер, либо перенос "
                "вторичного клиента на чтение уже собранных данных из SCADA."
            ),
            evidence=ev,
            commands=[
                self._cmd('-Y "mbtcp && tcp.dstport==502 && '
                          f"modbus.reference_num=={start}\" -T fields -e ip.src -e ip.dst "
                          "-e mbtcp.unit_id | sort | uniq -c | sort -rn"),
            ],
        )]

    def _rule_static_registers(self, mb: dict) -> list[Recommendation]:
        cfg = self.cfg
        candidates = [(k, v) for k, v in mb["valtrack"].items() if v[2] >= cfg.static_reg_min_reads]
        if len(candidates) < cfg.static_reg_min_candidates:
            return []
        static = [(k, v) for k, v in candidates
                  if 100.0 * v[1] / v[2] < cfg.static_reg_change_pct]
        share = 100.0 * len(static) / len(candidates)
        if share < cfg.static_share_pct:
            return []
        static.sort(key=lambda kv: kv[1][2], reverse=True)
        sv, unit, fc, reg = static[0][0]
        return [Recommendation(
            id="static-registers",
            severity="info",
            title=f"~{share:.0f}% часто читаемых регистров не меняются",
            problem=(
                f"{len(static)} из {len(candidates)} регистров меняются реже чем в "
                f"{cfg.static_reg_change_pct:.0f}% случаев, но продолжают опрашиваться "
                "в общем цикле. Например, регистр "
                f"{reg} (сервер {sv}, unit {unit}, FC{fc}) прочитан {static[0][1][2]} раз "
                f"без изменений ({static[0][1][1]} изменений)."
            ),
            advice=(
                "Разделить карту опроса на быстрый контур (динамичные величины) и медленный "
                "(конфигурация, уставки): статичные регистры читать раз в N минут или по "
                "событию изменения. Это сокращает трафик и время цикла без потери актуальности."
            ),
            evidence=[
                f"Топ статичных: {static[0][0]} ({static[0][1][2]} чтений), "
                f"{static[1][0]} ({static[1][1][2]} чтений)" if len(static) > 1 else ""
            ],
            commands=[
                self._cmd('-Y "modbus.reference_num=='
                          f"{reg} && modbus.func_code=={fc}\" -T fields "
                          "-e frame.time -e ip.dst -e modbus.regval_uint16 | head -40"),
            ],
        )]


def merge_ranges(spans: dict[tuple[int, int], float]) -> list[tuple[int, int, float]]:
    """Слить перекрывающиеся/смежные диапазоны, просуммировав вес."""
    items = sorted(spans.items())
    merged: list[list[int]] = []
    weights: dict[tuple[int, int], float] = {}
    for (s, e), w in items:
        if merged and s <= merged[-1][1]:
            prev = merged[-1]
            if e > prev[1]:
                old_key = (prev[0], prev[1])
                old_w = weights.pop(old_key, 0.0)
                prev[1] = e
                weights[(prev[0], e)] = old_w + w
            else:
                key_now = (prev[0], prev[1])
                weights[key_now] = weights.get(key_now, 0.0) + w
        else:
            merged.append([s, e])
            weights[(s, e)] = w
    return [(s, e, weights.get((s, e), 0.0)) for s, e in merged]
