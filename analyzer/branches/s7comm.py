"""Ветка анализа S7comm (Siemens S7 Communication, TCP/102).

Собирает метрики обмена клиент-SCADA/HMI с PLC Siemens: подключения,
состав функций (чтение/запись переменных, установка связи), области памяти,
времена отклика по сопоставлению Job/Ack_Data (s7comm.header.pduref),
коды ошибок элементов — и формирует рекомендации по оптимизации.
"""

from __future__ import annotations

import hashlib
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
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
    Section,
    sort_recommendations,
)

PORT = 102  # стандартный порт S7comm

# Режимы сообщения (ROSCTR)
ROSCTR_NAMES = {
    "1": "Job (запрос)",
    "2": "Ack (подтверждение)",
    "3": "Ack_Data (ответ с данными)",
    "7": "Userdata",
}

# Функции параметра (s7comm.param.func)
FUNC_NAMES = {
    "0xf0": "Установка связи (Setup communication)",
    "0x04": "Чтение переменных (Read Var)",
    "0x05": "Запись переменных (Write Var)",
    "0x00": "Сервис PLC/системные функции",
    "0x1a": "Запрос загрузки блока (Request Download)",
    "0x1b": "Загрузка блока (Download Block)",
    "0x1c": "Конец загрузки (Download End)",
    "0x1d": "Начало выгрузки (Start Upload)",
    "0x1e": "Выгрузка (Upload)",
    "0x1f": "Конец выгрузки (Upload End)",
    "0x28": "Управление PLC (PLC Control)",
    "0x29": "Останов PLC (PLC Stop)",
}

# Области памяти (s7comm.param.item.area)
AREA_NAMES = {
    "0x81": "I — входы (Process Input)",
    "0x82": "Q — выходы (Process Output)",
    "0x83": "M — меркеры (Flags)",
    "0x84": "DB — блок данных",
    "0x85": "DI — блок данных экземпляра",
    "0x86": "L — локальные данные",
    "0x87": "V — предыдущий PLC (S5)",
    "0x1c": "P — периферия (PE/PA)",
    "0x1d": "C — счётчики (S5)",
    "0x1e": "T — таймеры (S5)",
    "0x03": "System failure/диагностика",
}

# Коды возврата элемента данных (s7comm.data.returncode)
RETCODE_NAMES = {
    "0xff": "OK / зарезервировано",
    "0x00": "OK (зарезервировано)",
    "0x01": "Reserved",
    "0x05": "Ошибка адреса (Address Out Of Range)",
    "0x06": "Тип данных не разрешён (Data Type Not Allowed)",
    "0x07": "Тип данных не поддерживается",
    "0x08": "Объект ещё не существует",
    "0x09": "Объект уже существует",
    "0x0a": "Объект не существует (Object Does Not Exist)",
    "0x0b": "Данные не помещаются (Insufficient Memory)",
}


# ---------------------------------------------------------------------------
# Утилиты
# ---------------------------------------------------------------------------

def _to_int(value, default=-1):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _truthy(v: str) -> bool:
    return v.strip() in {"1", "True", "true"}


def _first(value: str) -> str:
    """Первое значение из агрегированного tshark поля (разделитель ',')."""
    return (value or "").split(",")[0].strip().lower()


def _percentile(sorted_vals, p: float):
    if not sorted_vals:
        return None
    k = (len(sorted_vals) - 1) * p / 100.0
    lo, hi = int(k // 1), int(-(-k // 1))
    return sorted_vals[lo] if lo == hi else \
        sorted_vals[lo] * (hi - k) + sorted_vals[hi] * (k - lo)


def _epoch_to_str(ts: float | None, time_only: bool = False) -> str:
    if ts is None:
        return "&mdash;"
    dt = datetime.fromtimestamp(ts, tz=timezone.utc).astimezone()
    return (dt.strftime("%H:%M:%S") if time_only
            else dt.strftime("%Y-%m-%d %H:%M:%S"))


def _fmt_ts_offset(ts: float, first_ts: float) -> str:
    d = max(ts - first_ts, 0)
    m, s = divmod(int(d), 60)
    h, m = divmod(m, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


# ---------------------------------------------------------------------------
# Структуры данных
# ---------------------------------------------------------------------------

class Req:
    """Запрос Job (rosctr=1) в ожидании Ack_Data."""

    __slots__ = ("ts", "stream", "pair")

    def __init__(self, ts, stream, pair):
        self.ts = ts
        self.stream = stream
        self.pair = pair          # (client, plc)


@dataclass
class PairStats:
    reqs: int = 0
    resps: int = 0
    errors: int = 0          # ответы с кодом ошибки элемента/заголовка
    no_resp: int = 0
    bytes_: int = 0
    streams: set = field(default_factory=set)
    fcodes: Counter = field(default_factory=Counter)
    rtts: deque = field(default_factory=lambda: deque())
    items: int = 0           # всего элементов в запросах
    single_item_reqs: int = 0


@dataclass
class GeneralStats:
    total_packets: int = 0
    total_bytes: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    syn102: list = field(default_factory=list)          # (ts, client, server)
    rst102: int = 0
    fin102: int = 0
    streams102: dict = field(default_factory=dict)      # stream -> dict(...)
    ip_pkts: Counter = field(default_factory=Counter)

    @property
    def duration(self) -> float:
        if self.first_ts is not None and self.last_ts is not None:
            return max(self.last_ts - self.first_ts, 0.0)
        return 0.0


# ---------------------------------------------------------------------------
# Анализатор
# ---------------------------------------------------------------------------

class S7CommAnalyzer(BaseBranch):
    name = "s7comm"
    title = "Анализ S7comm (Siemens)"
    description = (
        "Клиенты и PLC, функции протокола, области памяти, времена отклика "
        "(Job/Ack_Data), коды ошибок элементов и рекомендации."
    )

    def analyze(
        self,
        pcap_path: Path,
        cfg: Config,
        progress: ProgressCb = lambda msg: None,
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

        progress("Проход 1/2: общий обзор TCP/IP…")
        gen = self._pass_general()

        result.capture_start_ts = gen.first_ts

        progress("Проход 2/2: разбор S7comm…")
        s7 = self._pass_s7(gen)

        # тёплые цвета серверов (PLC): единая раскраска таблиц, диаграмм
        # и легенды шапки отчёта
        self._set_servers(p for (_c, p) in s7["pairs"])

        result.kpi = self._build_kpi(gen, s7)
        result.sections = self._build_sections(gen, s7)
        result.recommendations = self._build_recommendations(gen, s7)
        result.server_colors = dict(self._srv_colors)
        return result

    # -- вспомогательное ----------------------------------------------------

    @staticmethod
    def _sha256_short(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()[:16]

    def _cmd(self, args_tail: str) -> str:
        # в командах для пользователя — только имя файла: он может лежать
        # где угодно, полный путь нужен лишь самому анализатору
        return f"tshark -r {self.pcap.name} {args_tail}"

    @staticmethod
    def _roles(sport: int, dport: int, src: str, dst: str) -> tuple[str, str]:
        """(клиент, сервер) по положению порта 102."""
        if sport == PORT and dport != PORT:
            return dst, src
        return src, dst

    # -- Проход 1: общие сведения -------------------------------------------

    FIELDS_GENERAL = [
        "frame.time_epoch", "frame.len", "ip.src", "ip.dst",
        "tcp.stream", "tcp.srcport", "tcp.dstport",
        "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.reset", "tcp.flags.fin",
    ]

    def _pass_general(self) -> GeneralStats:
        g = GeneralStats()
        rows = stream_fields(self.tshark, self.pcap_str, self.FIELDS_GENERAL)
        for r in rows:
            g.total_packets += 1
            g.total_bytes += _to_int(r.get("frame.len"), 0)
            ts = _to_float(r.get("frame.time_epoch"))
            if ts is not None:
                if g.first_ts is None:
                    g.first_ts = ts
                g.last_ts = ts
            src = r.get("ip.src", "")
            dst = r.get("ip.dst", "")
            if src:
                g.ip_pkts[src] += 1
            sport = _to_int(r.get("tcp.srcport"), -1)
            dport = _to_int(r.get("tcp.dstport"), -1)
            if sport < 0 and dport < 0:
                continue
            is_syn = _truthy(r.get("tcp.flags.syn", ""))
            is_ack = _truthy(r.get("tcp.flags.ack", ""))
            on_port = sport == PORT or dport == PORT
            if on_port and _truthy(r.get("tcp.flags.reset", "")):
                g.rst102 += 1
            if on_port and _truthy(r.get("tcp.flags.fin", "")):
                g.fin102 += 1
            if is_syn and not is_ack and dport == PORT and src:
                g.syn102.append((ts or 0.0, src, dst))
            if on_port:
                st = r.get("tcp.stream", "")
                if st != "":
                    client, server = self._roles(sport, dport, src, dst)
                    info = g.streams102.setdefault(
                        st, {"client": client, "server": server,
                             "first": ts, "last": ts}
                    )
                    if ts is not None:
                        if info["first"] is None or ts < info["first"]:
                            info["first"] = ts
                        if info["last"] is None or ts > info["last"]:
                            info["last"] = ts
                    if "closed_by" not in info and (
                            _truthy(r.get("tcp.flags.fin", ""))
                            or _truthy(r.get("tcp.flags.reset", ""))):
                        info["closed_by"] = src
        return g

    # -- Проход 2: S7comm -----------------------------------------------------

    FIELDS_S7 = [
        "frame.number", "frame.time_epoch", "frame.len",
        "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "tcp.stream",
        "s7comm.header.rosctr", "s7comm.header.pduref",
        "s7comm.header.errcls", "s7comm.header.errcod",
        "s7comm.param.func", "s7comm.param.itemcount",
        "s7comm.param.item.area", "s7comm.param.item.db",
        "s7comm.data.returncode", "s7comm.data.length",
    ]

    def _pass_s7(self, gen: GeneralStats) -> dict:
        s7 = {
            "total_pdu": 0,
            "req_total": 0,
            "resp_total": 0,
            "userdata_total": 0,
            "err_total": 0,
            "setup_comms": 0,
            "pairs": {},                  # (client, plc) -> PairStats
            "fcodes_all": Counter(),      # func -> число сообщений
            "areas": Counter(),           # (area, db) -> число чтений элементов
            "retcodes": Counter(),       # код возврата -> число элементов
            "timeline": {},               # bucket -> [reqs, errs]
            "pending": {},                # (stream, pduref) -> [Req, ...]
            "stream_reqs": Counter(),
        }
        rows = stream_fields(self.tshark, self.pcap_str, self.FIELDS_S7,
                             display_filter="s7comm")
        first_ts = gen.first_ts or 0.0
        bucket_sec = self.cfg.timeline_bucket_sec

        for r in rows:
            s7["total_pdu"] += 1
            ts = _to_float(r.get("frame.time_epoch"))
            rosctr = _first(r.get("s7comm.header.rosctr"))
            pduref = _first(r.get("s7comm.header.pduref"))
            func = _first(r.get("s7comm.param.func"))
            src = r.get("ip.src", "")
            dst = r.get("ip.dst", "")
            sport = _to_int(r.get("tcp.srcport"), -1)
            dport = _to_int(r.get("tcp.dstport"), -1)
            st = r.get("tcp.stream", "")
            client, plc = self._roles(sport, dport, src, dst)
            key = (client, plc)

            ps = s7["pairs"].setdefault(key, PairStats())
            ps.bytes_ += _to_int(r.get("frame.len"), 0)
            if st != "":
                ps.streams.add(st)

            errcls = _first(r.get("s7comm.header.errcls"))

            if rosctr == "1":
                # Запрос Job
                s7["req_total"] += 1
                ps.reqs += 1
                if func:
                    ps.fcodes[func] += 1
                    s7["fcodes_all"][func] += 1
                if func == "0xf0":
                    s7["setup_comms"] += 1
                itemcnt = _to_int(_first(r.get("s7comm.param.itemcount")), 0)
                ps.items += max(itemcnt, 0)
                if itemcnt <= 1:
                    ps.single_item_reqs += 1
                area = _first(r.get("s7comm.param.item.area"))
                if area:
                    db = _first(r.get("s7comm.param.item.db"))
                    s7["areas"][(area, db)] += max(itemcnt, 1)
                if ts is not None and st != "":
                    s7.setdefault("pending", {}).setdefault(
                        (st, pduref), []).append(Req(ts, st, key))
                b = int((ts or first_ts) - first_ts) // bucket_sec
                s7["timeline"].setdefault(b, [0, 0])[0] += 1

            elif rosctr == "3":
                # Ответ Ack_Data
                s7["resp_total"] += 1
                ps.resps += 1
                waiters = s7.get("pending", {}).get((st, pduref))
                if waiters:
                    req = waiters.pop(0)
                    if not waiters:
                        del s7["pending"][(st, pduref)]
                    if req.ts is not None and ts is not None:
                        # RTT хранится в СЕКУНДАХ (fmt_ms сам переводит в мс)
                        ps.rtts.append(max(ts - req.ts, 0.0))
                has_err = (errcls not in ("", "0x0", "0x00"))
                rets = [v.strip().lower()
                        for v in (r.get("s7comm.data.returncode") or "").split(",")
                        if v.strip()]
                bad_rets = [v for v in rets
                            if v not in ("0xff", "0x00", "")]
                for v in rets:
                    s7["retcodes"][v] += 1
                if has_err or bad_rets:
                    ps.errors += 1
                    s7["err_total"] += 1
                    b = int((ts or first_ts) - first_ts) // bucket_sec
                    s7["timeline"].setdefault(b, [0, 0])[1] += 1

            elif rosctr == "7":
                s7["userdata_total"] += 1

        # запросы, оставшиеся без ответа до конца захвата
        for waiters in list(s7.get("pending", {}).values()):
            for req in waiters:
                ps = s7["pairs"].get(req.pair)
                if ps is not None:
                    ps.no_resp += 1
        return s7

    # -- Сборка результата ----------------------------------------------------

    def _build_kpi(self, gen: GeneralStats, s7: dict) -> list[KpiItem]:
        dur = gen.duration
        clients = sorted({c for (c, _s) in s7["pairs"]})
        plcs = sorted({p for (_c, p) in s7["pairs"]})
        all_rtts = sorted(t for ps in s7["pairs"].values() for t in ps.rtts)
        med_rtt = _percentile(all_rtts, 50)
        conns = len(gen.streams102) or len(gen.syn102)
        no_resp = sum(p.no_resp for p in s7["pairs"].values())
        return [
            KpiItem("Длительность захвата", C.fmt_dur(dur)),
            KpiItem("Всего пакетов", C.fmt_int(gen.total_packets),
                    f"{C.fmt_bytes(gen.total_bytes)} трафика"),
            KpiItem("PDU S7comm", C.fmt_int(s7["total_pdu"]),
                    C.fmt_pct(s7["total_pdu"], gen.total_packets) + " от всех пакетов"),
            KpiItem("Клиентов", C.fmt_int(len(clients)),
                    ", ".join(clients[:3]) + ("…" if len(clients) > 3 else "")),
            KpiItem("PLC (:102)", C.fmt_int(len(plcs))),
            KpiItem("TCP-соединений к :102", C.fmt_int(conns),
                    f"SYN-попыток: {len(gen.syn102)}"),
            KpiItem("S7-запросов (Job)", C.fmt_int(s7["req_total"]),
                    f"ответов: {C.fmt_int(s7['resp_total'])}"),
            KpiItem("Сообщений Userdata", C.fmt_int(s7["userdata_total"]),
                    "диагностика/SZL и пр."),
            KpiItem("Ошибок в ответах", C.fmt_int(s7["err_total"]),
                    (C.fmt_pct(s7["err_total"], s7["resp_total"]) +
                     " от ответов") if s7["resp_total"] else ""),
            KpiItem("Медиана отклика PLC", f"{C.fmt_ms(med_rtt)} мс"
                    if med_rtt is not None else "&mdash;"),
        ]

    def _build_sections(self, gen: GeneralStats, s7: dict) -> list[Section]:
        sections = [self._sec_summary(gen)]
        if s7["total_pdu"]:
            sections.append(self._sec_timeline(gen, s7))
            sections.append(self._sec_pairs(gen, s7))
            sections.append(self._sec_connections(gen, s7))
            sections.append(self._sec_functions(s7))
            sections.append(self._sec_areas(s7))
            sections.append(self._sec_errors(s7))
        else:
            sections.append(Section(
                "nos7", "S7comm не обнаружен",
                "<p>В файле нет пакетов с протоколом S7comm (фильтр "
                "<code class=\"inline\">s7comm</code> пуст). Проверьте, тот ли "
                "файл выбран и захватывался ли порт 102.</p>",
                [("Проверка наличия S7comm", self._cmd('-Y "s7comm" -c 5'))],
            ))
        return sections

    # -- Секции ---------------------------------------------------------------

    def _sec_summary(self, gen: GeneralStats) -> Section:
        rows = [
            ["Файл", C.esc(self.pcap.name)],
            ["Размер файла", C.fmt_bytes(self.pcap.stat().st_size)],
            ["SHA-256 (фрагмент)",
             f'<code class="inline">{self.sha256_short}&hellip;</code>'],
            ["Начало захвата", _epoch_to_str(gen.first_ts)],
            ["Конец захвата", _epoch_to_str(gen.last_ts)],
            ["Длительность", C.fmt_dur(gen.duration)],
            ["Всего пакетов", C.fmt_int(gen.total_packets)],
            ["Объём трафика", C.fmt_bytes(gen.total_bytes)],
            [f"RST на порту {PORT}", C.fmt_int(gen.rst102)],
            [f"FIN на порту {PORT}", C.fmt_int(gen.fin102)],
        ]
        top = "".join(
            "<li>"
            + (self._srv_cell(ip) if ip in self._srv_colors
               else f"<code class=\"inline\">{C.esc(ip)}</code>")
            + f" — {C.fmt_int(cnt)} пак.</li>"
            for ip, cnt in gen.ip_pkts.most_common(6)
        )
        body = (
            C.table_html(["Параметр", "Значение"], rows)
            + '<h3 class="subhead">Самые активные узлы (по всем протоколам)</h3>'
            + f"<ul>{top}</ul>"
            + '<p class="note">Роли определяются по порту 102: сторона с портом '
              "102 — PLC (сервер), инициатор соединения — клиент "
              "(SCADA/HMI/TIA Portal).</p>"
        )
        cmds = [
            ("Общая статистика по файлу", self._cmd("-q -z io,stat,0")),
            ("Таблица TCP-соединений", self._cmd("-q -z conv,tcp")),
            ("Первые пакеты S7comm", self._cmd('-Y "s7comm" -c 10')),
        ]
        return Section("general", "Общая информация о захвате", body, cmds)

    def _sec_timeline(self, gen: GeneralStats, s7: dict) -> Section:
        bucket_sec = self.cfg.timeline_bucket_sec
        first_ts = gen.first_ts or 0.0
        n_buckets = (max(s7["timeline"].keys(), default=0)) + 1
        reqs = [0] * n_buckets
        errs = [0] * n_buckets
        labels = []
        for b in range(n_buckets):
            rq, _rp, er = (*s7["timeline"].get(b, (0, 0)), 0)[:3]
            reqs[b], errs[b] = rq, er
            labels.append(_epoch_to_str(first_ts + b * bucket_sec,
                                        time_only=True))
        svg = C.timeline_svg(labels, [reqs, errs],
                             [C.PALETTE[0], C.PALETTE[3]],
                             [f"S7-запросы / {bucket_sec // 60 or 1} мин",
                              "Ошибки"], height=230)
        peak_b = max(range(n_buckets), key=lambda b: reqs[b]) if reqs else 0
        rate = s7["req_total"] / gen.duration if gen.duration else 0
        body = (
            '<div class="chart-box">' + svg + "</div>"
            + "<p>Средняя интенсивность: <strong>" + f"{rate:.1f}</strong> "
            + "запросов/с; пик: <strong>" + f"{labels[peak_b]}</strong> "
            + f"({C.fmt_int(reqs[peak_b])} запросов).</p>"
            + '<p class="note">Циклический опрос HMI даёт ровную «гребёнку» '
              "одинаковой высоты; провалы — паузы опроса или потеря связи.</p>"
        )
        cmds = [
            ("Интенсивность PDU S7comm поминутно",
             self._cmd(f'-q -z io,stat,{bucket_sec},"COUNT(s7comm)s7comm"')),
            ("Поиск минут с ошибками",
             self._cmd('-Y "s7comm && s7comm.data.returncode != 0xff" '
                       "-T fields -e frame.number -e frame.time "
                       "-e s7comm.data.returncode")),
        ]
        return Section("timeline", "Активность во времени", body, cmds)

    def _sec_pairs(self, gen: GeneralStats, s7: dict) -> Section:
        rows = []
        for (cl, sv), ps in sorted(s7["pairs"].items(),
                                   key=lambda kv: kv[1].reqs, reverse=True):
            rtts = sorted(ps.rtts)
            p50 = _percentile(rtts, 50)
            p95 = _percentile(rtts, 95)
            fc_str = ", ".join(
                f"{FUNC_NAMES.get(f, f)}<span class='note'>×{n}</span>"
                for f, n in ps.fcodes.most_common(3)
            )
            rows.append([
                f"<strong>{C.esc(cl)}</strong>", self._srv_cell(sv),
                f'<span class="num">{C.fmt_int(ps.reqs)}</span>',
                f'<span class="num">{C.fmt_int(ps.resps)}</span>',
                f'<span class="num">{C.fmt_int(ps.errors)}</span>',
                f'<span class="num">{C.fmt_int(ps.items)}</span>',
                f'<span class="num">{C.fmt_ms(p50)}</span>',
                f'<span class="num">{C.fmt_ms(p95)}</span>',
                C.fmt_bytes(ps.bytes_), fc_str,
            ])
        body = (
            C.table_html(
                ["Клиент", "PLC", "Запросы", "Ответы", "Ошибки",
                 "Элементов", "p50, мс", "p95, мс", "Байты",
                 "Основные функции"],
                rows, cls="pairs")
            + '<p class="note"><strong>p50</strong> (медиана) — половина запросов '
              "получила ответ быстрее этого времени, половина — медленнее. "
              "<strong>p95</strong> — 95% запросов уложились в это время, лишь 5% "
              "были медленнее: если p50 маленький, а p95 большой, отклик обычно "
              "быстрый, но иногда «подвисает». «Элементов» — суммарное число "
              "переменных (элементов Read/Write Var) в запросах.</p>"
        )
        cmds = [
            ("Диалоги клиент-PLC", self._cmd("-q -z conv,tcp")),
            ("Кто отправляет запросы (клиенты)",
             self._cmd('-Y "s7comm && s7comm.header.rosctr==1" '
                       "-T fields -e ip.src | sort | uniq -c | sort -rn")),
            ("Адреса PLC (порт 102)",
             self._cmd(f'-Y "s7comm && tcp.dstport=={PORT}" '
                       "-T fields -e ip.dst | sort | uniq -c | sort -rn")),
        ]
        return Section("pairs", "Клиенты и PLC (пары обмена)", body, cmds)

    def _sec_connections(self, gen: GeneralStats, s7: dict) -> Section:
        dur = gen.duration or 1
        syn_per_min = len(gen.syn102) / (dur / 60) if dur else 0
        durations = []
        st_rows = []
        for st, info in sorted(
                gen.streams102.items(),
                key=lambda kv: (kv[1]["last"] or 0) - (kv[1]["first"] or 0),
                reverse=True)[: self.cfg.max_rows_per_table]:
            d = max((info["last"] or 0) - (info["first"] or 0), 0)
            durations.append(d)
            st_rows.append([
                f"<code class=\"inline\">{C.esc(st)}</code>",
                f"{C.esc(info['client'])} &rarr; {self._srv_cell(info['server'])}",
                _fmt_ts_offset(info["first"] or 0, gen.first_ts or 0),
                C.fmt_dur(d),
            ])
        short_cnt = sum(1 for d in durations if d < self.cfg.short_stream_sec)
        head = (
            f"<p>Новых подключений к порту {PORT} (SYN): "
            f"<strong>{len(gen.syn102)}</strong> ({syn_per_min:.1f}/мин); "
            f"наблюдаемых потоков: <strong>{len(gen.streams102)}</strong>; "
            f"коротких (&lt;{C.fmt_dur(self.cfg.short_stream_sec)}): "
            f"<strong>{short_cnt}</strong>.</p>"
        )
        detail = ""
        per_pair = Counter((c, s) for _t, c, s in gen.syn102)
        close_by_srv: Counter = Counter()
        close_by_cli: Counter = Counter()
        for info in gen.streams102.values():
            cb = info.get("closed_by")
            if not cb:
                continue
            k = (info["client"], info["server"])
            if cb == info["server"]:
                close_by_srv[k] += 1
            elif cb == info["client"]:
                close_by_cli[k] += 1
        keys = set(per_pair) | set(close_by_srv) | set(close_by_cli)
        if keys:
            total_syn = len(gen.syn102)
            pair_rows = []
            for (c, s) in sorted(keys, key=lambda k: per_pair.get(k, 0),
                                 reverse=True)[: self.cfg.max_rows_per_table]:
                n = per_pair.get((c, s), 0)

                def cell(cnt: int, hot: bool) -> str:
                    val = f'<span class="num">{C.fmt_int(cnt)}</span>'
                    return (val, "cell-hot") if hot and cnt > 0 else val

                pair_rows.append([
                    f"<strong>{C.esc(c)}</strong>", self._srv_cell(s),
                    cell(n, True),
                    cell(close_by_srv.get((c, s), 0), True),
                    cell(close_by_cli.get((c, s), 0), True),
                    f'<span class="num">'
                    f'{C.fmt_pct(n, total_syn) if total_syn else "—"}</span>',
                ])
            detail = (
                '<h3 class="subhead">Подключения и разрывы по парам '
                "клиент &rarr; PLC</h3>"
                + C.table_html(
                    ["Клиент", "PLC", "Подключений", "Разрывов сервером",
                     "Разрывов клиентом", "Доля подключений"],
                    pair_rows)
                + '<p class="note"><strong>Подключений</strong> — сколько раз '
                  "клиент устанавливал TCP-соединение с PLC (SYN к порту 102); "
                  'больше 1 <span class="hot-legend">подсвечено розовым</span>: '
                  "соединение пересоздавалось, нормой считается одно долгоживущее "
                  "(keep-alive) соединение на пару. <strong>Разрывов сервером/"
                  "клиентом</strong> — кто первым послал FIN или RST; розовым "
                  "отмечены значения больше нуля. Разрывы со стороны PLC — повод "
                  "проверить таймауты простоя на контроллере и сетевом "
                  "оборудовании (NAT, межсетевые экраны).</p>"
            )
        tbl = ""
        if st_rows:
            tbl = ('<h3 class="subhead">Самые долгие соединения</h3>'
                   + C.table_html(["Поток", "Направление", "Старт",
                                   "Длительность"], st_rows))
        body = head + detail + tbl + (
            '<p class="note">Для S7comm нормой считается одно долгоживущее '
            "соединение на пару клиент-PLC. Частые SYN — признак пересоздания "
            "соединений, нестабильной сети или агрессивного таймаута HMI.</p>"
        )
        cmds = [
            ("Число подключений по парам (колонка «Подключений»)",
             self._cmd('-Y "tcp.flags.syn==1 && tcp.flags.ack==0 '
                       f'&& tcp.dstport=={PORT}" '
                       "-T fields -e ip.src -e ip.dst | sort | uniq -c")),
            ("Все попытки подключения к PLC",
             self._cmd('-Y "tcp.flags.syn==1 && tcp.flags.ack==0 '
                       f'&& tcp.dstport=={PORT}" '
                       "-T fields -e frame.time -e ip.src -e ip.dst "
                       "-e tcp.stream")),
            ("Кто первым завершил соединение (колонки «Разрывов…»)",
             self._cmd('-Y "(tcp.flags.fin==1 || tcp.flags.reset==1) '
                       '&& tcp.port==102" '
                       "-T fields -e tcp.stream -e frame.time_epoch -e ip.src "
                       "| sort -k1,1n -k2,2g "
                       "| awk '!seen[$1]++ {print $3}' | sort | uniq -c")),
            ("Полностью проследить одно соединение (подставьте номер потока)",
             self._cmd("-q -z follow,tcp,ascii,0")),
        ]
        return Section("connections", f"Соединения TCP (порт {PORT})",
                       body, cmds)

    def _sec_functions(self, s7: dict) -> Section:
        total = sum(n for f, n in s7["fcodes_all"].items()
                    if not f.endswith(":resp"))
        bars = [(FUNC_NAMES.get(f, f), n)
                for f, n in s7["fcodes_all"].most_common(8)
                if not f.endswith(":resp")]
        svg = C.vbar_svg(bars, color=C.PALETTE[0]) if len(bars) <= 12 else ""
        chart = f'<div class="chart-box">{svg}</div>' if svg else ""
        rows = []
        for f, cnt in s7["fcodes_all"].most_common():
            if f.endswith(":resp"):
                continue
            rows.append([
                f"<code class=\"inline\">{C.esc(f)}</code>",
                FUNC_NAMES.get(f, "Прочее/неизвестная функция"),
                f'<span class="num">{C.fmt_int(cnt)}</span>',
                f'<span class="num">{C.fmt_pct(cnt, total)}</span>',
            ])
        body = (
            chart
            + f"<p>Всего запросов (Job): <strong>{C.fmt_int(total)}</strong>. "
              "Распределение по функциям:</p>"
            + C.table_html(["Код", "Операция", "Запросов", "Доля"], rows)
            + '<p class="note"><strong>Read Var</strong> — циклическое чтение '
              "переменных (основная нагрузка); <strong>Write Var</strong> — "
              "команды управления; <strong>Setup communication</strong> при "
              "многих соединениях — признак постоянных переподключений.</p>"
        )
        cmds = [
            ("Распределение функций",
             self._cmd("-Y s7comm -T fields -e s7comm.param.func "
                       "| sort | uniq -c | sort -rn")),
            ("Все операции записи переменных",
             self._cmd('-Y "s7comm.param.func == 0x05" '
                       "-T fields -e frame.number -e frame.time -e ip.src "
                       "-e ip.dst -e s7comm.param.itemcount")),
        ]
        return Section("functions", "Функции S7comm", body, cmds)

    def _sec_areas(self, s7: dict) -> Section:
        rows = []
        for (area, db), cnt in s7["areas"].most_common(
                self.cfg.top_registers_limit):
            name = AREA_NAMES.get(area, f"Область {area}")
            label = f"{name}, №{int(db, 16)}" if area == "0x84" and db else name
            rows.append([
                f"<code class=\"inline\">{C.esc(area)}</code>",
                C.esc(label),
                f'<span class="num">{C.fmt_int(cnt)}</span>',
            ])
        body = (
            "<p>Какие области памяти читаются чаще всего:</p>"
            + C.table_html(["Код", "Область", "Обращений"], rows)
            + '<p class="note">Для области DB указан номер блока. Много мелких '
              "чтений одного блока — кандидат на объединение: S7 позволяет "
              "запрашивать до ~480 байт за один элемент Read Var.</p>"
        )
        cmds = [
            ("Обращения к областям памяти",
             self._cmd("-Y \"s7comm.param.item.area\" -T fields "
                       "-e s7comm.param.item.area -e s7comm.param.item.db "
                       "| sort | uniq -c | sort -rn")),
            ("Чтения конкретного DB (подставьте номер)",
             self._cmd('-Y "s7comm.param.item.db == 0x1" '
                       "-T fields -e frame.time -e s7comm.param.item.address")),
        ]
        return Section("areas", "Области памяти PLC", body, cmds)

    def _sec_errors(self, s7: dict) -> Section:
        rows = []
        for code, cnt in s7["retcodes"].most_common():
            ok = code in ("0xff", "0x00")
            rows.append([
                f"<code class=\"inline\">{C.esc(code)}</code>",
                RETCODE_NAMES.get(code, "Неизвестный код"),
                f'<span class="num">{C.fmt_int(cnt)}</span>',
                "нет" if ok else '<span class="hot-legend">да</span>',
            ])
        note = (
            '<p class="note">Коды возврата проверяются для каждого элемента '
            "данных в ответе. Ошибки вида «адрес вне диапазона» или «объект "
            "не существует» означают, что HMI/SCADA запрашивает несуществующие "
            "переменные — это тратит циклы PLC впустую.</p>")
        if not rows:
            return Section("errors", "Ошибки и коды возврата",
                           "<p>Ошибок не зафиксировано.</p>" + note,
                           [("Проверка кодов возврата",
                             self._cmd("-Y s7comm -T fields "
                                       "-e s7comm.data.returncode "
                                       "| sort | uniq -c"))])
        body = (
            C.table_html(["Код", "Значение", "Элементов", "Ошибка?"], rows)
            + note)
        cmds = [
            ("Только ошибочные ответы",
             self._cmd('-Y "s7comm && s7comm.data.returncode != 0xff" '
                       "-T fields -e frame.number -e ip.src -e ip.dst "
                       "-e s7comm.data.returncode -e s7comm.param.item.db")),
            ("Классы ошибок заголовка",
             self._cmd('-Y "s7comm.header.errcls != 0" '
                       "-T fields -e frame.number -e s7comm.header.errcls "
                       "-e s7comm.header.errcod")),
        ]
        return Section("errors", "Ошибки и коды возврата", body, cmds)

    # -- Рекомендации ---------------------------------------------------------

    def _build_recommendations(self, gen: GeneralStats,
                               s7: dict) -> list[Recommendation]:
        recs = []

        def add(rid, sev, title, problem, advice, evidence=None,
                commands=None):
            recs.append(Recommendation(
                rid, sev, title, problem, advice,
                evidence or [], commands or []))

        # 1. Медленный отклик PLC
        all_rtts = sorted(t for ps in s7["pairs"].values() for t in ps.rtts)
        p95 = _percentile(all_rtts, 95)
        med = _percentile(all_rtts, 50)
        if p95 is not None and p95 > self.cfg.slow_rtt_p95_ms:
            add("s7-slow-response", "warning",
                "Медленный отклик PLC",
                f"95% запросов укладываются в {C.fmt_ms(p95)} мс"
                + (f", медиана — {C.fmt_ms(med)} мс" if med is not None else "")
                + ". При циклическом опросе это удлиняет цикл обновления "
                  "данных SCADA.",
                "Проверьте нагрузку PLC (цикл OB1), длину списков чтения и "
                "паузу между запросами: при p95 выше сотен миллисекунд данные "
                "в SCADA будут запаздывать.",
                evidence=[f"Медиана RTT: {C.fmt_ms(med)} мс",
                          f"p95 RTT: {C.fmt_ms(p95)} мс"])

        # 2. Ошибки доступа к переменным
        resp_total = s7["resp_total"]
        err_rate = (s7["err_total"] / resp_total * 100.0) if resp_total else 0.0
        if resp_total and err_rate >= self.cfg.s7_item_error_pct:
            hot_codes = [c for c, _n in s7["retcodes"].most_common()
                         if c not in ("0xff", "0x00")][:3]
            ev = [f"{RETCODE_NAMES.get(c, c)} ({c})"
                  for c in hot_codes]
            add("s7-item-errors", "warning",
                "Часть ответов содержит ошибки доступа к переменным",
                f"Ошибочные ответы: {C.fmt_int(s7['err_total'])} из "
                f"{C.fmt_int(resp_total)} ({C.fmt_pct(s7['err_total'], resp_total)}).",
                "Сверьте список тегов HMI/SCADA с реальными переменными PLC: "
                "ошибки адресации означают устаревшую привязку тегов после "
                "изменения программы.",
                evidence=ev,
                commands=[self._cmd(
                    '-Y "s7comm.data.returncode != 0xff" -T fields '
                    "-e frame.number -e s7comm.data.returncode "
                    "-e s7comm.param.item.db")])

        # 3. Запросы без ответа
        pending_cnt = len(s7.get("pending", {}))
        if pending_cnt:
            add("s7-unanswered", "info",
                "Есть запросы без сопоставленного ответа",
                f"Не дождались Ack_Data: {pending_cnt}.",
                "Возможны обрывы соединения или ретрансмиссии; проверьте "
                "стабильность канала до PLC.")

        # 4. Частые переподключения
        dur = gen.duration
        # захваты короче минуты не масштабируем: иначе пара SYN за 5 секунд
        # даст ложную «частоту» 24/мин
        dur_min = max(dur / 60.0, 1.0)
        by_rate = len(gen.syn102) / dur_min >= self.cfg.conn_churn_per_min
        per_pair = Counter((c, s) for _t, c, s in gen.syn102)
        hot_pairs = [(k, n) for k, n in per_pair.items()
                     if n >= self.cfg.conn_churn_pair_min]
        if by_rate or hot_pairs:
            ev = [f"{c} → {p}: {n} подключ." for (c, p), n in
                  sorted(hot_pairs, key=lambda x: x[1], reverse=True)[:3]]
            repeat = (" Наиболее активные пары:\n" +
                      "\n".join(ev)) if ev and not by_rate else ""
            add("s7-conn-churn", "warning",
                "Частые переподключения к PLC",
                f"Новых подключений к порту {PORT}: {len(gen.syn102)} "
                f"({len(gen.syn102)/dur_min:.1f}/мин)." + repeat,
                "Правильнее держать одно постоянное keep-alive-соединение на "
                "пару клиент-PLC: каждое переподключение — это handshake плюс "
                "Setup communication, а PLC имеет ограниченный лимит "
                "одновременных соединений (например, S7-1200 — 8).",
                evidence=ev,
                commands=[self._cmd(
                    '-Y "tcp.flags.syn==1 && tcp.flags.ack==0 '
                    '&& tcp.dstport==102" -T fields -e ip.src -e ip.dst '
                    "| sort | uniq -c")])

        # 5. Повторные установки связи
        conns = len(gen.streams102) or 1
        if s7["setup_comms"] >= max(self.cfg.s7_setup_comm_warn, conns + 1):
            add("s7-setup-repeats", "info",
                "Повторные установки связи сверх числа соединений",
                f"Setup communication: {s7['setup_comms']} при "
                f"{conns} TCP-соединениях.",
                "Клиент заново согласовывает параметры PDU внутри живого "
                "соединения или часто пересоздаёт его. Проверьте настройки "
                "таймаутов HMI-драйвера.",
                evidence=[f"Setup: {s7['setup_comms']}; соединений: {conns}"])

        # 6. Одиночные чтения — кандидат на группировку
        reads = s7["fcodes_all"].get("0x04", 0)
        single = sum(p.single_item_reqs for p in s7["pairs"].values()
                     if "0x04" in p.fcodes)
        if reads >= self.cfg.s7_single_read_min and \
                single / max(reads, 1) * 100.0 >= self.cfg.s7_single_read_pct:
            add("s7-single-reads", "info",
                "Чтение по одной переменной за запрос",
                f"{single} из {reads} операций чтения содержат один элемент.",
                "Группируйте соседние переменные в один Read Var: меньше "
                "пакетов на цикл опроса и меньшая загрузка PLC. Один элемент "
                "может прочитать непрерывный диапазон до ~480 байт.",
                evidence=[f"Доля одиночных чтений: "
                          f"{C.fmt_pct(single, reads)}"],
                commands=[self._cmd(
                    '-Y "s7comm.param.func == 0x04" -T fields '
                    "-e frame.number -e s7comm.param.itemcount "
                    "| sort | uniq -c | sort -rn")])

        return sort_recommendations(recs)
