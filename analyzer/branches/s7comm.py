"""Ветка анализа S7comm (Siemens S7 Communication, TCP/102).

Собирает метрики обмена клиент-SCADA/HMI с PLC Siemens: подключения,
состав функций (чтение/запись переменных, установка связи), области памяти,
времена отклика по сопоставлению Job/Ack_Data (s7comm.header.pduref),
коды ошибок элементов — и формирует рекомендации по оптимизации.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
import re

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
    fmt_ts_offset,
    percentile,
    sort_recommendations,
    to_float,
    to_int,
    truthy,
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

# ---------------------------------------------------------------------------
# Утилиты
# ---------------------------------------------------------------------------

def _first(value: str) -> str:
    """Первое значение из агрегированного tshark поля (разделитель ',')."""
    return (value or "").split(",")[0].strip().lower()


def _split_field(value: str) -> list[str]:
    """Разбить агрегированное поле tshark на список значений."""
    return [x.strip().lower()
            for x in (value or "").split(",") if x.strip()]


def _to_int_auto(value: str) -> int | None:
    """Целое с автоопределением основания (tshark даёт «0x1f» и «31»)."""
    try:
        return int(value, 0)
    except (TypeError, ValueError):
        return None


def cv_of_ivs(values) -> float | None:
    """Коэффициент вариации интервалов (регулярность цикла опроса)."""
    vals = list(values)
    if len(vals) < 2:
        return None
    mean = sum(vals) / len(vals)
    if mean <= 0:
        return None
    var = sum((v - mean) ** 2 for v in vals) / (len(vals) - 1)
    return var ** 0.5 / mean


def _item_labels(r: dict) -> tuple[str, ...]:
    """Читаемая метка каждого элемента запроса: «DB123@100..107», «M@5».

    Поля tshark агрегированы через запятую по позициям элементов —
    склеиваем их попарно.
    """
    areas = _split_field(r.get("s7comm.param.item.area"))
    dbs = _split_field(r.get("s7comm.param.item.db"))
    addrs = _split_field(r.get("s7comm.param.item.address.byte"))
    lens = _split_field(r.get("s7comm.param.item.length"))
    out = []
    for i, area in enumerate(areas):
        db = dbs[i] if i < len(dbs) else ""
        base = (f"DB{int(db, 16)}" if area == "0x84" and db
                else AREA_NAMES.get(area, f"область {area}"))
        addr = _to_int_auto(addrs[i]) if i < len(addrs) else None
        ln = _to_int_auto(lens[i]) if i < len(lens) else None
        suffix = ""
        if addr is not None:
            if ln and ln > 1:
                suffix = f"@{addr}..{addr + ln - 1}"
            else:
                suffix = f"@{addr}"
        out.append(base + suffix)
    return tuple(out)


class Req:
    """Запрос Job (rosctr=1) в ожидании Ack_Data."""

    __slots__ = ("ts", "stream", "pair", "func", "items")

    def __init__(self, ts, stream, pair, func: str = "", items=()):
        self.ts = ts
        self.stream = stream
        self.pair = pair          # (client, plc)
        self.func = func          # код функции параметра («0x04» и т.п.)
        self.items = items        # метки элементов запроса («DB1@0»…)


@dataclass
class PairStats:
    reqs: int = 0
    resps: int = 0
    errors: int = 0          # ответы с кодом ошибки элемента/заголовка
    no_resp: int = 0
    bytes_: int = 0
    streams: set = field(default_factory=set)
    fcodes: Counter = field(default_factory=Counter)
    rtts: Reservoir = field(default_factory=lambda: Reservoir(0))
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

        result.capture_start_ts = gen.first_ts

        progress("Проход 2/3: разбор S7comm…", pct=50)
        s7 = self._pass_s7(gen)

        # тёплые цвета серверов (PLC): единая раскраска таблиц, диаграмм
        # и легенды шапки отчёта
        self._set_servers(p for (_c, p) in s7["pairs"])

        # окна для диаграмм Ганта (общий хелпер BaseBranch; есть что
        # показывать — только при наличии S7-трафика)
        self._threads = []
        if s7["req_total"] and gen.duration > 0 and not cfg.skip_gantt:
            progress("Проход 3/3: подбор окон активности…", pct=83)
            self._threads = self._thread_windows(
                "s7comm && tcp.dstport==102", gen.first_ts, gen.duration)

        pending_cnt = sum(len(v) for v in s7.get("pending", {}).values()) \
            + s7.get("stale_dropped", 0) + s7.get("stale_matched", 0)
        all_rtts = sorted(t for ps in s7["pairs"].values() for t in ps.rtts)
        med_rtt = percentile(all_rtts, 50)
        p95_rtt = percentile(all_rtts, 95)
        silent = sum(1 for i in gen.streams102.values() if not i["resp_bytes"])
        result.metrics = {
            "jobs": float(s7["req_total"]),
            "acks": float(s7["resp_total"]),
            "unans_pct": (100.0 * pending_cnt / s7["req_total"]
                          if s7["req_total"] else 0.0),
            "err_pct": (100.0 * s7["err_total"] / s7["resp_total"]
                        if s7["resp_total"] else 0.0),
            "rtt_med_ms": med_rtt * 1000.0 if med_rtt is not None else 0.0,
            "rtt_p95_ms": p95_rtt * 1000.0 if p95_rtt is not None else 0.0,
            "syn": float(len(gen.syn102)),
            "silent_streams": float(silent),
            "clients": float(len({c for (c, _p) in s7["pairs"]})),
            "plcs": float(len({p for (_c, p) in s7["pairs"]})),
        }
        result.kpi = self._build_kpi(gen, s7)
        result.sections = self._build_sections(gen, s7)
        result.recommendations = self._build_recommendations(gen, s7)
        result.server_colors = dict(self._srv_colors)
        return result

    # -- вспомогательное ----------------------------------------------------

    @staticmethod
    def _roles(sport: int, dport: int, src: str, dst: str) -> tuple[str, str]:
        """(клиент, сервер) по положению порта 102."""
        if sport == PORT and dport != PORT:
            return dst, src
        return src, dst

    # -- Проход 1: общие сведения -------------------------------------------

    FIELDS_GENERAL = [
        "frame.time_epoch", "frame.len", "ip.src", "ip.dst",
        "tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.len",
        "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.reset", "tcp.flags.fin",
    ]

    def _pass_general(self) -> GeneralStats:
        g = GeneralStats()
        rows = stream_fields(self.tshark, self.pcap_str, self.FIELDS_GENERAL)
        for r in rows:
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
            on_port = sport == PORT or dport == PORT
            if on_port and truthy(r.get("tcp.flags.reset", "")):
                g.rst102 += 1
            if on_port and truthy(r.get("tcp.flags.fin", "")):
                g.fin102 += 1
            if is_syn and not is_ack and dport == PORT and src:
                g.syn102.append((ts or 0.0, src, dst))
            if on_port:
                st = r.get("tcp.stream", "")
                if st != "":
                    client, server = self._roles(sport, dport, src, dst)
                    info = g.streams102.setdefault(
                        st, {"client": client, "server": server,
                             "first": ts, "last": ts,
                             # полезная нагрузка в сторону PLC и обратно —
                             # для поиска «пустых» подключений без обмена
                             "req_bytes": 0, "resp_bytes": 0,
                             "rst_srv": False, "rst_cli": False}
                    )
                    tlen = to_int(r.get("tcp.len"), 0)
                    if sport == PORT:
                        info["resp_bytes"] += max(tlen, 0)
                    else:
                        info["req_bytes"] += max(tlen, 0)
                    if ts is not None:
                        if info["first"] is None or ts < info["first"]:
                            info["first"] = ts
                        if info["last"] is None or ts > info["last"]:
                            info["last"] = ts
                    if "closed_by" not in info and (
                            truthy(r.get("tcp.flags.fin", ""))
                            or truthy(r.get("tcp.flags.reset", ""))):
                        info["closed_by"] = src
                    # факт RST с каждой стороны — независимо от того, кто
                    # закрыл соединение первым
                    if truthy(r.get("tcp.flags.reset", "")):
                        if sport == PORT:
                            info["rst_srv"] = True
                        else:
                            info["rst_cli"] = True
        return g

    # -- Проход 2: S7comm -----------------------------------------------------

    FIELDS_S7 = [
        "frame.number", "frame.time_epoch", "frame.len",
        "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "tcp.stream",
        "s7comm.header.rosctr", "s7comm.header.pduref",
        "s7comm.header.errcls", "s7comm.header.errcod",
        "s7comm.param.func", "s7comm.param.itemcount",
        "s7comm.param.item.area", "s7comm.param.item.db",
        "s7comm.param.item.address.byte", "s7comm.param.item.length",
        "s7comm.data.returncode", "s7comm.data.length",
        "tcp.payload", "frame.protocols",
    ]

    def _value_digests(self, r: dict, lens: list[int],
                       expect: int) -> tuple[str, ...]:
        """Дайджесты данных элементов Ack_Data из tcp.payload.

        Полей с байтами значений в tshark нет, поэтому проходим структуру
        PDU вручную: TPKT(4) + COTP(1+len) + заголовок Ack_Data (12 байт с
        полями ошибки) + параметр-эхо (parlen) + элементы
        [код(1) транспорт(1) длина(2) данные(+fill при нечётной длине)].
        Длины данных берём из поля s7comm.data.length (tshark уже учёл
        единицы transport size); шаг — 4 + длина + выравнивание.
        Дайджест — первые 16 байтов значения. Возвращает () при любой
        неоднозначности (фрагментация, несовпадение числа элементов).
        """
        hx = (r.get("tcp.payload") or "").replace(":", "").replace(",", "")
        if not hx or len(hx) % 2 or "cotp.segments" in (
                r.get("frame.protocols") or ""):
            return ()
        try:
            buf = bytes.fromhex(hx)
        except ValueError:
            return ()
        if len(buf) < 24 or expect <= 0 or len(lens) != expect:
            return ()
        s7 = 4 + 1 + buf[4]                     # COTP-длина не включает свой байт
        if s7 + 13 > len(buf) or buf[s7] != 0x32 or buf[s7 + 1] != 3:
            return ()                           # только Ack_Data
        parlen = int.from_bytes(buf[s7 + 6:s7 + 8], "big")
        off = s7 + 12 + parlen                  # начало элементов данных
        limit = off + int.from_bytes(buf[s7 + 8:s7 + 10], "big") + 2
        out = []
        for ln in lens:
            if off + 4 > min(len(buf), limit):
                return ()
            if buf[off + 2:off + 4] != b"\x00\x00" and \
                    int.from_bytes(buf[off + 2:off + 4], "big") not in (ln,):
                # спека в заголовке может быть в битах — не сверяем жёстко
                pass
            out.append(buf[off + 4:off + 4 + ln][:16].hex())
            off += 4 + ln + (ln % 2)
        return tuple(out) if len(out) == expect else ()

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
            "areas_r": Counter(),         # (area, db) -> элементы чтения
            "areas_w": Counter(),         # (area, db) -> элементы записи
            "itemcnt_hist": Counter(),    # число элементов запроса -> запросов
            "retcodes": Counter(),       # код возврата -> число элементов
            "timeline": {},               # bucket -> [reqs, errs]
            "pending": {},                # (stream, pduref) -> [Req, ...]
            "stream_reqs": Counter(),
            "s7_streams": set(),          # потоки, где был хоть один PDU S7
            "stale_dropped": 0,           # Job вытеснен переполненной очередью pduref
            "stale_matched": 0,           # ответ «сцепился» с давно зависшим Job
            "err_pairs": {},              # (client, plc) -> ответов с ошибками
            # (client, plc, объект) -> {"codes": Counter, "read": n, "write": n}
            "err_targets": {},
            # трекинг значений чтений: (pair, объект) -> [дайджест, изменения, чтений]
            "valtrack": {},
            "poll_last": {},              # (client, plc, func) -> ts последнего Job
            # периодика Job по целям: (client, plc, func) -> Reservoir интервалов
            "poll_int": {},
            # глубина конвейера: (client, plc) -> Reservoir числа незакрытых Job
            "pipe_depth": {},
        }
        rows = stream_fields(self.tshark, self.pcap_str, self.FIELDS_S7,
                             display_filter="s7comm")
        first_ts = gen.first_ts or 0.0
        bucket_sec = self.cfg.timeline_bucket_sec

        for r in rows:
            s7["total_pdu"] += 1
            ts = to_float(r.get("frame.time_epoch"))
            rosctr = _first(r.get("s7comm.header.rosctr"))
            pduref = _first(r.get("s7comm.header.pduref"))
            func = _first(r.get("s7comm.param.func"))
            src = r.get("ip.src", "")
            dst = r.get("ip.dst", "")
            sport = to_int(r.get("tcp.srcport"), -1)
            dport = to_int(r.get("tcp.dstport"), -1)
            st = r.get("tcp.stream", "")
            client, plc = self._roles(sport, dport, src, dst)
            key = (client, plc)

            ps = s7["pairs"].get(key)
            if ps is None:
                ps = s7["pairs"][key] = PairStats(
                    rtts=Reservoir(self.cfg.max_rtts_per_pair))
            ps.bytes_ += to_int(r.get("frame.len"), 0)
            if st != "":
                ps.streams.add(st)
                s7["s7_streams"].add(st)

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
                itemcnt = to_int(_first(r.get("s7comm.param.itemcount")), 0)
                ps.items += max(itemcnt, 0)
                if itemcnt <= 1:
                    ps.single_item_reqs += 1
                if itemcnt > 0:
                    s7["itemcnt_hist"][itemcnt] += 1
                area = _first(r.get("s7comm.param.item.area"))
                if area:
                    db = _first(r.get("s7comm.param.item.db"))
                    bucket = (s7["areas_w"] if func == "0x05"
                              else s7["areas_r"])
                    bucket[(area, db)] += max(itemcnt, 1)
                if ts is not None and st != "":
                    q = s7.setdefault("pending", {}).setdefault(
                        (st, pduref), [])
                    q.append(Req(ts, st, key, func=func,
                                 items=_item_labels(r)))
                    # периодика Job: интервал между соседними запросами
                    # той же цели (клиент → PLC → функция)
                    pt_key = (key[0], key[1], func)
                    last_job = s7["poll_last"].get(pt_key)
                    if ts is not None:
                        if last_job and 0 < ts - last_job <= 3600:
                            pi = s7["poll_int"].get(pt_key)
                            if pi is None:
                                pi = s7["poll_int"][pt_key] = Reservoir(
                                    self.cfg.max_intervals_per_target)
                            pi.add(ts - last_job)
                        s7["poll_last"][pt_key] = ts
                    # pduref циклически переиспользуется на долгоживущем
                    # потоке: если старые Job так и не получили ответ,
                    # ограничиваем очередь, иначе каждый новый ответ
                    # «сцепится» с самым старым зависшим запросом и
                    # раздует RTT до минут
                    while len(q) > self.cfg.s7_max_pending_per_ref:
                        stale = q.pop(0)
                        s7["stale_dropped"] += 1
                        ps_ = s7["pairs"].get(stale.pair)
                        if ps_ is not None:
                            ps_.no_resp += 1
                b = int((ts or first_ts) - first_ts) // bucket_sec
                s7["timeline"].setdefault(b, [0, 0])[0] += 1

            elif rosctr == "3":
                # Ответ Ack_Data
                s7["resp_total"] += 1
                ps.resps += 1
                req = None
                waiters = s7.get("pending", {}).get((st, pduref))
                if waiters:
                    req = waiters.pop(0)
                    if not waiters:
                        del s7["pending"][(st, pduref)]
                    # сколько Job этой пары ещё ждёт ответа после текущего —
                    # глубина конвейера незакрытых транзакций
                    pd_ = s7["pipe_depth"].get(key)
                    if pd_ is None:
                        pd_ = s7["pipe_depth"][key] = Reservoir(
                            self.cfg.max_intervals_per_target)
                    pd_.add(len(waiters))
                    if req.ts is not None and ts is not None:
                        rtt = max(ts - req.ts, 0.0)
                        # санитарный потолок: RTT больше порога — почти
                        # наверняка потерянный запрос и переиспользованный
                        # pduref, а не реальная задержка PLC
                        if rtt <= self.cfg.s7_rtt_sanity_max_sec:
                            ps.rtts.add(rtt)          # секунды (fmt_ms → мс)
                        else:
                            ps.no_resp += 1
                            s7["stale_matched"] += 1
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
                # привязываем ошибки к паре и к объектам запроса: позиции
                # кодов возврата соответствуют позициям элементов запроса
                if bad_rets:
                    s7["err_pairs"][key] = s7["err_pairs"].get(key, 0) + 1
                    is_write = bool(req and req.func == "0x05")
                    items = (req.items or ()) if req is not None else ()
                    for i, code in enumerate(bad_rets):
                        label = items[i] if i < len(items) else "?"
                        d = s7["err_targets"].setdefault(
                            (key[0], key[1], label),
                            {"codes": Counter(), "read": 0, "write": 0})
                        d["codes"][code] += 1
                        d["write" if is_write else "read"] += 1

                # трекинг значений чтений: дайджест данных каждого элемента
                digests = ()
                if req is not None and not bad_rets and req.items:
                    lens = [_to_int_auto(x) or 0
                            for x in _split_field(r.get("s7comm.data.length"))]
                    digests = self._value_digests(r, lens, len(rets))
                if (req is not None and not bad_rets and digests
                        and req.items
                        and len(digests) == len(rets) == len(req.items)):
                    vt = s7["valtrack"]
                    cap = self.cfg.valtrack_max_registers
                    for lbl, dg in zip(req.items, digests):
                        k = (req.pair, lbl)
                        rec = vt.get(k)
                        if rec is None:
                            if len(vt) < cap:
                                vt[k] = [dg, 0, 1]
                        else:
                            rec[2] += 1
                            if dg != rec[0]:
                                rec[0] = dg
                                rec[1] += 1

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
        med_rtt = percentile(all_rtts, 50)
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
            KpiItem("Запросов без ответа", C.fmt_int(no_resp),
                    C.fmt_pct(no_resp, s7["req_total"]) + " от запросов"
                    if s7["req_total"] else ""),
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
            threads = self._sec_threads()
            if threads:
                sections.append(threads)
            per_sec = self._sec_periodicity(s7)
            if per_sec:
                sections.append(per_sec)
            static_sec = self._sec_static_tags(s7)
            if static_sec:
                sections.append(static_sec)
            sections.append(self._sec_functions(s7))
            sections.append(self._sec_areas(s7))
            sections.append(self._sec_errors(s7))
            err_sec = self._sec_item_errors(s7)
            if err_sec:
                sections.append(err_sec)
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
            ["Начало захвата", epoch_to_str(gen.first_ts)],
            ["Конец захвата", epoch_to_str(gen.last_ts)],
            ["Длительность", C.fmt_dur(gen.duration)],
            ["Всего пакетов", C.fmt_int(gen.total_packets)],
            ["Объём трафика", C.fmt_bytes(gen.total_bytes)],
            [f"RST на порту {PORT}", C.fmt_int(gen.rst102)],
            [f"FIN на порту {PORT}", C.fmt_int(gen.fin102)],
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
            + '<p class="note">Роли определяются по порту 102: сторона с портом '
              "102 — PLC (сервер), инициатор соединения — клиент "
              "(SCADA/HMI/TIA Portal). Объём считается по длине кадров "
              "(frame.len): отправлено — узел источник, получено — назначение.</p>"
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
            labels.append(epoch_to_str(first_ts + b * bucket_sec,
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
            p50 = percentile(rtts, 50)
            p95 = percentile(rtts, 95)
            fc_str = ", ".join(
                f"{FUNC_NAMES.get(f, f)}<span class='note'>×{n}</span>"
                for f, n in ps.fcodes.most_common(3)
            )
            no_resp_cell = f'<span class="num">{C.fmt_int(ps.no_resp)}</span>'
            if ps.reqs and 100.0 * ps.no_resp / ps.reqs >= \
                    self.cfg.s7_no_response_warn_pct:
                no_resp_cell = (no_resp_cell, "cell-hot")
            rows.append([
                f"<strong>{C.esc(cl)}</strong>", self._srv_cell(sv),
                f'<span class="num">{C.fmt_int(ps.reqs)}</span>',
                f'<span class="num">{C.fmt_int(ps.resps)}</span>',
                no_resp_cell,
                f'<span class="num">{C.fmt_int(ps.errors)}</span>',
                f'<span class="num">{C.fmt_int(ps.items)}</span>',
                f'<span class="num">{C.fmt_ms(p50)}</span>',
                f'<span class="num">{C.fmt_ms(p95)}</span>',
                C.fmt_bytes(ps.bytes_), fc_str,
            ])
        body = (
            C.table_html(
                ["Клиент", "PLC", "Запросы", "Ответы", "Нет отв.", "Ошибки",
                 "Элементов", "p50, мс", "p95, мс", "Байты",
                 "Основные функции"],
                rows, cls="pairs")
            + '<p class="note"><strong>p50</strong> (медиана) — половина запросов '
              "получила ответ быстрее этого времени, половина — медленнее. "
              "<strong>p95</strong> — 95% запросов уложились в это время, лишь 5% "
              "были медленнее: если p50 маленький, а p95 большой, отклик обычно "
              "быстрый, но иногда «подвисает». «Элементов» — суммарное число "
              "переменных (элементов Read/Write Var) в запросах. "
              "<strong>Нет отв.</strong> — Job без сопоставленного Ack_Data до "
              "конца захвата: при переподключениях транзакции теряются вместе с "
              "соединением, высокая доля подсвечена розовым.</p>"
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
        # короткие соединения считаем по ВСЕМ потокам: таблица ниже показывает
        # только топ-N самых долгих, они почти всегда длиннее порога
        all_durations = [
            max((i["last"] or 0) - (i["first"] or 0), 0)
            for i in gen.streams102.values()
        ]
        short_cnt = sum(1 for d in all_durations
                        if d < self.cfg.short_stream_sec)
        st_rows = []
        for st, info in sorted(
                gen.streams102.items(),
                key=lambda kv: (kv[1]["last"] or 0) - (kv[1]["first"] or 0),
                reverse=True)[: self.cfg.max_rows_per_table]:
            d = max((info["last"] or 0) - (info["first"] or 0), 0)
            st_rows.append([
                f"<code class=\"inline\">{C.esc(st)}</code>",
                f"{C.esc(info['client'])} &rarr; {self._srv_cell(info['server'])}",
                fmt_ts_offset(info["first"] or 0, gen.first_ts or 0),
                C.fmt_dur(d),
            ])
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
        rst_by_srv: Counter = Counter()
        rst_by_cli: Counter = Counter()
        for info in gen.streams102.values():
            k = (info["client"], info["server"])
            cb = info.get("closed_by")
            if cb == info["server"]:
                close_by_srv[k] += 1
            elif cb == info["client"]:
                close_by_cli[k] += 1
            if info.get("rst_srv"):
                rst_by_srv[k] += 1
            if info.get("rst_cli"):
                rst_by_cli[k] += 1
        keys = (set(per_pair) | set(close_by_srv) | set(close_by_cli)
                | set(rst_by_srv) | set(rst_by_cli))
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
                    cell(rst_by_srv.get((c, s), 0), True),
                    cell(rst_by_cli.get((c, s), 0), True),
                    f'<span class="num">'
                    f'{C.fmt_pct(n, total_syn) if total_syn else "—"}</span>',
                ])
            detail = (
                '<h3 class="subhead">Подключения и разрывы по парам '
                "клиент &rarr; PLC</h3>"
                + C.table_html(
                    ["Клиент", "PLC", "Подключений",
                     "Первым закрыл: сервер", "Первым закрыл: клиент",
                     "RST от сервера", "RST от клиента", "Доля подключений"],
                    pair_rows)
                + '<p class="note"><strong>Подключений</strong> — сколько раз '
                  "клиент устанавливал TCP-соединение с PLC (SYN к порту 102); "
                  'больше 1 <span class="hot-legend">подсвечено розовым</span>: '
                  "соединение пересоздавалось, нормой считается одно долгоживущее "
                  "(keep-alive) соединение на пару. <strong>Первым закрыл</strong> — "
                  "кто послал первый FIN или RST. <strong>RST от сервера / от "
                  "клиента</strong> — потоки со сбросом с этой стороны независимо от "
                  "того, кто закрыл первым: рисунок «клиент закрыл FIN-ом, но RST от "
                  "PLC есть» означает сброс вместо корректной обработки полузакрытия; "
                  "массовые сбросы вне процедуры закрытия — повод проверить таймауты "
                  "простоя на контроллере и сетевом оборудовании (NAT, межсетевые "
                  "экраны).</p>"
            )
        tbl = ""
        if st_rows:
            tbl = ('<h3 class="subhead">Самые долгие соединения</h3>'
                   + C.table_html(["Поток", "Направление", "Старт",
                                   "Длительность"], st_rows))
        # Цели :102: где поднимали соединения и был ли в них хоть какой-то
        # обмен. Поток «молчит», если от PLC не пришло ни байта полезной
        # нагрузки, — признак недоступного или резервного устройства.
        tgt_rows = []
        targets = sorted({info["server"] for info in gen.streams102.values()}
                         | {s for _t, _c, s in gen.syn102})
        for srv in targets:
            streams = {n: i for n, i in gen.streams102.items()
                       if i["server"] == srv}
            syn_n = sum(1 for _t, _c, s in gen.syn102 if s == srv)
            with_s7 = sum(1 for n in streams if n in s7["s7_streams"])
            dead = sum(1 for i in streams.values() if not i["resp_bytes"])
            tgt_rows.append([
                self._srv_cell(srv),
                f'<span class="num">{C.fmt_int(syn_n)}</span>',
                f'<span class="num">{C.fmt_int(len(streams))}</span>',
                f'<span class="num">{C.fmt_int(with_s7)}</span>',
                (f'<span class="num">{C.fmt_int(dead)}</span>', "cell-hot")
                if dead and dead >= len(streams) and syn_n >= 2 else
                f'<span class="num">{C.fmt_int(dead)}</span>',
            ])
        targets_tbl = ""
        if tgt_rows:
            targets_tbl = (
                '<h3 class="subhead">Цели на порту 102: обмен по соединениям</h3>'
                + C.table_html(
                    ["Узел", "SYN", "Потоков", "С S7-обменом", "Молчат"],
                    tgt_rows)
                + '<p class="note"><strong>Молчат</strong> — соединения, в '
                  'которых от узла не пришло ни одного байта полезной нагрузки: '
                  'клиенты регулярно подключаются, но контроллер не отвечает '
                  '(устройство обесточено/в резерве, блокировка по IP или '
                  'ограничение числа TSAP). Розовым отмечены узлы, где молчат '
                  'все наблюдаемые потоки.</p>')
        body = head + detail + targets_tbl + tbl + (
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

    def _sec_threads(self) -> Section | None:
        """Диаграммы Ганта по потокам (общий хелпер BaseBranch)."""
        tw_list = getattr(self, "_threads", [])
        body = self._gantt_section_body(tw_list, req_noun="S7-запросы",
                                        unit_acc="S7-обращений")
        if not body:
            return None
        # примеры команд: самый нагруженный PLC и самый плотный поток окна
        busy_dst, busy_port = "", -1
        fast_pair = ("", -1)
        if tw_list:
            r0 = tw_list[0]["rows"]
            if r0:
                ticks_cnt: dict[str, int] = {}
                for (dst, _sp), e in r0.items():
                    ticks_cnt[dst] = ticks_cnt.get(dst, 0) + len(e["ticks"])
                busy_dst = max(ticks_cnt, key=lambda d: ticks_cnt[d])
                fast_pair = max(r0.items(),
                                key=lambda kv: len(kv[1]["ticks"]))[0]
        cmds = []
        if busy_dst:
            cmds.append((
                "Все S7 Job-запросы к самому загруженному PLC",
                self._cmd(f'-Y "s7comm && tcp.dstport==102 && '
                          f'ip.dst=={busy_dst}" -T fields -e frame.time '
                          "-e tcp.srcport -e s7comm.header.rosctr "
                          "-e s7comm.param.func")))
        if fast_pair[0]:
            cmds.append((
                "Самый быстрый поток: PLC "
                f"{fast_pair[0]}, порт {fast_pair[1]} — интервалы между "
                "строками — период цикла опроса",
                self._cmd(f'-Y "s7comm && tcp.dstport==102 && '
                          f'ip.dst=={fast_pair[0]} && '
                          f'tcp.srcport=={fast_pair[1]}" '
                          "-T fields -e frame.time -e s7comm.header.rosctr "
                          "-e s7comm.param.func")))
        if not cmds:
            cmds.append((
                "Все соединения к порту 102 с эфемеральными портами",
                self._cmd('-Y "s7comm && tcp.dstport==102" -T fields '
                          "-e tcp.stream -e tcp.srcport -e ip.dst | sort -u")))
        return Section("threads", "Опрос по потокам (диаграмма Ганта)",
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
        # Сколько переменных запрашивают за один Job: много одиночных
        # запросов — кандидат на группировку в один Read Var.
        hist_html = ""
        if s7["itemcnt_hist"]:
            hist = sorted(s7["itemcnt_hist"].items())[:12]
            bars = [(f"{n} эл.", cnt) for n, cnt in hist]
            svg = C.vbar_svg(bars, color=C.PALETTE[5]) if len(bars) > 1 else ""
            total_jobs = sum(s7["itemcnt_hist"].values())
            single = s7["itemcnt_hist"].get(1, 0)
            top_line = (
                f"<p>Запросов с одним элементом: <strong>{C.fmt_int(single)}</strong> "
                f"из {C.fmt_int(total_jobs)} ({C.fmt_pct(single, total_jobs)}).</p>")
            hist_html = (
                '<h3 class="subhead">Сколько элементов в одном запросе</h3>'
                + (f'<div class="chart-box">{svg}</div>' if svg else "")
                + top_line
                + '<p class="note">Один элемент Read Var читает непрерывный '
                  'участок до ~480 байт; соседние переменные выгодно собирать '
                  'в один Job — меньше пакетов на цикл и меньше загрузка PLC. '
                  'Пик на «1 эл.» при большом числе запросов — признак '
                  'поэлементного опроса.</p>')
        body += hist_html
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
        keys = (set(s7["areas_r"]) | set(s7["areas_w"]))
        ranked = sorted(keys, key=lambda k: s7["areas_r"][k] + s7["areas_w"][k],
                        reverse=True)
        rows = []
        for area, db in ranked[: self.cfg.top_registers_limit]:
            name = AREA_NAMES.get(area, f"Область {area}")
            label = f"{name}, №{int(db, 16)}" if area == "0x84" and db else name
            rd = s7["areas_r"][(area, db)]
            wr = s7["areas_w"][(area, db)]
            rows.append([
                f"<code class=\"inline\">{C.esc(area)}</code>",
                C.esc(label),
                f'<span class="num">{C.fmt_int(rd)}</span>',
                f'<span class="num">{C.fmt_int(wr)}</span>',
                f'<span class="num">{C.fmt_pct(wr, rd + wr)}</span>',
            ])
        body = (
            "<p>Какие области памяти читаются и пишутся чаще всего "
            "(элементы в запросах):</p>"
            + C.table_html(["Код", "Область", "Чтений", "Записей",
                            "Доля записей"], rows)
            + '<p class="note">Для области DB указан номер блока. Много мелких '
              "чтений одного блока — кандидат на объединение: S7 позволяет "
              "запрашивать до ~480 байт за один элемент Read Var. Высокая доля "
              "записей в DB — повод проверить циклы обмена с уставками: запись "
              "тяжелее чтения и может блокировать области на время транзакции.</p>"
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

    def _sec_item_errors(self, s7: dict) -> Section | None:
        """Кто и какие именно переменные опрашивает «мимо» (ошибки элементов)."""
        if not s7["err_targets"] and not s7["err_pairs"]:
            return None
        # Таблица 1: по парам клиент → PLC
        pair_rows = []
        for (cl, plc), cnt in sorted(s7["err_pairs"].items(),
                                     key=lambda kv: kv[1], reverse=True):
            ps = s7["pairs"].get((cl, plc))
            reqs = ps.reqs if ps else 0
            pct = C.fmt_pct(cnt, reqs) if reqs else "&mdash;"
            cell = f'<span class="num">{C.fmt_int(cnt)}</span>'
            if reqs and 100.0 * cnt / reqs >= self.cfg.s7_no_response_warn_pct:
                cell = (cell, "cell-hot")
            pair_rows.append([
                f"<strong>{C.esc(cl)}</strong>", self._srv_cell(plc),
                cell,
                f'<span class="num">{C.fmt_int(reqs)}</span>',
                pct,
            ])
        html = (
            '<h3 class="subhead">Кто получает ошибки</h3>'
            + C.table_html(
                ["Клиент", "PLC", "Ответов с ошибками", "Всего запросов",
                 "Доля"], pair_rows))
        # Таблица 2: конкретные объекты с ошибками
        ranked = sorted(
            s7["err_targets"].items(),
            key=lambda kv: sum(kv[1]["codes"].values()), reverse=True)
        obj_rows = []
        for (cl, plc, label), d in ranked[: self.cfg.max_rows_per_table]:
            total = sum(d["codes"].values())
            codes = ", ".join(
                f"{C.esc(code)}×{n}" for code, n in
                sorted(d["codes"].items(), key=lambda kv: kv[1],
                       reverse=True))
            obj_rows.append([
                f"<strong>{C.esc(cl)}</strong>",
                self._srv_cell(plc),
                f"<code class=\"inline\">{C.esc(label)}</code>",
                "запись" if d["write"] > d["read"] else "чтение",
                f'<span class="num">{C.fmt_int(total)}</span>',
                codes,
            ])
        html += (
            '<h3 class="subhead">Какие объекты отвечают ошибкой</h3>'
            + C.table_html(
                ["Клиент", "PLC", "Объект запроса", "Операция",
                 "Ошибок", "Коды"], obj_rows)
            + '<p class="note"><strong>Объект</strong> восстановлен из '
              'элемента запроса, позиция которого совпадает с позицией '
              'кода возврата в ответе. Частые коды: <strong>0x0a</strong> — '
              'объекта не существует (тег удалён/переименован в программе '
              'PLC); <strong>0x05</strong> — адрес вне диапазона (границы DB '
              'меньше запрашиваемых); <strong>0x07/0x06</strong> — тип данных '
              'не поддерживается/не разрешён. Каждая такая транзакция — '
              'бесполезный цикл обмена: PLC тратит время и отвечает пустым '
              'результатом. Исправьте привязку тегов на стороне HMI/SCADA '
              'или верните переменную в программу.</p>')
        cmds = []
        if ranked:
            (cl, plc, label), d = ranked[0]
            db_m = re.match(r"DB(\d+)", label)
            db_filter = (f" && s7comm.param.item.db == 0x{int(db_m.group(1)):x}"
                         if db_m else "")
            cmds.append((
                f"Все ошибочные обращения к {label} от {cl}",
                self._cmd(f'-Y "s7comm.data.returncode != 0xff && '
                          f"ip.src=={cl}{db_filter}\" -T fields "
                          "-e frame.number -e frame.time "
                          "-e s7comm.data.returncode "
                          "-e s7comm.param.item.address.byte")))
        return Section("item-errors",
                       "Ошибки доступа к переменным: кто и что",
                       html, cmds)

    def _sec_periodicity(self, s7: dict) -> Section | None:
        """Интенсивность Job по целям и глубина конвейера."""
        bars = []
        for (cl, plc_ip, func), ivs in s7["poll_int"].items():
            if len(ivs) < self.cfg.poll_pressure_min_intervals:
                continue
            med = percentile(sorted(ivs), 50)
            if med is None:
                continue
            fname = FUNC_NAMES.get(func, func)
            bars.append((f"{cl} → {plc_ip} {fname}", med * 1000))
        depth_lines = []
        for (cl, plc_ip), depths in sorted(
                s7["pipe_depth"].items(),
                key=lambda kv: percentile(sorted(kv[1]), 95) or 0,
                reverse=True):
            if len(depths) < self.cfg.poll_pressure_min_intervals:
                continue
            p50 = percentile(sorted(depths), 50)
            p95 = percentile(sorted(depths), 95)
            depth_lines.append(
                f"{C.esc(cl)} → {self._srv_cell(plc_ip)}: медиана "
                f"<strong>{p50:.0f}</strong>, p95 <strong>{p95:.0f}</strong>")
        if not bars and not depth_lines:
            return None
        parts = []
        if bars:
            bars.sort(key=lambda x: x[1])
            parts.append('<div class="chart-box">'
                         + C.hbar_svg(bars[:12],
                                      value_fmt=lambda v: f"{v:.1f} мс")
                         + "</div>"
                         + "<p>Медианный зазор между отправкой соседних Job "
                           "одной цели — интенсивность генерации запросов.</p>")
        if depth_lines:
            parts.append(
                '<h3 class="subhead">Конвейер незакрытых Job (по парам)</h3>'
                "<p>" + "; ".join(depth_lines[:8]) + ".</p>"
                + '<p class="note">SCADA может держать несколько транзакций '
                  'в полёте одновременно (конвейер). Глубина 1 — строгий '
                  'запрос-ответ; растущая глубина означает, что клиент не '
                  'успевает «переваривать» ответы или сознательно '
                  'пипелайнит опрос: это усиливает очередь PLC и разброс '
                  'RTT. См. правило «Глубокий конвейер запросов».</p>')
        return Section("periodicity",
                       "Интенсивность и конвейер запросов",
                       "".join(parts), [])

    def _sec_static_tags(self, s7: dict) -> Section | None:
        """Теги, которые читаются, но их значения не меняются."""
        cfg = self.cfg
        candidates = [(k, v) for k, v in s7["valtrack"].items()
                      if v[2] >= cfg.static_reg_min_reads]
        if not candidates:
            return None
        static = [(k, v) for k, v in candidates
                  if 100.0 * v[1] / v[2] < cfg.static_reg_change_pct]
        if len(candidates) < cfg.static_reg_min_candidates or \
                100.0 * len(static) / len(candidates) < cfg.static_share_pct:
            return None
        static.sort(key=lambda kv: kv[1][2], reverse=True)
        rows = []
        for (pair, label), (_dg, changes, reads) in static[:10]:
            cl, plc_ip = pair
            rows.append([
                f"<strong>{C.esc(cl)}</strong>", self._srv_cell(plc_ip),
                f"<code class=\"inline\">{C.esc(label)}</code>",
                f'<span class="num">{C.fmt_int(reads)}</span>',
                f'<span class="num">{C.fmt_int(changes)}</span>',
                f'<span class="num">{C.fmt_pct(changes, reads)}</span>',
            ])
        body = (
            f"<p>Из {C.fmt_int(len(candidates))} достаточно часто читаемых "
            f"переменных <strong>{C.fmt_int(len(static))} "
            f"({C.fmt_pct(len(static), len(candidates))})</strong> не меняют "
            f"значения за весь захват (изменения реже чем в "
            f"{cfg.static_reg_change_pct:.0f}% чтений):</p>"
            + C.table_html(
                ["Клиент", "PLC", "Переменная", "Чтений", "Изменений",
                 "% изм."], rows)
            + '<p class="note">Значение отслеживается по дайджесту первых '
              'байтов ответа. Статичные теги — кандидаты на медленный цикл '
              'опроса или чтение по изменению: конфигурация, уставки и '
              'счётчики наработки редко нужны с периодом основного цикла. '
              'Разделение на быстрый и медленный контуры разгружает PLC без '
              'потери актуальности.</p>')
        cmds = []
        if static:
            (pair, label) = static[0][0]
            db_m = re.match(r"DB(\d+)", label)
            addr_m = re.search(r"@(\d+)", label)
            flt = "s7comm.param.item.area"
            if db_m:
                flt += f" && s7comm.param.item.db == 0x{int(db_m.group(1)):x}"
            cmds.append((
                f"Все чтения {label} ({pair[0]} → {pair[1]})",
                self._cmd(f'-Y "{flt}" -T fields -e frame.time -e ip.src '
                          "-e s7comm.param.item.db "
                          "-e s7comm.param.item.address.byte | head -40")))
        return Section("static-tags",
                       "Статичные переменные (читаются, но не меняются)",
                       body, cmds)

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
        p95 = percentile(all_rtts, 95)
        med = percentile(all_rtts, 50)
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
            # виновники: пары с наибольшим числом ошибочных ответов
            pair_ev = [f"{cl} → {p}: {n} ответов с ошибками"
                       for (cl, p), n in
                       sorted(s7["err_pairs"].items(), key=lambda kv: kv[1],
                              reverse=True)[:3]]
            # конкретные объекты, отвечающие ошибкой
            obj_ev = []
            for (cl, plc_ip, label), d in sorted(
                    s7["err_targets"].items(),
                    key=lambda kv: sum(kv[1]["codes"].values()),
                    reverse=True)[:5]:
                total = sum(d["codes"].values())
                top_code, top_n = d["codes"].most_common(1)[0]
                obj_ev.append(
                    f"{cl} → {plc_ip} {label}: {total}× "
                    f"({RETCODE_NAMES.get(top_code, top_code)})")
            add("s7-item-errors", "warning",
                "Часть ответов содержит ошибки доступа к переменным",
                f"Ошибочные ответы: {C.fmt_int(s7['err_total'])} из "
                f"{C.fmt_int(resp_total)} ({C.fmt_pct(s7['err_total'], resp_total)}).",
                "Сверьте перечисленные объекты со списком тегов HMI/SCADA и "
                "актуальной программой PLC: «объект не существует» (0x0a) — "
                "тег удалён или переименован; «адрес вне диапазона» (0x05) — "
                "запрос выходит за границы DB. Каждая такая транзакция тратит "
                "цикл контроллера впустую; исправьте привязку тегов или верните "
                "переменные в программу.",
                evidence=obj_ev + pair_ev,
                commands=[self._cmd(
                    '-Y "s7comm.data.returncode != 0xff" -T fields '
                    "-e frame.number -e ip.src -e s7comm.param.item.db "
                    "-e s7comm.param.item.address.byte "
                    "-e s7comm.data.returncode | head -40")])

        # 2b. Глубокий конвейер: много незакрытых Job на пару клиент → PLC
        deep = []
        for (cl, plc_ip), depths in s7["pipe_depth"].items():
            if len(depths) < self.cfg.poll_pressure_min_intervals:
                continue
            p95 = percentile(sorted(depths), 95)
            if p95 is not None and p95 >= self.cfg.s7_pipeline_warn_depth:
                ps = s7["pairs"].get((cl, plc_ip))
                med_rtt = percentile(sorted(ps.rtts), 50) if ps else None
                deep.append((cl, plc_ip, p95, med_rtt))
        if deep:
            deep.sort(key=lambda x: x[2], reverse=True)
            cl, plc_ip, p95, rtt = deep[0]
            rtt_txt = f" при медианном отклике {C.fmt_ms(rtt)} мс" \
                if rtt is not None else ""
            add("s7-poll-pressure", "warning",
                "Глубокий конвейер запросов к PLC",
                f"{cl} → {plc_ip}: в 5% ответов очередь незакрытых Job "
                f"достигает {p95:.0f}{rtt_txt}. Таких пар: {len(deep)}.",
                "Клиент держит много транзакций одновременно: пока PLC "
                "отвечает на одни, новые уже стоят в очереди контроллера — "
                "латентность растёт, а таймауты клиента порождают потерянные "
                "Job и переподключения. Ограничьте число одновременных "
                "запросов на соединение до 1–3 или сократите списки чтения; "
                "период цикла при этом не пострадает.",
                evidence=[f"{c} → {p}: p95 конвейера {d:.0f} Job"
                          for c, p, d, _r in deep[:6]],
                commands=[self._cmd(
                    '-Y "s7comm.header.pduref" -T fields -e ip.src '
                    "-e ip.dst -e tcp.stream -e s7comm.header.pduref "
                    "| awk '{c[$1\" \"$2\" \"$3]++} END{for(k in c)"
                    "print c[k],k}' | sort -rn | head -15")])

        # 2c. Статичные теги: читаются, но значения не меняются
        candidates = [(k, v) for k, v in s7["valtrack"].items()
                      if v[2] >= self.cfg.static_reg_min_reads]
        static_tags = [(k, v) for k, v in candidates
                       if 100.0 * v[1] / v[2] < self.cfg.static_reg_change_pct]
        if len(candidates) >= self.cfg.static_reg_min_candidates and \
                100.0 * len(static_tags) / len(candidates) \
                >= self.cfg.static_share_pct:
            static_tags.sort(key=lambda kv: kv[1][2], reverse=True)
            (pair, label), (_dg, ch, rd) = static_tags[0]
            db_m = re.match(r"DB(\d+)", label)
            db_part = (f" && s7comm.param.item.db == "
                       f"0x{int(db_m.group(1)):x}") if db_m else ""
            add("s7-static-tags", "info",
                f"~{100.0 * len(static_tags) / len(candidates):.0f}% часто "
                "читаемых тегов не меняются",
                f"{len(static_tags)} из {len(candidates)} переменных меняются "
                f"реже чем в {self.cfg.static_reg_change_pct:.0f}% чтений. "
                f"Например, {label} ({pair[0]} → {pair[1]}): {rd} чтений без "
                f"изменений.",
                "Разделите карту опроса на быстрый контур (динамичные "
                "величины) и медленный: уставки, конфигурацию и счётчики "
                "наработки читать раз в N минут или по событию. Это сокращает "
                "трафик и нагрузку на PLC без потери актуальности данных.",
                evidence=[f"{k[0][0]} → {k[0][1]} {k[1]}: "
                          f"{v[2]} чтений, {v[1]} изменений"
                          for k, v in static_tags[:5]],
                commands=[self._cmd(
                    '-Y "s7comm.header.rosctr==3'
                    + (db_part or "") + '" -T fields -e frame.time -e ip.dst '
                    "-e s7comm.data.length | head -40")])

        # 3. Запросы без ответа: считаем ВСЕ зависшие транзакции, а не
        # только ключи словаря; при высокой доле — эскалация до warning
        pending_cnt = sum(len(v) for v in s7.get("pending", {}).values()) \
            + s7.get("stale_dropped", 0) + s7.get("stale_matched", 0)
        if pending_cnt:
            rate = 100.0 * pending_cnt / s7["req_total"] if s7["req_total"] else 0.0
            sev = ("warning" if rate >= self.cfg.s7_no_response_warn_pct
                   else "info")
            worst = sorted(s7["pairs"].items(),
                           key=lambda kv: kv[1].no_resp, reverse=True)[:3]
            ev = [f"{cl} → {p}: {ps.no_resp} без ответа из {ps.reqs}"
                  for (cl, p), ps in worst if ps.no_resp]
            stale = (f" Переиспользование pduref: вытеснено "
                     f"{s7.get('stale_dropped', 0)}, отцеплено при ответе "
                     f"{s7.get('stale_matched', 0)}.") \
                if (s7.get("stale_dropped") or s7.get("stale_matched")) else ""
            add("s7-unanswered", sev,
                "Запросы остаются без ответа PLC",
                f"Не дождались Ack_Data: {pending_cnt} "
                f"({rate:.1f}% от всех Job).{stale}",
                "Возможных причин две группы. Первая — сеть действительно "
                "теряет ответы: транзакция пропадает вместе с соединением при "
                "переподключении либо PLC не успевает ответить до таймаута "
                "клиента. Вторая — эффект измерения: асимметрия маршрута или "
                "неполный захват. Асимметрия маршрута означает, что путь "
                "«туда» и «обратно» разный: запрос от SCADA доходит до "
                "контроллера через один коммутатор, а ответ возвращается "
                "другой дорогой. Точка съёма трафика (зеркало) физически стоит "
                "на одном конкретном участке и видит лишь те пути, которые "
                "через него пролегают. Это как почта: письмо опущено в ящик у "
                "дома, а ответ вам вручили на работе — наблюдатель, стоящий "
                "только у дома, запишет «вопрос без ответа», хотя переписка "
                "шла исправно. Как отличить одно от другого: если два зеркала "
                "на разных участках показывают сильно разные доли «безответных» "
                "запросов для одних и тех же сессий (например, у SCADA — 0%, у "
                f"PLC — {rate:.0f}%), а TCP-соединения живут долго и без "
                "разрывов, — почти наверняка виновата точка съёма, а не PLC. "
                "Тогда сверьте схему зеркалирования и полноту записи дампов. "
                "Если же дампы согласны между собой — проверяйте таймауты "
                "клиента, длину цикла PLC и число одновременных соединений.",
                evidence=ev,
                commands=[self._cmd(
                    '-Y "s7comm.header.rosctr==3" -T fields -e ip.src '
                    "| sort | uniq -c | sort -rn")])

        # 3b. «Молчащие» цели :102 — подключения без единого байта ответа
        dead_ev = []
        for srv in sorted({i["server"] for i in gen.streams102.values()}):
            streams = [i for i in gen.streams102.values()
                       if i["server"] == srv]
            if not streams:
                continue
            syn_n = sum(1 for _t, _c, s in gen.syn102 if s == srv)
            dead = sum(1 for i in streams if not i["resp_bytes"])
            if dead and dead == len(streams) \
                    and syn_n >= self.cfg.s7_dead_min_syns:
                dead_ev.append(
                    f"{srv}: {syn_n} подключений, ни одного байта ответа")
        if dead_ev:
            add("s7-dead-target", "warning",
                "Подключения к узлу :102 без какого-либо ответа",
                f"Молчащих узлов: {len(dead_ev)}.",
                "Клиент регулярно открывает TCP-соединения, но контроллер не "
                "отвечает даже handshake-данными: устройство обесточено или в "
                "резерве, занято лимитом соединений, либо фильтрует адрес "
                "клиента. Лишние попытки создают нагрузку и шум; уберите "
                "узел из конфигурации опроса или верните его в работу.",
                evidence=dead_ev[:6],
                commands=[self._cmd(
                    '-Y "tcp.dstport==102 && tcp.flags.syn==1 && '
                    'tcp.flags.ack==0" -T fields -e ip.dst | '
                    "sort | uniq -c | sort -rn")])

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
