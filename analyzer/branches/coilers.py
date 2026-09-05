"""Ветка анализа телеграмм прокатного стана (Coilers).

Разбирает по структурам конфигурации «Coilers.xml» телеграммы четырёх
TCP-каналов транслятора (порты 10000/10015/20001/10002), собирает
статистику передаваемых полей (уставки на полосу, данные моталок) и
выявляет аномалии:

* «зависшие» поля — значения не меняются при активной передаче;
* «резервные» поля — всегда нули;
* скачки и сбросы сквозного счётчика (потери телеграмм);
* инверсии собственного времени в телеграммах;
* длительные паузы между кадрами;
* высокая частота передачи;
* ретрансмиссии и неразобранные кадры;
* доля кадров Setup формата «keepalive» (нет данных уставок).

Описания структур загружаются из Coilers.xml (путь через
``cfg.coilers_xml``, переменную окружения ``COILERS_XML`` или образец из
``pcap-sample/``); если файл недоступен — используется встроенное описание
тех же четырёх телеграмм.
"""

from __future__ import annotations

import calendar
import os
import struct
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from ..config import Config
from ..report import components as C
from ..tshark_runner import find_tshark, stream_fields
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
    to_float,
    to_int,
    truthy,
)

#: формат struct для типов полей Coilers.xml (little-endian)
_STRUCTS = {
    "long": "<q",
    "short": "<h",
    "float": "<f",
    "byte": "<B",
}

_HEADER_LEN = 64          # длина заголовка телеграммы
_LENGTH_OFFSET = 4        # поле длины payload (short) в заголовке
_SIGNATURE_OFFSET = 32    # сигнатура телеграммы в заголовке

#: порядок каналов (соответствует Coilers.xml)
_CHANNEL_ORDER = ["2001", "2004", "3001", "3002"]


@dataclass
class _FieldSpec:
    """Описание одного поля телеграммы."""

    name: str
    offset: int
    typ: str              # long / short / float / byte / byte[]
    length: int = 0       # размер для byte[]

    @property
    def numeric(self) -> bool:
        return self.typ in _STRUCTS


@dataclass
class _TelegramSpec:
    """Описание телеграммы: порт, сигнатура, поля, группы для отчёта."""

    key: str                      # сигнатура: "2001" / "3001"
    title: str                    # короткое русское название
    port: int
    direction: str                # "output" (от управляющей станции) / "input" (от прокатного стана)
    length: int | None            # ожидаемая длина телеграммы (если задана)
    sig_kind: str                 # "string" (ASCII) или "short" (значение)
    sig: bytes | int              # байты или значение сигнатуры
    fields: list[_FieldSpec] = field(default_factory=list)
    groups: list[tuple[str, tuple[str, ...]]] = field(default_factory=list)
    snapshot_fields: tuple[str, ...] = ()   # поля для «смены полос»
    counter_name: str = ""                  # имя поля-счётчика
    time_names: tuple[str, ...] = ()        # (год,мес,день,час,мин,сек,мс)
    description: str = ""


# ---------------------------------------------------------------------------
# Встроенное описание четырёх телеграмм (поля — из Coilers.xml)
# ---------------------------------------------------------------------------

_TIME_HEADER = ("_year", "_month", "_day", "_hour", "_minute", "_second",
                "_millisecond")
_TIME_HEADER_IN = ("CurrentYear", "CurrentMonth", "CurrentDay", "CurrentHour",
                   "CurrentMinute", "CurrentSecond", "CurrentMillesecond")


def _fs(name: str, offset: int, typ: str, length: int = 0) -> _FieldSpec:
    return _FieldSpec(name, offset, typ, length)


_SETUP_FIELDS = [
    _fs("_headerSignature", 0, "byte[]", 4),
    _fs("_counter", 6, "short"),
    *(_fs(n, off, "short") for n, off in zip(_TIME_HEADER,
                                             range(8, 22, 2))),
    _fs("_stripId", 64, "long"),
    _fs("_nominalStripWidth", 72, "short"),
    _fs("_nominalStripThickness", 74, "float"),
    _fs("_hotYieldPoint", 78, "short"),
    _fs("_RollCard", 80, "short"),
    _fs("_nominalCoilingTemperature", 82, "short"),
    _fs("_SteelGrade", 84, "byte[]", 20),
    _fs("_standActive", 104, "short"),
    _fs("_slipForwardFactor", 106, "float"),
    _fs("_ripplesHeight", 110, "float"),
    _fs("_keepAliveFlag", 114, "short"),
    _fs("_SetHalfCrop", 116, "short"),
    _fs("_CUR_ACCEL", 118, "float"),
]

_UUTR_FIELDS = [
    _fs("_headerSignature", 0, "byte[]", 4),
    _fs("_counter", 6, "short"),
    *(_fs(n, off, "short") for n, off in zip(_TIME_HEADER,
                                             range(8, 22, 2))),
    _fs("_stripId", 64, "long"),
    _fs("_nominalStripWidth", 72, "short"),
    _fs("_Temperature", 74, "float"),
]

_COIL_FIELDS = [
    _fs("counter", 6, "short"),
    *(_fs(n, off, "short") for n, off in zip(_TIME_HEADER_IN,
                                             range(8, 22, 2))),
    _fs("stripId", 64, "long"),
    _fs("coilerNumber", 72, "short"),
    _fs("hotYieldPoint", 74, "short"),
    _fs("specificTension", 76, "short"),
    _fs("tensionPercent", 78, "short"),
    _fs("SATTP2_ON", 80, "short"),
    _fs("SATTP2_DIST", 82, "short"),
    _fs("SATTP2_COEF", 84, "float"),
    _fs("COEFF_PRESS_1", 88, "float"),
    _fs("COEFF_PRESS_2", 92, "float"),
]

# Поля канала данных (по три моталки + общие) — смещения из Coilers.xml
_DATA_ROLL = [
    ("coiler%dDrawRollerLinearVelocity", "short", 64),  # 1,2,3
    ("coiler%dReelBlockAngularVelocity", "float", 70),
    ("coiler%dRollDiameter", "float", 82),
    ("coiler%dMomentReelBlock", "float", 94),
    ("coiler%dMomentDrawRoller", "float", 106),
    ("coiler%dArmOpening", "short", 118),
    ("coiler%dDrawRollerOpening", "float", 124),
    ("coiler%dDrawRollerEffort", "float", 136),
]
_DATA_FORM = [
    ("coiler%dFormingRoller%dLocation", "float", 148, 152, 156,
     160, 164, 168, 172, 176, 180),
    ("coiler%dFormingRoller%dEffort", "float", 184, 188, 192,
     196, 200, 204, 208, 212, 216),
]
_DATA_MISC = [
    ("VEL_%02d", "float", 220, 224, 228, 232, 236),
    ("Accel_for_Tail", "float", 240),
    ("C1_eCoeff_Tail", "float", 244),
    ("C1_stripH", "float", 248),
    ("C2_eCoeff_Tail", "float", 252),
    ("C2_stripH", "float", 256),
    ("C3_eCoeff_Tail", "float", 260),
    ("C3_stripH", "float", 264),
    ("curLength", "float", 268),
    ("curTCM", "float", 272),
]
_DATA_MISC_END = [
    ("C%d_FOLD_COUNTER", "short", 286, 288, 290),
    ("C%d_STRIP_LENGTH", "float", 292, 296, 300),
]


def _data_fields() -> list[_FieldSpec]:
    """Все поля канала Data (порядок — из Coilers.xml)."""
    out: list[_FieldSpec] = [_fs("counter", 6, "short")]
    out += [_fs(n, off, "short") for n, off in zip(_TIME_HEADER_IN,
                                                   range(8, 22, 2))]
    for fmt, typ, *offs in _DATA_ROLL:
        for n, off in enumerate(offs, 1):
            out.append(_fs(fmt % n, off, typ))
    for fmt, typ, *offs in _DATA_FORM:
        for j in range(3):
            row = offs[j * 3:j * 3 + 3]
            for k, off in enumerate(row, 1):
                out.append(_fs(fmt % (j + 1, k), off, typ))
    for fmt, typ, *offs in _DATA_MISC:
        if "%" in fmt:
            for n, off in enumerate(offs, 1):
                out.append(_fs(fmt % n, off, typ))
        else:
            out.append(_fs(fmt, offs[0], typ))
    bytex = [_fs(f"_BYTE_{n}", off, "byte")
             for n, off in enumerate(range(276, 309))]
    for fmt, typ, *offs in _DATA_MISC_END:
        for n, off in enumerate(offs, 1):
            out.append(_fs(fmt % n, off, typ))
    # служебные байты идут вместе со счётчиками/длинами в конце
    out += bytex
    return out


def _data_groups() -> list[tuple[str, tuple[str, ...]]]:
    roll_names = []
    for fmt, _t, *offs in _DATA_ROLL:
        roll_names += [fmt % n for n, _ in enumerate(offs, 1)]
    form_names = []
    for fmt, _t, *offs in _DATA_FORM:
        for j in range(3):
            form_names += [fmt % (j + 1, k) for k in (1, 2, 3)]
    misc_names = []
    for fmt, typ, *offs in _DATA_MISC:
        if "%" in fmt:
            misc_names += [fmt % n for n, _ in enumerate(offs, 1)]
        else:
            misc_names.append(fmt)
    end_names = []
    for fmt, _t, *offs in _DATA_MISC_END:
        end_names += [fmt % n for n, _ in enumerate(offs, 1)]
    end_names += [f"_BYTE_{n}" for n in range(33)]
    return [
        ("Заголовок и таймер", ("counter", *_TIME_HEADER_IN)),
        ("Скорости и моменты моталок", tuple(roll_names)),
        ("Формирующие ролики", tuple(form_names)),
        ("Прочие поля (скорости, хвост полосы)", tuple(misc_names)),
        ("Служебные байты и счётчики", tuple(end_names)),
    ]


_HEADER_TIMER_GROUP = ["_headerSignature", "_counter", *_TIME_HEADER]

_EMBEDDED_TELEGRAMS: dict[str, _TelegramSpec] = {
    "2001": _TelegramSpec(
        key="2001", title="Уставки на полосу (управляющая станция)",
        port=10000, direction="output", length=134, sig_kind="string",
        sig=b"2001", description="Уставки на полосу (управляющая станция)",
        fields=_SETUP_FIELDS,
        groups=[
            ("Заголовок и таймер", tuple(_HEADER_TIMER_GROUP)),
            ("Уставки на полосу", ("_stripId", "_nominalStripWidth",
                                   "_nominalStripThickness", "_hotYieldPoint",
                                   "_RollCard", "_nominalCoilingTemperature",
                                   "_SteelGrade")),
            ("Режимы и параметры", ("_standActive", "_slipForwardFactor",
                                    "_ripplesHeight", "_keepAliveFlag",
                                    "_SetHalfCrop", "_CUR_ACCEL")),
        ],
        snapshot_fields=("_stripId", "_nominalStripWidth",
                         "_nominalStripThickness", "_hotYieldPoint",
                         "_RollCard", "_nominalCoilingTemperature",
                         "_SteelGrade", "_standActive", "_keepAliveFlag"),
        counter_name="_counter", time_names=_TIME_HEADER,
    ),
    "2004": _TelegramSpec(
        key="2004", title="Ширина и температура полосы",
        port=10015, direction="output", length=100, sig_kind="string",
        sig=b"2004", description="Ширина и температура полосы",
        fields=_UUTR_FIELDS,
        groups=[
            ("Заголовок и таймер", tuple(_HEADER_TIMER_GROUP)),
            ("Ширина и температура", ("_stripId", "_nominalStripWidth",
                                      "_Temperature")),
        ],
        snapshot_fields=("_stripId", "_nominalStripWidth", "_Temperature"),
        counter_name="_counter", time_names=_TIME_HEADER,
    ),
    "3001": _TelegramSpec(
        key="3001", title="Уставки на моталки",
        port=20001, direction="input", length=None, sig_kind="short",
        sig=3001, description="Уставки на моталки (задание от стана)",
        fields=_COIL_FIELDS,
        groups=[
            ("Заголовок и таймер", ("counter", *_TIME_HEADER_IN)),
            ("Уставки моталок", ("stripId", "coilerNumber", "hotYieldPoint",
                                 "specificTension", "tensionPercent",
                                 "SATTP2_ON", "SATTP2_DIST", "SATTP2_COEF",
                                 "COEFF_PRESS_1", "COEFF_PRESS_2")),
        ],
        snapshot_fields=("stripId", "coilerNumber", "hotYieldPoint",
                         "specificTension", "tensionPercent"),
        counter_name="counter", time_names=_TIME_HEADER_IN,
    ),
    "3002": _TelegramSpec(
        key="3002", title="Данные моталок",
        port=10002, direction="input", length=None, sig_kind="short",
        sig=3002, description="Данные моталок",
        fields=_data_fields(),
        groups=_data_groups(),
        counter_name="counter", time_names=_TIME_HEADER_IN,
    ),
}

_EMBEDDED_TELEGRAMS["2001"].groups = _EMBEDDED_TELEGRAMS["2001"].groups
_EMBEDDED_TELEGRAMS["2004"].groups = _EMBEDDED_TELEGRAMS["2004"].groups


# ---------------------------------------------------------------------------
# Загрузка описаний из Coilers.xml
# ---------------------------------------------------------------------------

def _xml_candidates(cfg: Config) -> list[Path]:
    cands: list[Path] = []
    for raw in (getattr(cfg, "coilers_xml", None),
                os.environ.get("COILERS_XML")):
        if raw:
            cands.append(Path(raw).expanduser())
    cands.append(Path(__file__).resolve().parent.parent.parent
                 / "pcap-sample" / "tcp-telegram" / "p3trans-insys"
                 / "Coilers.xml")
    return cands


def load_telegram_specs(cfg: Config) -> tuple[Path | None, str,
                                              dict[str, _TelegramSpec]]:
    """(файл или None, пояснение источника, описания телеграмм).

    Если Coilers.xml доступен, структуры четырёх каналов (порты, сигнатуры,
    поля) берутся из файла, а русские заголовки/группы — из встроенного
    описания тех же сигнатур.
    """
    spec_file = None
    for cand in _xml_candidates(cfg):
        if cand.is_file():
            spec_file = cand
            break
    if spec_file is None:
        return None, "встроенное описание структур (Coilers.xml не найден)", \
            dict(_EMBEDDED_TELEGRAMS)
    try:
        with open(spec_file, "rb") as f:
            root = ET.parse(f).getroot()
    except (OSError, ET.ParseError) as exc:
        return None, f"встроенное описание (Coilers.xml не разобран: {exc})", \
            dict(_EMBEDDED_TELEGRAMS)

    merged = dict(_EMBEDDED_TELEGRAMS)
    found = 0
    xml_ids = {"TCP_Setup", "TCP_UUTR", "TCP_Coil", "TCP_Data"}
    for tcp in root.iter("tcp"):
        tid = (tcp.get("id") or "").strip()
        if tid not in xml_ids:
            continue
        port = to_int(tcp.get("port"), -1)
        if port <= 0:
            continue
        header = tcp.find("header")
        hdr_type = header.get("type") if header is not None else ""
        for dir_tag, direction in (("outputTelegram", "output"),
                                   ("inputTelegram", "input")):
            node = next((t for t in tcp.iter() if t.tag == dir_tag), None)
            if node is None:
                continue
            key = (node.get("signature") or "").strip()
            embedded = merged.get(key)
            if embedded is None:
                continue
            sig_kind = hdr_type or embedded.sig_kind
            sig: bytes | int
            if sig_kind == "string":
                sig = key.encode("ascii")
            else:
                try:
                    sig = int(key)
                except ValueError:
                    continue
            fields = []
            for f in node.iter("field"):
                typ = f.get("type") or ""
                name = (f.get("variable") or "").strip()
                if not name:
                    continue
                if typ == "byte[]":
                    fields.append(_fs(name, to_int(f.get("offset"), 0), typ,
                                      to_int(f.get("length"), 1)))
                elif typ in _STRUCTS:
                    fields.append(_fs(name, to_int(f.get("offset"), 0), typ))
            if not fields:
                continue
            merged[key] = _TelegramSpec(
                key=key, title=embedded.title, port=port,
                direction=direction,
                length=to_int(node.get("length"), None),
                sig_kind=sig_kind, sig=sig, fields=fields,
                groups=embedded.groups,
                snapshot_fields=embedded.snapshot_fields,
                counter_name=embedded.counter_name,
                time_names=embedded.time_names,
                description=(node.get("description") or "").strip())
            found += 1
    note = (f"структуры из «{spec_file.name}» ({found} телеграмм)" if found
            else f"встроенное описание (в «{spec_file}» знакомых телеграмм нет)")
    return spec_file, note, merged


# ---------------------------------------------------------------------------
# Накопление статистики
# ---------------------------------------------------------------------------

class _FieldStats:
    """Статистика одного поля (ограниченный объём памяти)."""

    __slots__ = ("spec", "n", "zeros", "changes", "_prev", "acc",
                 "min", "max", "reservoir", "top", "_top_full", "_top_cap")

    def __init__(self, spec: _FieldSpec, max_samples: int, top_cap: int):
        self.spec = spec
        self.n = 0
        self.zeros = 0
        self.changes = 0
        self._prev = None
        self.acc = 0.0
        self.min: float | None = None
        self.max: float | None = None
        self.reservoir = Reservoir(max_samples)
        self.top: Counter = Counter()
        self._top_full = False
        self._top_cap = top_cap

    @property
    def num(self) -> bool:
        return self.spec.numeric

    def observe(self, value) -> None:
        self.n += 1
        if self.num:
            v = float(value)
            if v == 0.0:
                self.zeros += 1
            if self.min is None or v < self.min:
                self.min = v
            if self.max is None or v > self.max:
                self.max = v
            self.acc += v
            self.reservoir.add(v)
            top_key = int(v) if self.spec.typ != "float" else f"{v:.4g}"
        else:
            raw = bytes(value)
            if not raw or not any(raw):
                self.zeros += 1
            top_key = _clean_bytes(raw)
        if self._prev is not None and value != self._prev:
            self.changes += 1
        self._prev = value
        if not self._top_full and self.n <= self._top_cap * 2:
            self.top[top_key] += 1
            if len(self.top) >= self._top_cap:
                self._top_full = True

    def mean(self) -> float | None:
        return self.acc / self.n if self.n else None


def _clean_bytes(raw: bytes) -> str:
    """Байты → читаемая строка (обрезать NUL, убрать лишние пробелы)."""
    head = bytes(raw).split(b"\x00", 1)[0].decode("cp1251", errors="replace")
    return " ".join(head.split()) or "(пусто)"


@dataclass
class _ChannelStats:
    """Статистика канала (одного порта)."""

    telegram: _TelegramSpec
    frames: int = 0            # все кадры с payload на порту
    parsed: int = 0            # разобрано (исключая ретрансмиссии)
    retrans: int = 0           # ретранслированных кадров
    bytes_n: int = 0           # байт трафика канала (frame.len)
    streams: set[str] = field(default_factory=set)
    first_ts: float | None = None
    last_ts: float | None = None
    intervals: Reservoir = field(default_factory=lambda: Reservoir(2000))
    prev_ts: float | None = None
    gap_worst: float = 0.0
    gap_start: float | None = None
    gap_end: float | None = None
    fields_: dict[str, _FieldStats] = field(default_factory=dict)
    _cur_sid: int | None = None
    _cur_snap: dict | None = None
    _cur_frames: int = 0
    strips: list[dict] = field(default_factory=list)
    counter_prev: int | None = None
    counter_wraps: int = 0
    counter_skips: int = 0
    ts_prev: float | None = None
    ts_reversals: int = 0
    ts_drift: Reservoir = field(default_factory=lambda: Reservoir(2000))
    src_ips: Counter = field(default_factory=Counter)
    dst_ips: Counter = field(default_factory=Counter)
    len_mismatch: int = 0

    def field(self, spec: _FieldSpec, max_samples: int, top_cap: int
              ) -> _FieldStats:
        fs = self.fields_.get(spec.name)
        if fs is None:
            fs = _FieldStats(spec, max_samples, top_cap)
            self.fields_[spec.name] = fs
        return fs


def _telegram_epoch(values: dict, time_names: tuple[str, ...]) -> float | None:
    """Время из полей телеграммы → epoch UTC (None при повреждённых полях)."""
    try:
        y = max(int(values[time_names[0]]), 1970)
        m = int(values[time_names[1]])
        d = int(values[time_names[2]])
        h = int(values[time_names[3]])
        mi = int(values[time_names[4]])
        s = int(values[time_names[5]])
        ms = int(values[time_names[6]])
    except (KeyError, TypeError, ValueError):
        return None
    if not (1 <= m <= 12 and 1 <= d <= 31 and 0 <= h <= 23
            and 0 <= mi <= 59 and 0 <= s <= 60):
        return None
    try:
        base = calendar.timegm((y, m, d, h, mi, s, 0, 0, 0))
    except (ValueError, OverflowError):
        return None
    return base + ms / 1000.0


def _build_ips(channels: Iterable[_ChannelStats]
               ) -> tuple[str | None, str | None]:
    """(управляющая станция, прокатный стан) — стороны по направлению каналов."""
    trans_cnt: Counter = Counter()
    peer_cnt: Counter = Counter()
    for ch in channels:
        if ch.telegram.direction == "output":
            trans_cnt.update(ch.src_ips)
            peer_cnt.update(ch.dst_ips)
        else:
            trans_cnt.update(ch.dst_ips)
            peer_cnt.update(ch.src_ips)
    if not trans_cnt and not peer_cnt:
        return None, None
    trans = next((ip for ip, _c in trans_cnt.most_common()), None)
    peer = next((ip for ip, _c in peer_cnt.most_common()), None)
    if peer == trans:
        peer = next((ip for ip, _c in peer_cnt.most_common() if ip != trans),
                    None)
    return trans, peer


def _signature_matches(spec: _TelegramSpec, buf: bytes) -> bool:
    try:
        if spec.sig_kind == "string":
            return buf[_SIGNATURE_OFFSET:
                        _SIGNATURE_OFFSET + len(spec.sig)] == spec.sig
        sig = struct.unpack_from("<H", buf, _SIGNATURE_OFFSET)[0]
        return sig == int(spec.sig)
    except (struct.error, IndexError):
        return False


def _parse_fields(spec: _TelegramSpec, buf: bytes) -> dict:
    out: dict[str, object] = {}
    for f in spec.fields:
        if f.numeric:
            size = struct.calcsize(_STRUCTS[f.typ])
            if len(buf) < f.offset + size:
                continue
            try:
                val = struct.unpack_from(_STRUCTS[f.typ], buf, f.offset)[0]
            except struct.error:
                continue
            out[f.name] = val
        else:
            if len(buf) < f.offset + f.length:
                continue
            out[f.name] = bytes(buf[f.offset:f.offset + f.length])
    return out


def _sig_text(spec: _TelegramSpec) -> str:
    if spec.sig_kind == "string":
        return (spec.sig or b"").decode("ascii", "replace")
    return str(int(spec.sig))


def _value_repr(name: str, raw) -> str:
    if isinstance(raw, bytes):
        return _clean_bytes(raw) or "(пусто)"
    v = float(raw)
    if v == int(v) and abs(v) < 1e15:
        return f"{int(v)}"
    return f"{v:.4g}"


def _num_text(value: float | None, is_float: bool) -> str:
    if value is None:
        return "&mdash;"
    if not is_float:
        return C.fmt_int(value)
    v = float(value)
    return f"{v:.4g}"


def _field_table(stats: Iterable[_FieldStats]) -> str:
    rows = []
    for fs in stats:
        if fs.n == 0:
            continue
        f = fs.spec
        med = percentile(sorted(fs.reservoir), 50)
        mean = fs.mean()
        if fs.num:
            min_c = _num_text(fs.min, f.typ == "float")
            max_c = _num_text(fs.max, f.typ == "float")
            med_c = _num_text(med, f.typ == "float")
            mean_c = _num_text(mean, f.typ == "float")
        else:
            min_c = med_c = max_c = mean_c = "&mdash;"
        top_items = "".join(
            f"<div>{C.esc(str(k))} ({C.fmt_int(v)})</div>"
            for k, v in fs.top.most_common(3))
        if fs._top_full:
            top_items += "<div>…</div>"
        rows.append([
            f"<strong>{C.esc(f.name)}</strong>",
            f'<span class="num">{f.offset}</span>',
            C.esc(f.typ) + (f" [{f.length}]" if f.typ == "byte[]" else ""),
            f'<span class="num">{C.fmt_int(fs.n)}</span>',
            f'<span class="num">{C.fmt_pct(fs.changes, fs.n)}</span>',
            f'<span class="num">{C.fmt_pct(fs.zeros, fs.n)}</span>',
            min_c, med_c, max_c, mean_c,
            top_items or "&mdash;",
        ])
    return C.table_html(
        ["Поле", "Смещ.", "Тип", "Кадров", "Изменений", "Нулей",
         "Мин.", "Медиана", "Макс.", "Среднее", "Частые значения"],
        rows)


# ---------------------------------------------------------------------------
# Ветка анализа
# ---------------------------------------------------------------------------

class CoilersAnalyzer(BaseBranch):
    name = "coilers"
    title = "Анализ телеграмм прокатного стана (Coilers)"
    description = (
        "Разбор телеграмм по конфигурации Coilers.xml: уставки на полосу, "
        "ширина/температура, данные моталок; статистика полей и аномалии "
        "значений, счётчиков и времени."
    )

    FIELDS_GENERAL = [
        "frame.time_epoch", "frame.len", "ip.src", "ip.dst",
        "tcp.stream", "tcp.srcport", "tcp.dstport",
        "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.reset", "tcp.flags.fin",
    ]

    FIELDS_TELEGRAM = [
        "frame.number", "frame.time_epoch", "frame.len", "ip.src", "ip.dst",
        "tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.len",
        "tcp.payload", "tcp.analysis.retransmission",
        "tcp.analysis.fast_retransmission",
    ]

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

        self.spec_file, self.spec_note, self.teleg = load_telegram_specs(cfg)
        self.ports = sorted({t.port for t in self.teleg.values()})
        self._port_to_key = {t.port: key for key, t in self.teleg.items()}
        self._max_samples = cfg.coilers_max_samples
        self._top_cap = cfg.coilers_uniq_cap

        result = BranchResult(
            branch_name=self.name,
            branch_title=self.title,
            pcap_path=pcap_path,
            pcap_size_bytes=pcap_path.stat().st_size,
        )
        self.sha256_short = self._sha256_short(pcap_path)

        progress("Проход 1/2: общий обзор TCP/IP…", pct=30)
        gen = self._pass_general()
        result.capture_start_ts = gen["first_ts"]

        progress("Проход 2/2: разбор телеграмм Coilers…", pct=60)
        data = self._pass_telegrams(gen)

        trans, peer = _build_ips(data["channels"])
        self._trans_ip, self._peer_ip = trans, peer
        if peer:
            self._set_servers([peer])

        result.kpi = self._build_kpi(gen, data)
        result.sections = self._build_sections(gen, data)
        result.recommendations = self._build_recommendations(gen, data)
        result.server_colors = dict(self._srv_colors)
        result.metrics = self._metrics(data)
        return result

    # -- Проход 1: общие сведения -------------------------------------------

    def _pass_general(self) -> dict:
        g = {"total_packets": 0, "total_bytes": 0, "first_ts": None,
             "last_ts": None, "duration": 0.0, "ip_pkts": Counter(),
             "ip_bytes_tx": Counter(), "ip_bytes_rx": Counter(),
             "syn_to_ports": Counter()}
        rows = stream_fields(self.tshark, self.pcap_str, self.FIELDS_GENERAL)
        ports = set(self.ports)
        for i, r in enumerate(rows):
            g["total_packets"] += 1
            plen = to_int(r.get("frame.len"), 0)
            g["total_bytes"] += plen
            ts = to_float(r.get("frame.time_epoch"))
            if ts is not None:
                if g["first_ts"] is None:
                    g["first_ts"] = ts
                g["last_ts"] = ts
            src, dst = r.get("ip.src", ""), r.get("ip.dst", "")
            if src:
                g["ip_pkts"][src] += 1
                g["ip_bytes_tx"][src] += plen
            if dst:
                g["ip_bytes_rx"][dst] += plen
            sport = to_int(r.get("tcp.srcport"), -1)
            dport = to_int(r.get("tcp.dstport"), -1)
            if (sport in ports or dport in ports) \
                    and truthy(r.get("tcp.flags.syn", "")) \
                    and not truthy(r.get("tcp.flags.ack", "")):
                g["syn_to_ports"][dport if dport in ports else sport] += 1
            if (i + 1) % 100000 == 0:
                self.progress(f"  обработано {i + 1} пакетов…", pct=30)
        if g["first_ts"] is not None and g["last_ts"] is not None:
            g["duration"] = g["last_ts"] - g["first_ts"]
        return g

    # -- Проход 2: телеграммы -------------------------------------------------

    def _pass_telegrams(self, gen: dict) -> dict:
        max_samples = self._max_samples
        top_cap = self._top_cap
        channels: dict[str, _ChannelStats] = {
            k: _ChannelStats(self.teleg[k]) for k in _CHANNEL_ORDER
            if k in self.teleg
        }
        misc: Counter = Counter()
        misc_examples: list[tuple[int, int, str]] = []
        retrans_total = 0
        parsed_total = 0

        filt = ("(" + " || ".join(
            f"tcp.srcport=={p} || tcp.dstport=={p}" for p in self.ports)
            + ") && tcp.payload")
        rows = stream_fields(self.tshark, self.pcap_str,
                             self.FIELDS_TELEGRAM, display_filter=filt)
        first_ts = gen["first_ts"] or 0.0
        bucket_sec = self.cfg.timeline_bucket_sec
        timeline: dict[int, Counter] = {}

        for row in rows:
            ts = to_float(row.get("frame.time_epoch"))
            frame = to_int(row.get("frame.number"), 0)
            sport = to_int(row.get("tcp.srcport"), -1)
            dport = to_int(row.get("tcp.dstport"), -1)
            port = sport if sport in self._port_to_key else dport
            ch = channels.get(self._port_to_key.get(port, ""))
            payload = (row.get("tcp.payload") or "").replace(":", "")
            try:
                buf = bytes.fromhex(payload)
            except ValueError:
                buf = b""
            is_retrans = truthy(row.get("tcp.analysis.retransmission", "")) \
                or truthy(row.get("tcp.analysis.fast_retransmission", ""))

            if ch is None or not buf:
                continue
            ch.frames += 1
            ch.bytes_n += to_int(row.get("frame.len"), 0)
            ch.streams.add(row.get("tcp.stream", ""))
            src_ip, dst_ip = row.get("ip.src", ""), row.get("ip.dst", "")
            if src_ip:
                ch.src_ips[src_ip] += 1
            if dst_ip:
                ch.dst_ips[dst_ip] += 1
            if is_retrans:
                ch.retrans += 1
                retrans_total += 1
                continue
            if len(buf) < _HEADER_LEN \
                    or not _signature_matches(ch.telegram, buf):
                misc[port] += 1
                if len(misc_examples) < 3:
                    misc_examples.append((port, frame, epoch_to_str(ts)))
                continue
            values = _parse_fields(ch.telegram, buf)
            if not values:
                misc[port] += 1
                continue
            length_field = struct.unpack_from("<H", buf, _LENGTH_OFFSET)[0]
            if length_field != len(buf):
                ch.len_mismatch += 1
            ch.parsed += 1
            parsed_total += 1

            if ts is not None:
                if ch.first_ts is None:
                    ch.first_ts = ts
                    ch.prev_ts = ts
                ch.last_ts = ts
                if ch.prev_ts is not None and ts > ch.prev_ts:
                    dt = ts - ch.prev_ts
                    ch.intervals.add(dt)
                    if dt > ch.gap_worst:
                        ch.gap_worst = dt
                        ch.gap_start, ch.gap_end = ch.prev_ts, ts
                ch.prev_ts = ts
                if bucket_sec > 0:
                    timeline.setdefault(
                        bucket_sec and int((ts - first_ts) / bucket_sec),
                        Counter())[ch.telegram.port] += 1

            for fspec in ch.telegram.fields:
                raw = values.get(fspec.name)
                if raw is not None:
                    ch.field(fspec, max_samples, top_cap).observe(raw)
            self._track_counter(ch, values)
            self._track_time(ch, values, ts)
            self._track_strip(ch, values, ts)

        for ch in channels.values():
            self._flush_strip(ch)

        return {
            "channels": [channels[k] for k in _CHANNEL_ORDER
                         if k in channels],
            "misc": dict(misc),
            "misc_examples": misc_examples,
            "retrans_total": retrans_total,
            "parsed_total": parsed_total,
            "bytes_total": sum(c.bytes_n for c in channels.values()),
            "timeline": timeline,
            "filter": filt,
        }

    def _track_counter(self, ch: _ChannelStats, values: dict) -> None:
        name = ch.telegram.counter_name
        if not name:
            return
        val = to_int(values.get(name))
        if val < 0:
            return
        if ch.counter_prev is not None:
            if val < ch.counter_prev:
                ch.counter_wraps += 1
            elif val - ch.counter_prev > 1:
                ch.counter_skips += 1
        ch.counter_prev = val

    def _track_time(self, ch: _ChannelStats, values: dict,
                    frame_ts) -> None:
        te = _telegram_epoch(values, ch.telegram.time_names)
        if te is None or frame_ts is None:
            return
        ch.ts_drift.add(te - frame_ts)
        if ch.ts_prev is not None and te < ch.ts_prev:
            ch.ts_reversals += 1
        ch.ts_prev = te

    def _track_strip(self, ch: _ChannelStats, values: dict, ts) -> None:
        if not ch.telegram.snapshot_fields:
            return
        sid = to_int(values.get(ch.telegram.snapshot_fields[0]))
        if sid <= 0:
            return
        snap = {"_sid": sid}
        for name in ch.telegram.snapshot_fields[1:]:
            if name in values:
                snap[name] = _value_repr(name, values[name])
        if ch._cur_sid is None:
            ch._cur_sid = sid
            ch._cur_snap = {"_ts": ts, "_frames": 1}
            ch._cur_frames = 1
        elif sid != ch._cur_sid:
            ch._cur_snap["_frames"] = ch._cur_frames
            if len(ch.strips) < 500:
                ch.strips.append(ch._cur_snap)
            ch._cur_sid = sid
            ch._cur_snap = {"_ts": ts, "_frames": 1}
            ch._cur_frames = 1
        else:
            ch._cur_frames += 1
            ch._cur_snap["_frames"] = ch._cur_frames
        ch._cur_snap.update({"_ts": ts, "_frames": ch._cur_frames})
        ch._cur_snap.update(snap)

    def _flush_strip(self, ch: _ChannelStats) -> None:
        if ch._cur_sid is not None and ch._cur_snap is not None:
            ch.strips.append(ch._cur_snap)
            ch._cur_sid = None
            ch._cur_snap = None

    # -- Отчёт ----------------------------------------------------------------

    def _build_kpi(self, gen: dict, data: dict) -> list[KpiItem]:
        dur = gen["duration"]
        total = data["parsed_total"]
        by_key = {ch.telegram.key: ch for ch in data["channels"]}
        def cnt(key: str) -> int:
            ch = by_key.get(key)
            return ch.parsed if ch else 0
        return [
            KpiItem("Длительность захвата", C.fmt_dur(dur)),
            KpiItem("Всего пакетов", C.fmt_int(gen["total_packets"]),
                    C.fmt_bytes(gen["total_bytes"]) + " трафика"),
            KpiItem("Телеграмм Coilers", C.fmt_int(total),
                    C.fmt_pct(total, gen["total_packets"]) + " от всех пакетов"),
            KpiItem("Setup (10000)", C.fmt_int(cnt("2001"))),
            KpiItem("UUTR (10015)", C.fmt_int(cnt("2004"))),
            KpiItem("Coil (20001)", C.fmt_int(cnt("3001"))),
            KpiItem("Data (10002)", C.fmt_int(cnt("3002")),
                    C.fmt_pct(cnt("3002"), total) + " от телеграмм"),
            KpiItem("Ретрансмиссий", C.fmt_int(data["retrans_total"])),
            KpiItem("Неразобранных кадров", C.fmt_int(
                sum(data["misc"].values()))),
            KpiItem("Источник структур", C.esc("xml" if self.spec_file
                                               else "встроенный")),
        ]

    def _build_sections(self, gen: dict, data: dict) -> list[Section]:
        sections = [self._sec_summary(gen, data)]
        if not data["parsed_total"]:
            sections.append(Section(
                "nocoilers", "Телеграммы Coilers не обнаружены",
                "<p>В файле нет кадров с сигнатурами каналов Coilers "
                "(порты "
                + " / ".join(str(p) for p in self.ports)
                + "). Проверьте выбранный файл и конфигурацию структур.</p>",
                [("Проверка портов", self._cmd(
                    '-Y "' + data["filter"] + '" -c 5'))],
            ))
            return sections
        sections.append(self._sec_channels(data))
        sections.append(self._sec_timeline(gen, data))
        for ch in data["channels"]:
            if not ch.parsed:
                continue
            if ch.strips:
                sections.append(self._sec_strips(ch))
            sections.extend(self._sec_fields(ch))
        return sections

    def _sec_summary(self, gen: dict, data: dict) -> Section:
        rows = [
            ["Файл", C.esc(self.pcap.name)],
            ["Размер файла", C.fmt_bytes(self.pcap.stat().st_size)],
            ["SHA-256 (фрагмент)",
             f'<code class="inline">{self.sha256_short}&hellip;</code>'],
            ["Начало захвата", epoch_to_str(gen["first_ts"])],
            ["Конец захвата", epoch_to_str(gen["last_ts"])],
            ["Длительность", C.fmt_dur(gen["duration"])],
            ["Всего пакетов", C.fmt_int(gen["total_packets"])],
            ["Объём трафика", C.fmt_bytes(gen["total_bytes"])],
            ["Структуры телеграмм", C.esc(self.spec_note)],
        ]
        if self._trans_ip or self._peer_ip:
            rows.append(["Управляющая станция → прокатный стан",
                         f'{C.esc(self._trans_ip or "?")} '
                         f'&rarr; {C.esc(self._peer_ip or "?")}'])
        top_rows = [
            [self._srv_cell(ip) if ip == self._peer_ip
             else f"<code class=\"inline\">{C.esc(ip)}</code>",
             f'<span class="num">{C.fmt_int(cnt)}</span>',
             f'<span class="num">{C.fmt_bytes(gen["ip_bytes_tx"].get(ip, 0))}</span>',
             f'<span class="num">{C.fmt_bytes(gen["ip_bytes_rx"].get(ip, 0))}</span>']
            for ip, cnt in gen["ip_pkts"].most_common(6)
        ]
        body = (
            C.table_html(["Параметр", "Значение"], rows)
            + '<h3 class="subhead">Самые активные узлы (по всем протоколам)</h3>'
            + C.table_html(["Узел", "Пакетов", "Отправлено", "Получено"],
                           top_rows)
            + '<p class="note">Роли сторон заданы направлением каналов: '
              "уставки на полосу (2001) и ширина/температура (2004) приходят "
              "на порты 10000/10015 прокатного стана от управляющей станции; "
              "уставки на моталки (3001) и данные моталок (3002) прокатный "
              "стан отправляет управляющей станции. "
              "Описание структур (Coilers.xml или встроенное) и таблицы "
              "полей воспроизводимы командами tshark ниже.</p>"
        )
        cmds = [
            ("Общая статистика по файлу", self._cmd("-q -z io,stat,0")),
            ("Разговоры TCP по портам Coilers",
             self._cmd(f'-q -z conv,tcp,"{data["filter"]}"')),
            ("Первые телеграммы на портах Coilers",
             self._cmd(f'-Y "{data["filter"]}" -c 10')),
        ]
        return Section("general", "Общая информация о захвате", body, cmds)

    def _sec_channels(self, data: dict) -> Section:
        rows = []
        for ch in data["channels"]:
            if not ch.frames:
                continue
            med = percentile(sorted(ch.intervals), 50)
            p95 = percentile(sorted(ch.intervals), 95)
            rows.append([
                f"<strong>{C.esc(ch.telegram.title)}</strong><br>"
                f'<code class="inline">порт {ch.telegram.port}</code>',
                f'<code class="inline">{C.esc(_sig_text(ch.telegram))}</code>',
                "из прокатного стана" if ch.telegram.direction == "input"
                else "от управляющей станции",
                f'<span class="num">{C.fmt_int(ch.parsed)}</span>',
                f'<span class="num">{C.fmt_bytes(ch.bytes_n)}</span>',
                f'<span class="num">{C.fmt_int(len(ch.streams))}</span>',
                f'<span class="num">{C.fmt_ms(med)} мс</span>'
                if med is not None else "&mdash;",
                f'<span class="num">{C.fmt_ms(p95)} мс</span>'
                if p95 is not None else "&mdash;",
                C.fmt_dur(ch.gap_worst) if ch.gap_worst else "—",
                f'<span class="num">{C.fmt_int(ch.retrans)}</span>',
            ])
        body = (
            C.table_html(
                ["Канал", "Сигнатура", "Направление", "Телеграмм", "Байт",
                 "Соединений", "Медиана интервала", "p95 интервала",
                 "Макс. пауза", "Ретрансмиссии"],
                rows)
            + '<p class="note">Интервалы и паузы считаются по поступившим '
              "(не ретранслированным) кадрам. Смещение собственных часов "
              "источника относительно времени захвата приведено в полях "
              "«Год … миллисекунда» каждой телеграммы.</p>"
        )
        cmds = [
            ("Кадры на портах Coilers",
             self._cmd(f'-Y "{data["filter"]}" -T fields -e frame.number '
                       "-e frame.time -e ip.src -e tcp.srcport -e ip.dst "
                       "-e tcp.dstport -e tcp.len")),
            ("Ретрансмиссии каналов",
             self._cmd('-Y "tcp.port==' + "||tcp.port==".join(
                 str(p) for p in self.ports)
                 + ' && tcp.analysis.retransmission" -c 20')),
        ]
        return Section("channels", "Каналы и телеграммы", body, cmds)

    def _sec_timeline(self, gen: dict, data: dict) -> Section:
        bucket_sec = self.cfg.timeline_bucket_sec
        first_ts = gen["first_ts"] or 0.0
        n_buckets = max((b for b in data["timeline"] if b is not None),
                        default=-1) + 1
        ports = [ch.telegram.port for ch in data["channels"] if ch.parsed]
        series = {p: [0] * n_buckets for p in ports}
        for b, cnt in data["timeline"].items():
            if b is None:
                continue
            for p in cnt:
                if p in series:
                    series[p][b] += int(cnt[p])
        labels = [epoch_to_str(first_ts + b * bucket_sec, time_only=True)
                  for b in range(n_buckets)]
        names = {ch.telegram.port: ch.telegram.title.split(" (")[0]
                 for ch in data["channels"]}
        colors = [C.PALETTE[i % len(C.PALETTE)] for i in range(len(ports))]
        svg = C.timeline_svg(labels, [series[p] for p in ports], colors,
                             [names[p] for p in ports], height=230)
        body = (
            '<div class="chart-box">' + svg + "</div>"
            + '<p class="note">Ровная «гребёнка» — регулярный обмен; '
              "провалы — паузы в передаче или обрыв связи с моталками.</p>"
        )
        cmds = [("Интенсивность каналов поминутно",
                 self._cmd("-q -z io,stat,"
                           + str(bucket_sec) + "," + ",".join(
                               f'"COUNT(tcp.len) tcp.port=={p}"' for p in ports)))]
        return Section("timeline", "Активность во времени", body, cmds)

    def _sec_strips(self, ch: _ChannelStats) -> Section:
        sid_name = ch.telegram.snapshot_fields[0]
        headers = (["Время", "Кадров", sid_name]
                   + list(ch.telegram.snapshot_fields[1:]))
        rows = []
        for snap in ch.strips[: self.cfg.max_rows_per_table]:
            ts = snap.get("_ts")
            cells = [epoch_to_str(ts) if ts is not None else "&mdash;",
                     f'<span class="num">{snap.get("_frames", 0)}</span>',
                     C.esc(str(snap.get("_sid", "&mdash;")))]
            for name in ch.telegram.snapshot_fields[1:]:
                cells.append(C.esc(str(snap.get(name, "&mdash;"))))
            rows.append(cells)
        body = (
            C.table_html(headers, rows)
            + '<p class="note">Строка — очередная полоса, увиденная в канале '
              "(смена <strong>" + C.esc(sid_name)
              + "</strong>); значения приведены на момент последнего кадра "
              "полосы. Кадров — число телеграмм, встреченных для этой полосы."
              "</p>"
        )
        return Section(f"strips-{ch.telegram.key}",
                       f"Смены полос — {ch.telegram.title}", body, [])

    def _sec_fields(self, ch: _ChannelStats) -> list[Section]:
        sections = []
        for g_title, names in ch.telegram.groups:
            stats = [ch.fields_[n] for n in names if n in ch.fields_]
            if not stats:
                continue
            cmds = [
                ("Проверка raw-байт телеграмм канала",
                 self._cmd(f'-Y "tcp.port=={ch.telegram.port} && tcp.payload" '
                           "-T fields -e frame.number -e frame.time "
                           "-e tcp.payload | head -10")),
            ]
            sid = f"fields-{ch.telegram.key}-" + g_title.lower()[0:24]
            sections.append(Section(
                sid, f"{ch.telegram.title}: {g_title}",
                _field_table(stats), cmds))
        return sections

    def _metrics(self, data: dict) -> dict[str, float]:
        m: dict[str, float] = {"coilers_frames": 0.0}
        by_key = {ch.telegram.key: ch for ch in data["channels"]}
        for key, mkey in (("2001", "setup_frames"), ("2004", "uutr_frames"),
                          ("3001", "coil_frames"), ("3002", "data_frames")):
            ch = by_key.get(key)
            val = float(ch.parsed) if ch else 0.0
            m[mkey] = val
            m["coilers_frames"] += val
        m["misc_frames"] = float(sum(data["misc"].values()))
        m["retrans_frames"] = float(data["retrans_total"])
        meds = [percentile(sorted(ch.intervals), 50)
                for ch in data["channels"] if ch.intervals.seen]
        meds = [x for x in meds if x is not None]
        m["coilers_interval_ms"] = (1000.0 * sum(meds) / len(meds)
                                    if meds else 0.0)
        ch_d = by_key.get("3002")
        if ch_d and ch_d.parsed:
            med = percentile(sorted(ch_d.intervals), 50) or 0.0
            m["data_interval_med_ms"] = 1000.0 * med
        else:
            m["data_interval_med_ms"] = 0.0
        m["ts_reversals"] = float(sum(ch.ts_reversals
                                      for ch in data["channels"]))
        m["static_fields"] = float(sum(
            1 for ch in data["channels"]
            for fs in ch.fields_.values()
            if fs.changes == 0 and fs.spec.offset >= _HEADER_LEN
            and fs.n >= self.cfg.coilers_static_min_frames))
        return m

    # -- Рекомендации ----------------------------------------------------------

    def _build_recommendations(self, gen: dict, data: dict
                               ) -> list[Recommendation]:
        if data["parsed_total"] == 0:
            return [Recommendation(
                id="coilers-none", severity="info",
                title="Данные Coilers не обнаружены",
                problem="Ни одной телеграммы не разобрано.",
                advice=("Проверьте фильтр и наличие кадров на портах "
                        + ", ".join(str(p) for p in self.ports) + "."))]
        recs: list[Recommendation] = []
        recs.extend(self._rule_static_fields(data))
        recs.extend(self._rule_intervals(data))
        recs.extend(self._rule_counter(data))
        recs.extend(self._rule_ts(data))
        recs.extend(self._rule_retrans(data))
        recs.extend(self._rule_always_zero(data))
        recs.extend(self._rule_misc(data))
        recs.extend(self._rule_syns(gen))
        if not recs:
            recs.append(Recommendation(
                id="ok", severity="info",
                title="Явных проблем не обнаружено",
                problem="Ни одно правило аномалий не сработало.",
                advice="Сохраните отчёт как эталон и повторяйте анализ."))
        return recs

    def _rule_static_fields(self, data: dict) -> list[Recommendation]:
        """Значения не менялись ни разу при активной передаче."""
        out = []
        cfg = self.cfg
        for ch in data["channels"]:
            if not ch.parsed:
                continue
            candidates = [
                fs.spec.name for fs in ch.fields_.values()
                if fs.changes == 0 and fs.spec.offset >= _HEADER_LEN
                and fs.n >= cfg.coilers_static_min_frames
                and not (fs.num and fs.min == 0.0 and fs.max == 0.0)]
            if len(candidates) < 2:
                continue
            if ch.telegram.key != "3002" and len(ch.strips) < 2:
                continue
            sev = "warning" if ch.telegram.key == "3002" else "info"
            out.append(Recommendation(
                id=f"coilers-static-{ch.telegram.key}",
                severity=sev,
                title=f"Данные не обновляются: «{ch.telegram.title}»",
                problem=(f"За {ch.parsed} телеграмм не менялись: "
                         + ", ".join(candidates[:8])
                         + (f" и ещё {len(candidates) - 8}" if len(candidates) > 8
                            else "")),
                advice=("Проверьте источник данных (PLC/управляющую станцию): "
                        "поле могло «зависнуть», а на стан продолжает уходить "
                        "прежнее значение. Для канала данных это признак "
                        "неактуальных показаний моталок."),
                evidence=[f"Статичных полей: {len(candidates)}",
                          f"Кадров в канале: {ch.parsed}"]))
        return out

    def _rule_always_zero(self, data: dict) -> list[Recommendation]:
        """Всегда нулевые числовые поля — «резервные»."""
        out = []
        cfg = self.cfg
        for ch in data["channels"]:
            if not ch.parsed:
                continue
            zeros = [
                fs.spec.name for fs in ch.fields_.values()
                if fs.num and fs.n >= cfg.coilers_static_min_frames
                and fs.zeros / fs.n * 100.0 >= cfg.coilers_static_zero_pct]
            if not zeros:
                continue
            out.append(Recommendation(
                id=f"coilers-zeros-{ch.telegram.key}",
                severity="info",
                title=f"Резервные поля «{ch.telegram.title}»",
                problem=(f"Всегда нулевые поля: {', '.join(zeros[:8])}"),
                advice=("Сверьте с проектом: если поля не должны "
                        "использоваться — это ожидаемо; если должны — "
                        "проверьте привязку тегов в UDH-конфигураторе."),
                evidence=[f"Всегда-нулевых полей: {len(zeros)}"]))
        return out

    def _rule_intervals(self, data: dict) -> list[Recommendation]:
        """Высокая частота и длительные паузы."""
        out = []
        cfg = self.cfg
        for ch in data["channels"]:
            if not ch.parsed or ch.intervals.seen < cfg.coilers_gap_min_frames:
                continue
            med = percentile(sorted(ch.intervals), 50)
            if med is None:
                continue
            if med < cfg.coilers_fast_interval_ms / 1000.0:
                out.append(Recommendation(
                    id=f"coilers-rate-{ch.telegram.key}",
                    severity="info",
                    title=f"Частая передача «{ch.telegram.title}»",
                    problem=(f"Медианный интервал между кадрами "
                             f"{C.fmt_ms(med)} мс."),
                    advice=("Оцените, нужна ли такая частота: это постоянная "
                            "нагрузка на сеть и стан."),
                    evidence=[f"Интервалов оценено: {ch.intervals.seen}"]))
            if med > 0.0 and ch.gap_worst > cfg.coilers_gap_mult * med:
                out.append(Recommendation(
                    id=f"coilers-gaps-{ch.telegram.key}",
                    severity="warning",
                    title=f"Длительные паузы «{ch.telegram.title}»",
                    problem=(f"Самая большая пауза — {C.fmt_dur(ch.gap_worst)} "
                             f"при медиане {C.fmt_ms(med)} мс "
                             f"(больше {cfg.coilers_gap_mult:.0f}× медианы)."),
                    advice=("Проверьте соединение и стабильность приложений: "
                            "длинные паузы — обрыв передачи, перезапуск "
                            "транслятора или стана."),
                    evidence=[self._gap_period(ch)],
                    commands=[self._cmd(
                        f'-Y "tcp.port=={ch.telegram.port} && '
                        "tcp.analysis.retransmission\" -c 20")]))
        return out

    def _rule_counter(self, data: dict) -> list[Recommendation]:
        """Скачки/сбросы сквозного счётчика = потери телеграмм."""
        out = []
        cfg = self.cfg
        for ch in data["channels"]:
            if not ch.parsed:
                continue
            if ch.counter_skips >= cfg.coilers_counter_skips_warn:
                sev = ("warning" if ch.counter_skips
                       >= cfg.coilers_counter_skips_warn * 3 else "info")
                out.append(Recommendation(
                    id=f"coilers-counter-{ch.telegram.key}",
                    severity=sev,
                    title=f"Потери телеграмм «{ch.telegram.title}»",
                    problem=(f"Счётчик пропускал значения {ch.counter_skips} "
                             "раз (скачок более чем на 1)."),
                    advice=("Часть телеграмм не дошла или потеряна "
                            "приложением; сопоставьте с паузами и "
                            "ретрансмиссиями."),
                    evidence=[f"Сбросов счётчика: {ch.counter_wraps}"]))
            elif ch.counter_wraps >= cfg.coilers_counter_wraps_warn:
                out.append(Recommendation(
                    id=f"coilers-counter-wrap-{ch.telegram.key}",
                    severity="info",
                    title=f"Сброс счётчика «{ch.telegram.title}»",
                    problem=f"Счётчик обнулялся {ch.counter_wraps} раз.",
                    advice=("Нормально при периодическом сбросе через 9999, "
                            "если сброс не сопровождается потерей данных."),
                    evidence=[f"Пропусков значений: {ch.counter_skips}"]))
        return out

    def _rule_ts(self, data: dict) -> list[Recommendation]:
        """Инверсии собственного времени в телеграммах."""
        out = []
        cfg = self.cfg
        for ch in data["channels"]:
            if ch.ts_reversals >= cfg.coilers_ts_reversals_min:
                out.append(Recommendation(
                    id=f"coilers-ts-{ch.telegram.key}",
                    severity="warning",
                    title=f"Метки времени «{ch.telegram.title}» прыгают",
                    problem=(f"Время внутри телеграмм возвращалось назад "
                             f"{ch.ts_reversals} раз."),
                    advice=("Часы источника (PLC/станции) синхронизированы "
                            "некорректно; это путает архивацию по времени."),
                    evidence=[f"Инверсий времени: {ch.ts_reversals}"]))
        return out

    def _rule_retrans(self, data: dict) -> list[Recommendation]:
        total = data["parsed_total"] or 1
        if not data["retrans_total"]:
            return []
        pct = 100.0 * data["retrans_total"] / (total + data["retrans_total"])
        sev = "warning" if pct >= self.cfg.coilers_retrans_pct else "info"
        return [Recommendation(
            id="coilers-retrans",
            severity=sev,
            title="Ретрансмиссии TCP в каналах Coilers",
            problem=(f"Повторных передач: {data['retrans_total']} — "
                     f"{pct:.1f}% от всех кадров каналов."),
            advice=("Ретрансмиссии — признак перегрузки сегмента или сбоя "
                    "первой передачи; при росте влияют на своевременность "
                    "данных."),
            evidence=[f"{C.esc(_sig_text(ch.telegram))}: {ch.retrans}"
                      for ch in data["channels"] if ch.retrans],
            commands=[self._cmd(
                '-Y "tcp.port==' + "||tcp.port==".join(
                    str(p) for p in self.ports)
                + ' && tcp.analysis.retransmission" -T fields -e frame.number '
                "-e frame.time -e ip.src -e ip.dst | head -20")])]

    def _rule_misc(self, data: dict) -> list[Recommendation]:
        out = []
        for port, cnt in data["misc"].items():
            if cnt:
                out.append(Recommendation(
                    id=f"coilers-misc-{port}",
                    severity="info",
                    title=f"Неразобранные кадры на порту {port}",
                    problem=(f"{cnt} кадров с payload не совпали с "
                             "сигнатурой телеграмм канала."),
                    advice=("Проверьте, не изменилась ли структура (другая "
                            "версия Coilers.xml) или не идёт ли на порт "
                            "посторонний трафик."),
                    evidence=[": ".join(
                        f"кадр {n} ({t})" if i == 1 else f"{n} ({t})"
                        for i, n, t in ())
                        if False else (
                        "Примеры: " + "; ".join(
                            f"кадр {n}, {t}" for _p, n, t
                            in data["misc_examples"]))],
                    commands=[self._cmd(
                        f'-Y "tcp.port=={port} && tcp.payload" '
                        "-T fields -e frame.number -e frame.time "
                        "-e tcp.payload | head -15")]))
        return out

    def _rule_syns(self, gen: dict) -> list[Recommendation]:
        if not gen["syn_to_ports"]:
            return []
        pairs = ", ".join(f":{p} ({v})" for p, v in
                          gen["syn_to_ports"].most_common())
        sev = "info" if all(v < self.cfg.coilers_syn_warn
                            for v in gen["syn_to_ports"].values()) else "warning"
        return [Recommendation(
            id="coilers-reconnects",
            severity=sev,
            title="Новые подключения к портам Coilers",
            problem=f"SYN-пакетов на порты каналов: {pairs}.",
            advice=("Транслятор перезапускался или соединения рвались; при "
                    "постоянных переподключениях проверьте стабильность "
                    "соединений."))]

    def _gap_period(self, ch: _ChannelStats) -> str:
        if ch.gap_start is None or ch.gap_end is None:
            return ""
        return (f"пауза {C.fmt_dur(ch.gap_worst)} в период "
                f"{epoch_to_str(ch.gap_start)} – {epoch_to_str(ch.gap_end)}")