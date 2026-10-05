"""Ветка анализа протокола SINEC H1 (S5 fetch/write) поверх ISO-TCP.

SINEC H1 — «сырой» протокол обмена с контроллерами Siemens S5/S7 по
RFC 1006 (fetch/write); типовой порт — 2000. Каждое сообщение начинается
с сигнатуры ``S5``, далее общая длина и цепочка блоков::

    53 35 | len | [тип, длина блока, тело…]… | ff 02

Типы блоков: ``0x01`` — код операции, ``0x03`` — адрес (область памяти,
номер блока, начальное слово, число слов), ``0x0F`` — код ответа,
``0xFF`` — пустой блок-терминатор. Длина блока включает собственный
заголовок (тип + длина), то есть блок «код операции» — это ``01 03 <код>``.
Коды операций: 3/4 — запись (запрос/ответ), 5/6 — чтение (запрос/ответ).

Ответ на чтение устроен иначе: адресного блока в нём нет (какой DB
отвечает — известно только из запроса), объявленная длина покрывает
только заголовок, а возвращённые слова идут следом без заголовка
блока::

    53 35 10 | 01 03 06 | 0f 03 00 | ff 07 00 00 00 00 00 | данные…

Сколько именно байт данных относится к ответу, известно только из
сопоставленного запроса (``2 * dlen``), поэтому длину хвоста ветка
уточняет по очереди неотвеченных запросов.

tshark такой поток разбирает (диссектор ``packet-h1.c`` подключён как
эвристика к TCP и понимает поля ``h1.opcode``/``h1.org``/``h1.dbnr``/
``h1.dwnr``/``h1.dlen``), но **только первое** сообщение сегмента: хвост
уходит в общий диссектор данных. Поэтому ветка читает ``tcp.payload`` и
разбирает всю цепочку сообщений сама.

Свойства протокола, на которые опирается анализ:

* номера ссылки/транзакции в H1 нет, поэтому сопоставление запроса и
  ответа возможно строго по порядку (FIFO);
* типовой опрос шлёт запросы пачками по два-три сообщения в одном
  TCP-сегменте и не ждёт ответа на каждое — глубину неотвеченных
  запросов ограничивает только окно TCP;
* в одностороннем захвате (например, снятом «сверху» только со стороны
  клиента) ответов PLC в файле нет. Их объём и момент прихода
  восстанавливаются по полям ``tcp.ack`` встречных ACK: чистый ACK,
  подтверждающий данные сервера, доказывает, что ответ дошёл до клиента.
  Отсюда — нижняя оценка отклика и учёт неотвеченных запросов.
"""

from __future__ import annotations

import math
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Config
from ..report import components as C
from ..tshark_runner import find_tshark, run_list, stream_fields
from .base import (
    SEVERITY_CRITICAL,
    SEVERITY_WARNING,
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

# --- Формат сообщения SINEC H1 ---------------------------------------------

H1_MAGIC = b"S5"

BLOCK_EMPTY = 0xFF
BLOCK_OPCODE = 0x01
BLOCK_REQUEST = 0x03
BLOCK_RESPONSE = 0x0F

OP_WRITE_REQ = 3
OP_WRITE_RSP = 4
OP_READ_REQ = 5
OP_READ_RSP = 6

REQUEST_OPS = frozenset({OP_WRITE_REQ, OP_READ_REQ})
RESPONSE_OPS = frozenset({OP_WRITE_RSP, OP_READ_RSP})

#: Пара «код операции запроса» → «код операции ответа» (FIFO-сопоставление)
PAIRED_OPCODE = {OP_WRITE_REQ: OP_WRITE_RSP, OP_READ_REQ: OP_READ_RSP}

OPCODES = {
    OP_WRITE_REQ: "запись (Write Request)",
    OP_WRITE_RSP: "ответ на запись",
    OP_READ_REQ: "чтение (Read Request)",
    OP_READ_RSP: "ответ на чтение",
}

#: Области памяти S5 (поле h1.org, таблица диссектора packet-h1.c)
ORG_NAMES = {
    0x01: "DB", 0x02: "MB", 0x03: "EB", 0x04: "AB", 0x05: "PB",
    0x06: "ZB", 0x07: "TB", 0x08: "BS", 0x09: "AS", 0x0A: "DX",
    0x10: "DE", 0x11: "QB",
}

RETURN_CODES = {
    0x00: "нет ошибки",
    0x02: "запрошенный блок не существует",
    0x03: "запрошенный блок слишком мал",
    0xFF: "ошибка, причина неизвестна",
}

BLOCK_NAMES = {
    BLOCK_OPCODE: "код операции",
    BLOCK_REQUEST: "адрес",
    BLOCK_RESPONSE: "код ответа",
    BLOCK_EMPTY: "пустой блок",
}

#: Стандартный порт SINEC H1 (ISO-TCP fetch/write)
H1_PORTS = (2000,)

#: Операция = (код операции, тип памяти, номер блока, первое слово, слов)
OpKey = tuple

#: Блок адреса = (тип памяти, номер блока, первое слово, слов)
AddrBlock = tuple


def _seq_ge(a: int, b: int) -> bool:
    """``a >= b`` в 32-битном кольце номеров последовательности TCP."""
    return ((a - b) & 0xFFFFFFFF) < 0x7FFFFFFF


@dataclass
class H1Message:
    """Одно разобранное сообщение H1."""

    raw: bytes
    opcode: int | None = None
    #: Все блоки адреса запроса — их может быть несколько в одном сообщении
    addrs: list[AddrBlock] = field(default_factory=list)
    retcode: int | None = None
    blocks: int = 0                  # сколько блоков разобрано
    truncated: bool = False          # длина блока вышла за границу сообщения
    data: bytes = b""                # хвост ответа на чтение (без заголовка)

    @property
    def org(self) -> int | None:
        """Тип памяти первого блока адреса (для совместимости с h1.org)."""
        return self.addrs[0][0] if self.addrs else None

    @property
    def db(self) -> int | None:
        """Номер блока первого блока адреса."""
        return self.addrs[0][1] if self.addrs else None

    @property
    def dwnr(self) -> int | None:
        """Первое слово первого блока адреса."""
        return self.addrs[0][2] if self.addrs else None

    @property
    def dlen(self) -> int | None:
        """Слов в первом блоке адреса (не во всём сообщении!)."""
        return self.addrs[0][3] if self.addrs else None

    @property
    def multi_addr(self) -> bool:
        """Запрос читает/пишет несколько областей одним сообщением."""
        return len(self.addrs) > 1

    @property
    def is_request(self) -> bool:
        return self.opcode in REQUEST_OPS

    @property
    def is_response(self) -> bool:
        return self.opcode in RESPONSE_OPS

    @property
    def op_name(self) -> str:
        return OPCODES.get(self.opcode, "операция с неизвестным кодом")

    @property
    def org_name(self) -> str:
        return ORG_NAMES.get(self.org,
                             "?" if self.org is None
                             else f"тип 0x{self.org:02x}")

    @property
    def error(self) -> bool:
        return self.retcode is not None and self.retcode != 0

    @property
    def ret_text(self) -> str:
        if self.retcode is None:
            return "&mdash;"
        return RETURN_CODES.get(self.retcode,
                                f"неизвестный код 0x{self.retcode:02x}")

    @property
    def words(self) -> int:
        """Слов во всём сообщении — сумма по всем блокам адреса."""
        return sum(d for _o, _d, _w, d in self.addrs)

    @property
    def data_words(self) -> int:
        """Слов в хвосте ответа на чтение (длина известна только из запроса)."""
        return len(self.data) // 2

    def area(self) -> str:
        """Область памяти в виде «DB200» (пусто, если адреса нет)."""
        if self.org is None or self.db is None:
            return "?"
        return f"{self.org_name}{self.db}"

    def range_text(self, dash: str = "–") -> str:
        """Запрошенный диапазон слов: «DW0–51»."""
        return _range_text(self.dwnr, self.dlen, dash)

    def areas_text(self, dash: str = "–", sep: str = " + ") -> str:
        """Все запрошенные области: «DB200 DW0–51 + DB201 DW0–42»."""
        if not self.addrs:
            return "?"
        return sep.join(
            f"{ORG_NAMES.get(org, '?')}{db} {_range_text(dwnr, dlen, dash)}"
            for org, db, dwnr, dlen in self.addrs)

    def op_key(self) -> OpKey | None:
        """Ключ группировки операций или None, если код операции неизвестен.

        Для одного блока адреса ключ совпадает с набором полей h1.opcode/
        h1.org/h1.dbnr/h1.dwnr/h1.dlen. Запрос с несколькими областями одним
        сообщением — отдельная операция, поэтому его ключ длиннее.
        """
        if self.opcode is None:
            return None
        if len(self.addrs) <= 1:
            return (self.opcode, self.org, self.db, self.dwnr, self.dlen)
        return (self.opcode, tuple(self.addrs))


def parse_h1_messages(buf: bytes,
                      expect_data=None) -> tuple[list[H1Message], int]:
    """Разобрать подряд идущие сообщения H1 в начале ``buf``.

    Возвращает список сообщений и число потреблённых байт. Разбор
    останавливается на первом байте, который уже не начинает сообщение
    H1: в одном TCP-сегменте их может быть несколько, а после них может
    идти посторонний payload.

    Ответ на чтение отличается от запроса: объявленная длина покрывает
    только заголовок (``S5``, код операции, код ответа, пустой блок), а
    возвращённые данные идут следом **без заголовка блока** — их длина
    равна ``2 * dlen`` сопоставленного запроса. Поэтому ``expect_data`` —
    необязательный обратный вызов ``(сообщение) -> сколько байт данных
    ждать``; без него остаток сегмента приписывается первому ответу на
    чтение целиком.
    """
    msgs: list[H1Message] = []
    pos = 0
    while pos + 3 <= len(buf):
        if buf[pos:pos + 2] != H1_MAGIC:
            break
        total = buf[pos + 2]
        if total < 4 or pos + total > len(buf):
            break                                   # длина не помещается
        m = _parse_one(buf[pos:pos + total])
        pos += total
        if m.opcode == OP_READ_RSP and pos < len(buf):
            n = expect_data(m) if expect_data is not None else None
            take = len(buf) - pos if n is None else min(max(n, 0),
                                                        len(buf) - pos)
            m.data = buf[pos:pos + take]
            pos += take
        msgs.append(m)
    return msgs, pos


def _parse_one(raw: bytes, data: bytes = b"") -> H1Message:
    """Разбор одного сообщения: сигнатура, длина, цепочка блоков."""
    m = H1Message(raw=raw, data=data)
    off = 3                                       # сигнатура + длина
    while off + 2 <= len(raw):
        btype, blen = raw[off], raw[off + 1]
        if blen < 2:
            break
        end = off + blen
        if end > len(raw):
            m.truncated = True                     # блок обрезан концом пакета
            end = len(raw)
        body = raw[off + 2:end]
        if btype == BLOCK_OPCODE and body:
            m.opcode = body[0]
        elif btype == BLOCK_REQUEST and len(body) >= 6:
            # блоков адреса в сообщении может быть несколько — запрос на
            # чтение двух DB одним сообщением вполне штатен, и данные ответа
            # приходят единым хвостом, поэтому все блоки сохраняем
            m.addrs.append((body[0], body[1],
                            int.from_bytes(body[2:4], "big"),
                            int.from_bytes(body[4:6], "big")))
        elif btype == BLOCK_RESPONSE and body:
            m.retcode = body[0]
        m.blocks += 1
        off = end
    return m


def describe_message(raw: bytes,
                    data: bytes = b"") -> list[tuple[int, bytes, str]]:
    """Разбор сообщения по байтам: (смещение, байты, как читается).

    ``raw`` — объявленная часть сообщения, ``data`` — хвост ответа на
    чтение, который в разборе идёт без заголовка блока.
    """
    if len(raw) < 2 or raw[0:2] != H1_MAGIC:
        return []
    rows: list[tuple[int, bytes, str]] = [
        (0, raw[0:2], "сигнатура <code>S5</code>")]
    if len(raw) < 3:
        return rows
    rows.append((2, raw[2:3],
                 f"длина сообщения: {raw[2]} Б (включая сигнатуру"
                 + ("; возвращённые данные идут после неё"
                    if data else ")")))
    off = 3
    while off + 2 <= len(raw):
        btype, blen = raw[off], raw[off + 1]
        if blen < 2:
            rows.append((off, raw[off:],
                         "разбор прерван: длина блока равна 0"))
            break
        end = min(off + blen, len(raw))
        body = raw[off + 2:end]
        if btype == BLOCK_OPCODE and body:
            rows.append((off, raw[off:end],
                         f"блок кода операции: {OPCODES.get(body[0], '?')}"))
        elif btype == BLOCK_REQUEST and len(body) >= 6:
            org, db = body[0], body[1]
            dwnr = int.from_bytes(body[2:4], "big")
            dlen = int.from_bytes(body[4:6], "big")
            tail = dwnr + dlen - 1 if dlen else dwnr
            rng = f"DW{dwnr}" + (f"–{tail}" if tail != dwnr else "")
            rows.append((off, raw[off:end],
                         f"блок адреса: {ORG_NAMES.get(org, '?')}{db}, "
                         f"{rng}, {dlen} слов"))
        elif btype == BLOCK_RESPONSE and body:
            rows.append((off, raw[off:end],
                         "блок кода ответа: "
                         f"{RETURN_CODES.get(body[0], 'неизвестный код')}"))
        elif btype == BLOCK_EMPTY:
            rows.append((off, raw[off:end],
                         "пустой блок" + (" — дальше идут данные ответа"
                                          if data else " — конец сообщения")))
        else:
            rows.append((off, raw[off:end],
                         f"блок «{BLOCK_NAMES.get(btype, f'тип 0x{btype:02x}')}"
                         f"»: {len(body)} Б данных"))
        off = end
    if data:
        rows.append((len(raw), data,
                     f"данные ответа без заголовка блока: {len(data)} Б = "
                     f"{len(data) // 2} слов (длина известна только из "
                     f"сопоставленного запроса)"))
    return rows


def _range_text(dwnr: int | None, dlen: int | None,
                dash: str = "–") -> str:
    """Диапазон слов по номеру первого слова и длине."""
    if dwnr is None:
        return "?"
    if not dlen:
        return f"DW{dwnr}"
    end = dwnr + dlen - 1
    return f"DW{dwnr}" if end == dwnr else f"DW{dwnr}{dash}{end}"


def op_name(op: OpKey, dash: str = "–") -> str:
    """Читаемое имя операции: «чтение DB200 DW0–51».

    Разделитель диапазона по умолчанию — обычный тире: результат
    вставляется и в текст KPI, и в ``C.esc(...)``, поэтому HTML-сущности
    здесь были бы видны как ``&ndash;``.
    """
    opcode, *rest = op
    kind = OPCODES.get(opcode, f"код 0x{opcode:02x}"
                        if opcode is not None and opcode >= 0
                        else "операция без кода").split(" (")[0]
    if rest and isinstance(rest[0], tuple):
        # несколько областей одним сообщением: (org, db, dwnr, dlen) в кортеже
        addrs = rest[0]
        return f"{kind} " + " + ".join(
            f"{ORG_NAMES.get(org, '?')}{db} {_range_text(dwnr, dlen, dash)}"
            for org, db, dwnr, dlen in addrs)
    org, db, dwnr, dlen = rest
    area = f"{ORG_NAMES.get(org, '?')}{db}"
    if dwnr is None:
        return f"{kind} {area}"
    tail = dwnr + dlen - 1 if dlen else dwnr
    rng = f"DW{dwnr}" + (f"{dash}{tail}" if tail != dwnr else "")
    return f"{kind} {area} {rng}"


def op_label(op: OpKey) -> str:
    """Метка для карты опроса (совпадает со стилем s7comm: «DB200@0..51»)."""
    opcode, *rest = op
    if rest and isinstance(rest[0], tuple):
        return op_name(op, dash="-")
    org, db, dwnr, dlen = rest
    if opcode != OP_READ_REQ or dwnr is None:
        return op_name(op, dash="-")
    base = f"{ORG_NAMES.get(org, '?')}{db}"
    tail = dwnr + dlen - 1 if dlen else dwnr
    return base + (f"@{dwnr}..{tail}" if tail != dwnr else f"@{dwnr}")


def op_words(op: OpKey) -> int:
    """Слов в одном сообщении с такой операцией (сумма по блокам адреса)."""
    return sum(d for _o, _db, _w, d in op_all_addrs(op))


def op_all_addrs(op: OpKey) -> list[AddrBlock]:
    """Все блоки адреса операции: [(org, db, dwnr, dlen), …]."""
    rest = op[1:]
    if rest and isinstance(rest[0], tuple):
        return list(rest[0])
    if len(rest) > 3:
        return [(rest[0], rest[1], rest[2], rest[3])]
    return []


def op_areas(op: OpKey) -> list[tuple[int, int]]:
    """Диапазоны слов всех блоков адреса операции: [(dwnr, dlen), …]."""
    return [(dwnr, dlen) for _o, _db, dwnr, dlen in op_all_addrs(op)]


def cv_of(values) -> float | None:
    """Коэффициент вариации (мало значений или неположительное среднее)."""
    vals = list(values)
    if len(vals) < 2:
        return None
    mean = sum(vals) / len(vals)
    if mean <= 0:
        return None
    var = sum((v - mean) ** 2 for v in vals) / (len(vals) - 1)
    return math.sqrt(var) / mean


# --- Агрегаты --------------------------------------------------------------

@dataclass
class _General:
    total_packets: int = 0
    total_bytes: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    ip_pkts: Counter = field(default_factory=Counter)
    ip_bytes_tx: Counter = field(default_factory=Counter)
    ip_bytes_rx: Counter = field(default_factory=Counter)
    syn_total: int = 0
    rst_total: int = 0
    fin_total: int = 0
    retrans_total: int = 0
    syn_to_port: Counter = field(default_factory=Counter)
    syn_to_ip: Counter = field(default_factory=Counter)

    @property
    def duration(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return max(self.last_ts - self.first_ts, 0.0)


@dataclass
class _AckState:
    """Учёт ACK по одному соединению пары клиент↔PLC.

    ``pending`` — отправленные сегменты с данными, ответ на которые ещё
    не подтверждён встречным ACK клиента. Очередь ограничена по размеру:
    файл может содержать сотни тысяч сегментов.
    """

    pending: deque = field(default_factory=deque)
    seen_client_ack: int | None = None    # ACK клиента → байты, доставленные PLC
    seen_server_ack: int | None = None    # ACK PLC → байты, принятые от клиента
    resp_bytes: int = 0                   # объём ответов PLC по ACK клиента
    req_acked_bytes: int = 0              # объём запросов, принятых PLC
    dropped: int = 0                      # сброшено при переполнении очереди


@dataclass
class _PairStats:
    """Агрегат по паре «клиент → PLC» в терминах протокола H1."""

    client: str
    server: str
    client_ports: set = field(default_factory=set)
    server_ports: set = field(default_factory=set)
    streams: set = field(default_factory=set)
    req_msgs: int = 0
    resp_msgs: int = 0
    req_bytes: int = 0
    resp_bytes: int = 0
    req_words: int = 0
    resp_words: int = 0
    req_segs: int = 0                     # сегментов с запросами
    retrans: int = 0
    window: int | None = None
    first_ts: float | None = None
    last_ts: float | None = None
    opcodes: Counter = field(default_factory=Counter)
    ops: Counter = field(default_factory=Counter)      # OpKey -> сколько раз
    retcodes: Counter = field(default_factory=Counter)
    msgs_per_seg: Counter = field(default_factory=Counter)
    last_seg_ts: float | None = None
    period: Reservoir = field(default_factory=lambda: Reservoir(0))
    rtt: Reservoir = field(default_factory=lambda: Reservoir(0))      # по видимым ответам
    ack_rtt: Reservoir = field(default_factory=lambda: Reservoir(0))  # нижняя оценка по ACK
    last_req_raw: bytes | None = None
    repeat_msgs: int = 0
    repeat_run: int = 0
    repeat_run_max: int = 0
    repeat_examples: list = field(default_factory=list)
    fifo: deque = field(default_factory=deque)          # ответы строго по порядку
    orphan_resps: int = 0
    size_mismatch: int = 0              # объём данных ответа ≠ dlen запроса
    unacked: int = 0
    unacked_bytes: int = 0
    unacked_frames: list = field(default_factory=list)
    resp_bytes_est: int = 0
    req_acked_bytes: int = 0

    @property
    def side(self) -> str:
        return f"{self.client} → {self.server}"

    @property
    def server_port(self) -> int | None:
        return sorted(self.server_ports)[0] if self.server_ports else None


class SinecH1Analyzer(BaseBranch):
    name = "sinec-h1"
    title = "Анализ SINEC H1 (S5 fetch/write)"
    description = (
        "Разбор протокола Siemens SINEC H1 поверх ISO-TCP: карта опроса "
        "блоков памяти DB/MB, коды операций чтения и записи, батчинг "
        "запросов в сегменты, периодика и джиттер таймера, отклик PLC "
        "(по видимым ответам и по ACK), неотвеченные запросы, "
        "ретрансмиссии и односторонние захваты."
    )

    FIELDS_GENERAL = [
        "frame.time_epoch", "frame.len", "ip.src", "ip.dst",
        "tcp.stream", "tcp.srcport", "tcp.dstport",
        "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.reset", "tcp.flags.fin",
        "tcp.analysis.retransmission",
    ]

    FIELDS_H1 = [
        "frame.number", "frame.time_epoch", "frame.len",
        "ip.src", "ip.dst", "tcp.stream", "tcp.srcport", "tcp.dstport",
        "tcp.seq", "tcp.ack", "tcp.len", "tcp.payload", "tcp.flags.ack",
        "tcp.analysis.retransmission", "tcp.window_size_value",
    ]

    #: Потолок очереди неотвеченных запросов пары (сопоставление по FIFO)
    FIFO_MAX = 20000
    #: Потолок длины очереди неподтверждённых сегментов в _AckState
    PENDING_MAX = 4096

    def __init__(self) -> None:
        super().__init__()
        self._reset_pass_state()

    def _reset_pass_state(self) -> None:
        """Обнулить счётчики разбора H1 (до прохода и для юнит-тестов)."""
        self._h1_frames = 0
        self._msgs_total = 0
        self._unparsed_bytes = 0
        self._max_msgs_per_frame = 0
        self._example: tuple | None = None        # (кадр, raw, H1Message, n)
        self._example_resp: tuple | None = None   # первый ответ с данными

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

        progress("Проход 1/2: общий обзор TCP/IP…", pct=20)
        gen = self._pass_general()
        result.capture_start_ts = gen.first_ts

        progress("Проход 2/2: разбор сообщений SINEC H1…", pct=55)
        self._pass_h1()

        self._set_servers(p.server for p in self._pairs.values())
        if not self._pairs:
            return self._empty_result(result, gen)

        result.kpi = self._build_kpi(gen)
        result.sections = self._build_sections(gen)
        result.recommendations = self._build_recommendations(gen)
        result.server_colors = dict(self._srv_colors)
        result.metrics = self._metrics(gen)
        result.read_labels = frozenset(self._pollmap_labels())
        return result

    # -- Проход 1: общий обзор ------------------------------------------------

    def _pass_general(self) -> _General:
        g = _General()
        ports = set(H1_PORTS)
        for i, r in enumerate(stream_fields(self.tshark, self.pcap_str,
                                           self.FIELDS_GENERAL)):
            g.total_packets += 1
            plen = to_int(r.get("frame.len"), 0)
            g.total_bytes += plen
            ts = to_float(r.get("frame.time_epoch"))
            if ts is not None:
                if g.first_ts is None:
                    g.first_ts = ts
                g.last_ts = ts
            src, dst = r.get("ip.src", ""), r.get("ip.dst", "")
            if src:
                g.ip_pkts[src] += 1
                g.ip_bytes_tx[src] += plen
            if dst:
                g.ip_bytes_rx[dst] += plen
            sport = to_int(r.get("tcp.srcport"))
            dport = to_int(r.get("tcp.dstport"))
            if truthy(r.get("tcp.flags.syn", "")):
                g.syn_total += 1
                if not truthy(r.get("tcp.flags.ack", "")):
                    if dport in ports or sport in ports:
                        g.syn_to_port[dport if dport in ports else sport] += 1
                    if dst:
                        g.syn_to_ip[dst] += 1
            if truthy(r.get("tcp.flags.reset", "")):
                g.rst_total += 1
            if truthy(r.get("tcp.flags.fin", "")):
                g.fin_total += 1
            if truthy(r.get("tcp.analysis.retransmission", "")):
                g.retrans_total += 1
            if (i + 1) % 100000 == 0:
                self.progress(f"  обработано {i + 1} пакетов…", pct=20)
        return g

    # -- Проход 2: сообщения H1 и учёт ACK -----------------------------------

    def _pass_h1(self) -> None:
        self._pairs: dict[tuple[str, str], _PairStats] = {}
        self._acks: dict[tuple, _AckState] = {}
        self._dir_role: dict[tuple, str] = {}     # (src,dst,stream) -> роль
        self._reset_pass_state()

        # Кандидаты — сегменты с сигнатурой H1 плюс чистые ACK: по ACK мы
        # считаем приход ответов PLC, даже когда самих ответов в файле нет.
        filt = "tcp.payload contains 53:35 || (tcp.flags.ack==1 && tcp.len==0)"
        for row in stream_fields(self.tshark, self.pcap_str, self.FIELDS_H1,
                                 display_filter=filt):
            src, dst = row.get("ip.src", ""), row.get("ip.dst", "")
            seg_len = to_int(row.get("tcp.len"), 0)
            payload = (row.get("tcp.payload") or "").replace(":", "")
            ts = to_float(row.get("frame.time_epoch"))
            frame = to_int(row.get("frame.number"), 0)
            stream = to_int(row.get("tcp.stream"), -1)
            retrans = truthy(row.get("tcp.analysis.retransmission", ""))
            if retrans:
                pair = self._pair_by_role(src, dst, stream)
                if pair is not None:
                    pair.retrans += 1
            if payload:
                try:
                    buf = bytes.fromhex(payload)
                except ValueError:
                    buf = b""
                msgs, used = parse_h1_messages(
                    buf, expect_data=self._data_expecter(stream))
                if msgs:
                    self._h1_frames += 1
                    self._msgs_total += len(msgs)
                    self._max_msgs_per_frame = max(self._max_msgs_per_frame,
                                                   len(msgs))
                    self._unparsed_bytes += len(buf) - used
                    if self._example is None:
                        self._example = (frame, buf, msgs[0], len(msgs))
                    if self._example_resp is None:
                        self._example_resp = next(
                            (m for m in msgs if m.is_response and m.data),
                            None)
                        if self._example_resp is not None:
                            self._example_resp = (frame, buf,
                                                  self._example_resp, len(msgs))
                    self._on_segment(buf, msgs, row, src, dst, stream, ts,
                                     frame, seg_len, retrans)
                else:
                    self._unparsed_bytes += len(buf)
            else:
                # У сегмента с данными tcp.ack — накопленный счётчик байт в
                # обратном направлении: такой кадр подтверждал бы собственный
                # запрос, поэтому в учёте отклика участвуют только чистые ACK.
                self._on_ack(row, src, dst, stream, ts)
        self._finalize()

    # -- учёт ------------------------------------------------------------------

    def _pair(self, client: str, server: str) -> _PairStats:
        p = self._pairs.get((client, server))
        if p is None:
            p = self._pairs[(client, server)] = _PairStats(
                client=client, server=server,
                period=Reservoir(self.cfg.max_intervals_per_target),
                rtt=Reservoir(self.cfg.max_rtts_per_pair),
                ack_rtt=Reservoir(self.cfg.max_rtts_per_pair))
        return p

    def _ack_state(self, pair: _PairStats, stream: int) -> _AckState:
        key = (pair.client, pair.server, stream)
        st = self._acks.get(key)
        if st is None:
            st = self._acks[key] = _AckState()
        return st

    def _pair_by_role(self, src: str, dst: str,
                      stream: int) -> _PairStats | None:
        """Пара по уже известному направлению ролей (иначе None)."""
        role = self._dir_role.get((src, dst, stream))
        if role == "client":
            return self._pairs.get((src, dst))
        if role == "server":
            return self._pairs.get((dst, src))
        return None

    def _pair_by_stream(self, stream: int) -> _PairStats | None:
        """Пара по номеру потока TCP (None, если поток неоднозначен)."""
        found = None
        for pair in self._pairs.values():
            if stream in pair.streams:
                if found is not None:
                    return None              # поток общий у нескольких пар
                found = pair
        return found

    def _on_segment(self, buf: bytes, msgs: list[H1Message], row: dict,
                    src: str, dst: str, stream: int, ts: float | None,
                    frame: int, seg_len: int, retrans: bool) -> None:
        """Учёт всех сообщений одного TCP-сегмента (в т.ч. «пачки»)."""
        reqs: Counter = Counter()
        for msg in msgs:
            pair = self._on_message(msg, src, dst, stream, ts, frame,
                                    to_int(row.get("tcp.srcport")),
                                    to_int(row.get("tcp.dstport")))
            if pair is not None and msg.is_request:
                reqs[(pair.client, pair.server, stream)] += 1
        win = to_int(row.get("tcp.window_size_value"), -1)
        for (client, server, st_id), n in reqs.items():
            pair = self._pairs[(client, server)]
            pair.req_segs += 1
            pair.req_bytes += seg_len
            pair.msgs_per_seg[n] += 1
            if win > 0:
                pair.window = win
            # сегмент уходит в очередь неотвеченных — по одному входу на
            # сегмент, а не на сообщение (в пачке их несколько)
            if ts is not None and not retrans:
                st = self._ack_state(pair, st_id)
                if len(st.pending) >= self.PENDING_MAX:
                    st.pending.popleft()             # потолок памяти
                    st.dropped += 1
                seq = to_int(row.get("tcp.seq"))
                st.pending.append((seq + seg_len, ts, frame, seg_len))

    def _on_message(self, msg: H1Message, src: str, dst: str, stream: int,
                    ts: float | None, frame: int, sport: int,
                    dport: int) -> _PairStats | None:
        """Одно разобранное сообщение: роль направления, операция, адрес."""
        if msg.is_request:
            client, server, cport, srv_port = src, dst, sport, dport
        elif msg.is_response:
            client, server, cport, srv_port = dst, src, dport, sport
        else:
            # Код операции неизвестен: направление определяем по порту H1 —
            # к серверу клиент шлёт запросы.
            if sport in H1_PORTS and dport not in H1_PORTS:
                client, server = dst, src
            else:
                client, server = src, dst
            cport = sport if client == src else dport
            srv_port = dport if client == src else sport
        self._dir_role[(src, dst, stream)] = \
            "client" if src == client else "server"
        self._dir_role[(dst, src, stream)] = \
            "server" if src == client else "client"
        pair = self._pair(client, server)
        pair.streams.add(stream)
        pair.client_ports.add(cport)
        pair.server_ports.add(srv_port)
        if ts is not None:
            pair.first_ts = ts if pair.first_ts is None \
                else min(pair.first_ts, ts)
            pair.last_ts = ts if pair.last_ts is None \
                else max(pair.last_ts, ts)
        pair.opcodes[msg.opcode if msg.opcode is not None else -1] += 1

        if not msg.is_request:
            self._on_response(msg, pair, ts)
            return pair

        pair.req_msgs += 1
        pair.req_words += msg.words
        op = msg.op_key()
        if op is not None and len(pair.ops) < self.cfg.pollmap_max_registers:
            pair.ops[op] += 1
        if ts is not None:
            if pair.last_seg_ts is not None and ts > pair.last_seg_ts:
                pair.period.add(ts - pair.last_seg_ts)
            pair.last_seg_ts = ts
        # побайтово одинаковые соседние запросы (цикл без изменений)
        if pair.last_req_raw is not None and msg.raw == pair.last_req_raw:
            pair.repeat_msgs += 1
            pair.repeat_run += 1
            if len(pair.repeat_examples) < 6:
                pair.repeat_examples.append(frame)
        else:
            pair.repeat_run = 1
        pair.repeat_run_max = max(pair.repeat_run_max, pair.repeat_run)
        pair.last_req_raw = msg.raw
        if len(pair.fifo) < self.FIFO_MAX:
            # (код операции, время, длина запроса): по длине запроса
            # определяется объём данных в ответе на чтение
            pair.fifo.append((msg.opcode, ts, msg.words))
        return pair

    def _data_expecter(self, stream: int):
        """Обратный вызов разбора: сколько байт данных ждать в ответе.

        Ответ на чтение приходит без адресного блока и без длины данных —
        объём известен только из сопоставленного запроса, который лежит в
        начале очереди неотвеченных. В одном сегменте ответов может быть
        несколько, поэтому курсор ``seen`` двигается по ``fifo`` вместе с
        ними (сама очередь на этом шаге ещё не расходуется — она уменьшается
        ниже, в ``_on_response``).
        """
        seen = 0

        def expect(msg) -> int | None:
            nonlocal seen
            if msg.opcode != OP_READ_RSP:
                return 0
            pair = self._pair_by_stream(stream)
            if pair is None:
                return None
            for i in range(seen, len(pair.fifo)):
                op, _ots, words = pair.fifo[i]
                if op == OP_READ_REQ:
                    seen = i + 1                   # следующий ответ — за ним
                    return 2 * words
            return None
        return expect

    def _on_response(self, msg: H1Message, pair: _PairStats,
                     ts: float | None) -> None:
        """Ответ PLC: код ответа и отклик по порядковой (FIFO) очереди."""
        pair.resp_msgs += 1
        pair.resp_bytes += len(msg.raw) + len(msg.data)
        if msg.retcode is not None:
            pair.retcodes[msg.retcode] += 1
        want = self._paired_opcode(msg.opcode)
        matched = None
        # тот же порядок обхода, что и в _data_expecter: ответ на чтение идёт
        # к первому неотвеченному запросу чтения, прочие ответы — к первому
        # запросу своего типа операции
        for i, (op, ots, words) in enumerate(pair.fifo):
            if want is not None and op != want:
                continue
            matched = (op, ots, words)
            # deque не умеет удалять срезы — выбрасываем по одному
            for _ in range(i + 1):
                pair.fifo.popleft()
            break
        if matched is None:
            pair.orphan_resps += 1
            return
        _op, ots, words = matched
        # объём данных известен только из запроса; проверяем, что PLC вернул
        # столько же (при ошибке код ответа ненулевой и данных может не быть)
        pair.resp_words += words
        if msg.data and msg.data_words != words:
            pair.size_mismatch += 1
        if ts is not None and ots is not None and ts >= ots:
            pair.rtt.add(ts - ots)

    @staticmethod
    def _paired_opcode(op: int | None) -> int | None:
        """Код операции запроса, на который пришёл ответ ``op``."""
        for req, rsp in PAIRED_OPCODE.items():
            if rsp == op:
                return req
        return None

    def _on_ack(self, row: dict, src: str, dst: str, stream: int,
                ts: float | None) -> None:
        """Учёт чистого ACK: объём доставленных байт и момент прихода ответа.

        ACK, отправленный клиентом, подтверждает байты **от PLC** — по нему
        видно, что ответ дошёл; ACK от PLC подтверждает приём запросов.
        """
        pair = self._pair_by_role(src, dst, stream)
        if pair is None or not truthy(row.get("tcp.flags.ack", "")):
            return
        ack = to_int(row.get("tcp.ack"), -1)
        if ack < 0 or ts is None:
            return
        st = self._ack_state(pair, stream)
        if src == pair.client:
            prev = st.seen_client_ack
            st.seen_client_ack = ack
            if prev is not None and _seq_ge(ack, prev):
                pair.resp_bytes_est += (ack - prev) & 0xFFFFFFFF
            # ответ дошёл: снимаем отправленные сегменты, чьи байты этим
            # ACK подтверждены
            while st.pending and _seq_ge(ack, st.pending[0][0]):
                _seq_end, ots, _frame, _blen = st.pending.popleft()
                if ots is not None and ts >= ots:
                    pair.ack_rtt.add(ts - ots)
        elif src == pair.server:
            prev = st.seen_server_ack
            st.seen_server_ack = ack
            if prev is not None and _seq_ge(ack, prev):
                pair.req_acked_bytes += (ack - prev) & 0xFFFFFFFF

    def _finalize(self) -> None:
        """Итоги по каждой паре: сегменты без подтверждённого ответа."""
        for pair in self._pairs.values():
            left = left_bytes = 0
            for (client, server, _st), st in self._acks.items():
                if (client, server) != (pair.client, pair.server):
                    continue
                for _seq_end, _ots, ofr, blen in st.pending:
                    left += 1
                    left_bytes += blen
                    if len(pair.unacked_frames) < self.cfg.h1_unacked_examples:
                        pair.unacked_frames.append(ofr)
            pair.unacked = left
            pair.unacked_bytes = left_bytes

    # -- сводные числа --------------------------------------------------------

    def _totals(self, gen: _General | None = None) -> dict:
        """Сводные числа по всем парам (KPI, метрики, правила)."""
        pairs = list(self._pairs.values())
        reqs = sum(p.req_msgs for p in pairs)
        resps = sum(p.resp_msgs for p in pairs)
        segs = sum(p.req_segs for p in pairs)
        periods = sorted(v for p in pairs for v in p.period)
        rtt = sorted(v for p in pairs for v in p.rtt)
        ack_rtt = sorted(v for p in pairs for v in p.ack_rtt)
        ops = {op for p in pairs for op in p.ops}
        dur = 0.0
        if gen is not None:
            dur = gen.duration
        else:
            dur = self._span()
        return {
            "pairs": pairs,
            "reqs": reqs,
            "resps": resps,
            "errs": sum(n for p in pairs
                        for rc, n in p.retcodes.items() if rc != 0),
            "unacked": sum(p.unacked for p in pairs),
            "unacked_bytes": sum(p.unacked_bytes for p in pairs),
            "segs": segs,
            "req_words": sum(p.req_words for p in pairs),
            "msgs": self._msgs_total,
            "ops": ops,
            "periods": periods,
            "rtt": rtt,
            "ack_rtt": ack_rtt,
            "med_period": percentile(periods, 50),
            "p95_period": percentile(periods, 95),
            "p50_rtt": percentile(rtt, 50),
            "p95_rtt": percentile(rtt, 95),
            "p50_ack": percentile(ack_rtt, 50),
            "p95_ack": percentile(ack_rtt, 95),
            "busy": sum(ack_rtt),
            "orphans": sum(p.orphan_resps for p in pairs),
            "repeats": sum(p.repeat_msgs for p in pairs),
            "retrans": sum(p.retrans for p in pairs),
            "resp_bytes_est": sum(p.resp_bytes_est for p in pairs),
            "resp_bytes": sum(p.resp_bytes for p in pairs),
            "streams": len({s for p in pairs for s in p.streams}),
            "syn": sum(gen.syn_to_ip.get(p.server, 0) for p in pairs)
            if gen else 0,
            "duration": dur,
        }

    def _span(self) -> float:
        """Длительность обмена по парам (когда недоступен первый проход)."""
        stamps = [p.first_ts for p in self._pairs.values()
                  if p.first_ts is not None]
        ends = [p.last_ts for p in self._pairs.values()
                if p.last_ts is not None]
        if not stamps or not ends:
            return 0.0
        return max(max(ends) - min(stamps), 0.0)

    def _metrics(self, gen: _General) -> dict[str, float]:
        t = self._totals(gen)
        msgs = t["reqs"] + t["resps"] or 1
        retrans = t["retrans"] or gen.retrans_total
        dur = gen.duration
        return {
            "h1_msgs": float(t["msgs"]),
            "h1_reqs": float(t["reqs"]),
            "h1_resps": float(t["resps"]),
            "h1_err_pct": 100.0 * t["errs"] / max(t["resps"], 1),
            "h1_unans_pct": 100.0 * t["unacked"] / max(t["segs"], 1),
            "h1_period_ms": (t["med_period"] or 0.0) * 1000.0,
            "h1_rtt_p95_ms": ((t["p95_rtt"] or t["p95_ack"]) or 0.0) * 1000.0,
            "h1_ack_p95_ms": (t["p95_ack"] or 0.0) * 1000.0,
            "h1_busy_pct": (100.0 * t["busy"] / dur) if dur else 0.0,
            "h1_ops": float(len(t["ops"])),
            "h1_words": float(t["req_words"]),
            "h1_plcs": float(len({p.server for p in t["pairs"]})),
            "h1_clients": float(len({p.client for p in t["pairs"]})),
            "h1_streams": float(t["streams"]),
            "h1_syn": float(t["syn"] or gen.syn_total),
            "h1_retrans_pct": 100.0 * retrans / max(msgs, 1),
        }

    def _build_kpi(self, gen: _General) -> list[KpiItem]:
        t = self._totals(gen)
        pairs = t["pairs"]
        if t["p50_rtt"] is not None:
            rtt_txt = f"{C.fmt_ms(t['p50_rtt'])} мс"
            rtt_hint = "по видимым ответам PLC"
        elif t["p50_ack"] is not None:
            rtt_txt = f"≥{C.fmt_ms(t['p50_ack'])} мс"
            rtt_hint = "нижняя оценка по ACK: ответы в файле не видны"
        else:
            rtt_txt = rtt_hint = "&mdash;"
        busy = 100.0 * t["busy"] / gen.duration if gen.duration else 0.0
        return [
            KpiItem("Длительность захвата", C.fmt_dur(gen.duration)),
            KpiItem("Сообщений H1", C.fmt_int(t["msgs"]),
                    f"{C.fmt_int(self._h1_frames)} сегментов, в среднем "
                    f"{t['msgs'] / max(t['segs'], 1):.1f} на сегмент"),
            KpiItem("Запросов / ответов",
                    f"{C.fmt_int(t['reqs'])} / {C.fmt_int(t['resps'])}",
                    "запросы видны всегда, ответы — только при "
                    "двустороннем захвате"),
            KpiItem("Уникальных операций", C.fmt_int(len(t["ops"])),
                    ", ".join(sorted({op_name(op) for op in t["ops"]})[:2])),
            KpiItem("Прочитано слов", C.fmt_int(t["req_words"]),
                    "сумма запрошенных объёмов чтения"),
            KpiItem("Цикл опроса",
                    f"{C.fmt_ms(t['med_period'])} мс"
                    if t["med_period"] is not None else "&mdash;",
                    f"p95 {C.fmt_ms(t['p95_period'])} мс"
                    if t["p95_period"] is not None else ""),
            KpiItem("Отклик PLC", rtt_txt, rtt_hint),
            KpiItem("Занятость PLC", f"{busy:.1f}%" if gen.duration
                    else "&mdash;",
                    "оценка суммой откликов — обычно намного меньше "
                    "периода опроса"),
            KpiItem("PLC / клиентов",
                    f"{C.fmt_int(len({p.server for p in pairs}))} / "
                    f"{C.fmt_int(len({p.client for p in pairs}))}"),
            KpiItem("Потоков / SYN",
                    f"{C.fmt_int(t['streams'])} / "
                    f"{C.fmt_int(gen.syn_total)}",
                    "SYN не видно, если захват начат по уже "
                    "установленным соединениям"),
        ]

    # -- секции ----------------------------------------------------------------

    def _build_sections(self, gen: _General) -> list[Section]:
        return [
            self._sec_general(gen),
            self._sec_format(gen),
            self._sec_pairs(gen),
            self._sec_ops(gen),
            self._sec_pollmap(gen),
            self._sec_timing(gen),
            self._sec_response(gen),
            self._sec_health(gen),
        ]

    def _sec_general(self, gen: _General) -> Section:
        t = self._totals(gen)
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
            ["Сегментов с H1", C.fmt_int(self._h1_frames)],
            ["Сообщений H1", C.fmt_int(t["msgs"])],
            ["SYN / RST (TCP)", f'{C.fmt_int(gen.syn_total)} / '
                                f'{C.fmt_int(gen.rst_total)}'],
        ]
        ip_rows = []
        for ip, cnt in sorted(gen.ip_pkts.items(),
                              key=lambda kv: -kv[1])[:8]:
            role = (f'<span class="num">{C.fmt_int(gen.syn_to_ip.get(ip, 0))}'
                    f"</span> SYN") if ip in gen.syn_to_ip else "клиент"
            ip_rows.append([
                f'<code class="inline">{C.esc(ip)}</code>',
                self._srv_cell(ip) if ip in self._srv_colors else role,
                f'<span class="num">{C.fmt_int(cnt)}</span>',
                f'<span class="num">'
                f'{C.fmt_bytes(gen.ip_bytes_tx.get(ip, 0))}</span>',
                f'<span class="num">'
                f'{C.fmt_bytes(gen.ip_bytes_rx.get(ip, 0))}</span>',
            ])
        body = (
            C.table_html(["Параметр", "Значение"], rows)
            + '<h3 class="subhead">Узлы захвата</h3>'
            + C.table_html(["Узел", "Роль", "Пакетов", "Отправлено",
                            "Получено"], ip_rows)
            + '<p class="note">SINEC H1 — протокол обмена с контроллерами '
              'Siemens S5/S7 по RFC 1006 (fetch/write), типовой порт 2000. '
              'В отчёте видны только пакеты, попавшие в точку съёма: если в '
              'файле нет ни одного байта от PLC, замер односторонний и все '
              'оценки отклика даются по ACK (см. раздел «Отклик PLC и учёт '
              'байтов»).</p>'
        )
        return Section("general", "Общая информация о захвате", body, [
            ("Пакеты порта SINEC H1 (2000) с полезной нагрузкой",
             self._cmd('-Y "tcp.port==2000 && tcp.payload" -T fields '
                       "-e frame.number -e frame.time -e ip.src -e ip.dst "
                       "-e tcp.len")),
            ("Сегменты с сигнатурой H1 (независимо от порта)",
             self._cmd('-Y "tcp.payload contains 53:35" -T fields '
                       "-e frame.number -e frame.time -e ip.src -e ip.dst "
                       "-e tcp.len")),
            ("Таблица TCP-соединений", self._cmd("-q -z conv,tcp")),
        ])

    def _sec_format(self, gen: _General) -> Section:
        """Устройство сообщения H1 и как его разбирает tshark."""
        block_rows = [
            ["<code>53 35</code>", "сигнатура <code>S5</code>",
             "начало сообщения; этим же признаком ищутся сегменты H1"],
            ["<code>10</code>", "длина сообщения",
             "общая длина в байтах вместе с сигнатурой"],
            ["<code>01 03 05</code>", "блок кода операции",
             "<code>05</code> — чтение (<code>03</code> — запись)"],
            ["<code>03 08 01 c8 00 00 00 34</code>", "блок адреса",
             "тип памяти <code>01</code> = DB, блок 200, слово 0, 52 слова; "
             "таких блоков в сообщении может быть несколько — тогда читаются "
             "несколько областей одним запросом"],
            ["<code>ff 02</code>", "пустой блок", "терминатор сообщения"],
        ]
        body = (
            "<p>Сообщение SINEC H1 — цепочка блоков вида "
            "<code>&lt;тип, длина, тело&gt;</code>, где длина блока включает "
            "собственный двухбайтовый заголовок:</p>"
            + C.table_html(["Байты", "Блок", "Содержимое"], block_rows)
        )
        if self._example is None:
            body += "<p>Разобранных сообщений H1 в файле нет.</p>"
            return Section("format", "Формат сообщения SINEC H1", body, [])
        frame, raw, msg, n_msgs = self._example
        head = msg.raw
        tail = raw[len(head):]
        marked = f'<code class="inline">{head.hex(" ")}</code>'
        if tail:
            marked += (' <span class="muted">+ '
                       + tail.hex(" ") + "</span>")
        ex_rows = [[str(off), f"<code>{chunk.hex(' ')}</code>", text]
                   for off, chunk, text in describe_message(head, msg.data)]
        info = self._tshark_info(frame)
        body += (
            '<h3 class="subhead">Разбор первого сообщения в файле '
            f"(кадр {C.fmt_int(frame)})</h3>"
            + f'<p class="hexdump">{marked}</p>'
            + C.table_html(["Смещение", "Байты", "Как читается"], ex_rows)
            + f'<p class="note">tshark разбирает только <strong>первое</strong> '
              f"сообщение сегмента (<code>{C.esc(info)}</code>), остальные "
              f"{self._example[3] - 1} показывает как <code>Data</code> — "
              "поэтому ветка читает <code>tcp.payload</code> и разбирает "
              "цепочку сообщений сама. Сообщений в этом сегменте: "
              f"<strong>{n_msgs}</strong>; байт, не разобранных как H1, во "
              f"всём файле: {C.fmt_int(self._unparsed_bytes)}.</p>"
            + '<p class="note">В протоколе <strong>нет номера ссылки или '
              'транзакции</strong>: сопоставление запроса и ответа возможно '
              'только строго по порядку (FIFO). Поэтому ответ всегда '
              'сопоставляется с самым старым неотвеченным запросом того же '
              'типа операции, а повтор одного и того же запроса (ретрай '
              'после таймаута) отличить от нового запроса нельзя.</p>'
        )
        cmds = [
            ("Как tshark разбирает это сообщение",
             self._cmd('-Y "frame.number==%d" -T fields -e h1.header '
                       "-e h1.len -e h1.opcode -e h1.org -e h1.dbnr "
                       "-e h1.dwnr -e h1.dlen" % frame)),
            ("Сырой payload этого сегмента",
             self._cmd('-Y "frame.number==%d" -x' % frame)),
            ("Первые сегменты с сигнатурой H1",
             self._cmd('-Y "tcp.payload contains 53:35" -T fields '
                        "-e frame.number -e frame.time -e ip.src -e ip.dst "
                        "-e tcp.payload | head -30")),
        ]
        if self._example_resp is not None:
            body += self._response_example()
            cmds.append(
                ("Ответ PLC: разбор и данные",
                 self._cmd('-Y "frame.number==%d" -x'
                           % self._example_resp[0])))
        return Section("format", "Формат сообщения SINEC H1", body, cmds)

    def _response_example(self) -> str:
        """Разбор первого ответа на чтение — у него другой формат."""
        frame, raw, msg, _n = self._example_resp
        head, data = msg.raw, msg.data
        rows = [[str(off), f"<code>{chunk.hex(' ')}</code>", text]
                for off, chunk, text in describe_message(head, data)]
        preview = data[:24]
        marked = (f'<code class="inline">{head.hex(" ")}</code>'
                  f' <span class="muted">+ {preview.hex(" ")}'
                  + (" …" if len(data) > len(preview) else "")
                  + f" ({len(data)} Б)</span>")
        return (
            '<h3 class="subhead">Ответ на чтение устроен иначе '
            f"(кадр {C.fmt_int(frame)})</h3>"
            + f'<p class="hexdump">{marked}</p>'
            + C.table_html(["Смещение", "Байты", "Как читается"], rows)
            + '<p class="note">В ответе <strong>нет блока адреса</strong>: '
              'какой DB и какой диапазон пришли — известно только из '
              'сопоставленного запроса. Объявленная длина покрывает лишь '
              'заголовок, а возвращённые слова идут следом без заголовка '
              'блока; их количество известно как <code>2 × dlen</code> '
              'запроса, поэтому ветка берёт длину из очереди '
              'неотвеченных запросов. При ненулевом коде ответа данных '
              'может не быть вовсе.</p>'
        )

    def _tshark_info(self, frame: int) -> str:
        """Колонка Info tshark для кадра: как разобран протокол на практике."""
        try:
            out = run_list(self.tshark, ["-r", self.pcap_str,
                                         "-Y", f"frame.number=={frame}",
                                         "-T", "fields",
                                         "-e", "_ws.col.Info"])
        except Exception:
            return ""
        lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
        return lines[0] if lines else ""

    def _sec_pairs(self, gen: _General) -> Section:
        t = self._totals(gen)
        pairs = sorted(t["pairs"],
                       key=lambda p: p.req_msgs + p.resp_msgs, reverse=True)
        rows = []
        for p in pairs[: self.cfg.max_rows_per_table]:
            med = percentile(sorted(p.period), 50)
            cv = cv_of(p.period)
            rows.append([
                self._srv_cell(p.server),
                f'<code class="inline">{C.esc(p.client)}</code>',
                f':{sorted(p.client_ports)[0]}'
                if p.client_ports else "&mdash;",
                f':{sorted(p.server_ports)[0]}'
                if p.server_ports else "&mdash;",
                f'<span class="num">{C.fmt_int(len(p.streams))}</span>',
                f'<span class="num">{C.fmt_int(p.req_msgs)}</span>',
                f'<span class="num">{C.fmt_int(p.resp_msgs)}</span>',
                f'<span class="num">{C.fmt_ms(med)}</span>'
                if med else "&mdash;",
                f"{cv:.3f}" if cv is not None else "&mdash;",
                f'<span class="num">{C.fmt_int(p.req_words)}</span>',
                f'<span class="num">{C.fmt_int(p.req_segs)}</span>',
                f'<span class="num">{C.fmt_bytes(p.window)}</span>'
                if p.window else "&mdash;",
            ])
        win = next((p.window for p in pairs if p.window), None)
        depth = (int(win / max(self._max_msgs_per_frame * 16, 1))
                 if win else 0)
        win_note = (f"при объявленном окне {C.fmt_bytes(win)} и пачке из "
                    f"{self._max_msgs_per_frame} запросов возможно до "
                    f"{depth} неотвеченных сегментов" if win else
                    "окно TCP в файле не видно")
        body = (
            "<p>Пары «клиент → PLC», для которых найдены сообщения H1:</p>"
            + C.table_html(
                ["PLC", "Клиент", "Порт клиента", "Порт PLC", "Потоков",
                 "Запросов", "Ответов", "Медиан. цикл, мс", "CV", "Слов",
                 "Сегментов", "Окно TCP"], rows)
            + f'<p class="note"><strong>CV</strong> — коэффициент вариации '
              'интервалов между сегментами с запросами: чем он ниже, тем '
              'жёстче задан цикл опроса. Окно TCP ограничивает глубину '
              f'неотвеченных запросов при батчинге — {C.esc(win_note)}. '
              'Отсутствие SYN означает, что захват начат по уже установленным '
              'соединениям, и не позволяет проверить window scaling.</p>'
        )
        top = pairs[0]
        return Section("pairs", "Пары клиент → PLC", body, [
            (f"Все сегменты с H1 пары {top.side}",
             self._cmd('-Y "tcp.payload contains 53:35 && '
                       f"ip.addr=={top.client} && ip.addr=={top.server}\" "
                       "-T fields -e frame.number -e frame.time -e ip.src "
                       "-e ip.dst -e tcp.payload | head -40")),
            ("Кто подключается к PLC по порту H1 (2000)",
             self._cmd('-Y "tcp.flags.syn==1 && tcp.flags.ack==0 && '
                       "tcp.dstport==2000\" -T fields -e frame.time "
                       "-e ip.src -e ip.dst | head -30")),
            ("Соглашения TCP-соединений этой пары",
             self._cmd(f'-Y "ip.addr=={top.client} && ip.addr=={top.server}" '
                       "-q -z conv,tcp")),
        ])

    def _sec_ops(self, gen: _General) -> Section:
        t = self._totals(gen)
        pairs = t["pairs"]
        dur = gen.duration or 1.0
        counts: Counter = Counter()
        for p in pairs:
            counts.update(p.opcodes)
        items = []
        for code, n in counts.most_common():
            label = (OPCODES.get(code, f"код 0x{code:02x}") if code >= 0
                     else "без кода операции")
            items.append((label, float(n)))
        chart = ('<div class="chart-box">'
                 + C.vbar_svg(items, value_fmt=lambda v: f"{v:.0f}")
                 + "</div>") if items else ""
        owner: dict[OpKey, _PairStats] = {}
        merged: Counter = Counter()
        for p in pairs:
            merged.update(p.ops)
            for op in p.ops:
                owner.setdefault(op, p)
        op_rows = []
        for op, n in merged.most_common(self.cfg.max_rows_per_table):
            p = owner.get(op)
            med = percentile(sorted(p.period), 50) if p else None
            op_rows.append([
                f"<strong>{C.esc(op_name(op))}</strong>",
                self._srv_cell(p.server) if p else "&mdash;",
                f'<span class="num">{C.fmt_int(n)}</span>',
                f'<span class="num">{100.0 * n / max(t["reqs"], 1):.1f}%</span>',
                f'<span class="num">{C.fmt_int(op_words(op))}</span>',
                f'<span class="num">{n / dur:.2f}</span>',
                f'<span class="num">{C.fmt_ms(med)}</span>' if med
                else "&mdash;",
            ])
        rc_rows = []
        for p in pairs:
            for rc, n in p.retcodes.most_common():
                share = 100.0 * n / max(p.resp_msgs, 1)
                cell = f'<span class="num">{share:.1f}%</span>'
                rc_rows.append([
                    self._srv_cell(p.server),
                    f"<code>0x{rc:02x}</code>",
                    C.esc(RETURN_CODES.get(rc, "неизвестный код")),
                    f'<span class="num">{C.fmt_int(n)}</span>',
                    (cell, "cell-hot") if rc else cell,
                ])
        body = (
            chart
            + f"<p>Кодов операций: <strong>{len(counts)}</strong> уникальных, "
              f"сообщений всего {C.fmt_int(t['msgs'])}.</p>"
            + '<h3 class="subhead">Карта операций</h3>'
            + C.table_html(["Операция", "PLC", "Сообщений", "Доля",
                            "Слов в сообщении", "Сообщ./с", "Цикл, мс"],
                           op_rows)
        )
        if rc_rows:
            body += ('<h3 class="subhead">Коды ответа PLC</h3>'
                     + C.table_html(["PLC", "Код", "Значение", "Сообщений",
                                     "Доля"], rc_rows))
        else:
            body += (
                '<p class="note">Ответы PLC в файле <strong>не видны</strong> '
                "(односторонний захват или фильтр на стороне клиента), поэтому "
                "коды ответа и фактические значения блоков памяти проверить "
                "невозможно. Косвенный признак отсутствия ошибок — объём "
                "ответов по ACK: если он совпадает с суммой отправленных "
                "запросов, ответы приходили полными. "
                '<span class="hot-legend">ненулевые коды ответа '
                "выделяются розовым</span>.</p>"
            )
        body += (
            '<p class="note">Коды операций H1: <code>03</code>/<code>04</code> '
            '— запись и её ответ, <code>05</code>/<code>06</code> — чтение и '
            'его ответ. Отсутствие кодов записи означает, что в этом захвате '
            'PLC только читают: конфигурация не менялась, либо шлюз работает в '
            'режиме опроса.</p>'
        )
        return Section("ops", "Операции чтения и записи", body, [
            ("Распределение кодов операций H1",
             self._cmd('-Y "tcp.payload contains 53:35" -T fields '
                       "-e h1.opcode | sort | uniq -c | sort -rn")),
            ("Что tshark разбирает в первом сообщении каждого сегмента",
             self._cmd('-Y "h1.opcode" -T fields -e frame.number '
                       "-e h1.opcode -e h1.org -e h1.dbnr -e h1.dwnr "
                       "-e h1.dlen | head -40")),
            ("Адреса блоков памяти (первое сообщение сегмента)",
             self._cmd('-Y "h1.org" -T fields -e frame.time -e h1.org '
                       "-e h1.dbnr -e h1.dwnr -e h1.dlen | sort | uniq -c "
                       "| sort -rn | head -40")),
        ])

    def _pollmap_labels(self) -> list[str]:
        """Метки карты опроса для diff-отчёта («PLC DB200@0..51»)."""
        labels = []
        for p in self._pairs.values():
            for op in p.ops:
                if op[0] != OP_READ_REQ:
                    continue
                if len(labels) >= self.cfg.pollmap_max_registers:
                    return labels
                labels.append(f"{p.server} {op_label(op)}")
        return labels

    def _sec_pollmap(self, gen: _General) -> Section:
        t = self._totals(gen)
        dur = gen.duration or 1.0
        blocks: dict[tuple, Counter] = {}
        for p in t["pairs"]:
            for op, n in p.ops.items():
                if op[0] != OP_READ_REQ:
                    continue
                for org, db, dwnr, dlen in op_all_addrs(op):
                    # комбинированный запрос учитывается у каждой области,
                    # но слова берём её долю, а не сумму по сообщению
                    blocks.setdefault((org, db, p.server),
                                      Counter())[(dwnr, dlen)] += n
        if not blocks:
            return Section(
                "pollmap", "Карта опроса блоков памяти",
                "<p>Запросов чтения блоков памяти не обнаружено.</p>", [])
        rows = []
        charts = []
        ordered = sorted(blocks.items(), key=lambda kv: -sum(kv[1].values()))
        for (org, db, plc), ops in ordered[: self.cfg.max_rows_per_table]:
            total = sum(ops.values())
            words = sum(dlen * n for (_dwnr, dlen), n in ops.items())
            cov_ranges = [(dwnr, dlen, n)
                          for (dwnr, dlen), n in ops.items() if dlen]
            dwnrs = [d for d, _n, _c in cov_ranges]
            ends = [d + (n or 1) - 1 for d, n, _c in cov_ranges]
            span = (f"DW{min(dwnrs)}–{max(ends)}"
                    if dwnrs else "&mdash;")
            rows.append([
                self._srv_cell(plc),
                f"<strong>{C.esc(ORG_NAMES.get(org, f'тип 0x{org:02x}'))}"
                f"{db}</strong>",
                f'<span class="num">{C.fmt_int(total)}</span>',
                f'<span class="num">{C.fmt_int(words)}</span>',
                C.esc(span),
                f'<span class="num">{total / dur:.2f}</span>',
                f'<span class="num">{len(ops)}</span>',
            ])
            svg = _coverage([(dwnr, dwnr + dlen, cnt)
                         for dwnr, dlen, cnt in cov_ranges])
            if svg:
                charts.append(
                    f'<h3 class="subhead">{C.esc(plc)} — '
                    f"{C.esc(ORG_NAMES.get(org, '?'))}{db}: покрытие блока"
                    "</h3>"
                    f'<div class="chart-box">{svg}</div>')
        body = (
            "<p>Блоки памяти, которые читает клиент (операции чтения; "
            "записи в карту опроса не попадают):</p>"
            + C.table_html(["PLC", "Блок", "Запросов", "Слов",
                            "Диапазон слов", "Запросов/с", "Разбиений"],
                           rows)
            + "".join(charts)
            + '<p class="note">Полосы на схемах — диапазоны запрошенных слов; '
              'чем темнее, тем чаще читается этот участок. Читать блок целиком '
              'удобно при отладке, но в рабочем режиме это лишняя нагрузка на '
              'PLC и канал: обычно достаточно нужных смещений, а медленные '
              'редко меняющиеся теги стоит опрашивать отдельным, более длинным '
              'циклом.</p>'
        )
        return Section("pollmap", "Карта опроса блоков памяти", body, [
            ("Запросы чтения: блок, слово, длина",
             self._cmd('-Y "h1.opcode==5" -T fields -e frame.time -e h1.org '
                       "-e h1.dbnr -e h1.dwnr -e h1.dlen | sort | uniq -c "
                       "| sort -rn | head -40")),
            ("Все операции H1 по кодам и адресам",
             self._cmd('-Y "h1.opcode" -T fields -e h1.opcode -e h1.org '
                       "-e h1.dbnr -e h1.dwnr -e h1.dlen | sort | uniq -c "
                       "| sort -rn | head -40")),
        ])

    def _sec_timing(self, gen: _General) -> Section:
        t = self._totals(gen)
        pairs = t["pairs"]
        dur = gen.duration or 1.0
        bars = []
        for p in pairs:
            if len(p.period) >= self.cfg.h1_min_msgs_for_period:
                med = percentile(sorted(p.period), 50)
                if med is not None:
                    bars.append((f"{p.client} → {p.server}", med * 1000))
        if not bars:
            return Section(
                "timing", "Периодика и батчинг",
                "<p>Циклов с устойчивым периодом не обнаружено (минимум "
                f"{self.cfg.h1_min_msgs_for_period} сегментов с запросами на "
                "пару).</p>", [])
        bars.sort(key=lambda x: x[1])
        svg = ('<div class="chart-box">'
               + C.hbar_svg(bars[:12], value_fmt=lambda v: f"{v:.0f} мс")
               + "</div>")
        cycle_rows = []
        for p in pairs:
            med = percentile(sorted(p.period), 50)
            if not med or len(p.period) < self.cfg.h1_min_msgs_for_period:
                continue
            cycle_rows.append([
                self._srv_cell(p.server),
                f'<code class="inline">{C.esc(p.client)}</code>',
                f'<span class="num">{C.fmt_ms(med)}</span>',
                f'<span class="num">{C.fmt_ms(percentile(sorted(p.period), 95))}'
                "</span>",
                f'<span class="num">{1.0 / med:.3f} Гц</span>',
                f'<span class="num">{100.0 * p.req_msgs / dur:.2f}/с</span>',
                f"{cv_of(p.period):.3f}" if cv_of(p.period) is not None
                else "&mdash;",
            ])
        # кратность периода базовому циклу таймера S5/S7
        q = self.cfg.h1_timer_quantum_ms / 1000.0
        ticks: Counter = Counter()
        dev_sum = dev_n = 0
        for p in pairs:
            for v in p.period:
                n = v / q
                nearest = round(n)
                if nearest > 0:
                    ticks[nearest] += 1
                    dev_sum += abs(n - nearest) / nearest * 100
                    dev_n += 1
        tick_txt = tick_chart = ""
        if ticks and dev_n:
            dev = dev_sum / dev_n
            items = sorted(ticks.items())[:14]
            tick_chart = (
                '<h3 class="subhead">Кратность периода базовому циклу '
                f"{C.fmt_int(self.cfg.h1_timer_quantum_ms)} мс</h3>"
                '<div class="chart-box">'
                + C.vbar_svg([(f"{n} квантов", float(c))
                              for n, c in items],
                             value_fmt=lambda v: f"{v:.0f}")
                + "</div>"
                + f'<p>Среднее отклонение периода от ближайшего кратного '
                  f"кванта: <strong>{dev:.1f}%</strong>.</p>")
            tick_txt = (f"Период близок к кратному "
                        f"{C.fmt_int(self.cfg.h1_timer_quantum_ms)} мс "
                        f"(отклонение {dev:.1f}%) — цикл держится на "
                        "границе дискретности таймера, а не «плавает» по сети")
        # батчинг: сколько сообщений в одном сегменте
        batch: Counter = Counter()
        for p in pairs:
            batch.update(p.msgs_per_seg)
        batch_chart = batch_txt = ""
        if batch:
            batch_chart = (
                '<h3 class="subhead">Сколько сообщений в одном TCP-сегменте'
                "</h3>"
                '<div class="chart-box">'
                + C.vbar_svg([(f"{n} сообщ.", float(c))
                              for n, c in sorted(batch.items())],
                             value_fmt=lambda v: f"{v:.0f}")
                + "</div>")
            avg = self._msgs_total / max(t["segs"], 1)
            single = 100.0 * batch.get(1, 0) / max(sum(batch.values()), 1)
            batch_txt = (f"в среднем <strong>{avg:.2f}</strong> сообщений на "
                         f"сегмент, сегментов с одним сообщением "
                         f"<strong>{single:.0f}%</strong>")
        body = (
            svg
            + C.table_html(["PLC", "Клиент", "Медиана, мс", "p95, мс",
                            "Частота", "Запросов", "CV"], cycle_rows)
            + tick_chart
            + batch_chart
            + f'<p class="note">{C.esc(batch_txt)}'
            + (f"; {C.esc(tick_txt)}" if tick_txt else "") + ".</p>"
            + '<p class="note">Несколько сообщений в одном сегменте — '
              'нормальный приём: H1 не имеет номеров транзакций, клиент '
              'поэтому пакует независимые чтения в один сегмент и разбирает '
              'ответы по порядку. Обратная ситуация (один запрос на сегмент '
              'при большом числе мелких чтений) нагружает сеть служебными '
              'байтами и увеличивает время ожидания первого полезного '
              'ответа — такие чтения стоит объединять в один запрос '
              'диапазона или в пачку.</p>'
            + '<p class="note">Умеренный CV — норма для циклического опроса: '
              'смещение накапливается от задержек планировщика и сети. Разброс '
              'в пределах одного кванта таймера означает, что цикл задан '
              'программно и сеть его не искажает; резкие отклонения (&gt;10%) '
              'указывают на конкуренцию за канал или пропуски циклов.</p>'
        )
        return Section("timing", "Периодика и батчинг", body, [
            ("Интервалы между сегментами с запросами",
             self._cmd('-Y "tcp.payload contains 53:35 && tcp.dstport==2000" '
                       "-T fields -e tcp.stream -e frame.time_epoch "
                       "| awk '{if($1==s){print $2-t}{s=$1;t=$2}}' "
                       "| head -40")),
            ("Моменты запросов и размеры сегментов",
             self._cmd('-Y "tcp.payload contains 53:35" -T fields '
                       "-e frame.number -e frame.time -e tcp.stream "
                       "-e tcp.len | head -40")),
            ("Кто и когда стучится в порт PLC",
             self._cmd('-Y "tcp.dstport==2000 && tcp.payload" -T fields '
                       "-e frame.time -e ip.src -e tcp.srcport | head -40")),
        ])

    def _sec_response(self, gen: _General) -> Section:
        t = self._totals(gen)
        pairs = t["pairs"]
        rows = []
        for p in sorted(pairs, key=lambda x: x.req_msgs, reverse=True):
            ack_med = percentile(sorted(p.ack_rtt), 50)
            ack_p95 = percentile(sorted(p.ack_rtt), 95)
            rtt_med = percentile(sorted(p.rtt), 50)
            unacked = f'<span class="num">{C.fmt_int(p.unacked)}</span>'
            rows.append([
                self._srv_cell(p.server),
                f'<span class="num">{C.fmt_int(p.req_msgs)}</span>',
                f'<span class="num">{C.fmt_int(p.resp_msgs)}</span>',
                f'<span class="num">{C.fmt_ms(rtt_med)}</span>'
                if rtt_med is not None else "&mdash;",
                f'<span class="num">{C.fmt_ms(ack_med)}</span>'
                if ack_med is not None else "&mdash;",
                f'<span class="num">{C.fmt_ms(ack_p95)}</span>'
                if ack_p95 is not None else "&mdash;",
                f'<span class="num">{C.fmt_int(p.resp_bytes_est)}</span>',
                f'<span class="num">{C.fmt_int(p.req_acked_bytes)}</span>',
                (unacked, "cell-hot") if p.unacked else unacked,
            ])
        busy = 100.0 * t["busy"] / gen.duration if gen.duration else 0.0
        med_rtt = t["p50_rtt"] if t["p50_rtt"] is not None else t["p50_ack"]
        share = (med_rtt / t["med_period"] * 100
                 if med_rtt and t["med_period"] else None)
        headroom = ""
        if busy < self.cfg.h1_idle_headroom_pct:
            headroom = (
                f'<p>PLC занят примерно <strong>{busy:.2f}%</strong> времени '
                f"захвата при цикле {C.fmt_ms(t['med_period'])} мс"
                + (f"; отклик занимает {share:.1f}% длительности цикла"
                   if share else "")
                + " — запас по времени не используется.</p>")
        body = (
            "<p>Отклик PLC по парам. «Ответы видны» — в файле есть байты от "
            "PLC; иначе отклик оценивается по ACK клиента, подтверждающим "
            "приём байтов от сервера (это <strong>нижняя оценка</strong>: в неё "
            "входит задержка ACK и потери до точки съёма).</p>"
            + C.table_html(
                ["PLC", "Запросов", "Ответов", "Отклик p50, мс",
                 "Оценка по ACK p50, мс", "Оценка по ACK p95, мс",
                 "Ответов по ACK, Б", "Запросов принято, Б", "Без ACK"],
                rows)
            + headroom
            + '<p class="note">Столбец «Ответов по ACK» — объём данных, '
              'принятых клиентом от PLC, восстановленный по дельтам поля '
              '<code>tcp.ack</code> в ACK клиента. Если он заметно меньше '
              'объёма отправленных запросов, часть запросов осталась без '
              'полного ответа (таймаут, обрыв, перегрузка). Столбец '
              '«Запросов принято» считается по ACK PLC и показывает, сколько '
              'клиентских байт контроллер подтвердил.</p>'
        )
        if t["orphans"]:
            body += (f'<p class="note">Ответов без соответствующего запроса '
                     f"(в очереди не нашлось неотвеченного запроса того же "
                     f"типа операции): <strong>{C.fmt_int(t['orphans'])}"
                     "</strong>. Обычно это следствие начала захвата с середины "
                     "обмена или повторов запросов.</p>")
        top = max(pairs, key=lambda x: x.req_msgs)
        cmds = [
            ("Чистые ACK клиента: подтверждённый объём ответов PLC",
             self._cmd(f'-Y "ip.addr=={top.client} && ip.addr=={top.server} '
                       '&& tcp.flags.ack==1 && tcp.len==0" -T fields '
                       "-e frame.number -e frame.time -e ip.src -e tcp.ack "
                       "| head -40")),
            ("Байты в обе стороны по этой паре",
             self._cmd(f'-Y "ip.addr=={top.client} && ip.addr=={top.server} '
                       '" -T fields -e frame.number -e frame.time -e ip.src '
                       "-e ip.dst -e tcp.seq -e tcp.ack -e tcp.len "
                       "| head -40")),
        ]
        if top.unacked_frames:
            nums = ",".join(str(f) for f in top.unacked_frames)
            cmds.append((
                "Сегменты без подтверждённого ответа",
                self._cmd(f'-Y "frame.number in {{{nums}}}" -T fields '
                          "-e frame.number -e frame.time -e ip.src -e ip.dst "
                          "-e tcp.seq -e tcp.ack -e tcp.len")))
        return Section("response", "Отклик PLC и учёт байтов", body, cmds)

    def _sec_health(self, gen: _General) -> Section:
        t = self._totals(gen)
        pairs = t["pairs"]
        retrans = t["retrans"] or gen.retrans_total
        msgs = t["reqs"] + t["resps"] or 1
        rows = []
        for p in pairs:
            syn = gen.syn_to_ip.get(p.server, 0)
            rows.append([
                self._srv_cell(p.server),
                f'<span class="num">{C.fmt_int(len(p.streams))}</span>',
                f'<span class="num">{C.fmt_int(syn)}</span>' if syn
                else '<span class="muted">не видно</span>',
                f'<span class="num">{C.fmt_int(p.retrans)}</span>',
                f'<span class="num">{C.fmt_int(gen.rst_total)}</span>'
                if gen.rst_total else "0",
                f'<span class="num">{C.fmt_bytes(p.window)}</span>'
                if p.window else "&mdash;",
                f'<span class="num">{C.fmt_int(p.unacked)}</span>',
                f'<span class="num">{C.fmt_int(p.orphan_resps)}</span>',
            ])
        one_way = [p for p in pairs if p.resp_msgs == 0 and p.req_msgs]
        one_way_txt = ""
        if one_way and len(one_way) == len(pairs):
            plc = one_way[0].server
            one_way_txt = (
                '<p class="note"><strong>Захват односторонний:</strong> в '
                "файле нет ни одного байта от PLC — только запросы клиента и "
                "его подтверждения. Так бывает, когда съём настроен на одном "
                "порту зеркалирования или фильтр BPF отбрасывает обратный "
                "трафик. Значения блоков памяти, коды ответа и точный отклик "
                "по такому файлу проверить нельзя; всё, что основано на ACK — "
                "оценка снизу.</p>"
                '<p class="note">Повторный захват без потери направления: '
                "<code>tcpdump -i any -s 0 -w dump.pcap "
                f"'host {plc} and port 2000'</code></p>")
        body = (
            "<p>Состояние TCP-соединений по парам H1:</p>"
            + C.table_html(
                ["PLC", "Потоков", "SYN", "Ретрансмиссий", "RST в файле",
                 "Окно", "Без ACK", "Ответов-сирот"], rows)
            + f'<p>Ретрансмиссий TCP: <strong>{C.fmt_int(retrans)}</strong> '
              f"({100.0 * retrans / msgs:.2f}% от сообщений H1), RST: "
              f"<strong>{C.fmt_int(gen.rst_total)}</strong>.</p>"
            + one_way_txt
            + '<p class="note">Отсутствие SYN у всех соединений — типично '
              'для захватов, начатых по уже установленным сессиям (обычный '
              'случай на работающем АСУ ТП, где опрос идёт постоянно). Это '
              'не дефект сети, но проверить window scaling, keepalive и '
              'исходные параметры соединения по такому файлу невозможно. '
              '«Ответов-сирот» — ответы, которым не нашёлся неотвеченный '
              'запрос в очереди FIFO: признак начала захвата с середины обмена '
              'либо повторов запросов.</p>'
        )
        return Section("health", "Состояние TCP и односторонние захваты",
                       body, [
            ("Ретрансмиссии TCP в парах H1",
             self._cmd('-Y "tcp.analysis.retransmission && '
                       'tcp.payload contains 53:35" -T fields '
                       "-e frame.number -e frame.time -e ip.src -e ip.dst "
                       "-e tcp.seq -e tcp.ack | head -40")),
            ("SYN к порту H1 (2000)",
             self._cmd('-Y "tcp.dstport==2000 && tcp.flags.syn==1 && '
                       'tcp.flags.ack==0" -T fields -e frame.time -e ip.src '
                       "-e ip.dst | head -30")),
            ("RST в файле",
             self._cmd('-Y "tcp.flags.reset==1" -T fields -e frame.number '
                       "-e frame.time -e ip.src -e ip.dst | head -30")),
        ])

    # -- рекомендации ----------------------------------------------------------

    def _build_recommendations(self, gen: _General) -> list[Recommendation]:
        recs: list[Recommendation] = []
        recs.extend(self._rule_one_sided(gen))
        recs.extend(self._rule_errors(gen))
        recs.extend(self._rule_unanswered(gen))
        recs.extend(self._rule_slow_response(gen))
        recs.extend(self._rule_fast_poll(gen))
        recs.extend(self._rule_period_jitter(gen))
        recs.extend(self._rule_idle_headroom(gen))
        recs.extend(self._rule_batching(gen))
        recs.extend(self._rule_full_range(gen))
        recs.extend(self._rule_repeats(gen))
        recs.extend(self._rule_retrans(gen))
        recs.extend(self._rule_churn(gen))
        if not recs:
            recs.append(Recommendation(
                id="ok", severity="info",
                title="Явных проблем не обнаружено",
                problem="Ни одно правило оптимизации не сработало.",
                advice="Повторите анализ после изменений конфигурации опроса "
                       "или по захвату с двусторонним трафиком.",
            ))
        return sort_recommendations(recs)

    def _rule_one_sided(self, gen: _General) -> list[Recommendation]:
        pairs = list(self._pairs.values())
        one_way = [p for p in pairs if p.resp_msgs == 0 and p.req_msgs]
        if not one_way or len(one_way) < len(pairs):
            return []
        t = self._totals(gen)
        plc = ", ".join(sorted({p.server for p in one_way}))
        top = max(one_way, key=lambda p: p.req_msgs)
        return [Recommendation(
            id="h1-one-sided", severity="info",
            title="Захват односторонний: ответов PLC в файле нет",
            problem=(
                f"{C.fmt_int(t['reqs'])} запросов к {plc}, ответов — ноль; "
                f"SYN, FIN и RST по этим потокам тоже не видны. Объём "
                f"ответов восстановлен только по ACK клиента: "
                f"{C.fmt_bytes(t['resp_bytes_est'])}."),
            advice=(
                "Такой файл годится для анализа опроса, но не значений: "
                "нельзя проверить фактические данные блоков памяти, коды "
                "ответа и точный отклик. Переснимите дамп без потери "
                "направления — фильтром по обоим адресам, а не по порту на "
                "стороне клиента."),
            evidence=[
                f"запросов: {C.fmt_int(t['reqs'])}, ответов в файле: 0",
                f"оценка объёма ответов по ACK: "
                f"{C.fmt_bytes(t['resp_bytes_est'])}",
            ],
            commands=[
                self._cmd(f'-Y "tcp.payload contains 53:35 && '
                          f'ip.src=={top.server}" -T fields -e frame.number '
                          "-e frame.time -e ip.src | head -20"),
                f"tcpdump -i any -s 0 -w dump.pcap 'host {top.server} and "
                "port 2000'",
            ],
        )]

    def _rule_errors(self, gen: _General) -> list[Recommendation]:
        out = []
        for p in self._pairs.values():
            if not p.resp_msgs:
                continue
            errs = sum(n for rc, n in p.retcodes.items() if rc != 0)
            pct = 100.0 * errs / p.resp_msgs
            if pct < self.cfg.exception_rate_pct:
                continue
            sev = (SEVERITY_CRITICAL if pct >= self.cfg.critical_rate_pct
                   else SEVERITY_WARNING)
            top = sorted(((rc, n) for rc, n in p.retcodes.items() if rc),
                         key=lambda kv: -kv[1])[:3]
            out.append(Recommendation(
                id=f"h1-errors-{p.server}".replace(".", "-"),
                severity=sev,
                title=f"Ответы PLC с ошибками: {p.server}",
                problem=(
                    f"{errs} из {C.fmt_int(p.resp_msgs)} ответов "
                    f"({pct:.2f}%) содержат ненулевой код ответа."),
                advice=(
                    "Коды ответа H1: 0x02 — запрошенный блок не существует, "
                    "0x03 — блок слишком мал, 0xFF — ошибка без причины. "
                    "Проверьте номера и длины диапазонов в конфигурации опроса "
                    "против фактической раскладки DB в PLC и убедитесь, что "
                    "запрашиваемые блоки не удалены при изменении программы."),
                evidence=[f"код 0x{rc:02x} ({RETURN_CODES.get(rc, '?')}): "
                          f"{C.fmt_int(n)} ответов" for rc, n in top],
                commands=[self._cmd(
                    '-Y "h1.resvalue" -T fields -e frame.time -e ip.src '
                    "-e ip.dst -e h1.resvalue | sort | uniq -c | sort -rn "
                    "| head -20")],
            ))
        return out

    def _rule_unanswered(self, gen: _General) -> list[Recommendation]:
        t = self._totals(gen)
        if not t["unacked"] or not t["segs"]:
            return []
        pct = 100.0 * t["unacked"] / t["segs"]
        if pct < self.cfg.no_response_rate_pct:
            return []
        pair = max(self._pairs.values(), key=lambda p: p.unacked)
        frames = ", ".join(str(f) for f in pair.unacked_frames[:6])
        return [Recommendation(
            id="h1-unanswered", severity="warning",
            title="Часть запросов осталась без подтверждённого ответа",
            problem=(
                f"{t['unacked']} сегментов с запросами ({pct:.1f}% от "
                f"{C.fmt_int(t['segs'])}) не подтверждены ACK клиента даже к "
                f"концу захвата; на {pair.server} не принято "
                f"{C.fmt_bytes(t['unacked_bytes'])} байт запросов."),
            advice=(
                "Возможные причины: таймаут обработки на PLC (слишком часто "
                "или слишком длинные запросы), обрыв связи либо задержка ответа "
                "за пределами захвата. Проверьте загрузку CPU контроллера и "
                "наличие повторов: в H1 нет номера транзакции, поэтому клиент "
                "не может отличить свой повтор от нового запроса."),
            evidence=[f"первые неподтверждённые кадры: {frames}"]
            if frames else [],
            commands=[self._cmd(
                f'-Y "ip.addr=={pair.client} && ip.addr=={pair.server}" '
                "-T fields -e frame.number -e frame.time -e ip.src "
                "-e tcp.seq -e tcp.ack -e tcp.len | tail -20")],
        )]

    def _rule_slow_response(self, gen: _General) -> list[Recommendation]:
        t = self._totals(gen)
        p95 = t["p95_rtt"] if t["p95_rtt"] is not None else t["p95_ack"]
        if p95 is None or p95 * 1000 < self.cfg.slow_rtt_p95_ms:
            return []
        med = t["p50_rtt"] if t["p50_rtt"] is not None else t["p50_ack"]
        pair = max(self._pairs.values(),
                   key=lambda p: (percentile(sorted(p.rtt or p.ack_rtt), 95)
                                  or 0.0))
        return [Recommendation(
            id="h1-slow-response", severity="warning",
            title="PLC отвечает медленно",
            problem=(
                f"p95 отклика {C.fmt_ms(p95)} мс при пороге "
                f"{C.fmt_int(self.cfg.slow_rtt_p95_ms)} мс, медиана "
                f"{C.fmt_ms(med)} мс. "
                + ("Отклик измерен по видимым ответам PLC."
                   if t["p50_rtt"] is not None else
                   "Отклик оценён по ACK: ответы в файле не видны.")),
            advice=(
                "Проверьте, не загружен ли контроллер: при большом числе "
                "клиентов опрос вытесняет цикл программы и удлиняет ответ. "
                "Уменьшите объём читаемых блоков, разнесите опрос разных "
                "клиентов по времени либо увеличьте период."),
            evidence=[f"PLC: {pair.server}",
                      f"запросов: {C.fmt_int(pair.req_msgs)}"],
            commands=[self._cmd(
                '-Y "tcp.analysis.ack_rtt" -T fields -e frame.number '
                "-e frame.time -e ip.src -e ip.dst -e tcp.analysis.ack_rtt "
                "| sort -k5 -rn | head -20")],
        )]

    def _rule_fast_poll(self, gen: _General) -> list[Recommendation]:
        t = self._totals(gen)
        med = t["med_period"]
        rtt = t["p50_rtt"] if t["p50_rtt"] is not None else t["p50_ack"]
        if not med or not rtt or med > self.cfg.poll_pressure_factor * rtt:
            return []
        pair = max(self._pairs.values(), key=lambda p: p.req_msgs)
        return [Recommendation(
            id="h1-fast-poll", severity="warning",
            title="Цикл опроса короче времени отклика PLC",
            problem=(
                f"период {C.fmt_ms(med)} мс при отклике {C.fmt_ms(rtt)} мс — "
                f"цикл короче в {self.cfg.poll_pressure_factor:g}× отклика, "
                "то есть следующий цикл начинается до завершения "
                "предыдущего."),
            advice=(
                "Клиент не дожидается ответа на предыдущий запрос, и его "
                "повторы становятся неотличимы от новых запросов. Если данные "
                "не требуют такой частоты, увеличьте период; если требуют — "
                "разделите опрос на независимые циклы и ограничьте глубину "
                "очереди на стороне шлюза."),
            evidence=[f"PLC: {pair.server}",
                      f"окно TCP: {C.fmt_bytes(pair.window)}"],
            commands=[self._cmd(
                '-Y "tcp.payload contains 53:35" -T fields -e frame.time '
                "-e tcp.stream -e tcp.len | head -40")],
        )]

    def _rule_period_jitter(self, gen: _General) -> list[Recommendation]:
        out = []
        for p in self._pairs.values():
            if len(p.period) < self.cfg.h1_min_msgs_for_period:
                continue
            vals = sorted(p.period)
            med = percentile(vals, 50)
            if not med:
                continue
            jitter = 100.0 * (percentile(vals, 95) - med) / med
            if jitter < self.cfg.h1_period_jitter_pct:
                continue
            cv = cv_of(p.period)
            out.append(Recommendation(
                id=f"h1-jitter-{p.server}".replace(".", "-"),
                severity="info",
                title=f"Нестабильный цикл опроса к {p.server}",
                problem=(
                    f"медиана периода {C.fmt_ms(med)} мс, разброс до p95 "
                    f"+{jitter:.1f}% при пороге "
                    f"{self.cfg.h1_period_jitter_pct:g}%."),
                advice=(
                    "Разброс в пределах одного кванта таймера "
                    f"({C.fmt_int(self.cfg.h1_timer_quantum_ms)} мс) — норма "
                    "для S5/S7. Больший разброс обычно означает конкуренцию за "
                    "канал или пропуски циклов: проверьте, не появляются ли в "
                    "это время потоки с большим объёмом данных."),
                evidence=[f"CV периода: {cv:.3f}"] if cv is not None else [],
                commands=[self._cmd(
                    f'-Y "tcp.payload contains 53:35 && ip.dst=={p.server}" '
                    "-T fields -e frame.time -e tcp.stream | head -40")],
            ))
        return out

    def _rule_idle_headroom(self, gen: _General) -> list[Recommendation]:
        t = self._totals(gen)
        if not gen.duration or not t["busy"]:
            return []
        busy = 100.0 * t["busy"] / gen.duration
        if busy >= self.cfg.h1_idle_headroom_pct:
            return []
        pair = max(self._pairs.values(), key=lambda p: p.req_msgs)
        port = pair.server_port or H1_PORTS[0]
        return [Recommendation(
            id="h1-idle-headroom", severity="info",
            title="Запас PLC не используется: цикл задан слишком часто",
            problem=(
                f"оценка занятости PLC {busy:.2f}% времени при цикле "
                f"{C.fmt_ms(t['med_period'])} мс — контроллер успевает "
                "обслужить запрос задолго до следующего."),
            advice=(
                "Если данные не нужны с такой частотой, увеличьте период "
                "(в 2–5 раз обычно безопасно) — это снизит нагрузку и на "
                "клиент, и на PLC. Ещё лучше: быстрые теги опрашивать часто, "
                "медленные и редко меняющиеся — отдельным длинным циклом, а "
                "критичные события передавать по факту изменения значения, а "
                "не циклически."),
            evidence=[f"PLC: {pair.server}",
                      f"запросов за захват: {C.fmt_int(pair.req_msgs)}"],
            commands=[self._cmd(
                f'-Y "tcp.dstport=={port} && tcp.payload" -T fields '
                "-e frame.time -e ip.src -e tcp.len | head -40")],
        )]

    def _rule_batching(self, gen: _General) -> list[Recommendation]:
        t = self._totals(gen)
        segs = t["segs"]
        if not segs:
            return []
        single = sum(p.msgs_per_seg.get(1, 0) for p in self._pairs.values())
        share = 100.0 * single / segs
        if share < self.cfg.h1_single_msg_seg_pct:
            return []
        return [Recommendation(
            id="h1-batching", severity="info",
            title="По одному запросу на сегмент — есть смысл батчить",
            problem=(
                f"{share:.0f}% сегментов с запросами несут ровно одно "
                f"сообщение ({C.fmt_int(t['msgs'])} сообщений в "
                f"{C.fmt_int(segs)} сегментах)."),
            advice=(
                "Упакуйте независимые чтения в один сегмент (H1 не имеет "
                "номеров транзакций, ответы разбираются по порядку) либо "
                "объедините близкие диапазоны в один запрос: меньше служебных "
                "байт и меньше задержка до первого полезного ответа. Следите, "
                "чтобы глубина очереди не превышала разумного значения."),
            evidence=[f"в среднем {t['msgs'] / segs:.2f} сообщений на сегмент"],
            commands=[self._cmd(
                '-Y "tcp.payload contains 53:35" -T fields -e frame.time '
                "-e tcp.len -e tcp.payload | head -30")],
        )]

    def _rule_full_range(self, gen: _General) -> list[Recommendation]:
        out = []
        for p in self._pairs.values():
            big = [(op, n) for op, n in p.ops.items()
                   if op_words(op) >= self.cfg.h1_full_range_words]
            if not big:
                continue
            reqs = sum(n for _op, n in big)
            share = 100.0 * reqs / max(p.req_msgs, 1)
            if share < 50.0:
                continue
            words = sum(op_words(op) * n for op, n in big)
            out.append(Recommendation(
                id=f"h1-full-range-{p.server}".replace(".", "-"),
                severity="info",
                title=f"Чтение целых крупных диапазонов памяти: {p.server}",
                problem=(
                    f"{share:.0f}% запросов читают диапазоны от "
                    f"{C.fmt_int(self.cfg.h1_full_range_words)} слов и более; "
                    f"суммарно {C.fmt_int(words)} слов за захват."),
                advice=(
                    "Чтение всего блока удобно при отладке, но в рабочем режиме "
                    "это лишняя нагрузка и канал. Оставьте в опросе только "
                    "используемые смещения, а большие редко меняющиеся области "
                    "вынесите в отдельный длинный цикл."),
                evidence=[f"{C.esc(op_name(op))} — {C.fmt_int(n)} запросов"
                          for op, n in sorted(big, key=lambda kv: -kv[1])[:3]],
                commands=[self._cmd(
                    f'-Y "ip.addr=={p.server} && tcp.payload contains 53:35" '
                    "-T fields -e frame.time -e h1.dbnr -e h1.dwnr "
                    "-e h1.dlen | head -30")],
            ))
        return out

    def _rule_repeats(self, gen: _General) -> list[Recommendation]:
        out = []
        for p in self._pairs.values():
            if not p.req_msgs:
                continue
            share = 100.0 * p.repeat_msgs / p.req_msgs
            if share < self.cfg.h1_repeat_share_pct:
                continue
            out.append(Recommendation(
                id=f"h1-repeats-{p.server}".replace(".", "-"),
                severity="info",
                title=f"Один и тот же запрос повторяется без изменений: "
                      f"{p.server}",
                problem=(
                    f"{share:.0f}% сообщений ({C.fmt_int(p.repeat_msgs)} из "
                    f"{C.fmt_int(p.req_msgs)}) побайтово совпадают с "
                    "предыдущим; максимальная серия одинаковых подряд — "
                    f"{C.fmt_int(p.repeat_run_max)}."),
                advice=(
                    "Повтор того же диапазона в следующем же цикле почти "
                    "всегда означает неизменившиеся данные: уменьшите частоту "
                    "опроса этой области либо переходите на передачу по событию "
                    "изменения значения. Учтите, что повтор запроса нельзя "
                    "отличить от ретрая после таймаута: если серии одинаковых "
                    "запросов идут непрерывно, вероятно, клиент перезапрашивает "
                    "данные без смены диапазона."),
                evidence=[f"примеры кадров: "
                          + ", ".join(str(f) for f in p.repeat_examples[:5])],
                commands=[self._cmd(
                    f'-Y "ip.dst=={p.server} && tcp.payload contains 53:35" '
                    "-T fields -e frame.number -e frame.time -e tcp.payload "
                    "| head -40")],
            ))
        return out

    def _rule_retrans(self, gen: _General) -> list[Recommendation]:
        out = []
        for p in self._pairs.values():
            total = p.req_msgs + p.resp_msgs
            if total < 100:
                continue
            pct = 100.0 * p.retrans / total
            if pct < self.cfg.h1_retrans_warn_pct:
                continue
            out.append(Recommendation(
                id=f"h1-retrans-{p.server}".replace(".", "-"),
                severity="warning",
                title=f"Ретрансмиссии TCP в обмене с {p.server}",
                problem=(
                    f"{C.fmt_int(p.retrans)} повторных передач ({pct:.1f}% "
                    "сообщений пары)."),
                advice=(
                    "Ретрансмиссии означают потери в пути: перегруженный "
                    "линк, дуплексные рассогласования или неисправный порт. "
                    "Для промышленной сети это первая причина таймаутов "
                    "опроса. Если на другой точке съёма ретрансмиссий "
                    "значительно меньше — подозревайте саму запись "
                    "(переполнение зеркала), а не канал."),
                commands=[self._cmd(
                    f'-Y "tcp.analysis.retransmission && ip.addr=={p.server}" '
                    "-T fields -e frame.number -e frame.time -e ip.src "
                    "-e ip.dst -e tcp.seq | head -40")],
            ))
        return out

    def _rule_churn(self, gen: _General) -> list[Recommendation]:
        out = []
        dur_min = max(gen.duration / 60.0, 1e-9)
        for p in self._pairs.values():
            syn = gen.syn_to_ip.get(p.server, 0)
            if syn < self.cfg.conn_churn_pair_min:
                continue
            if syn / dur_min < self.cfg.conn_churn_per_min:
                continue
            port = p.server_port or H1_PORTS[0]
            out.append(Recommendation(
                id=f"h1-churn-{p.server}".replace(".", "-"),
                severity="warning",
                title=f"Частые переподключения к {p.server}",
                problem=(
                    f"{C.fmt_int(syn)} новых соединений "
                    f"({syn / dur_min:.1f}/мин) при живом обмене данными."),
                advice=(
                    "Клиент пересоздаёт соединения вместо долгоживущего: каждый "
                    "раз заново handshake и прогрев протокола. Проверьте "
                    "таймауты простоя клиента и промежуточных устройств "
                    "(NAT, межсетевой экран)."),
                commands=[self._cmd(
                    f'-Y "tcp.flags.syn==1 && tcp.flags.ack==0 && '
                    f'tcp.dstport=={port}" -T fields -e frame.time -e ip.src '
                    "-e ip.dst | head -30")],
            ))
        return out

    # -- файл без сообщений H1 -------------------------------------------------

    def _empty_result(self, result: BranchResult,
                      gen: _General) -> BranchResult:
        """Файл без сообщений H1 — понятный отчёт вместо пустого."""
        note = ("в файле нет ни одного сегмента с сигнатурой H1"
                if not gen.total_packets else
                f"в файле {C.fmt_int(gen.total_packets)} пакетов, "
                "но сигнатура H1 не найдена")
        body = (
            "<p>В файле не найдено ни одного сообщения SINEC H1: ни один "
            "TCP-сегмент не начинается с сигнатуры <code>53 35</code>.</p>"
            "<p>Проверьте, что это тот протокол. SINEC H1 работает по "
            "RFC 1006 (fetch/write), типовой порт — 2000. Если трафик идёт "
            "по TPKT/COTP с кодом операции S7comm, используйте ветку "
            "<code>s7comm</code>; для произвольного TCP/UDP без "
            "дизассемблера — ветку <code>services</code>.</p>"
            f'<p class="note">{C.esc(note)}.</p>'
        )
        result.kpi = [
            KpiItem("Длительность захвата", C.fmt_dur(gen.duration)),
            KpiItem("Всего пакетов", C.fmt_int(gen.total_packets),
                    C.fmt_bytes(gen.total_bytes) + " трафика"),
            KpiItem("Сообщений H1", "0", "сигнатура «S5» не найдена"),
            KpiItem("SYN-подключений", C.fmt_int(gen.syn_total)),
        ]
        result.sections = [Section(
            "general", "SINEC H1 не обнаружен", body,
            [("Пакеты порта 2000 с данными",
              self._cmd('-Y "tcp.port==2000 && tcp.payload" -T fields '
                        "-e frame.number -e frame.time -e ip.src -e ip.dst "
                        "-e tcp.payload | head -30")),
             ("Что tshark считает протоколом (колонка Protocol)",
              self._cmd("-T fields -e frame.number -e _ws.col.Protocol "
                        "| head -30"))],
        )]
        result.recommendations = [Recommendation(
            id="h1-not-found", severity="info",
            title="Сообщений SINEC H1 в файле нет",
            problem=note + ".",
            advice=("Проверьте выбор ветки: этот протокол отличается от "
                    "S7comm (порт 102, TPKT/COTP). Для произвольного "
                    "TCP-трафика подойдёт ветка services."),
            commands=[self._cmd('-Y "tcp.port==2000 && tcp.payload" '
                               "-T fields -e frame.number -e frame.time "
                               "-e ip.src -e ip.dst | head -30")],
        )]
        result.metrics = {
            "h1_msgs": 0.0, "h1_reqs": 0.0, "h1_resps": 0.0,
            "h1_err_pct": 0.0, "h1_unans_pct": 0.0,
        }
        return result


def _coverage(ranges: list[tuple[int, int, float]]) -> str:
    """Схема покрытия блока: пересекающиеся диапазоны сливаются."""
    if not ranges:
        return ""
    top = max(n for _s, _e, n in ranges) or 1
    merged: list[list] = []
    for start, end, n in sorted(ranges):
        if merged and start <= merged[-1][1]:
            prev = merged[-1]
            prev[1] = max(prev[1], end)
            prev[2] = max(prev[2], n)
        else:
            merged.append([start, end, n])
    return C.coverage_svg(
        [(s, e, n / top) for s, e, n in merged],
        max_reg=max(e for _s, e, _n in merged),
        label="слова блока")