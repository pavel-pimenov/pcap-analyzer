"""Генератор синтетического pcap-дампа с трафиком Modbus/TCP (только stdlib).

Используется тестами и CI: бинарные образцы в репозиторий не коммитятся
(*.pcap в .gitignore), а интеграционные проверки должны выполняться везде,
где есть tshark. Запись из командной строки:

    python tests/pcapgen.py /tmp/modbus_smoke.pcap

Сценарий спроектирован так, чтобы сработали правила рекомендаций:
мелкие одиночные чтения в одном окне, пачка одиночных записей FC6,
регулярные исключения, запрос без ответа и сверхбыстрый опрос
(интервал сопоставим со временем отклика).
"""

from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path

CLIENT_IP = "10.0.0.10"
SERVER_IP = "10.0.0.1"
CLIENT_PORT = 49152
SERVER_PORT = 502
BASE_TS = 1735000000.0

FLAG_SYN = 0x02
FLAG_PSH_ACK = 0x18

_ETH = (bytes.fromhex("001122334455")            # dst MAC
        + bytes.fromhex("66778899aabb")          # src MAC
        + struct.pack(">H", 0x0800))


def _cksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f">{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


# --- Сборка PDU Modbus/TCP ---------------------------------------------------

def mbtcp(trans: int, unit: int, func: int, tail: bytes = b"") -> bytes:
    """Кадр Modbus/TCP: MBAP (7 байт) + PDU."""
    pdu = bytes([func]) + tail
    return struct.pack(">HHHB", trans & 0xFFFF, 0, len(pdu) + 1, unit) + pdu


def fc3_request(ref: int, cnt: int) -> bytes:
    return mbtcp_tail(3, struct.pack(">HH", ref, cnt))


def fc6_request(ref: int, value: int) -> bytes:
    return mbtcp_tail(6, struct.pack(">HH", ref, value))


def mbtcp_tail(func: int, tail: bytes) -> bytes:
    return bytes([func]) + tail


def fc3_response(values: list[int]) -> bytes:
    return bytes([2 * len(values)]) + b"".join(
        struct.pack(">H", v) for v in values)


class Capture:
    """Накопитель кадров: (время, направление, TCP-payload, флаги)."""

    def __init__(self) -> None:
        self.frames: list[tuple[float, bool, bytes, int]] = []
        self._trans = 0

    def next_trans(self) -> int:
        self._trans += 1
        return self._trans

    def raw(self, ts: float, from_client: bool, payload: bytes,
            flags: int = FLAG_PSH_ACK) -> None:
        self.frames.append((ts, from_client, payload, flags))

    def exchange(self, ts: float, rtt: float, req_func: int, req_tail: bytes,
                 resp_func: int | None = None,
                 resp_tail: bytes = b"") -> float:
        """Запрос и ответ на нём (resp_func None — ответа нет)."""
        tr = self.next_trans()
        self.raw(ts, True, mbtcp(tr, 1, req_func, req_tail))
        if resp_func is not None:
            self.raw(ts + rtt, False, mbtcp(tr, 1, resp_func, resp_tail))
        return tr


def build_modbus_scenario() -> Capture:
    """Трафик одного клиента с одним сервером (см. докстринг модуля)."""
    cap = Capture()
    t = BASE_TS

    # Фаза A: 30 мелких чтений (1 регистр) в пределах одного окна ~0,9 с —
    # кандидат на объединение в пакетный запрос; значения чередуются.
    for i in range(30):
        t += 0.03
        cap.exchange(t, 0.0005, 3, struct.pack(">HH", 0, 1),
                     3, fc3_response([i % 2]))

    # Фаза B: обращения к несуществующему регистру — исключения Modbus
    # (функция 0x80|3, код 2 ILLEGAL DATA ADDRESS).
    for _ in range(4):
        t += 0.05
        cap.exchange(t, 0.0005, 3, struct.pack(">HH", 200, 1),
                     0x83, bytes([2]))

    # Фаза C: сверхбыстрый опрос — интервал 3 мс при RTT 2,5 мс
    # («давление» на сервер, правило poll-pressure).
    for i in range(60):
        t += 0.003
        cap.exchange(t, 0.0025, 3, struct.pack(">HH", 300, 1),
                     3, fc3_response([i % 3]))

    # Пачка одиночных записей FC6 в одном окне — кандидат на FC16.
    t += 0.5
    for i in range(15):
        t += 0.02
        cap.exchange(t, 0.0005, 6, struct.pack(">HH", 10 + i, 0xAA),
                     6, struct.pack(">HH", 10 + i, 1))

    # Последний запрос остаётся без ответа (обрыв захвата).
    cap.exchange(t + 0.05, 0.0, 3, struct.pack(">HH", 0, 4), resp_func=None)
    return cap


# --- Упаковка Ethernet/IP/TCP/pcap -------------------------------------------

def _ipv4_header(sip: str, dip: str, payload_len: int, ident: int) -> bytes:
    hdr = struct.pack(">BBHHHBBH4s4s",
                      0x45, 0, 20 + payload_len, ident, 0x4000,
                      64, 6, 0,
                      socket.inet_aton(sip), socket.inet_aton(dip))
    hdr = hdr[:10] + struct.pack(">H", _cksum(hdr)) + hdr[12:]
    return hdr


def _tcp_segment(sip: str, dip: str, sport: int, dport: int, seq: int,
                 ack: int, flags: int, payload: bytes) -> bytes:
    hdr = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags,
                      64240, 0, 0)
    pseudo = (socket.inet_aton(sip) + socket.inet_aton(dip)
              + struct.pack(">BBH", 0, 6, len(hdr) + len(payload)))
    ck = _cksum(pseudo + hdr + payload)
    hdr = hdr[:16] + struct.pack(">H", ck) + hdr[18:]
    return hdr + payload


def write_pcap(path: Path, cap: Capture) -> int:
    """Записать кадры в классический pcap; вернуть число кадров."""
    cseq, sseq, ident = 1000, 5000, 1
    written = 0
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for ts, from_client, payload, flags in cap.frames:
            sip, dip = ((CLIENT_IP, SERVER_IP) if from_client
                        else (SERVER_IP, CLIENT_IP))
            sport, dport = ((CLIENT_PORT, SERVER_PORT) if from_client
                            else (SERVER_PORT, CLIENT_PORT))
            seg = _tcp_segment(sip, dip, sport, dport, cseq if from_client
                               else sseq, 1, flags, payload)
            ip = _ipv4_header(sip, dip, len(seg), ident) + seg
            if from_client:
                cseq += max(len(payload), 1)
            else:
                sseq += max(len(payload), 1)
            ident = (ident + 1) & 0xFFFF
            frame = _ETH + ip
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000)) % 1_000_000
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)
            written += 1
    return written


def write_modbus_pcap(path: Path) -> int:
    """Полный сценарий: SYN к порту 502 + обмен; вернуть число кадров."""
    cap = Capture()
    cap.raw(BASE_TS, True, b"", flags=FLAG_SYN)     # попытка подключения
    cap.frames.extend(build_modbus_scenario().frames)
    return write_pcap(path, cap)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("использование: python tests/pcapgen.py <выход.pcap>",
              file=sys.stderr)
        return 2
    n = write_modbus_pcap(Path(argv[1]))
    print(f"записано кадров: {n} → {argv[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
