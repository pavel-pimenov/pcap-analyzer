"""Fuzz-тесты парсеров недоверенных данных (фиксированное зерно).

Парсеры получают байты прямо из pcap-файлов, которые могут быть битыми
или специально сформированными: ни один из них не должен бросать ничего,
кроме ожидаемых доменных исключений, и не должен уходить в бесконечный
цикл. Запуск вместе с остальными: python -m unittest discover -s tests
"""

from __future__ import annotations

import io
import random
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SEED = 20260825


class ValueDigestsFuzzTest(unittest.TestCase):
    """S7comm._value_digests: произвольные payload и длины."""

    def setUp(self):
        from analyzer.branches.s7comm import S7CommAnalyzer
        self.an = S7CommAnalyzer()
        self.an.cfg = __import__("analyzer.config",
                                 fromlist=["DEFAULT_CONFIG"]).DEFAULT_CONFIG
        self.rng = random.Random(SEED)

    def _payload(self) -> str:
        """Случайный hex-payload, иногда с правдоподобным заголовком."""
        rng = self.rng
        n = rng.choice([0, 5, 16, 24, 40, 80, 157, 300])
        raw = bytearray(rng.randrange(256) for _ in range(n))
        if n >= 20 and rng.random() < 0.5:
            # TPKT + COTP DT + магия S7 + rosctr 1|3 — глубокие ветки
            total = rng.randrange(30, max(31, n))
            raw[0:4] = bytes([3, 0, (total >> 8) & 0xFF, total & 0xFF])
            raw[4] = rng.choice([2, 3])          # LI COTP
            raw[5] = 0xF0
            if n >= 9:
                raw[7] = 0x32                     # magic
                raw[8] = rng.choice([1, 3])       # rosctr
                raw[15:17] = rng.randrange(300).to_bytes(2, "big")
        if rng.random() < 0.2 and raw:
            i = rng.randrange(len(raw))
            raw[i] ^= 0xFF                        # порча байта
        bad_hex = rng.random() < 0.05
        hx = raw.hex()
        if bad_hex:
            hx += "zz"
        return hx

    def test_never_raises(self):
        from analyzer.branches.s7comm import S7CommAnalyzer
        fn = S7CommAnalyzer._value_digests
        for _ in range(4000):
            hx = self._payload()
            lens = [self.rng.randrange(0, 64)
                    for _ in range(self.rng.randrange(0, 12))]
            expect = self.rng.randrange(0, 12)
            job = bool(self.rng.getrandbits(1))
            protos = ("eth:tpkt:cotp:cotp.segments:s7comm"
                      if self.rng.random() < 0.2 else "eth:tpkt:cotp:s7comm")
            res = fn(self.an,
                     {"tcp.payload": hx, "frame.protocols": protos},
                     lens, expect, job=job)
            self.assertTrue(res == () or isinstance(res, tuple))
            if isinstance(res, tuple):
                self.assertTrue(all(isinstance(x, str) for x in res))

    def test_realistic_header_no_hang(self):
        """Валидный каркас со случайными длинами — ограниченное время."""
        import time as _t
        from analyzer.branches.s7comm import S7CommAnalyzer
        fn = S7CommAnalyzer._value_digests
        base = bytearray.fromhex(
            "0300009d02f08032030000d6e70002008800000411ff0400")
        base += bytes(self.rng.randrange(256) for _ in range(120))
        t0 = _t.monotonic()
        for _ in range(2000):
            buf = bytearray(base)
            i = self.rng.randrange(len(buf))
            buf[i] = self.rng.randrange(256)
            fn(self.an, {"tcp.payload": buf.hex(),
                         "frame.protocols": "eth:tpkt:cotp:s7comm"},
               [self.rng.randrange(0, 500)], self.rng.randrange(1, 20),
               job=bool(self.rng.getrandbits(1)))
        self.assertLess(_t.monotonic() - t0, 10.0)


class ItemLabelsFuzzTest(unittest.TestCase):
    """_item_labels: агрегированные поля tshark с мусором не роняют код."""

    def test_random_fields(self):
        from analyzer.branches.s7comm import _item_labels
        rng = random.Random(SEED + 1)

        def val():
            kind = rng.randrange(4)
            if kind == 0:
                return hex(rng.randrange(1 << 16))
            if kind == 1:
                return str(rng.randrange(1 << 16))
            if kind == 2:
                return ""
            return rng.choice(["zz", "-", "0x", "1e9", "999999999999"])

        for _ in range(3000):
            areas = ",".join(val() for _ in range(rng.randrange(0, 6)))
            dbs = ",".join(val() for _ in range(rng.randrange(0, 6)))
            addrs = ",".join(val() for _ in range(rng.randrange(0, 6)))
            lens = ",".join(val() for _ in range(rng.randrange(0, 6)))
            out = _item_labels({
                "s7comm.param.item.area": areas,
                "s7comm.param.item.db": dbs,
                "s7comm.param.item.address.byte": addrs,
                "s7comm.param.item.length": lens,
            })
            self.assertIsInstance(out, tuple)


class MultipartFuzzTest(unittest.TestCase):
    """parse_multipart_file: случайные тела — только ValueError или успех."""

    def _run(self, body: bytes, limit=None):
        from analyzer.webapp import server as srv
        old = srv.MAX_UPLOAD_BYTES
        if limit is not None:
            srv.MAX_UPLOAD_BYTES = limit
        try:
            with tempfile.TemporaryDirectory() as td:
                dest = Path(td) / "out.part"
                try:
                    name, size = srv.parse_multipart_file(
                        io.BufferedReader(io.BytesIO(body)),
                        b"----boundaryX", dest, len(body))
                    return ("ok", dest.read_bytes())
                except ValueError as ve:
                    return ("valueerror", str(ve))
        finally:
            if limit is not None:
                srv.MAX_UPLOAD_BYTES = old

    def test_random_bodies_only_valueerror_or_ok(self):
        rng = random.Random(SEED + 2)
        bnd = b"----boundaryX"
        sep = b"\r\n--" + bnd
        good_head = (b"--" + bnd + b"\r\n"
                     b'Content-Disposition: form-data; name="file"; '
                     b'filename="a.pcap"\r\n\r\n')
        good_tail = sep + b"--\r\n"
        for _ in range(2500):
            mode = rng.randrange(5)
            if mode == 0:
                body = bytes(rng.randrange(256)
                             for _ in range(rng.randrange(0, 512)))
            elif mode == 1:
                payload = bytes(rng.randrange(256)
                                for _ in range(rng.randrange(0, 400)))
                cut = rng.randrange(0, len(good_tail) + 1)
                body = good_head + payload + good_tail[:cut]   # обрыв хвоста
            elif mode == 2:
                payload = bytes(rng.randrange(256)
                                for _ in range(rng.randrange(0, 400)))
                pos = rng.randrange(0, len(payload) + 1)
                body = (good_head + payload[:pos] + sep +
                        payload[pos:] + good_tail)     # ложная граница внутри
            elif mode == 3:
                body = good_head + b"x" * rng.randrange(0, 1000) \
                    + good_tail[:-1]                   # без финальных --
            else:
                body = b""
            status, _info = self._run(body)
            self.assertIn(status, ("ok", "valueerror"))

    def test_size_limit_is_valueerror(self):
        body = (b"--" + b"----boundaryX" + b"\r\n"
                b'Content-Disposition: form-data; filename="a"\r\n\r\n'
                + b"z" * 5000 + b"\r\n--" + b"----boundaryX" + b"--\r\n")
        status, msg = self._run(body, limit=100)
        self.assertEqual(status, "valueerror")
        self.assertIn("большой", msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
