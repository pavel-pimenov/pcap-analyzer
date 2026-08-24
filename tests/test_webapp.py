"""Интеграционные тесты веб-GUI: реальный http.server в фоновом потоке.

Покрывают: список веток, загрузку pcap (multipart), очередь анализа,
просмотр и экспорт отчёта, повторный анализ, отмену, удаление, ошибки
маршрутов и некорректных идентификаторов. Требуют tshark и образцы;
иначе пропускаются.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analyzer.webapp.server import AppState, make_handler   # noqa: E402
from tests.test_smoke import HAS_TSHARK, SAMPLES, _pick_sample  # noqa: E402


def _request(base: str, path: str, method: str = "GET", body: bytes | None = None,
             timeout: float = 30.0, content_type: str | None = None):
    req = urllib.request.Request(base + path, data=body, method=method)
    req.add_header("Content-Type",
                   content_type or "application/octet-stream")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        try:
            return e.code, dict(e.headers), e.read()
        finally:
            e.close()


MULTIPART_CT = "multipart/form-data; boundary=----WebApiTestBoundary7"


def _multipart(payload: bytes, filename: str) -> bytes:
    bnd = b"----WebApiTestBoundary7"
    return b"".join([
        b"--" + bnd + b"\r\n",
        b'Content-Disposition: form-data; name="file"; filename="'
        + filename.encode() + b'"\r\n\r\n',
        payload,
        b"\r\n--" + bnd + b"--\r\n",
    ])


@unittest.skipUnless(HAS_TSHARK, "нет tshark в PATH")
@unittest.skipUnless(SAMPLES.is_dir(), f"нет каталога образцов: {SAMPLES}")
class WebApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pcap = (_pick_sample("cote", "modbus")
                    or _pick_sample() or min(
                        p for p in SAMPLES.iterdir()
                        if p.suffix.lower() in {".pcap", ".pcapng", ".cap"}))
        cls.tmp = Path(__import__("tempfile").mkdtemp(prefix="pcapweb-"))
        cls.state = AppState(cls.tmp / "data", SAMPLES.resolve(), None)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0),
                                        make_handler(cls.state))
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # -- служебное ------------------------------------------------------------

    def _upload(self, filename: str | None = None, payload: bytes | None = None) -> dict:
        body = _multipart(payload if payload is not None
                          else self.pcap.read_bytes(),
                          filename or self.pcap.name)
        code, _h, data = _request(self.base, "/api/upload?branch=modbus",
                                  method="POST", body=body,
                                  content_type=MULTIPART_CT)
        self.assertEqual(code, 201, data[:300])
        return json.loads(data)

    def _wait_done(self, fid: str, timeout: float = 240.0) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            _c, _h, data = _request(self.base, f"/api/status/{fid}")
            st = json.loads(data)
            if st["status"] in ("done", "error", "cancelled"):
                return st
            time.sleep(0.5)
        self.fail("анализ не завершился за отведённое время")

    # -- тесты ------------------------------------------------------------------

    def test_index_page_served(self):
        code, headers, body = _request(self.base, "/")
        self.assertEqual(code, 200)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn(b"pcap-analyzer", body)

    def test_branches_listed(self):
        code, _h, data = _request(self.base, "/api/branches")
        self.assertEqual(code, 200)
        branches = {b["key"] for b in json.loads(data)}
        self.assertIn("modbus", branches)
        self.assertIn("s7comm", branches)

    def test_full_upload_analyze_view_export_delete(self):
        entry = self._upload()
        fid = entry["id"]
        self.assertTrue(fid.isalnum())
        status = self._wait_done(fid)
        self.assertEqual(status["status"], "done",
                         f"ошибка анализа: {status.get('error')}")

        # просмотр HTML
        code, headers, body = _request(self.base, f"/view/{fid}")
        self.assertEqual(code, 200)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn(b"</html>", body)

        # экспорт HTML; PDF — либо готов, либо честный 404 JSON (без weasyprint)
        code, headers, body = _request(self.base, f"/export/{fid}?fmt=html")
        self.assertEqual(code, 200)
        self.assertTrue(headers["Content-Disposition"].startswith("attachment"))
        code, _h, body = _request(self.base, f"/export/{fid}?fmt=pdf")
        self.assertIn(code, (200, 404))
        if code == 404:
            self.assertIn("не готов", json.loads(body)["error"])
        self.assertEqual(_request(self.base, f"/export/{fid}?fmt=xlsx")[0], 400)

        # повторный анализ принимается, немедленный дубль отклоняется
        code, _h, _d = _request(self.base, f"/api/files/{fid}/analyze",
                                method="POST", body=b'{"branch": "modbus"}')
        self.assertEqual(code, 202)
        code, _h, _d = _request(self.base, f"/api/files/{fid}/analyze",
                                method="POST", body=b'{"branch": "s7comm"}')
        self.assertEqual(code, 409)
        self._wait_done(fid)

        # неизвестная ветка
        code, _h, _d = _request(self.base, f"/api/files/{fid}/analyze",
                                method="POST", body=b'{"branch": "netflow"}')
        self.assertEqual(code, 400)

        # удаление: файл и отчёты исчезают из API
        code, _h, data = _request(self.base, f"/api/files/{fid}",
                                  method="DELETE")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(data), {"ok": True})
        self.assertEqual(_request(self.base, f"/view/{fid}")[0], 404)

    def test_bad_and_unknown_ids(self):
        # символы вне [A-Za-z0-9_-] не совпадают с маршрутами → 404;
        # обхода путей нет: идентификаторы никогда не попадают в пути ОС
        self.assertEqual(_request(self.base, "/api/status/..%2Fetc")[0], 404)
        self.assertEqual(_request(self.base, "/view/abc.def")[0], 404)
        self.assertEqual(_request(self.base, "/api/status/deadbeef0000")[0],
                         404)
        self.assertEqual(_request(self.base, "/no/such/route")[0], 404)

    def test_cancel_then_second_cancel_conflict(self):
        entry = self._upload()
        fid = entry["id"]
        code, _h, _d = _request(self.base, f"/api/files/{fid}/cancel",
                                method="POST", body=b"")
        self.assertIn(code, (200, 409))          # успело стартовать или нет
        status = self._wait_done(fid)
        self.assertEqual(status["status"], "cancelled")
        code2, _h, data = _request(self.base, f"/api/files/{fid}/cancel",
                                   method="POST", body=b"")
        self.assertEqual(code2, 409)

    def test_upload_rejects_empty_file(self):
        code, _h, data = _request(self.base, "/api/upload", method="POST",
                                  body=_multipart(b"", "empty.pcap"),
                                  content_type=MULTIPART_CT)
        self.assertEqual(code, 400)
        self.assertIn("пустой", json.loads(data)["error"])

    def test_upload_requires_multipart(self):
        code, _h, data = _request(self.base, "/api/upload", method="POST",
                                  body=b"not-multipart")
        self.assertEqual(code, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
