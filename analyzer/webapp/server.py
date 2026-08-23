"""Веб-сервер pcap-analyzer на стандартной библиотеке (http.server).

Возможности:
* загрузка pcap-файлов через браузер (multipart, потоково, без чтения
  всего файла в память);
* фоновый анализ в рабочих потоках (очередь), статусы в реальном времени;
* просмотр HTML-отчёта и экспорт в HTML/PDF;
* каталог образцов (read-only) — предлагается в списке, удалять нельзя.

Запуск: python -m analyzer serve --host 127.0.0.1 --port 8000 \
            --data-dir webdata --samples-dir pcap-sample
"""

from __future__ import annotations

import hashlib
import json
import queue
import re
import shutil
import threading
import uuid
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

from ..branches import BRANCHES, DEFAULT_BRANCH, get_branch
from ..config import DEFAULT_CONFIG
from ..report import render_document, render_pdf_bytes
from . import page

_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_PCAP_EXTS = {".pcap", ".pcapng", ".cap"}
MAX_UPLOAD_BYTES = 1 << 30          # 1 ГБ


# ---------------------------------------------------------------------------
# Состояние приложения
# ---------------------------------------------------------------------------

class AppState:
    def __init__(self, data_dir: Path, samples_dir: Path | None,
                 tshark_bin: str | None):
        self.data_dir = data_dir.resolve()
        self.uploads_dir = self.data_dir / "uploads"
        self.reports_dir = self.data_dir / "reports"
        self.uploads_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.samples_dir = samples_dir.resolve() if samples_dir else None
        self.tshark_bin = tshark_bin
        self.lock = threading.RLock()
        self.entries: dict[str, dict] = {}
        self.jobs: queue.Queue[str] = queue.Queue()
        self._load_persisted()
        for _ in range(2):
            threading.Thread(target=self._worker, daemon=True).start()

    # -- реестр ---------------------------------------------------------------
    def _meta_path(self, fid: str) -> Path:
        return self.uploads_dir / f"{fid}.json"

    def _load_persisted(self) -> None:
        """Восстановить загрузки с прошлого запуска (файлы + meta.json)."""
        for mp in sorted(self.uploads_dir.glob("*.json")):
            try:
                meta = json.loads(mp.read_text(encoding="utf-8"))
                fid = meta["id"]
                if not _ID_RE.match(fid):
                    continue
                pcap = Path(meta["path"])
                if not pcap.is_file():
                    continue
                status = "done" if (self.reports_dir / f"{fid}.html").is_file() \
                    else "error"
                meta.update(status=status,
                            error=None if status == "done"
                            else "отчёт не найден, запустите анализ повторно")
                self.entries[fid] = meta
            except (KeyError, ValueError, OSError, json.JSONDecodeError):
                continue

    def _scan_samples(self) -> None:
        """Зарегистрировать образцы из read-only каталога."""
        if not self.samples_dir or not self.samples_dir.is_dir():
            return
        for p in sorted(self.samples_dir.iterdir()):
            if p.suffix.lower() not in _PCAP_EXTS or not p.is_file():
                continue
            fid = "s-" + hashlib.sha1(str(p).encode()).hexdigest()[:10]
            if fid in self.entries:
                continue
            self.entries[fid] = {
                "id": fid, "kind": "sample", "name": p.name,
                "path": str(p), "size": p.stat().st_size,
                "branch": DEFAULT_BRANCH, "status":
                    "done" if (self.reports_dir / f"{fid}.html").is_file()
                    else "new",
                "stage": "", "error": "", "added": "",
            }

    def public(self, e: dict) -> dict:
        fid = e["id"]
        return {
            "id": fid,
            "kind": e["kind"],
            "name": e["name"],
            "size": e["size"],
            "branch": e.get("branch", DEFAULT_BRANCH),
            "status": e["status"],
            "stage": e.get("stage", ""),
            "error": e.get("error", ""),
            "added": e.get("added", ""),
            "hasHtml": (self.reports_dir / f"{fid}.html").is_file(),
            "hasPdf": (self.reports_dir / f"{fid}.pdf").is_file(),
        }

    def list_files(self) -> list[dict]:
        with self.lock:
            self._scan_samples()
            items = [self.public(e) for e in self.entries.values()]
        items.sort(key=lambda x: (
            0 if x["kind"] == "sample" else 1, x["name"]))
        return items

    def get(self, fid: str) -> dict | None:
        with self.lock:
            self._scan_samples()
            return self.entries.get(fid)

    # -- жизненный цикл файла ---------------------------------------------------
    def add_upload(self, src: Path, orig_name: str, branch: str) -> dict:
        fid = uuid.uuid4().hex[:12]
        dst = self.uploads_dir / f"{fid}{src.suffix.lower()}"
        shutil.move(str(src), dst)
        entry = {
            "id": fid, "kind": "upload", "name": orig_name,
            "path": str(dst), "size": dst.stat().st_size,
            "branch": branch, "status": "queued",
            "stage": "", "error": "",
            "added": datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
        }
        with self.lock:
            self.entries[fid] = entry
            self._persist(entry)
        self.enqueue(fid, branch)
        return entry

    def _persist(self, e: dict) -> None:
        if e["kind"] != "upload":
            return
        try:
            self._meta_path(e["id"]).write_text(
                json.dumps(e, ensure_ascii=False, indent=1),
                encoding="utf-8")
        except OSError:
            pass

    def enqueue(self, fid: str, branch: str) -> None:
        with self.lock:
            e = self.entries[fid]
            e["branch"] = branch if branch in BRANCHES else DEFAULT_BRANCH
            e["status"] = "queued"
            e["stage"] = ""
            e["error"] = ""
        self.jobs.put(fid)

    def delete(self, fid: str) -> None:
        with self.lock:
            e = self.entries.pop(fid, None)
            if e and e["kind"] == "upload":
                self._meta_path(fid).unlink(missing_ok=True)
                for p in self.uploads_dir.glob(f"{fid}.*"):
                    if p.suffix != ".json":
                        p.unlink(missing_ok=True)
        for ext in ("html", "pdf"):
            (self.reports_dir / f"{fid}.{ext}").unlink(missing_ok=True)

    # -- анализ -----------------------------------------------------------------
    def _stage(self, fid: str, msg: str) -> None:
        with self.lock:
            e = self.entries.get(fid)
            if e:
                e["stage"] = msg
                if e["status"] in ("queued", "new"):
                    e["status"] = "running"

    def _worker(self) -> None:
        while True:
            fid = self.jobs.get()
            with self.lock:
                e = self.entries.get(fid)
            if not e:
                continue
            with self.lock:
                e["status"] = "running"
            branch = get_branch(e.get("branch", DEFAULT_BRANCH))
            try:
                result = branch.analyze(
                    Path(e["path"]), DEFAULT_CONFIG,
                    progress=lambda m: self._stage(fid, m),
                    tshark_bin=self.tshark_bin)
                (self.reports_dir / f"{fid}.html").write_text(
                    render_document(result), encoding="utf-8")
                pdf_err = ""
                try:
                    (self.reports_dir / f"{fid}.pdf").write_bytes(
                        render_pdf_bytes(result))
                except Exception as pe:              # PDF не критичен
                    pdf_err = f"PDF не собран: {pe}"
                with self.lock:
                    e["status"] = "done"
                    e["stage"] = "готово" + (f" ({pdf_err})" if pdf_err else "")
                    e["error"] = ""
                    self._persist(e)
            except Exception as ex:                  # noqa: BLE001 — статус в UI
                with self.lock:
                    e["status"] = "error"
                    e["error"] = str(ex)
                    self._persist(e)


# ---------------------------------------------------------------------------
# Потоковый разбор multipart/form-data (cgi удалён в Python 3.13+)
# ---------------------------------------------------------------------------

def parse_multipart_file(rfile, boundary: bytes, dest: Path,
                         total_len: int) -> tuple[str, int]:
    """Сохранить первый файл из multipart-запроса в `dest` (потоково).

    Чтение ограничено Content-Length и выполняется через read1(), иначе
    BufferedReader блокируется, дожидаясь полного чанка за концом тела.
    Возвращает (имя_файла, размер).
    """
    sep = b"\r\n--" + boundary
    remaining = total_len

    def _readline() -> bytes:
        nonlocal remaining
        if remaining <= 0:
            raise ValueError("неожиданный конец запроса")
        line = rfile.readline(65536)
        if not line:
            raise ValueError("неожиданный конец запроса")
        remaining -= len(line)
        return line

    def _chunk() -> bytes:
        nonlocal remaining
        if remaining <= 0:
            return b""
        data = rfile.read1(min(1 << 16, remaining))
        remaining -= len(data)
        return data

    line = _readline()
    while line and not line.startswith(b"--" + boundary):
        line = _readline()                       # пропустить преамбулу
    headers: dict[str, str] = {}
    while True:
        h = _readline()
        if h in (b"\r\n", b"\n"):
            break
        k, _, v = h.decode("latin-1").partition(":")
        headers[k.strip().lower()] = v.strip()
    disp = headers.get("content-disposition", "")
    m = re.search(r'filename="([^"]*)"', disp)
    filename = m.group(1) if m else ""

    total = 0
    tail = b""
    keep = len(sep) - 1
    with open(dest, "wb") as out:
        while True:
            chunk = _chunk()
            if not chunk:
                raise ValueError("завершающая граница не найдена "
                                 "(обрыв или неверный формат запроса)")
            buf = tail + chunk
            idx = buf.find(sep)
            if idx >= 0:
                out.write(buf[:idx])
                total += idx
                break
            if len(buf) > keep:
                out.write(buf[:-keep])
                total += len(buf) - keep
                buf = buf[-keep:]
            tail = buf
            if total > MAX_UPLOAD_BYTES:
                raise ValueError("файл слишком большой (лимит 1 ГБ)")
    return filename, total


# ---------------------------------------------------------------------------
# HTTP-обработчик
# ---------------------------------------------------------------------------

_CT = {
    ".html": "text/html; charset=utf-8",
    ".pdf": "application/pdf",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png", ".svg": "image/svg+xml", ".ico": "image/x-icon",
}


def make_handler(state: AppState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "pcap-analyzer-web"

        def log_message(self, fmt, *args):       # тише в консоли
            pass

        # -- ответы ----------------------------------------------------------
        def _json(self, obj, code: int = 200):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", _CT[".json"])
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _file(self, path: Path, ctype: str, download: str | None = None):
            data = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            if download:
                # RFC 6266/5987: ascii-фолбэк + UTF-8 имя для кириллицы
                stem = download.rsplit(".", 1)[0]
                ext = download.rsplit(".", 1)[-1]
                utf8 = quote(f"{stem}.{ext}")
                self.send_header(
                    "Content-Disposition",
                    f'attachment; filename="report.{ext}"; '
                    f"filename*=UTF-8''{utf8}")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _entry_or_404(self, fid: str):
            if not _ID_RE.match(fid):
                self._json({"error": "некорректный идентификатор"}, 400)
                return None
            e = state.get(fid)
            if not e:
                self._json({"error": "файл не найден"}, 404)
            return e

        # -- GET -------------------------------------------------------------
        def do_GET(self):                        # noqa: N802 (стандарт API)
            u = urlparse(self.path)
            path = u.path
            if path in ("/", "/index.html"):
                body = page.PAGE.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", _CT[".html"])
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/favicon.ico":
                self.send_response(204)
                self.end_headers()
                return
            if path == "/api/files":
                self._json(state.list_files())
                return
            if path == "/api/branches":
                self._json([
                    {"key": k, "title": BRANCHES[k]().title,
                     "description": BRANCHES[k]().description,
                     "default": k == DEFAULT_BRANCH}
                    for k in sorted(BRANCHES)])
                return
            m = re.fullmatch(r"/api/status/([A-Za-z0-9_-]+)", path)
            if m:
                e = self._entry_or_404(m.group(1))
                if e:
                    self._json(state.public(e))
                return
            m = re.fullmatch(r"/view/([A-Za-z0-9_-]+)", path)
            if m:
                e = self._entry_or_404(m.group(1))
                if not e:
                    return
                rep = state.reports_dir / f"{e['id']}.html"
                if rep.is_file():
                    self._file(rep, _CT[".html"])
                else:
                    self._json({"error": "отчёт ещё не готов"}, 404)
                return
            m = re.fullmatch(r"/export/([A-Za-z0-9_-]+)", path)
            if m:
                e = self._entry_or_404(m.group(1))
                if not e:
                    return
                fmt = (parse_qs(u.query).get("fmt") or ["html"])[0]
                ext = {"html": "html", "pdf": "pdf"}.get(fmt)
                if ext is None:
                    self._json({"error": "формат должен быть html|pdf"}, 400)
                    return
                rep = state.reports_dir / f"{e['id']}.{ext}"
                if not rep.is_file():
                    self._json({"error": "отчёт в этом формате не готов"}, 404)
                    return
                base = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(e["name"]).stem)
                self._file(rep, _CT[f".{ext}"],
                           download=f"отчет_{base}.{ext}")
                return
            self._json({"error": "нет такого маршрута"}, 404)

        # -- POST --------------------------------------------------------------
        def do_POST(self):                       # noqa: N802
            u = urlparse(self.path)
            if u.path == "/api/upload":
                self._handle_upload()
                return
            m = re.fullmatch(r"/api/files/([A-Za-z0-9_-]+)/analyze", u.path)
            if m:
                e = self._entry_or_404(m.group(1))
                if not e:
                    return
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                branch = DEFAULT_BRANCH
                if raw:
                    try:
                        branch = json.loads(raw.decode("utf-8")).get(
                            "branch", DEFAULT_BRANCH)
                    except (ValueError, UnicodeDecodeError):
                        pass
                if branch not in BRANCHES:
                    self._json({"error": "неизвестная ветка анализа"}, 400)
                    return
                with state.lock:
                    if e["status"] in ("running", "queued"):
                        self._json({"error": "анализ уже выполняется"}, 409)
                        return
                state.enqueue(e["id"], branch)
                self._json(state.public(state.get(e["id"])), 202)
                return
            self._json({"error": "нет такого маршрута"}, 404)

        def _handle_upload(self):
            ctype = self.headers.get("Content-Type", "")
            m = re.search(r'boundary="?([^";]+)"?', ctype)
            if "multipart/form-data" not in ctype or not m:
                self._json(
                    {"error": "ожидается multipart/form-data"}, 400)
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_UPLOAD_BYTES + (1 << 20):
                self._json({"error": "файл слишком большой (лимит 1 ГБ)"},
                           413)
                return
            tmp = state.uploads_dir / f"tmp-{uuid.uuid4().hex}.part"
            branch_q = None
            try:
                fname, size = parse_multipart_file(
                    self.rfile, m.group(1).encode("latin-1"), tmp, length)
                if size == 0:
                    self._json({"error": "пустой файл"}, 400)
                    return
                # ветка может идти следующим полем формы; упрощённо — из query
                qs = parse_qs(urlparse(self.path).query)
                branch_q = (qs.get("branch") or [None])[0]
                safe_ext = Path(fname).suffix.lower()
                if safe_ext not in _PCAP_EXTS:
                    safe_ext = ".pcap"
                entry = state.add_upload(tmp, Path(fname).name or "dump.pcap",
                                         branch_q or DEFAULT_BRANCH)
                self._json(state.public(entry), 201)
            except ValueError as ve:
                tmp.unlink(missing_ok=True)
                self._json({"error": str(ve)}, 400)
            except Exception as ex:              # noqa: BLE001
                tmp.unlink(missing_ok=True)
                self._json({"error": f"ошибка приёма файла: {ex}"}, 500)

        # -- DELETE --------------------------------------------------------------
        def do_DELETE(self):                     # noqa: N802
            m = re.fullmatch(r"/api/files/([A-Za-z0-9_-]+)",
                             urlparse(self.path).path)
            if not m:
                self._json({"error": "нет такого маршрута"}, 404)
                return
            e = self._entry_or_404(m.group(1))
            if not e:
                return
            if e["kind"] == "sample":
                self._json({"error": "образцы удалять нельзя"}, 403)
                return
            state.delete(e["id"])
            self._json({"ok": True})

    return Handler


def run_server(host: str, port: int, data_dir: Path,
               samples_dir: Path | None, tshark_bin: str | None) -> int:
    state = AppState(data_dir, samples_dir, tshark_bin)
    httpd = ThreadingHTTPServer((host, port), make_handler(state))
    url = f"http://{host}:{port}"
    print(f"[pcap-analyzer] Веб-интерфейс запущен: {url}", flush=True)
    print(f"[pcap-analyzer] Каталог данных: {state.data_dir}", flush=True)
    if samples_dir:
        print(f"[pcap-analyzer] Образцы: {samples_dir.resolve()}",
              flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[pcap-analyzer] Остановка веб-интерфейса.", flush=True)
    finally:
        httpd.server_close()
    return 0
