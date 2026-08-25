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
import secrets
import shutil
import threading
import time
import uuid
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

from ..branches import BRANCHES, DEFAULT_BRANCH, get_branch
from ..config import DEFAULT_CONFIG
from ..report import (render_diff_html, render_document,
                      render_html_to_pdf, render_pdf_bytes,
                      render_trend_html)
from ..trend import build_trend
from . import page

_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_PCAP_EXTS = {".pcap", ".pcapng", ".cap"}
MAX_UPLOAD_BYTES = DEFAULT_CONFIG.max_upload_bytes


class AnalysisCancelled(Exception):
    """Анализ отменён пользователем (поднимается в callback прогресса)."""


def _pct_from_stage(msg: str) -> int | None:
    """Оценить процент готовности по служебному сообщению ветки."""
    m = re.match(r"Проход (\d+)/(\d+)", msg)
    if not m:
        return None
    x, y = int(m.group(1)), int(m.group(2))
    if y <= 0:
        return None
    return min(90, max(5, round((x - 0.5) / y * 100)))


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
        # обрывки прерванных загрузок больше не нужны
        for p in self.uploads_dir.glob("tmp-*.part"):
            p.unlink(missing_ok=True)
        self.samples_dir = samples_dir.resolve() if samples_dir else None
        self.tshark_bin = tshark_bin
        self.groups_dir = self.data_dir / "groups"
        self.groups_dir.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.entries: dict[str, dict] = {}
        self.groups: dict[str, dict] = {}
        # задания: ("file", fid) | ("series", gid) | ("diff", gid)
        self.jobs: queue.Queue[tuple[str, str]] = queue.Queue()
        self._load_persisted()
        self._load_groups()
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

    def _load_groups(self) -> None:
        """Восстановить серии/сравнения с прошлого запуска."""
        for mp in sorted(self.groups_dir.glob("*.json")):
            try:
                g = json.loads(mp.read_text(encoding="utf-8"))
                gid = g["id"]
                if not _ID_RE.match(gid):
                    continue
                g.setdefault("status", "error")
                if g["status"] == "done" and \
                        not (self.reports_dir / f"{gid}.html").is_file():
                    g["status"] = "error"
                    g["error"] = "отчёт не найден, запустите повторно"
                self.groups[gid] = g
            except (KeyError, ValueError, OSError, json.JSONDecodeError):
                continue

    def _persist_group(self, g: dict) -> None:
        try:
            (self.groups_dir / f"{g['id']}.json").write_text(
                json.dumps(g, ensure_ascii=False, indent=1),
                encoding="utf-8")
        except OSError:
            pass

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
            "progress": int(e.get("progress") or 0),
            "tookS": "" if e.get("took_s") in (None, "") else str(e["took_s"]),
            "error": e.get("error", ""),
            "added": e.get("added", ""),
            "hasHtml": (self.reports_dir / f"{fid}.html").is_file(),
            "hasPdf": (self.reports_dir / f"{fid}.pdf").is_file(),
        }

    def group_public(self, g: dict) -> dict:
        gid = g["id"]
        return {
            "id": gid,
            "kind": "series" if g["kind"] == "trend" else "diff",
            "name": g["name"],
            "branch": g.get("branch", DEFAULT_BRANCH),
            "status": g["status"],
            "stage": g.get("stage", ""),
            "progress": int(g.get("progress") or 0),
            "tookS": "" if g.get("took_s") in (None, "") else str(g["took_s"]),
            "error": g.get("error", ""),
            "added": g.get("added", ""),
            "members": len(g.get("fids", [])),
            "hasHtml": (self.reports_dir / f"{gid}.html").is_file(),
            "hasPdf": (self.reports_dir / f"{gid}.pdf").is_file(),
        }

    def list_files(self) -> list[dict]:
        with self.lock:
            self._scan_samples()
            items = [self.public(e) for e in self.entries.values()]
            items += [self.group_public(g) for g in self.groups.values()]
        items.sort(key=lambda x: (
            0 if x["kind"] == "sample" else
            1 if x["kind"] in ("series", "diff") else 2, x["name"]))
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

    def create_series(self, fids: list[str], branch: str) -> dict:
        """Группа-серия из существующих файлов; сразу ставится в очередь."""
        pairs: list[tuple[str, str]] = []
        with self.lock:
            for fid in fids:
                e = self.entries.get(fid)
                if e and _ID_RE.match(fid):
                    pairs.append((fid, e["path"]))
            if len(pairs) < 2:
                raise ValueError("для серии нужно минимум два файла")
            gid = "g" + uuid.uuid4().hex[:10]
            g = {
                "id": gid, "kind": "trend", "branch":
                    branch if branch in BRANCHES else DEFAULT_BRANCH,
                "fids": [fid for fid, _p in pairs],
                "paths": [p for _fid, p in pairs],
                "name": f"серия из {len(pairs)} файлов",
                "status": "queued", "stage": "", "progress": 0,
                "error": "", "added":
                    datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
            }
            self.groups[gid] = g
            self._persist_group(g)
        self.jobs.put(("series", gid))
        return g

    def create_diff(self, gid_a: str, gid_b: str) -> dict:
        with self.lock:
            ga, gb = self.groups.get(gid_a), self.groups.get(gid_b)
            if not ga or not gb or ga.get("kind") != "trend" \
                    or gb.get("kind") != "trend":
                raise ValueError("нужны две существующие серии")
            gid = "d" + uuid.uuid4().hex[:10]
            g = {
                "id": gid, "kind": "diff",
                "branch": ga.get("branch", DEFAULT_BRANCH),
                "fids": [gid_a, gid_b], "a": gid_a, "b": gid_b,
                "paths": [],
                "name": (f"{ga['name']} vs {gb['name']}"),
                "status": "queued", "stage": "", "progress": 0,
                "error": "", "added":
                    datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
            }
            self.groups[gid] = g
            self._persist_group(g)
        self.jobs.put(("diff", gid))
        return g

    def request_cancel_group(self, gid: str) -> bool:
        with self.lock:
            g = self.groups.get(gid)
            if not g or g.get("status") not in ("running", "queued"):
                return False
            g["cancel"] = True
            if g["status"] == "queued":
                g["status"] = "cancelled"
                g["stage"] = "отменено"
                self._persist_group(g)
            return True

    def delete_group(self, gid: str) -> None:
        with self.lock:
            self.groups.pop(gid, None)
            (self.groups_dir / f"{gid}.json").unlink(missing_ok=True)
        (self.reports_dir / f"{gid}.html").unlink(missing_ok=True)

    def enqueue(self, fid: str, branch: str) -> None:
        with self.lock:
            e = self.entries[fid]
            e["branch"] = branch if branch in BRANCHES else DEFAULT_BRANCH
            e["status"] = "queued"
            e["stage"] = ""
            e["progress"] = 0
            e["took_s"] = ""
            e["cancel"] = False
            e["error"] = ""
        self.jobs.put(("file", fid))

    def request_cancel(self, fid: str) -> bool:
        """Пометить задание как отменённое; True, если оно было активным."""
        with self.lock:
            e = self.entries.get(fid)
            if not e or e.get("status") not in ("running", "queued"):
                return False
            e["cancel"] = True
            # ещё не начатое задание снимаем сразу, не дожидаясь воркера
            if e["status"] == "queued":
                e["status"] = "cancelled"
                e["stage"] = "анализ отменён"
                self._persist(e)
            return True

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
    def _stage(self, fid: str, msg: str, pct: int | None = None) -> None:
        with self.lock:
            e = self.entries.get(fid)
            if e:
                e["stage"] = msg
                # приоритет у структурного процента от ветки; разбор строк
                # «Проход N/M» оставлен для совместимости
                if pct is not None:
                    e["progress"] = max(0, min(100, int(pct)))
                else:
                    parsed = _pct_from_stage(msg)
                    if parsed is not None:
                        e["progress"] = parsed
                if e["status"] in ("queued", "new"):
                    e["status"] = "running"

    @staticmethod
    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    def _find_cached(self, fid: str, sha256: str,
                     branch: str) -> dict | None:
        """Другая запись с тем же дампом, веткой и ГОТОВЫМ отчётом."""
        with self.lock:
            for other in self.entries.values():
                if (other["id"] != fid and other.get("sha256") == sha256
                        and other.get("branch") == branch
                        and other.get("status") == "done"):
                    return other
            return None

    def _gstage(self, gid: str, msg: str, pct: int | None = None) -> None:
        with self.lock:
            g = self.groups.get(gid)
            if g:
                g["stage"] = msg
                if pct is not None:
                    g["progress"] = max(0, min(100, int(pct)))
                if g["status"] in ("queued", "new"):
                    g["status"] = "running"

    def _run_series(self, gid: str) -> None:
        with self.lock:
            g = self.groups.get(gid)
        t0 = time.monotonic()
        paths = [Path(x) for x in g.get("paths", [])]

        def prog(msg, pct=None, _gid=gid):
            with self.lock:
                cancelled = bool(self.groups.get(_gid, {}).get("cancel"))
            if cancelled:
                raise AnalysisCancelled()
            self._gstage(_gid, msg, pct)

        branch = get_branch(g.get("branch", DEFAULT_BRANCH))
        points, took = build_trend(paths, branch, DEFAULT_CONFIG,
                                   progress=prog)
        html = render_trend_html(points, branch.title,
                                 g.get("name") or gid)
        (self.reports_dir / f"{gid}.html").write_text(html, encoding="utf-8")
        try:
            (self.reports_dir / f"{gid}.pdf").write_bytes(
                render_html_to_pdf(html))
        except Exception as pe:                  # PDF не критичен
            self._gstage(gid, f"готово; PDF не собран: {pe}")
        with self.lock:
            g2 = self.groups.get(gid)
            g2.update(status="done", progress=100,
                      took_s=round(time.monotonic() - t0, 1),
                      stage=f"готово: {len(points)} файлов за {took:.0f} c",
                      error="")
            self._persist_group(g2)

    def _run_diff(self, gid: str) -> None:
        with self.lock:
            g = self.groups.get(gid)
            ga = self.groups.get(g.get("a"))
            gb = self.groups.get(g.get("b"))
        branch = get_branch(ga.get("branch", DEFAULT_BRANCH))

        def prog(msg, pct=None, _gid=gid):
            with self.lock:
                cancelled = bool(self.groups.get(_gid, {}).get("cancel"))
            if cancelled:
                raise AnalysisCancelled()
            self._gstage(_gid, msg, pct)

        pa, ta = build_trend([Path(x) for x in ga.get("paths", [])],
                             branch, DEFAULT_CONFIG, progress=prog)
        pb, tb = build_trend([Path(x) for x in gb.get("paths", [])],
                             branch, DEFAULT_CONFIG, progress=prog)
        html = render_diff_html(pa, pb, ga["name"], gb["name"], branch.title)
        (self.reports_dir / f"{gid}.html").write_text(html, encoding="utf-8")
        try:
            (self.reports_dir / f"{gid}.pdf").write_bytes(
                render_html_to_pdf(html))
        except Exception as pe:
            self._gstage(gid, f"готово; PDF не собран: {pe}")
        with self.lock:
            g2 = self.groups.get(gid)
            g2.update(status="done", progress=100,
                      took_s=round(ta + tb, 1),
                      stage=f"готово ({len(pa)}+{len(pb)} файлов)",
                      error="")
            self._persist_group(g2)

    def _worker(self) -> None:
        while True:
            kind, fid = self.jobs.get()
            if kind == "series":
                self._guarded(self._run_series, fid)
                continue
            if kind == "diff":
                self._guarded(self._run_diff, fid)
                continue
            e = self._file_job(fid)
            if not e:
                continue

    def _guarded(self, fn, gid: str) -> None:
        try:
            fn(gid)
        except AnalysisCancelled:
            with self.lock:
                g = self.groups.get(gid)
                if g:
                    g.update(status="cancelled", stage="анализ отменён")
                    self._persist_group(g)
        except Exception as ex:                  # noqa: BLE001 — статус в UI
            with self.lock:
                g = self.groups.get(gid)
                if g:
                    g.update(status="error", error=str(ex))
                    self._persist_group(g)

    def _file_job(self, fid: str):
        """Обработка одного файла; вернуть None, если задание отброшено."""
        with self.lock:
            e = self.entries.get(fid)
        if not e:
            return None
        with self.lock:
            if e.get("cancel"):
                # отменено, пока лежало в очереди
                e["status"] = "cancelled"
                e["stage"] = "анализ отменён"
                return None
            e["status"] = "running"
        branch = get_branch(e.get("branch", DEFAULT_BRANCH))
        t0 = time.monotonic()

        def progress(m: str, pct: int | None = None, _fid=fid) -> None:
            with self.lock:
                cancelled = bool(self.entries.get(_fid, {}).get("cancel"))
            if cancelled:
                raise AnalysisCancelled()
            self._stage(_fid, m, pct)

        try:
            # кэш по содержимому: идентичный дамп с готовым отчётом
            # той же ветки — просто переиспользуем результат
            progress("  контрольная сумма файла…")
            sha = self._sha256_file(Path(e["path"]))
            with self.lock:
                e["sha256"] = sha
            cached = self._find_cached(fid, sha, branch.name)
            if cached is not None:
                for ext in ("html", "pdf"):
                    src = self.reports_dir / f"{cached['id']}.{ext}"
                    dst = self.reports_dir / f"{fid}.{ext}"
                    if src.is_file():
                        shutil.copyfile(src, dst)
                took = round(time.monotonic() - t0, 1)
                with self.lock:
                    e["captured"] = cached.get("captured", "")
                    e["status"] = "done"
                    e["progress"] = 100
                    e["took_s"] = took
                    e["stage"] = (f"готово за {took:g} с "
                                  "(отчёт из кэша: идентичный файл "
                                  "уже анализировался)")
                    e["error"] = ""
                    self._persist(e)
                return e
            result = branch.analyze(
                Path(e["path"]), DEFAULT_CONFIG,
                progress=progress,
                tshark_bin=self.tshark_bin)
            # момент снятия дампа — для имени файлов экспорта
            e["captured"] = (
                datetime.fromtimestamp(result.capture_start_ts)
                .strftime("%Y-%m-%d_%H-%M-%S")
                if result.capture_start_ts else "")
            (self.reports_dir / f"{fid}.html").write_text(
                render_document(result), encoding="utf-8")
            pdf_err = ""
            try:
                (self.reports_dir / f"{fid}.pdf").write_bytes(
                    render_pdf_bytes(result))
            except Exception as pe:              # PDF не критичен
                pdf_err = f"PDF не собран: {pe}"
            took = round(time.monotonic() - t0, 1)
            with self.lock:
                e["status"] = "done"
                e["progress"] = 100
                e["took_s"] = took
                e["stage"] = f"готово за {took:g} с" + \
                    (f" ({pdf_err})" if pdf_err else "")
                e["error"] = ""
                self._persist(e)
        except AnalysisCancelled:
            with self.lock:
                e["status"] = "cancelled"
                e["took_s"] = round(time.monotonic() - t0, 1)
                e["stage"] = "анализ отменён"
                self._persist(e)
        except Exception as ex:                  # noqa: BLE001 — статус в UI
            with self.lock:
                e["status"] = "error"
                e["took_s"] = round(time.monotonic() - t0, 1)
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
                # лимит проверяем и на финальном куске: маленький файл
                # может целиком уместиться в один чанк чтения
                if total > MAX_UPLOAD_BYTES:
                    gb = MAX_UPLOAD_BYTES >> 30
                    raise ValueError(
                        f"файл слишком большой (лимит {gb} ГБ)")
                break
            if len(buf) > keep:
                out.write(buf[:-keep])
                total += len(buf) - keep
                buf = buf[-keep:]
            tail = buf
            if total > MAX_UPLOAD_BYTES:
                gb = MAX_UPLOAD_BYTES >> 30
                raise ValueError(f"файл слишком большой (лимит {gb} ГБ)")
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


def make_handler(state: AppState, token: str | None = None
                 ) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "pcap-analyzer-web"
        protocol_version = "HTTP/1.1"       # keep-alive: UI опрашивает статус каждые ~1,5 с

        def log_message(self, fmt, *args):       # тише в консоли
            pass

        def _authorized(self) -> bool:
            """Проверка токена (если задан): ?token= или X-Auth-Token."""
            if not token:
                return True
            tb = token.encode("utf-8")
            qs = parse_qs(urlparse(self.path).query).get("token", [""])[0]
            if qs and secrets.compare_digest(qs.encode("utf-8"), tb):
                return True
            hdr = self.headers.get("X-Auth-Token", "").encode("utf-8")
            return bool(hdr) and secrets.compare_digest(hdr, tb)

        def _deny(self):
            body = json.dumps(
                {"error": "требуется токен доступа (?token= или "
                          "заголовок X-Auth-Token)"},
                ensure_ascii=False).encode("utf-8")
            self.send_response(401)
            self.send_header("Content-Type", _CT[".json"])
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # -- ответы ----------------------------------------------------------
        def _content_length(self) -> int:
            """Разобрать Content-Length; -1 — отсутствует/некорректное значение."""
            raw = self.headers.get("Content-Length")
            if raw is None or not raw.strip():
                return 0
            try:
                value = int(raw.strip())
            except ValueError:
                return -1
            return value if value >= 0 else -1

        def _json(self, obj, code: int = 200):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", _CT[".json"])
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _file(self, path: Path, ctype: str, download: str | None = None):
            """Отдать файл поточно: отчёты бывают по десяткам мегабайт."""
            size = path.stat().st_size
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(size))
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
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            with open(path, "rb") as f:
                shutil.copyfileobj(f, self.wfile)

        def _target_exists(self, fid: str) -> bool:
            """Файл или группа (серия/дифф) с таким идентификатором."""
            with state.lock:
                return fid in state.entries or fid in state.groups

        def _entry_or_404(self, fid: str):
            if not _ID_RE.match(fid):
                self._json({"error": "некорректный идентификатор"}, 400)
                return None
            e = state.get(fid)
            if not e:
                self._json({"error": "файл не найден"}, 404)
            return e

        def _view_target(self, fid: str):
            """Проверка id для /view и /export (файлы и группы)."""
            if not _ID_RE.match(fid):
                self._json({"error": "некорректный идентификатор"}, 400)
                return False
            if not self._target_exists(fid):
                self._json({"error": "файл не найден"}, 404)
                return False
            return True

        # -- GET -------------------------------------------------------------
        def do_GET(self):                        # noqa: N802 (стандарт API)
            u = urlparse(self.path)
            path = u.path
            if path not in ("/", "/index.html") and not self._authorized():
                self._deny()
                return
            if path in ("/", "/index.html"):
                body = page.PAGE.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", _CT[".html"])
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/favicon.ico":
                self.send_response(204)
                self.send_header("Content-Length", "0")
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
            m = re.fullmatch(r"/api/groups/([A-Za-z0-9_-]+)", path)
            if m:
                with state.lock:
                    g = state.groups.get(m.group(1))
                    if not g:
                        self._json({"error": "серия не найдена"}, 404)
                        return
                    self._json(state.group_public(g))
                return
            m = re.fullmatch(r"/api/status/([A-Za-z0-9_-]+)", path)
            if m:
                e = self._entry_or_404(m.group(1))
                if e:
                    self._json(state.public(e))
                return
            m = re.fullmatch(r"/view/([A-Za-z0-9_-]+)", path)
            if m:
                if not self._view_target(m.group(1)):
                    return
                rep = state.reports_dir / f"{m.group(1)}.html"
                if rep.is_file():
                    self._file(rep, _CT[".html"])
                else:
                    self._json({"error": "отчёт ещё не готов"}, 404)
                return
            m = re.fullmatch(r"/export/([A-Za-z0-9_-]+)", path)
            if m:
                if not self._view_target(m.group(1)):
                    return
                fmt = (parse_qs(u.query).get("fmt") or ["html"])[0]
                ext = {"html": "html", "pdf": "pdf"}.get(fmt)
                if ext is None:
                    self._json({"error": "формат должен быть html|pdf"}, 400)
                    return
                rep = state.reports_dir / f"{m.group(1)}.{ext}"
                if not rep.is_file():
                    self._json({"error": "отчёт в этом формате не готов"}, 404)
                    return
                with state.lock:
                    tgt = state.entries.get(m.group(1)) \
                        or state.groups.get(m.group(1))
                src_name = tgt["name"] if tgt else m.group(1)
                captured = tgt.get("captured", "") if tgt else ""
                base = re.sub(r"[^A-Za-z0-9._-]+", "_",
                              Path(src_name).stem or "report")
                ts_part = f"_{captured}" if captured else ""
                self._file(rep, _CT[f".{ext}"],
                           download=f"отчет_{base}{ts_part}.{ext}")
                return
            self._json({"error": "нет такого маршрута"}, 404)

        # -- POST --------------------------------------------------------------
        def do_POST(self):                       # noqa: N802
            if not self._authorized():
                self._deny()
                return
            u = urlparse(self.path)
            if u.path == "/api/upload":
                self._handle_upload()
                return
            m = re.fullmatch(r"/api/files/([A-Za-z0-9_-]+)/analyze", u.path)
            if m:
                e = self._entry_or_404(m.group(1))
                if not e:
                    return
                length = self._content_length()
                if length < 0:
                    self._json({"error": "некорректный Content-Length"}, 400)
                    return
                if length > (64 << 10):          # JSON с именем ветки — байты
                    self._json({"error": "тело запроса слишком большое"}, 413)
                    return
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
            m = re.fullmatch(r"/api/series", u.path)
            if m:
                length = self._content_length()
                if length < 0 or length > (64 << 10):
                    self._json({"error": "некорректное тело запроса"}, 400)
                    return
                raw = self.rfile.read(length) if length else b""
                try:
                    body = json.loads(raw.decode("utf-8"))
                    fids = [str(x) for x in body.get("fids", [])]
                    branch = body.get("branch", DEFAULT_BRANCH)
                except (ValueError, UnicodeDecodeError):
                    self._json({"error": "ожидается JSON"}, 400)
                    return
                if branch not in BRANCHES:
                    self._json({"error": "неизвестная ветка анализа"}, 400)
                    return
                try:
                    g = state.create_series(fids, branch)
                except ValueError as ve:
                    self._json({"error": str(ve)}, 400)
                    return
                self._json(state.group_public(g), 201)
                return
            m = re.fullmatch(r"/api/diff", u.path)
            if m:
                length = self._content_length()
                if length < 0 or length > (64 << 10):
                    self._json({"error": "некорректное тело запроса"}, 400)
                    return
                raw = self.rfile.read(length) if length else b""
                try:
                    body = json.loads(raw.decode("utf-8"))
                    gid_a, gid_b = str(body.get("a", "")), str(body.get("b", ""))
                except (ValueError, UnicodeDecodeError):
                    self._json({"error": "ожидается JSON"}, 400)
                    return
                if not (_ID_RE.match(gid_a) and _ID_RE.match(gid_b)):
                    self._json({"error": "некорректный идентификатор серии"}, 400)
                    return
                try:
                    g = state.create_diff(gid_a, gid_b)
                except ValueError as ve:
                    self._json({"error": str(ve)}, 400)
                    return
                self._json(state.group_public(g), 201)
                return
            m = re.fullmatch(r"/api/groups/([A-Za-z0-9_-]+)/cancel", u.path)
            if m:
                if not state.request_cancel_group(m.group(1)):
                    self._json({"error": "задание не запущено"}, 409)
                    return
                with state.lock:
                    g = state.groups.get(m.group(1))
                    self._json(state.group_public(g) if g else {"ok": True})
                return
            m = re.fullmatch(r"/api/files/([A-Za-z0-9_-]+)/cancel", u.path)
            if m:
                e = self._entry_or_404(m.group(1))
                if not e:
                    return
                if not state.request_cancel(e["id"]):
                    self._json({"error": "анализ не запущен"}, 409)
                    return
                self._json(state.public(state.get(e["id"])))
                return
            self._json({"error": "нет такого маршрута"}, 404)

        def _handle_upload(self):
            ctype = self.headers.get("Content-Type", "")
            m = re.search(r'boundary="?([^";]+)"?', ctype)
            if "multipart/form-data" not in ctype or not m:
                self._json(
                    {"error": "ожидается multipart/form-data"}, 400)
                return
            length = self._content_length()
            if length < 0:
                self._json({"error": "некорректный Content-Length"}, 400)
                return
            if length > MAX_UPLOAD_BYTES + (1 << 20):
                gb = MAX_UPLOAD_BYTES >> 30
                self._json(
                    {"error": f"файл слишком большой (лимит {gb} ГБ)"}, 413)
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
            if not self._authorized():
                self._deny()
                return
            path = urlparse(self.path).path
            mg = re.fullmatch(r"/api/groups/([A-Za-z0-9_-]+)", path)
            if mg:
                with state.lock:
                    g = state.groups.get(mg.group(1))
                if not g:
                    self._json({"error": "серия не найдена"}, 404)
                    return
                state.delete_group(mg.group(1))
                self._json({"ok": True})
                return
            m = re.fullmatch(r"/api/files/([A-Za-z0-9_-]+)", path)
            if not m:
                self._json({"error": "нет такого маршрута"}, 404)
                return
            e = self._entry_or_404(m.group(1))
            if not e:
                return
            if not e:
                self._json({"error": "файл не найден"}, 404)
                return
            if e["kind"] == "sample":
                self._json({"error": "образцы удалять нельзя"}, 403)
                return
            state.delete(e["id"])
            self._json({"ok": True})

    return Handler


def run_server(host: str, port: int, data_dir: Path,
               samples_dir: Path | None, tshark_bin: str | None,
               token: str | None = None) -> int:
    state = AppState(data_dir, samples_dir, tshark_bin)
    httpd = ThreadingHTTPServer((host, port), make_handler(state, token))
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
