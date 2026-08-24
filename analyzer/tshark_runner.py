"""Обёртка над tshark: поиск бинарника и потоковое извлечение полей."""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
from collections import deque
from typing import Iterable, Iterator, Sequence

# Разделители вывода tshark -T fields
FIELD_SEPARATOR = "|"
OCCURRENCE_SEPARATOR = ","


class TsharkError(RuntimeError):
    """Ошибка запуска/завершения tshark."""


def find_tshark(explicit: str | None = None) -> str:
    """Найти исполняемый файл tshark.

    Порядок: явный аргумент -> переменная окружения TSHARK_BIN -> PATH.
    """
    candidate = explicit or os.environ.get("TSHARK_BIN") or "tshark"
    path = shutil.which(candidate) or (candidate if os.path.isfile(candidate) else None)
    if not path:
        raise TsharkError(
            "tshark не найден. Установите Wireshark/tshark или задайте "
            "переменную TSHARK_BIN / флаг --tshark-bin."
        )
    return path


def stream_fields(
    tshark_bin: str,
    pcap_path: str,
    fields: Sequence[str],
    display_filter: str | None = None,
    extra_args: Iterable[str] = (),
) -> Iterator[dict[str, str]]:
    """Потоково отдавать строки разбора как dict[field] -> значение (или '').

    Используется `tshark -r <pcap> -Y <filter> -T fields -E header=y ...`.
    Вывод читается построчно, чтобы не держать весь результат в памяти.
    """
    cmd: list[str] = [
        tshark_bin,
        "-n",                       # не резолвить имена (быстрее и детерминированнее)
        "-r", pcap_path,
        "-T", "fields",
        "-E", f"separator={FIELD_SEPARATOR}",
        "-E", f"occurrence=a",
        "-E", f"aggregator={OCCURRENCE_SEPARATOR}",
        "-E", "quote=n",
        "-E", "header=y",
    ]
    if display_filter:
        cmd += ["-Y", display_filter]
    for f in fields:
        cmd += ["-e", f]
    cmd += list(extra_args)

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert proc.stdout is not None

    # stderr обязан сливаться непрерывно: если tshark завалит пайп stderr
    # предупреждениями (битые пакеты, экспериментальные диссекторы), он
    # заблокируется на записи и никогда не завершится. Читаем в фоновом
    # потоке через ДУБЛИКАТ дескриптора (свой файловый объект): закрытие
    # proc.stderr из основного потока не заденет читающий поток и не
    # устроит гонку на внутреннем замке BufferedReader. Для диагностики
    # хватает последних строк.
    err_tail: deque[str] = deque(maxlen=50)
    err_stream = os.fdopen(os.dup(proc.stderr.fileno()),
                           "r", encoding="utf-8", errors="replace")

    def _drain_stderr() -> None:
        try:
            for line in err_stream:
                err_tail.append(line)
        except (ValueError, OSError):
            pass                                # пайп закрыт при kill — штатно
        finally:
            try:
                err_stream.close()
            except OSError:
                pass

    err_thread = threading.Thread(target=_drain_stderr, daemon=True)
    err_thread.start()
    try:
        header_line = proc.stdout.readline()
        if not header_line:
            # Возможна ошибка запуска — проверим stderr
            _raise_from_process(proc, err_tail)
        columns = [c.strip() for c in header_line.rstrip("\n").split(FIELD_SEPARATOR)]
        for line in proc.stdout:
            line = line.rstrip("\n")
            if not line:
                continue
            values = line.split(FIELD_SEPARATOR)
            # Выравниваем длину на случай «хвостовых» пустых полей
            if len(values) < len(columns):
                values += [""] * (len(columns) - len(values))
            yield dict(zip(columns, values))
        proc.stdout.close()
        code = proc.wait()
        if code != 0:
            err = "".join(err_tail)
            raise TsharkError(f"tshark завершился с кодом {code}: {err.strip()[:2000]}")
    finally:
        if proc.poll() is None:
            proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        if proc.stdout is not None:
            proc.stdout.close()
        if proc.stderr is not None:
            proc.stderr.close()
        # после kill пайп достигает EOF, поток заканчивается сам; ждём
        # ограниченно. Если генератор закрывается при финализации
        # интерпретатора, join запрещён — глушим RuntimeError.
        if err_thread.is_alive():
            try:
                err_thread.join(timeout=2)
            except RuntimeError:
                pass


def run_list(tshark_bin: str, args: Sequence[str]) -> str:
    """Одноразовый запуск tshark с возвратом всего stdout (для -z статистик)."""
    result = subprocess.run(
        [tshark_bin, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        raise TsharkError(f"tshark {' '.join(args)}: {result.stderr.strip()[:2000]}")
    return result.stdout


def _raise_from_process(proc: subprocess.Popen, err_tail: deque) -> None:
    """Если tshark не выдал заголовок — завершить процесс и бросить ошибку."""
    code = proc.wait()
    err = "".join(err_tail)
    raise TsharkError(f"tshark не вернул данных (код {code}): {err.strip()[:2000]}")
