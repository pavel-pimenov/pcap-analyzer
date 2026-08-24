"""Командная строка pcap-analyzer."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from . import __version__
from .branches import DEFAULT_BRANCH, BRANCHES, get_branch
from .config import DEFAULT_CONFIG
from .report import render_document
from .tshark_runner import TsharkError


def _progress(msg: str, pct: int | None = None) -> None:
    print(msg, file=sys.stderr, flush=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="analyzer",
        description="Анализ сетевых дампов (pcap) с HTML/PDF-отчётом. "
                    "Разбор выполняется через tshark.",
    )
    parser.add_argument("--version", action="version",
                        version=f"pcap-analyzer {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # --- analyze -------------------------------------------------------------
    p_an = sub.add_parser("analyze", help="проанализировать pcap-файл и собрать отчёт")
    p_an.add_argument("pcap", help="путь к pcap/pcapng файлу")
    p_an.add_argument("-o", "--output", default="report.html",
                      help="путь к итоговому файлу; расширение подставляется "
                           "по формату (по умолчанию report.html)")
    p_an.add_argument("-f", "--format", choices=("html", "pdf", "both"),
                      default="html",
                      help="формат отчёта (по умолчанию html); для pdf нужен "
                           "weasyprint (см. requirements.txt)")
    p_an.add_argument("-b", "--branch", default=DEFAULT_BRANCH,
                      choices=sorted(BRANCHES),
                      help="ветка анализа (по умолчанию: %(default)s)")
    p_an.add_argument("--tshark-bin", default=None,
                      help="путь к tshark (иначе TSHARK_BIN или PATH)")

    # --- branches --------------------------------------------------------------
    sub.add_parser("branches", help="список доступных веток анализа")

    # --- serve -----------------------------------------------------------------
    p_sv = sub.add_parser(
        "serve",
        help="веб-интерфейс: загрузка pcap-файлов, анализ, просмотр и экспорт")
    p_sv.add_argument("--host", default="127.0.0.1",
                      help="адрес прослушивания (по умолчанию 127.0.0.1)")
    p_sv.add_argument("--port", type=int, default=8000,
                      help="порт (по умолчанию 8000)")
    p_sv.add_argument("--data-dir", default="webdata",
                      help="каталог для загрузок и отчётов (по умолчанию webdata)")
    p_sv.add_argument("--samples-dir", default=None,
                      help="каталог с образцами pcap (предлагаются в списке, "
                           "только чтение)")
    p_sv.add_argument("--tshark-bin", default=None,
                      help="путь к tshark (иначе TSHARK_BIN или PATH)")
    return parser


def _write_reports(result, fmt: str, out_path: Path) -> list[Path]:
    """Записать отчёт(ы) в выбранном формате; вернуть список файлов."""
    from .report import render_pdf_bytes

    stem = out_path.with_suffix("")
    written: list[Path] = []
    if fmt in ("html", "both"):
        p = stem.with_suffix(".html")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(render_document(result), encoding="utf-8")
        written.append(p)
    if fmt in ("pdf", "both"):
        p = stem.with_suffix(".pdf")
        try:
            data = render_pdf_bytes(result)
        except RuntimeError as e:
            raise SystemExit(f"Ошибка: {e}")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        written.append(p)
    return written


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "branches":
        print("Доступные ветки анализа:")
        for key in sorted(BRANCHES):
            br = BRANCHES[key]()
            print(f"  {key:10s} — {br.title}: {br.description}")
        return 0

    if args.command == "analyze":
        pcap_path = Path(args.pcap)
        if not pcap_path.is_file():
            print(f"Ошибка: файл не найден: {pcap_path}", file=sys.stderr)
            return 2

        branch = get_branch(args.branch)
        t0 = time.monotonic()
        _progress(f"[pcap-analyzer] Ветка: {branch.title}")
        try:
            result = branch.analyze(
                pcap_path,
                cfg=DEFAULT_CONFIG,
                progress=_progress,
                tshark_bin=args.tshark_bin,
            )
        except TsharkError as e:
            print(f"Ошибка: {e}", file=sys.stderr)
            return 1
        try:
            written = _write_reports(result, args.format, Path(args.output))
        except OSError as e:
            print(f"Ошибка записи отчёта: {e}", file=sys.stderr)
            return 1
        elapsed = time.monotonic() - t0
        rec_counts: dict[str, int] = {}
        for r in result.recommendations:
            rec_counts[r.severity] = rec_counts.get(r.severity, 0) + 1
        _progress(
            f"[pcap-analyzer] Готово за {elapsed:.1f} c → "
            + ", ".join(str(p) for p in written)
            + f" (рекомендаций: {len(result.recommendations)}"
            + (": " + ", ".join(f"{k}={v}" for k, v in sorted(rec_counts.items()))
               if rec_counts else "")
            + ")"
        )
        print("\n".join(str(p) for p in written))
        return 0

    if args.command == "serve":
        from .webapp.server import run_server

        return run_server(
            host=args.host,
            port=args.port,
            data_dir=Path(args.data_dir),
            samples_dir=Path(args.samples_dir) if args.samples_dir else None,
            tshark_bin=args.tshark_bin,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
