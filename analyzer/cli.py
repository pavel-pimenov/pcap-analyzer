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
    p_an.add_argument("--config", default=None,
                      help="TOML-файл с порогами правил "
                           "(ключи как в analyzer/config.py)")
    p_an.add_argument("--tz", type=float, default=None, metavar="ЧАСЫ",
                      help="зона показа времени в отчёте, часов от UTC "
                           "(например 3 или -5.5); по умолчанию — локальная")

    # --- branches --------------------------------------------------------------
    sub.add_parser("branches", help="список доступных веток анализа")

    # --- trend -----------------------------------------------------------------
    p_tr = sub.add_parser(
        "trend",
        help="тренды по серии дампов (динамика метрик и правил)")
    p_tr.add_argument("pattern",
                      help="маска файлов серии, например "
                           "\"pcap-sample/plc_cgn_*.pcap\"")
    p_tr.add_argument("-b", "--branch", default=DEFAULT_BRANCH,
                      choices=sorted(BRANCHES),
                      help="ветка анализа (по умолчанию: %(default)s)")
    p_tr.add_argument("-o", "--output", default="trend.html",
                      help="путь к итоговому HTML (по умолчанию trend.html)")
    p_tr.add_argument("--tshark-bin", default=None,
                      help="путь к tshark (иначе TSHARK_BIN или PATH)")
    p_tr.add_argument("--jobs", type=int, default=1, metavar="N",
                      help="параллельно анализировать N файлов серии "
                           "(по умолчанию 1)")
    p_tr.add_argument("--config", default=None,
                      help="TOML-файл с порогами правил "
                           "(ключи как в analyzer/config.py)")
    p_tr.add_argument("--tz", type=float, default=None, metavar="ЧАСЫ",
                      help="зона показа времени в отчёте, часов от UTC "
                           "(например 3 или -5.5); по умолчанию — локальная")

    # --- overlap ----------------------------------------------------------------
    p_ov = sub.add_parser(
        "overlap",
        help="сравнение карт опроса двух дампов: кто какие регистры читает")
    p_ov.add_argument("before", help="первый pcap (сторона А)")
    p_ov.add_argument("after", help="второй pcap (сторона Б)")
    p_ov.add_argument("-o", "--output", default="overlap.html",
                      help="путь к итоговому HTML (по умолчанию overlap.html)")
    p_ov.add_argument("--tshark-bin", default=None,
                      help="путь к tshark (иначе TSHARK_BIN или PATH)")
    p_ov.add_argument("--config", default=None,
                      help="TOML-файл с порогами правил")
    p_ov.add_argument("--tz", type=float, default=None, metavar="ЧАСЫ",
                      help="зона показа времени, часов от UTC")

    # --- diff -------------------------------------------------------------------
    p_df = sub.add_parser(
        "diff",
        help="сравнение двух серий дампов: до и после изменений")
    p_df.add_argument("before", help="маска серии «до»")
    p_df.add_argument("after", help="маска серии «после»")
    p_df.add_argument("-b", "--branch", default=DEFAULT_BRANCH,
                      choices=sorted(BRANCHES),
                      help="ветка анализа (по умолчанию: %(default)s)")
    p_df.add_argument("-o", "--output", default="diff.html",
                      help="путь к итоговому HTML (по умолчанию diff.html)")
    p_df.add_argument("--tshark-bin", default=None,
                      help="путь к tshark (иначе TSHARK_BIN или PATH)")
    p_df.add_argument("--jobs", type=int, default=1, metavar="N",
                      help="параллельно анализировать N файлов серии "
                           "(по умолчанию 1)")
    p_df.add_argument("--config", default=None,
                      help="TOML-файл с порогами правил "
                           "(ключи как в analyzer/config.py)")
    p_df.add_argument("--tz", type=float, default=None, metavar="ЧАСЫ",
                      help="зона показа времени в отчёте, часов от UTC "
                           "(например 3 или -5.5); по умолчанию — локальная")

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
    p_sv.add_argument("--config", default=None,
                      help="TOML-файл с порогами правил "
                           "(ключи как в analyzer/config.py)")
    p_sv.add_argument("--token", default=None,
                      help="требовать токен доступа: все маршруты, кроме "
                           "самой страницы, проверяют ?token= или заголовок "
                           "X-Auth-Token")
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


def _load_cfg(path: str | None):
    from .config import load_config
    if not path:
        return DEFAULT_CONFIG
    try:
        return load_config(Path(path))
    except (OSError, ValueError) as e:
        print(f"Ошибка конфигурации: {e}", file=sys.stderr)
        raise SystemExit(2)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = _load_cfg(getattr(args, "config", None))
    tz_val = getattr(args, "tz", None)
    if tz_val is None:
        tz_val = getattr(cfg, "display_tz_offset", None)
    from .branches.base import set_display_tz
    set_display_tz(tz_val)

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
                cfg=cfg,
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

    if args.command == "trend":
        from pathlib import Path as _Path

        from .trend import build_trend, expand_series

        files = expand_series(args.pattern)
        if not files:
            print(f"Ошибка: по маске не найдено файлов: {args.pattern}",
                  file=sys.stderr)
            return 2
        branch = get_branch(args.branch)
        try:
            points, took = build_trend(
                files, branch, cfg,
                progress=lambda m, pct=None: _progress(m),
                tshark_bin=args.tshark_bin,
                jobs=max(1, getattr(args, "jobs", 1)))
        except TsharkError as e:
            print(f"Ошибка: {e}", file=sys.stderr)
            return 1
        out = _Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        from .report import render_trend_html
        out.write_text(render_trend_html(points, branch.title, args.pattern),
                       encoding="utf-8")
        _progress(f"[pcap-analyzer] Серия из {len(points)} файлов обработана "
                  f"за {took:.0f} c → {out}")
        print(str(out))
        return 0

    if args.command == "diff":
        from pathlib import Path as _Path

        from .report import render_diff_html
        from .trend import build_trend, expand_series

        files_a = expand_series(args.before)
        files_b = expand_series(args.after)
        if not files_a or not files_b:
            print("Ошибка: маски должны указывать хотя бы на один файл "
                  f"(до: {len(files_a)}, после: {len(files_b)})",
                  file=sys.stderr)
            return 2
        branch = get_branch(args.branch)

        def prog(m, pct=None):
            _progress(m)

        _progress("Период «до»…")
        points_a, ta = build_trend(files_a, branch, cfg,
                                   progress=prog,
                                   tshark_bin=args.tshark_bin,
                                   jobs=max(1, args.jobs))
        _progress("Период «после»…")
        points_b, tb = build_trend(files_b, branch, cfg,
                                   progress=prog,
                                   tshark_bin=args.tshark_bin,
                                   jobs=max(1, args.jobs))
        out = _Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render_diff_html(points_a, points_b,
                                        args.before, args.after,
                                        branch.title), encoding="utf-8")
        _progress(f"[pcap-analyzer] Сравнение готово "
                  f"({len(points_a)}+{len(points_b)} файлов, "
                  f"{ta + tb:.0f} c) → {out}")
        print(str(out))
        return 0

    if args.command == "overlap":
        from .overlap import collect_side, render_overlap_html

        pa, pb = Path(args.before), Path(args.after)
        for x in (pa, pb):
            if not x.is_file():
                print(f"Ошибка: файл не найден: {x}", file=sys.stderr)
                return 2
        _progress("Сторона А: разбор карты чтений…")
        side_a = collect_side(pa, cfg, args.tshark_bin)
        _progress("Сторона Б: разбор карты чтений…")
        side_b = collect_side(pb, cfg, args.tshark_bin)
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render_overlap_html(side_a, side_b, cfg),
                       encoding="utf-8")
        _progress(f"[pcap-analyzer] Сравнение карт готово → {out}")
        print(str(out))
        return 0

    if args.command == "serve":
        from .webapp.server import run_server

        return run_server(
            host=args.host,
            port=args.port,
            data_dir=Path(args.data_dir),
            samples_dir=Path(args.samples_dir) if args.samples_dir else None,
            tshark_bin=args.tshark_bin,
            token=args.token,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
