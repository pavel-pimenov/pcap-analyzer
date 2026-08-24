"""Трендовый отчёт по серии файлов: динамика метрик и правил между дампами.

Каждая точка — результат обычного analyze() одного файла (метрики ветка
складывает в BranchResult.metrics). Рендер автономный, стили общие с
основным отчётом; PDF для трендов пока не строится.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from html import escape
from pathlib import Path

from .. import __version__
from ..branches.base import SEVERITY_ORDER, display_tz
from .html_report import _CSS

#: человекочитаемые названия метрик по ключам из BranchResult.metrics
METRIC_TITLES = {
    "reqs": "Запросов",
    "resps": "Ответов",
    "jobs": "Job-запросов",
    "acks": "Ack_Data",
    "no_resp_pct": "Запросов без ответа, %",
    "unans_pct": "Job без ответа, %",
    "exc_pct": "Исключений, %",
    "err_pct": "Ответов с ошибками, %",
    "rtt_med_ms": "Медиана отклика, мс",
    "rtt_p95_ms": "p95 отклика, мс",
    "syn": "SYN-подключений",
    "writes": "Операций записи",
    "conns": "Потоков к серверу",
    "clients": "Клиентов",
    "servers": "Серверов",
    "plcs": "PLC",
    "frames": "Всего кадров",
    "arp_per_min": "ARP-кадров в минуту",
    "retrans_pct": "Ретрансляций TCP, %",
    "tcp_services": "TCP-сервисов",
    "silent_streams": "«Молчащих» потоков",
    "noise_frames": "Служебных кадров",
}


@dataclass
class TrendPoint:
    """Один файл серии."""

    path: Path
    start_ts: float | None                 # начало захвата (epoch)
    metrics: dict[str, float] = field(default_factory=dict)
    rec_ids: set[str] = field(default_factory=set)
    # id правила -> (severity, title) — наполняется по мере обхода точек
    rule_info: dict[str, tuple[str, str]] = field(default_factory=dict)
    took_s: float = 0.0


def _label(ts: float | None) -> str:
    if ts is None:
        return "?"
    return datetime.datetime.fromtimestamp(
        ts, tz=datetime.timezone.utc).astimezone(display_tz()).strftime("%H:%M")


def _psize(p: Path) -> int:
    try:
        return p.stat().st_size
    except OSError:
        return 0


def render_trend_html(points: list[TrendPoint], branch_title: str,
                      pattern: str) -> str:
    """Собрать автономный HTML трендового отчёта."""
    generated = datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    n = len(points)
    total_bytes = sum(_psize(pt.path) for pt in points)
    t0 = min((p.start_ts for p in points if p.start_ts is not None),
             default=None)
    t1max = max((p.start_ts for p in points if p.start_ts is not None),
                default=None)

    # ---- сводная таблица файлов -------------------------------------------
    rows = []
    for i, pt in enumerate(points, 1):
        rows.append([
            f"<strong>{i}</strong>",
            _label(pt.start_ts),
            f'<code class="inline">{pt.path.name}</code>',
            f'<span class="num">{pt.took_s:.0f} c</span>',
            f'<span class="num">{len(pt.rec_ids)}</span>',
        ])
    files_html = (
        '<section class="card" id="files"><h2>Файлы серии</h2>'
        "<p>Точки рядов ниже соответствуют строкам этой таблицы.</p>"
        + _table(["№", "Старт захвата", "Файл", "Анализ, с", "Правил"], rows)
        + "</section>")

    # ---- графики метрик -----------------------------------------------------
    keys: list[str] = []
    for pt in points:
        for k in pt.metrics:
            if k not in keys:
                keys.append(k)
    charts = []
    for k in keys:
        vals = [pt.metrics.get(k, 0.0) for pt in points]
        if all(v == 0 for v in vals):
            continue
        labels = [_label(pt.start_ts) for pt in points]
        title = METRIC_TITLES.get(k, k)
        svg = _timeline_line(labels, vals)
        charts.append(
            f'<section class="card" id="m-{k}"><h2>{title}</h2>'
            f'<div class="chart-box">{svg}</div>'
            f"<p class=\"num note\">min {min(vals):.1f} · max "
            f"{max(vals):.1f} · последний {vals[-1]:.1f}</p></section>")
    charts_html = "".join(charts) or \
        '<section class="card"><p>Метрик не собрано.</p></section>'

    # ---- матрица правил ------------------------------------------------------
    rule_info: dict[str, tuple[str, str]] = {}
    for pt in points:
        for rid in pt.rec_ids:
            sev_title = pt.rule_info.get(rid)
            if sev_title and rid not in rule_info:
                rule_info[rid] = sev_title
    matrix_rows = []
    for rid, (sev, title) in sorted(
            rule_info.items(),
            key=lambda kv: (SEVERITY_ORDER.get(kv[1][0], 9), kv[0])):
        cells = [f'{_sev_dot(sev)} '
                 f'<span title="{escape(rid)}">'
                 f'{title.replace("|", "/")}</span>']
        fired_any = False
        for pt in points:
            hit = rid in pt.rec_ids
            fired_any = fired_any or hit
            cells.append("●" if hit else "·")
        if not fired_any:
            continue
        matrix_rows.append(cells)
    head_cells = ["Правило"] + [str(i + 1) for i in range(n)]
    matrix_html = ""
    if matrix_rows:
        matrix_html = (
            '<section class="card" id="rules"><h2>Сработавшие правила</h2>'
            "<p>Колонки — файлы из таблицы выше; ● правило сработало.</p>"
            + _table(head_cells, matrix_rows, cls="matrix")
            + "</section>")
    else:
        matrix_html = ('<section class="card" id="rules">'
                       "<p>Ни в одном файле рекомендации не сработали.</p>"
                       "</section>")

    period = (_label(t0) + " &ndash; " + _label(t1max)) if t0 else "&mdash;"
    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>pcap-analyzer — Тренды: {branch_title}</title>
<style>{_CSS}
table.data-table.matrix td {{ text-align:center; }}
table.data-table.matrix td:first-child {{ text-align:left; white-space:normal; }}
</style>
</head>
<body>
<div class="wrap">

<header class="report">
  <h1>Тренды по серии дампов &mdash; {branch_title}</h1>
  <div class="sub">
    Маска: <code class="inline">{pattern}</code>
    &nbsp;&middot;&nbsp; Файлов: <strong>{n}</strong>
    &nbsp;&middot;&nbsp; Период: {period}
    &nbsp;&middot;&nbsp; Суммарный объём: {total_bytes >> 20} МБ
    &nbsp;&middot;&nbsp; Отчёт сформирован: {generated}
    &nbsp;&middot;&nbsp; pcap-analyzer v{__version__}
  </div>
</header>

{files_html}
{charts_html}
{matrix_html}

<footer class="report">
  Трендовый отчёт статический и полностью автономный.
  Каждая точка — результат полного анализа одного файла серии.
</footer>

</div>
</body>
</html>
"""


def _sev_dot(sev: str) -> str:
    cls = {"critical": "sev-critical", "warning": "sev-warning"}.get(
        sev, "sev-info")
    return f'<span class="badge {cls}">&nbsp;</span>'


def _table(headers: list[str], rows: list[list[str]],
           cls: str = "") -> str:
    head = "".join(f"<th>{h}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>"
                   for row in rows)
    return (
        '<div class="table-scroll">'
        f'<table class="data-table {cls}">'
        f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>")


def _timeline_line(labels: list[str], values: list[float],
                   height: int = 200) -> str:
    """Линейный график с точками: значения по файлам серии."""
    width = 960
    pad_l, pad_r, pad_t, pad_b = 46, 14, 14, 40
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    n = len(values)
    max_val = max(abs(v) for v in values) or 1.0
    out = [f'<svg viewBox="0 0 {width} {height}" '
           'xmlns="http://www.w3.org/2000/svg" role="img" '
           'style="width:100%;height:auto;">'
           f'<rect x="0" y="0" width="{width}" height="{height}" fill="#fff"/>']
    # сетка + подписи Y
    for i in range(5):
        y = pad_t + plot_h * i / 4
        val = max_val * (4 - i) / 4
        out.append(f'<line x1="{pad_l}" y1="{y:.1f}" x2="{width - pad_r}" '
                   f'y2="{y:.1f}" stroke="#e5e7eb"/>')
        out.append(f'<text x="{pad_l - 6}" y="{y + 4:.1f}" font-size="11" '
                   f'fill="#6b7280" text-anchor="end">{val:.1f}</text>')
    if n:
        step = plot_w / max(n - 1, 1)
        pts = []
        for i, v in enumerate(values):
            x = pad_l + i * step
            y = pad_t + plot_h * (1 - v / max_val)
            pts.append(f"{x:.1f},{y:.1f}")
            out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.5" '
                       'fill="#2563eb"/>')
            out.append(f'<text x="{x:.1f}" y="{y - 8:.1f}" font-size="10" '
                       f'fill="#111827" text-anchor="middle">{v:.1f}</text>')
        out.append(f'<polyline points="{" ".join(pts)}" fill="none" '
                   'stroke="#2563eb" stroke-width="2"/>')
        # подписи X — каждые k точек
        lab_step = max(1, n // 12)
        for i in range(0, n, lab_step):
            x = pad_l + i * step
            out.append(f'<text x="{x:.1f}" y="{height - pad_b + 16}" '
                       'font-size="10.5" fill="#6b7280" text-anchor="middle">'
                       f'{labels[i]}</text>')
    out.append("</svg>")
    return "".join(out)
