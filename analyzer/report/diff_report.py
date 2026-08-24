"""Дифф-отчёт: сравнение двух серий дампов («до» и «после»).

Каждая серия обрабатывается трендовым механизмом (analyzer/trend.py),
затем сравниваются агрегаты метрик (среднее и размах по файлам) и
множества сработавших правил: что исчезло, что появилось, что стабильно.
"""

from __future__ import annotations

import datetime
from html import escape

from .. import __version__
from ..branches.base import SEVERITY_ORDER
from ..branches.base import display_tz as _display_tz
from .html_report import _CSS
from ..report.trend_report import METRIC_TITLES, TrendPoint, _psize

#: метрики, для которых уменьшение — улучшение
GOOD_WHEN_LOWER = {
    "no_resp_pct", "unans_pct", "exc_pct", "err_pct",
    "rtt_med_ms", "rtt_p95_ms", "syn", "arp_per_min",
    "retrans_pct", "silent_streams", "noise_frames",
}

_EXTRA_CSS = """
.delta { padding:1px 7px; border-radius:4px; font-weight:600;
         font-size:12px; white-space:nowrap; }
.delta.good { background:#dcfce7; color:#166534; }
.delta.bad  { background:#fee2e2; color:#991b1b; }
.delta.flat { background:#f1f5f9; color:#475569; }
.chip { display:inline-block; padding:1px 8px; border-radius:999px;
        font-size:11.5px; font-weight:600; }
.chip.gone    { background:#dcfce7; color:#166534; }
.chip.new     { background:#fee2e2; color:#991b1b; }
.chip.both    { background:#fef3c7; color:#92400e; }
"""


def _agg(points: list[TrendPoint], key: str) -> tuple[float, float, float]:
    vals = [pt.metrics.get(key, 0.0) for pt in points] or [0.0]
    return sum(vals) / len(vals), min(vals), max(vals)


def _fmt_range(mean: float, lo: float, hi: float) -> str:
    return f"{mean:.1f} <span class='note'>({lo:.1f}…{hi:.1f})</span>"


def _label(ts: float | None) -> str:
    if ts is None:
        return "?"
    return datetime.datetime.fromtimestamp(
        ts, tz=datetime.timezone.utc).astimezone(_display_tz()).strftime("%H:%M")


def _period(points: list[TrendPoint]) -> str:
    starts = [pt.start_ts for pt in points if pt.start_ts is not None]
    return f"{_label(min(starts))}&ndash;{_label(max(starts))}" if starts \
        else "&mdash;"


def render_diff_html(points_a: list[TrendPoint], points_b: list[TrendPoint],
                     label_a: str, label_b: str, branch_title: str
                     ) -> str:
    """Собрать автономный HTML дифф-отчёта."""
    generated = datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")

    # ---- сводка серий -------------------------------------------------------
    def series_card(tag: str, title: str, pts: list[TrendPoint],
                    mask: str) -> str:
        size = sum(_psize(pt.path) for pt in pts)
        rows = [[f"<strong>{i}</strong>", _label(pt.start_ts),
                 f'<code class="inline">{escape(pt.path.name)}</code>',
                 f'<span class="num">{pt.took_s:.0f}</span>']
                for i, pt in enumerate(pts, 1)]
        return (
            f'<section class="card" id="{tag}"><h2>{title}</h2>'
            f"<p>Маска <code class=\"inline\">{escape(mask)}</code> · "
            f"файлов: <strong>{len(pts)}</strong> · период "
            f"{_period(pts)} · объём {size >> 20} МБ</p>"
            + _table(["№", "Старт", "Файл", "Анализ, с"], rows) + "</section>")

    # ---- ΔKPI -----------------------------------------------------------------
    keys: list[str] = []
    for src in (points_a, points_b):
        for pt in src:
            for k in pt.metrics:
                if k not in keys:
                    keys.append(k)
    kpi_rows = []
    for k in keys:
        ma, la, ha = _agg(points_a, k)
        mb, lb, hb = _agg(points_b, k)
        title = METRIC_TITLES.get(k, k)
        delta = mb - ma
        if abs(delta) < 1e-9:
            chip = "<span class='delta flat'>без изменений</span>"
        elif k in GOOD_WHEN_LOWER:
            better = delta < 0
            chip = (f"<span class='delta {'good' if better else 'bad'}'>"
                    f"{'лучше' if better else 'хуже'} на "
                    f"{abs(delta):.1f}</span>")
        else:
            chip = (f"<span class='delta flat'>{delta:+.1f}</span>")
        rel = (f"{100.0 * delta / ma:+.0f}%" if abs(ma) > 1e-9
               else "&mdash;")
        kpi_rows.append([
            title,
            _fmt_range(ma, la, ha),
            _fmt_range(mb, lb, hb),
            f"{delta:+.1f}",
            rel,
            chip,
        ])
    kpi_html = (
        '<section class="card" id="kpi"><h2>Метрики: до и после</h2>'
        "<p>Среднее по файлам серии, в скобках — размах (min…max).</p>"
        + _table(["Метрика", "До", "После", "Δ абс.", "Δ %", "Оценка"],
                 kpi_rows)
        + '<p class="note">«Лучше/хуже» оценивается по смыслу метрики: '
          'для долей ошибок, времени отклика, SYN и служебного шума '
          'уменьшение — улучшение; объёмные счётчики (запросы, кадры) '
          'нейтральны.</p></section>')

    # ---- правила ------------------------------------------------------------
    frac_a = _rule_fractions(points_a)
    frac_b = _rule_fractions(points_b)
    info: dict[str, tuple[str, str]] = {}
    for src in (points_a, points_b):
        for pt in src:
            for rid, st in pt.rule_info.items():
                info.setdefault(rid, st)
    rule_rows = []
    for rid, (sev, title) in sorted(
            info.items(),
            key=lambda kv: (SEVERITY_ORDER.get(kv[1][0], 9), kv[0])):
        fa = frac_a.get(rid, 0.0)
        fb = frac_b.get(rid, 0.0)
        if fa == 0 and fb == 0:
            continue
        if fb == 0:
            chip = "<span class='chip gone'>исчез</span>"
        elif fa == 0:
            chip = "<span class='chip new'>появился</span>"
        else:
            chip = "<span class='chip both'>в обоих периодах</span>"
        rule_rows.append([
            f'<span title="{escape(rid)}">{_sev_dot(sev)} '
            f'{escape(title)}</span>',
            f"{fa * len(points_a):.0f}/{len(points_a)}",
            f"{fb * len(points_b):.0f}/{len(points_b)}",
            chip,
        ])
    rules_html = (
        '<section class="card" id="rules"><h2>Правила: до и после</h2>'
        + (_table(["Правило", "Срабатывал (до)", "(после)", "Статус"],
                  rule_rows) if rule_rows
           else "<p>Правила не срабатывали ни в одном периоде.</p>")
        + "</section>")

    total_bytes = (sum(_psize(pt.path) for pt in points_a + points_b))
    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>pcap-analyzer — Сравнение периодов: {branch_title}</title>
<style>{_CSS}{_EXTRA_CSS}</style>
</head>
<body>
<div class="wrap">

<header class="report">
  <h1>Сравнение периодов &mdash; {branch_title}</h1>
  <div class="sub">
    До: <code class="inline">{escape(label_a)}</code>
    &nbsp;&middot;&nbsp; После: <code class="inline">{escape(label_b)}</code>
    &nbsp;&middot;&nbsp; Файлов: {len(points_a)} + {len(points_b)}
    &nbsp;&middot;&nbsp; Объём: {total_bytes >> 20} МБ
    &nbsp;&middot;&nbsp; Отчёт сформирован: {generated}
    &nbsp;&middot;&nbsp; pcap-analyzer v{__version__}
  </div>
</header>

<section class="card" id="verdict"><h2>Вывод</h2>{_verdict(kpi_rows, rule_rows)}</section>

{series_card("before", "Период «до»", points_a, label_a)}
{kpi_html}
{series_card("after", "Период «после»", points_b, label_b)}
{rules_html}

<footer class="report">
  Дифф-отчёт статический и полностью автономный. Каждая точка — результат
  полного анализа одного файла соответствующей серии.
</footer>

</div>
</body>
</html>
"""


def _verdict(kpi_rows: list[list[str]], rule_rows: list[list[str]]) -> str:
    """Короткая текстовая сводка: сколько улучшилось/ухудшилось, правила."""
    good = sum(1 for r in kpi_rows if "лучше" in r[-1])
    bad = sum(1 for r in kpi_rows if "хуже" in r[-1])
    gone = sum(1 for r in rule_rows if "исчез" in r[-1])
    new = sum(1 for r in rule_rows if "появился" in r[-1])
    parts = []
    if good:
        parts.append(f"<strong>{good}</strong> метрик улучшилось")
    if bad:
        parts.append(f"<strong>{bad}</strong> ухудшилось")
    if gone:
        parts.append(f"<strong>{gone}</strong> правил перестало срабатывать")
    if new:
        parts.append(f"<strong>{new}</strong> появилось новых")
    if not parts:
        return "<p>Заметных изменений между периодами нет.</p>"
    return "<p>" + ", ".join(parts) + ".</p>"


def _rule_fractions(points: list[TrendPoint]) -> dict[str, float]:
    """Доля файлов серии, где правило сработало."""
    if not points:
        return {}
    cnt: dict[str, int] = {}
    for pt in points:
        for rid in pt.rec_ids:
            cnt[rid] = cnt.get(rid, 0) + 1
    return {rid: n / len(points) for rid, n in cnt.items()}


def _sev_dot(sev: str) -> str:
    cls = {"critical": "sev-critical", "warning": "sev-warning"}.get(
        sev, "sev-info")
    return f'<span class="badge {cls}">&nbsp;</span>'


def _table(headers: list[str], rows: list[list[str]], cls: str = "") -> str:
    head = "".join(f"<th>{h}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>"
                   for row in rows)
    return (
        '<div class="table-scroll">'
        f'<table class="data-table {cls}">'
        f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>")
