"""Сборка итогового автономного HTML-документа отчёта."""

from __future__ import annotations

import datetime
from typing import Iterable

from .. import __version__
from ..branches.base import BranchResult, Recommendation, SEVERITY_ORDER
from .components import (COPY_BTN, cmd_block, example_cmd, esc,
                         fmt_bytes, kpi_cards, severity_badge)

_CSS = """\
:root {
  --bg:#f3f4f6; --card:#ffffff; --text:#111827; --muted:#6b7280;
  --accent:#2563eb; --border:#e5e7eb;
  --sev-critical-bg:#fee2e2; --sev-critical-fg:#991b1b;
  --sev-warning-bg:#fef3c7;  --sev-warning-fg:#92400e;
  --sev-info-bg:#dbeafe;     --sev-info-fg:#1e40af;
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text);
       font-family:-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
       font-size:14.5px; line-height:1.55; }
.wrap { max-width:1120px; margin:0 auto; padding:24px 20px 60px; }
header.report { background:linear-gradient(135deg,#1e3a8a,#2563eb); color:#fff;
       border-radius:12px; padding:26px 30px; margin-bottom:22px; }
header.report h1 { margin:0 0 6px; font-size:24px; }
header.report .sub { opacity:.85; font-size:13px; }
nav.toc { background:var(--card); border:1px solid var(--border); border-radius:10px;
       padding:12px 18px; margin-bottom:22px; font-size:13.5px; }
nav.toc a { color:var(--accent); text-decoration:none; margin-right:16px; white-space:nowrap; }
nav.toc a:hover { text-decoration:underline; }
section.card { background:var(--card); border:1px solid var(--border); border-radius:10px;
       padding:20px 24px; margin-bottom:20px; }
section.card > h2 { margin:0 0 4px; font-size:18px; }
section.card > .lead { color:var(--muted); font-size:13px; margin:0 0 14px; }
.kpi-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
       gap:12px; margin:6px 0 2px; }
.kpi { background:#f8fafc; border:1px solid var(--border); border-radius:8px; padding:10px 12px; }
.kpi-value { font-size:20px; font-weight:700; }
.kpi-label { color:var(--muted); font-size:12px; margin-top:2px; }
.kpi-hint { color:#9ca3af; font-size:11px; }
table.data-table { border-collapse:collapse; width:100%; margin:10px 0 4px; font-size:13px; }
table.data-table th { background:#f8fafc; text-align:left; padding:7px 9px;
       border-bottom:2px solid var(--border); font-weight:600; white-space:nowrap; }
table.data-table td { padding:6px 9px; border-bottom:1px solid var(--border);
       vertical-align:top; }
table.data-table tr:hover td { background:#f9fafb; }
table.data-table td.num, table.data-table th.num { text-align:right;
       font-variant-numeric:tabular-nums; }
td.empty { color:var(--muted); text-align:center; padding:16px; }
table.data-table td.cell-hot { background:#fee2e2; }
.hot-legend { background:#fee2e2; padding:1px 6px; border-radius:4px; }
td span.srv, .srv-legend .srv { padding:1px 7px; border-radius:4px;
              font-weight:600; white-space:nowrap; }
.srv-legend { margin:10px 0 2px; font-size:13px; color:var(--muted); }
.srv-legend-title { margin-right:6px; }
.srv-legend .srv { margin-right:6px; display:inline-block; }
.legend span { margin-right:18px; font-size:12.5px; color:#475569;
               white-space:nowrap; }
.lg { display:inline-block; vertical-align:-2px; margin-right:5px; }
.lg-tick { width:2px; height:13px; background:#b91c1c; }
.lg-span { width:24px; height:9px; background:#ffe1de; border-radius:3px; }
.lg-grid { width:1px; height:13px; background:#cbd5e1; }
.table-scroll { overflow-x:auto; }
.chart-box { overflow-x:auto; }
.badge { display:inline-block; padding:2px 10px; border-radius:999px;
       font-size:11.5px; font-weight:600; }
.sev-critical { background:var(--sev-critical-bg); color:var(--sev-critical-fg); }
.sev-warning  { background:var(--sev-warning-bg);  color:var(--sev-warning-fg); }
.sev-info     { background:var(--sev-info-bg);     color:var(--sev-info-fg); }
.rec { border:1px solid var(--border); border-left-width:5px; border-radius:8px;
       padding:12px 16px; margin:10px 0; }
.rec.critical { border-left-color:#dc2626; background:#fffafa; }
.rec.warning  { border-left-color:#d97706; background:#fffbeb; }
.rec.info     { border-left-color:#2563eb; background:#f8fbff; }
.rec h3 { margin:0 0 6px; font-size:15px; display:flex; align-items:center; gap:10px; }
.rec .problem { margin:0 0 6px; }
.rec ul { margin:4px 0 8px; padding-left:20px; color:#374151; }
.cmd-details { margin-top:14px; border-top:1px dashed var(--border); padding-top:10px; }
.cmd-details summary { cursor:pointer; color:var(--accent); font-size:13px; user-select:none; }
.cmd-row { margin:8px 0; }
.cmd-desc { font-size:12.5px; color:var(--muted); margin-bottom:3px; }
.cmd-line { position:relative; }
pre.cmd { background:#0f172a; color:#e2e8f0; padding:9px 12px; border-radius:8px;
       font-size:12.5px; overflow-x:auto; margin:0; padding-right:42px; }
.copy-btn { position:absolute; top:6px; right:6px; width:26px; height:26px;
       display:inline-flex; align-items:center; justify-content:center;
       background:transparent; border:0; border-radius:6px; color:#94a3b8;
       cursor:pointer; padding:0; }
.copy-btn:hover { background:#1e293b; color:#e2e8f0; }
.copy-btn .ic-ok { display:none; }
.copy-btn.copied .ic-copy, .copy-btn.failed .ic-copy { display:none; }
.copy-btn.copied .ic-ok, .copy-btn.failed .ic-ok { display:block; }
.copy-btn.copied { color:#4ade80; }
.copy-btn.failed { color:#f87171; }
code.inline { background:#eef2ff; padding:1px 5px; border-radius:4px;
       font-size:.92em; color:#3730a3; }
footer.report { color:var(--muted); font-size:12px; text-align:center; margin-top:26px; }
h3.subhead { font-size:15px; margin:18px 0 6px; }
.note { color:var(--muted); font-size:12.5px; }
"""

# Инлайновый обработчик кнопок «копировать в буфер» (файл остаётся
# автономным). navigator.clipboard требует защищённый контекст; для file://
# и старых браузеров — резерв через execCommand. WeasyPrint скрипты игнорирует.
_CLIPBOARD_JS = """
(function(){
"use strict";
document.addEventListener("click", function(ev){
  var t = ev.target;
  var btn = t.closest ? t.closest(".copy-btn") : null;
  if (!btn) return;
  var line = btn.closest(".cmd-row");
  var code = line ? line.querySelector(".cmd-line code") : null;
  var txt = code ? code.textContent : "";
  var timer = null;
  function mark(ok){
    btn.classList.add(ok ? "copied" : "failed");
    if (timer) clearTimeout(timer);
    timer = setTimeout(function(){ btn.classList.remove("copied","failed"); }, 1300);
  }
  function fallback(){
    var ta = document.createElement("textarea");
    ta.value = txt;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.top = "-1000px";
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(ta);
    mark(ok);
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(txt).then(function(){ mark(true); }, fallback);
  } else {
    fallback();
  }
});
})();
"""


def render_document(result: BranchResult) -> str:
    """Собрать полный HTML-файл отчёта (один автономный файл)."""
    generated = datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    recs = sorted(result.recommendations, key=lambda r: (SEVERITY_ORDER.get(r.severity, 9), r.id))
    toc = " ".join(
        f'<a href="#{esc(s.id)}">{esc(s.title)}</a>' for s in result.sections
    )
    if result.recommendations:
        toc += ' <a href="#recommendations">Рекомендации</a>'

    sections_html = []
    for s in result.sections:
        cmds = cmd_block(s.commands)
        sections_html.append(
            f'<section class="card" id="{esc(s.id)}">'
            f"<h2>{esc(s.title)}</h2>"
            f"{s.body_html}"
            f"{cmds}"
            f"</section>"
        )

    recommendations_html = _render_recommendations(recs) if recs else ""

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>pcap-analyzer &mdash; {esc(result.branch_title)}: {esc(result.pcap_path.name)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">

<header class="report">
  <h1>Анализ сетевого трафика &mdash; {esc(result.branch_title)}</h1>
  <div class="sub">
    Файл: <strong>{esc(result.pcap_path.name)}</strong> ({fmt_bytes(result.pcap_size_bytes)})
    &nbsp;&middot;&nbsp; Ветка: {esc(result.branch_title)}
    &nbsp;&middot;&nbsp; Отчёт сформирован: {generated}
    &nbsp;&middot;&nbsp; pcap-analyzer v{__version__} (tshark)
  </div>
</header>

<nav class="toc">{toc}</nav>

{(
    '<div class="srv-legend"><span class="srv-legend-title">PLC в отчёте '
    '(цвет одинаков во всех таблицах и на диаграммах):</span> '
    + "".join(
        f'<span class="srv" style="background:{esc(bg)};color:{esc(fg)}">'
        f"{esc(ip)}</span>"
        for ip, (bg, fg) in result.server_colors.items())
    + "</div>"
) if len(result.server_colors) >= 2 else ""}

{('<section class="card" id="summary"><h2>Ключевые показатели</h2>' + kpi_cards(result.kpi) + '</section>') if result.kpi else ""}

{"".join(sections_html)}

{recommendations_html}

<footer class="report">
  Отчёт статический и полностью автономный (без внешних ресурсов).
  Все выборки можно воспроизвести командами tshark, приведёнными в секциях.
</footer>

</div>
<script>{_CLIPBOARD_JS}</script>
</body>
</html>
"""


def _render_recommendations(recs: Iterable[Recommendation]) -> str:
    items = []
    for r in recs:
        evidence = ""
        if r.evidence:
            lis = "".join(f"<li>{esc(e)}</li>" for e in r.evidence)
            evidence = f"<ul>{lis}</ul>"
        cmds = ""
        if r.commands:
            rows = "".join(
                f'<div class="cmd-row"><div class="cmd-line">'
                f'<pre class="cmd"><code>{esc(example_cmd(c))}'
                f"</code></pre>{COPY_BTN}</div></div>"
                for c in r.commands
            )
            cmds = (
                '<details class="cmd-details"><summary>Команды tshark для проверки'
                f" ({len(r.commands)})</summary>{rows}</details>"
            )
        items.append(
            f'<div class="rec {esc(r.severity)}">'
            f"<h3>{severity_badge(r.severity)} {esc(r.title)}</h3>"
            f'<p class="problem"><strong>Обнаружено:</strong> {esc(r.problem)}</p>'
            f"{evidence}"
            f'<p><strong>Рекомендация:</strong> {esc(r.advice)}</p>'
            f"{cmds}</div>"
        )
    body = "".join(items)
    return (
        '<section class="card" id="recommendations">'
        "<h2>Рекомендации по оптимизации работы клиентов</h2>"
        '<p class="lead">Правила формируются автоматически по порогам из '
        "<code class=\"inline\">analyzer/config.py</code>. Порядок &mdash; по важности.</p>"
        f"{body}</section>"
    )
