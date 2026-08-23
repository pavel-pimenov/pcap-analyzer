"""Хелперы для построения HTML-компонентов отчёта (без внешних зависимостей)."""

from __future__ import annotations

import html
from typing import Iterable, Sequence


def esc(value) -> str:
    """Экранирование для вставки в HTML."""
    return html.escape(str(value), quote=True)


# ---------------------------------------------------------------------------
# Форматирование чисел и величин
# ---------------------------------------------------------------------------

def fmt_int(value) -> str:
    try:
        return f"{int(value):,}".replace(",", " ")
    except (TypeError, ValueError):
        return "&mdash;"


def fmt_float(value, digits: int = 2) -> str:
    try:
        return f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return "&mdash;"


def fmt_pct(part, whole, digits: int = 1) -> str:
    try:
        if not whole:
            return "&mdash;"
        return f"{100.0 * part / whole:.{digits}f}%"
    except (TypeError, ValueError):
        return "&mdash;"


def fmt_ms(seconds, digits: int = 1) -> str:
    if seconds is None:
        return "&mdash;"
    try:
        return f"{float(seconds) * 1000:.{digits}f}"
    except (TypeError, ValueError):
        return "&mdash;"


def fmt_dur(seconds) -> str:
    """Длительность в человекочитаемом виде (рус.)."""
    try:
        s = float(seconds)
    except (TypeError, ValueError):
        return "&mdash;"
    if s < 1:
        return f"{s * 1000:.0f} мс"
    m, sec = divmod(int(round(s)), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h} ч {m:02d} мин {sec:02d} с"
    if m:
        return f"{m} мин {sec:02d} с"
    return f"{sec} с"


def fmt_bytes(num_bytes) -> str:
    try:
        b = float(num_bytes)
    except (TypeError, ValueError):
        return "&mdash;"
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if b < 1024 or unit == "ТБ":
            return f"{b:.1f} {unit}" if unit != "Б" else f"{int(b)} {unit}"
        b /= 1024
    return "&mdash;"


# ---------------------------------------------------------------------------
# Компоненты
# ---------------------------------------------------------------------------

def kpi_cards(items: Iterable) -> str:
    cards = []
    for it in items:
        hint = f'<div class="kpi-hint">{esc(it.hint)}</div>' if getattr(it, "hint", "") else ""
        cards.append(
            f'<div class="kpi"><div class="kpi-value">{it.value}</div>'
            f'<div class="kpi-label">{esc(it.label)}</div>{hint}</div>'
        )
    return '<div class="kpi-grid">' + "".join(cards) + "</div>"


def table_html(headers: Sequence[str], rows: Sequence[Sequence], cls: str = "") -> str:
    """Таблица; ячейка-кортеж (html, css_class) получает класс на <td>."""
    head = "".join(f"<th>{h}</th>" for h in headers)
    body_rows = []
    for row in rows:
        cells = []
        for c in row:
            if isinstance(c, tuple):
                val, ccls = c
                cells.append(f'<td class="{esc(ccls)}">{val}</td>')
            else:
                cells.append(f"<td>{c}</td>")
        body_rows.append("<tr>" + "".join(cells) + "</tr>")
    body = "".join(body_rows) or '<tr><td colspan="99" class="empty">нет данных</td></tr>'
    # обёртка с горизонтальной прокруткой: широкие таблицы не ломают вёрстку
    return (
        '<div class="table-scroll">'
        f'<table class="data-table {cls}">'
        f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"
        "</div>"
    )


# Кнопка «копировать в буфер» для блоков команд. Обрабатывается инлайновым
# скриптом отчёта (см. _CLIPBOARD_JS в html_report); на печать (PDF)
# скрывается печатной таблицей стилей.
COPY_BTN = (
    '<button type="button" class="copy-btn" '
    'title="Копировать команду в буфер обмена" '
    'aria-label="Копировать команду в буфер обмена">'
    '<svg class="ic ic-copy" viewBox="0 0 16 16" width="13" height="13" '
    'aria-hidden="true"><rect x="5.2" y="5.2" width="8.3" height="8.3" '
    'rx="1.5" fill="none" stroke="currentColor" stroke-width="1.6"/>'
    '<path d="M11 3H4.2A1.7 1.7 0 0 0 2.5 4.7V12" fill="none" '
    'stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>'
    '<svg class="ic ic-ok" viewBox="0 0 16 16" width="13" height="13" '
    'aria-hidden="true"><path d="M2.5 8.6 6.1 12l7.4-8.4" fill="none" '
    'stroke="currentColor" stroke-width="2" stroke-linecap="round" '
    'stroke-linejoin="round"/></svg>'
    "</button>"
)


def cmd_block(commands: Sequence[tuple[str, str]]) -> str:
    """Блок команд tshark для проверки выборок."""
    if not commands:
        return ""
    items = []
    for desc, cmd in commands:
        items.append(
            f'<div class="cmd-row"><div class="cmd-desc">{esc(desc)}</div>'
            f'<div class="cmd-line"><pre class="cmd"><code>{esc(cmd)}</code>'
            f"</pre>{COPY_BTN}</div></div>"
        )
    return (
        '<details class="cmd-details"><summary>Показать команды tshark '
        f'для проверки ({len(commands)})</summary>{"".join(items)}</details>'
    )


# ---------------------------------------------------------------------------
# SVG-графики (инлайном, файл полностью автономен)
# ---------------------------------------------------------------------------

PALETTE = ["#2563eb", "#16a34a", "#d97706", "#dc2626", "#7c3aed", "#0891b2", "#65a30d", "#db2777"]

# Тёплые оттенки для визуального разделения PLC (серверов) в таблицах и на
# диаграммах: светлый фон ячейки и насыщенный цвет текста/графики той же гаммы.
WARM_TINTS = ["#ffe1de", "#ffeadb", "#fff3bf", "#ffe3ee", "#fde8cf", "#f7f1c6"]
WARM_STRONG = ["#b91c1c", "#c2410c", "#a16207", "#be185d", "#9a3412", "#854d0e"]


def warm_pair(index: int) -> tuple[str, str]:
    """Пара (светлый фон, насыщенный цвет) для сервера с номером index."""
    i = index % len(WARM_TINTS)
    return WARM_TINTS[i], WARM_STRONG[i]


def _svg_open(width: int, height: int) -> str:
    return (
        f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
        f'role="img" style="width:100%;height:auto;">'
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#ffffff"/>'
    )


def timeline_svg(
    labels: Sequence[str],
    series: Sequence[Sequence[float]],
    colors: Sequence[str],
    legend: Sequence[str],
    height: int = 220,
) -> str:
    """Столбчатая диаграмма активности по времени."""
    width = 960
    pad_l, pad_r, pad_t, pad_b = 46, 12, 14, 42
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    n = len(labels)
    out = [_svg_open(width, height)]

    max_val = max((max(s) for s in series), default=0) or 1
    # Сетка и подписи Y
    grid_lines = 4
    for i in range(grid_lines + 1):
        y = pad_t + plot_h * i / grid_lines
        val = max_val * (grid_lines - i) / grid_lines
        out.append(
            f'<line x1="{pad_l}" y1="{y:.1f}" x2="{width - pad_r}" y2="{y:.1f}" '
            f'stroke="#e5e7eb" stroke-width="1"/>'
        )
        out.append(
            f'<text x="{pad_l - 6}" y="{y + 4:.1f}" font-size="11" fill="#6b7280" '
            f'text-anchor="end">{val:.0f}</text>'
        )

    if n:
        group_w = plot_w / n
        bar_w = max(group_w / max(len(series), 1) - 1.0, 0.8)
        for bi, values in enumerate(series):
            color = colors[bi % len(colors)]
            x0 = pad_l + bi * group_w
            for si, v in enumerate(values):
                bh = plot_h * v / max_val if max_val else 0
                bx = x0 + si * (group_w / max(len(series), 1))
                if v > 0:
                    out.append(
                        f'<rect x="{bx:.1f}" y="{pad_t + plot_h - bh:.1f}" '
                        f'width="{bar_w:.1f}" height="{bh:.1f}" fill="{color}"/>'
                    )
        # подписи X — каждые k бакетов
        step = max(1, n // 8)
        for bi in range(0, n, step):
            x0 = pad_l + bi * group_w + group_w / 2
            out.append(
                f'<text x="{x0:.1f}" y="{height - pad_b + 16}" font-size="10.5" fill="#6b7280" '
                f'text-anchor="middle">{esc(labels[bi])}</text>'
            )

    # Легенда
    lx = pad_l
    ly = height - 8
    for name, color in zip(legend, colors):
        out.append(f'<rect x="{lx}" y="{ly - 9}" width="10" height="10" fill="{color}" rx="2"/>')
        out.append(
            f'<text x="{lx + 14}" y="{ly}" font-size="11" fill="#374151">{esc(name)}</text>'
        )
        lx += 14 + 6 * len(name) + 24
    out.append("</svg>")
    return "".join(out)


def gantt_svg(rows: Sequence[dict], t0: float, t1: float,
              bursts: bool = False) -> str:
    """Диаграмма Ганта опроса: ряды = соединения (потоки), точки = запросы.

    rows — список словарей {"label", "color", "bg"?, "fg"?, "span"?, "ticks"};
    времена в секундах от начала окна [t0; t1]. При bursts=True ряды высокие,
    запросы группируются в пачки, над каждой пачкой — счётчик со стрелкой.
    Возвращает "" для пустого списка рядов.
    """
    if not rows or t1 <= t0:
        return ""
    width = 960
    label_w, pad_r, pad_t, pad_b = 175, 14, 12, 28
    row_h = 38 if bursts else 22
    plot_w = width - label_w - pad_r
    height = pad_t + len(rows) * row_h + pad_b

    def x(t: float) -> float:
        return label_w + (t - t0) / (t1 - t0) * plot_w

    out = [_svg_open(width, height)]
    win = t1 - t0
    # шаг сетки под масштаб окна; подписи — с русской десятичной запятой
    if win <= 0.55:
        step = 0.05
    elif win <= 2.5:
        step = 0.1
    elif win <= 16:
        step = 1.0
    else:
        step = win / 10.0
    dec = 2 if step < 0.1 else (1 if step < 1 else 0)
    g = t0
    while g <= t1 + 1e-9:                      # сетка с подписями времени
        gx = x(g)
        out.append(f'<line x1="{gx:.1f}" y1="{pad_t}" x2="{gx:.1f}" '
                   f'y2="{height - pad_b}" stroke="#e2e8f0" stroke-width="1"/>')
        lbl = f"{g - t0:.{dec}f}".replace(".", ",") if step < 1 else f"{g - t0:g}"
        out.append(f'<text x="{gx:.1f}" y="{height - pad_b + 17}" '
                   f'font-size="11" fill="#64748b" text-anchor="middle">'
                   f'{lbl} с</text>')
        g += step
    for i, r in enumerate(rows):
        y = pad_t + i * row_h
        color = r.get("color", PALETTE[0])
        if i % 2 == 0:                         # чередование фона рядов
            out.append(f'<rect x="{label_w}" y="{y}" width="{plot_w}" '
                       f'height="{row_h}" fill="#f8fafc"/>')
        lbl = str(r.get("label", ""))
        if len(lbl) > 26:
            lbl = lbl[:25] + "…"
        bg = r.get("bg")                       # подкраска подписи ряда (PLC)
        if bg:
            out.append(f'<rect x="2" y="{y + 1}" width="{label_w - 10}" '
                       f'height="{row_h - 2}" rx="3" fill="{bg}"/>')
        out.append(f'<text x="{label_w - 8}" y="{y + row_h / 2 + 4}" '
                   f'font-size="11" font-weight="600" '
                   f'fill="{esc(r.get("fg") or "#334155")}" text-anchor="end">'
                   f'{esc(lbl)}</text>')
        span = r.get("span")
        if span:                               # полоса жизни соединения
            a, b = max(span[0], t0), min(span[1], t1)
            if b > a:
                sy = y + row_h - 13 if bursts else y + 4
                sh = 9 if bursts else row_h - 8
                out.append(f'<rect x="{x(a):.1f}" y="{sy}" '
                           f'width="{max(x(b) - x(a), 1.5):.1f}" '
                           f'height="{sh}" rx="3" fill="{color}" '
                           f'opacity="0.25"/>')
        ticks = sorted(float(t) for t in r.get("ticks", ()) if t0 <= t <= t1)
        ty = y + row_h - 16 if bursts else y + 3     # полоса самих запросов
        th = 12 if bursts else row_h - 6
        for t in ticks:                        # сами запросы
            tx = x(t)
            out.append(f'<rect x="{tx - 1:.1f}" y="{ty}" width="2" '
                       f'height="{th}" fill="{color}" opacity="0.85"/>')
        if bursts and len(ticks) > 1:          # разметка пачек со счётчиком
            gap = max(0.005, win * 0.04)       # порог «разрыва» между пачками
            groups = [[ticks[0]]]
            for t in ticks[1:]:
                if t - groups[-1][-1] > gap:
                    groups.append([])
                groups[-1].append(t)
            for gr in groups:
                if len(gr) < 2:
                    continue                   # одиночный запрос — не пачка
                cx = x((gr[0] + gr[-1]) / 2)
                out.append(f'<text x="{cx:.1f}" y="{y + 13}" font-size="11" '
                           f'font-weight="600" fill="{color}" '
                           f'text-anchor="middle">{len(gr)} зап.</text>')
                out.append(f'<line x1="{cx:.1f}" y1="{y + 17}" x2="{cx:.1f}" '
                           f'y2="{y + row_h - 21}" stroke="{color}" '
                           f'stroke-width="1.4"/>')
                ay = y + row_h - 20            # остриё стрелки вниз
                out.append(f'<polygon points="{cx - 3.2:.1f},{ay} '
                           f'{cx + 3.2:.1f},{ay} {cx:.1f},{ay + 4}" '
                           f'fill="{color}"/>')
    out.append("</svg>")
    return "".join(out)


def vbar_svg(items: Sequence[tuple[str, float]], color: str = PALETTE[0], height: int = 240,
             value_fmt=None) -> str:
    """Вертикальные столбцы с подписями категорий (немного категорий)."""
    width = 960
    pad_l, pad_r, pad_t, pad_b = 46, 12, 16, 52
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    n = len(items)
    out = [_svg_open(width, height)]
    max_val = max((v for _, v in items), default=0) or 1
    for i in range(5):
        y = pad_t + plot_h * i / 4
        val = max_val * (4 - i) / 4
        out.append(
            f'<line x1="{pad_l}" y1="{y:.1f}" x2="{width - pad_r}" y2="{y:.1f}" stroke="#e5e7eb"/>'
        )
        out.append(
            f'<text x="{pad_l - 6}" y="{y + 4:.1f}" font-size="11" fill="#6b7280" '
            f'text-anchor="end">{value_fmt(val) if value_fmt else f"{val:.0f}"}</text>'
        )
    if n:
        slot = plot_w / n
        bar_w = min(slot * 0.6, 120)
        for i, (label, v) in enumerate(items):
            bh = plot_h * v / max_val
            x = pad_l + i * slot + (slot - bar_w) / 2
            out.append(
                f'<rect x="{x:.1f}" y="{pad_t + plot_h - bh:.1f}" width="{bar_w:.1f}" '
                f'height="{bh:.1f}" fill="{color}" rx="3"/>'
            )
            vf = value_fmt(v) if value_fmt else f"{v:.0f}"
            out.append(
                f'<text x="{x + bar_w / 2:.1f}" y="{pad_t + plot_h - bh - 6:.1f}" '
                f'font-size="11" fill="#111827" text-anchor="middle">{esc(vf)}</text>'
            )
            out.append(
                f'<text x="{x + bar_w / 2:.1f}" y="{height - pad_b + 18}" font-size="11.5" '
                f'fill="#374151" text-anchor="middle">{esc(label)}</text>'
            )
    out.append("</svg>")
    return "".join(out)


def hbar_svg(items: Sequence[tuple[str, float]], color: str = PALETTE[0],
             value_fmt=None) -> str:
    """Горизонтальные полосы (для перцентилей, топов)."""
    width = 960
    label_w = 300
    pad_l, pad_r = label_w + 10, 70
    plot_w = width - pad_l - pad_r
    row_h = 26
    height = len(items) * row_h + 12
    out = [_svg_open(width, height)]
    max_val = max((v for _, v in items), default=0) or 1
    for i, (label, v) in enumerate(items):
        y = i * row_h + 6
        bw = plot_w * v / max_val
        out.append(
            f'<text x="{label_w}" y="{y + 14}" font-size="12" fill="#374151" '
            f'text-anchor="end">{esc(label)}</text>'
        )
        out.append(
            f'<rect x="{pad_l}" y="{y + 3}" width="{max(bw, 1.5):.1f}" height="16" '
            f'fill="{color}" rx="3"/>'
        )
        vf = value_fmt(v) if value_fmt else f"{v:.1f}"
        out.append(
            f'<text x="{pad_l + bw + 8:.1f}" y="{y + 15.5}" font-size="11.5" fill="#111827">'
            f"{esc(vf)}</text>"
        )
    out.append("</svg>")
    return "".join(out)


def coverage_svg(ranges: Sequence[tuple[int, int, float]], max_reg: int,
                 color: str = "#2563eb", height: int = 64, label: str = "") -> str:
    """Карта покрытия регистров: ranges = [(start, end_exclusive, интенсивность 0..1)]."""
    width = 960
    pad_l, pad_r = 8, 8
    plot_w = width - pad_l - pad_r
    bar_y, bar_h = 24, 22
    scale = plot_w / max(max_reg, 1)
    out = [_svg_open(width, height)]
    if label:
        out.append(
            f'<text x="{pad_l}" y="14" font-size="12" fill="#374151">{esc(label)}</text>'
        )
    out.append(
        f'<rect x="{pad_l}" y="{bar_y}" width="{plot_w}" height="{bar_h}" '
        f'fill="#f3f4f6" rx="3"/>'
    )
    for start, end, w in ranges:
        x = pad_l + start * scale
        rw = max((end - start) * scale, 1.5)
        opacity = 0.35 + 0.65 * min(w, 1.0)
        out.append(
            f'<rect x="{x:.1f}" y="{bar_y}" width="{rw:.1f}" height="{bar_h}" '
            f'fill="{color}" opacity="{opacity:.2f}" rx="2">'
            f"<title>регистры {start}&ndash;{end - 1}</title></rect>"
        )
    # Подписи шкалы
    ticks = 6
    for i in range(ticks + 1):
        reg = int(max_reg * i / ticks)
        x = pad_l + reg * scale
        out.append(
            f'<text x="{x:.1f}" y="{bar_y + bar_h + 14}" font-size="10.5" fill="#9ca3af" '
            f'text-anchor="{"start" if i == 0 else ("end" if i == ticks else "middle")}">{reg}</text>'
        )
    out.append("</svg>")
    return "".join(out)


def severity_badge(severity: str) -> str:
    names = {
        "critical": ("Критично", "sev-critical"),
        "warning": ("Важно", "sev-warning"),
        "info": ("Совет", "sev-info"),
    }
    text, cls = names.get(severity, (severity, "sev-info"))
    return f'<span class="badge {cls}">{text}</span>'
