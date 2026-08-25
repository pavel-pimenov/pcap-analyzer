"""Сравнение карт опроса двух дампов Modbus/TCP (`analyzer overlap`).

Для каждого дампа строится покрытие «регистр → чтений в минуту»
(диапазоны разворачиваются в отдельные адреса, частоты нормируются на
длительность захвата). Затем:

* пересечение и уникальные регистры сторон — кто что читает;
* нагрузка на PLC в запросах/мин по каждой стороне;
* оценка выгоды «одного опрашивающего»: суммарная скорость чтения слов
  сейчас против суммы максимумов по каждому регистру;
* каноническая карта: объединение регистров обеих сторон в слитные
  блоки (≤ batch_max_words) — кандидат на единую карту опроса.
"""

from __future__ import annotations

import datetime
from collections import defaultdict
from dataclasses import dataclass, field
from html import escape
from pathlib import Path

from . import __version__
from .branches.base import display_tz
from .branches.modbus_tcp import ModbusTcpAnalyzer
from .report.html_report import _CSS, _TABLE_CSV_JS


@dataclass
class Side:
    """Покрытие одного дампа."""

    path: Path
    label: str
    duration_min: float = 0.0
    req_total: int = 0
    clients: list[str] = field(default_factory=list)
    servers: list[str] = field(default_factory=list)
    # (сервер, unit, fc, регистр) -> чтений/мин
    cov: dict[tuple[str, int, int, int], float] = field(
        default_factory=lambda: defaultdict(float))
    # запросов/мин на сервер
    ops_by_srv: dict[str, float] = field(default_factory=dict)
    words_min: float = 0.0


def collect_side(path: Path, cfg, tshark_bin: str | None,
                 progress=lambda m, pct=None: None) -> Side:
    """Прогнать два прохода анализатора и собрать покрытие регистра."""
    from analyzer.tshark_runner import find_tshark

    b = ModbusTcpAnalyzer()
    b.cfg = cfg
    b.tshark = find_tshark(tshark_bin)
    b.pcap_str = str(path)
    b.progress = progress
    gen = b._pass_general()
    mb = b._pass_modbus(gen)
    dur_min = max(gen.duration / 60.0, 1e-9)
    side = Side(path=path, label=path.name, duration_min=dur_min,
                req_total=mb["req_total"],
                clients=sorted({c for (c, _s) in mb["pairs"]}),
                servers=sorted({s for (_c, s) in mb["pairs"]}))
    for (sv, u, fc, st, ln), (ops, w) in mb["reads"].items():
        rate = ops / dur_min
        for reg in range(st, st + max(ln, 1)):
            side.cov[(sv, u, fc, reg)] += rate
        side.ops_by_srv[sv] = side.ops_by_srv.get(sv, 0.0) + rate
    # слова/мин: w уже суммарная длина по всем операциям диапазона
    side.words_min = sum(w for (_ops, w) in mb["reads"].values()) / dur_min
    return side


def canonical_blocks(cov_a: dict, cov_b: dict, max_words: int) -> list[dict]:
    """Слить регистры обеих сторон в непрерывные блоки ≤ max_words.

    Возвращает блоки {server, unit, fc, start, len, rate, rate_a,
    rate_b}; rate — нужная частота опроса блока одним опрашивающим
    (чтений блока в минуту), максимум из потребностей сторон.
    """
    grouped: dict[tuple[str, int, int], set[int]] = defaultdict(set)
    for k in set(cov_a) | set(cov_b):
        grouped[(k[0], k[1], k[2])].add(k[3])
    blocks = []
    for (sv, u, fc), regs in sorted(grouped.items()):
        runs: list[tuple[int, int]] = []
        run_start = prev = None
        for reg in sorted(regs):
            if run_start is None:
                run_start = prev = reg
            elif reg == prev + 1:
                prev = reg
            else:
                runs.append((run_start, prev))
                run_start = prev = reg
        if run_start is not None:
            runs.append((run_start, prev))
        for rs, re_ in runs:
            for cs in range(rs, re_ + 1, max_words):
                ce = min(cs + max_words - 1, re_)
                ra = _block_rate(cov_a, sv, u, fc, cs, ce)
                rb = _block_rate(cov_b, sv, u, fc, cs, ce)
                blocks.append({"server": sv, "unit": u, "fc": fc,
                               "start": cs, "len": ce - cs + 1,
                               "rate": max(ra, rb), "rate_a": ra,
                               "rate_b": rb})
    return blocks


def _block_rate(cov: dict, sv: str, u: int, fc: int, start: int,
                end: int) -> float:
    """Средняя частота стороны по активным регистрам блока."""
    vals = [cov.get((sv, u, fc, r), 0.0) for r in range(start, end + 1)]
    active = [v for v in vals if v > 0]
    return sum(active) / len(active) if active else 0.0


def _table(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{h}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>"
                   for row in rows) or '<tr><td colspan="99" class="empty">нет данных</td></tr>'
    return ('<div class="table-scroll">'
            f'<table class="data-table"><thead><tr>{head}</tr></thead>'
            f"<tbody>{body}</tbody></table></div>")


def _runs_str(regs: list[int]) -> str:
    runs: list[tuple[int, int]] = []
    s = p = None
    for r in sorted(regs):
        if s is None:
            s = p = r
        elif r == p + 1:
            p = r
        else:
            runs.append((s, p))
            s = p = r
    if s is not None:
        runs.append((s, p))
    return ", ".join(f"{a}" if a == b_ else f"{a}&ndash;{b_}"
                     for a, b_ in runs)


def render_overlap_html(side_a: Side, side_b: Side, cfg,
                        label_a: str = "", label_b: str = "") -> str:
    """Автономный HTML-отчёт сравнения карт опроса."""
    generated = datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    keys_a, keys_b = set(side_a.cov), set(side_b.cov)
    both = keys_a & keys_b
    only_a, only_b = keys_a - keys_b, keys_b - keys_a
    union = keys_a | keys_b

    cur_words = sum(side_a.cov.values()) + sum(side_b.cov.values())
    one_words = sum(max(side_a.cov.get(k, 0.0), side_b.cov.get(k, 0.0))
                    for k in union)
    saving_pct = (100.0 * (cur_words - one_words) / cur_words) \
        if cur_words else 0.0

    servers = sorted(set(side_a.ops_by_srv) | set(side_b.ops_by_srv))
    load_rows = []
    tot_a = tot_b = 0.0
    for sv in servers:
        ra = side_a.ops_by_srv.get(sv, 0.0)
        rb = side_b.ops_by_srv.get(sv, 0.0)
        tot_a += ra
        tot_b += rb
        skew = f"×{max(ra, rb) / min(ra, rb):.1f}" \
            if min(ra, rb) > 0 else "&mdash;"
        load_rows.append([
            escape(sv),
            f'<span class="num">{ra:.0f}</span>',
            f'<span class="num">{rb:.0f}</span>',
            f'<span class="num">{ra + rb:.0f}</span>', skew])
    load_rows.append([
        "<strong>ИТОГО</strong>",
        f'<span class="num"><strong>{tot_a:.0f}</strong></span>',
        f'<span class="num"><strong>{tot_b:.0f}</strong></span>',
        f'<span class="num"><strong>{tot_a + tot_b:.0f}</strong></span>',
        ""])
    load_tbl = _table(["PLC", "запросов/мин A", "запросов/мин B",
                       "сумма", "перекос"], load_rows)

    blocks = canonical_blocks(side_a.cov, side_b.cov, cfg.batch_max_words)
    block_rows = []
    for bl in sorted(blocks, key=lambda x: -x["rate"])[:25]:
        interval = 60000.0 / bl["rate"] if bl["rate"] > 0 else 0.0
        block_rows.append([
            escape(bl["server"]), str(bl["unit"]), f"FC{bl['fc']}",
            f"<strong>{bl['start']}</strong>&ndash;"
            f"{bl['start'] + bl['len'] - 1}",
            str(bl["len"]),
            f'{bl["rate"]:.0f}',
            f"{interval:.0f} мс" if interval else "&mdash;"])
    blocks_tbl = (
        '<h3 class="subhead">Каноническая карта (топ-25 блоков по частоте)'
        "</h3>"
        + _table(["PLC", "Unit", "Функция", "Регистры", "Слов",
                  "Чтений блока/мин", "Интервал"], block_rows)
        + '<p class="note">Блоки слиты из регистров ОБЕИХ сторон; частота — '
          "максимум потребностей сторон, интервал — обратная величина. "
          "Один опрашивающий закрывает этими запросами все данные сразу.</p>")

    def uniq_table(keys: set, side: Side, title: str) -> str:
        agg: dict[tuple[str, int, int], list[int]] = defaultdict(list)
        for k in keys:
            agg[(k[0], k[1], k[2])].append(k[3])
        items = []
        for key, regs in agg.items():
            rate = sum(side.cov[(key[0], key[1], key[2], r)] for r in regs)
            items.append((key, regs, rate))
        items.sort(key=lambda x: -x[2])
        rows = [[escape(key[0]), str(key[1]), f"FC{key[2]}",
                 f'<code class="inline">{_runs_str(regs)}</code>',
                 f'<span class="num">{rate:.0f}</span>']
                for key, regs, rate in items[:10]]
        if not rows:
            return ""
        return (f'<h3 class="subhead">{title}</h3>'
                + _table(["PLC", "Unit", "Функция", "Регистры",
                          "Чтений/мин"], rows))

    uniq_html = ((uniq_table(only_a, side_a, "Только сторона А")
                  + uniq_table(only_b, side_b, "Только сторона Б"))
                 or "<p>Стороны читают идентичные наборы.</p>")

    common_pct = (100 * len(both) // len(union)) if union else 0
    verdict_parts = [
        f"Регистров: общих <strong>{len(both)}</strong>, у «А» только "
        f"{len(only_a)}, у «Б» только {len(only_b)} (всего {len(union)})."]
    if common_pct >= 40:
        verdict_parts.append(
            f"Наборы пересекаются на {common_pct}% — дублирующий опрос "
            "парой серверов.")
    verdict_parts.append(
        f"Чтение слов: сейчас {cur_words:.0f}/мин на двоих; одному "
        f"опрашивающему достаточно {one_words:.0f}/мин (−{saving_pct:.0f}%).")
    if tot_a > 0 and tot_b > 0:
        verdict_parts.append(
            f"Запросов к PLC: {tot_a:.0f} + {tot_b:.0f} = "
            f"{tot_a + tot_b:.0f}/мин — перевод резерва на данные от "
            "активного сервера убирает меньшую часть целиком.")
    verdict = ("<p>" + " ".join(verdict_parts) + "</p>"
               + '<p class="note"><strong>Как оптимизировать:</strong> '
                 "1) hot-standby — резервный берёт данные от активного или "
                 "опрашивает только health-check; 2) агрегатор: PLC опрашивает "
                 "шлюз единой канонической картой выше, серверы читают шлюз; "
                 "3) выровнять границы окон и слить смежные регистры — мелкие "
                 "окна по 1–4 регистра дороже для PLC, чем редкие крупные.</p>")

    def meta(side: Side) -> str:
        cl = ", ".join(side.clients) or "&mdash;"
        return (f"клиент(ы): {cl}; захват {side.duration_min:.1f} мин; "
                f"запросов {side.req_total}")

    body = f"""
<header class="report">
  <h1>Сравнение карт опроса Modbus/TCP</h1>
  <div class="sub">
    А: <code class="inline">{escape(label_a or side_a.label)}</code>
    &nbsp;&middot;&nbsp;
    Б: <code class="inline">{escape(label_b or side_b.label)}</code>
    &nbsp;&middot;&nbsp; {generated} &nbsp;&middot;&nbsp; v{__version__}
  </div>
</header>

<section class="card" id="verdict"><h2>Вывод</h2>{verdict}
<p class="note">Сторона А: {meta(side_a)}.<br>Сторона Б: {meta(side_b)}.</p>
</section>

<section class="card" id="load"><h2>Нагрузка на PLC</h2>{load_tbl}
<p class="note">«Перекос» — во сколько раз одна сторона нагружает PLC
больше другой по этому контроллеру; сильный перекос при общем наборе
данных означает разные циклы опроса одного и того же.</p></section>

<section class="card" id="canonical"><h2>Единая карта опроса</h2>
{blocks_tbl}</section>

<section class="card" id="unique"><h2>Уникальные диапазоны</h2>
{uniq_html}</section>

<footer class="report">Отчёт статический и автономный; таблицы можно
скачать кнопкой CSV.</footer>
"""

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>pcap-analyzer — Сравнение карт опроса</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
{body}
</div>
<script>{_TABLE_CSV_JS}</script>
</body>
</html>
"""
