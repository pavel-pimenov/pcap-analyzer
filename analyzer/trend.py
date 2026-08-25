"""Трендовый режим: серия дампов → динамика метрик и правил.

Точка тренда — результат обычного analyze() одного файла (ветка
складывает компактные метрики в BranchResult.metrics). Тяжёлый проход
диаграмм Ганта пропускается через Config.skip_gantt.

Файлы можно обрабатывать параллельно (--jobs N): каждый воркер получает
СВОЙ экземпляр ветки — состояние анализа инкапсулировано в экземпляре,
общие данные только для чтения (зона отображения времени задаётся до
запуска пула). Порядок результатов всегда соответствует порядку файлов.
"""

from __future__ import annotations

import time as _time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from glob import iglob
from pathlib import Path

from .branches.base import BaseBranch
from .report import TrendPoint


def snapshot_from_points(points: list[TrendPoint],
                         branch_name: str) -> dict:
    """Агрегировать серию в эталонный снимок (среднее метрик + правила).

    Снимок сохраняется в JSON и позже сравнивается с новым дампом через
    `diff ... --baseline`, без хранения целой серии «до».
    """
    import datetime as _dt

    from . import __version__
    metrics = {}
    for pt in points:
        for k, v in pt.metrics.items():
            metrics.setdefault(k, []).append(v)
    rules: dict[str, dict] = {}
    fired: dict[str, int] = {}
    for pt in points:
        for rid in pt.rec_ids:
            fired[rid] = fired.get(rid, 0) + 1
        for rid, st in pt.rule_info.items():
            rules.setdefault(rid, {"severity": st[0], "title": st[1]})
    return {
        "pcap_analyzer": __version__,
        "branch": branch_name,
        "created": _dt.datetime.now().isoformat(timespec="seconds"),
        "files": len(points),
        "metrics": {k: sum(v) / len(v) for k, v in metrics.items()},
        "rules": rules,
        "rule_hits": fired,
    }


def point_from_snapshot(snap: dict, label: str = "эталон") -> TrendPoint:
    """Восстановить одну синтетическую точку тренда из снимка."""
    pt = TrendPoint(path=Path(label), start_ts=None,
                    metrics={k: float(v)
                             for k, v in snap.get("metrics", {}).items()})
    for rid, info in snap.get("rules", {}).items():
        pt.rec_ids.add(rid)
        pt.rule_info[rid] = (info.get("severity", "info"),
                             info.get("title", rid))
    return pt


def expand_series(pattern: str) -> list[Path]:
    """Файлы серии по маске, отсортированные по имени."""
    return sorted(Path(x) for x in iglob(pattern) if Path(x).is_file())


def _analyze_file(branch: BaseBranch, f: Path, cfg,
                  tshark_bin: str | None) -> tuple[TrendPoint, float]:
    """Анализ одного файла; вернуть (точка, время анализа)."""
    from dataclasses import replace
    t0 = _time.monotonic()
    res = branch.analyze(f, cfg=replace(cfg, skip_gantt=True),
                         progress=lambda m, pct=None: None,
                         tshark_bin=tshark_bin)
    pt = TrendPoint(path=f, start_ts=res.capture_start_ts,
                    metrics=dict(res.metrics),
                    took_s=_time.monotonic() - t0)
    for r in res.recommendations:
        pt.rec_ids.add(r.id)
        pt.rule_info.setdefault(r.id, (r.severity, r.title))
    return pt, _time.monotonic() - t0


def build_trend(files: list[Path], branch: BaseBranch, cfg,
                progress=lambda msg, pct=None: None,
                tshark_bin: str | None = None, jobs: int = 1
                ) -> tuple[list[TrendPoint], float]:
    """Проанализировать каждый файл серии; вернуть точки и общее время.

    jobs > 1 — параллельная обработка в потоках; прогресс сообщается по
    мере завершения файлов, порядок точек — как на входе.
    """
    t_all = _time.monotonic()
    points: list[TrendPoint | None] = [None] * len(files)

    if jobs <= 1 or len(files) < 2:
        for i, f in enumerate(files, 1):
            progress(f"[{i}/{len(files)}] {f.name} …")
            pt, dt = _analyze_file(branch, f, cfg, tshark_bin)
            points[i - 1] = pt
            progress(f"    готово за {dt:.0f} c")
    else:
        done = 0
        workers = min(jobs, len(files))
        progress(f"Параллельная обработка: {workers} потоков…")
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(_analyze_file, type(branch)(), f, cfg,
                              tshark_bin): i
                    for i, f in enumerate(files)}
            try:
                for fut in as_completed(futs):
                    i = futs[fut]
                    points[i], _dt = fut.result()
                    done += 1
                    progress(f"[{done}/{len(files)}] готово: "
                             f"{files[i].name}")
            except BaseException:
                for fu in futs:
                    fu.cancel()
                raise

    return points, _time.monotonic() - t_all
