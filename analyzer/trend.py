"""Трендовый режим: серия дампов → динамика метрик и правил.

Точка тренда — результат обычного analyze() одного файла (ветка
складывает компактные метрики в BranchResult.metrics). Тяжёлый проход
диаграмм Ганта пропускается через Config.skip_gantt.
"""

from __future__ import annotations

import time as _time
from dataclasses import dataclass, field
from glob import iglob
from pathlib import Path

from .branches.base import BaseBranch
from .report import TrendPoint


def expand_series(pattern: str) -> list[Path]:
    """Файлы серии по маске, отсортированные по имени."""
    return sorted(Path(x) for x in iglob(pattern) if Path(x).is_file())


def build_trend(files: list[Path], branch: BaseBranch, cfg,
                progress=lambda msg, pct=None: None,
                tshark_bin: str | None = None
                ) -> tuple[list[TrendPoint], float]:
    """Проанализировать каждый файл серии; вернуть точки и общее время."""
    from dataclasses import replace
    run_cfg = replace(cfg, skip_gantt=True)
    points: list[TrendPoint] = []
    t_all = _time.monotonic()
    for i, f in enumerate(files, 1):
        t0 = _time.monotonic()
        progress(f"[{i}/{len(files)}] {f.name} …")
        res = branch.analyze(f, cfg=run_cfg, progress=progress,
                             tshark_bin=tshark_bin)
        pt = TrendPoint(path=f, start_ts=res.capture_start_ts,
                        metrics=dict(res.metrics),
                        took_s=_time.monotonic() - t0)
        for r in res.recommendations:
            pt.rec_ids.add(r.id)
            pt.rule_info.setdefault(r.id, (r.severity, r.title))
        points.append(pt)
        progress(f"    готово за {_time.monotonic() - t0:.0f} c")
    return points, _time.monotonic() - t_all
