"""Базовые сущности веток анализа."""

from __future__ import annotations

import bisect
import datetime as _dt
import hashlib
import math
import random
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass, field
from html import escape
from pathlib import Path
from typing import Callable, Sequence

#: Колбэк хода анализа: progress(сообщение, pct=None), где pct — оценка
#: готовности 0..100 (или None, если оценить нечем). Второй аргумент
#: необязательный, но колбэк должен его принимать.
ProgressCb = Callable[..., None]

from ..tshark_runner import stream_fields  # noqa: E402

# Уровни важности рекомендаций
SEVERITY_CRITICAL = "critical"
SEVERITY_WARNING = "warning"
SEVERITY_INFO = "info"

SEVERITY_ORDER = {SEVERITY_CRITICAL: 0, SEVERITY_WARNING: 1, SEVERITY_INFO: 2}


class Reservoir:
    """Ограниченная случайная выборка значений (алгоритм R, Vitter).

    Хранит не более cap значений из n добавленных; каждое из n значений
    попадает в выборку с равной вероятностью, поэтому перцентили по выборке
    корректно оценивают весь захват (важно для больших файлов: все RTT
    в память не помещаются). Зерно генератора фиксировано — поведение
    детерминировано от запуска к запуску при одинаковом входе.
    """

    __slots__ = ("cap", "seen", "_items", "_rng")

    def __init__(self, cap: int) -> None:
        self.cap = max(int(cap), 0)
        self.seen = 0
        self._items: list[float] = []
        self._rng = random.Random(0)

    def add(self, value: float) -> None:
        """Добавить значение, вытесняя случайное при заполненной выборке."""
        self.seen += 1
        if len(self._items) < self.cap:
            self._items.append(value)
            return
        j = self._rng.randrange(self.seen)
        if j < self.cap:
            self._items[j] = value

    def __iter__(self):
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)


@dataclass
class Recommendation:
    """Рекомендация по оптимизации/устранению проблемы."""

    id: str
    severity: str                      # critical / warning / info
    title: str                         # краткий заголовок
    problem: str                       # что обнаружено (с цифрами)
    advice: str                        # что делать
    evidence: list[str] = field(default_factory=list)   # строки-факты
    commands: list[str] = field(default_factory=list)   # команды tshark для проверки


@dataclass
class Section:
    """Секция HTML-отчёта."""

    id: str
    title: str
    body_html: str
    commands: list[tuple[str, str]] = field(default_factory=list)  # (описание, команда)


@dataclass
class KpiItem:
    label: str
    value: str
    hint: str = ""


@dataclass
class BranchResult:
    """Результат работы ветки анализа — вход для рендера HTML."""

    branch_name: str
    branch_title: str
    pcap_path: Path
    pcap_size_bytes: int
    kpi: list[KpiItem] = field(default_factory=list)
    sections: list[Section] = field(default_factory=list)
    recommendations: list[Recommendation] = field(default_factory=list)
    # момент первого пакета захвата (epoch) — попадает в имена файлов экспорта
    capture_start_ts: float | None = None
    # ip сервера (PLC) -> (светлый фон, насыщенный цвет); для легенды в шапке
    server_colors: dict[str, tuple[str, str]] = field(default_factory=dict)
    # компактные числовые метрики для трендового режима (ключ -> значение)
    metrics: dict[str, float] = field(default_factory=dict)
    # карта опроса: метки целей чтения («192.0.2.1 DB100@50»); наполняет
    # ветка, если поддерживает; используется diff-отчётом для поиска
    # новых/исчезнувших регистров между периодами
    read_labels: frozenset[str] = field(default_factory=frozenset)


class BaseBranch(ABC):
    """Интерфейс ветки анализа.

    Каждая ветка знает, как разобрать pcap под свой протокол и собрать
    секции отчёта + рекомендации.
    """

    name: str = "base"
    title: str = "Базовая ветка"
    description: str = ""

    def __init__(self) -> None:
        self._srv_colors: dict[str, tuple[str, str]] = {}

    # -- общее для веток ------------------------------------------------------
    # Атрибуты pcap/pcap_str/cfg/tshark/progress заполняет analyze() ветки.

    @staticmethod
    def _sha256_short(path: Path) -> str:
        """Первые 16 hex-символов SHA-256 файла (идентификатор дампа в отчёте)."""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()[:16]

    def _cmd(self, args_tail: str) -> str:
        """Команда tshark для блока «проверить в отчёте».

        В команде — только имя файла: он может лежать где угодно, полный
        путь нужен лишь самому анализатору.
        """
        return f"tshark -r {self.pcap.name} {args_tail}"

    @staticmethod
    def _ip_key(ip: str) -> tuple:
        """Ключ сортировки IP по октетам (в таблицах порядок стабильный)."""
        try:
            return tuple(int(x) for x in ip.split("."))
        except ValueError:
            return (float("inf"),)

    def _set_servers(self, servers) -> None:
        """Закрепить тёплые цвета за серверами (PLC).

        Одинаково используется во всех таблицах, на диаграммах и в легенде
        шапки отчёта: один IP — один цвет на весь документ. Импорт локальный,
        чтобы не зациклить модули (report импортирует branches.base).
        """
        from analyzer.report.components import warm_pair
        self._srv_colors = {
            ip: warm_pair(i)
            for i, ip in enumerate(sorted(set(servers), key=self._ip_key))
        }

    def _srv_cell(self, ip: str) -> str:
        """IP сервера на тёплом фоне — цвет кодирует конкретный PLC."""
        bg, fg = self._srv_colors.get(ip, ("#f1f5f9", "#334155"))
        return (f'<span class="srv" style="background:{bg};color:{fg}">'
                f"{escape(str(ip), quote=True)}</span>")

    # -- Диаграммы Ганта по потокам (общие для протокольных веток) -----------
    #
    # Три диаграммы: самое загруженное окно, «зум» внутри него и самая
    # плотная пачка. Память ограничена шириной окна, а не размером файла:
    # первый прогон строит гистограмму запросов по секундам, события
    # собираются отдельно только внутри выбранных окон.

    FIELDS_THREADS = ["frame.time_epoch", "tcp.srcport", "tcp.dstport",
                      "ip.dst"]

    @staticmethod
    def _num_f(v):
        try:
            return float(v)
        except (TypeError, ValueError):
            return None

    def _thread_windows(self, req_filter: str, first_ts: float | None,
                        duration: float) -> list[dict]:
        """Окна активности соединений для диаграмм Ганта.

        req_filter — дисплей-фильтр tshark, считающий «запросами»
        (например, "mbtcp && tcp.dstport==502").
        """
        base = first_ts
        win_big = min(self.cfg.gantt_window_sec, duration)
        if base is None or win_big <= 0:
            return []

        hist: Counter = Counter()
        for r in stream_fields(self.tshark, self.pcap_str,
                               ["frame.time_epoch"], display_filter=req_filter):
            ts = self._num_f(r.get("frame.time_epoch"))
            if ts is not None:
                hist[int(ts - base)] += 1
        if not hist:
            return []

        L = max(int(win_big), 1)
        best_s, best_cnt = min(hist), -1
        for s in range(min(hist), max(hist) + 1):
            cnt = sum(hist.get(x, 0) for x in range(s, s + L))
            if cnt > best_cnt:
                best_s, best_cnt = s, cnt

        windows = [
            self._thread_events(req_filter, base, float(best_s), win_big)
        ]
        # «зум»: самая загруженная целая секунда внутри большого окна
        win_zoom = min(self.cfg.gantt_zoom_sec, win_big)
        if win_zoom < win_big:
            sec = max(range(int(best_s), int(best_s) + L),
                      key=lambda s: hist.get(s, 0))
            zwin = self._thread_events(req_filter, base, float(sec), win_zoom)
            windows.append(zwin)
            # третья диаграмма: самая плотная пачка внутри зум-секунды
            bw = min(self.cfg.gantt_burst_sec, win_zoom)
            burst = self._burst_window(zwin, bw)
            if burst:
                windows.append(burst)
        return [w for w in windows if w["rows"]]

    @staticmethod
    def _burst_window(zwin: dict, bw: float) -> dict | None:
        """Окно самой плотной пачки запросов из событий зум-секунды.

        Скользящее окно длиной bw по отсортированным моментам запросов;
        новый проход tshark не нужен — события уже в памяти.
        """
        offs = sorted(t for e in zwin["rows"].values() for t in e["ticks"])
        if len(offs) < 2:
            return None
        best_t, best_n = offs[0], 0
        for i, t in enumerate(offs):           # скользящее окно по bisect
            hi = bisect.bisect_right(offs, t + bw)
            if hi - i > best_n:
                best_n, best_t = hi - i, t
        w0, w1 = best_t, best_t + bw
        rows = {}
        for key, e in zwin["rows"].items():
            tk = [t for t in e["ticks"] if w0 <= t < w1]
            if tk:
                rows[key] = {"ticks": tk, "min": min(tk), "max": max(tk)}
        if best_n < 2 or not rows:
            return None
        return {"win": bw, "start_off": w0, "events": best_n, "rows": rows}

    def _thread_events(self, filt: str, base: float, w0: float,
                       win: float) -> dict:
        """Собрать события одного окна: точки запросов по каждому соединению."""
        self.progress("  сбор событий выбранного окна…", pct=85)
        rows: dict[tuple[str, int], dict] = {}
        events = 0
        for r in stream_fields(self.tshark, self.pcap_str, self.FIELDS_THREADS,
                               display_filter=filt):
            ts = self._num_f(r.get("frame.time_epoch"))
            if ts is None:
                continue
            off = ts - base
            if not (w0 <= off < w0 + win):
                continue
            sport = int(r.get("tcp.srcport") or -1)
            dst = r.get("ip.dst", "")
            key = (dst, sport)
            e = rows.setdefault(key, {"ticks": [], "min": off, "max": off})
            e["ticks"].append(off)
            if off < e["min"]:
                e["min"] = off
            if off > e["max"]:
                e["max"] = off
            events += 1
        return {"win": win, "start_off": w0, "events": events, "rows": rows}

    def _gantt_section_body(self, tw_list: Sequence[dict],
                            req_noun: str = "Modbus-запросы",
                            unit_acc: str = "Modbus-обращений") -> str | None:
        """Тело секции с диаграммами Ганта (графики, легенда, пояснения).

        req_noun — название запросов для текста («Modbus-запросы»,
        «S7-запросы»); unit_acc — форма для счётчика над пачкой.
        """
        from analyzer.report import components as C

        def fmt_win(w: float) -> str:
            return f"{w:g}".replace(".", ",")

        charts = []
        for i, tw in enumerate(tw_list):
            # ряды группируем по серверу: сортировка по IP, затем порт
            ordered = sorted(
                tw["rows"].items(),
                key=lambda kv: (self._ip_key(kv[0][0]), kv[0][1]))
            g_rows = []
            for (dst, sport), e in ordered:
                bg, strong = self._srv_colors.get(dst, ("#f1f5f9", "#334155"))
                g_rows.append({
                    "label": f":{sport} → {dst}",
                    "color": strong,
                    "bg": bg,
                    "fg": strong,
                    "span": (e["min"], e["max"]),
                    "ticks": e["ticks"],
                })
            svg = C.gantt_svg(g_rows, tw["start_off"],
                              tw["start_off"] + tw["win"], bursts=(i >= 1))
            if not svg:
                continue
            mm, ss = divmod(int(tw["start_off"]), 60)
            ms = int(round((tw["start_off"] % 1) * 1000))
            if i == 0:
                title = (f"Окно {fmt_win(tw['win'])} с "
                         f"(начало — {mm}:{ss:02d} от начала файла)")
            elif i == 1:
                title = (f"Самая загруженная секунда этого окна "
                         f"(масштаб {fmt_win(tw['win'])} с); над слитными "
                         f"группами запросов указано их число")
            else:
                title = (f"Самая плотная пачка запросов (масштаб "
                         f"{fmt_win(tw['win'])} с; начало {mm}:{ss:02d},"
                         f"{ms:03d}) — над каждой пачкой число {unit_acc}")
            charts.append(
                f'<h3 class="subhead">{title}</h3>'
                f'<div class="chart-box">{svg}</div>'
            )
        if not charts:
            return None
        ev_str = " + ".join(C.fmt_int(tw["events"]) for tw in tw_list)
        return (
            "".join(charts)
            + "<p>Вертикальные полоски-чёрточки — это <strong>отдельные "
              f"{C.esc(req_noun)}</strong>: каждая чёрточка на оси времени — "
              "один пакет-запрос к серверу. Чем гуще стоят чёрточки, тем "
              "интенсивнее опрос в этот момент. Чёрточки окрашены цветом "
              "того сервера, которому адресован запрос. "
              f"Запросов на диаграммах: {ev_str}.</p>"
            + '<p class="legend">'
              f'<span><i class="lg lg-tick"></i>один '
              f'{C.esc(req_noun.replace("ы", ""))}</span>'
              '<span><i class="lg lg-span"></i>активность соединения</span>'
              '<span><i class="lg lg-grid"></i>линии сетки — деления времени</span>'
              "</p>"
            + '<p class="note">Каждый ряд — отдельное TCP-соединение '
              '(эфемерный порт клиента &rarr; сервер); подпись ряда подкрашена '
              'цветом этого сервера, как в таблицах, ряды отсортированы по IP '
              'сервера — соединения с одним сервером идут подряд. Точки — '
              f'отдельные {req_noun}, светлая полоса — период, в котором '
              'наблюдалась активность соединения. Перекрывающиеся по времени '
              'ряды — одновременный опрос из нескольких потоков; строгое '
              'чередование рядов «лесенкой» — последовательная работа одного '
              'потока. «Зум»-диаграмма показывает детально одну секунду '
              'внутри большого окна — на ней видно чередование запросов между '
              'серверами; над сливающимися группами стрелкой указано число '
              'запросов, редкие одиночные обращения остаются без подписи. '
              'Третья диаграмма раскрывает самую плотную пачку '
              '(масштаб ~0,1 с): сливающиеся в полоску запросы разделяются.</p>'
        )

    @abstractmethod
    def analyze(
        self,
        pcap_path: Path,
        cfg,
        progress: ProgressCb = lambda msg, pct=None: None,
        tshark_bin: str | None = None,
    ) -> BranchResult:
        """Выполнить анализ и вернуть данные для отчёта."""


def sort_recommendations(items: Sequence[Recommendation]) -> list[Recommendation]:
    return sorted(items, key=lambda r: (SEVERITY_ORDER.get(r.severity, 9), r.id))


# ---------------------------------------------------------------------------
# Общие утилиты разбора и форматирования (используются ветками протоколов)
# ---------------------------------------------------------------------------

def to_int(value, default: int = -1) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def to_float(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def truthy(v: str) -> bool:
    """tshark отдаёт булевы поля строками «1»/«True»."""
    return (v or "").strip() in {"1", "True", "true"}


def percentile(sorted_vals, p: float):
    """Перцентиль p по ЗАРАНЕЕ отсортированному списку (линейная интерполяция)."""
    if not sorted_vals:
        return None
    k = (len(sorted_vals) - 1) * p / 100.0
    lo, hi = math.floor(k), math.ceil(k)
    if lo == hi:
        return sorted_vals[int(k)]
    return sorted_vals[lo] * (hi - k) + sorted_vals[hi] * (k - lo)


def fmt_ts_offset(ts: float, first_ts: float) -> str:
    """Смещение от начала захвата в виде ЧЧ:ММ:СС."""
    d = max(ts - first_ts, 0)
    m, s = divmod(int(d), 60)
    h, m = divmod(m, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


#: зона отображения времени в отчётах; None — локальная машина аналитика
_DISPLAY_TZ: _dt.tzinfo | None = None


def set_display_tz(offset_hours: float | None) -> None:
    """Задать смещение зоны показа времени от UTC в часах (например 3, -5.5)."""
    global _DISPLAY_TZ
    if offset_hours is None:
        _DISPLAY_TZ = None
    else:
        _DISPLAY_TZ = _dt.timezone(
            _dt.timedelta(hours=float(offset_hours)))


def display_tz() -> _dt.tzinfo:
    return _DISPLAY_TZ or _dt.timezone.utc


def epoch_to_str(ts, time_only: bool = False) -> str:
    """epoch → время в зоне отображения; единый формат дат во всех отчётах."""
    if ts is None:
        return "&mdash;"
    d = _dt.datetime.fromtimestamp(float(ts),
                                   tz=_dt.timezone.utc).astimezone(
                                       display_tz())
    return d.strftime("%H:%M:%S") if time_only \
        else d.strftime("%d.%m.%Y %H:%M:%S")
