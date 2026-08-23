"""Базовые сущности веток анализа."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from html import escape
from pathlib import Path
from typing import Callable, Sequence

ProgressCb = Callable[[str], None]

# Уровни важности рекомендаций
SEVERITY_CRITICAL = "critical"
SEVERITY_WARNING = "warning"
SEVERITY_INFO = "info"

SEVERITY_ORDER = {SEVERITY_CRITICAL: 0, SEVERITY_WARNING: 1, SEVERITY_INFO: 2}


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

    @abstractmethod
    def analyze(
        self,
        pcap_path: Path,
        cfg,
        progress: ProgressCb = lambda msg: None,
        tshark_bin: str | None = None,
    ) -> BranchResult:
        """Выполнить анализ и вернуть данные для отчёта."""


def sort_recommendations(items: Sequence[Recommendation]) -> list[Recommendation]:
    return sorted(items, key=lambda r: (SEVERITY_ORDER.get(r.severity, 9), r.id))
