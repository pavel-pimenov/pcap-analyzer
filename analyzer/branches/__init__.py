"""Реестр веток анализа.

Новая ветка добавляется в BRANCHES: {"ключ": класс_анализатора}.
"""

from __future__ import annotations

from .base import BaseBranch
from .modbus_tcp import ModbusTcpAnalyzer
from .services import ServicesAnalyzer
from .s7comm import S7CommAnalyzer

BRANCHES: dict[str, type[BaseBranch]] = {
    ModbusTcpAnalyzer.name: ModbusTcpAnalyzer,
    S7CommAnalyzer.name: S7CommAnalyzer,
    ServicesAnalyzer.name: ServicesAnalyzer,
}

DEFAULT_BRANCH = "modbus"


def get_branch(name: str) -> BaseBranch:
    try:
        return BRANCHES[name]()
    except KeyError:
        known = ", ".join(sorted(BRANCHES))
        raise SystemExit(
            f"Неизвестная ветка анализа: '{name}'. Доступны: {known}"
        ) from None
