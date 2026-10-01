"""Поиск значений, которых не должно быть в файле открытым текстом.

Правило простое: если имя переменной говорит о пароле, ключе или токене, то её значение должно
приходить из окружения (`${DB_PASSWORD}`) или из секрет-хранилища, а не лежать строкой в compose,
который каждый день коммитится в git. Заглушки вроде `changeme` не считаются: они для того и нужны.

Само значение в отчёт не попадает — только его маска, иначе отчёт сам станет местом утечки.
"""

from __future__ import annotations

import re
from typing import Final

from doctor.env import looks_like_placeholder, mask, referenced

SENSITIVE: Final = re.compile(
    r"(?i)(pass|passwd|password|secret|token|api[-_]?key|access[-_]?key|private[-_]?key|credential|auth)"
)
LONG_RANDOM: Final = re.compile(r"^[A-Za-z0-9+/=_\-]{24,}$")
PRIVATE_KEY: Final = "-----BEGIN"


def sensitive_name(name: str) -> bool:
    """Имя переменной намекает на секрет."""
    return bool(SENSITIVE.search(name))


def exposed(name: str, value: str) -> bool:
    """Значение похоже на настоящий секрет, а не на подстановку и не на заглушку."""
    text = value.strip()
    if not text or referenced(text):
        return False
    if looks_like_placeholder(text):
        return False
    if PRIVATE_KEY in text:
        return True
    if sensitive_name(name):
        return True
    return bool(LONG_RANDOM.fullmatch(text)) and len(text) >= 32


def why(name: str, value: str) -> str:
    """Объяснение для отчёта — с маской вместо значения."""
    text = value.strip()
    if PRIVATE_KEY in text:
        return "значение похоже на закрытый ключ"
    if sensitive_name(name):
        return f"значение задано прямо в файле ({mask(text)})"
    return f"похоже на случайный ключ ({mask(text)})"
