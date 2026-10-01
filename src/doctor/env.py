"""Чтение .env-файлов и подстановок `${VAR}` из значений compose.

Compose подставляет переменные окружения в значения, и это самое частое место, где выкат ломается
молча: переменной нет — вместо неё подставляется пустая строка, контейнер поднимается и работает
неправильно. Поэтому подстановки разбираются отдельно, а ключи сверяются с `.env` и `.env.example`.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

VARIABLE: Final = re.compile(
    r"""
    \$\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)(?::?[-?+][^}]*)?\}   # ${VAR}, ${VAR:-по умолчанию}
    |
    \$(?P<plain>[A-Za-z_][A-Za-z0-9_]*)                          # $VAR
    """,
    re.VERBOSE,
)

PLACEHOLDERS: Final = {
    "",
    "-",
    "change_me",
    "changeme",
    "placeholder",
    "redacted",
    "secret",
    "todo",
    "xxx",
    "your_password",
    "замените",
    "сюда",
}


class EnvError(ValueError):
    """Файл переменных окружения прочитать не удалось."""


def parse(text: str) -> dict[str, str]:
    """Разбирает .env: комментарии, `export`, кавычки, пустые строки."""
    values: dict[str, str] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            raise EnvError(f"строка {number}: «{raw.strip()}» — ожидалось имя=значение")
        name, _, value = line.partition("=")
        values[name.strip()] = _unquote(value.strip())
    return values


def read(path: Path) -> dict[str, str]:
    try:
        return parse(path.read_text("utf-8"))
    except OSError as exc:
        raise EnvError(f"Не удалось прочитать {path.name}: {exc}") from exc
    except EnvError as exc:
        raise EnvError(f"{path.name}: {exc}") from exc


def referenced(value: str) -> set[str]:
    """Имена переменных, которые compose подставит в это значение."""
    names: set[str] = set()
    for match in VARIABLE.finditer(value):
        name = match.group("braced") or match.group("plain")
        if name:
            names.add(name)
    return names


def has_default(value: str, name: str) -> bool:
    """У подстановки задано значение по умолчанию: `${VAR:-8080}` не сломается без переменной."""
    pattern = re.compile(r"\$\{" + re.escape(name) + r":?[-?+][^}]*\}")
    return bool(pattern.search(value))


def looks_like_placeholder(value: str) -> bool:
    stripped = value.strip().strip("<>[]{}\"'").lower()
    return stripped in PLACEHOLDERS or stripped.startswith("your") or stripped.startswith("ваш")


def mask(value: str) -> str:
    """Показывает, что значение есть, не показывая самого значения."""
    text = value.strip()
    if len(text) <= 4:
        return "*" * len(text)
    return f"{text[:2]}{'*' * (len(text) - 4)}{text[-2:]}"


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value.split(" #")[0].strip()
