"""Отчёт: что нашли, почему это важно и что дописать в файл.

Отдельно — машинный вывод: тот же результат в JSON, чтобы проверку можно было поставить в сборку
и разбирать её вывод чем угодно.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from doctor.findings import ERROR, HINT, WARNING, Finding, by_level, count
from doctor.rules import describe


def report(findings: Sequence[Finding], *, path: Path, short: bool = False) -> str:
    """Полный отчёт по файлу: находки по уровням и итоговая строка."""
    if not findings:
        return f"{path}: замечаний нет."
    groups = by_level(findings)
    parts = [f"{path}"]
    for level, header in ((ERROR, "Ошибки"), (WARNING, "Предупреждения"), (HINT, "Советы")):
        block = groups.get(level) or []
        if not block:
            continue
        parts.append("")
        parts.append(f"{header} ({len(block)}):")
        parts.extend(item.line() if short else item.block() for item in block)
    parts.append("")
    parts.append(summary(findings))
    return "\n".join(parts)


def summary(findings: Sequence[Finding]) -> str:
    if not findings:
        return "Замечаний нет."
    return (
        f"Итого: ошибок {count(findings, ERROR)}, "
        f"предупреждений {count(findings, WARNING)}, "
        f"советов {count(findings, HINT)}."
    )


def as_json(findings: Sequence[Finding], *, path: Path) -> str:
    payload = {
        "файл": str(path),
        "ошибок": count(findings, ERROR),
        "предупреждений": count(findings, WARNING),
        "советов": count(findings, HINT),
        "находки": [finding.as_dict() for finding in findings],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def rules_table() -> str:
    """Все правила списком: код, уровень, о чём оно."""
    rows = describe()
    width = max(len(row[0]) for row in rows)
    level_width = max(len(row[1]) for row in rows)
    title_width = max(len(row[2]) for row in rows)
    lines = [f"Правил: {len(rows)}", ""]
    lines.extend(
        f"{code.ljust(width)}  {level.ljust(level_width)}  {title.ljust(title_width)}  {about}"
        for code, level, title, about in rows
    )
    return "\n".join(lines)
