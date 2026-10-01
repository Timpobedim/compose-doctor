"""Находка проверки: код, уровень, место, объяснение и что именно дописать в файл.

Отчёт без объяснения бесполезен: «нарушено правило R04» заставляет человека искать документацию,
а «образ без тега — при следующем выкате приедет другая версия, и это не будет видно в git» уже
говорит, что делать. Поэтому у каждой находки есть и причина, и готовая правка.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Final

ERROR: Final = "ошибка"
WARNING: Final = "внимание"
HINT: Final = "совет"

ORDER: Final = {ERROR: 0, WARNING: 1, HINT: 2}
MARKS: Final = {ERROR: "!", WARNING: "·", HINT: "→"}


@dataclass(frozen=True, slots=True)
class Finding:
    """Одно замечание к конфигурации."""

    code: str
    level: str
    where: str
    title: str
    detail: str
    fix: str = ""

    @property
    def mark(self) -> str:
        return MARKS.get(self.level, "?")

    def line(self) -> str:
        return f"{self.mark} [{self.code}] {self.where}: {self.title}"

    def block(self) -> str:
        parts = [self.line(), f"    {self.detail}"]
        if self.fix:
            parts.append(f"    Как поправить: {self.fix}")
        return "\n".join(parts)

    def as_dict(self) -> dict[str, str]:
        return {
            "код": self.code,
            "уровень": self.level,
            "где": self.where,
            "что": self.title,
            "почему": self.detail,
            "как поправить": self.fix,
        }


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Сначала ошибки, потом предупреждения, потом советы; внутри уровня — по коду и месту."""
    return sorted(findings, key=lambda item: (ORDER.get(item.level, 9), item.code, item.where))


def by_level(findings: Sequence[Finding]) -> dict[str, list[Finding]]:
    groups: dict[str, list[Finding]] = {ERROR: [], WARNING: [], HINT: []}
    for finding in findings:
        groups.setdefault(finding.level, []).append(finding)
    return groups


def count(findings: Sequence[Finding], level: str) -> int:
    return sum(1 for finding in findings if finding.level == level)


def worst(findings: Sequence[Finding]) -> str | None:
    """Самый серьёзный уровень среди находок — по нему решается код возврата."""
    levels = [finding.level for finding in findings]
    for level in (ERROR, WARNING, HINT):
        if level in levels:
            return level
    return None
