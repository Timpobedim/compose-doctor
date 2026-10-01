from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest

from doctor import rules
from doctor.findings import Finding
from doctor.project import Project, load

SIMPLE = """services:
  web:
    image: nginx:1.27.2
    restart: unless-stopped
    user: "101:101"
    healthcheck:
      test: ["CMD", "true"]
    deploy:
      resources:
        limits:
          memory: 128M
    logging:
      driver: json-file
"""


def write(
    folder: Path, compose: str, *, env: str | None = None, example: str | None = None, gitignore: str | None = None
) -> Path:
    """Кладёт compose и соседние файлы в папку и возвращает путь к compose."""
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "compose.yaml"
    path.write_text(compose, "utf-8")
    if env is not None:
        (folder / ".env").write_text(env, "utf-8")
    if example is not None:
        (folder / ".env.example").write_text(example, "utf-8")
    if gitignore is not None:
        (folder / ".gitignore").write_text(gitignore, "utf-8")
    return path


def project(tmp_path: Path, compose: str, **files: str | None) -> Project:
    return load(write(tmp_path / "стенд", compose, **files))


def findings(tmp_path: Path, compose: str, **files: str | None) -> list[Finding]:
    return rules.run(project(tmp_path, compose, **files))


def codes(items: Sequence[Finding]) -> list[str]:
    return sorted({item.code for item in items})


@pytest.fixture
def simple(tmp_path: Path) -> Project:
    return project(tmp_path, SIMPLE)
