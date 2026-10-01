"""Демонстрация: один и тот же сервис в двух вариантах — как обычно пишут и как стоит.

Оба файла создаются во временной папке: класть в репозиторий пример с «секретом» внутри — плохая
идея даже в учебных целях, его найдёт первый же сканер.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

from doctor import report as report_module
from doctor import rules
from doctor.findings import ERROR, Finding, count
from doctor.project import load

BAD_COMPOSE = """version: "3.8"

services:
  web:
    image: nginx
    container_name: shop-web
    ports:
      - "80:80"
    environment:
      DB_PASSWORD: s3cret-p@ssw0rd-123456
      API_URL: ${API_URL}
    depends_on:
      - база
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

  база:
    image: postgres:16
    privileged: true
    ports:
      - "5432:5432"
    environment:
      POSTGRES_PASSWORD: postgres
    volumes:
      - /var/lib/postgresql/data
"""

GOOD_COMPOSE = """services:
  web:
    image: nginx:1.27.2-alpine
    restart: unless-stopped
    user: "101:101"
    read_only: true
    ports:
      - "127.0.0.1:8080:80"
    environment:
      DB_PASSWORD: ${DB_PASSWORD}
      API_URL: ${API_URL:-http://localhost:8000}
    depends_on:
      база:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost/health"]
      interval: 10s
      retries: 3
    deploy:
      resources:
        limits:
          memory: 256M
    logging:
      driver: json-file
      options:
        max-size: 10m
        max-file: "3"

  база:
    image: postgres:16.4-alpine
    restart: unless-stopped
    user: "999:999"
    environment:
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      retries: 5
    deploy:
      resources:
        limits:
          memory: 512M
    logging:
      driver: json-file
      options:
        max-size: 10m
        max-file: "3"
    volumes:
      - данные:/var/lib/postgresql/data

volumes:
  данные:
"""

GOOD_ENV_EXAMPLE = """# Заполните перед первым запуском
DB_PASSWORD=
API_URL=
"""

GOOD_GITIGNORE = ".env\n"


@dataclass(frozen=True, slots=True)
class DemoResult:
    root: Path
    bad: list[Finding]
    good: list[Finding]
    text: str


def run(*, root: Path | None = None) -> DemoResult:
    base = Path(root) if root else Path(tempfile.mkdtemp(prefix="compose-doctor-demo-"))
    bad_folder = base / "как-обычно"
    good_folder = base / "как-стоит"
    _write(bad_folder / "compose.yaml", BAD_COMPOSE)
    (bad_folder / ".env").write_text("DB_PASSWORD=s3cret-p@ssw0rd-123456\n", "utf-8")

    _write(good_folder / "compose.yaml", GOOD_COMPOSE)
    (good_folder / ".env").write_text("DB_PASSWORD=из-хранилища-секретов\nAPI_URL=http://api:8000\n", "utf-8")
    (good_folder / ".env.example").write_text(GOOD_ENV_EXAMPLE, "utf-8")
    (good_folder / ".gitignore").write_text(GOOD_GITIGNORE, "utf-8")

    bad = rules.run(load(bad_folder))
    good = rules.run(load(good_folder))

    text = "\n".join(
        [
            "Как обычно пишут:",
            report_module.report(bad, path=(bad_folder / "compose.yaml"), short=True),
            "",
            "Как стоит:",
            report_module.report(good, path=(good_folder / "compose.yaml"), short=True),
            "",
            f"Ошибок было {count(bad, ERROR)}, стало {count(good, ERROR)}.",
            f"Файлы демонстрации: {base}",
        ]
    )
    return DemoResult(root=base, bad=bad, good=good, text=text)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, "utf-8")
