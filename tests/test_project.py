from __future__ import annotations

from pathlib import Path

import pytest
from conftest import project, write

from doctor.project import LoadError, load


def test_ports_in_every_notation(tmp_path: Path) -> None:
    parsed = project(
        tmp_path,
        """services:
  web:
    image: nginx:1.27
    ports:
      - "8080:80"
      - "127.0.0.1:9090:90"
      - "5353:53/udp"
      - "3000"
      - target: 8000
        published: "18000"
        host_ip: 127.0.0.1
""",
    )
    ports = parsed.services["web"].ports
    assert [port.published for port in ports] == ["8080", "9090", "5353", None, "18000"]
    assert [port.target for port in ports] == ["80", "90", "53", "3000", "8000"]
    assert ports[1].host_ip == "127.0.0.1"
    assert ports[2].protocol == "udp"
    assert ports[0].public, "без адреса порт виден снаружи"
    assert not ports[1].public


def test_volumes_in_every_notation(tmp_path: Path) -> None:
    parsed = project(
        tmp_path,
        """services:
  web:
    image: nginx:1.27
    volumes:
      - ./configs:/app/config:ro
      - данные:/var/lib/data
      - /var/log
      - type: bind
        source: ./logs
        target: /logs
        read_only: true
""",
    )
    mounts = parsed.services["web"].mounts
    assert [mount.kind for mount in mounts] == ["привязка", "том", "анонимный", "привязка"]
    assert mounts[0].read_only
    assert mounts[1].source == "данные"
    assert mounts[2].source is None
    assert mounts[3].target == "/logs"


def test_current_folder_and_windows_drive(tmp_path: Path) -> None:
    """«.:/app» — привязка текущей папки, а не буква диска."""
    parsed = project(
        tmp_path,
        r"""services:
  dev:
    image: node:24-alpine
    volumes:
      - .:/app
      - C:\data:/data
""",
    )
    mounts = parsed.services["dev"].mounts
    assert mounts[0].source == "."
    assert mounts[0].target == "/app"
    assert mounts[0].kind == "привязка"
    assert mounts[1].source == r"C:\data"
    assert mounts[1].target == "/data"


def test_environment_as_list_and_mapping(tmp_path: Path) -> None:
    as_list = project(
        tmp_path / "список",
        """services:
  web:
    image: nginx:1.27
    environment:
      - A=1
      - B=строка со знаком = внутри
""",
    )
    assert as_list.services["web"].environment == {"A": "1", "B": "строка со знаком = внутри"}

    as_map = project(
        tmp_path / "словарь",
        """services:
  web:
    image: nginx:1.27
    environment:
      A: 1
      B:
""",
    )
    assert as_map.services["web"].environment == {"A": "1", "B": ""}


def test_depends_on_both_forms(tmp_path: Path) -> None:
    parsed = project(
        tmp_path,
        """services:
  web:
    image: nginx:1.27
    depends_on:
      база:
        condition: service_healthy
  api:
    image: nginx:1.27
    depends_on: [база]
  база:
    image: postgres:16
""",
    )
    assert parsed.services["web"].depends_on == {"база": "service_healthy"}
    assert parsed.services["api"].depends_on == {"база": ""}


def test_limits_from_deploy_and_old_keys(tmp_path: Path) -> None:
    parsed = project(
        tmp_path,
        """services:
  new:
    image: nginx:1.27
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: "0.5"
  old:
    image: nginx:1.27
    mem_limit: 512m
""",
    )
    assert parsed.services["new"].limits == {"memory": "256M", "cpus": "0.5"}
    assert parsed.services["old"].limits["memory"] == "512m"


def test_compose_is_found_in_a_folder(tmp_path: Path) -> None:
    folder = tmp_path / "проект"
    write(folder, "services:\n  web:\n    image: nginx:1.27\n")
    assert load(folder).path.name == "compose.yaml"


def test_neighbours_are_picked_up(tmp_path: Path) -> None:
    parsed = project(
        tmp_path,
        "services:\n  web:\n    image: nginx:1.27\n",
        env="A=1\n",
        example="A=\nB=\n",
        gitignore=".env\n",
    )
    assert parsed.env == {"A": "1"}
    assert set(parsed.env_example) == {"A", "B"}
    assert parsed.gitignore == (".env",)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "пуст"),
        ("просто строка", "ожидался словарь"),
        ("services: {}", "нет ни одного сервиса"),
        ("services:\n  web: строка\n", "ожидался словарь настроек"),
        ("services:\n  web:\n   image: a\n  - плохо\n", "не разобрать как YAML"),
    ],
)
def test_broken_files_are_explained(tmp_path: Path, text: str, message: str) -> None:
    path = write(tmp_path / f"стенд{len(text)}", text)
    with pytest.raises(LoadError, match=message):
        load(path)


def test_missing_file_is_explained(tmp_path: Path) -> None:
    with pytest.raises(LoadError, match="не найден"):
        load(tmp_path / "нет-такого.yaml")
    with pytest.raises(LoadError, match="нет ни одного из файлов"):
        load(tmp_path)
