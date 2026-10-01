from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import write

from doctor.cli import main

BAD = """services:
  web:
    image: nginx
    environment:
      DB_PASSWORD: s3cret-p@ssw0rd
"""

FINE = """services:
  web:
    image: nginx:1.27.2
    restart: unless-stopped
    user: "101:101"
    deploy:
      resources:
        limits:
          memory: 128M
    logging:
      driver: json-file
"""


def test_errors_give_exit_code_one(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    folder = tmp_path / "плохой"
    write(folder, BAD)
    assert main(["check", str(folder)]) == 1
    printed = capsys.readouterr().out
    assert "[S01]" in printed
    assert "Как поправить" in printed
    assert "s3cret-p@ssw0rd" not in printed, "секрет не должен попадать в вывод"


def test_clean_file_gives_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    folder = tmp_path / "чистый"
    write(folder, FINE)
    assert main(["check", str(folder), "--ignore", "S05"]) == 0
    assert "замечаний нет" in capsys.readouterr().out.lower()


def test_strict_turns_warnings_into_failure(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    folder = tmp_path / "спорный"
    write(folder, 'services:\n  web:\n    image: nginx:1.27.2\n    user: "101:101"\n')
    assert main(["check", str(folder)]) == 0
    assert main(["check", str(folder), "--strict"]) == 1
    assert "Предупреждения" in capsys.readouterr().out


def test_json_output_is_machine_readable(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    folder = tmp_path / "json"
    write(folder, BAD)
    main(["check", str(folder), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["ошибок"] >= 1
    assert payload["находки"][0]["код"]
    assert payload["находки"][0]["как поправить"]


def test_short_output_has_no_explanations(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    folder = tmp_path / "коротко"
    write(folder, BAD)
    main(["check", str(folder), "--short"])
    printed = capsys.readouterr().out
    assert "[S01]" in printed
    assert "Как поправить" not in printed


def test_missing_file_gives_exit_code_two(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["check", str(tmp_path / "нет")]) == 2
    assert "Ошибка:" in capsys.readouterr().err


def test_rules_are_listed(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["rules"]) == 0
    printed = capsys.readouterr().out
    assert "S01" in printed
    assert "R12" in printed
    assert "Правил:" in printed


def test_demo_shows_before_and_after(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["demo", "--root", str(tmp_path / "демо")]) == 0
    printed = capsys.readouterr().out
    assert "Как обычно пишут:" in printed
    assert "Как стоит:" in printed
    assert "стало 0" in printed


def test_examples_folder_is_clean(capsys: pytest.CaptureFixture[str]) -> None:
    """Образец в examples обязан проходить собственную проверку без единого замечания."""
    examples = Path(__file__).resolve().parent.parent / "examples"
    assert main(["check", str(examples)]) == 0
    assert "замечаний нет" in capsys.readouterr().out.lower()
