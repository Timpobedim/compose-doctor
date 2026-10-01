from __future__ import annotations

from pathlib import Path

from conftest import codes, findings, project

from doctor import rules
from doctor.findings import ERROR, HINT, WARNING

GOOD = """services:
  web:
    image: nginx:1.27.2-alpine
    restart: unless-stopped
    user: "101:101"
    ports:
      - "127.0.0.1:8080:80"
    environment:
      DB_PASSWORD: ${DB_PASSWORD}
    depends_on:
      база:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "true"]
    deploy:
      resources:
        limits:
          memory: 256M
    logging:
      driver: json-file

  база:
    image: postgres:16.4-alpine
    restart: unless-stopped
    user: "999:999"
    healthcheck:
      test: ["CMD", "true"]
    deploy:
      resources:
        limits:
          memory: 512M
    logging:
      driver: json-file
    volumes:
      - данные:/var/lib/postgresql/data

volumes:
  данные:
"""


def test_good_file_has_no_findings(tmp_path: Path) -> None:
    found = findings(tmp_path, GOOD, env="DB_PASSWORD=x\n", example="DB_PASSWORD=\n", gitignore=".env\n")
    assert found == [], "образцовый файл не должен давать замечаний"


def test_plain_secret_is_an_error(tmp_path: Path) -> None:
    found = findings(
        tmp_path,
        """services:
  web:
    image: nginx:1.27
    environment:
      DB_PASSWORD: s3cret-p@ssw0rd
""",
    )
    secret = [item for item in found if item.code == "S01"]
    assert secret
    assert secret[0].level == ERROR
    assert "s3cret-p@ssw0rd" not in secret[0].detail, "значение секрета не должно попадать в отчёт"


def test_privileged_and_socket(tmp_path: Path) -> None:
    found = findings(
        tmp_path,
        """services:
  агент:
    image: agent:1.0
    privileged: true
    network_mode: host
    cap_add: [SYS_ADMIN]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
""",
    )
    assert {"S02", "S03", "S04", "S07"} <= set(codes(found))


def test_public_port_is_a_warning(tmp_path: Path) -> None:
    found = findings(
        tmp_path,
        """services:
  web:
    image: nginx:1.27
    ports: ["8080:80"]
""",
    )
    public = [item for item in found if item.code == "S06"]
    assert public
    assert public[0].level == WARNING
    assert "127.0.0.1" in public[0].fix


def test_env_without_gitignore_is_an_error(tmp_path: Path) -> None:
    found = findings(tmp_path, "services:\n  web:\n    image: nginx:1.27\n", env="A=1\n", gitignore="*.log\n")
    assert "S08" in codes(found)

    safe = findings(tmp_path / "второй", "services:\n  web:\n    image: nginx:1.27\n", env="A=1\n", gitignore=".env\n")
    assert "S08" not in codes(safe)


def test_missing_env_file_is_an_error(tmp_path: Path) -> None:
    found = findings(
        tmp_path,
        """services:
  web:
    image: nginx:1.27
    env_file: [нет-такого.env]
""",
    )
    assert "S09" in codes(found)


def test_unknown_variable_is_reported(tmp_path: Path) -> None:
    found = findings(
        tmp_path,
        """services:
  web:
    image: nginx:1.27
    environment:
      API_URL: ${API_URL}
      PORT: ${PORT:-8080}
""",
        example="DB_PASSWORD=\n",
    )
    unknown = [item for item in found if item.code == "S10"]
    assert len(unknown) == 1, "переменная со значением по умолчанию не считается потерянной"
    assert "API_URL" in unknown[0].title


def test_missing_restart_and_limits_and_logging(tmp_path: Path) -> None:
    found = findings(tmp_path, "services:\n  web:\n    image: nginx:1.27\n")
    assert {"R01", "R06", "M04"} <= set(codes(found))


def test_healthcheck_required_only_for_dependencies(tmp_path: Path) -> None:
    found = findings(
        tmp_path,
        """services:
  web:
    image: nginx:1.27
    depends_on: [база]
  база:
    image: postgres:16
""",
    )
    health = [item for item in found if item.code == "R02"]
    assert [item.where for item in health] == ["services.база"]
    assert "R03" in codes(found), "короткая запись depends_on — повод для совета"


def test_unpinned_and_floating_tags(tmp_path: Path) -> None:
    found = findings(
        tmp_path,
        """services:
  a:
    image: nginx
  b:
    image: redis:latest
  c:
    image: ghcr.io/owner/app:stable
  d:
    image: postgres:16.4
""",
    )
    unpinned = [item for item in found if item.code == "R04"]
    floating = [item for item in found if item.code == "R05"]
    assert {item.where for item in unpinned} == {"services.a.image", "services.b.image"}
    assert [item.where for item in floating] == ["services.c.image"]
    assert all(item.level == ERROR for item in unpinned)
    assert all(item.level == HINT for item in floating)


def test_anonymous_data_volume(tmp_path: Path) -> None:
    found = findings(
        tmp_path,
        """services:
  база:
    image: postgres:16.4
    volumes:
      - /var/lib/postgresql/data
""",
    )
    assert "R07" in codes(found)


def test_port_conflict_between_services(tmp_path: Path) -> None:
    found = findings(
        tmp_path,
        """services:
  a:
    image: nginx:1.27
    ports: ["8080:80"]
  b:
    image: nginx:1.27
    ports: ["8080:81"]
""",
    )
    conflict = [item for item in found if item.code == "R09"]
    assert conflict
    assert conflict[0].level == ERROR


def test_unknown_dependency_and_undeclared_volume(tmp_path: Path) -> None:
    found = findings(
        tmp_path,
        """services:
  web:
    image: nginx:1.27
    depends_on: [нет-такого]
    volumes:
      - незаявленный:/data
    networks: [внутренняя]
""",
    )
    assert {"R10", "R12"} <= set(codes(found))


def test_unused_declarations(tmp_path: Path) -> None:
    found = findings(
        tmp_path,
        """services:
  web:
    image: nginx:1.27

volumes:
  лишний:

networks:
  тоже-лишняя:
""",
    )
    unused = [item for item in found if item.code == "R11"]
    assert {item.where for item in unused} == {"volumes.лишний", "networks.тоже-лишняя"}


def test_version_key_and_missing_example(tmp_path: Path) -> None:
    found = findings(
        tmp_path,
        """version: "3.8"
services:
  web:
    image: nginx:1.27
    environment:
      API_URL: ${API_URL}
""",
    )
    assert {"M01", "M02"} <= set(codes(found))


def test_example_drift_both_ways(tmp_path: Path) -> None:
    found = findings(
        tmp_path,
        "services:\n  web:\n    image: nginx:1.27\n",
        env="A=1\nB=2\n",
        example="A=\nC=\n",
        gitignore=".env\n",
    )
    drift = [item for item in found if item.code == "M03"]
    assert len(drift) == 2
    assert any("B" in item.title for item in drift)
    assert any("C" in item.title for item in drift)


def test_service_without_image_or_build(tmp_path: Path) -> None:
    found = findings(tmp_path, "services:\n  web:\n    restart: always\n")
    assert "M05" in codes(found)


def test_only_and_ignore_filters(tmp_path: Path) -> None:
    parsed = project(tmp_path, "services:\n  web:\n    image: nginx\n")
    assert codes(rules.run(parsed, only=("R04",))) == ["R04"]
    assert "R04" not in codes(rules.run(parsed, ignore=("R",)))
    # S05 («работа от root») срабатывает законно: пользователь в этом файле не задан.
    assert codes(rules.run(parsed, only=("S",))) == ["S05"]


def test_every_rule_has_a_description() -> None:
    rows = rules.describe()
    assert len(rows) == len({row[0] for row in rows}), "коды правил не должны повторяться"
    assert all(row[3] for row in rows), "у каждого правила есть пояснение"
    assert len(rows) >= 22
