"""Разбор compose-файла и окружения рядом с ним.

Compose допускает две записи почти для всего: порты строкой и объектом, переменные списком и
словарём, зависимости списком и словарём с условиями. Проверки не должны об этом знать, поэтому
здесь всё приводится к одному виду, а дальше правила работают с понятными полями.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import yaml

from doctor.env import EnvError
from doctor.env import read as read_env

COMPOSE_NAMES: Final = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")
ENV_NAMES: Final = (".env",)
EXAMPLE_NAMES: Final = (".env.example", ".env.sample", ".env.dist")

BIND_PREFIXES: Final = (".", "/", "~", "$")


class LoadError(ValueError):
    """Файл конфигурации прочитать или разобрать не удалось."""


@dataclass(frozen=True, slots=True)
class Port:
    target: str
    published: str | None
    host_ip: str | None
    protocol: str
    raw: str

    @property
    def public(self) -> bool:
        """Порт виден снаружи машины: адрес не указан или указан не локальный."""
        return self.published is not None and self.host_ip not in {"127.0.0.1", "::1", "localhost"}


@dataclass(frozen=True, slots=True)
class Mount:
    source: str | None
    target: str
    read_only: bool
    kind: str
    raw: str


@dataclass(frozen=True, slots=True)
class Service:
    name: str
    image: str | None = None
    build: dict[str, Any] | None = None
    ports: tuple[Port, ...] = ()
    mounts: tuple[Mount, ...] = ()
    environment: dict[str, str] = field(default_factory=dict)
    env_files: tuple[str, ...] = ()
    depends_on: dict[str, str] = field(default_factory=dict)
    healthcheck: dict[str, Any] | None = None
    restart: str | None = None
    privileged: bool = False
    cap_add: tuple[str, ...] = ()
    user: str | None = None
    network_mode: str | None = None
    container_name: str | None = None
    networks: tuple[str, ...] = ()
    limits: dict[str, str] = field(default_factory=dict)
    logging: dict[str, Any] | None = None
    read_only: bool = False

    @property
    def where(self) -> str:
        return f"services.{self.name}"


@dataclass(frozen=True, slots=True)
class Project:
    path: Path
    services: dict[str, Service]
    name: str | None = None
    version: str | None = None
    volumes: dict[str, Any] = field(default_factory=dict)
    networks: dict[str, Any] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)
    env_example: dict[str, str] = field(default_factory=dict)
    env_path: Path | None = None
    env_example_path: Path | None = None
    gitignore: tuple[str, ...] = ()

    @property
    def folder(self) -> Path:
        return self.path.parent


def find_compose(path: Path) -> Path:
    """Путь к compose-файлу: либо он сам, либо первый подходящий в папке."""
    if path.is_dir():
        for name in COMPOSE_NAMES:
            candidate = path / name
            if candidate.exists():
                return candidate
        raise LoadError(f"В папке {path} нет ни одного из файлов: {', '.join(COMPOSE_NAMES)}")
    if not path.exists():
        raise LoadError(f"Файл {path} не найден")
    return path


def load(path: Path) -> Project:
    """Читает compose и всё, что лежит рядом: .env, пример окружения, .gitignore."""
    compose = find_compose(Path(path))
    try:
        raw = yaml.safe_load(compose.read_text("utf-8"))
    except OSError as exc:
        raise LoadError(f"Не удалось прочитать {compose.name}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise LoadError(f"{compose.name}: файл не разобрать как YAML ({_yaml_place(exc)})") from exc

    if raw is None:
        raise LoadError(f"{compose.name}: файл пуст")
    if not isinstance(raw, dict):
        raise LoadError(f"{compose.name}: ожидался словарь с ключом «services»")
    services_raw = raw.get("services")
    if not isinstance(services_raw, dict) or not services_raw:
        raise LoadError(f"{compose.name}: нет ни одного сервиса в разделе «services»")

    services = {str(name): _service(str(name), body) for name, body in services_raw.items()}
    folder = compose.parent
    env_path = _first_existing(folder, ENV_NAMES)
    example_path = _first_existing(folder, EXAMPLE_NAMES)
    return Project(
        path=compose,
        services=services,
        name=_text(raw.get("name")),
        version=_text(raw.get("version")),
        volumes=_mapping(raw.get("volumes")),
        networks=_mapping(raw.get("networks")),
        env=_env_or_empty(env_path),
        env_example=_env_or_empty(example_path),
        env_path=env_path,
        env_example_path=example_path,
        gitignore=_gitignore(folder),
    )


def _service(name: str, body: object) -> Service:
    if not isinstance(body, dict):
        raise LoadError(f"services.{name}: ожидался словарь настроек сервиса")
    deploy = _mapping(body.get("deploy"))
    resources = _mapping(deploy.get("resources"))
    limits = {str(key): str(value) for key, value in _mapping(resources.get("limits")).items()}
    for legacy, modern in (("mem_limit", "memory"), ("cpus", "cpus")):
        if body.get(legacy) is not None:
            limits.setdefault(modern, str(body[legacy]))
    return Service(
        name=name,
        image=_text(body.get("image")),
        build=_mapping(body.get("build")) if body.get("build") is not None else None,
        ports=tuple(_port(item, name) for item in _sequence(body.get("ports"))),
        mounts=tuple(_mount(item, name) for item in _sequence(body.get("volumes"))),
        environment=_environment(body.get("environment"), name),
        env_files=tuple(str(item) for item in _sequence(body.get("env_file"))),
        depends_on=_depends(body.get("depends_on"), name),
        healthcheck=_mapping(body.get("healthcheck")) if body.get("healthcheck") is not None else None,
        restart=_text(body.get("restart")) or _text(deploy.get("restart_policy")),
        privileged=bool(body.get("privileged", False)),
        cap_add=tuple(str(item).upper() for item in _sequence(body.get("cap_add"))),
        user=_text(body.get("user")),
        network_mode=_text(body.get("network_mode")),
        container_name=_text(body.get("container_name")),
        networks=tuple(_networks(body.get("networks"))),
        limits=limits,
        logging=_mapping(body.get("logging")) if body.get("logging") is not None else None,
        read_only=bool(body.get("read_only", False)),
    )


def _port(item: object, service: str) -> Port:
    if isinstance(item, dict):
        return Port(
            target=str(item.get("target", "")),
            published=_text(item.get("published")),
            host_ip=_text(item.get("host_ip")),
            protocol=_text(item.get("protocol")) or "tcp",
            raw=str(item),
        )
    raw = str(item)
    body, _, protocol = raw.partition("/")
    parts = body.split(":")
    if len(parts) == 1:
        return Port(target=parts[0], published=None, host_ip=None, protocol=protocol or "tcp", raw=raw)
    if len(parts) == 2:
        return Port(target=parts[1], published=parts[0], host_ip=None, protocol=protocol or "tcp", raw=raw)
    if len(parts) >= 3:
        return Port(
            target=parts[-1],
            published=parts[-2],
            host_ip=":".join(parts[:-2]),
            protocol=protocol or "tcp",
            raw=raw,
        )
    raise LoadError(f"services.{service}: не разобрать порт «{raw}»")


def _mount(item: object, service: str) -> Mount:
    if isinstance(item, dict):
        source = _text(item.get("source"))
        kind = str(item.get("type", "volume"))
        return Mount(
            source=source,
            target=str(item.get("target", "")),
            read_only=bool(item.get("read_only", False)),
            kind="привязка" if kind == "bind" else ("анонимный" if source is None else "том"),
            raw=str(item),
        )
    raw = str(item)
    parts = raw.split(":")
    if len(parts) == 1:
        return Mount(source=None, target=parts[0], read_only=False, kind="анонимный", raw=raw)
    # Одна буква перед двоеточием — это диск Windows (C:\data). Точка или тильда так выглядеть не могут:
    # «.:/app» — обычная привязка текущей папки.
    drive = len(parts[0]) == 1 and parts[0].isalpha()
    if len(parts) == 2 and drive:
        raise LoadError(f"services.{service}: том «{raw}» без точки монтирования")
    source = parts[0]
    if len(parts) >= 3 and drive and parts[1].startswith(("/", "\\")):
        source = ":".join(parts[:2])  # путь Windows вида C:\data
        parts = [source, *parts[2:]]
    target = parts[1]
    flags = parts[2].split(",") if len(parts) > 2 else []
    kind = "привязка" if source.startswith(BIND_PREFIXES) or drive else "том"
    return Mount(source=source, target=target, read_only="ro" in flags, kind=kind, raw=raw)


def _environment(raw: object, service: str) -> dict[str, str]:
    values: dict[str, str] = {}
    if raw is None:
        return values
    if isinstance(raw, dict):
        return {str(key): "" if value is None else str(value) for key, value in raw.items()}
    if isinstance(raw, list):
        for item in raw:
            text = str(item)
            name, _, value = text.partition("=")
            values[name.strip()] = value.strip()
        return values
    raise LoadError(f"services.{service}: «environment» — список или словарь")


def _depends(raw: object, service: str) -> dict[str, str]:
    if raw is None:
        return {}
    if isinstance(raw, list):
        return {str(item): "" for item in raw}
    if isinstance(raw, dict):
        return {str(key): str(_mapping(value).get("condition", "")) for key, value in raw.items()}
    raise LoadError(f"services.{service}: «depends_on» — список или словарь")


def _networks(raw: object) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(item) for item in raw]
    if isinstance(raw, dict):
        return [str(key) for key in raw]
    return [str(raw)]


def _sequence(raw: object) -> list[Any]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return list(raw)
    return [raw]


def _mapping(raw: object) -> dict[str, Any]:
    if isinstance(raw, dict):
        return {str(key): value for key, value in raw.items()}
    return {}


def _text(raw: object) -> str | None:
    if raw is None:
        return None
    text = str(raw).strip()
    return text or None


def _first_existing(folder: Path, names: tuple[str, ...]) -> Path | None:
    for name in names:
        candidate = folder / name
        if candidate.exists():
            return candidate
    return None


def _env_or_empty(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    try:
        return read_env(path)
    except EnvError:
        return {}


def _gitignore(folder: Path) -> tuple[str, ...]:
    for candidate in (folder / ".gitignore", folder.parent / ".gitignore"):
        if candidate.exists():
            try:
                return tuple(line.strip() for line in candidate.read_text("utf-8").splitlines() if line.strip())
            except OSError:
                return ()
    return ()


def _yaml_place(exc: yaml.YAMLError) -> str:
    mark = getattr(exc, "problem_mark", None)
    if mark is None:
        return "разбор не удался"
    return f"строка {mark.line + 1}, столбец {mark.column + 1}"
