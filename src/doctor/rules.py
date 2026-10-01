"""Правила проверки: двадцать семь штук, каждое со своим кодом, уровнем и объяснением.

Правила делятся на три семьи: `S` — безопасность, `R` — надёжность выката, `M` — сопровождение.
Уровень определяется последствием, а не строгостью автора: «ошибка» — то, из-за чего выкат сломается
или утечёт секрет; «внимание» — то, что рано или поздно разбудит ночью; «совет» — то, что просто
делает конфигурацию понятнее.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Final

from doctor import secrets
from doctor.env import has_default, referenced
from doctor.findings import ERROR, HINT, WARNING, Finding, sort_findings
from doctor.project import Project

DANGEROUS_CAPS: Final = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "ALL"}
FLOATING_TAGS: Final = {"latest", "stable", "main", "master", "edge", "dev", "nightly", "rolling"}
DATA_PATHS: Final = ("/var/lib", "/data", "/var/www", "/srv", "/home")
DOCKER_SOCKET: Final = "/var/run/docker.sock"


@dataclass(frozen=True, slots=True)
class Rule:
    code: str
    level: str
    title: str
    about: str
    check: Callable[[Project], list[Finding]]


def run(project: Project, *, only: Sequence[str] = (), ignore: Sequence[str] = ()) -> list[Finding]:
    """Прогоняет правила. `only` и `ignore` принимают коды правил и буквы семей."""
    findings: list[Finding] = []
    for rule in RULES:
        if only and not _matches(rule.code, only):
            continue
        if ignore and _matches(rule.code, ignore):
            continue
        findings.extend(rule.check(project))
    return sort_findings(findings)


def _matches(code: str, selectors: Sequence[str]) -> bool:
    return any(code == item.upper() or code.startswith(item.upper()) for item in selectors)


# ── безопасность ────────────────────────────────────────────────────────────────────────────────


def _plain_secrets(project: Project) -> list[Finding]:
    found: list[Finding] = []
    for service in project.services.values():
        for name, value in service.environment.items():
            if secrets.exposed(name, value):
                found.append(
                    Finding(
                        code="S01",
                        level=ERROR,
                        where=f"{service.where}.environment.{name}",
                        title="секрет лежит в файле открытым текстом",
                        detail=f"{secrets.why(name, value)}; compose лежит в git — секрет уедет вместе с ним",
                        fix=f"вынести значение в .env и подставить: {name}: ${{{name}}}",
                    )
                )
    return found


def _privileged(project: Project) -> list[Finding]:
    return [
        Finding(
            code="S02",
            level=ERROR,
            where=service.where,
            title="контейнер запускается в привилегированном режиме",
            detail="privileged: true снимает почти все ограничения: такой контейнер может управлять хостом",
            fix="убрать privileged и выдать только нужные возможности через cap_add",
        )
        for service in project.services.values()
        if service.privileged
    ]


def _docker_socket(project: Project) -> list[Finding]:
    found: list[Finding] = []
    for service in project.services.values():
        for mount in service.mounts:
            if mount.source and DOCKER_SOCKET in mount.source:
                found.append(
                    Finding(
                        code="S03",
                        level=ERROR,
                        where=service.where,
                        title="внутрь контейнера проброшен сокет Docker",
                        detail="доступ к /var/run/docker.sock равен правам root на хосте",
                        fix="монтировать сокет только для чтения и через прокси с ограничением команд",
                    )
                )
    return found


def _host_network(project: Project) -> list[Finding]:
    return [
        Finding(
            code="S04",
            level=WARNING,
            where=service.where,
            title="сеть хоста вместо своей",
            detail="network_mode: host убирает изоляцию сети: контейнер видит все порты машины и занимает их напрямую",
            fix="оставить обычную сеть compose и опубликовать только нужные порты",
        )
        for service in project.services.values()
        if service.network_mode == "host"
    ]


def _root_user(project: Project) -> list[Finding]:
    return [
        Finding(
            code="S05",
            level=HINT,
            where=service.where,
            title="процесс в контейнере работает от root",
            detail="пользователь не задан или это root: пробой приложения сразу даёт root внутри контейнера",
            fix='добавить user: "1000:1000" и выдать права на нужные тома',
        )
        for service in project.services.values()
        if service.user in {None, "root", "0", "0:0"} and service.image is not None
    ]


def _public_ports(project: Project) -> list[Finding]:
    found: list[Finding] = []
    for service in project.services.values():
        for port in service.ports:
            if port.public:
                found.append(
                    Finding(
                        code="S06",
                        level=WARNING,
                        where=f"{service.where}.ports",
                        title=f"порт {port.raw} открыт на всех интерфейсах",
                        detail="без адреса Docker слушает 0.0.0.0 и обходит брандмауэр хоста: сервис виден из сети",
                        fix=f'указать адрес явно: "127.0.0.1:{port.published}:{port.target}"',
                    )
                )
    return found


def _dangerous_caps(project: Project) -> list[Finding]:
    found: list[Finding] = []
    for service in project.services.values():
        risky = sorted(set(service.cap_add) & DANGEROUS_CAPS)
        if risky:
            found.append(
                Finding(
                    code="S07",
                    level=WARNING,
                    where=service.where,
                    title=f"опасные возможности: {', '.join(risky)}",
                    detail="эти возможности почти равны привилегированному режиму",
                    fix="оставить только те возможности, без которых сервис не работает, и записать, зачем они",
                )
            )
    return found


def _env_in_git(project: Project) -> list[Finding]:
    if project.env_path is None:
        return []
    patterns = {line.strip("/") for line in project.gitignore}
    if patterns & {".env", ".env*", "*.env", ".env.*"}:
        return []
    return [
        Finding(
            code="S08",
            level=ERROR,
            where=".gitignore",
            title=".env не исключён из git",
            detail="рядом лежит .env с настоящими значениями, а в .gitignore его нет — он попадёт в первый же коммит",
            fix="добавить строку .env в .gitignore (а .env.example оставить в репозитории)",
        )
    ]


def _missing_env_files(project: Project) -> list[Finding]:
    found: list[Finding] = []
    for service in project.services.values():
        for name in service.env_files:
            if not (project.folder / name).exists():
                found.append(
                    Finding(
                        code="S09",
                        level=ERROR,
                        where=f"{service.where}.env_file",
                        title=f"файл переменных «{name}» не найден",
                        detail="compose не поднимет сервис: указанного файла нет рядом с конфигурацией",
                        fix=f"создать {name} или убрать ссылку на него",
                    )
                )
    return found


def _unknown_variables(project: Project) -> list[Finding]:
    known = set(project.env) | set(project.env_example)
    found: list[Finding] = []
    for service in project.services.values():
        for name, value in service.environment.items():
            for variable in sorted(referenced(value)):
                if variable in known or has_default(value, variable):
                    continue
                found.append(
                    Finding(
                        code="S10",
                        level=WARNING,
                        where=f"{service.where}.environment.{name}",
                        title=f"переменная ${{{variable}}} нигде не описана",
                        detail="её нет ни в .env, ни в примере: compose подставит пустую строку",
                        fix=f"добавить {variable} в .env.example или задать значение по умолчанию",
                    )
                )
    return found


# ── надёжность ──────────────────────────────────────────────────────────────────────────────────


def _no_restart(project: Project) -> list[Finding]:
    return [
        Finding(
            code="R01",
            level=WARNING,
            where=service.where,
            title="не задана политика перезапуска",
            detail="после перезагрузки машины или падения процесса контейнер не поднимется сам",
            fix="restart: unless-stopped",
        )
        for service in project.services.values()
        if service.restart is None
    ]


def _no_healthcheck(project: Project) -> list[Finding]:
    needed = {name for service in project.services.values() for name in service.depends_on}
    return [
        Finding(
            code="R02",
            level=WARNING,
            where=service.where,
            title="нет проверки здоровья, хотя от сервиса зависят другие",
            detail="зависимые стартуют, как только процесс запущен, — а он ещё не готов отвечать",
            fix='healthcheck: test: ["CMD", "curl", "-f", "http://localhost/health"]',
        )
        for name, service in project.services.items()
        if name in needed and service.healthcheck is None
    ]


def _depends_without_condition(project: Project) -> list[Finding]:
    found: list[Finding] = []
    for service in project.services.values():
        for name, condition in service.depends_on.items():
            if not condition:
                found.append(
                    Finding(
                        code="R03",
                        level=HINT,
                        where=f"{service.where}.depends_on.{name}",
                        title="зависимость без условия",
                        detail="короткая запись ждёт только запуска контейнера, а не его готовности",
                        fix=f"{name}: condition: service_healthy",
                    )
                )
    return found


def _unpinned_image(project: Project) -> list[Finding]:
    """R04: образа без тега или с latest быть не должно."""
    found: list[Finding] = []
    for service in project.services.values():
        if service.image is None:
            continue
        tag = _tag(service.image)
        if tag is None:
            found.append(
                Finding(
                    code="R04",
                    level=ERROR,
                    where=f"{service.where}.image",
                    title=f"образ без тега: {service.image}",
                    detail="без тега Docker берёт latest: в следующий раз приедет другая версия",
                    fix=f"указать версию: {service.image}:1.2.3",
                )
            )
        elif tag == "latest":
            found.append(
                Finding(
                    code="R04",
                    level=ERROR,
                    where=f"{service.where}.image",
                    title="тег latest",
                    detail="latest меняется молча: одинаковый конфиг на двух машинах поднимет разные версии",
                    fix="закрепить версию образа или его цифровой отпечаток (sha256)",
                )
            )
    return found


def _floating_tag(project: Project) -> list[Finding]:
    """R05: тег есть, но он плавающий — stable, main, edge и подобные."""
    found: list[Finding] = []
    for service in project.services.values():
        if service.image is None:
            continue
        tag = _tag(service.image)
        if tag is not None and tag != "latest" and tag in FLOATING_TAGS:
            found.append(
                Finding(
                    code="R05",
                    level=HINT,
                    where=f"{service.where}.image",
                    title=f"плавающий тег: {tag}",
                    detail="такой тег указывает на «последнюю в ветке» версию и меняется без предупреждения",
                    fix="закрепить точную версию, а обновления делать отдельным коммитом",
                )
            )
    return found


def _no_limits(project: Project) -> list[Finding]:
    return [
        Finding(
            code="R06",
            level=WARNING,
            where=service.where,
            title="нет ограничения памяти",
            detail="один протёкший контейнер съест память всей машины, и ядро убьёт не его, а соседа",
            fix="deploy: resources: limits: memory: 512M",
        )
        for service in project.services.values()
        if "memory" not in service.limits and service.image is not None
    ]


def _anonymous_data_volume(project: Project) -> list[Finding]:
    found: list[Finding] = []
    for service in project.services.values():
        for mount in service.mounts:
            if mount.kind == "анонимный" and mount.target.startswith(DATA_PATHS):
                found.append(
                    Finding(
                        code="R07",
                        level=WARNING,
                        where=f"{service.where}.volumes",
                        title=f"данные лежат в безымянном томе: {mount.target}",
                        detail="безымянный том теряется при пересоздании контейнера",
                        fix=f"дать тому имя: данные:{mount.target}",
                    )
                )
    return found


def _container_name(project: Project) -> list[Finding]:
    return [
        Finding(
            code="R08",
            level=HINT,
            where=service.where,
            title=f"жёсткое имя контейнера: {service.container_name}",
            detail="с фиксированным именем нельзя поднять вторую копию сервиса и нельзя выкатывать без простоя",
            fix="убрать container_name — compose назовёт контейнер сам",
        )
        for service in project.services.values()
        if service.container_name
    ]


def _port_conflicts(project: Project) -> list[Finding]:
    seen: dict[tuple[str, str], str] = {}
    found: list[Finding] = []
    for service in project.services.values():
        for port in service.ports:
            if port.published is None:
                continue
            key = (port.host_ip or "любой адрес", f"{port.published}/{port.protocol}")
            if key in seen and seen[key] != service.name:
                found.append(
                    Finding(
                        code="R09",
                        level=ERROR,
                        where=f"{service.where}.ports",
                        title=f"порт {port.published} занят сервисом «{seen[key]}»",
                        detail="два сервиса публикуют один и тот же порт: второй не поднимется",
                        fix="развести порты или оставить публикацию только у одного сервиса",
                    )
                )
            seen.setdefault(key, service.name)
    return found


def _unknown_dependency(project: Project) -> list[Finding]:
    found: list[Finding] = []
    for service in project.services.values():
        for name in service.depends_on:
            if name not in project.services:
                found.append(
                    Finding(
                        code="R10",
                        level=ERROR,
                        where=f"{service.where}.depends_on",
                        title=f"зависимость от несуществующего сервиса «{name}»",
                        detail="compose откажется запускать проект целиком",
                        fix=f"исправить опечатку в имени или описать сервис {name}",
                    )
                )
    return found


def _unused_declarations(project: Project) -> list[Finding]:
    used_volumes = {
        mount.source for service in project.services.values() for mount in service.mounts if mount.kind == "том"
    }
    used_networks = {name for service in project.services.values() for name in service.networks}
    found = [
        Finding(
            code="R11",
            level=HINT,
            where=f"volumes.{name}",
            title="объявленный том никто не использует",
            detail="лишнее объявление сбивает с толку: кажется, что данные где-то хранятся",
            fix=f"удалить том {name} или примонтировать его в сервис",
        )
        for name in project.volumes
        if name not in used_volumes
    ]
    found += [
        Finding(
            code="R11",
            level=HINT,
            where=f"networks.{name}",
            title="объявленная сеть никто не использует",
            detail="лишнее объявление сбивает с толку",
            fix=f"удалить сеть {name} или подключить к ней сервис",
        )
        for name in project.networks
        if name not in used_networks
    ]
    return found


def _undeclared_usage(project: Project) -> list[Finding]:
    found: list[Finding] = []
    for service in project.services.values():
        for mount in service.mounts:
            if mount.kind == "том" and mount.source and mount.source not in project.volumes:
                found.append(
                    Finding(
                        code="R12",
                        level=ERROR,
                        where=f"{service.where}.volumes",
                        title=f"том «{mount.source}» нигде не объявлен",
                        detail="compose не поднимет проект: именованный том должен быть описан в разделе volumes",
                        fix=f"добавить в конец файла:\nvolumes:\n  {mount.source}:",
                    )
                )
        for name in service.networks:
            if name not in project.networks:
                found.append(
                    Finding(
                        code="R12",
                        level=ERROR,
                        where=f"{service.where}.networks",
                        title=f"сеть «{name}» нигде не объявлена",
                        detail="compose не поднимет проект: сеть должна быть описана в разделе networks",
                        fix=f"добавить в конец файла:\nnetworks:\n  {name}:",
                    )
                )
    return found


# ── сопровождение ───────────────────────────────────────────────────────────────────────────────


def _obsolete_version(project: Project) -> list[Finding]:
    if project.version is None:
        return []
    return [
        Finding(
            code="M01",
            level=HINT,
            where="version",
            title="устаревший ключ version",
            detail="Compose Spec его не использует и печатает предупреждение при каждом запуске",
            fix="удалить строку version",
        )
    ]


def _missing_example(project: Project) -> list[Finding]:
    uses_env = any(
        service.env_files or referenced(value)
        for service in project.services.values()
        for value in service.environment.values()
    )
    if not uses_env or project.env_example_path is not None:
        return []
    return [
        Finding(
            code="M02",
            level=WARNING,
            where=str(project.path.name),
            title="нет примера окружения",
            detail="конфигурация ждёт переменных, но рядом нет .env.example",
            fix="создать .env.example с именами переменных и пустыми значениями",
        )
    ]


def _example_drift(project: Project) -> list[Finding]:
    if project.env_path is None or project.env_example_path is None:
        return []
    missing = sorted(set(project.env) - set(project.env_example))
    extra = sorted(set(project.env_example) - set(project.env))
    found: list[Finding] = []
    if missing:
        found.append(
            Finding(
                code="M03",
                level=WARNING,
                where=project.env_example_path.name,
                title=f"в примере нет переменных: {', '.join(missing)}",
                detail="они есть в .env, значит, нужны для работы — но на новой машине о них никто не узнает",
                fix="дописать эти имена в пример с пустыми значениями",
            )
        )
    if extra:
        found.append(
            Finding(
                code="M03",
                level=HINT,
                where=project.env_example_path.name,
                title=f"в примере есть лишние переменные: {', '.join(extra)}",
                detail="их нет в .env: либо они больше не нужны, либо про них забыли",
                fix="убрать лишние имена или добавить их в .env",
            )
        )
    return found


def _no_log_rotation(project: Project) -> list[Finding]:
    return [
        Finding(
            code="M04",
            level=HINT,
            where=service.where,
            title="логи не ограничены",
            detail="драйвер по умолчанию пишет в файл без ротации: разговорчивый сервис за месяц займёт весь диск",
            fix="logging: driver: json-file, options: max-size: 10m, max-file: 3",
        )
        for service in project.services.values()
        if service.logging is None and service.image is not None
    ]


def _nothing_to_run(project: Project) -> list[Finding]:
    return [
        Finding(
            code="M05",
            level=ERROR,
            where=service.where,
            title="сервис не описывает, что запускать",
            detail="нет ни image, ни build: compose не поймёт, откуда взять контейнер",
            fix="добавить image: имя:версия или раздел build",
        )
        for service in project.services.values()
        if service.image is None and service.build is None
    ]


def _tag(image: str) -> str | None:
    body = image.split("@")[0]
    if "/" in body:
        _, _, tail = body.rpartition("/")
        if ":" not in tail:
            return None
        return tail.split(":", 1)[1]
    if ":" not in body:
        return None
    return body.split(":", 1)[1]


RULES: Final[tuple[Rule, ...]] = (
    Rule("S01", ERROR, "секреты в открытом виде", "пароли и токены не должны лежать в compose", _plain_secrets),
    Rule("S02", ERROR, "привилегированный режим", "privileged: true равен правам root на хосте", _privileged),
    Rule(
        "S03", ERROR, "сокет Docker в контейнере", "монтирование docker.sock отдаёт управление хостом", _docker_socket
    ),
    Rule("S04", WARNING, "сеть хоста", "network_mode: host снимает изоляцию сети", _host_network),
    Rule("S05", HINT, "работа от root", "контейнеру почти никогда не нужен root", _root_user),
    Rule("S06", WARNING, "порт на всех интерфейсах", "публикация без адреса обходит брандмауэр", _public_ports),
    Rule("S07", WARNING, "опасные возможности", "SYS_ADMIN и подобные почти равны privileged", _dangerous_caps),
    Rule("S08", ERROR, ".env в репозитории", ".env с настоящими значениями не должен попасть в git", _env_in_git),
    Rule("S09", ERROR, "нет файла переменных", "env_file указывает на несуществующий файл", _missing_env_files),
    Rule(
        "S10",
        WARNING,
        "переменная не описана",
        "подстановка без значения превращается в пустую строку",
        _unknown_variables,
    ),
    Rule("R01", WARNING, "нет политики перезапуска", "после перезагрузки сервис не поднимется", _no_restart),
    Rule("R02", WARNING, "нет проверки здоровья", "зависимые сервисы стартуют раньше готовности", _no_healthcheck),
    Rule(
        "R03",
        HINT,
        "зависимость без условия",
        "короткая запись depends_on ждёт только запуска",
        _depends_without_condition,
    ),
    Rule("R04", ERROR, "образ без версии", "без тега или с latest выкат невоспроизводим", _unpinned_image),
    Rule("R05", HINT, "плавающий тег", "stable и main меняются без предупреждения", _floating_tag),
    Rule("R06", WARNING, "нет ограничения памяти", "протёкший контейнер уносит всю машину", _no_limits),
    Rule(
        "R07",
        WARNING,
        "данные в безымянном томе",
        "такой том теряется при пересоздании контейнера",
        _anonymous_data_volume,
    ),
    Rule("R08", HINT, "жёсткое имя контейнера", "мешает второй копии и выкату без простоя", _container_name),
    Rule("R09", ERROR, "конфликт портов", "два сервиса публикуют один порт", _port_conflicts),
    Rule(
        "R10",
        ERROR,
        "зависимость от несуществующего сервиса",
        "compose откажется запускать проект",
        _unknown_dependency,
    ),
    Rule("R11", HINT, "лишние объявления", "объявленные тома и сети никто не использует", _unused_declarations),
    Rule("R12", ERROR, "необъявленный том или сеть", "именованный том должен быть описан", _undeclared_usage),
    Rule("M01", HINT, "устаревший version", "Compose Spec игнорирует этот ключ", _obsolete_version),
    Rule(
        "M02", WARNING, "нет примера окружения", "новому человеку неоткуда узнать список переменных", _missing_example
    ),
    Rule("M03", WARNING, "пример разошёлся с .env", "имена переменных в примере и в .env не совпадают", _example_drift),
    Rule("M04", HINT, "логи без ротации", "драйвер по умолчанию пишет без ограничения размера", _no_log_rotation),
    Rule("M05", ERROR, "нечего запускать", "у сервиса нет ни image, ни build", _nothing_to_run),
)


def describe() -> list[tuple[str, str, str, str]]:
    """Список правил для команды «doctor rules»."""
    seen: set[str] = set()
    rows: list[tuple[str, str, str, str]] = []
    for rule in RULES:
        if rule.code in seen:
            continue
        seen.add(rule.code)
        rows.append((rule.code, rule.level, rule.title, rule.about))
    return rows
