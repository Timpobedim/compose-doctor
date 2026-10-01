"""Командная строка: check, rules, demo."""

from __future__ import annotations

import argparse
import io
import sys
from collections.abc import Sequence
from pathlib import Path

from doctor import demo as demo_module
from doctor import report as report_module
from doctor import rules
from doctor.env import EnvError
from doctor.findings import ERROR, WARNING, count
from doctor.project import LoadError, load


def main(argv: Sequence[str] | None = None) -> int:
    _utf8_console()
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (LoadError, EnvError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 2


def _utf8_console() -> None:
    """В стандартной консоли Windows кодировка cp866: без этого отчёт падает на первой же стрелке."""
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper) and stream.encoding.lower() not in {"utf-8", "utf8"}:
            stream.reconfigure(encoding="utf-8", errors="replace")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="doctor", description="Проверка docker compose и .env до выката")
    commands = parser.add_subparsers(dest="command", required=True)

    check = commands.add_parser("check", help="проверить файл или папку")
    check.add_argument("path", type=Path, nargs="?", default=Path(), help="compose-файл или папка с ним")
    check.add_argument("--strict", action="store_true", help="считать предупреждения ошибками")
    check.add_argument("--short", action="store_true", help="только строки находок, без объяснений")
    check.add_argument("--json", action="store_true", help="машинный вывод")
    check.add_argument("--only", default="", help="коды правил через запятую: S,R04")
    check.add_argument("--ignore", default="", help="что пропустить: M,R08")
    check.set_defaults(handler=_check)

    listing = commands.add_parser("rules", help="показать все правила")
    listing.set_defaults(handler=_rules)

    show = commands.add_parser("demo", help="показать проверку на двух примерах: как не надо и как надо")
    show.add_argument("--root", type=Path)
    show.set_defaults(handler=_demo)
    return parser


def _check(args: argparse.Namespace) -> int:
    project = load(args.path)
    findings = rules.run(project, only=_codes(args.only), ignore=_codes(args.ignore))
    if args.json:
        print(report_module.as_json(findings, path=project.path))
    else:
        print(report_module.report(findings, path=project.path, short=args.short))
    if count(findings, ERROR):
        return 1
    if args.strict and count(findings, WARNING):
        return 1
    return 0


def _rules(_: argparse.Namespace) -> int:
    print(report_module.rules_table())
    return 0


def _demo(args: argparse.Namespace) -> int:
    result = demo_module.run(root=args.root)
    print(result.text)
    return 0


def _codes(raw: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in raw.split(",") if item.strip())


if __name__ == "__main__":
    raise SystemExit(main())
