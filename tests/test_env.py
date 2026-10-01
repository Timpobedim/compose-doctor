from __future__ import annotations

import pytest

from doctor import env


def test_env_file_is_parsed() -> None:
    values = env.parse(
        """
        # комментарий
        DB_PASSWORD=тайна
        export API_URL=http://api:8000
        QUOTED="значение с пробелом"
        EMPTY=
        """.replace("        ", "")
    )
    assert values == {
        "DB_PASSWORD": "тайна",
        "API_URL": "http://api:8000",
        "QUOTED": "значение с пробелом",
        "EMPTY": "",
    }


def test_line_without_equals_is_refused() -> None:
    with pytest.raises(env.EnvError, match="строка 2"):
        env.parse("A=1\nпросто строка\n")


def test_inline_comment_is_cut() -> None:
    assert env.parse("PORT=8080 # порт наружу")["PORT"] == "8080"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("${DB_PASSWORD}", {"DB_PASSWORD"}),
        ("$HOST:8080", {"HOST"}),
        ("${API_URL:-http://localhost}", {"API_URL"}),
        ("постоянное значение", set()),
        ("${A}-${B}", {"A", "B"}),
    ],
)
def test_referenced_variables(value: str, expected: set[str]) -> None:
    assert env.referenced(value) == expected


def test_default_is_recognised() -> None:
    assert env.has_default("${PORT:-8080}", "PORT")
    assert env.has_default("${PORT-8080}", "PORT")
    assert not env.has_default("${PORT}", "PORT")


@pytest.mark.parametrize("value", ["", "changeme", "CHANGE_ME", "<your_password>", "ваш-ключ", "redacted"])
def test_placeholders_are_recognised(value: str) -> None:
    assert env.looks_like_placeholder(value)


def test_real_value_is_not_a_placeholder() -> None:
    assert not env.looks_like_placeholder("s3cret-p@ssw0rd")


def test_mask_hides_the_value() -> None:
    assert env.mask("s3cret-p@ssw0rd") == "s3***********rd"
    assert env.mask("abc") == "***"
    assert "s3cret" not in env.mask("s3cret-p@ssw0rd")[2:-2]
