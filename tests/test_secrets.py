from __future__ import annotations

import pytest

from doctor import secrets


@pytest.mark.parametrize("name", ["DB_PASSWORD", "api_key", "GITHUB_TOKEN", "PRIVATE_KEY", "AWS_SECRET_ACCESS_KEY"])
def test_sensitive_names(name: str) -> None:
    assert secrets.sensitive_name(name)


@pytest.mark.parametrize("name", ["API_URL", "PORT", "TZ", "LOG_LEVEL"])
def test_ordinary_names(name: str) -> None:
    assert not secrets.sensitive_name(name)


def test_literal_password_is_exposed() -> None:
    assert secrets.exposed("DB_PASSWORD", "s3cret-p@ssw0rd")


def test_substitution_is_not_a_leak() -> None:
    assert not secrets.exposed("DB_PASSWORD", "${DB_PASSWORD}")
    assert not secrets.exposed("DB_PASSWORD", "$DB_PASSWORD")


@pytest.mark.parametrize("value", ["", "changeme", "<your_password>", "redacted"])
def test_placeholder_is_not_a_leak(value: str) -> None:
    assert not secrets.exposed("DB_PASSWORD", value)


def test_long_random_value_is_suspicious() -> None:
    assert secrets.exposed("SOME_VALUE", "dGhpcy1pcy1hLXZlcnktbG9uZy1yYW5kb20tc3RyaW5n")


def test_short_ordinary_value_is_fine() -> None:
    assert not secrets.exposed("LOG_LEVEL", "debug")
    assert not secrets.exposed("API_URL", "http://api:8000")


def test_private_key_is_caught() -> None:
    assert secrets.exposed("CERT", "-----BEGIN RSA PRIVATE KEY-----")


def test_explanation_never_shows_the_value() -> None:
    text = secrets.why("DB_PASSWORD", "s3cret-p@ssw0rd")
    assert "s3cret-p@ssw0rd" not in text
    assert "***" in text
