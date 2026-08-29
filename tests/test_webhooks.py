"""Webhook target validation.

The webhook URL is a per-request form field, so an unvalidated one lets any
authenticated caller make the server issue requests into its own network and
POST the pack result there. Every URL here is a literal address, so nothing in
this module needs DNS.
"""

import pytest

from fuin.server.services.webhook_service import is_safe_url, parse_urls

INTERNAL = [
    "http://169.254.169.254/latest/meta-data/",  # cloud instance metadata
    "https://169.254.169.254/",
    "http://127.0.0.1:8000/hook",
    "https://127.0.0.1/hook",
    "http://[::1]/hook",
    "https://10.0.0.5/hook",
    "https://192.168.1.1/hook",
    "https://172.16.0.1/hook",
    "https://0.0.0.0/hook",
]


@pytest.mark.parametrize("url", INTERNAL)
def test_internal_targets_are_refused(url):
    assert is_safe_url(url) is False


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://127.0.0.1/",
        "ftp://example.com/",
        "not a url at all",
        "",
    ],
)
def test_non_http_schemes_are_refused(url):
    assert is_safe_url(url) is False


def test_plain_http_is_refused_by_default():
    """The payload carries the package name and pack report."""
    assert is_safe_url("http://93.184.216.34/hook") is False


def test_plain_http_can_be_opted_into(monkeypatch):
    monkeypatch.setenv("FUIN_WEBHOOK_ALLOW_HTTP", "true")

    assert is_safe_url("http://93.184.216.34/hook") is True


def test_public_https_target_is_allowed():
    assert is_safe_url("https://93.184.216.34/hook") is True


def test_parse_urls_drops_unsafe_targets_and_keeps_order():
    urls = parse_urls(
        "https://93.184.216.34/a,http://169.254.169.254/,https://93.184.216.35/b",
        "https://93.184.216.34/a",
    )

    assert urls == ["https://93.184.216.34/a", "https://93.184.216.35/b"]


def test_parse_urls_handles_empty_sources():
    assert parse_urls("", "") == []
