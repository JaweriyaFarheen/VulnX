import pytest

from scanner.checks.tls_checker import inspect_tls


def test_rejects_http_url():
    with pytest.raises(ValueError):
        inspect_tls("http://example.com")


def test_rejects_missing_hostname():
    with pytest.raises(ValueError):
        inspect_tls("https://")


def test_rejects_invalid_port():
    with pytest.raises(ValueError):
        inspect_tls("https://example.com:99999")