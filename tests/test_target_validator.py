import pytest

from scanner.core.target_validator import (
    TargetValidationError,
    validate_target_url,
)


@pytest.mark.parametrize(
    "url",
    [
        "",
        "not-a-url",
        "ftp://example.com",
        "file:///etc/passwd",
        "http://localhost",
        "http://localhost:8000",
        "http://127.0.0.1",
        "http://192.168.1.10",
        "http://10.0.0.5",
        "http://169.254.169.254",
        "https://user:password@example.com",
        "http://example.com:99999",
    ],
)
def test_rejects_invalid_or_unsafe_targets(url):
    """Reject malformed URLs and explicitly unsafe destinations."""

    with pytest.raises(TargetValidationError):
        validate_target_url(url)


def test_normalizes_url():
    """Normalize scheme, hostname, port, and fragment."""

    result = validate_target_url(
        "HTTPS://Example.COM:443/security#section"
    )

    assert result == "https://example.com/security"


def test_preserves_query_parameters():
    """Preserve query parameters during URL normalization."""

    result = validate_target_url(
        "https://example.com/search?q=test"
    )

    assert result == "https://example.com/search?q=test"