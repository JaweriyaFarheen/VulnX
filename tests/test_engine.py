"""
VulnX - Scanning Engine Tests
"""

from unittest.mock import patch

from scanner.core.engine import run_scan
from scanner.core.http_client import (
    HTTPClientError,
    ScanResponse,
)


def test_run_scan_collects_security_findings():
    """Verify that the engine analyzes HTTP responses."""

    fake_response = ScanResponse(
        url="https://example.com/",
        status_code=200,
        headers={
            "Content-Type": "text/html",
            "Server": "ExampleServer",
        },
        body="<html><body>Test</body></html>",
        content_length=34,
        truncated=False,
        set_cookie_headers=[
            (
                "sessionid=example; Path=/; "
                "Secure; HttpOnly; SameSite=Lax"
            )
        ],
    )

    with patch(
        "scanner.core.engine.request",
        return_value=fake_response,
    ), patch(
        "scanner.core.engine.inspect_tls",
        return_value=None,
    ):

        result = run_scan("https://example.com/")

    assert result.status_code == 200
    assert result.final_url == "https://example.com/"
    assert result.error is None
    assert len(result.findings) > 0
    assert result.cookie_findings == []


def test_run_scan_handles_http_errors():
    """Verify that HTTP errors are handled gracefully."""

    with patch(
        "scanner.core.engine.request",
        side_effect=HTTPClientError(
            "Could not resolve target hostname."
        ),
    ):

        result = run_scan("https://example.com/")

    assert result.status_code is None
    assert result.error == "Could not resolve target hostname."
    assert result.findings == []
    assert result.cookie_findings == []


def test_run_scan_detects_cookie_misconfiguration():
    """Verify that the engine passes cookies to the analyzer."""

    fake_response = ScanResponse(
        url="https://example.com/",
        status_code=200,
        headers={
            "Content-Type": "text/html",
        },
        body="<html></html>",
        content_length=13,
        truncated=False,
        set_cookie_headers=[
            "sessionid=example; Path=/"
        ],
    )

    with patch(
        "scanner.core.engine.request",
        return_value=fake_response,
    ), patch(
        "scanner.core.engine.inspect_tls",
        return_value=None,
    ):

        result = run_scan("https://example.com/")

    titles = {
        finding.title
        for finding in result.cookie_findings
    }

    assert "Cookie Missing Secure Attribute" in titles
    assert "Cookie Missing HttpOnly Attribute" in titles
    assert "Cookie Missing SameSite Attribute" in titles


def test_run_scan_detects_database_error_disclosure():
    """The engine should detect database errors in responses."""

    response = ScanResponse(
        url="https://example.com",
        status_code=500,
        headers={},
        body="ORA-00933: SQL command not properly ended",
        set_cookie_headers=[],
        content_length=43,
        truncated=False,
    )

    with patch(
        "scanner.core.engine.request",
        return_value=response,
    ):
        result = run_scan("https://example.com")

    assert result.error is None
    assert len(result.database_error_findings) == 1

    finding = result.database_error_findings[0]

    assert finding.title == "Database Error Message Disclosed"
    assert finding.category == "Information Disclosure"

def test_run_scan_ignores_normal_database_response():
    """The engine should ignore responses without database errors."""

    response = ScanResponse(
        url="https://example.com",
        status_code=200,
        headers={},
        body="<html><body>Welcome!</body></html>",
        set_cookie_headers=[],
        content_length=35,
        truncated=False,
    )

    with patch(
        "scanner.core.engine.request",
        return_value=response,
    ):
        result = run_scan("https://example.com")

    assert result.error is None
    assert result.database_error_findings == []    