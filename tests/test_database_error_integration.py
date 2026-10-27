
from types import SimpleNamespace

from scanner.core import engine


def test_run_scan_records_database_error_finding(monkeypatch):
    """Verify database errors reach the ScanResult."""

    mock_response = SimpleNamespace(
        url="https://example.com/test",
        status_code=500,
        headers={"content-type": "text/plain"},
        body=(
            "Database error: "
            "ORA-01756: quoted string not properly terminated"
        ),
        set_cookie_headers=[],
    )

    monkeypatch.setattr(
        engine,
        "request",
        lambda url: mock_response,
    )

    result = engine.run_scan("https://example.com/test")

    assert result.error is None
    assert result.status_code == 500
    assert result.database_error_findings

    assert any(
        "Oracle" in finding.description
        for finding in result.database_error_findings
    )


def test_run_scan_has_no_database_finding_for_normal_response(
    monkeypatch,
):
    """Verify normal response content does not trigger a finding."""

    mock_response = SimpleNamespace(
        url="https://example.com/",
        status_code=200,
        headers={"content-type": "text/html"},
        body="<html><body>Welcome!</body></html>",
        set_cookie_headers=[],
    )

    monkeypatch.setattr(
        engine,
        "request",
        lambda url: mock_response,
    )

    result = engine.run_scan("https://example.com/")

    assert result.error is None
    assert result.database_error_findings == []
