"""Additional regression tests for HSTS configuration analysis."""

from scanner.checks.security_headers import analyze_security_headers


def _titles(headers):
    return {
        finding.title
        for finding in analyze_security_headers(
            "https://example.test",
            headers,
        )
    }


def test_hsts_max_age_zero_is_reported():
    titles = _titles({"Strict-Transport-Security": "max-age=0"})
    assert "HSTS max-age Disables HSTS" in titles


def test_hsts_missing_max_age_is_reported():
    titles = _titles({"Strict-Transport-Security": "includeSubDomains"})
    assert "HSTS max-age Missing or Invalid" in titles


def test_hsts_invalid_max_age_is_reported():
    titles = _titles({"Strict-Transport-Security": "max-age=abc"})
    assert "HSTS max-age Missing or Invalid" in titles


def test_hsts_short_max_age_is_reported_for_review():
    titles = _titles({"Strict-Transport-Security": "max-age=3600"})
    assert "HSTS max-age Is Short" in titles


def test_hsts_long_valid_max_age_is_not_flagged():
    titles = _titles({
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
    })
    assert "HSTS max-age Disables HSTS" not in titles
    assert "HSTS max-age Missing or Invalid" not in titles
    assert "HSTS max-age Is Short" not in titles


def test_hsts_is_not_checked_on_http():
    findings = analyze_security_headers(
        "http://example.test",
        {"Strict-Transport-Security": "max-age=0"},
    )
    assert not any("HSTS max-age" in finding.title for finding in findings)
