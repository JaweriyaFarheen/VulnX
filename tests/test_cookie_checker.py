from scanner.checks.cookie_checker import analyze_cookies


def test_detects_missing_cookie_attributes():
    findings = analyze_cookies(
        "https://example.com",
        [
            "sessionid=abc123; Path=/"
        ],
    )

    titles = {finding.title for finding in findings}

    assert "Cookie Missing Secure Attribute" in titles
    assert "Cookie Missing HttpOnly Attribute" in titles
    assert "Cookie Missing SameSite Attribute" in titles


def test_accepts_properly_configured_cookie():
    findings = analyze_cookies(
        "https://example.com",
        [
            (
                "sessionid=abc123; Path=/; Secure; "
                "HttpOnly; SameSite=Lax"
            )
        ],
    )

    assert findings == []


def test_detects_samesite_none_without_secure():
    findings = analyze_cookies(
        "https://example.com",
        [
            "sessionid=abc123; Path=/; HttpOnly; SameSite=None"
        ],
    )

    titles = {finding.title for finding in findings}

    assert "SameSite=None Without Secure" in titles
    assert "Cookie Missing Secure Attribute" in titles


def test_http_cookie_is_not_flagged_for_missing_secure():
    findings = analyze_cookies(
        "http://example.com",
        [
            "preference=dark; Path=/; HttpOnly; SameSite=Lax"
        ],
    )

    titles = {finding.title for finding in findings}

    assert "Cookie Missing Secure Attribute" not in titles


def test_ignores_empty_and_malformed_headers():
    findings = analyze_cookies(
        "https://example.com",
        [
            "",
            "invalid-cookie-header",
            "   ",
        ],
    )

    assert findings == []


def test_cookie_values_are_not_exposed_in_evidence():
    findings = analyze_cookies(
        "https://example.com",
        [
            "sessionid=secret-session-token; Path=/"
        ],
    )

    assert findings

    for finding in findings:
        assert "secret-session-token" not in finding.evidence
        assert "sessionid" in finding.evidence

def test_detects_secure_prefix_without_secure_attribute():
    findings = analyze_cookies(
        "https://example.com/",
        [
            "__Secure-session=secret; Path=/; HttpOnly"
        ],
    )

    titles = {finding.title for finding in findings}

    assert "Cookie Missing Secure Attribute" in titles
    assert "Secure Cookie Prefix Requirement Not Met" in titles


def test_detects_host_prefix_requirements():
    findings = analyze_cookies(
        "https://example.com/",
        [
            "__Host-session=secret; Path=/; Secure; HttpOnly"
        ],
    )

    titles = {finding.title for finding in findings}

    assert "Host Cookie Prefix Requirements Not Met" not in titles


def test_detects_host_prefix_with_domain_attribute():
    findings = analyze_cookies(
        "https://example.com/",
        [
            "__Host-session=secret; Path=/; Secure; "
            "HttpOnly; Domain=example.com"
        ],
    )

    titles = {finding.title for finding in findings}

    assert "Host Cookie Prefix Requirements Not Met" in titles


def test_invalid_url_returns_no_cookie_findings():
    findings = analyze_cookies(
        "not-a-url",
        [
            "sessionid=secret; Path=/"
        ],
    )

    assert findings == []


def test_cookie_values_never_appear_in_any_finding():
    secret_value = "sensitive-session-value"

    findings = analyze_cookies(
        "https://example.com/",
        [
            f"sessionid={secret_value}; Path=/"
        ],
    )

    assert findings

    for finding in findings:
        assert secret_value not in finding.evidence
        assert secret_value not in finding.description
        assert secret_value not in finding.recommendation     
