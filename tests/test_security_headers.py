from scanner.checks.security_headers import (
    analyze_security_headers,
)


def test_detects_missing_security_headers():
    findings = analyze_security_headers(
        "https://example.com",
        {},
    )

    titles = {finding.title for finding in findings}

    assert "Content Security Policy Missing" in titles
    assert "HSTS Header Missing" in titles
    assert "X-Content-Type-Options Not Properly Set" in titles
    assert "Referrer Policy Missing" in titles
    assert "Permissions Policy Missing" in titles


def test_accepts_configured_security_headers():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=()",
    }

    findings = analyze_security_headers(
        "https://example.com",
        headers,
    )

    titles = {finding.title for finding in findings}

    assert "Content Security Policy Missing" not in titles
    assert "HSTS Header Missing" not in titles
    assert "X-Content-Type-Options Not Properly Set" not in titles
    assert "Referrer Policy Missing" not in titles
    assert "Permissions Policy Missing" not in titles


def test_hsts_not_required_for_http_response():
    findings = analyze_security_headers(
        "http://example.com",
        {},
    )

    titles = {finding.title for finding in findings}

    assert "HSTS Header Missing" not in titles


def test_finding_contains_remediation():
    findings = analyze_security_headers(
        "https://example.com",
        {},
    )

    assert findings

    for finding in findings:
        assert finding.title
        assert finding.severity
        assert finding.confidence
        assert finding.evidence
        assert finding.recommendation
        
def test_report_only_policy_does_not_count_as_enforced_csp():
    findings = analyze_security_headers(
        "https://example.com/",
        {
            "Content-Security-Policy-Report-Only":
                "default-src 'self'",
        },
    )

    titles = {finding.title for finding in findings}

    assert "CSP Report-Only Without Enforced Policy" in titles
    assert "Content Security Policy Missing" not in titles


def test_unsafe_eval_in_enforced_script_src_is_detected():
    findings = analyze_security_headers(
        "https://example.com/",
        {
            "Content-Security-Policy":
                "default-src 'self'; script-src 'self' 'unsafe-eval'",
        },
    )

    titles = {finding.title for finding in findings}

    assert "CSP Allows unsafe-eval" in titles


def test_unsafe_eval_in_unrelated_directive_is_not_flagged():
    findings = analyze_security_headers(
        "https://example.com/",
        {
            "Content-Security-Policy":
                "default-src 'self'; "
                "img-src https://unsafe-eval.example",
        },
    )

    titles = {finding.title for finding in findings}

    assert "CSP Allows unsafe-eval" not in titles


def test_report_only_unsafe_eval_is_not_reported_as_enforced():
    findings = analyze_security_headers(
        "https://example.com/",
        {
            "Content-Security-Policy-Report-Only":
                "script-src 'self' 'unsafe-eval'",
        },
    )

    titles = {finding.title for finding in findings}

    assert "CSP Allows unsafe-eval" not in titles
    assert "CSP Report-Only Without Enforced Policy" in titles


def test_enforced_csp_without_unsafe_eval_is_not_flagged():
    findings = analyze_security_headers(
        "https://example.com/",
        {
            "Content-Security-Policy":
                "default-src 'self'; script-src 'self'",
        },
    )

    titles = {finding.title for finding in findings}

    assert "CSP Allows unsafe-eval" not in titles
    assert "Content Security Policy Missing" not in titles        