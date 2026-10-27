
"""
VulnX - Scanning Engine

Coordinates HTTP, security-header, cookie, TLS,
and database error disclosure analysis.
"""

from dataclasses import dataclass, field

from scanner.core.http_client import (
    HTTPClientError,
    request,
)

from scanner.checks.security_headers import (
    SecurityFinding,
    analyze_security_headers,
)

from scanner.checks.tls_checker import (
    TLSResult,
    inspect_tls,
)

from scanner.checks.cookie_checker import (
    CookieFinding,
    analyze_cookies,
)

from scanner.checks.sql_injection import (
    SQLInjectionFinding,
    analyze_database_errors,
)


@dataclass
class ScanResult:
    """Stores the results of a VulnX scan."""

    target_url: str
    final_url: str | None = None
    status_code: int | None = None

    # HTTP security-header findings.
    findings: list[SecurityFinding] = field(
        default_factory=list
    )

    # Cookie security findings.
    cookie_findings: list[CookieFinding] = field(
        default_factory=list
    )

    # Database error disclosure findings.
    database_error_findings: list[SQLInjectionFinding] = field(
        default_factory=list
    )

    # TLS inspection results.
    tls_result: TLSResult | None = None

    # Error encountered during scanning.
    error: str | None = None


def run_scan(target_url: str) -> ScanResult:
    """
    Execute a basic web security assessment.

    Checks:
    - HTTP response retrieval
    - HTTP security headers
    - Cookie security attributes
    - Passive database error disclosure
    - TLS certificate inspection

    If the HTTP request fails, TLS inspection is attempted
    independently for HTTPS targets.

    Database error detection is passive. It analyzes the
    returned response body and does not send SQL injection
    payloads or independently establish exploitability.
    """

    result = ScanResult(target_url=target_url)

    try:
        # Retrieve the HTTP response using the validated client.
        response = request(target_url)

        result.final_url = response.url
        result.status_code = response.status_code

        # --------------------------------------------------
        # 1. HTTP security-header analysis
        # --------------------------------------------------
        result.findings = analyze_security_headers(
            url=response.url,
            headers=response.headers,
        )

        # --------------------------------------------------
        # 2. Cookie security analysis
        # --------------------------------------------------
        result.cookie_findings = analyze_cookies(
            url=response.url,
            set_cookie_headers=response.set_cookie_headers,
        )

        # --------------------------------------------------
        # 3. Passive database error disclosure analysis
        # --------------------------------------------------
        result.database_error_findings = (
            analyze_database_errors(
                url=response.url,
                body=response.body,
            )
        )

        # --------------------------------------------------
        # 4. TLS inspection
        # --------------------------------------------------
        if response.url.lower().startswith("https://"):
            result.tls_result = inspect_tls(response.url)

    except HTTPClientError as exc:
        # Preserve the original HTTP request error.
        result.error = str(exc)

        # --------------------------------------------------
        # Attempt TLS inspection even when the HTTP request
        # fails, such as when certificate verification fails.
        # Certificate verification remains enabled.
        # --------------------------------------------------
        try:
            if target_url.lower().startswith("https://"):
                result.tls_result = inspect_tls(target_url)

        except (ValueError, OSError) as tls_exc:
            # Keep the original HTTP error and record the
            # additional inspection error without exposing
            # unnecessary exception details.
            result.error += (
                " | Additional TLS inspection error: "
                f"{type(tls_exc).__name__}"
            )

    return result
