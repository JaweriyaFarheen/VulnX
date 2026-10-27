"""
VulnX - HTTP Security Header Analyzer

Analyzes HTTP response headers for common security
misconfigurations.

This module performs passive analysis. Findings represent
security observations and do not prove exploitability.
"""

import re
from dataclasses import dataclass
from typing import Literal


Severity = Literal[
    "Informational",
    "Low",
    "Medium",
    "High",
]


@dataclass
class SecurityFinding:
    """Represents a security observation."""

    title: str
    category: str
    severity: Severity
    confidence: str
    evidence: str
    description: str
    recommendation: str
    status: str = "Observation"


def normalize_headers(
    headers: dict[str, str],
) -> dict[str, str]:
    """
    Normalize header names to lowercase.

    Header names are case-insensitive. Values are stripped
    of surrounding whitespace.
    """

    return {
        str(name).strip().lower(): str(value).strip()
        for name, value in headers.items()
    }


def _parse_csp_directives(
    policy: str,
) -> dict[str, list[str]]:
    """
    Parse a CSP policy into directive names and values.

    Directive names are case-insensitive.

    If a directive occurs more than once, the first occurrence
    is retained for analysis, consistent with browser CSP
    parsing behavior for duplicate directives.

    This helper is intentionally lightweight. It is not a
    complete implementation of the CSP specification.
    """

    directives: dict[str, list[str]] = {}

    for raw_directive in policy.split(";"):
        parts = raw_directive.strip().split()

        if not parts:
            continue

        name = parts[0].lower()

        # Ignore duplicate directives after the first occurrence.
        if name in directives:
            continue

        directives[name] = [
            value.strip("'").lower()
            for value in parts[1:]
        ]

    return directives


def _effective_script_directives(
    directives: dict[str, list[str]],
) -> list[str] | None:
    """
    Return the effective script-related directive.

    CSP fallback order:
        script-src-elem
        script-src
        default-src

    For the general script execution policy, script-src-elem
    takes precedence for script elements. This helper uses the
    first applicable directive in that order for this specific
    passive check.

    Returns None when no applicable directive exists.
    """

    for name in (
        "script-src-elem",
        "script-src",
        "default-src",
    ):
        if name in directives:
            return directives[name]

    return None


def _analyze_csp(
    normalized: dict[str, str],
) -> list[SecurityFinding]:
    """
    Analyze enforced and report-only CSP headers.

    Missing-policy findings are based on the absence of an
    enforced Content-Security-Policy header.

    Weak-policy findings are generated only when unsafe-eval
    occurs in an applicable script directive.
    """

    findings: list[SecurityFinding] = []

    enforced_csp = normalized.get(
        "content-security-policy"
    )

    report_only_csp = normalized.get(
        "content-security-policy-report-only"
    )

    if not enforced_csp:
        if report_only_csp:
            findings.append(
                SecurityFinding(
                    title="CSP Report-Only Without Enforced Policy",
                    category="Security Misconfiguration",
                    severity="Low",
                    confidence="High",
                    evidence=(
                        "Content-Security-Policy-Report-Only is present, "
                        "but Content-Security-Policy is absent."
                    ),
                    description=(
                        "The response defines a reporting-only CSP but "
                        "does not provide an enforced CSP through these "
                        "response headers. Report-only policies monitor "
                        "violations rather than enforcing restrictions."
                    ),
                    recommendation=(
                        "Review reported violations and, after testing, "
                        "deploy an appropriate enforced "
                        "Content-Security-Policy header."
                    ),
                )
            )

        else:
            findings.append(
                SecurityFinding(
                    title="Content Security Policy Missing",
                    category="Security Misconfiguration",
                    severity="Medium",
                    confidence="High",
                    evidence=(
                        "Content-Security-Policy header is absent."
                    ),
                    description=(
                        "The response does not define an enforced "
                        "Content Security Policy. A suitable policy can "
                        "help reduce the impact of certain cross-site "
                        "scripting attacks."
                    ),
                    recommendation=(
                        "Define and test an appropriate Content Security "
                        "Policy. Consider report-only mode during policy "
                        "development, then deploy an enforced policy."
                    ),
                )
            )

    # Inspect the enforced policy, not the report-only policy.
    if enforced_csp:
        directives = _parse_csp_directives(enforced_csp)

        script_sources = _effective_script_directives(
            directives
        )

        if (
            script_sources is not None
            and "unsafe-eval" in script_sources
        ):
            findings.append(
                SecurityFinding(
                    title="CSP Allows unsafe-eval",
                    category="Security Misconfiguration",
                    severity="Low",
                    confidence="High",
                    evidence=(
                        "An applicable enforced CSP script directive "
                        "contains 'unsafe-eval'."
                    ),
                    description=(
                        "The enforced Content Security Policy permits "
                        "dynamic code evaluation in the applicable "
                        "script context. This can weaken protection "
                        "against some script-injection attacks."
                    ),
                    recommendation=(
                        "Remove 'unsafe-eval' if the application does "
                        "not require it. Test application compatibility "
                        "before changing the policy."
                    ),
                )
            )

    return findings


def analyze_security_headers(
    url: str,
    headers: dict[str, str],
) -> list[SecurityFinding]:
    """
    Analyze HTTP response headers for common misconfigurations.

    Args:
        url: URL associated with the HTTP response.
        headers: HTTP response headers.

    Returns:
        A list of security observations.
    """

    normalized = normalize_headers(headers)
    findings: list[SecurityFinding] = []

    is_https = url.lower().startswith("https://")

    # Content Security Policy.
    findings.extend(
        _analyze_csp(normalized)
    )

    # HTTP Strict Transport Security.
    # HSTS is only meaningful when delivered over HTTPS.
    hsts = normalized.get("strict-transport-security")

    if is_https and not hsts:
        findings.append(
            SecurityFinding(
                title="HSTS Header Missing",
                category="Security Misconfiguration",
                severity="Low",
                confidence="High",
                evidence=(
                    "Strict-Transport-Security header is absent "
                    "from an HTTPS response."
                ),
                description=(
                    "The response does not instruct compatible "
                    "browsers to prefer HTTPS for future requests."
                ),
                recommendation=(
                    "Consider enabling HSTS after confirming that "
                    "HTTPS works correctly across the intended domain."
                ),
            )
        )
    elif is_https and hsts:
        # Parse max-age without assuming directive order or casing.
        max_age_match = None
        for directive in hsts.split(";"):
            directive = directive.strip()
            match = re.fullmatch(
                r"max-age\s*=\s*([^;\s]+)",
                directive,
                flags=re.IGNORECASE,
            )
            if match:
                max_age_match = match.group(1)
                break

        if max_age_match is None or not max_age_match.isdigit():
            findings.append(
                SecurityFinding(
                    title="HSTS max-age Missing or Invalid",
                    category="Security Misconfiguration",
                    severity="Low",
                    confidence="High",
                    evidence=(
                        "Strict-Transport-Security is present, but "
                        "max-age is missing or is not a non-negative integer."
                    ),
                    description=(
                        "Browsers need a valid max-age value to determine "
                        "how long to remember the HSTS policy."
                    ),
                    recommendation=(
                        "Set a valid max-age in seconds. Choose the duration "
                        "based on the domain's HTTPS readiness and deployment policy."
                    ),
                )
            )
        else:
            max_age = int(max_age_match)

            if max_age == 0:
                findings.append(
                    SecurityFinding(
                        title="HSTS max-age Disables HSTS",
                        category="Security Misconfiguration",
                        severity="Medium",
                        confidence="High",
                        evidence="Strict-Transport-Security specifies max-age=0.",
                        description=(
                            "A max-age of zero instructs browsers to clear "
                            "the remembered HSTS policy for the host."
                        ),
                        recommendation=(
                            "If HSTS is intended, configure a positive max-age "
                            "after confirming HTTPS works correctly."
                        ),
                    )
                )
            elif max_age < 15552000:
                findings.append(
                    SecurityFinding(
                        title="HSTS max-age Is Short",
                        category="Security Misconfiguration",
                        severity="Informational",
                        confidence="Medium",
                        evidence=(
                            f"Strict-Transport-Security max-age is {max_age} "
                            "seconds, less than the 180-day review threshold."
                        ),
                        description=(
                            "A shorter HSTS duration means browsers remember "
                            "the HTTPS-only policy for less time. Whether this "
                            "is appropriate depends on the deployment."
                        ),
                        recommendation=(
                            "Review whether a longer max-age is appropriate. "
                            "Increase it only after confirming HTTPS is reliable "
                            "across the intended host and subdomains."
                        ),
                    )
                )

    # X-Content-Type-Options.
    content_type_options = normalized.get(
        "x-content-type-options"
    )

    if (
        content_type_options is None
        or content_type_options.lower() != "nosniff"
    ):
        findings.append(
            SecurityFinding(
                title="X-Content-Type-Options Not Properly Set",
                category="Security Misconfiguration",
                severity="Low",
                confidence="High",
                evidence=(
                    "X-Content-Type-Options is missing or is not "
                    "set to 'nosniff'."
                ),
                description=(
                    "Browsers may perform MIME-type sniffing in some "
                    "contexts when this header is not configured."
                ),
                recommendation=(
                    "Set X-Content-Type-Options: nosniff where "
                    "appropriate for the application."
                ),
            )
        )

    # Referrer Policy.
    referrer_policy = normalized.get(
        "referrer-policy"
    )

    if not referrer_policy:
        findings.append(
            SecurityFinding(
                title="Referrer Policy Missing",
                category="Security Misconfiguration",
                severity="Informational",
                confidence="High",
                evidence=(
                    "Referrer-Policy header is absent."
                ),
                description=(
                    "The response does not explicitly define a "
                    "Referrer Policy."
                ),
                recommendation=(
                    "Consider an appropriate policy, such as "
                    "'strict-origin-when-cross-origin', based on "
                    "the application's privacy requirements."
                ),
            )
        )

    # Permissions Policy.
    permissions_policy = normalized.get(
        "permissions-policy"
    )

    if not permissions_policy:
        findings.append(
            SecurityFinding(
                title="Permissions Policy Missing",
                category="Security Misconfiguration",
                severity="Informational",
                confidence="High",
                evidence=(
                    "Permissions-Policy header is absent."
                ),
                description=(
                    "The response does not explicitly configure "
                    "Permissions Policy restrictions for browser features."
                ),
                recommendation=(
                    "Review the browser features the application uses "
                    "and define an appropriate Permissions Policy."
                ),
            )
        )

    # Server banner.
    server_header = normalized.get("server")

    if server_header:
        findings.append(
            SecurityFinding(
                title="Server Header Disclosed",
                category="Information Disclosure",
                severity="Informational",
                confidence="High",
                evidence=f"Server: {server_header}",
                description=(
                    "The response exposes a server identification "
                    "header. This is not, by itself, proof of a vulnerability."
                ),
                recommendation=(
                    "Consider minimizing unnecessary server details "
                    "if supported by the server configuration."
                ),
            )
        )

    # Deduplicate findings by stable identifying fields.
    unique_findings: dict[
        tuple[str, str, str],
        SecurityFinding,
    ] = {}

    for finding in findings:
        key = (
            finding.title,
            finding.category,
            finding.evidence,
        )
        unique_findings[key] = finding

    return list(unique_findings.values())