"""
VulnX - Cookie Security Analyzer

Performs passive analysis of Set-Cookie response headers.

Findings represent configuration observations and do not
independently prove that a vulnerability is exploitable.
"""

from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass
class CookieFinding:
    """Represents a cookie security observation."""

    title: str
    cookie_name: str
    severity: str
    confidence: str
    evidence: str
    description: str
    recommendation: str


VALID_SAMESITE_VALUES = {
    "strict",
    "lax",
    "none",
}


def _add_finding(
    findings: list[CookieFinding],
    *,
    title: str,
    cookie_name: str,
    severity: str,
    confidence: str,
    evidence: str,
    description: str,
    recommendation: str,
) -> None:
    """Add a finding only once per cookie and finding type."""

    key = (title, cookie_name.lower())

    for existing in findings:
        if (existing.title, existing.cookie_name.lower()) == key:
            return

    findings.append(
        CookieFinding(
            title=title,
            cookie_name=cookie_name,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            description=description,
            recommendation=recommendation,
        )
    )


def analyze_cookies(
    url: str,
    set_cookie_headers: list[str],
) -> list[CookieFinding]:
    """
    Analyze individual Set-Cookie headers.

    Args:
        url: URL that returned the cookies.
        set_cookie_headers: Individual Set-Cookie header values.

    Returns:
        A list of cookie security observations.

    Cookie values are never included in findings.
    """

    findings: list[CookieFinding] = []

    try:
        parsed_url = urlsplit(url)

        if parsed_url.scheme.lower() not in {"http", "https"}:
            return findings

        if not parsed_url.hostname:
            return findings

        is_https = parsed_url.scheme.lower() == "https"

    except (TypeError, ValueError):
        return findings

    for header in set_cookie_headers or []:

        if not isinstance(header, str) or not header.strip():
            continue

        parts = [
            part.strip()
            for part in header.split(";")
            if part.strip()
        ]

        if not parts or "=" not in parts[0]:
            continue

        cookie_name, _cookie_value = parts[0].split("=", 1)
        cookie_name = cookie_name.strip()

        if not cookie_name:
            continue

        # Cookie names must not contain whitespace or separators.
        # Invalid names are skipped rather than interpreted as valid cookies.
        if any(
            char.isspace() or char in '()<>@,;:\\"/[]?={}'
            for char in cookie_name
        ):
            continue

        attributes: dict[str, str | bool] = {}

        for part in parts[1:]:

            if "=" in part:
                key, value = part.split("=", 1)
                key = key.strip().lower()

                # Preserve the first attribute occurrence.
                if key and key not in attributes:
                    attributes[key] = value.strip()

            else:
                key = part.strip().lower()

                if key and key not in attributes:
                    attributes[key] = True

        evidence = f"Cookie name: {cookie_name}"

        has_secure = "secure" in attributes
        has_httponly = "httponly" in attributes

        # --------------------------------------------------
        # Secure attribute
        # --------------------------------------------------

        if is_https and not has_secure:

            _add_finding(
                findings,
                title="Cookie Missing Secure Attribute",
                cookie_name=cookie_name,
                severity="Medium",
                confidence="High",
                evidence=evidence,
                description=(
                    "The cookie was received over HTTPS without the "
                    "Secure attribute. If the cookie is later sent "
                    "over an unencrypted HTTP connection, its contents "
                    "could be exposed."
                ),
                recommendation=(
                    "Set Secure on cookies that must only be sent "
                    "over HTTPS. Verify the application's HTTP-to-HTTPS "
                    "behavior and cookie requirements."
                ),
            )

        # --------------------------------------------------
        # HttpOnly attribute
        # --------------------------------------------------

        if not has_httponly:

            _add_finding(
                findings,
                title="Cookie Missing HttpOnly Attribute",
                cookie_name=cookie_name,
                severity="Low",
                confidence="Medium",
                evidence=evidence,
                description=(
                    "The cookie does not explicitly restrict access "
                    "through ordinary browser JavaScript cookie APIs. "
                    "Whether this creates a security concern depends "
                    "on the cookie's purpose and application design."
                ),
                recommendation=(
                    "Use HttpOnly for session and other sensitive "
                    "cookies that do not require JavaScript access. "
                    "Leave it off only when client-side access is "
                    "intentionally required."
                ),
            )

        # --------------------------------------------------
        # SameSite attribute
        # --------------------------------------------------

        same_site = attributes.get("samesite")

        if same_site is None:

            _add_finding(
                findings,
                title="Cookie Missing SameSite Attribute",
                cookie_name=cookie_name,
                severity="Low",
                confidence="Medium",
                evidence=evidence,
                description=(
                    "The cookie does not explicitly declare a SameSite "
                    "policy. Browser defaults and the security impact "
                    "depend on the cookie's purpose and usage."
                ),
                recommendation=(
                    "Explicitly configure SameSite=Lax or Strict "
                    "where appropriate. Use SameSite=None only when "
                    "cross-site cookie behavior is required, together "
                    "with Secure."
                ),
            )

        elif isinstance(same_site, str):

            normalized_same_site = same_site.lower()

            if normalized_same_site not in VALID_SAMESITE_VALUES:

                _add_finding(
                    findings,
                    title="Invalid SameSite Attribute",
                    cookie_name=cookie_name,
                    severity="Low",
                    confidence="High",
                    evidence=evidence,
                    description=(
                        "The cookie declares an unrecognized SameSite "
                        "value. The browser may ignore the invalid "
                        "value or apply its default behavior."
                    ),
                    recommendation=(
                        "Use a supported SameSite value: Strict, Lax, "
                        "or None. SameSite=None requires Secure in "
                        "modern browsers."
                    ),
                )

            elif (
                normalized_same_site == "none"
                and not has_secure
            ):

                _add_finding(
                    findings,
                    title="SameSite=None Without Secure",
                    cookie_name=cookie_name,
                    severity="Medium",
                    confidence="High",
                    evidence=evidence,
                    description=(
                        "The cookie uses SameSite=None without the "
                        "Secure attribute. Modern browsers generally "
                        "require Secure for SameSite=None cookies."
                    ),
                    recommendation=(
                        "Add Secure when cross-site cookie behavior "
                        "is required, and verify compatibility with "
                        "the application's supported browsers."
                    ),
                )

        # --------------------------------------------------
        # __Secure- prefix
        # --------------------------------------------------

        if cookie_name.startswith("__Secure-") and not has_secure:

            _add_finding(
                findings,
                title="Secure Cookie Prefix Requirement Not Met",
                cookie_name=cookie_name,
                severity="Medium",
                confidence="High",
                evidence=evidence,
                description=(
                    "A cookie using the __Secure- prefix was received "
                    "without the Secure attribute. This does not meet "
                    "the prefix's browser-enforced requirements."
                ),
                recommendation=(
                    "Set the Secure attribute and serve the cookie "
                    "over HTTPS. Verify the resulting cookie behavior "
                    "in supported browsers."
                ),
            )

        # --------------------------------------------------
        # __Host- prefix
        # --------------------------------------------------

        if cookie_name.startswith("__Host-"):

            path_value = attributes.get("path")
            domain_value = attributes.get("domain")

            if (
                not has_secure
                or path_value != "/"
                or domain_value is not None
            ):

                _add_finding(
                    findings,
                    title="Host Cookie Prefix Requirements Not Met",
                    cookie_name=cookie_name,
                    severity="Medium",
                    confidence="High",
                    evidence=evidence,
                    description=(
                        "A cookie using the __Host- prefix does not "
                        "meet one or more expected requirements: "
                        "Secure must be present, Path must be '/', "
                        "and Domain must be absent."
                    ),
                    recommendation=(
                        "Serve the cookie over HTTPS with Secure and "
                        "Path=/, and omit the Domain attribute. Verify "
                        "the cookie against browser prefix requirements."
                    ),
                )

    return findings