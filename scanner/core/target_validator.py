"""
VulnX - Target URL Validator

Validates and normalizes HTTP/HTTPS target URLs.

DNS resolution is intentionally handled by the HTTP client so that
validation and IP pinning can use the same resolved addresses.
"""

import ipaddress
from urllib.parse import urlsplit, urlunsplit


class TargetValidationError(ValueError):
    """Raised when a target URL fails validation."""


def validate_target_url(url: str) -> str:
    """
    Validate and normalize an HTTP/HTTPS target URL.

    Rejects:
    - Empty or malformed URLs
    - Unsupported schemes
    - Embedded credentials
    - Localhost hostnames
    - Private, loopback, link-local, multicast, reserved,
      and unspecified literal IP addresses
    - Invalid hostnames and ports
    - Single-label internal hostnames

    Returns:
        A normalized URL without a trailing fragment.

    Security:
        Hostnames are syntax-validated here but are not resolved.
        The HTTP client must resolve each hostname, reject any
        non-public address, and pin the connection to a validated IP.
        Every redirect destination must be independently validated.
    """

    if not isinstance(url, str) or not url.strip():
        raise TargetValidationError("Target URL cannot be empty.")

    url = url.strip()

    if any(ord(char) < 32 or ord(char) == 127 for char in url):
        raise TargetValidationError(
            "Target URL contains invalid control characters."
        )

    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise TargetValidationError("Malformed target URL.") from exc

    scheme = parsed.scheme.lower()

    if scheme not in {"http", "https"}:
        raise TargetValidationError(
            "Only HTTP and HTTPS URLs are supported."
        )

    if not parsed.netloc or not parsed.hostname:
        raise TargetValidationError(
            "A valid hostname is required."
        )

    if parsed.username is not None or parsed.password is not None:
        raise TargetValidationError(
            "URLs containing embedded credentials are not allowed."
        )

    try:
        port = parsed.port
    except ValueError as exc:
        raise TargetValidationError(
            "The target URL contains an invalid port."
        ) from exc

    if port is not None and not 1 <= port <= 65535:
        raise TargetValidationError(
            "Port must be between 1 and 65535."
        )

    raw_hostname = parsed.hostname.rstrip(".")

    if not raw_hostname:
        raise TargetValidationError("A valid hostname is required.")

    # Convert internationalized domain names to their ASCII form
    # before hostname syntax validation and URL reconstruction.
    try:
        hostname = raw_hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise TargetValidationError(
            "Invalid internationalized hostname."
        ) from exc

    if not hostname:
        raise TargetValidationError("A valid hostname is required.")

    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise TargetValidationError(
            "Localhost targets are blocked by default."
        )

    # Literal IP addresses can be checked without DNS resolution.
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None

    if address is not None:
        if not address.is_global:
            raise TargetValidationError(
                "Non-public IP addresses are blocked by default."
            )

        # Use a canonical representation of literal IP addresses.
        hostname = str(address)

    else:
        if len(hostname) > 253:
            raise TargetValidationError("Hostname is too long.")

        labels = hostname.split(".")

        if len(labels) < 2:
            raise TargetValidationError(
                "A fully qualified public hostname is required."
            )

        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(
                char.isalnum() or char == "-"
                for char in label
            )
            for label in labels
        ):
            raise TargetValidationError(
                "Hostname contains invalid characters."
            )

    # Rebuild the authority using the validated hostname and port.
    # IPv6 literal addresses must be enclosed in square brackets.
    if ":" in hostname and not hostname.startswith("["):
        netloc = f"[{hostname}]"
    else:
        netloc = hostname

    if port is not None:
        default_port = 443 if scheme == "https" else 80

        if port != default_port:
            netloc = f"{netloc}:{port}"

    normalized_path = parsed.path or "/"

    return urlunsplit(
        (
            scheme,
            netloc,
            normalized_path,
            parsed.query,
            "",
        )
    )