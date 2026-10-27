"""
VulnX - TLS Certificate Checker

Inspects HTTPS certificate information.
Only use against authorized targets.
"""

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit


@dataclass
class TLSFinding:
    title: str
    severity: str
    confidence: str
    evidence: str
    description: str
    recommendation: str


@dataclass
class TLSResult:
    hostname: str
    port: int
    tls_version: str | None
    cipher: str | None
    certificate_expires: str | None
    findings: list[TLSFinding]
    error: str | None = None


def inspect_tls(
    url: str,
    timeout: float = 5.0,
) -> TLSResult:
    """
    Inspect a publicly reachable HTTPS endpoint.

    The default SSL context validates the certificate chain
    and hostname. This function does not disable verification.
    """

    parsed = urlsplit(url)

    if parsed.scheme.lower() != "https":
        raise ValueError("TLS inspection requires an HTTPS URL.")

    hostname = parsed.hostname

    if not hostname:
        raise ValueError("A valid hostname is required.")

    port = parsed.port or 443

    if not 1 <= port <= 65535:
        raise ValueError("Invalid port.")

    findings = []

    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (hostname, port),
            timeout=timeout,
        ) as raw_socket:

            with context.wrap_socket(
                raw_socket,
                server_hostname=hostname,
            ) as tls_socket:

                certificate = tls_socket.getpeercert()

                expiry_value = certificate.get("notAfter")

                expiry_date = None

                if expiry_value:
                    expiry_date = datetime.strptime(
                        expiry_value,
                        "%b %d %H:%M:%S %Y %Z",
                    ).replace(tzinfo=timezone.utc)

                current_time = datetime.now(timezone.utc)

                if expiry_date:
                    remaining = (
                        expiry_date - current_time
                    ).total_seconds()

                    if remaining < 0:
                        findings.append(
                            TLSFinding(
                                title="Certificate Expired",
                                severity="High",
                                confidence="High",
                                evidence=(
                                    f"Certificate expired on "
                                    f"{expiry_date.isoformat()}."
                                ),
                                description=(
                                    "The certificate's validity period "
                                    "has ended."
                                ),
                                recommendation=(
                                    "Renew the certificate and verify "
                                    "that the correct certificate chain "
                                    "is installed."
                                ),
                            )
                        )

                    elif remaining <= 30 * 24 * 60 * 60:
                        findings.append(
                            TLSFinding(
                                title="Certificate Expiring Soon",
                                severity="Medium",
                                confidence="High",
                                evidence=(
                                    f"Certificate expires on "
                                    f"{expiry_date.isoformat()}."
                                ),
                                description=(
                                    "The certificate expires within "
                                    "30 days."
                                ),
                                recommendation=(
                                    "Renew the certificate before "
                                    "its expiration date."
                                ),
                            )
                        )

                cipher_info = tls_socket.cipher()

                cipher_name = (
                    cipher_info[0]
                    if cipher_info
                    else None
                )

                return TLSResult(
                    hostname=hostname,
                    port=port,
                    tls_version=tls_socket.version(),
                    cipher=cipher_name,
                    certificate_expires=(
                        expiry_date.isoformat()
                        if expiry_date
                        else None
                    ),
                    findings=findings,
                )

    except ssl.SSLCertVerificationError as exc:
        return TLSResult(
            hostname=hostname,
            port=port,
            tls_version=None,
            cipher=None,
            certificate_expires=None,
            findings=[
                TLSFinding(
                    title="TLS Certificate Verification Failed",
                    severity="High",
                    confidence="High",
                    evidence=(
                        f"Certificate verification failed: "
                        f"{exc.verify_message}"
                    ),
                    description=(
                        "The TLS connection could not establish "
                        "a trusted, hostname-verified certificate."
                    ),
                    recommendation=(
                        "Verify the certificate's hostname, validity "
                        "period, issuer, and certificate chain."
                    ),
                )
            ],
        )

    except (socket.timeout, TimeoutError):
        return TLSResult(
            hostname=hostname,
            port=port,
            tls_version=None,
            cipher=None,
            certificate_expires=None,
            findings=[],
            error="TLS connection timed out.",
        )

    except (OSError, ssl.SSLError, ValueError) as exc:
        return TLSResult(
            hostname=hostname,
            port=port,
            tls_version=None,
            cipher=None,
            certificate_expires=None,
            findings=[],
            error=f"TLS inspection failed: {type(exc).__name__}.",
        )