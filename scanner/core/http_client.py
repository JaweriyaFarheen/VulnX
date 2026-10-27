"""
VulnX - Controlled HTTP Client with IP-Pinned Connections

Features:
- HTTP and HTTPS requests
- Target URL validation
- Public IP address validation
- TCP connections pinned to validated IP addresses
- Original hostname preserved for HTTPS verification
- Manual redirect handling
- Connection and read timeouts
- Response-size limits
- Preservation of individual Set-Cookie headers
- No environment-provided proxy configuration

Security note:
This implementation pins each HTTP connection to a validated IP.
Integration tests are still required to verify the complete request
path and its behavior under adversarial DNS and redirect conditions.
"""

from dataclasses import dataclass
import ipaddress
import socket
import ssl
from urllib.parse import urljoin, urlsplit

import certifi
import httpcore
import httpx
import pytest

from scanner.core.pinned_backend import (
    PinnedBackendError,
    PinnedNetworkBackend,
)
from scanner.core.target_validator import (
    TargetValidationError,
    validate_target_url,
)


MAX_REDIRECTS = 5
MAX_RESPONSE_BYTES = 1_000_000

TIMEOUT = httpx.Timeout(
    connect=5.0,
    read=10.0,
    write=5.0,
    pool=5.0,
)


@dataclass
class ScanResponse:
    """Represents a bounded HTTP response."""

    url: str
    status_code: int
    headers: dict[str, str]
    body: str
    content_length: int
    truncated: bool
    set_cookie_headers: list[str]


class HTTPClientError(Exception):
    """Raised when an HTTP request cannot safely be completed."""


def _canonical_hostname(hostname: str) -> str:
    """Return a canonical hostname suitable for matching a pin."""

    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        try:
            return hostname.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError as exc:
            raise HTTPClientError(
                "Target hostname is invalid."
            ) from exc


def _resolve_public_destination(
    url: str,
) -> tuple[str, str, int, str]:
    """
    Validate a URL and select a validated public IP for its connection.

    Returns:
        (normalized_url, canonical_hostname, port, pinned_ip)
    """

    try:
        normalized_url = validate_target_url(url)
    except TargetValidationError as exc:
        raise HTTPClientError(str(exc)) from exc

    try:
        parsed = urlsplit(normalized_url)
        hostname = parsed.hostname

        if not hostname:
            raise HTTPClientError("Missing hostname.")

        port = parsed.port or (
            443 if parsed.scheme == "https" else 80
        )

        canonical_hostname = _canonical_hostname(hostname)

        try:
            literal_address = ipaddress.ip_address(hostname)
        except ValueError:
            literal_address = None

        if literal_address is not None:
            addresses = [literal_address]
        else:
            try:
                results = socket.getaddrinfo(
                    hostname,
                    port,
                    type=socket.SOCK_STREAM,
                )
            except socket.gaierror as exc:
                raise HTTPClientError(
                    "Could not resolve target hostname."
                ) from exc

            addresses = []

            for result in results:
                try:
                    address = ipaddress.ip_address(result[4][0])
                except (ValueError, IndexError, TypeError) as exc:
                    raise HTTPClientError(
                        "DNS returned an invalid IP address."
                    ) from exc

                if address not in addresses:
                    addresses.append(address)

        if not addresses:
            raise HTTPClientError(
                "Target hostname did not resolve."
            )

        # Reject mixed public/private answers instead of selecting
        # only the public entries from an unsafe DNS response.
        if any(not address.is_global for address in addresses):
            raise HTTPClientError(
                "Target resolves to a non-public IP address."
            )

        # Pin the connection to one of the addresses validated above.
        pinned_ip = str(addresses[0])

        return (
            normalized_url,
            canonical_hostname,
            port,
            pinned_ip,
        )

    except HTTPClientError:
        raise
    except ValueError as exc:
        raise HTTPClientError(
            "Target URL contains an invalid hostname or port."
        ) from exc


def validate_public_destination(url: str) -> str:
    """Validate a URL and reject non-public IP destinations."""

    normalized_url, _, _, _ = _resolve_public_destination(url)
    return normalized_url


class _PinnedHTTPTransport(httpx.HTTPTransport):
    """
    HTTPX transport using HTTP Core with a pinned network backend.

    A fresh transport is created for each destination. Keep-alive
    connections are disabled so a connection cannot be reused after
    the selected destination pin changes.
    """

    def __init__(
        self,
        hostname: str,
        port: int,
        pinned_ip: str,
    ) -> None:
        # Use the same trusted CA bundle as HTTPX's normal verify=True
        # configuration, while disabling environment-dependent settings.
        ssl_context = ssl.create_default_context(
            cafile=certifi.where()
        )

        # Construct the normal HTTPX transport first so HTTPX retains
        # responsibility for adapting requests, responses and exceptions.
        super().__init__(
            verify=ssl_context,
            trust_env=False,
            http1=True,
            http2=False,
            limits=httpx.Limits(
                max_connections=10,
                max_keepalive_connections=0,
            ),
            retries=0,
        )

        # Replace its standard pool with a pool that uses our pinned
        # network backend. The original pool has not sent any requests.
        self._pool.close()

        backend = PinnedNetworkBackend({
            (hostname, port): pinned_ip,
        })

        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl_context,
            max_connections=10,
            max_keepalive_connections=0,
            keepalive_expiry=0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=backend,
        )


def request(
    url: str,
    *,
    max_redirects: int = MAX_REDIRECTS,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
) -> ScanResponse:
    """Perform a bounded GET request using destination-pinned TCP."""

    if (
        not isinstance(max_redirects, int)
        or isinstance(max_redirects, bool)
        or not 0 <= max_redirects <= MAX_REDIRECTS
    ):
        raise ValueError(
            f"max_redirects must be between 0 and {MAX_REDIRECTS}."
        )

    if (
        not isinstance(max_response_bytes, int)
        or isinstance(max_response_bytes, bool)
        or not 1 <= max_response_bytes <= MAX_RESPONSE_BYTES
    ):
        raise ValueError(
            f"max_response_bytes must be between 1 and "
            f"{MAX_RESPONSE_BYTES}."
        )

    current_url = url
    visited: set[str] = set()

    # Preserve Set-Cookie headers from every response in the redirect
    # chain, because cookies are often set on 3xx responses.
    collected_set_cookie_headers: list[str] = []

    request_headers = {
        "User-Agent": "VulnX-SecurityScanner/0.3",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    }

    try:
        for redirect_number in range(max_redirects + 1):
            (
                normalized_url,
                hostname,
                port,
                pinned_ip,
            ) = _resolve_public_destination(current_url)

            if normalized_url in visited:
                raise HTTPClientError("Redirect loop detected.")

            visited.add(normalized_url)

            transport = _PinnedHTTPTransport(
                hostname,
                port,
                pinned_ip,
            )

            with httpx.Client(
                transport=transport,
                timeout=TIMEOUT,
                follow_redirects=False,
                trust_env=False,
                headers=request_headers,
            ) as client:

                with client.stream(
                    "GET",
                    normalized_url,
                ) as response:

                    # Capture each individual Set-Cookie header before
                    # processing redirects; do not combine these headers.
                    collected_set_cookie_headers.extend(
                        response.headers.get_list("set-cookie")
                    )

                    if response.status_code in {
                        301,
                        302,
                        303,
                        307,
                        308,
                    }:
                        location = response.headers.get("location")

                        if not location:
                            raise HTTPClientError(
                                "Redirect response has no Location header."
                            )

                        if redirect_number >= max_redirects:
                            raise HTTPClientError(
                                "Maximum redirect count exceeded."
                            )

                        current_url = urljoin(
                            str(response.url),
                            location,
                        )

                        # The next loop iteration independently validates
                        # and pins the redirect destination.
                        continue

                    body_bytes = bytearray()
                    truncated = False

                    for chunk in response.iter_bytes(
                        chunk_size=8192
                    ):
                        remaining = (
                            max_response_bytes - len(body_bytes)
                        )

                        if remaining <= 0:
                            truncated = True
                            break

                        if len(chunk) > remaining:
                            body_bytes.extend(chunk[:remaining])
                            truncated = True
                            break

                        body_bytes.extend(chunk)

                    encoding = response.encoding or "utf-8"

                    return ScanResponse(
                        url=str(response.url),
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        body=body_bytes.decode(
                            encoding,
                            errors="replace",
                        ),
                        content_length=len(body_bytes),
                        truncated=truncated,
                        set_cookie_headers=list(
                            collected_set_cookie_headers
                        ),
                    )

    except HTTPClientError:
        raise

    except PinnedBackendError as exc:
        # Fail closed if the pinned backend rejects the destination or
        # detects that the connected peer does not match the validated IP.
        raise HTTPClientError(
            f"Pinned TCP connection rejected: {exc}"
        ) from exc

    except TargetValidationError as exc:
        raise HTTPClientError(str(exc)) from exc

    except httpx.HTTPError as exc:
        # Include nested causes so diagnostics can distinguish TLS
        # certificate failures from unrelated connection failures.
        details = []
        current = exc
        seen = set()

        while current is not None and id(current) not in seen:
            seen.add(id(current))
            message = str(current).strip()
            label = type(current).__name__
            if message:
                label = f"{label}: {message}"
            if label not in details:
                details.append(label)

            current = current.__cause__ or current.__context__

        detail_text = " -> ".join(details) or type(exc).__name__
        raise HTTPClientError(
            f"HTTP request failed: {detail_text}"
        ) from exc

    except httpcore.ConnectError as exc:
        details = []
        current = exc
        seen = set()

        while current is not None and id(current) not in seen:
            seen.add(id(current))
            message = str(current).strip()
            label = type(current).__name__
            if message:
                label = f"{label}: {message}"
            if label not in details:
                details.append(label)

            current = current.__cause__ or current.__context__

        detail_text = " -> ".join(details) or type(exc).__name__
        raise HTTPClientError(
            f"Pinned TCP connection could not be established: {detail_text}"
        ) from exc

    except OSError as exc:
        raise HTTPClientError(
            "Network operation failed."
        ) from exc

    raise HTTPClientError(
        "Request could not be completed."
    )

def test_pinned_backend_error_is_converted_to_http_client_error(
    monkeypatch,
):
    """Backend security errors should use the HTTP client's error type."""

    import httpx

    import scanner.core.http_client as http_client
    from scanner.core.pinned_backend import PinnedBackendError

    class FakeTransport:
        def __init__(self, hostname, port, pinned_ip):
            raise PinnedBackendError(
                "No validated IP pin exists for this destination."
            )

    monkeypatch.setattr(
        http_client,
        "_PinnedHTTPTransport",
        FakeTransport,
    )

    monkeypatch.setattr(
        http_client,
        "_resolve_public_destination",
        lambda url: (
            "http://example.com/",
            "example.com",
            80,
            "93.184.216.34",
        ),
    )

    with pytest.raises(
        http_client.HTTPClientError,
        match="validated IP pin",
    ):
        http_client.request("http://example.com/")