"""
VulnX - Pinned HTTP Core Network Backend

Connects to an explicitly supplied IP address instead of resolving
the requested hostname during TCP connection establishment.

The original hostname is retained by HTTP Core for HTTP Host handling,
TLS SNI, and certificate verification.
"""

import ipaddress
import socket

import httpcore
from httpcore._backends.sync import SyncBackend, SyncStream


class PinnedBackendError(Exception):
    """Raised when a pinned connection cannot be established safely."""


class PinnedNetworkBackend(SyncBackend):
    """
    Network backend that pins TCP connections to a validated IP.

    The mapping keys are (hostname, port), and values are IP strings.
    Only addresses supplied through this mapping may be connected to.
    """

    def __init__(
        self,
        pins: dict[tuple[str, int], str],
    ) -> None:
        super().__init__()

        self._pins: dict[tuple[str, int], str] = {}

        for key, value in pins.items():
            if (
                not isinstance(key, tuple)
                or len(key) != 2
                or not isinstance(key[0], str)
                or not key[0].strip()
                or not isinstance(key[1], int)
                or isinstance(key[1], bool)
                or not 1 <= key[1] <= 65535
            ):
                raise ValueError("Invalid hostname/port pin.")

            try:
                address = ipaddress.ip_address(value)
            except (ValueError, TypeError) as exc:
                raise ValueError(
                    "A pin must be a valid IP address."
                ) from exc

            if not address.is_global:
                raise ValueError(
                    "A pin must be a globally routable IP."
                )

            normalized_host = key[0].lower().rstrip(".")

            self._pins[(normalized_host, key[1])] = str(address)

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options=None,
    ) -> SyncStream:
        """
        Connect directly to the pinned IP.

        The caller supplies the original hostname to HTTP Core so
        hostname-based TLS verification remains possible.
        """

        pin_key = (host.lower().rstrip("."), port)
        pinned_ip = self._pins.get(pin_key)

        # Reject destinations without an explicit validated pin.
        if pinned_ip is None:
            raise PinnedBackendError(
                "No validated IP pin exists for this destination."
            )

        address = ipaddress.ip_address(pinned_ip)
        sock = None

        try:
            # Connect directly to the IP literal, not the hostname.
            sock = socket.create_connection(
                (str(address), port),
                timeout=timeout,
                source_address=(
                    None
                    if local_address is None
                    else (local_address, 0)
                ),
            )

            # Apply requested socket options.
            if socket_options:
                for option in socket_options:
                    sock.setsockopt(*option)

            # Verify the actual peer address.
            peer = sock.getpeername()
            peer_ip = ipaddress.ip_address(peer[0])

            if peer_ip != address:
                raise PinnedBackendError(
                    "Connected peer does not match the pinned IP."
                )

            return SyncStream(sock)

        except PinnedBackendError:
            if sock is not None:
                sock.close()
            raise

        except OSError as exc:
            if sock is not None:
                sock.close()

            raise httpcore.ConnectError(
                "Could not establish the pinned TCP connection."
            ) from exc

        except Exception:
            if sock is not None:
                sock.close()
            raise