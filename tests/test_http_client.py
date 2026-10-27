import socket

import pytest

from scanner.core.http_client import (
    HTTPClientError,
    request,
    validate_public_destination,
)


def test_rejects_localhost():
    with pytest.raises(HTTPClientError):
        request("http://localhost")


def test_rejects_private_ip():
    with pytest.raises(HTTPClientError):
        request("http://192.168.1.10")


def test_rejects_unsupported_protocol():
    with pytest.raises(HTTPClientError):
        request("ftp://example.com")


def test_rejects_invalid_redirect_limit():
    with pytest.raises(ValueError):
        request(
            "https://example.com",
            max_redirects=100,
        )


def test_rejects_invalid_response_limit():
    with pytest.raises(ValueError):
        request(
            "https://example.com",
            max_response_bytes=0,
        )


def test_rejects_hostname_resolving_to_private_ip(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("192.168.1.10", 80),
            )
        ]

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        fake_getaddrinfo,
    )

    with pytest.raises(
        HTTPClientError,
        match="non-public IP",
    ):
        validate_public_destination("http://example.com")


def test_rejects_hostname_with_mixed_public_and_private_ips(
    monkeypatch,
):
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("93.184.216.34", 80),
            ),
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("192.168.1.10", 80),
            ),
        ]

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        fake_getaddrinfo,
    )

    with pytest.raises(
        HTTPClientError,
        match="non-public IP",
    ):
        validate_public_destination("http://example.com")

def test_pinned_backend_error_is_converted_to_http_client_error(
    monkeypatch,
):
    """Backend security errors should use the HTTP client's error type."""

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