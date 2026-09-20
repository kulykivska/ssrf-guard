"""The bypasses, one test each.

Anyone can refuse http://127.0.0.1. The interesting cases are the ones that
look public: an integer, an IPv6 wrapper, a name that resolves inward, a
redirect that arrives after the check has already run.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any

import httpx
import pytest

from ssrf_guard import GuardedTransport, Policy, UnsafeUrlError, check_url, is_safe
from ssrf_guard.core import _is_blocked_address


def resolves_to(monkeypatch: pytest.MonkeyPatch, *addresses: str) -> None:
    def fake(host: str, *_args: object, **_kwargs: object) -> list[tuple]:  # type: ignore[type-arg]
        family = socket.AF_INET6 if ":" in addresses[0] else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 6, "", (a, 0)) for a in addresses]

    monkeypatch.setattr(socket, "getaddrinfo", fake)


NO_RESOLVE = Policy(resolve=False)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/admin",
        "http://localhost:8080/",
        "http://[::1]/",
        "http://10.0.0.5/",
        "http://192.168.1.1/",
        "http://172.16.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://0.0.0.0/",
        "http://[fe80::1]/",
        "http://[fc00::1]/",
    ],
)
def test_the_obvious_private_addresses_are_refused(url: str) -> None:
    assert not is_safe(url, NO_RESOLVE)


@pytest.mark.parametrize(
    ("url", "what"),
    [
        ("http://2130706433/", "127.0.0.1 written as an integer"),
        ("http://0x7f000001/", "the same in hex"),
        ("http://[::ffff:127.0.0.1]/", "IPv4 loopback wearing an IPv6 hat"),
        ("http://[::ffff:169.254.169.254]/", "the metadata service, same trick"),
    ],
)
def test_an_address_in_disguise_is_still_that_address(url: str, what: str) -> None:
    assert not is_safe(url, NO_RESOLVE), what


def test_the_host_is_the_host_not_the_userinfo() -> None:
    """https://api.example.com@127.0.0.1/ goes to 127.0.0.1, and a check that
    reads the netloc reports the wrong thing entirely."""
    assert not is_safe("https://api.example.com@127.0.0.1/", NO_RESOLVE)


def test_a_trailing_dot_is_the_same_host() -> None:
    assert not is_safe("http://localhost./", NO_RESOLVE)


@pytest.mark.parametrize(
    "url", ["file:///etc/passwd", "gopher://127.0.0.1:11211/", "data:text/plain,hi", "ftp://x/"]
)
def test_only_http_and_https_are_fetchable(url: str) -> None:
    assert not is_safe(url)


def test_a_public_name_that_resolves_inward_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """The case the string check cannot see, and the one an attacker uses."""
    resolves_to(monkeypatch, "169.254.169.254")
    with pytest.raises(UnsafeUrlError, match=r"169\.254\.169\.254"):
        check_url("https://totally-normal.example/")


def test_one_public_record_does_not_excuse_a_private_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Round-robin DNS with one internal answer is a coin flip the fetcher
    loses eventually."""
    resolves_to(monkeypatch, "93.184.216.34", "10.0.0.7")
    assert not is_safe("https://mixed.example/")


def test_a_public_address_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    resolves_to(monkeypatch, "93.184.216.34")
    assert is_safe("https://example.com/path?q=1")


def test_a_host_that_resolves_to_nothing_is_left_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unresolvable is not forbidden: the fetch will fail on its own terms, and
    claiming otherwise would block every typo as though it were an attack."""

    def fail(*_args: object, **_kwargs: object) -> list[tuple]:  # type: ignore[type-arg]
        raise socket.gaierror("no such host")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    assert is_safe("https://nothing-here.example/")


def test_resolution_can_be_turned_off_for_offline_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def fake(*_args: object, **_kwargs: object) -> list[tuple]:  # type: ignore[type-arg]
        nonlocal called
        called = True
        return []

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    assert is_safe("https://example.com/", NO_RESOLVE)
    assert not called


def test_an_allowed_host_skips_the_address_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    """A service you do mean to reach, on an address you would otherwise refuse."""
    policy = Policy(allow_hosts=frozenset({"internal.service"}))
    resolves_to(monkeypatch, "10.0.0.9")
    assert is_safe("http://internal.service/health", policy)
    assert is_safe("http://api.internal.service/health", policy)
    assert not is_safe("http://other.internal/health", policy)


def test_a_denied_host_is_refused_even_when_public(monkeypatch: pytest.MonkeyPatch) -> None:
    resolves_to(monkeypatch, "93.184.216.34")
    policy = Policy(deny_hosts=frozenset({"evil.example"}))
    assert not is_safe("https://evil.example/", policy)
    assert not is_safe("https://sub.evil.example/", policy)


def test_ports_can_be_restricted(monkeypatch: pytest.MonkeyPatch) -> None:
    resolves_to(monkeypatch, "93.184.216.34")
    policy = Policy(allow_ports=frozenset({80, 443}))
    assert is_safe("https://example.com/", policy)
    assert not is_safe("https://example.com:11211/", policy)


def test_the_error_says_which_address_and_why(monkeypatch: pytest.MonkeyPatch) -> None:
    resolves_to(monkeypatch, "10.1.2.3")
    with pytest.raises(UnsafeUrlError, match="private address"):
        check_url("https://name.example/")


# --- the transport --------------------------------------------------------


class FakeRequest:
    def __init__(self, url: str) -> None:
        self.url = url


class FakeTransport:
    def __init__(self) -> None:
        self.seen: list[str] = []

    def handle_request(self, request: Any) -> str:
        self.seen.append(str(request.url))
        return "response"

    async def handle_async_request(self, request: Any) -> str:
        self.seen.append(str(request.url))
        return "response"


def test_the_transport_checks_the_request_it_carries(monkeypatch: pytest.MonkeyPatch) -> None:
    resolves_to(monkeypatch, "93.184.216.34")
    inner = FakeTransport()
    transport = GuardedTransport(inner)
    assert transport.handle_request(FakeRequest("https://example.com/")) == "response"
    assert inner.seen == ["https://example.com/"]


def test_the_transport_refuses_a_redirect_hop(monkeypatch: pytest.MonkeyPatch) -> None:
    """The whole reason this lives in a transport: the first URL passed, and the
    second one is the metadata service."""
    inner = FakeTransport()
    transport = GuardedTransport(inner)
    with pytest.raises(UnsafeUrlError):
        transport.handle_request(FakeRequest("http://169.254.169.254/latest/meta-data/"))
    assert inner.seen == []


async def test_the_async_transport_checks_too(monkeypatch: pytest.MonkeyPatch) -> None:
    inner = FakeTransport()
    transport = GuardedTransport(inner)
    with pytest.raises(UnsafeUrlError):
        await transport.handle_async_request(FakeRequest("http://127.0.0.1/"))
    assert inner.seen == []


def test_mapped_addresses_are_unwrapped() -> None:
    assert _is_blocked_address(ipaddress.ip_address("::ffff:10.0.0.1")) == "private"
    assert _is_blocked_address(ipaddress.ip_address("93.184.216.34")) == ""


def test_a_real_client_stops_at_the_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    """Through httpx itself: the first URL is fine, the 302 is not, and the
    client never opens the second connection."""
    resolves_to(monkeypatch, "93.184.216.34")
    reached: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        reached.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/"})

    transport = GuardedTransport(httpx.MockTransport(handler))
    with httpx.Client(transport=transport, follow_redirects=True) as client, pytest.raises(
        UnsafeUrlError
    ):
        client.get("https://example.com/webhook")
    assert reached == ["https://example.com/webhook"]
