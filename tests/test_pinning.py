"""DNS rebinding: the answer that was checked is the answer that is used.

Every test here drives a real httpx client through a real httpcore pool; only
the socket layer is a recording fake, so nothing touches the network.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable, Sequence
from typing import Any

import httpcore
import httpx
import pytest

from ssrf_guard import (
    GuardedTransport,
    Policy,
    UnsafeUrlError,
    guarded_async_client,
    guarded_client,
    resolve_host,
)
from ssrf_guard.core import Address

PUBLIC = "93.184.216.34"
OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"


def redirect_to(location: str) -> bytes:
    return (
        f"HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n"
        "Connection: close\r\n\r\n"
    ).encode()


class Resolver:
    """Answers from a script, one entry per call, and counts the calls."""

    def __init__(self, *answers: Sequence[str], by_host: dict[str, list[str]] | None = None):
        self.answers = list(answers)
        self.by_host = by_host or {}
        self.calls: list[str] = []

    def __call__(self, host: str) -> list[Address]:
        self.calls.append(host)
        if host in self.by_host:
            chosen = self.by_host[host]
        else:
            chosen = list(self.answers.pop(0) if len(self.answers) > 1 else self.answers[0])
        return [ipaddress.ip_address(a) for a in chosen]


def first_public_then_loopback() -> Resolver:
    return Resolver([PUBLIC], ["127.0.0.1"])


class Stream(httpcore.MockStream):
    def __init__(self, record: Recorder, buffer: list[bytes]) -> None:
        super().__init__(buffer)
        self._record = record

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self._record.sent.append(buffer)

    def start_tls(
        self, ssl_context: Any, server_hostname: str | None = None, timeout: float | None = None
    ) -> httpcore.NetworkStream:
        self._record.sni.append(server_hostname)
        return self


class AsyncStream(httpcore.AsyncMockStream):
    def __init__(self, record: Recorder, buffer: list[bytes]) -> None:
        super().__init__(buffer)
        self._record = record

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self._record.sent.append(buffer)


class Recorder:
    """A network backend that records where it was asked to connect."""

    def __init__(self, responses: Iterable[bytes] = (OK,)) -> None:
        self.responses = list(responses)
        self.connected: list[str] = []
        self.sni: list[str | None] = []
        self.sent: list[bytes] = []

    def _next(self, host: str) -> list[bytes]:
        self.connected.append(host)
        body = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        return [body]

    def connect_tcp(self, host: str, port: int, *_args: Any, **_kw: Any) -> Stream:
        return Stream(self, self._next(host))

    def sleep(self, seconds: float) -> None:  # pragma: no cover - no retries here
        pass


class AsyncRecorder(Recorder):
    async def connect_tcp(  # type: ignore[override]
        self, host: str, port: int, *_args: Any, **_kw: Any
    ) -> AsyncStream:
        return AsyncStream(self, self._next(host))


def pinned(
    recorder: Recorder, resolver: Callable[[str], list[Address]], policy: Policy | None = None
) -> GuardedTransport:
    inner = httpx.HTTPTransport()
    inner._pool._network_backend = recorder  # type: ignore[assignment]
    transport = GuardedTransport(inner, policy or Policy(), resolver)
    assert transport.pinned
    return transport


def test_a_rebinding_answer_never_reaches_the_socket() -> None:
    """The attack: public for the check, loopback for the connect. The guard
    resolves once and connects to that answer; the next connect is refused."""
    recorder, resolver = Recorder(), first_public_then_loopback()
    with httpx.Client(transport=pinned(recorder, resolver)) as client:
        assert client.get("http://rebind.example/").text == "ok"
        with pytest.raises(UnsafeUrlError, match=r"127\.0\.0\.1"):
            client.get("http://rebind.example/")
    assert recorder.connected == [PUBLIC]
    assert resolver.calls == ["rebind.example", "rebind.example"]


def test_the_name_stays_on_host_header_and_tls() -> None:
    recorder = Recorder()
    with httpx.Client(transport=pinned(recorder, Resolver([PUBLIC]))) as client:
        client.get("https://pinned.example/path")
    assert recorder.connected == [PUBLIC]
    assert recorder.sni == ["pinned.example"]
    assert b"Host: pinned.example" in b"".join(recorder.sent)


def test_a_redirect_to_an_internal_name_is_checked_at_connect() -> None:
    recorder = Recorder([redirect_to("http://internal.example/admin"), OK])
    resolver = Resolver([PUBLIC], by_host={"internal.example": ["10.0.0.5"]})
    transport = pinned(recorder, resolver)
    with (
        httpx.Client(transport=transport, follow_redirects=True) as client,
        pytest.raises(UnsafeUrlError, match="private"),
    ):
        client.get("http://start.example/")
    assert recorder.connected == [PUBLIC]


def test_a_redirect_to_a_loopback_literal_is_refused_before_connect() -> None:
    recorder = Recorder([redirect_to("http://127.0.0.1:8080/"), OK])
    with (
        httpx.Client(
            transport=pinned(recorder, Resolver([PUBLIC])), follow_redirects=True
        ) as client,
        pytest.raises(UnsafeUrlError),
    ):
        client.get("http://start.example/")
    assert recorder.connected == [PUBLIC]


@pytest.mark.parametrize(
    ("answer", "why"),
    [
        (["::1"], "IPv6 loopback"),
        (["::ffff:127.0.0.1"], "IPv4-mapped loopback"),
        (["::ffff:169.254.169.254"], "IPv4-mapped metadata service"),
        ([PUBLIC, "10.0.0.7"], "one private record among public ones"),
        (["2606:4700::1111", "fd00::1"], "one unique-local AAAA among public ones"),
    ],
)
def test_any_refused_answer_blocks_the_connect(answer: list[str], why: str) -> None:
    recorder = Recorder()
    transport = pinned(recorder, Resolver(answer))
    with httpx.Client(transport=transport) as client, pytest.raises(UnsafeUrlError):
        client.get("http://multi.example/")
    assert recorder.connected == [], why


def test_a_later_address_is_tried_when_the_first_does_not_answer() -> None:
    recorder = Recorder()
    original = recorder.connect_tcp

    def flaky(host: str, port: int, *args: Any, **kw: Any) -> Stream:
        if host == PUBLIC:
            recorder.connected.append(host)
            raise httpcore.ConnectError("refused")
        return original(host, port, *args, **kw)

    recorder.connect_tcp = flaky  # type: ignore[method-assign]
    resolver = Resolver([PUBLIC, "2606:4700::1111"])
    with httpx.Client(transport=pinned(recorder, resolver)) as client:
        assert client.get("http://two.example/").status_code == 200
    assert recorder.connected == [PUBLIC, "2606:4700::1111"]


def test_guarded_client_caps_redirects_and_ignores_env_proxies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://10.0.0.1:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://10.0.0.1:3128")
    recorder = Recorder([redirect_to("http://loop.example/")])
    with guarded_client(resolver=Resolver([PUBLIC]), max_redirects=2) as client:
        transport = client._transport_for_url(httpx.URL("http://loop.example/"))
        assert isinstance(transport, GuardedTransport)
        assert transport.pinned
        transport._inner._pool._network_backend._inner = recorder
        with pytest.raises(httpx.TooManyRedirects):
            client.get("http://loop.example/")
    assert len(recorder.connected) == 3


def test_a_proxied_transport_is_refused_rather_than_trusted() -> None:
    with pytest.raises(ValueError, match="proxy"):
        GuardedTransport(httpx.HTTPTransport(proxy="http://proxy.example:3128"))


def test_a_custom_inner_transport_is_checked_but_not_pinned() -> None:
    transport = GuardedTransport(httpx.MockTransport(lambda _r: httpx.Response(200)))
    assert not transport.pinned


async def test_the_async_client_pins_too() -> None:
    recorder = AsyncRecorder()
    resolver = first_public_then_loopback()
    async with guarded_async_client(resolver=resolver) as client:
        transport = client._transport_for_url(httpx.URL("http://rebind.example/"))
        assert isinstance(transport, GuardedTransport)
        transport._inner._pool._network_backend._inner = recorder
        assert (await client.get("http://rebind.example/")).text == "ok"
        with pytest.raises(UnsafeUrlError):
            await client.get("http://rebind.example/")
    assert recorder.connected == [PUBLIC]


def test_resolve_host_honours_the_policy() -> None:
    private = Resolver(["10.0.0.9"])
    allowed = Policy(allow_hosts=frozenset({"internal.service"}))
    assert [str(a) for a in resolve_host("api.internal.service", allowed, private)] == [
        "10.0.0.9"
    ]
    with pytest.raises(UnsafeUrlError, match="deny"):
        resolve_host("x.evil.example", Policy(deny_hosts=frozenset({"evil.example"})), private)
    with pytest.raises(UnsafeUrlError, match="this machine"):
        resolve_host("localhost", Policy(), Resolver([PUBLIC]))
    assert resolve_host("nothing.example", Policy(), Resolver([])) == []
