"""Check every hop, and connect to the address that was checked.

A URL that passes and then answers 302 to 169.254.169.254 has defeated a check
that ran once. httpx sends each redirect as a new request through the
transport, so a transport is the one place that sees them all.

A check that resolves the name and then lets the client resolve it again has a
gap between the two answers (DNS rebinding). The transport closes it by
resolving inside the connection pool's network backend: the address that is
validated is the address the socket connects to. The URL keeps its host name,
so the Host header, TLS SNI and certificate verification all use the name.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable
from typing import Any

from .core import (
    DEFAULT_POLICY,
    Address,
    Policy,
    Resolver,
    addresses_for,
    check_url,
    resolve_host,
)

DEFAULT_MAX_REDIRECTS = 5


class _PinnedBackend:
    """A sync httpcore network backend that validates, then connects by address."""

    def __init__(self, inner: Any, policy: Policy, resolver: Resolver) -> None:
        self._inner = inner
        self._policy = policy
        self._resolver = resolver

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> Any:
        import httpcore  # noqa: PLC0415 - optional dependency

        addresses = resolve_host(host, self._policy, self._resolver)
        last: Exception = httpcore.ConnectError(f"{host} resolves to no address")
        for address in addresses:
            try:
                return self._inner.connect_tcp(
                    str(address), port, timeout, local_address, socket_options
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last = exc
        raise last

    def connect_unix_socket(self, *args: Any, **kwargs: Any) -> Any:
        # A socket path is chosen by whoever built the transport, not by a URL.
        return self._inner.connect_unix_socket(*args, **kwargs)

    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


class _AsyncPinnedBackend:
    """The async twin: resolution runs in a worker thread, never on the loop."""

    def __init__(self, inner: Any, policy: Policy, resolver: Resolver) -> None:
        self._inner = inner
        self._policy = policy
        self._resolver = resolver

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> Any:
        import anyio.to_thread  # noqa: PLC0415 - comes with httpx
        import httpcore  # noqa: PLC0415

        addresses: list[Address] = await anyio.to_thread.run_sync(
            resolve_host, host, self._policy, self._resolver
        )
        last: Exception = httpcore.ConnectError(f"{host} resolves to no address")
        for address in addresses:
            try:
                return await self._inner.connect_tcp(
                    str(address), port, timeout, local_address, socket_options
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last = exc
        raise last

    async def connect_unix_socket(self, *args: Any, **kwargs: Any) -> Any:
        return await self._inner.connect_unix_socket(*args, **kwargs)

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def _pin(inner: Any, policy: Policy, resolver: Resolver) -> bool:
    """Install the pinned backend in an httpx transport's pool. False when the
    transport is not one whose connections this can see."""
    pool = getattr(inner, "_pool", None)
    if pool is None:
        return False
    import httpcore  # noqa: PLC0415

    proxies = (httpcore.HTTPProxy, httpcore.SOCKSProxy)
    async_proxies = (httpcore.AsyncHTTPProxy, httpcore.AsyncSOCKSProxy)
    if isinstance(pool, proxies + async_proxies):
        # The proxy resolves the target, so no address here can be pinned.
        raise ValueError("GuardedTransport cannot pin addresses through a proxy")
    if isinstance(pool, httpcore.ConnectionPool):
        backend: Any = _PinnedBackend(pool._network_backend, policy, resolver)
        pool._network_backend = backend
        return True
    if isinstance(pool, httpcore.AsyncConnectionPool):
        async_backend: Any = _AsyncPinnedBackend(pool._network_backend, policy, resolver)
        pool._network_backend = async_backend
        return True
    return False


class GuardedTransport:
    """Wrap an httpx transport so every request it carries is checked, and every
    connection it opens goes to an address that was checked.

        import httpx
        from ssrf_guard import GuardedTransport

        client = httpx.Client(transport=GuardedTransport(), follow_redirects=True)

    For async, pass one in: ``GuardedTransport(httpx.AsyncHTTPTransport())``.
    Pinning needs an ``httpx.HTTPTransport`` or ``httpx.AsyncHTTPTransport``
    without a proxy. Any other inner transport gets the URL check only, and
    ``pinned`` is False.
    """

    def __init__(
        self,
        inner: Any = None,
        policy: Policy = DEFAULT_POLICY,
        resolver: Resolver | None = None,
    ) -> None:
        if inner is None:
            import httpx  # noqa: PLC0415 - optional, imported only when defaulted

            inner = httpx.HTTPTransport()
        self._inner = inner
        self._policy = policy
        resolver = resolver or addresses_for
        self._resolver = resolver
        self.pinned = _pin(inner, policy, resolver)
        # Pinned: the backend resolves and checks, so the URL check stays offline.
        self._url_policy = dataclasses.replace(policy, resolve=False) if self.pinned else policy

    def _check(self, request: Any) -> None:
        check_url(str(request.url), self._url_policy)

    def handle_request(self, request: Any) -> Any:
        self._check(request)
        return self._inner.handle_request(request)

    async def handle_async_request(self, request: Any) -> Any:
        self._check(request)
        return await self._inner.handle_async_request(request)

    def close(self) -> None:
        close = getattr(self._inner, "close", None)
        if close is not None:
            close()

    async def aclose(self) -> None:
        aclose = getattr(self._inner, "aclose", None)
        if aclose is not None:
            await aclose()

    def __enter__(self) -> GuardedTransport:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    async def __aenter__(self) -> GuardedTransport:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()


def guarded_client(
    policy: Policy = DEFAULT_POLICY,
    *,
    resolver: Resolver | None = None,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    **kwargs: Any,
) -> Any:
    """An ``httpx.Client`` with the pinned transport, redirects followed and
    capped, and proxy settings from the environment ignored."""
    import httpx  # noqa: PLC0415

    transport: Any = GuardedTransport(httpx.HTTPTransport(), policy, resolver)
    return httpx.Client(
        transport=transport,
        follow_redirects=True,
        max_redirects=max_redirects,
        trust_env=False,
        **kwargs,
    )


def guarded_async_client(
    policy: Policy = DEFAULT_POLICY,
    *,
    resolver: Resolver | None = None,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    **kwargs: Any,
) -> Any:
    """The async twin of :func:`guarded_client`."""
    import httpx  # noqa: PLC0415

    transport: Any = GuardedTransport(httpx.AsyncHTTPTransport(), policy, resolver)
    return httpx.AsyncClient(
        transport=transport,
        follow_redirects=True,
        max_redirects=max_redirects,
        trust_env=False,
        **kwargs,
    )
