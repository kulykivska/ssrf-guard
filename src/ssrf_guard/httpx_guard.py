"""Check every hop, not only the first.

A URL that passes and then answers 302 to 169.254.169.254 has defeated a check
that ran once. httpx sends each redirect as a new request through the
transport, so a transport is the one place that sees them all.
"""

from __future__ import annotations

from typing import Any

from .core import DEFAULT_POLICY, Policy, check_url


class GuardedTransport:
    """Wrap an httpx transport so every request it carries is checked.

        import httpx
        from ssrf_guard import GuardedTransport

        client = httpx.Client(transport=GuardedTransport(), follow_redirects=True)

    Works for the async transport too; pass one in.
    """

    def __init__(self, inner: Any = None, policy: Policy = DEFAULT_POLICY) -> None:
        if inner is None:
            import httpx  # noqa: PLC0415 - optional, imported only when defaulted

            inner = httpx.HTTPTransport()
        self._inner = inner
        self._policy = policy

    def handle_request(self, request: Any) -> Any:
        check_url(str(request.url), self._policy)
        return self._inner.handle_request(request)

    async def handle_async_request(self, request: Any) -> Any:
        check_url(str(request.url), self._policy)
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
