# Changelog

## 0.2.0

- Close DNS rebinding: `GuardedTransport` resolves once inside the httpx pool, refuses any non-public A/AAAA record and connects to that exact address, keeping the host name for the Host header, SNI and certificate checks. Adds `resolve_host`, `guarded_client`, `guarded_async_client`; refuses proxied transports; requires httpx 0.26 or later. The pinned transport checks addresses even with `resolve=False`.

## 0.1.0

- First release.
