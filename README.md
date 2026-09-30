# ssrf-guard

[![ci](https://github.com/kulykivska/ssrf-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/kulykivska/ssrf-guard/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Refuse to fetch a URL that points inside your network — including the
disguises, and on every redirect hop.

```bash
pip install ssrf-guard
```

No dependencies.

```python
from ssrf_guard import check_url, UnsafeUrlError

try:
    check_url(url_from_the_signup_form)
except UnsafeUrlError as why:
    return 400, str(why)   # "totally-normal.example resolves to 169.254.169.254, a link-local address"
```

## Why a library for four lines of code

Because it is not four lines. Every URL below points at the same machine, and
each one defeats a check that someone wrote in good faith:

| URL | What the naive check sees |
| --- | --- |
| `http://2130706433/` | a hostname that is not "127.0.0.1" |
| `http://0x7f000001/` | the same, in hex |
| `http://[::ffff:127.0.0.1]/` | an IPv6 address, and the check only knows IPv4 |
| `https://api.example.com@127.0.0.1/` | `api.example.com`, if it reads the netloc |
| `http://localhost./` | a hostname that is not "localhost" |
| `https://harmless.example/` | a public name — until you resolve it |
| a 302 from a public URL to `169.254.169.254` | nothing at all: the check already ran |

That last row is the one most libraries miss, and it is the easiest to exploit:
pass the check with a public URL, then redirect. The guard belongs on every
hop, not on the first one.

## Every hop, through httpx, pinned to the checked address

```python
from ssrf_guard import guarded_client

with guarded_client() as client:   # follows up to 5 redirects, ignores proxy env vars
    client.get(url_from_the_feed)  # raises UnsafeUrlError on any hop that points inward
```

Or wire the transport yourself:

```python
import httpx
from ssrf_guard import GuardedTransport

client = httpx.Client(transport=GuardedTransport(), follow_redirects=True, max_redirects=5)
```

httpx sends each redirect as a new request through the transport, so the
transport is the one place that sees them all. The async side works the same
way: `guarded_async_client()`, or `GuardedTransport(httpx.AsyncHTTPTransport())`.

The transport also closes DNS rebinding. It resolves the name once, inside the
connection pool, refuses the connection if **any** returned A or AAAA record is
non-public, and then connects to exactly those addresses. The URL keeps its
host name, so the `Host` header, TLS SNI and certificate verification all use
the name and not the IP. A second, different DNS answer never gets a say.

If you resolve names yourself, `resolve_host(host, policy)` does the same:
it returns the addresses you may connect to, or raises.

## What it refuses

Loopback, private (RFC 1918 and IPv6 unique-local), link-local — which is where
`169.254.169.254` lives, the cloud metadata service that hands out credentials —
reserved, multicast and unspecified addresses. Any scheme that is not `http` or
`https`. Hosts named `localhost`, whatever DNS says about them.

It resolves the name and checks **every** address it gets back: one public
A record does not excuse a private one beside it.

A host that resolves to nothing is allowed through. Unresolvable is not the
same as forbidden, and blocking every typo as though it were an attack teaches
people to turn the guard off.

## Policy

```python
from ssrf_guard import Policy, check_url

policy = Policy(
    allow_hosts=frozenset({"internal.metrics"}),   # a service you do mean to reach
    deny_hosts=frozenset({"pastebin.com"}),        # and one you never do
    allow_ports=frozenset({80, 443}),              # no 11211, no 6379
    resolve=True,                                  # False checks the string only
)
check_url(candidate, policy)
```

`allow_hosts` and `deny_hosts` match the name and every subdomain of it.

## What this does and does not protect against

Protects against, when requests go through `GuardedTransport` over the stock
`httpx.HTTPTransport` / `httpx.AsyncHTTPTransport` (check `transport.pinned`):

- private, loopback, link-local (the `169.254.169.254` metadata service),
  CGNAT, reserved and multicast addresses, including their disguised forms;
- a name with one internal record among public ones;
- a redirect to any of the above, on every hop, with `guarded_client` capping
  the number of hops;
- DNS rebinding between the check and the connect, because there is only one
  resolution and the socket uses its answer.

Does not protect against:

- **Other HTTP stacks.** `check_url` and `is_safe` check a string. If you use
  them in front of `requests`, `urllib` or a headless browser, that stack
  resolves the name again and rebinding is still possible. Use `resolve_host`
  and connect to what it returns.
- **Custom inner transports.** Wrap something other than the stock httpx
  transport and you get the URL check on every hop, but no pinning
  (`transport.pinned` is False).
- **Proxies.** The proxy resolves the target, not you, so nothing here can pin
  it. `GuardedTransport` refuses a proxied `HTTPTransport`, and
  `guarded_client` sets `trust_env=False` so `HTTP_PROXY` / `HTTPS_PROXY` are
  ignored. If you pass `transport=` to your own `httpx.Client`, httpx already
  ignores proxy variables; do not add `mounts=` that bypass the guard.
- **Unix sockets** chosen with `uds=`: that path is yours, not the URL's.
- **Response content.** It does not filter what comes back, and it is not an
  allowlist of where you should go. It answers one question: may this
  connection be made at all.

## Changes

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT.
