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

## Every hop, through httpx

```python
import httpx
from ssrf_guard import GuardedTransport

client = httpx.Client(transport=GuardedTransport(), follow_redirects=True)
client.get(url_from_the_feed)   # raises UnsafeUrlError on any hop that points inward
```

httpx sends each redirect as a new request through the transport, so the
transport is the one place that sees them all. The async transport works the
same way: `GuardedTransport(httpx.AsyncHTTPTransport())`.

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

## What this does not do

It does not protect you from DNS rebinding. The name is resolved when it is
checked and again when it is connected, and between those two moments the
answer can change. Closing that means pinning the address you validated and
connecting to it, which is a job for your HTTP stack rather than for a
validator — this library gives you `addresses_for(host)` so you can.

It does not filter response content, and it is not a proxy allowlist. It
answers one question: may this URL be fetched at all.

## License

MIT.
