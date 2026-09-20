"""Decide whether a URL is safe to fetch, before anything fetches it.

The rule is simple and the bypasses are not: a URL written by someone else
decides what your server connects to. The checks here are the ones that catch
the shapes people actually use - an address that only looks public until it is
resolved, an IPv6 form of a private address, an integer that is really
127.0.0.1, a hostname that is really in the userinfo.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit

DEFAULT_SCHEMES = frozenset({"http", "https"})

# Names that mean "this machine" whatever DNS says (RFC 6761), refused without
# a lookup - which matters exactly when resolution is off.
LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})

# The largest value an IPv4 address can be written as.
MAX_IPV4 = 0xFFFFFFFF


class UnsafeUrlError(ValueError):
    """The URL points somewhere this policy will not go."""


@dataclass(frozen=True)
class Policy:
    """What counts as fetchable.

    `resolve` is the difference between checking a string and checking a
    destination: without it, a public name pointing at 169.254.169.254 passes.
    """

    schemes: frozenset[str] = DEFAULT_SCHEMES
    resolve: bool = True
    allow_private: bool = False
    # Hosts that are always refused, matched on the name and on every subdomain.
    deny_hosts: frozenset[str] = frozenset()
    # Hosts that skip the address checks, for a service you do mean to reach.
    allow_hosts: frozenset[str] = frozenset()
    allow_ports: frozenset[int] = field(default_factory=frozenset)


DEFAULT_POLICY = Policy()


def _is_blocked_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Why this address is refused, or an empty string when it is fine."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        # ::ffff:127.0.0.1 is 127.0.0.1 wearing a different hat, and a check
        # that only knows IPv4 waves it through.
        return _is_blocked_address(address.ipv4_mapped)
    checks = (
        ("loopback", address.is_loopback),
        ("private", address.is_private),
        ("link-local", address.is_link_local),
        ("reserved", address.is_reserved),
        ("multicast", address.is_multicast),
        ("unspecified", address.is_unspecified),
    )
    for name, hit in checks:
        if hit:
            return name
    return ""


def addresses_for(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Every address this host resolves to, or an empty list if it resolves to
    nothing. All of them matter: one public A record does not excuse a private
    one beside it."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return []
    found: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        try:
            found.append(ipaddress.ip_address(info[4][0]))
        except ValueError:  # pragma: no cover - getaddrinfo returns addresses
            continue
    return found


def _literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The address a host is written as, including the forms people use to hide
    one: 2130706433, 0x7f000001, 0177.0.0.1, [::1]."""
    stripped = host.strip("[]")
    try:
        return ipaddress.ip_address(stripped)
    except ValueError:
        pass
    for base in (10, 16, 8):
        try:
            packed = int(stripped, base)
        except ValueError:
            continue
        if 0 <= packed <= MAX_IPV4:
            return ipaddress.ip_address(packed)
    return None


def check_url(url: str, policy: Policy = DEFAULT_POLICY) -> None:
    """Raise :class:`UnsafeUrlError` unless this URL may be fetched."""
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    if scheme not in policy.schemes:
        # file:// reads the machine; data:// and gopher:// have their own uses.
        raise UnsafeUrlError(f"scheme {scheme or '(none)'!r} is not allowed")

    # hostname, not netloc: userinfo is where "https://api.example.com@evil"
    # hides, and netloc would hand you the wrong host to check.
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise UnsafeUrlError("no host in the URL")

    if policy.allow_ports and parts.port is not None and parts.port not in policy.allow_ports:
        raise UnsafeUrlError(f"port {parts.port} is not allowed")
    if _matches(host, policy.deny_hosts):
        raise UnsafeUrlError(f"{host} is on the deny list")
    if _matches(host, policy.allow_hosts) or policy.allow_private:
        return
    _check_host(host, policy)


def _check_host(host: str, policy: Policy) -> None:
    if host in LOOPBACK_NAMES or host.endswith(".localhost"):
        raise UnsafeUrlError(f"{host} is this machine")

    literal = _literal(host)
    if literal is not None:
        reason = _is_blocked_address(literal)
        if reason:
            raise UnsafeUrlError(f"{host} is a {reason} address")
        return

    if not policy.resolve:
        return
    for address in addresses_for(host):
        # An empty list means the host resolves to nothing, which is not the
        # same as forbidden: let the fetch fail on its own terms.
        reason = _is_blocked_address(address)
        if reason:
            raise UnsafeUrlError(f"{host} resolves to {address}, a {reason} address")


def is_safe(url: str, policy: Policy = DEFAULT_POLICY) -> bool:
    try:
        check_url(url, policy)
    except UnsafeUrlError:
        return False
    return True


def _matches(host: str, names: frozenset[str]) -> bool:
    """A host matches a name, or any subdomain of it."""
    return any(host == name or host.endswith(f".{name}") for name in names)
