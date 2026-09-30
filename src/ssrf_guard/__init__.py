"""Refuse to fetch a URL that points inside your network.

A URL written by someone else - a webhook, a feed item, a search result, an
avatar address in a signup form - decides what your server connects to. This
says no before it does, and keeps saying no on every redirect hop.
"""

from __future__ import annotations

from .core import (
    DEFAULT_POLICY,
    DEFAULT_SCHEMES,
    Policy,
    Resolver,
    UnsafeUrlError,
    addresses_for,
    check_url,
    is_safe,
    resolve_host,
)
from .httpx_guard import GuardedTransport, guarded_async_client, guarded_client

__version__ = "0.2.0"

__all__ = [
    "DEFAULT_POLICY",
    "DEFAULT_SCHEMES",
    "GuardedTransport",
    "Policy",
    "Resolver",
    "UnsafeUrlError",
    "__version__",
    "addresses_for",
    "check_url",
    "guarded_async_client",
    "guarded_client",
    "is_safe",
    "resolve_host",
]
