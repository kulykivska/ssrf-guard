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
    UnsafeUrlError,
    addresses_for,
    check_url,
    is_safe,
)
from .httpx_guard import GuardedTransport

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_POLICY",
    "DEFAULT_SCHEMES",
    "GuardedTransport",
    "Policy",
    "UnsafeUrlError",
    "__version__",
    "addresses_for",
    "check_url",
    "is_safe",
]
