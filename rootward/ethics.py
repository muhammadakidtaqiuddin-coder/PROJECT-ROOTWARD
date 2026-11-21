"""Ethical-use notice, local scope validation, and scan stop control."""
from __future__ import annotations

import ipaddress
import threading


DISCLAIMER = (
    "RootWard is a read-only local security auditor for systems you own or are "
    "authorized to assess. Unauthorized access may violate the Computer Crimes "
    "Act 1997 (Malaysia) and other applicable laws. You are responsible for "
    "obtaining permission before use."
)

DEFAULT_SCOPE = "127.0.0.1"
_abort_event = threading.Event()


class ScopeError(ValueError):
    """Raised when a requested scope is not a loopback address."""


def validate_scope(scope: str) -> str:
    """Accept only an explicit IPv4 or IPv6 loopback address."""
    try:
        address = ipaddress.ip_address(scope)
    except ValueError as exc:
        raise ScopeError("scope must be a loopback IP address (127.0.0.1 or ::1)") from exc
    if not address.is_loopback:
        raise ScopeError("scope must be local; only loopback addresses are allowed")
    return str(address)


def request_abort() -> None:
    """Activate the kill switch; running checks should stop at their next safe point."""
    _abort_event.set()


def should_abort() -> bool:
    """Return whether the kill switch has been activated."""
    return _abort_event.is_set()


def reset_abort() -> None:
    """Clear the kill switch before a new scan (primarily for CLI reuse/tests)."""
    _abort_event.clear()
