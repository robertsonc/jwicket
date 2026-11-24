"""A small, closed set of failure kinds, so the UI can say *why* something is missing.

The spike filled unreadable panels with rows tagged "sample data". The product never does: a panel
is either real device data or one of these explicit states.
"""

from __future__ import annotations

import re


class JunosError(Exception):
    """Base class. ``public`` is safe to show to the signed-in operator; ``str()`` is for logs."""

    kind = "failed"

    def __init__(self, message: str, public: str = "") -> None:
        super().__init__(message)
        self.public = public or "The device could not complete the request."


class RpcDenied(JunosError):
    """The operator's Junos login class does not permit this read."""

    kind = "denied"

    def __init__(self, message: str, public: str = "") -> None:
        super().__init__(message, public or "Your Junos login class does not allow this.")


class RpcUnsupported(JunosError):
    """The feature or RPC is not present or not enabled on this device."""

    kind = "unsupported"

    def __init__(self, message: str, public: str = "") -> None:
        super().__init__(message, public or "This device does not support or has not enabled this.")


class RpcFailed(JunosError):
    """Timeout, transport loss, malformed reply or anything else."""

    kind = "failed"


class LoginRejected(JunosError):
    """Junos refused the credentials."""

    kind = "rejected"

    def __init__(self, message: str, public: str = "") -> None:
        super().__init__(message, public or "Sign-in failed. Check the user name and password.")


class LoginUnavailable(JunosError):
    """The local management service did not answer, so no one can sign in."""

    kind = "unavailable"

    def __init__(self, message: str, public: str = "") -> None:
        super().__init__(message, public or "J-Wicket could not reach the device's management service.")


class SessionLost(JunosError):
    """The operator's NETCONF session closed; they must sign in again (no password is kept)."""

    kind = "session-lost"

    def __init__(self, message: str, public: str = "") -> None:
        super().__init__(message, public or "Your device session ended. Sign in again.")


_DENIED = re.compile(r"permission denied|not authorized|authorization", re.IGNORECASE)
# Verified wording for the standalone case is pending a recorded reply (qualification Q-REL-01);
# these patterns are deliberately narrow so that an unexpected error is reported as a failure.
_UNSUPPORTED = re.compile(
    r"not enabled|syntax error|unknown command|not supported|is not running", re.IGNORECASE
)


def classify(exc: BaseException) -> JunosError:
    """Map a PyEZ/ncclient exception to one of our kinds without importing PyEZ."""
    if isinstance(exc, JunosError):
        return exc
    name = type(exc).__name__
    text = f"{name}: {exc}"
    if name in ("ConnectAuthError",):
        return LoginRejected(text)
    if name in ("ConnectRefusedError", "ConnectTimeoutError", "ConnectUnknownHostError", "ConnectError"):
        return LoginUnavailable(text)
    if name in ("ConnectClosedError",):
        return SessionLost(text)
    if name == "PermissionError" or _DENIED.search(str(exc)):
        return RpcDenied(text)
    if name == "RpcTimeoutError":
        return RpcFailed(text, "The device took too long to answer.")
    if _UNSUPPORTED.search(str(exc)):
        return RpcUnsupported(text)
    return RpcFailed(text)
