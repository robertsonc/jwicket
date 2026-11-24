"""Authentication backends. J-Wicket stores no passwords and invents no roles.

``netconf`` (the product design): the operator's user name and password are handed to Junos in a
NETCONF session to the device's own loopback address and are not kept. Junos applies its own
authentication order (local, RADIUS, TACACS+) and the operator's login class to everything that
session does afterwards. The loopback NETCONF port must be below 1024 so that only a root-owned
service (sshd) can be listening there; settings.py enforces that.

``lab-token`` (spike carry-over): one shared token; every read runs as the daemon's own Junos
account. Allowed only on a loopback bind (settings.py), shown on every screen, and recorded in the
audit trail. It exists so the read path can be exercised before Q-AUTH-01 passes on a device.
"""

from __future__ import annotations

import hmac
import os
import pwd
import re
from typing import Callable, Protocol

from jwicket.junos.errors import LoginRejected
from jwicket.junos.session import DeviceSession, PyEzLocalSession, PyEzUserSession

# Junos local user names are short; remote (RADIUS/TACACS+) names may carry a realm.
_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@\-]{0,63}$")
MAX_SECRET_LEN = 512


class AuthBackend(Protocol):
    name: str
    credential: str  # "password" or "token"; tells the UI which form to show

    def authenticate(self, username: str, secret: str) -> DeviceSession: ...


def validate_username(username: str) -> str:
    if not _USERNAME.match(username):
        raise LoginRejected(f"user name {username[:70]!r} rejected by format check")
    return username


def validate_secret(secret: str) -> str:
    if not secret or len(secret) > MAX_SECRET_LEN:
        raise LoginRejected("empty or oversized secret")
    return secret


Opener = Callable[..., DeviceSession]


class NetconfBackend:
    name = "netconf"
    credential = "password"

    def __init__(self, *, host: str, port: int, timeout_s: int, opener: Opener = PyEzUserSession.open) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout_s
        self._opener = opener

    def authenticate(self, username: str, secret: str) -> DeviceSession:
        user = validate_username(username)
        password = validate_secret(secret)
        return self._opener(host=self._host, port=self._port, user=user, password=password, timeout_s=self._timeout)


def daemon_account() -> str:
    try:
        return pwd.getpwuid(os.geteuid()).pw_name
    except KeyError:
        return f"uid {os.geteuid()}"


class LabTokenBackend:
    name = "lab-token"
    credential = "token"

    def __init__(
        self,
        *,
        token: bytes,
        timeout_s: int,
        account: str = "",
        factory: Callable[[str, int], DeviceSession] = PyEzLocalSession,
    ) -> None:
        self._token = token
        self._timeout = timeout_s
        self._account = account or daemon_account()
        self._factory = factory

    @property
    def account(self) -> str:
        return self._account

    def authenticate(self, username: str, secret: str) -> DeviceSession:
        presented = validate_secret(secret).strip().encode("utf-8", "replace")
        if not hmac.compare_digest(presented, self._token):
            raise LoginRejected("lab token mismatch", "That token was not accepted.")
        return self._factory(self._account, self._timeout)
