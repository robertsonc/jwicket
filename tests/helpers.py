"""Shared helpers for the J-Wicket test suite (stdlib only, Python 3.9 syntax).

Nothing here talks to a device. Device sessions are fakes or ``jwicket.fixtures.FixtureSession``
over the synthetic fixtures in tests/fixtures.
"""

from __future__ import annotations

import http.client
import json
import socket
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from xml.etree import ElementTree

from jwicket.api import App, build_router
from jwicket.auth.sessions import SessionStore
from jwicket.auth.throttle import LoginThrottle
from jwicket.logs import AuditTrail
from jwicket.web.server import JWicketServer

FIXTURES = Path(__file__).resolve().parent / "fixtures"
BRANCH = FIXTURES / "branch"
CLUSTER = FIXTURES / "cluster-lsys"
CSV_INJECTION = FIXTURES / "synthetic-csv-injection"

# Values from tests/fixtures/branch/config.xml that must never leave J-Wicket.
BRANCH_SECRETS = ("$9$FIXTURE-PLACEHOLDER-NOT-A-SECRET", "FIXTURE-PLACEHOLDER", "FIXTURE-DEVICE-ID")

JUNOS_NS = "http://xml.juniper.net/junos/24.4R2/junos"
# FixtureBackend accepts any non-empty password for a fixture user.
FIXTURE_PASSWORD = "fixture-password"


def xml(text: str) -> Any:
    """Parse XML text into an ElementTree element (comments dropped, like most transports)."""
    return ElementTree.fromstring(text)


def xml_with_comments(text: str) -> Any:
    """Parse XML keeping comments as Comment nodes, to prove helpers skip them."""
    parser = ElementTree.XMLParser(target=ElementTree.TreeBuilder(insert_comments=True))
    parser.feed(text)
    return parser.close()


def config(security: str = "", extra: str = "", applications: str = "") -> Any:
    """A <configuration> with the junos namespace declared, like a groups="groups" reply."""
    apps = f"<applications>{applications}</applications>" if applications else ""
    return xml(
        f'<configuration xmlns:junos="{JUNOS_NS}"><security>{security}</security>{apps}{extra}</configuration>'
    )


class FakeClock:
    """A monotonic clock the test moves by hand."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeDevice:
    """A DeviceSession double that records calls and replays canned replies or errors.

    ``replies`` maps an RPC name (or ``"get-configuration"``) to an Element or to an exception
    instance to raise.
    """

    backend = "fake"

    def __init__(self, user: str = "operator", replies: Optional[Dict[str, Any]] = None) -> None:
        self._user = user
        self.replies: Dict[str, Any] = dict(replies or {})
        self.calls: List[Tuple[str, Any]] = []
        self.closed = 0

    @property
    def user(self) -> str:
        return self._user

    def _answer(self, key: str) -> Any:
        found = self.replies.get(key)
        if isinstance(found, BaseException):
            raise found
        if found is None:
            from jwicket.junos.errors import RpcUnsupported

            raise RpcUnsupported(f"fake has no {key}")
        return found

    def get_configuration(self, filter_xml: str) -> Any:
        self.calls.append(("get-configuration", filter_xml))
        return self._answer("get-configuration")

    def rpc(self, name: str, **params: Any) -> Any:
        self.calls.append((name, params))
        return self._answer(name)

    def close(self) -> None:
        self.closed += 1


class StaticBackend:
    """An AuthBackend that hands out whatever device session ``factory`` builds."""

    credential = "password"

    def __init__(self, factory: Callable[[str], Any], name: str = "fake") -> None:
        self.name = name
        self._factory = factory
        self.opened: List[Any] = []

    def authenticate(self, username: str, secret: str) -> Any:
        from jwicket.auth.backends import validate_secret, validate_username

        user = validate_username(username)
        validate_secret(secret)
        device = self._factory(user)
        self.opened.append(device)
        return device


def make_app(
    backend: Any,
    clock: Optional[FakeClock] = None,
    *,
    max_sessions: int = 4,
    max_per_user: int = 1,
    per_name: int = 100,
    per_source: int = 100,
    audit: Optional[AuditTrail] = None,
    fixture: bool = True,
    warnings: Optional[List[str]] = None,
) -> App:
    clock = clock or FakeClock()
    return App(
        backend=backend,
        sessions=SessionStore(
            idle_s=900, absolute_s=3600, max_sessions=max_sessions, max_per_user=max_per_user, clock=clock
        ),
        throttle=LoginThrottle(per_name=per_name, per_source=per_source, clock=clock),
        audit=audit or AuditTrail(None),
        session_idle_s=900,
        fixture=fixture,
        mono_clock=clock,
        extra_warnings=list(warnings or []),
    )


class Reply:
    """One HTTP response: status, headers (lower-cased names, repeated ones joined), body."""

    def __init__(self, status: int, headers: List[Tuple[str, str]], body: bytes) -> None:
        self.status = status
        self.header_list = headers
        self.headers: Dict[str, str] = {}
        for name, value in headers:
            key = name.lower()
            self.headers[key] = f"{self.headers[key]}, {value}" if key in self.headers else value
        self.body = body

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))

    def all(self, name: str) -> List[str]:
        return [v for k, v in self.header_list if k.lower() == name.lower()]


class LiveServer:
    """A real JWicketServer on 127.0.0.1, port 0, serving in a daemon thread."""

    def __init__(
        self,
        app: App,
        *,
        max_connections: int = 8,
        socket_timeout_s: float = 5.0,
        max_body_bytes: int = 8192,
        allowed_hosts: Tuple[str, ...] = (),
    ) -> None:
        self.app = app
        self.server = JWicketServer(
            ("127.0.0.1", 0),
            build_router(app),
            tls=None,
            max_connections=max_connections,
            socket_timeout_s=socket_timeout_s,
            max_body_bytes=max_body_bytes,
            allowed_hosts=allowed_hosts,
        )
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )
        self.thread.start()

    @property
    def host(self) -> str:
        return f"127.0.0.1:{self.port}"

    @property
    def origin(self) -> str:
        return f"http://{self.host}"

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        host: Optional[str] = None,
    ) -> Reply:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            # skip_host so the test controls the Host header exactly.
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            hdrs = {"Host": host if host is not None else self.host}
            hdrs.update(headers or {})
            if body is not None:
                hdrs["Content-Length"] = str(len(body))
            for name, value in hdrs.items():
                conn.putheader(name, value)
            conn.endheaders(body)
            resp = conn.getresponse()
            data = resp.read()
            return Reply(resp.status, resp.getheaders(), data)
        finally:
            conn.close()

    def get(self, path: str, cookie: Optional[str] = None, **kw: Any) -> Reply:
        headers = dict(kw.pop("headers", None) or {})
        if cookie:
            headers["Cookie"] = cookie
        return self.request("GET", path, headers=headers, **kw)

    def post_json(
        self,
        path: str,
        payload: Any,
        *,
        origin: Optional[str] = "",
        cookie: Optional[str] = None,
        content_type: str = "application/json",
        extra: Optional[Dict[str, str]] = None,
    ) -> Reply:
        headers: Dict[str, str] = {"Content-Type": content_type}
        if origin == "":
            headers["Origin"] = self.origin
        elif origin is not None:
            headers["Origin"] = origin
        if cookie:
            headers["Cookie"] = cookie
        headers.update(extra or {})
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        return self.request("POST", path, body=raw, headers=headers)

    def login(
        self, user: str = "admin", password: str = FIXTURE_PASSWORD, cookie: Optional[str] = None
    ) -> Tuple[Reply, str]:
        reply = self.post_json("/api/login", {"username": user, "password": password}, cookie=cookie)
        cookie_value = ""
        set_cookie = reply.headers.get("set-cookie")
        if set_cookie:
            cookie_value = set_cookie.split(";", 1)[0]
        return reply, cookie_value

    def raw(self, data: bytes, timeout: float = 5.0) -> bytes:
        """Send raw bytes and read until the server closes the connection."""
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=timeout)
        try:
            sock.sendall(data)
            chunks = []
            while True:
                try:
                    chunk = sock.recv(65536)
                except ConnectionResetError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            sock.close()


def parse_raw_response(data: bytes) -> Reply:
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1])
    headers = []
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers.append((name.strip(), value.strip()))
    return Reply(status, headers, body)


def wait_until(predicate: Callable[[], bool], timeout: float = 5.0, interval: float = 0.02) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()
