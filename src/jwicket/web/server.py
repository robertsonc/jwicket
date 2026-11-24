"""Bounded threaded HTTP(S) server.

Differences from the spike, each closing a specific gap:

* A hard cap on concurrent connections. ``ThreadingHTTPServer`` starts one thread per connection
  without limit; on a small routing engine that is a denial-of-service lever. Over the cap, new
  connections are closed immediately.
* TLS handshakes happen in the worker thread with a socket timeout. Wrapping the listening socket
  (as the spike did) runs every handshake inside ``accept()`` on the single accept thread, so one
  slow client stalls everyone.
* HTTP/1.0, one request per connection, so a connection slot is never held idle.
* Request bodies are capped and need a Content-Length; chunked bodies are refused.
* Optional Host allowlist; no version in the Server header; errors never carry stack traces.
"""

from __future__ import annotations

import logging
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple

from jwicket.web.http import BASE_HEADERS, HSTS, Request, Response, parse_query

LOG = logging.getLogger("jwicket.web")

Route = Callable[[Request], Response]


class Router:
    """Exact-path routes, plus prefix routes whose handler receives the remainder of the path."""

    def __init__(self) -> None:
        self._routes: Dict[Tuple[str, str], Route] = {}
        self._prefixes: List[Tuple[str, str, Callable[[Request, str], Response]]] = []

    def add(self, method: str, path: str, handler: Route) -> None:
        self._routes[(method, path)] = handler

    def add_prefix(self, method: str, prefix: str, handler: Callable[[Request, str], Response]) -> None:
        self._prefixes.append((method, prefix, handler))

    def allowed(self, path: str) -> List[str]:
        methods = {m for (m, p) in self._routes if p == path}
        methods |= {m for (m, pre, _h) in self._prefixes if path.startswith(pre)}
        return sorted(methods)

    def dispatch(self, req: Request) -> Response:
        handler = self._routes.get((req.method, req.path))
        if handler is not None:
            return handler(req)
        for method, prefix, prefix_handler in self._prefixes:
            if method == req.method and req.path.startswith(prefix):
                return prefix_handler(req, req.path[len(prefix):])
        methods = self.allowed(req.path)
        if methods:
            resp = Response.error(405, "method not allowed")
            resp.headers.append(("Allow", ", ".join(methods)))
            return resp
        return Response.error(404, "not found")


class JWicketServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 16

    def __init__(
        self,
        address: Tuple[str, int],
        router: Router,
        *,
        tls: Optional[ssl.SSLContext],
        max_connections: int,
        socket_timeout_s: float,
        max_body_bytes: int,
        allowed_hosts: Tuple[str, ...] = (),
    ) -> None:
        self.address_family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
        self.router = router
        self.tls = tls
        self.socket_timeout_s = socket_timeout_s
        self.max_body_bytes = max_body_bytes
        self.allowed_hosts = tuple(h.lower() for h in allowed_hosts)
        self._slots = threading.BoundedSemaphore(max_connections)
        super().__init__(address, Handler)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            LOG.warning("connection limit reached; closing connection from %s", client_address[0])
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            request.settimeout(self.socket_timeout_s)
            if self.tls is not None:
                try:
                    request = self.tls.wrap_socket(request, server_side=True)
                except (ssl.SSLError, OSError) as exc:
                    LOG.info("TLS handshake with %s failed: %s", client_address[0], exc)
                    self.shutdown_request(request)
                    return
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class Handler(BaseHTTPRequestHandler):
    server: JWicketServer
    server_version = "jwicket"
    sys_version = ""
    protocol_version = "HTTP/1.0"
    error_content_type = "application/json"
    error_message_format = '{"error": "%(message)s"}\n'

    def version_string(self) -> str:
        return self.server_version

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        LOG.info("%s %s", self.client_address[0], format % args)

    def _respond(self, resp: Response, *, head_only: bool = False) -> None:
        self.send_response(resp.status)
        for name, value in BASE_HEADERS:
            if name == "Cache-Control" and any(h[0] == "Cache-Control" for h in resp.headers):
                continue
            self.send_header(name, value)
        if self.server.tls is not None:
            self.send_header(*HSTS)
        self.send_header("Content-Type", resp.content_type)
        self.send_header("Content-Length", str(len(resp.body)))
        for name, value in resp.headers:
            self.send_header(name, value)
        self.end_headers()
        if not head_only:
            self.wfile.write(resp.body)

    def _host_ok(self) -> bool:
        if not self.server.allowed_hosts:
            return True
        host = (self.headers.get("Host") or "").lower()
        return host in self.server.allowed_hosts

    def _read_body(self) -> Optional[bytes]:
        if self.headers.get("Transfer-Encoding"):
            self._respond(Response.error(411, "a Content-Length is required"))
            return None
        raw = self.headers.get("Content-Length")
        if raw is None:
            return b""
        try:
            length = int(raw)
        except ValueError:
            self._respond(Response.error(400, "bad Content-Length"))
            return None
        if length < 0 or length > self.server.max_body_bytes:
            self._respond(Response.error(413, "request body too large"))
            return None
        return self.rfile.read(length)

    def _handle(self, method: str) -> None:
        if not self._host_ok():
            self._respond(Response.error(421, "unexpected Host header"))
            return
        target, _, raw_query = self.path.partition("?")
        if not target.startswith("/") or "\x00" in target:
            self._respond(Response.error(400, "bad request target"))
            return
        path = target.rstrip("/") or "/"
        body = b""
        if method == "POST":
            read = self._read_body()
            if read is None:
                return
            body = read
        req = Request(
            method=method,
            path=path,
            query=parse_query(raw_query),
            headers=self.headers,  # type: ignore[arg-type]  # email.message.Message is a Mapping enough
            client=str(self.client_address[0]),
            tls=self.server.tls is not None,
            body=body,
        )
        try:
            resp = self.server.router.dispatch(req)
        except Exception:
            LOG.exception("unhandled error serving %s %s", method, path)
            resp = Response.error(500, "internal error")
        self._respond(resp)

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        self._handle("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._handle("POST")

    def _not_allowed(self) -> None:
        self._respond(Response.error(405, "method not allowed"))

    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = do_TRACE = do_CONNECT = _not_allowed  # noqa: N815


def make_tls_context(cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    return ctx
