"""Bounded threaded HTTP(S) server.

Differences from the spike, each closing a specific gap:

* A hard cap on concurrent connections. ``ThreadingHTTPServer`` starts one thread per connection
  without limit; on a small routing engine that is a denial-of-service lever. Over the cap, new
  connections are closed immediately.
* TLS handshakes happen in the worker thread with a socket timeout. Wrapping the listening socket
  (as the spike did) runs every handshake inside ``accept()`` on the single accept thread, so one
  slow client stalls everyone.
* HTTP/1.0, one request per connection.
* One deadline for reading the whole request: the TLS handshake, request line, headers and body
  together must arrive within ``socket_timeout_s``, or the connection is shut down. A per-read
  socket timeout alone restarts with every byte, so a client trickling one byte at a time could
  hold a connection slot for ever. The deadline ends once the request is read: answering it may
  take as long as the device read it asks for.
* The request line and headers together are capped at ``MAX_HEAD_BYTES`` (the standard library
  allows 64 KiB per line and 100 headers).
* Request bodies are capped and need a Content-Length; chunked bodies are refused.
* Optional Host allowlist; no version in the Server header; errors never carry stack traces.
"""

from __future__ import annotations

import contextlib
import http.client
import logging
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, BinaryIO, Callable, Dict, List, Optional, Tuple

from jwicket.web.http import BASE_HEADERS, HSTS, Request, Response, parse_query

LOG = logging.getLogger("jwicket.web")

Route = Callable[[Request], Response]

# Request line plus headers. Browsers send a few KiB; the cap keeps a slot from pinning megabytes.
MAX_HEAD_BYTES = 16 * 1024
# A connection over the cap waits this long for a slot before it is closed. A browser loading the app
# opens about six connections at once, so two browser profiles loading together go over a cap of 8;
# their requests for static files take milliseconds, so a short wait serves them instead of failing
# the page's module graph (F1). Meanwhile the accept loop waits too: further connections queue in the
# listen backlog, holding no thread.
CONNECTION_QUEUE_S = 1.5


class HeadTooLarge(http.client.HTTPException):
    """The request line and headers together exceed MAX_HEAD_BYTES."""


class _HeadLimitedReader:
    """The handler's ``rfile``: ``readline`` (request line and headers) shares one byte budget;
    ``read`` (the body, whose length is checked separately) is passed through."""

    def __init__(self, raw: BinaryIO, limit: int) -> None:
        self._raw = raw
        self._left = limit

    def readline(self, size: int = -1) -> bytes:
        if self._left <= 0:
            raise HeadTooLarge(f"request head over {MAX_HEAD_BYTES} bytes")
        want = self._left + 1 if size is None or size < 0 else min(size, self._left + 1)
        line = self._raw.readline(want)
        self._left -= len(line)
        if self._left < 0:
            raise HeadTooLarge(f"request head over {MAX_HEAD_BYTES} bytes")
        return line

    def read(self, size: int = -1) -> bytes:
        return self._raw.read(size)

    def close(self) -> None:
        self._raw.close()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw, name)


class _ReadDeadline:
    """Shuts a connection down if its request has not been read by the deadline."""

    def __init__(self, seconds: float) -> None:
        self._lock = threading.Lock()
        self._sock: Optional[socket.socket] = None
        self._done = False
        self.fired = False
        self._timer = threading.Timer(seconds, self._fire)
        self._timer.daemon = True

    def start(self, sock: socket.socket) -> None:
        with self._lock:
            self._sock = sock
        self._timer.start()

    def retarget(self, sock: socket.socket) -> None:
        """After the TLS wrap: the wrapped socket now owns the file descriptor."""
        with self._lock:
            self._sock = sock
            fired = self.fired
        if fired:
            _shutdown(sock)

    def _fire(self) -> None:
        with self._lock:
            if self._done:
                return
            self.fired = True
            sock = self._sock
        if sock is not None:
            _shutdown(sock)

    def cancel(self) -> bool:
        """Stop the deadline. False if it had already fired (the connection is being shut down)."""
        with self._lock:
            self._done = True
            fired = self.fired
        self._timer.cancel()
        return not fired


def _shutdown(sock: socket.socket) -> None:
    # The plain socket method, also for an SSLSocket: it ends both directions on the descriptor
    # without touching the TLS object the handler thread may be reading through.
    with contextlib.suppress(OSError):
        socket.socket.shutdown(sock, socket.SHUT_RDWR)


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
        self._local = threading.local()
        super().__init__(address, Handler)

    def request_read(self) -> bool:
        """Called by the handler once the whole request has been read: ends the read deadline.
        False if the deadline had already fired, in which case the request must not be served."""
        deadline: Optional[_ReadDeadline] = getattr(self._local, "deadline", None)
        return True if deadline is None else deadline.cancel()

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(timeout=CONNECTION_QUEUE_S):
            LOG.warning("connection limit reached; closing connection from %s", client_address[0])
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        deadline = _ReadDeadline(self.socket_timeout_s)
        try:
            request.settimeout(self.socket_timeout_s)
            deadline.start(request)
            if self.tls is not None:
                try:
                    # Wrap first, then hand the deadline the wrapped socket (which now owns the file
                    # descriptor), then shake hands: a client trickling its handshake is cut off too.
                    request = self.tls.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
                    deadline.retarget(request)
                    request.do_handshake()
                except (ssl.SSLError, OSError) as exc:
                    LOG.info("TLS handshake with %s failed: %s", client_address[0], exc)
                    self.shutdown_request(request)
                    return
            self._local.deadline = deadline
            super().process_request_thread(request, client_address)
        finally:
            deadline.cancel()
            self._local.deadline = None
            self._slots.release()


class Handler(BaseHTTPRequestHandler):
    server: JWicketServer
    server_version = "jwicket"
    sys_version = ""
    protocol_version = "HTTP/1.0"
    def version_string(self) -> str:
        return self.server_version

    def setup(self) -> None:
        super().setup()
        self.rfile = _HeadLimitedReader(self.rfile, MAX_HEAD_BYTES)  # type: ignore[assignment]

    def handle_one_request(self) -> None:
        try:
            super().handle_one_request()
        except HeadTooLarge:
            # Only the request line gets here: parse_request answers an oversized header block (431).
            self.requestline = ""
            self.request_version = "HTTP/1.0"
            self.command = ""
            self.close_connection = True
            self.send_error(414, "request line too long")

    def parse_request(self) -> bool:
        ok = super().parse_request()
        if ok and self.request_version == "HTTP/0.9":
            # Python before 3.12 answers a one-word request line HTTP/0.9-style, with no headers at
            # all (so no CSP). Refuse it with a normal, fully headed response instead.
            self.request_version = "HTTP/1.0"
            self.send_error(400, "HTTP/0.9 is not supported")
            return False
        return ok

    def send_error(self, code: int, message: Optional[str] = None, explain: Optional[str] = None) -> None:
        """Every error the standard library generates (400, 414, 431, 501, timeouts) goes through the
        same response path as ours: security headers, JSON body, connection closed."""
        self.close_connection = True
        if self.request_version == "HTTP/0.9":
            self.request_version = "HTTP/1.0"
        text = message or self.responses.get(code, ("error",))[0]
        try:
            self._respond(Response.error(code, str(text)), head_only=self.command == "HEAD")
        except OSError:
            LOG.debug("client went away before error %d could be sent", code)

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
        if not self.server.request_read():
            return  # the read deadline fired: the connection is already being shut down
        try:
            query = parse_query(raw_query)
        except ValueError:
            self._respond(Response.error(400, "bad query string"))
            return
        req = Request(
            method=method,
            path=path,
            query=query,
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
        path = self.path.partition("?")[0].rstrip("/") or "/"
        allowed = self.server.router.allowed(path) or ["GET", "POST"]
        resp = Response.error(405, "method not allowed")
        resp.headers.append(("Allow", ", ".join(allowed)))
        self._respond(resp)

    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = do_TRACE = do_CONNECT = _not_allowed  # noqa: N815


def make_tls_context(cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    return ctx
