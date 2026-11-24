"""Request and response types, security headers, cookies and same-origin checks.

Defaults are strict and not configurable: a strict Content-Security-Policy with no inline script or
style (the spike needed 'unsafe-inline'; the product does not), no framing, no referrer, no caching
of API responses, and same-origin enforcement on every state-changing request.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple
from urllib.parse import parse_qs

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
    "font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; "
    "require-trusted-types-for 'script'"
)

BASE_HEADERS: Tuple[Tuple[str, str], ...] = (
    ("Content-Security-Policy", CSP),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=(), payment=()"),
    ("Cache-Control", "no-store"),
)
HSTS = ("Strict-Transport-Security", "max-age=31536000")

# Cookies are not isolated by port (RFC 6265 section 8.5): every J-Wicket reached through its own SSH
# tunnel on one workstation is "127.0.0.1" to the browser, and every daemon listens on 8443 by
# default, so a fixed name would let signing in to one device overwrite another device's session
# cookie. Each daemon therefore names its cookie with a random suffix chosen at start-up. Sessions
# live in memory and end with the process, so a new name at each start loses nothing. This does
# not keep the cookie from other services on the same host (another port, the same 127.0.0.1): a
# naming rule cannot, so the plain-HTTP tunnel is for lab use (docs/deploy-lab.md).
INSTANCE_ID = secrets.token_hex(4)
COOKIE_TLS = f"__Host-jwicket-{INSTANCE_ID}"
COOKIE_PLAIN = f"jwicket-{INSTANCE_ID}"


@dataclass
class Request:
    method: str
    path: str
    query: Dict[str, str]
    headers: Mapping[str, str]
    client: str
    tls: bool
    body: bytes = b""

    @property
    def cookie_name(self) -> str:
        return COOKIE_TLS if self.tls else COOKIE_PLAIN

    def cookie(self) -> Optional[str]:
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            name, sep, value = part.strip().partition("=")
            if sep and name == self.cookie_name and value:
                return value
        return None

    def json(self) -> Dict[str, Any]:
        ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype != "application/json":
            raise ValueError("Content-Type must be application/json")
        data = json.loads(self.body.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object")  # noqa: TRY004 - callers map ValueError to 400
        return data

    def expected_origin(self) -> Optional[str]:
        host = self.headers.get("Host")
        if not host:
            return None
        return ("https://" if self.tls else "http://") + host

    def same_origin(self) -> bool:
        """A state-changing request must carry an Origin equal to the origin it was sent to."""
        origin = self.headers.get("Origin")
        expected = self.expected_origin()
        return origin is not None and expected is not None and origin == expected


@dataclass
class Response:
    status: int
    body: bytes = b""
    content_type: str = "application/json"
    headers: List[Tuple[str, str]] = field(default_factory=list)

    @classmethod
    def json(cls, status: int, payload: Any, headers: Optional[List[Tuple[str, str]]] = None) -> Response:
        body = (json.dumps(payload, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
        return cls(status, body, "application/json", list(headers or []))

    @classmethod
    def error(cls, status: int, message: str, **extra: Any) -> Response:
        return cls.json(status, {"error": message, **extra})


def parse_query(raw: str) -> Dict[str, str]:
    parsed = parse_qs(raw, keep_blank_values=False, strict_parsing=False, max_num_fields=20)
    return {k: v[0] for k, v in parsed.items() if v}


def session_cookie(name: str, value: str, *, tls: bool) -> str:
    attrs = [f"{name}={value}", "Path=/", "HttpOnly", "SameSite=Strict"]
    if tls:
        attrs.append("Secure")
    return "; ".join(attrs)


def clear_cookie(name: str, *, tls: bool) -> str:
    return session_cookie(name, "", tls=tls) + "; Max-Age=0"
