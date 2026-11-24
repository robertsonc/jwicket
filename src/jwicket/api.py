"""JSON API for the browser. Read-only: nothing here can change the device.

Endpoints (all JSON unless noted):

* ``GET  /api/session``    who is signed in, which credential the sign-in form needs, the CSRF token
* ``POST /api/login``      same-origin only, throttled; opens the operator's own Junos session
* ``POST /api/logout``     same-origin and CSRF token; closes the device session
* ``GET  /api/inventory``  ``?scope=root|lsys:<name>|tenant:<name>``; the Spec 001 snapshot
* ``GET  /api/export``     ``?scope=...&format=json|csv``; the same snapshot as a download
"""

from __future__ import annotations

import csv
import hmac
import io
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from jwicket import __version__, resources
from jwicket.auth.backends import AuthBackend
from jwicket.auth.sessions import SessionLimit, SessionStore, WebSession
from jwicket.auth.throttle import LoginThrottle
from jwicket.junos import facts
from jwicket.junos.errors import JunosError, LoginRejected, RpcDenied, RpcTimeout, RpcUnsupported, SessionLost
from jwicket.junos.inventory import SCHEMA, build_inventory, configuration_root, scope_summaries
from jwicket.junos.xmlutil import local
from jwicket.junos.session import open_config
from jwicket.logs import AuditTrail
from jwicket.web.http import Request, Response, clear_cookie, session_cookie
from jwicket.web.server import Router

Json = Dict[str, Any]
_SCOPE = re.compile(r"^(root|lsys:[A-Za-z0-9._\-]{1,63}|tenant:[A-Za-z0-9._\-]{1,63})\Z")
_FILENAME_SAFE = re.compile(r"[^A-Za-z0-9._\-]+")
MIN_READ_INTERVAL_S = 2.0


@dataclass
class App:
    backend: AuthBackend
    sessions: SessionStore
    throttle: LoginThrottle
    audit: AuditTrail
    session_idle_s: int
    fixture: bool = False
    wall_clock: Callable[[], float] = time.time
    mono_clock: Callable[[], float] = time.monotonic
    extra_warnings: List[str] = field(default_factory=list)


# --- helpers --------------------------------------------------------------------------------------


def _session(app: App, req: Request) -> Optional[WebSession]:
    return app.sessions.get(req.cookie())


def _csrf_ok(sess: WebSession, req: Request) -> bool:
    presented = req.headers.get("X-CSRF-Token") or ""
    return hmac.compare_digest(presented.encode("utf-8"), sess.csrf.encode("utf-8"))


def _utc(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _panel_error(err: JunosError) -> Json:
    return {"status": err.kind, "message": err.public}


def throttle_read(app: App, sess: WebSession, bucket: str, interval_s: float) -> Optional[Response]:
    """One device read per ``interval_s`` per endpoint per signed-in operator."""
    now = app.mono_clock()
    last = sess.last_read.get(bucket)
    if last is not None and now - last < interval_s:
        wait = max(1, int(interval_s - (now - last) + 0.999))
        return Response.json(429, {"error": "Reading too often.", "retry_after_s": wait}, [("Retry-After", str(wait))])
    sess.last_read[bucket] = now
    return None


def session_lost(app: App, sess: WebSession, req: Request, err: SessionLost) -> Response:
    app.sessions.drop(sess, "device session lost")
    app.audit.record("session_lost", user=sess.user, source=req.client)
    return Response.error(401, err.public, signed_out=True)


# --- session endpoints ----------------------------------------------------------------------------


def get_session(app: App, req: Request) -> Response:
    sess = _session(app, req)
    base: Json = {
        "credential": app.backend.credential,
        "backend": app.backend.name,
        "fixture": app.fixture,
        "version": __version__,
    }
    if sess is None:
        return Response.json(200, {"authenticated": False, **base})
    return Response.json(
        200,
        {
            "authenticated": True,
            "user": sess.user,
            "csrf": sess.csrf,
            "idle_timeout_s": app.session_idle_s,
            **base,
            "backend": sess.backend,
        },
    )


def login(app: App, req: Request) -> Response:
    if not req.same_origin():
        app.audit.record("login_refused", user=None, source=req.client, reason="cross-origin")
        return Response.error(403, "cross-origin sign-in refused")
    wait = app.throttle.attempt(req.client)
    if wait is not None:
        app.audit.record("login_throttled", user=None, source=req.client)
        return Response.json(
            429, {"error": "Too many sign-in attempts. Wait and try again."}, [("Retry-After", str(int(wait)))]
        )
    try:
        body = req.json()
    except (ValueError, UnicodeDecodeError):
        return Response.error(400, "expected a JSON object")
    username = str(body.get("username") or "")
    secret = str(body.get("password") or body.get("token") or "")
    # A fresh sign-in always gets a fresh session token (no fixation).
    app.sessions.remove(req.cookie())
    try:
        device = app.backend.authenticate(username, secret)
    except JunosError as err:
        status = 401 if isinstance(err, LoginRejected) else 503
        app.audit.record("login_failed", user=username[:64] or None, source=req.client, kind=err.kind)
        return Response.error(status, err.public)
    try:
        token, sess = app.sessions.create(
            user=device.user, backend=app.backend.name, device=device, source=req.client
        )
    except SessionLimit:
        device.close()
        app.audit.record("login_refused", user=device.user, source=req.client, reason="session-limit")
        return Response.error(503, "Too many people are signed in to J-Wicket on this device. Try again later.")
    app.audit.record("login", user=sess.user, source=req.client, backend=sess.backend)
    return Response.json(
        200,
        {
            "authenticated": True,
            "user": sess.user,
            "csrf": sess.csrf,
            "backend": sess.backend,
            "credential": app.backend.credential,
            "idle_timeout_s": app.session_idle_s,
            "fixture": app.fixture,
            "version": __version__,
        },
        [("Set-Cookie", session_cookie(req.cookie_name, token, tls=req.tls))],
    )


def logout(app: App, req: Request) -> Response:
    if not req.same_origin():
        return Response.error(403, "cross-origin request refused")
    sess = _session(app, req)
    clear = [("Set-Cookie", clear_cookie(req.cookie_name, tls=req.tls))]
    if sess is None:
        return Response.json(200, {"authenticated": False}, clear)
    if not _csrf_ok(sess, req):
        return Response.error(403, "missing or wrong CSRF token")
    app.sessions.remove(req.cookie())
    app.audit.record("logout", user=sess.user, source=req.client)
    return Response.json(200, {"authenticated": False}, clear)


# --- the read path --------------------------------------------------------------------------------


def read_snapshot(app: App, sess: WebSession, scope: str) -> Tuple[int, Json]:
    """One consistent read for one operator: device facts, HA, central management, inventory."""
    warnings: List[str] = list(app.extra_warnings)
    read_at = app.wall_clock()
    device: Json
    ha: Json
    management: Json = {"status": "failed", "message": "Not read."}
    config_status: Json
    inventories: Dict[str, Json] = {}
    config_root = None

    with sess.lock:
        try:
            device = facts.software(sess.device.rpc("get-software-information"))
        except SessionLost:
            raise
        except JunosError as err:
            device = _panel_error(err)
        try:
            config_root = configuration_root(open_config(sess.device, warnings))
            config_status = {"status": "ok"}
        except SessionLost:
            raise
        except JunosError as err:
            config_status = _panel_error(err)
        try:
            ha = facts.cluster(sess.device.rpc("get-chassis-cluster-status"))
        except SessionLost:
            raise
        except RpcUnsupported:
            ha = facts.standalone()
        except (RpcDenied, RpcTimeout) as err:
            ha = _panel_error(err)
        except JunosError as err:
            # The standalone error wording is not documented, so any other error from the cluster
            # status RPC means "not a chassis cluster as far as this read can tell", said plainly.
            ha = {**facts.standalone(), "message": f"Chassis cluster status was not available ({err.public})."}

    if config_root is None:
        # Central management is read from the configuration, so it shares the configuration's fate.
        management = dict(config_status)
    else:
        inventories = build_inventory(config_root)
        management = facts.central_management(config_root)
        if not any(local(c.tag) == "security" for c in config_root):
            # Junos may leave out what a login class cannot view rather than refuse the read, so an
            # empty inventory must not be presented as "nothing is configured".
            warnings.append(
                "The configuration J-Wicket read has no security section. Either nothing is configured, "
                f"or {sess.user}'s login class cannot view it (Junos may leave it out rather than refuse)."
            )
        if ha.get("mode") == "standalone" and facts.mnha_configured(config_root):
            ha = {"status": "ok", "mode": "mnha", "message": "Multinode High Availability is configured."}

    if config_root is not None and scope not in inventories:
        return 404, {"error": "unknown scope", "scopes": scope_summaries(inventories)}

    payload: Json = {
        "meta": {
            "schema": SCHEMA,
            "read_at": _utc(read_at),
            "scope": scope,
            "scopes": scope_summaries(inventories),
            "read_as": {"user": sess.user, "backend": sess.backend},
            "source": {"database": "committed", "inheritance": True, "groups_annotated": True},
            "fixture": app.fixture,
            "generator": f"jwicket {__version__}",
        },
        "device": device,
        "ha": ha,
        "management": management,
        "config": config_status,
        "scope": inventories.get(scope),
        "warnings": warnings,
    }
    return 200, payload


def _read_guarded(
    app: App, req: Request, bucket: str = "inventory"
) -> Tuple[Optional[WebSession], Response, Optional[Json]]:
    sess = _session(app, req)
    if sess is None:
        return None, Response.error(401, "sign-in required"), None
    scope = req.query.get("scope", "root")
    if not _SCOPE.match(scope):
        return sess, Response.error(400, "bad scope"), None
    limited = throttle_read(app, sess, bucket, MIN_READ_INTERVAL_S)
    if limited is not None:
        return sess, limited, None
    try:
        status, payload = read_snapshot(app, sess, scope)
    except SessionLost as err:
        return None, session_lost(app, sess, req, err), None
    if status != 200:
        return sess, Response.json(status, payload), None
    return sess, Response.json(200, payload), payload


def inventory(app: App, req: Request) -> Response:
    sess, resp, payload = _read_guarded(app, req)
    if sess is not None and payload is not None:
        scope_inv = payload.get("scope") or {}
        count = len(((scope_inv.get("policies") or {}).get("rows")) or [])
        app.audit.record("read_inventory", user=sess.user, source=req.client, scope=req.query.get("scope", "root"),
                         policies=count, config=payload["config"]["status"])
    return resp


_CSV_COLUMNS = (
    "scope", "kind", "seq", "from", "to", "name", "action", "source", "destination", "application",
    "inactive", "group", "inherited", "log_init", "log_close", "count", "scheduler", "description",
)


def _csv_cell(value: Any) -> str:
    if isinstance(value, list):
        value = " ".join(str(v) for v in value)
    text = "" if value is None else str(value)
    # Spreadsheet formula injection: neutralise cells a spreadsheet would evaluate.
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        text = "'" + text
    return text


def _to_csv(payload: Json) -> bytes:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    meta = payload["meta"]
    device = payload.get("device") or {}
    title = (
        f"# J-Wicket policy inventory, read {meta['read_at']} from the committed configuration of "
        f"{device.get('hostname') or 'unknown'} as {meta['read_as']['user']}; scope {meta['scope']}"
    )
    writer.writerow([_csv_cell(title)])
    writer.writerow(_CSV_COLUMNS)
    rows = ((payload.get("scope") or {}).get("policies") or {}).get("rows") or []
    for row in rows:
        writer.writerow([
            _csv_cell(v)
            for v in (
                row["scope"], row["kind"], row["seq"], row["from"], row["to"], row["name"], row["action"],
                row["match"]["source"], row["match"]["destination"], row["match"]["application"],
                row["inactive_reason"] or "", row["group"], row["inherited"], row["log"]["init"],
                row["log"]["close"], row["count"], row["scheduler"], row["description"],
            )
        ])
    return out.getvalue().encode("utf-8")


def export(app: App, req: Request) -> Response:
    fmt = req.query.get("format", "json")
    if fmt not in ("json", "csv"):
        return Response.error(400, "format must be json or csv")
    # Its own read bucket: an export right after loading the page is the normal sequence.
    sess, resp, payload = _read_guarded(app, req, bucket="export")
    if sess is None or payload is None:
        return resp
    host = _FILENAME_SAFE.sub("_", str((payload.get("device") or {}).get("hostname") or "device"))[:40]
    scope = _FILENAME_SAFE.sub("_", payload["meta"]["scope"])
    stamp = payload["meta"]["read_at"].replace(":", "").replace("-", "")
    filename = f"jwicket-{host}-{scope}-{stamp}.{fmt}"
    app.audit.record("export", user=sess.user, source=req.client, scope=payload["meta"]["scope"], format=fmt)
    disposition = ("Content-Disposition", f'attachment; filename="{filename}"')
    if fmt == "csv":
        return Response(200, _to_csv(payload), "text/csv; charset=utf-8", [disposition])
    resp.headers.append(disposition)
    return resp


# --- static and health ----------------------------------------------------------------------------


def serve_asset(name: str) -> Response:
    found = resources.asset(name)
    if found is None:
        return Response.error(404, "not found")
    body, ctype, etag = found
    return Response(200, body, ctype, [("ETag", f'"{etag}"')])


def healthz(_req: Request) -> Response:
    return Response.json(200, {"status": "ok"})


def build_router(app: App) -> Router:
    router = Router()
    router.add("GET", "/", lambda _r: serve_asset("index.html"))
    router.add_prefix("GET", "/static/", lambda _r, rest: serve_asset(rest))
    router.add("GET", "/healthz", healthz)
    router.add("GET", "/api/session", lambda r: get_session(app, r))
    router.add("POST", "/api/login", lambda r: login(app, r))
    router.add("POST", "/api/logout", lambda r: logout(app, r))
    router.add("GET", "/api/inventory", lambda r: inventory(app, r))
    router.add("GET", "/api/export", lambda r: export(app, r))
    from jwicket import live  # live imports helpers from this module, so import it late

    live.register(router, app)
    return router


# Re-exported for tests that want to assert error mapping without reaching into junos.errors.
__all__ = ["App", "RpcDenied", "build_router", "read_snapshot"]
