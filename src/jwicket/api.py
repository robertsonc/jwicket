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
import logging
import re
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from jwicket import __version__, resources
from jwicket.auth.backends import AuthBackend, validate_secret, validate_username
from jwicket.auth.sessions import SessionLimit, SessionStore, WebSession
from jwicket.auth.throttle import LoginThrottle, name_key
from jwicket.junos import facts
from jwicket.junos.errors import (
    JunosError,
    LoginRejected,
    LoginUnavailable,
    RpcDenied,
    RpcTimeout,
    RpcUnsupported,
    SessionLost,
)
from jwicket.junos.inventory import SCHEMA, build_inventory, configuration_root, scope_summaries
from jwicket.junos.xmlutil import local
from jwicket.junos.session import open_config
from jwicket.logs import AuditTrail
from jwicket.web.http import Request, Response, clear_cookie, session_cookie
from jwicket.web.server import Router

Json = Dict[str, Any]
LOG = logging.getLogger("jwicket.api")
_SCOPE = re.compile(r"^(root|lsys:[A-Za-z0-9._\-]{1,63}|tenant:[A-Za-z0-9._\-]{1,63})\Z")
_FILENAME_SAFE = re.compile(r"[^A-Za-z0-9._\-]+")
MIN_READ_INTERVAL_S = 2.0
# How long a request waits for its operator's device session while another read on it runs. Each
# waiting request holds a connection slot, so it waits briefly and is then answered 429.
SESSION_WAIT_S = 5.0
BUSY_RETRY_S = 2
# Device error text written to the diagnostic log is cut to this length (an ncclient RpcError string
# can carry the whole rpc-error XML).
MAX_ERROR_TEXT = 500


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


def _panel_error(err: JunosError, what: str = "device read") -> Json:
    """The operator-safe panel state for a failed read. The device's own error text goes to the
    diagnostic log (INFO, truncated), never to the browser."""
    if not getattr(err, "from_cache", False):  # a cached failure was logged when it happened
        LOG.info("%s: %s: %s", what, err.kind, str(err)[:MAX_ERROR_TEXT])
    return {"status": err.kind, "message": err.public}


class SessionBusy(Exception):
    """Another read on the same operator's device session did not finish within SESSION_WAIT_S."""


@contextmanager
def device_turn(sess: WebSession) -> Iterator[None]:
    """Exclusive use of the operator's device session (one RPC at a time), waiting at most
    SESSION_WAIT_S so that queued requests do not hold connection slots for a whole RPC timeout."""
    if not sess.lock.acquire(timeout=SESSION_WAIT_S):
        raise SessionBusy(sess.user)
    try:
        yield
    finally:
        sess.lock.release()


def busy() -> Response:
    return Response.json(
        429,
        {"error": "Another read for your session is still running. Try again shortly.", "retry_after_s": BUSY_RETRY_S},
        [("Retry-After", str(BUSY_RETRY_S))],
    )


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
    LOG.info("device session for %s lost: %s", sess.user, str(err)[:MAX_ERROR_TEXT])
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


def _throttled(wait: float, message: str) -> Response:
    seconds = max(1, int(wait + 0.999))
    return Response.json(429, {"error": message, "retry_after_s": seconds}, [("Retry-After", str(seconds))])


def login(app: App, req: Request) -> Response:
    """Sign-in. Refusals of a client that has no session are aggregated in the audit trail; only a
    sign-in that reaches the backend and fails uses up the throttle (see auth/throttle.py)."""
    if not req.same_origin():
        app.audit.record_refusal("login_refused", source=req.client, reason="cross-origin")
        return Response.error(403, "cross-origin sign-in refused")
    try:
        body = req.json()
    except (ValueError, UnicodeDecodeError):
        return Response.error(400, "expected a JSON object")
    username = str(body.get("username") or "")
    secret = str(body.get("password") or body.get("token") or "")
    per_person = app.backend.credential == "password"
    # Format checks first: a request Junos would never see costs no throttle budget and is not
    # recorded name by name (the commonest malformed user name is a password typed into it).
    try:
        if per_person:
            validate_username(username)
        validate_secret(secret)
    except LoginRejected as err:
        app.audit.record_refusal("login_failed", source=req.client, kind=err.kind, reason="format")
        return Response.error(401, err.public)
    throttle_name = username if per_person else ""
    wait = app.throttle.check(req.client, throttle_name)
    if wait is not None:
        app.audit.record_refusal("login_throttled", source=req.client, reason="failures")
        return _throttled(wait, "Too many failed sign-in attempts. Wait and try again.")
    if not app.throttle.begin():
        app.audit.record_refusal("login_throttled", source=req.client, reason="busy")
        return _throttled(BUSY_RETRY_S, "Other sign-ins are being checked. Try again in a moment.")
    try:
        # A fresh sign-in always gets a fresh session token (no fixation).
        app.sessions.remove(req.cookie())
        try:
            device = app.backend.authenticate(username, secret)
        except JunosError as err:
            if not isinstance(err, LoginUnavailable):
                app.throttle.failed(req.client, throttle_name)
            status = 401 if isinstance(err, LoginRejected) else 503
            LOG.info("sign-in from %s refused: %s: %s", req.client, err.kind, str(err)[:MAX_ERROR_TEXT])
            app.audit.record(
                "login_failed", user=None, source=req.client, kind=err.kind,
                user_hash=app.audit.pseudonym(name_key(username)) if per_person else None,
            )
            return Response.error(status, err.public)
    finally:
        app.throttle.end()
    app.throttle.succeeded(req.client, throttle_name)
    replaced: List[WebSession] = []
    try:
        token, sess = app.sessions.create(
            user=device.user, backend=app.backend.name, device=device, source=req.client,
            user_key=name_key(device.user) if per_person else None, replaced=replaced,
        )
    except SessionLimit:
        device.close()
        app.audit.record("login_refused", user=device.user, source=req.client, reason="session-limit")
        return Response.error(503, "Too many people are signed in to J-Wicket on this device. Try again later.")
    for old in replaced:
        app.audit.record("session_replaced", user=old.user, source=old.source, by=req.client)
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

    with device_turn(sess):
        try:
            device = facts.software(sess.device.rpc("get-software-information"))
        except SessionLost:
            raise
        except JunosError as err:
            device = _panel_error(err, "software information")
        try:
            config_root = configuration_root(open_config(sess.device, warnings))
            config_status = {"status": "ok"}
        except SessionLost:
            raise
        except JunosError as err:
            config_status = _panel_error(err, "inventory configuration read")
        try:
            ha = facts.cluster(sess.device.rpc("get-chassis-cluster-status"))
        except SessionLost:
            raise
        except RpcUnsupported:
            ha = facts.standalone()
        except (RpcDenied, RpcTimeout) as err:
            ha = _panel_error(err, "chassis cluster status")
        except JunosError as err:
            LOG.info("chassis cluster status: %s: %s", err.kind, str(err)[:MAX_ERROR_TEXT])
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
            # empty inventory must not be presented as "nothing is configured". J-Wicket reads only
            # security policies, zones and address books, so other security settings do not count.
            warnings.append(
                "The configuration J-Wicket read has no security section (policies, zones or address books). "
                f"Either nothing is configured, or {sess.user}'s login class cannot view it (Junos may leave "
                "it out rather than refuse)."
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
    except SessionBusy:
        return sess, busy(), None
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
