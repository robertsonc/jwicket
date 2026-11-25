"""JSON API for the browser. Read-only: nothing here can change the device.

Endpoints (all JSON unless noted):

* ``GET  /api/session``    who is signed in, which credential the sign-in form needs, the CSRF token,
  the version and the build (the bundle's payload digest)
* ``POST /api/login``      same-origin only, throttled; opens the operator's own Junos session
* ``POST /api/logout``     same-origin and CSRF token; closes the device session
* ``GET  /api/inventory``  ``?scope=root|lsys:<name>|tenant:<name>``; the Spec 001 snapshot
* ``GET  /api/export``     ``?scope=...&format=json|csv``; the same snapshot as a download

A GET carrying ``X-JWicket-Background: 1`` is a background poll: it is answered as usual but does not
refresh the session's idle clock (the header can only shorten a session). A request whose session has
ended is answered 401 with a ``reason`` (see ``signin_required``). A read that would collide with the
same session's identical read moments earlier gets that read's payload (``meta.reused``) instead of a
429 (``reuse_or_wait``); nothing is shared across sessions.
"""

from __future__ import annotations

import csv
import hmac
import io
import logging
import re
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from jwicket import __version__, resources
from jwicket.auth.backends import AuthBackend, validate_secret, validate_username
from jwicket.auth.sessions import Ended, SessionLimit, SessionStore, WebSession
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
from jwicket.junos.inventory import SCHEMA, build_inventory, configuration_root, scope_summaries, unselectable_warnings
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
_SHA256 = re.compile(r"^[0-9a-f]{64}\Z")
BACKGROUND_HEADER = "X-JWicket-Background"
# Session ends recorded as their own audit event; the others already have one (session_replaced,
# logout, session_lost).
AUDITED_ENDS = ("idle", "absolute", "shutdown")


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


def is_background(req: Request) -> bool:
    """A GET the browser marked as a background poll. Any other value, and any other method, is
    foreground. The header only ever skips refreshing the idle clock of the sender's own session."""
    return req.method == "GET" and (req.headers.get(BACKGROUND_HEADER) or "").strip() == "1"


def _session(app: App, req: Request) -> Optional[WebSession]:
    sess = app.sessions.get(req.cookie(), touch=not is_background(req))
    if sess is not None and sess.reuse:
        _prune(sess, app.mono_clock())  # B-8: any request of the session drops its expired reads
    return sess


def record_session_end(app: App, sess: WebSession, reason: str) -> None:
    """The store's ``on_end`` hook: audit the ends that have no audit event of their own."""
    if reason in AUDITED_ENDS:
        app.audit.record("session_ended", user=sess.user, source=sess.source, reason=reason)


def _ended_text(app: App, reason: str) -> str:
    if reason == "replaced":
        return "You were signed out: the same Junos user signed in again elsewhere."
    if reason == "idle":
        return f"Your session ended after {app.sessions.idle_s // 60} min without activity."
    if reason == "absolute":
        limit = app.sessions.absolute_s
        span = f"{limit // 3600} h" if limit % 3600 == 0 else f"{limit // 60} min"
        return f"Your session reached its {span} limit."
    if reason == "signed-out":
        return "You signed out in another tab or window."
    if reason == "session-lost":
        return "Your device session ended. Sign in again."
    return "Your J-Wicket session has ended."


def _ended_of(app: App, req: Request) -> Optional[Ended]:
    return app.sessions.ended(req.cookie())


def signin_required(app: App, req: Request) -> Response:
    """The 401 for a request without a live session, saying why when J-Wicket knows. The cookie is
    left as it is, so every tab of the browser gets the same reason; the next sign-in replaces it."""
    if not req.cookie():
        return Response.error(401, "sign-in required", reason="none")
    ended = _ended_of(app, req)
    if ended is None:
        # Evicted from the bounded tombstones, or the daemon restarted with the same cookie name.
        return Response.error(401, _ended_text(app, "unknown"), reason="unknown")
    return Response.error(401, _ended_text(app, ended.reason), reason=ended.reason, at=_utc(ended.at_wall))


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
        {"error": "Another read for your session is still running. Try again shortly.", "reason": "busy",
         "retry_after_s": BUSY_RETRY_S},
        [("Retry-After", str(BUSY_RETRY_S))],
    )


def throttle_read(app: App, sess: WebSession, bucket: str, interval_s: float) -> Optional[Response]:
    """One device read per ``interval_s`` per endpoint per signed-in operator. The floor is per session,
    so every tab and window holding the same cookie shares it."""
    now = app.mono_clock()
    last = sess.last_read.get(bucket)
    if last is not None and now - last < interval_s:
        wait = max(1, int(interval_s - (now - last) + 0.999))
        return Response.json(
            429,
            {"error": "Reading too often.", "reason": "rate", "retry_after_s": wait, "interval_s": float(interval_s)},
            [("Retry-After", str(wait))],
        )
    sess.last_read[bucket] = now
    return None


# --- per-session reuse of a read just made (B-8) ----------------------------------------------------
# A request that would collide with the same session's own identical read gets that read's payload:
# another tab of the same browser polling the same view, say. The stored value is held for one read
# floor (2 s or less), one per bucket, on the WebSession, so it is never shared across sessions (login
# classes differ) and goes with the session. An entry past its window is dropped (OD-07): on the
# session's next request of any kind, when this session stores another read, and by the reaper every
# 30 s (``prune_reuse``), so no device data stays in memory for the life of the session.

# The longest B-8 window: the inventory floor (the sessions and logs floors are 1.5 s).
REUSE_MAX_S = MIN_READ_INTERVAL_S
# At most this many requests per session and bucket wait for the identical read in flight; more get
# a busy 429 at once, so one session cannot hold the server's connection slots with parallel copies.
MAX_REUSE_WAITERS = 1
_WAITERS_LOCK = threading.Lock()


def _drop_entry(sess: WebSession, bucket: str, entry: Tuple[Any, float, Any]) -> None:
    """Drop ``entry`` unless the bucket has been given a newer one meanwhile."""
    if sess.reuse.get(bucket) is entry:
        sess.reuse.pop(bucket, None)


def _prune(sess: WebSession, now: float) -> None:
    for bucket, entry in list(sess.reuse.items()):
        if now - entry[1] >= REUSE_MAX_S:
            _drop_entry(sess, bucket, entry)


def prune_reuse(app: App) -> None:
    """Drop every signed-in session's reuse entries that are past the longest window (the reaper)."""
    now = app.mono_clock()
    for sess in app.sessions.live():
        _prune(sess, now)


def reuse_hit(app: App, sess: WebSession, bucket: str, key: Any, window_s: float) -> Optional[Any]:
    entry = sess.reuse.get(bucket)
    if entry is None:
        return None
    stored_key, stored_at, value = entry
    if app.mono_clock() - stored_at >= window_s:
        _drop_entry(sess, bucket, entry)  # past its window: nobody can use it any more
        return None
    if stored_key != key:
        return None
    return value


def _reading(sess: WebSession, bucket: str, key: Any) -> bool:
    """Whether this session has a read with this key running in this bucket (a key may be None)."""
    return bucket in sess.inflight and sess.inflight[bucket] == key


def reuse_or_wait(
    app: App, sess: WebSession, bucket: str, key: Any, window_s: float
) -> Tuple[Optional[Any], Optional[Response]]:
    """Steps 1 and 2 of B-8: (stored value, None) to answer from the read just made, (None, busy 429)
    when the identical read in flight ended without a result (or another request already waits for
    it), or (None, None) to read as usual."""
    hit = reuse_hit(app, sess, bucket, key, window_s)
    if hit is not None:
        return hit, None
    if not _reading(sess, bucket, key):
        return None, None
    with _WAITERS_LOCK:
        if sess.reuse_waiters.get(bucket, 0) >= MAX_REUSE_WAITERS:
            return None, busy()
        sess.reuse_waiters[bucket] = sess.reuse_waiters.get(bucket, 0) + 1
    try:
        # The same read is running for this session: wait for its device turn (bounded like any turn).
        deadline = time.monotonic() + SESSION_WAIT_S
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not sess.lock.acquire(timeout=remaining):
                break
            sess.lock.release()
            hit = reuse_hit(app, sess, bucket, key, window_s)
            if hit is not None:
                return hit, None
            if not _reading(sess, bucket, key):
                break
            # The read in flight has not taken its turn yet, or has not stored its result yet.
            time.sleep(0.01)
        return None, busy()
    finally:
        with _WAITERS_LOCK:
            left = sess.reuse_waiters.get(bucket, 1) - 1
            if left > 0:
                sess.reuse_waiters[bucket] = left
            else:
                sess.reuse_waiters.pop(bucket, None)


@contextmanager
def in_flight(sess: WebSession, bucket: str, key: Any) -> Iterator[None]:
    sess.inflight[bucket] = key
    try:
        yield
    finally:
        if _reading(sess, bucket, key):
            sess.inflight.pop(bucket, None)


def remember(app: App, sess: WebSession, bucket: str, key: Any, started_at: float, value: Any) -> None:
    """Keep this read for the session's identical requests within the window; drop entries past it.
    A read that took longer than the longest window is not kept: no request could use it."""
    now = app.mono_clock()
    _prune(sess, now)
    if now - started_at < REUSE_MAX_S:
        sess.reuse[bucket] = (key, started_at, value)
    else:
        sess.reuse.pop(bucket, None)


def reused_payload(payload: Json) -> Json:
    """A stored 200 payload as a reused reply: its own ``meta.read_at``, plus ``meta.reused``."""
    return {**payload, "meta": {**payload.get("meta", {}), "reused": True}}


def session_lost(app: App, sess: WebSession, req: Request, err: SessionLost) -> Response:
    LOG.info("device session for %s lost: %s", sess.user, str(err)[:MAX_ERROR_TEXT])
    app.sessions.drop(sess, "device session lost")
    app.audit.record("session_lost", user=sess.user, source=req.client)
    # The same time the cookie's tombstone holds, so later 401s for this cookie say the same.
    ended = _ended_of(app, req)
    at = ended.at_wall if ended is not None else app.wall_clock()
    return Response.error(401, err.public, signed_out=True, reason="session-lost", at=_utc(at))


def bundle_payload_sha256() -> Optional[str]:
    """The payload SHA-256 of the running bundle, which tools/bundle.py's importer puts on
    ``jwicket._embedded`` (bundle change D3 of the installation spec), or None when running from src/."""
    try:
        from jwicket import _embedded as emb  # type: ignore[attr-defined]  # generated in the bundle only
    except ImportError:
        return None
    value = getattr(emb, "PAYLOAD_SHA256", None)
    return value if isinstance(value, str) and _SHA256.match(value) else None


# --- session endpoints ----------------------------------------------------------------------------


def session_facts(app: App, sess: WebSession) -> Json:
    """What the browser needs to word session limits honestly (B-6)."""
    absolute = app.sessions.absolute_s
    return {
        "absolute_timeout_s": absolute,
        "signed_in_at": _utc(sess.created_wall),
        "ends_by": _utc(sess.created_wall + absolute),
        "max_sessions_per_user": app.sessions.max_per_user,
    }


def get_session(app: App, req: Request) -> Response:
    sess = _session(app, req)
    payload = bundle_payload_sha256()
    base: Json = {
        "credential": app.backend.credential,
        "backend": app.backend.name,
        "fixture": app.fixture,
        "version": __version__,
        "build": payload[:16] if payload else None,  # lets an installer tell which build is listening
    }
    if sess is None:
        out: Json = {"authenticated": False, **base}
        ended = _ended_of(app, req)
        if ended is not None:
            out["ended"] = {"reason": ended.reason, "at": _utc(ended.at_wall)}
        return Response.json(200, out)
    return Response.json(
        200,
        {
            "authenticated": True,
            "user": sess.user,
            "csrf": sess.csrf,
            "idle_timeout_s": app.session_idle_s,
            **session_facts(app, sess),
            **base,
            "backend": sess.backend,
        },
    )


def _throttled(wait: float, message: str, reason: str) -> Response:
    seconds = max(1, int(wait + 0.999))
    return Response.json(
        429, {"error": message, "reason": reason, "retry_after_s": seconds}, [("Retry-After", str(seconds))]
    )


def _session_limit(app: App, refusal: SessionLimit) -> Response:
    """The 503 at the session cap: counts and bounds only, no other user's name or source, and no
    Retry-After (an automatic retry would not help)."""
    return Response.json(
        503,
        {
            "error": "Too many people are signed in to J-Wicket on this device. Try again later.",
            "reason": "session-limit",
            "sessions": {"open": refusal.open_count, "max": refusal.max_sessions},
            "slot_free_by": _utc(app.wall_clock() + refusal.slot_free_by_s),
            "slot_free_by_s": refusal.slot_free_by_s,
            "slot_may_free_in_s": refusal.slot_may_free_in_s,
        },
    )


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
        return _throttled(wait, "Too many failed sign-in attempts. Wait and try again.", "login-failures")
    if not app.throttle.begin():
        app.audit.record_refusal("login_throttled", source=req.client, reason="busy")
        return _throttled(BUSY_RETRY_S, "Other sign-ins are being checked. Try again in a moment.", "login-busy")
    try:
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
            if isinstance(err, LoginUnavailable):
                return Response.error(status, err.public, reason="unavailable")
            return Response.error(status, err.public)
    finally:
        app.throttle.end()
    app.throttle.succeeded(req.client, throttle_name)
    # Only now, with Junos having accepted the credentials, is this browser's current session ended (a
    # failed sign-in leaves it alive). A fresh sign-in always gets a fresh token: no fixation.
    old = app.sessions.remove(req.cookie(), reason="new-sign-in")
    if old is not None:
        app.audit.record("logout", user=old.user, source=req.client, reason="new-sign-in")
    replaced: List[WebSession] = []
    try:
        token, sess = app.sessions.create(
            user=device.user, backend=app.backend.name, device=device, source=req.client,
            user_key=name_key(device.user) if per_person else None, replaced=replaced,
        )
    except SessionLimit as refusal:
        device.close()
        app.audit.record("login_refused", user=device.user, source=req.client, reason="session-limit")
        return _session_limit(app, refusal)
    for gone in replaced:
        app.audit.record("session_replaced", user=gone.user, source=gone.source, by=req.client)
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
            **session_facts(app, sess),
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


MINIMAL_MANAGEMENT = {
    "status": "unsupported",
    "message": "Central management was not read: the device rejected the configuration filter that includes it.",
}
MINIMAL_HA_NOTE = "Multinode HA settings were not read (the device rejected the full configuration filter)."
MINIMAL_CLOCK = {
    "status": "unsupported",
    "message": "The time zone was not read: the device rejected the configuration filter that includes it.",
}


def read_snapshot(app: App, sess: WebSession, scope: str) -> Tuple[int, Json]:
    """One consistent read for one operator: device facts, HA, central management, inventory."""
    warnings: List[str] = list(app.extra_warnings)
    read_at = app.wall_clock()
    device: Json
    ha: Json
    management: Json = {"status": "failed", "message": "Not read."}
    config_status: Json
    clock: Json
    inventories: Dict[str, Json] = {}
    config_root = None
    used: Dict[str, str] = {}

    with device_turn(sess):
        try:
            device = facts.software(sess.device.rpc("get-software-information"))
        except SessionLost:
            raise
        except JunosError as err:
            device = _panel_error(err, "software information")
        try:
            config_root = configuration_root(open_config(sess.device, warnings, report=used))
            config_status = {"status": "ok", "filter": used.get("filter", "full")}
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

    minimal = config_status.get("filter") == "minimal"
    if config_root is None:
        # Central management and the time zone are read from the configuration, so they share its
        # fate. J-Wicket never assumes UTC when the configuration was not read.
        management = dict(config_status)
        clock = dict(config_status)
    else:
        inventories = build_inventory(config_root)
        if minimal:
            # The minimal filter has no system or chassis part: not read is not "not configured".
            management = dict(MINIMAL_MANAGEMENT)
            clock = dict(MINIMAL_CLOCK)
        else:
            management = facts.central_management(config_root)
            clock = facts.time_zone(config_root)
        if not any(local(c.tag) == "security" for c in config_root):
            # Junos may leave out what a login class cannot view rather than refuse the read, so an
            # empty inventory must not be presented as "nothing is configured". J-Wicket reads only
            # security policies, zones and address books, so other security settings do not count.
            warnings.append(
                "The configuration J-Wicket read has no security section (policies, zones or address books). "
                f"Either nothing is configured, or {sess.user}'s login class cannot view it (Junos may leave "
                "it out rather than refuse)."
            )
        if ha.get("mode") == "standalone":
            if minimal:
                note = ha.get("message")
                ha = {**ha, "message": f"{note} {MINIMAL_HA_NOTE}" if note else MINIMAL_HA_NOTE}
            elif facts.mnha_configured(config_root):
                ha = {"status": "ok", "mode": "mnha", "message": "Multinode High Availability is configured."}
        warnings.extend(unselectable_warnings(inventories))

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
        "clock": clock,
        "scope": inventories.get(scope),
        "warnings": warnings,
    }
    return 200, payload


def _read_guarded(
    app: App, req: Request, bucket: str = "inventory", *, reuse: bool = True
) -> Tuple[Optional[WebSession], Response, Optional[Json]]:
    """A snapshot read with its guards. The payload is returned only for a read made by this request
    (so the caller audits it); a reply reused from this session's identical read (``reuse``) is not."""
    sess = _session(app, req)
    if sess is None:
        return None, signin_required(app, req), None
    scope = req.query.get("scope", "root")
    if not _SCOPE.match(scope):
        return sess, Response.error(400, "bad scope"), None
    if reuse:
        hit, refusal = reuse_or_wait(app, sess, bucket, scope, MIN_READ_INTERVAL_S)
        if hit is not None:
            return sess, Response.json(200, reused_payload(hit)), None
        if refusal is not None:
            return sess, refusal, None
    limited = throttle_read(app, sess, bucket, MIN_READ_INTERVAL_S)
    if limited is not None:
        return sess, limited, None
    started = app.mono_clock()
    try:
        with in_flight(sess, bucket, scope):
            status, payload = read_snapshot(app, sess, scope)
            if reuse and status == 200:
                remember(app, sess, bucket, scope, started, payload)
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
    "application_implicit", "dynamic_application", "comment", "pair_comment",
)


def _csv_cell(value: Any) -> str:
    if isinstance(value, list):
        value = " ".join(str(v) for v in value)
    text = "" if value is None else str(value)
    # Spreadsheet formula injection: neutralise cells a spreadsheet would evaluate.
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        text = "'" + text
    return text


def _csv_comment(row: Json) -> str:
    """The rule's comment, then each comment inside it (``before <statement>: <text>`` or ``at the end:
    <text>``), joined by `` | ``. Written exactly as on the device (owner decision OD-08)."""
    parts: List[str] = []
    if row.get("comment"):
        parts.append(str(row["comment"]))
    for note in row.get("part_comments") or []:
        before = note.get("before")
        parts.append(f"before {before}: {note.get('text')}" if before else f"at the end: {note.get('text')}")
    return " | ".join(parts)


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
        match = row["match"]
        writer.writerow([
            _csv_cell(v)
            for v in (
                row["scope"], row["kind"], row["seq"], row["from"], row["to"], row["name"], row["action"],
                match["source"], match["destination"], match["application"],
                row["inactive_reason"] or "", row["group"], row["inherited"], row["log"]["init"],
                row["log"]["close"], row["count"], row["scheduler"], row["description"],
                "true" if match.get("application_implicit") else "false",
                match.get("dynamic_application") or [],
                _csv_comment(row),
                row.get("pair_comment"),
            )
        ])
    return out.getvalue().encode("utf-8")


def export(app: App, req: Request) -> Response:
    fmt = req.query.get("format", "json")
    if fmt not in ("json", "csv"):
        return Response.error(400, "format must be json or csv")
    # Its own read bucket: an export right after loading the page is the normal sequence. Never
    # answered from a stored read: an export promises a fresh read.
    sess, resp, payload = _read_guarded(app, req, bucket="export", reuse=False)
    if sess is None or payload is None:
        return resp
    config = payload.get("config") or {}
    config_state = str(config.get("status") or "failed")
    scope_id = payload["meta"]["scope"]
    if fmt == "csv" and (config_state != "ok" or payload.get("scope") is None):
        app.audit.record("export", user=sess.user, source=req.client, scope=scope_id, format=fmt, status=config_state)
        return Response.json(
            409,
            {
                "error": (
                    f"The configuration was not read ({config_state}: {config.get('message') or 'no reason given'}), "
                    "so there are no policies to export as CSV."
                ),
                "config": {"status": config_state, "message": config.get("message")},
            },
        )
    host = _FILENAME_SAFE.sub("_", str((payload.get("device") or {}).get("hostname") or "device"))[:40]
    scope = _FILENAME_SAFE.sub("_", scope_id)
    stamp = payload["meta"]["read_at"].replace(":", "").replace("-", "")
    state = "" if config_state == "ok" else f"-config-{_FILENAME_SAFE.sub('_', config_state)}"
    filename = f"jwicket-{host}-{scope}-{stamp}{state}.{fmt}"
    app.audit.record("export", user=sess.user, source=req.client, scope=scope_id, format=fmt, status=config_state)
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
__all__ = ["App", "RpcDenied", "build_router", "bundle_payload_sha256", "read_snapshot", "signin_required"]
