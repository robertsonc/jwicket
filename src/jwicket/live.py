"""Spec 004 endpoints: live flow sessions and logs. Read-only.

* ``GET /api/sessions?src=&dst=&sport=&dport=&proto=&app=&iface=&limit=``
* ``GET /api/logs/sources``
* ``GET /api/logs?source=file:<name>&cursor=<n:digest>&lines=&contains=&exclude=``
* ``GET /api/logs?source=report&type=<report type>&start=&stop=&count=&expression=``
* ``GET /api/logs?source=buffer&since=<YYYY-MM-DD.HH:MM:SS>``

Every device read runs on the signed-in operator's own Junos session. ``/api/sessions`` and
``/api/logs`` are rate-limited per endpoint (and per log source); ``/api/logs/sources`` is bounded by
its cache, which also keeps a failed read (denied or unsupported for 60 s, any other failure for
10 s). "Live" in the browser is incremental polling: sessions are re-read with the same device-side
filters; file logs return only lines after the cursor; report and buffer reads move their start
time forward.

RPCs per poll: a sessions poll costs 2 (a summary and the list; 1 when the list is refused), plus
1 unfiltered summary for the gauge at most every 30 s when the poll is filtered. A log poll costs 1,
plus the sources refresh: 1 configuration read at most every 60 s and 1 software read at most every
10 min. Junos logs each RPC (UI_NETCONF_CMD), which is why the browser defaults to a 5 s interval.
Request parameters are checked before any device read, so a malformed request costs no RPC and no
read slot.
"""

from __future__ import annotations

from typing import Any, List, Optional, Tuple

from jwicket.api import (
    App,
    Json,
    SessionBusy,
    _panel_error,
    _session,
    _utc,
    busy,
    device_turn,
    session_lost,
    throttle_read,
)
from jwicket.auth.sessions import WebSession
from jwicket.junos import facts
from jwicket.junos import logs as logmod
from jwicket.junos import sessions as sessmod
from jwicket.junos.errors import JunosError, SessionLost
from jwicket.junos.inventory import configuration_root
from jwicket.junos.session import LOGS_FILTER
from jwicket.web.http import Request, Response
from jwicket.web.server import Router

SESSIONS_INTERVAL_S = 1.5
LOGS_INTERVAL_S = 1.5
SUGGESTED_INTERVAL_S = 5
GAUGE_TTL_S = 30.0
SOURCES_TTL_S = 60.0
# A failed sources read other than denied/unsupported (a timeout, say) is retried sooner.
SOURCES_FAILED_TTL_S = 10.0
MODEL_TTL_S = 600.0


def _meta(app: App, sess: WebSession, **extra: Any) -> Json:
    return {
        "read_at": _utc(app.wall_clock()),
        "read_as": {"user": sess.user, "backend": sess.backend},
        "fixture": app.fixture,
        "suggested_interval_s": SUGGESTED_INTERVAL_S,
        **extra,
    }


def _cached(app: App, sess: WebSession, key: str, ttl: float) -> Tuple[bool, Any]:
    entry = sess.cache.get(key)
    if entry is not None and app.mono_clock() - entry[0] < ttl:
        return True, entry[1]
    return False, None


def _store(app: App, sess: WebSession, key: str, value: Any) -> None:
    sess.cache[key] = (app.mono_clock(), value)


# --- sessions -------------------------------------------------------------------------------------


def _summary(sess: WebSession, **kwargs: str) -> Json:
    return sessmod.parse_summary(sess.device.rpc("get-flow-session-information", summary=True, **kwargs))


def sessions(app: App, req: Request) -> Response:
    sess = _session(app, req)
    if sess is None:
        return Response.error(401, "sign-in required")
    if req.query.get("scope", "root") != "root":
        return Response.error(400, "Sessions for logical and tenant systems are not supported yet (Spec 004).")
    try:
        filters = sessmod.device_filters(req.query)
        limit = sessmod.parse_limit(req.query.get("limit"))
    except sessmod.FilterError as exc:
        return Response.error(400, str(exc))
    limited = throttle_read(app, sess, "sessions", SESSIONS_INTERVAL_S)
    if limited is not None:
        return limited

    kwargs = sessmod.rpc_kwargs(filters)
    gauge: Json
    table: Json
    try:
        with device_turn(sess):
            # 1. How many sessions match: a (filtered) summary, which is cheap for the device.
            try:
                counted = _summary(sess, **kwargs)
            except SessionLost:
                raise
            except JunosError as err:
                counted = _panel_error(err, "session summary")
            # 2. The table-wide gauge (active of max): the same reply when unfiltered, else cached.
            if not filters:
                gauge = counted
                _store(app, sess, "sessions-gauge", gauge)
            else:
                hit, cached_gauge = _cached(app, sess, "sessions-gauge", GAUGE_TTL_S)
                if hit:
                    gauge = cached_gauge
                else:
                    try:
                        gauge = _summary(sess)
                        _store(app, sess, "sessions-gauge", gauge)
                    except SessionLost:
                        raise
                    except JunosError as err:
                        gauge = _panel_error(err, "session summary (gauge)")
            matching = counted.get("matching")
            if matching is None and not filters:
                matching = counted.get("active")
            # 3. Rows, only when the match count is known to be safe to pull through the routing
            # engine. The guard fails closed: no count, no list.
            refusal = _guard(counted, gauge, matching, bool(filters))
            if refusal is not None:
                table = refusal
            else:
                try:
                    reply = sess.device.rpc("get-flow-session-information", **kwargs)
                    table = sessmod.parse_sessions(reply, limit)
                except SessionLost:
                    raise
                except JunosError as err:
                    table = {**_panel_error(err, "session list"), "rows": []}
    except SessionLost as err:
        return session_lost(app, sess, req, err)
    except SessionBusy:
        return busy()

    # One audit line per change of filters or outcome, not one per poll (a 5 s poll would otherwise
    # rotate the audit history away within hours).
    filter_text = " ".join(f"{k}={v}" for k, v in filters.items())
    mark = f"{filter_text}|{table['status']}"
    if sess.audit_marks.get("sessions") != mark:
        sess.audit_marks["sessions"] = mark
        app.audit.record(
            "read_sessions", user=sess.user, source=req.client,
            filters=filter_text, rows=len(table.get("rows") or []), status=table["status"],
        )
    return Response.json(
        200,
        {
            "meta": _meta(app, sess, device_filters=filters, limit=limit, min_interval_s=SESSIONS_INTERVAL_S),
            "summary": gauge,
            "matching": matching,
            "sessions": table,
        },
    )


def _guard(counted: Json, gauge: Json, matching: Any, filtered: bool) -> Optional[Json]:
    """The sessions panel to answer instead of listing, or None when listing is safe."""
    limit = sessmod.MAX_UNFILTERED
    if counted.get("status") in ("denied", "unsupported"):
        # The list is the same RPC at the same privilege: it would fare no better.
        return {"status": counted["status"], "message": counted.get("message"), "rows": []}
    if isinstance(matching, int):
        if matching <= limit:
            return None
        return {
            "status": "refused",
            "message": (
                f"{matching:,} sessions match. J-Wicket lists at most {limit:,} at a time, because the "
                "device sends every listed session from the data plane to the routing engine. Narrow the "
                "source, destination, port, protocol, application or interface."
            ),
            "rows": [],
        }
    # The match count is unknown. Every match is an active session, so a known active count at or
    # under the limit still makes listing safe.
    active = gauge.get("active") if filtered and gauge.get("status") == "ok" else None
    if isinstance(active, int) and active <= limit:
        return None
    if counted.get("status") != "ok":
        why = f"the session summary failed: {counted.get('message') or 'no reason given'}"
    elif isinstance(active, int):
        why = f"the filtered summary had no count, and {active:,} sessions are active"
    else:
        why = "the session summary had no count"
    return {
        "status": "count-unknown",
        "message": (
            f"J-Wicket did not list sessions because it could not tell how many match ({why}). Listing "
            "sends every matching session from the data plane to the routing engine, so J-Wicket lists "
            f"only when at most {limit:,} match. Try again, or narrow the filters."
        ),
        "rows": [],
    }


# --- logs -----------------------------------------------------------------------------------------


def _model(app: App, sess: WebSession) -> Tuple[Optional[str], Optional[str]]:
    """(model, release) from get-software-information, cached for MODEL_TTL_S (a failure too)."""
    hit, found = _cached(app, sess, "model", MODEL_TTL_S)
    if not hit:
        try:
            info = facts.software(sess.device.rpc("get-software-information"))
            found = (info.get("model"), info.get("version"))
        except SessionLost:
            raise
        except JunosError:
            found = (None, None)
        _store(app, sess, "model", found)
    model, version = found
    return (model if isinstance(model, str) else None, version if isinstance(version, str) else None)


_FAILED_KEY = "log-sources-failed"


def _cached_failure(app: App, sess: WebSession) -> Optional[JunosError]:
    entry = sess.cache.get(_FAILED_KEY)
    if entry is None:
        return None
    stored_at, (cls, text, public) = entry
    ttl = SOURCES_TTL_S if cls.kind in ("denied", "unsupported") else SOURCES_FAILED_TTL_S
    if app.mono_clock() - stored_at >= ttl:
        return None
    err: JunosError = cls(text, public)
    err.from_cache = True  # type: ignore[attr-defined]  # logged when it happened, not again
    return err


def _log_sources(app: App, sess: WebSession) -> Json:
    """What the configuration says about where logs are. A success is cached for SOURCES_TTL_S; a
    failure is cached too (denied or unsupported for SOURCES_TTL_S, anything else for
    SOURCES_FAILED_TTL_S) and raised again from the cache, so a class that cannot read the log
    configuration does not send a configuration read with every request. SessionLost is never cached."""

    def from_cache() -> Optional[Json]:
        hit, found = _cached(app, sess, "log-sources", SOURCES_TTL_S)
        if hit:
            cached: Json = found
            return cached
        failure = _cached_failure(app, sess)
        if failure is not None:
            raise failure
        return None

    found = from_cache()
    if found is not None:
        return found
    with device_turn(sess):
        found = from_cache()  # another request may have read them while this one waited
        if found is not None:
            return found
        try:
            model, version = _model(app, sess)
            config = configuration_root(sess.device.get_configuration(LOGS_FILTER))
        except SessionLost:
            raise
        except JunosError as err:
            sess.cache[_FAILED_KEY] = (app.mono_clock(), (type(err), str(err), err.public))
            raise
    result = logmod.sources(config, model, version)
    _store(app, sess, "log-sources", result)
    sess.cache.pop(_FAILED_KEY, None)
    return result


def log_sources(app: App, req: Request) -> Response:
    sess = _session(app, req)
    if sess is None:
        return Response.error(401, "sign-in required")
    try:
        found = _log_sources(app, sess)
    except SessionLost as err:
        return session_lost(app, sess, req, err)
    except SessionBusy:
        return busy()
    except JunosError as err:
        found = _panel_error(err, "log sources")
    return Response.json(200, {"meta": _meta(app, sess), "sources": found})


def _parse_log_request(req: Request) -> Tuple[str, Json]:
    """The source and every parameter, checked before anything is read from the device. Whether a
    ``file:<name>`` source is a configured file is checked later, against the sources read."""
    source = req.query.get("source") or f"file:{req.query.get('file', 'messages')}"
    if source.startswith("file:"):
        if not logmod.valid_file_name(source[len("file:"):]):
            raise logmod.LogQueryError("unknown log file")
        return source, {
            "cursor": logmod.parse_cursor(req.query.get("cursor")),
            "want": logmod.parse_lines(req.query.get("lines")),
            "contains": logmod.parse_terms(req.query.get("contains"), "contains"),
            "exclude": logmod.parse_terms(req.query.get("exclude"), "exclude"),
        }
    if source == "report":
        kind = req.query.get("type", "session-all")
        if kind not in logmod.REPORT_TYPES:
            raise logmod.LogQueryError("unknown report type")
        return source, {
            "type": kind,
            "count": logmod.parse_lines(req.query.get("count")),
            "start": logmod.parse_report_time(req.query.get("start"), "start"),
            "stop": logmod.parse_report_time(req.query.get("stop"), "stop"),
            "expression": logmod.parse_expression(req.query.get("expression")),
        }
    if source == "buffer":
        return source, {"since": logmod.parse_buffer_time(req.query.get("since"))}
    raise logmod.LogQueryError("unknown log source")


def _read_file(sess: WebSession, name: str, params: Json) -> Json:
    with device_turn(sess):
        reply = sess.device.rpc("get-log", filename=name)
    lines = logmod.clean_lines(logmod.reply_text(reply))
    return {
        "status": "ok",
        **logmod.tail(
            lines, cursor=params["cursor"], want=params["want"], contains=params["contains"],
            exclude=params["exclude"],
        ),
    }


def _read_report(sess: WebSession, params: Json) -> Json:
    """``show security log report in-detail <type>``. Without a start time the newest records are
    wanted, so ``descending`` is sent (the detail RPCs have that leaf and no ``ascending``, which
    suggests oldest-first by default; inferred, confirmed by Q-LOG-01) and the lines are put back in
    time order. With a start time (live polls) the device's default order is kept."""
    kind = params["type"]
    rpc: Json = {"count": str(params["count"])}
    if params["start"]:
        rpc["start_time"] = params["start"]
    else:
        rpc["descending"] = True
    if params["stop"]:
        rpc["stop_time"] = params["stop"]
    if params["expression"]:
        rpc["expression"] = params["expression"]
    with device_turn(sess):
        reply = sess.device.rpc(f"get-sec-log-report-detail-{kind}", **rpc)
    lines = logmod.clean_lines(logmod.reply_text(reply))
    if not params["start"]:
        lines.reverse()
    return {"status": "ok", "lines": lines[-logmod.MAX_LINES:], "type": kind, "cursor": None, "reset": False}


def _read_buffer(sess: WebSession, params: Json) -> Json:
    since = params["since"]
    rpc = {"newer_than": since} if since else {}
    with device_turn(sess):
        reply = sess.device.rpc("get-security-log-information", **rpc)
    return {"status": "ok", "cursor": None, "reset": False, **logmod.buffer_events(reply)}


def _file_source(source: str, files: List[Json]) -> Optional[Json]:
    """The configured file a ``file:<name>`` source names, None for report/buffer, else an error."""
    if source.startswith("file:"):
        name = logmod.validate_file(source[len("file:"):], files)
        return next((f for f in files if f["name"] == name), None)
    if source not in ("report", "buffer"):
        raise logmod.LogQueryError("unknown log source")
    return None


def log_lines(app: App, req: Request) -> Response:
    sess = _session(app, req)
    if sess is None:
        return Response.error(401, "sign-in required")
    # 1. Syntax: costs nothing on the device and uses no read slot.
    try:
        source, params = _parse_log_request(req)
    except logmod.LogQueryError as exc:
        return Response.error(400, str(exc))
    # 2. Where logs are (cached, including a failure).
    try:
        found = _log_sources(app, sess)
    except SessionLost as err:
        return session_lost(app, sess, req, err)
    except SessionBusy:
        return busy()
    except JunosError as err:
        # One bucket for every source while the sources cannot be read, so the slot keys stay bounded.
        limited = throttle_read(app, sess, "logs:sources", LOGS_INTERVAL_S)
        if limited is not None:
            return limited
        empty = {**_panel_error(err, "log sources"), "lines": []}
        return Response.json(200, {"meta": _meta(app, sess, source=source), "log": empty})
    # 3. Membership: a file must be configured. Read slots are keyed only by known sources.
    try:
        info = _file_source(source, found.get("files") or [])
    except logmod.LogQueryError as exc:
        return Response.error(400, str(exc))
    limited = throttle_read(app, sess, f"logs:{source}", LOGS_INTERVAL_S)
    if limited is not None:
        return limited

    body: Json
    report = next((d for d in found.get("databases") or [] if d.get("id") == "report"), None)
    try:
        if info is not None:
            body = _read_file(sess, info["name"], params)
        elif source == "report" and report is not None and report.get("supported") is False:
            # The in-detail report queries do not exist on this release: say so without asking.
            body = {"status": "unsupported", "message": report.get("note"), "lines": []}
        elif source == "report":
            body = _read_report(sess, params)
        else:
            body = _read_buffer(sess, params)
    except SessionLost as err:
        return session_lost(app, sess, req, err)
    except SessionBusy:
        return busy()
    except JunosError as err:
        body = {**_panel_error(err, f"log read {source}"), "lines": []}

    if not (req.query.get("cursor") or req.query.get("start") or req.query.get("since")):
        app.audit.record("read_log", user=sess.user, source=req.client, log=source, status=body["status"])
    meta = _meta(
        app, sess, source=source, min_interval_s=LOGS_INTERVAL_S,
        structured_data=bool(info and info.get("structured_data")), self_noise=logmod.SELF_NOISE,
    )
    return Response.json(200, {"meta": meta, "log": body})


def register(router: Router, app: App) -> None:
    router.add("GET", "/api/sessions", lambda r: sessions(app, r))
    router.add("GET", "/api/logs/sources", lambda r: log_sources(app, r))
    router.add("GET", "/api/logs", lambda r: log_lines(app, r))
