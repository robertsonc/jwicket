"""Spec 004 endpoints: live flow sessions and logs. Read-only.

* ``GET /api/sessions?src=&dst=&sport=&dport=&proto=&app=&iface=&limit=``
* ``GET /api/logs/sources``
* ``GET /api/logs?source=file:<name>&cursor=<n:digest>&lines=&contains=&exclude=``
* ``GET /api/logs?source=report&type=<report type>&start=&stop=&count=&expression=``
* ``GET /api/logs?source=buffer&since=<YYYY-MM-DD.HH:MM:SS>``

Every device read runs on the signed-in operator's own Junos session and is rate-limited per
endpoint. "Live" in the browser is incremental polling: sessions are re-read with the same
device-side filters; file logs return only lines after the cursor; report and buffer reads move
their start time forward. Each poll costs at most two RPCs, and Junos logs each one
(UI_NETCONF_CMD), which is why the browser defaults to a 5 s interval.
"""

from __future__ import annotations

from typing import Any, List, Optional, Tuple

from jwicket.api import App, Json, _panel_error, _session, _utc, session_lost, throttle_read
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
        with sess.lock:
            # 1. How many sessions match: a (filtered) summary, which is cheap for the device.
            try:
                counted = _summary(sess, **kwargs)
            except SessionLost:
                raise
            except JunosError as err:
                counted = _panel_error(err)
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
                        gauge = _panel_error(err)
            matching = counted.get("matching")
            if matching is None and not filters:
                matching = counted.get("active")
            # 3. Rows, only when the match count is safe to pull through the routing engine.
            if isinstance(matching, int) and matching > sessmod.MAX_UNFILTERED:
                table = {
                    "status": "refused",
                    "message": (
                        f"{matching:,} sessions match. J-Wicket lists at most {sessmod.MAX_UNFILTERED:,} at a "
                        "time, because the device sends every listed session from the data plane to the routing "
                        "engine. Narrow the source, destination, port, protocol, application or interface."
                    ),
                    "rows": [],
                }
            else:
                try:
                    reply = sess.device.rpc("get-flow-session-information", **kwargs)
                    table = sessmod.parse_sessions(reply, limit)
                except SessionLost:
                    raise
                except JunosError as err:
                    table = {**_panel_error(err), "rows": []}
    except SessionLost as err:
        return session_lost(app, sess, req, err)

    app.audit.record(
        "read_sessions", user=sess.user, source=req.client,
        filters=" ".join(f"{k}={v}" for k, v in filters.items()), rows=len(table.get("rows") or []),
        status=table["status"],
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


# --- logs -----------------------------------------------------------------------------------------


def _model(app: App, sess: WebSession) -> Optional[str]:
    hit, model = _cached(app, sess, "model", MODEL_TTL_S)
    if not hit:
        try:
            model = facts.software(sess.device.rpc("get-software-information")).get("model")
        except SessionLost:
            raise
        except JunosError:
            model = None
        _store(app, sess, "model", model)
    return model if isinstance(model, str) else None


def _log_sources(app: App, sess: WebSession) -> Json:
    hit, found = _cached(app, sess, "log-sources", SOURCES_TTL_S)
    if hit:
        cached: Json = found
        return cached
    with sess.lock:
        model = _model(app, sess)
        config = configuration_root(sess.device.get_configuration(LOGS_FILTER))
    result = logmod.sources(config, model)
    _store(app, sess, "log-sources", result)
    return result


def log_sources(app: App, req: Request) -> Response:
    sess = _session(app, req)
    if sess is None:
        return Response.error(401, "sign-in required")
    try:
        found = _log_sources(app, sess)
    except SessionLost as err:
        return session_lost(app, sess, req, err)
    except JunosError as err:
        found = _panel_error(err)
    return Response.json(200, {"meta": _meta(app, sess), "sources": found})


def _read_file(sess: WebSession, name: str, req: Request) -> Json:
    cursor = logmod.parse_cursor(req.query.get("cursor"))
    want = logmod.parse_lines(req.query.get("lines"))
    contains = logmod.parse_terms(req.query.get("contains"), "contains")
    exclude = logmod.parse_terms(req.query.get("exclude"), "exclude")
    with sess.lock:
        reply = sess.device.rpc("get-log", filename=name)
    lines = logmod.clean_lines(logmod.reply_text(reply))
    return {"status": "ok", **logmod.tail(lines, cursor=cursor, want=want, contains=contains, exclude=exclude)}


def _read_report(sess: WebSession, req: Request) -> Json:
    kind = req.query.get("type", "session-all")
    if kind not in logmod.REPORT_TYPES:
        raise logmod.LogQueryError("unknown report type")
    params = {"count": str(logmod.parse_lines(req.query.get("count")))}
    start = logmod.parse_report_time(req.query.get("start"), "start")
    stop = logmod.parse_report_time(req.query.get("stop"), "stop")
    expression = logmod.parse_expression(req.query.get("expression"))
    if start:
        params["start_time"] = start
    if stop:
        params["stop_time"] = stop
    if expression:
        params["expression"] = expression
    with sess.lock:
        reply = sess.device.rpc(f"get-sec-log-report-detail-{kind}", **params)
    lines = logmod.clean_lines(logmod.reply_text(reply))
    return {"status": "ok", "lines": lines[-logmod.MAX_LINES:], "type": kind, "cursor": None, "reset": False}


def _read_buffer(sess: WebSession, req: Request) -> Json:
    since = logmod.parse_buffer_time(req.query.get("since"))
    params = {"newer_than": since} if since else {}
    with sess.lock:
        reply = sess.device.rpc("get-security-log-information", **params)
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
    source = req.query.get("source") or f"file:{req.query.get('file', 'messages')}"
    try:
        found = _log_sources(app, sess)
    except SessionLost as err:
        return session_lost(app, sess, req, err)
    except JunosError as err:
        empty = {**_panel_error(err), "lines": []}
        return Response.json(200, {"meta": _meta(app, sess, source=source), "log": empty})

    try:
        info = _file_source(source, found.get("files") or [])
    except logmod.LogQueryError as exc:
        return Response.error(400, str(exc))
    limited = throttle_read(app, sess, f"logs:{source}", LOGS_INTERVAL_S)
    if limited is not None:
        return limited

    body: Json
    try:
        if info is not None:
            body = _read_file(sess, info["name"], req)
        elif source == "report":
            body = _read_report(sess, req)
        else:
            body = _read_buffer(sess, req)
    except logmod.LogQueryError as exc:
        return Response.error(400, str(exc))
    except SessionLost as err:
        return session_lost(app, sess, req, err)
    except JunosError as err:
        body = {**_panel_error(err), "lines": []}

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
