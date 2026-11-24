"""Spec 004 endpoints: live flow sessions and log tailing. Read-only.

* ``GET /api/sessions?src=&dst=&sport=&dport=&proto=&app=&iface=&limit=``
* ``GET /api/logs/sources``
* ``GET /api/logs?file=<name>&cursor=<n:digest>&lines=&contains=&exclude=``

Every device read runs on the signed-in operator's own Junos session and is rate-limited per
endpoint. "Live" in the browser is incremental polling: sessions are re-read with the same
device-side filters; logs return only lines after the cursor.
"""

from __future__ import annotations

from typing import Any, List, Optional

from jwicket.api import App, Json, _panel_error, _session, _utc, session_lost, throttle_read
from jwicket.auth.sessions import WebSession
from jwicket.junos import logs as logmod
from jwicket.junos import sessions as sessmod
from jwicket.junos.errors import JunosError, SessionLost
from jwicket.junos.inventory import configuration_root
from jwicket.junos.session import LOGS_FILTER
from jwicket.web.http import Request, Response
from jwicket.web.server import Router

SESSIONS_INTERVAL_S = 1.5
LOGS_INTERVAL_S = 1.5
SOURCES_TTL_S = 60.0


def _meta(app: App, sess: WebSession, **extra: Any) -> Json:
    return {
        "read_at": _utc(app.wall_clock()),
        "read_as": {"user": sess.user, "backend": sess.backend},
        "fixture": app.fixture,
        **extra,
    }


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

    summary: Json
    table: Json
    try:
        with sess.lock:
            try:
                summary = sessmod.parse_summary(sess.device.rpc("get-flow-session-information", summary=True))
            except SessionLost:
                raise
            except JunosError as err:
                summary = _panel_error(err)
            active = summary.get("active")
            if not filters and isinstance(active, int) and active > sessmod.MAX_UNFILTERED:
                table = {
                    "status": "refused",
                    "message": (
                        f"{active:,} sessions are active. J-Wicket reads at most {sessmod.MAX_UNFILTERED:,} "
                        "without a device-side filter, to protect the routing engine. Add a source, "
                        "destination, port, protocol, application or interface filter."
                    ),
                    "rows": [],
                }
            else:
                try:
                    reply = sess.device.rpc("get-flow-session-information", **sessmod.rpc_kwargs(filters))
                    table = sessmod.parse_sessions(reply, limit)
                except SessionLost:
                    raise
                except JunosError as err:
                    table = {**_panel_error(err), "rows": []}
    except SessionLost as err:
        return session_lost(app, sess, req, err)

    app.audit.record(
        "read_sessions", user=sess.user, source=req.client, filters=" ".join(f"{k}={v}" for k, v in filters.items()),
        rows=len(table.get("rows") or []), status=table["status"],
    )
    return Response.json(
        200,
        {
            "meta": _meta(app, sess, device_filters=filters, limit=limit, min_interval_s=SESSIONS_INTERVAL_S),
            "summary": summary,
            "sessions": table,
        },
    )


def _log_sources(app: App, sess: WebSession) -> Json:
    cached = sess.cache.get("log-sources")
    now = app.mono_clock()
    if cached is not None and now - cached[0] < SOURCES_TTL_S:
        result: Json = cached[1]
        return result
    with sess.lock:
        config = configuration_root(sess.device.get_configuration(LOGS_FILTER))
    found = logmod.sources(config)
    sess.cache["log-sources"] = (now, found)
    return found


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


def log_lines(app: App, req: Request) -> Response:
    sess = _session(app, req)
    if sess is None:
        return Response.error(401, "sign-in required")
    try:
        found = _log_sources(app, sess)
    except SessionLost as err:
        return session_lost(app, sess, req, err)
    except JunosError as err:
        return Response.json(200, {"meta": _meta(app, sess), "log": {**_panel_error(err), "lines": []}})
    files: List[Json] = found.get("files") or []
    try:
        name = logmod.validate_file(req.query.get("file", "messages"), files)
        cursor = logmod.parse_cursor(req.query.get("cursor"))
        want = logmod.parse_lines(req.query.get("lines"))
        contains = logmod.parse_terms(req.query.get("contains"), "contains")
        exclude = logmod.parse_terms(req.query.get("exclude"), "exclude")
    except logmod.LogQueryError as exc:
        return Response.error(400, str(exc))
    limited = throttle_read(app, sess, f"logs:{name}", LOGS_INTERVAL_S)
    if limited is not None:
        return limited
    info: Optional[Json] = next((f for f in files if f["name"] == name), None)
    try:
        with sess.lock:
            reply = sess.device.rpc("get-log", filename=name)
        lines = logmod.clean_lines(logmod.reply_text(reply))
        window = logmod.tail(lines, cursor=cursor, want=want, contains=contains, exclude=exclude)
        body: Json = {"status": "ok", **window}
    except SessionLost as err:
        return session_lost(app, sess, req, err)
    except JunosError as err:
        body = {**_panel_error(err), "lines": []}
    if cursor is None:
        app.audit.record("read_log", user=sess.user, source=req.client, file=name, status=body["status"])
    return Response.json(
        200,
        {
            "meta": _meta(app, sess, file=name, min_interval_s=LOGS_INTERVAL_S,
                          structured_data=bool(info and info.get("structured_data"))),
            "log": body,
        },
    )


def register(router: Router, app: App) -> None:
    router.add("GET", "/api/sessions", lambda r: sessions(app, r))
    router.add("GET", "/api/logs/sources", lambda r: log_sources(app, r))
    router.add("GET", "/api/logs", lambda r: log_lines(app, r))

