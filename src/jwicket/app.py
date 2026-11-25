"""Process entry point.

Under Junos the daemon is started by the extension-service with no arguments and reads
``/var/db/jwicket/jwicket.ini``. Outside Junos (development, CI) a few options exist; none of them
can weaken a rule in settings.py.
"""

from __future__ import annotations

import argparse
import importlib
import json
import logging
import os
import signal
import sys
import threading
from pathlib import Path
from typing import Any, List, Optional

from jwicket import __version__
from jwicket.api import App, build_router, prune_reuse, record_session_end
from jwicket.auth.backends import AuthBackend, LabTokenBackend, NetconfBackend
from jwicket.auth.sessions import SessionStore
from jwicket.auth.throttle import LoginThrottle
from jwicket.logs import AuditTrail, escape_handlers, setup_logging
from jwicket.settings import (
    DEFAULT_CONFIG_PATH,
    ConfigError,
    Settings,
    check_tls_files,
    load_lab_token,
    load_settings,
)
from jwicket.web.server import JWicketServer, make_tls_context

LOG = logging.getLogger("jwicket")

PROBE_MODULES = ("http.server", "ssl", "json", "hmac", "threading", "jnpr.junos", "lxml", "ncclient", "paramiko")
REAP_INTERVAL_S = 30.0


def probe() -> int:
    """Report the interpreter and which modules import (qualification Q-RT-01)."""
    result: dict[str, Any] = {"jwicket": __version__, "python": sys.version.split()[0], "modules": {}}
    for name in PROBE_MODULES:
        try:
            importlib.import_module(name)
            result["modules"][name] = "ok"
        except ImportError as exc:
            result["modules"][name] = f"missing: {exc}"
    try:
        import ssl

        result["openssl"] = ssl.OPENSSL_VERSION
    except ImportError:
        result["openssl"] = None
    print(json.dumps(result, indent=2))
    return 0 if all(v == "ok" for v in result["modules"].values()) else 1


def build_backend(settings: Settings) -> AuthBackend:
    auth = settings.auth
    if auth.backend == "lab-token":
        assert auth.lab_token_file is not None  # noqa: S101 - guaranteed by settings.validate()
        LOG.warning("lab-token backend: every read runs as this daemon's Junos account; loopback only")
        return LabTokenBackend(token=load_lab_token(auth.lab_token_file), timeout_s=auth.rpc_timeout_s)
    return NetconfBackend(host=auth.netconf_host, port=auth.netconf_port, timeout_s=auth.rpc_timeout_s)


def build_app(
    settings: Settings, backend: AuthBackend, *, fixture: bool = False, warnings: Optional[List[str]] = None
) -> App:
    auth = settings.auth
    app = App(
        backend=backend,
        sessions=SessionStore(
            idle_s=auth.session_idle_s,
            absolute_s=auth.session_absolute_s,
            max_sessions=auth.max_sessions,
            max_per_user=auth.max_sessions_per_user,
        ),
        throttle=LoginThrottle(
            per_name=auth.login_failures_per_user_per_min,
            per_source=auth.login_failures_per_source_per_min,
            concurrent=auth.login_concurrent,
        ),
        audit=AuditTrail(settings.log.audit_file, settings.log.max_bytes, settings.log.backups),
        session_idle_s=auth.session_idle_s,
        fixture=fixture,
        extra_warnings=list(warnings or []),
    )
    # Idle, absolute and shutdown ends get a session_ended audit event; the others have their own.
    app.sessions.on_end = lambda sess, reason: record_session_end(app, sess, reason)
    return app


def serve(settings: Settings, app: App) -> int:
    srv = settings.server
    tls = None
    if srv.tls_enabled:
        check_tls_files(srv)
        try:
            tls = make_tls_context(str(srv.tls_cert), str(srv.tls_key))
        except (OSError, ValueError) as exc:
            raise ConfigError(f"cannot load TLS certificate {srv.tls_cert} / key {srv.tls_key}: {exc}") from exc
    try:
        httpd = JWicketServer(
            (srv.bind, srv.port),
            build_router(app),
            tls=tls,
            max_connections=srv.max_connections,
            socket_timeout_s=srv.socket_timeout_s,
            max_body_bytes=srv.max_body_bytes,
            allowed_hosts=srv.allowed_hosts,
        )
    except OSError as exc:
        raise ConfigError(f"cannot listen on {srv.bind}:{srv.port}: {exc.strerror or exc}") from exc

    stop = threading.Event()

    def reaper() -> None:
        while not stop.wait(REAP_INTERVAL_S):
            app.sessions.reap()  # ends are audited by the store's on_end hook
            prune_reuse(app)  # B-8: drop reused reads past their window (OD-07)
            app.audit.flush()  # repeat counts of aggregated refusals whose window has ended

    threading.Thread(target=reaper, name="jwicket-reaper", daemon=True).start()

    def on_signal(signum: int, _frame: Any) -> None:
        LOG.info("signal %d received, shutting down", signum)
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    if tls is None:
        LOG.warning("TLS is off; listening on loopback only (%s). Reach it through an SSH tunnel.", srv.bind)
    LOG.info("listening on %s:%d tls=%s backend=%s", srv.bind, srv.port, tls is not None, app.backend.name)
    app.audit.record("start", user=None, source="local", version=__version__, backend=app.backend.name)
    try:
        httpd.serve_forever(poll_interval=0.5)
    finally:
        stop.set()
        httpd.server_close()
        app.sessions.close_all()
        app.audit.flush(force=True)
        app.audit.record("stop", user=None, source="local")
    return 0


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="jwicket", description="J-Wicket on-box daemon")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="settings file (INI)")
    parser.add_argument("--check-config", action="store_true", help="validate settings and exit")
    parser.add_argument("--probe", action="store_true", help="report the interpreter's modules and exit")
    parser.add_argument("--version", action="version", version=f"jwicket {__version__}")
    return parser.parse_args(argv)


def record_startup_refusal(config_path: Path, reason: str) -> None:
    """Best effort: put the refusal where an operator will look (``file show``), next to the settings."""
    target = config_path.parent / "startup-refused.txt"
    if not config_path.parent.is_dir():
        return
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(f"jwicket {__version__} refused to start: {reason}\n")
    except OSError as exc:
        LOG.debug("could not record startup refusal in %s: %s", target, exc)


def main(argv: Optional[List[str]] = None) -> int:
    os.umask(0o077)  # every file J-Wicket creates (logs, audit trail) is private to its account
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.probe:
        return probe()
    try:
        settings = load_settings(args.config)
    except ConfigError as exc:
        logging.basicConfig(level=logging.INFO)
        escape_handlers(logging.getLogger().handlers)
        LOG.error("startup refused: %s", exc)
        record_startup_refusal(args.config, str(exc))
        return 2
    if args.check_config:
        print(f"{args.config}: ok")
        return 0
    setup_logging(settings.log)
    try:
        return serve(settings, build_app(settings, build_backend(settings)))
    except ConfigError as exc:
        LOG.error("startup refused: %s", exc)
        record_startup_refusal(args.config, str(exc))
        return 2
