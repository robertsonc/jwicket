"""Process entry point.

Under Junos the daemon is started by the extension-service with no arguments and reads
``/var/db/jwicket/jwicket.ini``. Outside Junos (development, CI) a few options exist; none of them
can weaken a rule in settings.py.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib
import json
import logging
import os
import signal
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, Iterator, List, Optional

from jwicket import __version__
from jwicket.api import App, build_router, bundle_payload_sha256, prune_reuse, record_session_end
from jwicket.auth.backends import AuthBackend, LabTokenBackend, NetconfBackend
from jwicket.auth.sessions import SessionStore
from jwicket.auth.throttle import LoginThrottle
from jwicket.logs import AuditTrail, escape_handlers, setup_logging
from jwicket.settings import (
    DEFAULT_CONFIG_PATH,
    ConfigError,
    Settings,
    check_log_paths,
    check_output_directory,
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


@contextlib.contextmanager
def routing_instance(name: Optional[str]) -> Iterator[None]:
    """Create sockets in Junos routing instance ``name`` inside the block, then return to the default.

    ``jcs.set_routing_instance`` is process-wide and applies to sockets created after it. Only the
    listening socket belongs in that instance: the NETCONF sessions to 127.0.0.1:830 must stay in the
    default instance, where they time out otherwise (recorded on Junos 25.2R1-S1.4, SRX4100). A socket
    keeps the instance it was created in, so switching back afterwards leaves the listener where it is.
    """
    if name is None:
        yield
        return
    try:
        import jcs  # Junos on-box module; absent anywhere else
    except ImportError as exc:
        raise ConfigError(
            f"[server] routing_instance = {name} needs the Junos jcs module, which this Python does not have"
        ) from exc
    jcs.set_routing_instance(name)
    try:
        yield
    finally:
        jcs.set_routing_instance("default")


def serve(settings: Settings, app: App) -> int:
    srv = settings.server
    app.max_account_reads = min(app.max_account_reads, srv.max_connections - 1)
    tls = None
    if srv.tls_enabled:
        check_tls_files(srv)
        try:
            tls = make_tls_context(str(srv.tls_cert), str(srv.tls_key))
        except (OSError, ValueError) as exc:
            raise ConfigError(f"cannot load TLS certificate {srv.tls_cert} / key {srv.tls_key}: {exc}") from exc
    try:
        with routing_instance(srv.routing_instance):
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
        where = f" in routing instance {srv.routing_instance}" if srv.routing_instance else ""
        raise ConfigError(f"cannot listen on {srv.bind}:{srv.port}{where}: {exc.strerror or exc}") from exc

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
    # The build is in the start line and record so an installer can tell this process from an earlier
    # one (installation spec, bundle change D3); payload is the payload digest, "none" from src/. The
    # installer's check C4 (tools/jwicket_install/plan.py start_line) matches this text exactly.
    payload = bundle_payload_sha256()
    LOG.info(
        "listening on %s:%d tls=%s backend=%s routing_instance=%s version=%s payload=%s",
        srv.bind, srv.port, tls is not None, app.backend.name, srv.routing_instance or "default",
        __version__, payload[:16] if payload else "none",
    )
    app.audit.record("start", user=None, source="local", version=__version__, backend=app.backend.name,
                     payload_sha256=payload)
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
    tmp = None
    try:
        check_output_directory(target, label="startup refusal note")
        # Do not open or truncate the existing destination. Publishing a fresh inode also avoids
        # following a symbolic or hard link and preserves a previous note if the write fails.
        fd, name = tempfile.mkstemp(prefix=".startup-refused-", dir=str(target.parent))
        tmp = Path(name)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(f"jwicket {__version__} refused to start: {reason}\n")
        os.replace(tmp, target)
        tmp = None
    except (ConfigError, OSError) as exc:
        LOG.debug("could not record startup refusal in %s: %s", target, exc)
    finally:
        if tmp is not None:
            with contextlib.suppress(OSError):
                tmp.unlink()


def main(argv: Optional[List[str]] = None) -> int:
    os.umask(0o077)  # every file J-Wicket creates (logs, audit trail) is private to its account
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.probe:
        return probe()
    try:
        settings = load_settings(args.config)
        check_log_paths(settings.log)
    except ConfigError as exc:
        logging.basicConfig(level=logging.INFO)
        escape_handlers(logging.getLogger().handlers)
        LOG.error("startup refused: %s", exc)
        record_startup_refusal(args.config, str(exc))
        return 2
    if args.check_config:
        print(f"{args.config}: ok")
        return 0
    try:
        setup_logging(settings.log)
        return serve(settings, build_app(settings, build_backend(settings)))
    except ConfigError as exc:
        logging.basicConfig(level=logging.INFO)
        escape_handlers(logging.getLogger().handlers)
        LOG.error("startup refused: %s", exc)
        record_startup_refusal(args.config, str(exc))
        return 2
