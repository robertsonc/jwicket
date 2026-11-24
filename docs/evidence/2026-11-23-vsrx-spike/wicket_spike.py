#!/usr/bin/env python3
"""Wicket spike: minimal on-box JET daemon.

Purpose: prove (or kill) the on-box design. It answers three questions:
  1. Can an unsigned Python JET app bind a listening TCP socket?
  2. Is that socket reachable through fxp0 and through a revenue interface?
  3. Can the daemon call local mgd RPCs through on-box PyEZ?

Constraints: standard library only, plus the PyEZ that ships on the box.
No third-party packages, no C extensions (veriexec would block them).

Endpoints (GET only):
  /               no auth, the single-page UI (it asks for the token)
  /healthz        no auth, proves the socket is reachable
  /api/version    bearer token, proves the local RPC path
  /api/dashboard  bearer token, read-only device state for the UI

Options come from the command line or, when none are given, from /var/tmp/wicket.args.
Run "--probe" first. It reports which modules the on-box interpreter has.
"""
from __future__ import annotations

import argparse
import hmac
import importlib
import json
import logging
import logging.handlers
import os
import shlex
import signal
import stat
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional

LOG = logging.getLogger("wicket.spike")

PROBE_MODULES = ("http.server", "ssl", "json", "hmac", "threading", "jnpr.junos", "lxml")
LOOPBACK = {"127.0.0.1", "::1", "localhost"}
SOCKET_TIMEOUT_S = 10
MIN_TOKEN_LEN = 24
# Junos cscript mangles "--flag" style JET arguments, so options can also live in a file.
ARGS_FILE = Path("/var/tmp/wicket.args")
PORT_PREFIXES = ("ge-", "xe-", "et-", "fxp", "reth", "irb", "st0")
STARTED = time.time()
CSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'"


class ConfigError(Exception):
    """Raised when startup configuration is unsafe or unusable."""


class RpcFailure(Exception):
    """Raised when the local Junos RPC cannot be completed."""


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Wicket on-box spike daemon")
    parser.add_argument("--bind", default="127.0.0.1", help="listen address (default: loopback)")
    parser.add_argument("--port", type=int, default=8443, help="listen TCP port (default: 8443)")
    parser.add_argument("--token-file", type=Path, help="file holding the bearer token (mode 0600)")
    parser.add_argument("--cert", type=Path, help="PEM server certificate; enables TLS with --key")
    parser.add_argument("--key", type=Path, help="PEM private key (mode 0600)")
    parser.add_argument(
        "--allow-plaintext",
        action="store_true",
        help="spike only: permit a non-loopback bind without TLS",
    )
    parser.add_argument("--rpc-timeout", type=int, default=15, help="local RPC timeout in seconds")
    parser.add_argument("--log-file", type=Path, help="optional rotating log file")
    parser.add_argument("--log-level", default="INFO", choices=("DEBUG", "INFO", "WARNING", "ERROR"))
    parser.add_argument("--probe", action="store_true", help="report importable modules and exit")
    return parser.parse_args(argv)


def setup_logging(level: str, log_file: Optional[Path]) -> None:
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file is not None:
        handlers.append(
            logging.handlers.RotatingFileHandler(log_file, maxBytes=512_000, backupCount=2)
        )
    root = logging.getLogger()
    root.setLevel(level)
    # PyEZ logs whole RPC replies at INFO through ncclient; keep device data out of the log.
    logging.getLogger("ncclient").setLevel(logging.WARNING)
    for handler in handlers:
        handler.setFormatter(fmt)
        root.addHandler(handler)


def probe() -> int:
    """Test T0: report the interpreter and which modules import on this box."""
    result: dict[str, Any] = {"python": sys.version.split()[0], "modules": {}}
    for name in PROBE_MODULES:
        try:
            importlib.import_module(name)
            result["modules"][name] = "ok"
        except ImportError as exc:
            result["modules"][name] = f"missing: {exc}"
    print(json.dumps(result, indent=2))
    return 0 if all(v == "ok" for v in result["modules"].values()) else 1


def check_private(path: Path, label: str) -> None:
    """Refuse secrets that group or other can read."""
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise ConfigError(f"{label} {path} is not readable: {exc}") from exc
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigError(f"{label} {path} must be mode 0600, found {stat.S_IMODE(mode):o}")


def load_token(path: Optional[Path]) -> bytes:
    if path is None:
        raise ConfigError("--token-file is required (no unauthenticated API)")
    check_private(path, "token file")
    token = path.read_text(encoding="ascii").strip().encode("ascii")
    if len(token) < MIN_TOKEN_LEN:
        raise ConfigError(f"token in {path} is shorter than {MIN_TOKEN_LEN} characters")
    return token


def make_tls_context(cert: Optional[Path], key: Optional[Path]) -> Optional[Any]:
    """Build a server TLS context, or None when TLS is not configured."""
    if cert is None and key is None:
        return None
    if cert is None or key is None:
        raise ConfigError("--cert and --key must be given together")
    check_private(key, "private key")
    try:
        import ssl
    except ImportError as exc:
        raise ConfigError(f"ssl module is not available on this box: {exc}") from exc
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    except (OSError, ssl.SSLError) as exc:
        raise ConfigError(f"cannot load certificate {cert} / key {key}: {exc}") from exc
    return ctx


def _txt(node: Any, path: str) -> Optional[str]:
    value = node.findtext(path)
    return value.strip() if value and value.strip() else None


def _int(value: Optional[str]) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _names(value: Any) -> list[str]:
    """Junos JSON config gives leaf-lists as strings or as {"name": ...} objects."""
    out: list[str] = []
    for item in _as_list(value):
        if isinstance(item, dict):
            item = item.get("name")
        if item is not None:
            out.append(str(item))
    return out


def _device(dev: Any) -> dict[str, Any]:
    reply = dev.rpc.get_software_information()
    return {
        "hostname": _txt(reply, ".//host-name"),
        "model": _txt(reply, ".//product-model"),
        "version": _txt(reply, ".//junos-version"),
    }


def _health(dev: Any) -> dict[str, Any]:
    reply = dev.rpc.get_route_engine_information()
    return {
        "uptime": _txt(reply, ".//up-time"),
        "mem_util": _int(_txt(reply, ".//memory-buffer-utilization")),
        "cpu_idle": _int(_txt(reply, ".//cpu-idle")),
    }


def _sessions(dev: Any) -> dict[str, Any]:
    reply = dev.rpc.get_flow_session_information(summary=True)
    return {
        "sessions_active": _int(_txt(reply, ".//active-sessions")),
        "sessions_max": _int(_txt(reply, ".//max-sessions")),
    }


def _interfaces(dev: Any) -> dict[str, Any]:
    reply = dev.rpc.get_interface_information(terse=True)
    rows = []
    for phy in reply.iterfind(".//physical-interface"):
        name = _txt(phy, "name")
        if not name or not name.startswith(PORT_PREFIXES):
            continue
        addresses = [a.text.strip() for a in phy.iterfind(".//ifa-local") if a.text and a.text.strip()]
        rows.append({"name": name, "oper": _txt(phy, "oper-status"), "addresses": addresses})
    return {"rows": rows}


def _config(dev: Any) -> dict[str, Any]:
    reply = dev.rpc.get_config(options={"format": "json"})
    if not isinstance(reply, dict):
        raise TypeError("configuration was not returned as JSON")
    return {"conf": reply.get("configuration") or {}}


def _zones(conf: dict[str, Any]) -> list[dict[str, Any]]:
    zones = _as_list(((conf.get("security") or {}).get("zones") or {}).get("security-zone"))
    return [
        {
            "name": str(zone.get("name")),
            "interfaces": _names(zone.get("interfaces")),
            "services": _names((zone.get("host-inbound-traffic") or {}).get("system-services")),
        }
        for zone in zones
        if isinstance(zone, dict)
    ]


def _policies(conf: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    pairs = _as_list(((conf.get("security") or {}).get("policies") or {}).get("policy"))
    for pair in pairs:
        if not isinstance(pair, dict):
            continue
        for pol in _as_list(pair.get("policy")):
            match = pol.get("match") or {}
            then = pol.get("then") or {}
            action = next((a for a in ("permit", "deny", "reject") if a in then), "unknown")
            rows.append(
                {
                    "from": str(pair.get("from-zone-name")),
                    "to": str(pair.get("to-zone-name")),
                    "name": str(pol.get("name")),
                    "src": _names(match.get("source-address")),
                    "dst": _names(match.get("destination-address")),
                    "app": _names(match.get("application")),
                    "action": action,
                }
            )
    return rows


class JunosLocal:
    """Serialised access to local mgd through on-box PyEZ."""

    def __init__(self, timeout_s: int) -> None:
        self._timeout_s = timeout_s
        self._lock = threading.Lock()

    @staticmethod
    def _pyez() -> tuple[Any, tuple[type, ...]]:
        try:
            from jnpr.junos import Device
            from jnpr.junos.exception import ConnectError, RpcError
        except ImportError as exc:
            raise RpcFailure(f"PyEZ is not importable on this box: {exc}") from exc
        return Device, (ConnectError, RpcError)

    def software_information(self) -> dict[str, Optional[str]]:
        device_cls, errors = self._pyez()
        with self._lock:
            try:
                # Empty argument list = connect to the local device (on-box only).
                with device_cls() as dev:
                    dev.timeout = self._timeout_s
                    return _device(dev)
            except errors as exc:
                raise RpcFailure(f"get-software-information failed: {exc!r}") from exc

    @staticmethod
    def _panel(name: str, collect: Any, dev: Any) -> dict[str, Any]:
        try:
            return {"ok": True, **collect(dev)}
        except Exception as exc:  # noqa: BLE001 - one failed panel must not blank the whole page
            LOG.warning("panel %s unavailable: %r", name, exc)
            return {"ok": False, "error": type(exc).__name__}

    def dashboard(self) -> dict[str, Any]:
        """Read-only device state for the UI. Each panel fails independently."""
        device_cls, errors = self._pyez()
        with self._lock:
            try:
                with device_cls() as dev:
                    dev.timeout = self._timeout_s
                    device = self._panel("device", _device, dev)
                    health = self._panel("health", _health, dev)
                    sessions = self._panel("sessions", _sessions, dev)
                    interfaces = self._panel("interfaces", _interfaces, dev)
                    config = self._panel("config", _config, dev)
            except errors as exc:
                raise RpcFailure(f"local session to mgd failed: {exc!r}") from exc

        merged: dict[str, Any] = {}
        for part in (device, health, sessions):
            merged.update({k: v for k, v in part.items() if k not in ("ok", "error")})
        result: dict[str, Any] = {"device": merged, "interfaces": interfaces, "services": []}
        if config["ok"]:
            conf = config["conf"]
            result["zones"] = self._panel("zones", lambda _d: {"rows": _zones(conf)}, None)
            result["policies"] = self._panel("policies", lambda _d: {"rows": _policies(conf)}, None)
            services = (conf.get("system") or {}).get("services") or {}
            result["services"] = sorted(str(k) for k in services) if isinstance(services, dict) else []
        else:
            result["zones"] = {"ok": False, "error": config["error"]}
            result["policies"] = {"ok": False, "error": config["error"]}
        return result


class SpikeHandler(BaseHTTPRequestHandler):
    server_version = "wicket-spike/0.1"
    sys_version = ""
    timeout = SOCKET_TIMEOUT_S  # per-connection socket timeout

    # Injected by serve().
    token: bytes = b""
    junos: JunosLocal
    served = 0
    served_lock = threading.Lock()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 (stdlib signature)
        LOG.info("%s %s", self.client_address[0], format % args)

    def _send_json(self, status: HTTPStatus, body: dict[str, Any]) -> None:
        payload = (json.dumps(body) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _send_html(self, html: str) -> None:
        payload = html.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(payload)

    def _deny(self) -> None:
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", "Bearer")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _authorised(self) -> bool:
        header = self.headers.get("Authorization", "")
        scheme, _, presented = header.partition(" ")
        if scheme.lower() != "bearer":
            return False
        return hmac.compare_digest(presented.strip().encode("utf-8"), self.token)

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        with SpikeHandler.served_lock:
            SpikeHandler.served += 1
            served = SpikeHandler.served
        if path == "/":
            self._send_html(INDEX_HTML)
            return
        if path == "/api/dashboard":
            if not self._authorised():
                self._deny()
                return
            try:
                body = self.junos.dashboard()
            except RpcFailure as exc:
                LOG.error("dashboard failed: %s", exc)
                self._send_json(HTTPStatus.BAD_GATEWAY, {"error": "local RPC failed"})
                return
            body["wicket"] = {
                "pid": os.getpid(),
                "python": sys.version.split()[0],
                "uptime_s": int(time.time() - STARTED),
                "requests": served,
            }
            self._send_json(HTTPStatus.OK, body)
            return
        if path == "/healthz":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        if path == "/api/version":
            if not self._authorised():
                self._deny()
                return
            try:
                self._send_json(HTTPStatus.OK, self.junos.software_information())
            except RpcFailure as exc:
                LOG.error("local RPC failed: %s", exc)
                self._send_json(HTTPStatus.BAD_GATEWAY, {"error": "local RPC failed"})
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})


INDEX_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>J-Wicket</title>
<style>
:root{--turf:#0e3a2f;--turf2:#134637;--turf3:#1a5644;--line:rgba(244,239,225,.16);--cream:#f4efe1;
--mute:#a9c4b6;--gold:#e9b44c;--red:#e2574c;--up:#9be28a;
--disp:"Avenir Next Condensed","Arial Narrow","Helvetica Neue",Arial,sans-serif;
--text:"Avenir Next","Segoe UI","Helvetica Neue",Arial,sans-serif;
--data:"SF Mono",Menlo,Consolas,monospace}
*{box-sizing:border-box}html,body{margin:0}
body{background:var(--turf);color:var(--cream);font:15px/1.5 var(--text);-webkit-font-smoothing:antialiased}
button,input{font:inherit;color:inherit}
:focus-visible{outline:2px solid var(--gold);outline-offset:2px}
.wrap{max-width:1180px;margin:0 auto;padding:0 28px}
.bar{display:flex;align-items:center;gap:22px;padding:18px 0;border-bottom:1px solid var(--line)}
.mark{display:flex;align-items:center;gap:12px}
.mark svg{width:40px;height:40px;display:block}
.mark b{font:700 30px/1 var(--disp);letter-spacing:.01em}
.host{font-family:var(--data);font-size:13px;color:var(--mute)}
.host strong{color:var(--cream);font-weight:600}
.bar .sp{flex:1}
.tag{font-size:12.5px;padding:3px 10px;border:1px solid var(--line);border-radius:999px;color:var(--mute)}
.tag.gold{border-color:var(--gold);color:var(--gold)}
.ghost{background:none;border:1px solid var(--line);border-radius:6px;padding:5px 12px;cursor:pointer}
.ghost:hover{border-color:var(--cream)}
h1{font:700 44px/1.02 var(--disp);margin:0 0 6px;letter-spacing:-.005em}
h2{font:600 24px/1.1 var(--disp);margin:0 0 4px}
.sub{color:var(--mute);margin:0 0 18px;max-width:58ch}
.lead{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(0,1fr);gap:44px;padding:38px 0 34px;border-bottom:1px solid var(--line)}
.matrix{display:grid;gap:6px;font-size:13.5px}
.matrix .corner,.matrix .col,.matrix .row{color:var(--mute);padding:6px 8px;font-family:var(--data);font-size:12.5px}
.matrix .col{text-align:left}
.matrix .row{display:flex;align-items:center}
.cell{min-height:74px;border-radius:8px;padding:10px 12px;background:var(--turf2);border:1px solid transparent}
.cell.none{background:none;border:1px dashed var(--line);color:var(--mute)}
.cell.permit{background:#1d6a4c;border-color:rgba(155,226,138,.45)}
.cell.deny{background:#5a2b2a;border-color:rgba(226,87,76,.55)}
.cell .n{font:700 26px/1 var(--disp)}
.cell .p{font-family:var(--data);font-size:12px;opacity:.9;margin-top:5px;overflow-wrap:anywhere}
.axis{font-size:12.5px;color:var(--mute);margin-top:10px}
dl.facts{margin:0;display:grid;grid-template-columns:auto 1fr;column-gap:18px}
dl.facts dt{color:var(--mute);padding:9px 0;border-bottom:1px solid var(--line)}
dl.facts dd{margin:0;padding:9px 0;border-bottom:1px solid var(--line);text-align:right;font-family:var(--data);font-size:13.5px}
dl.facts dd.big{font:700 22px/1.2 var(--disp)}
.two{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:44px;padding:34px 0;border-bottom:1px solid var(--line)}
.full{padding:34px 0}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{text-align:left;font-weight:500;color:var(--mute);padding:7px 10px 7px 0;border-bottom:1px solid var(--line)}
td{padding:9px 10px 9px 0;border-bottom:1px solid var(--line);vertical-align:top}
td.d,.d{font-family:var(--data);font-size:12.5px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:8px;background:var(--mute)}
.dot.up{background:var(--up)}.dot.down{background:none;border:1.5px solid var(--mute)}
.pill{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12.5px;font-weight:600}
.pill.permit{background:rgba(155,226,138,.16);color:var(--up)}
.pill.deny,.pill.reject{background:rgba(226,87,76,.2);color:#ff9b92}
.chip{display:inline-block;font-family:var(--data);font-size:12px;padding:1px 7px;margin:0 5px 5px 0;border:1px solid var(--line);border-radius:5px}
.zone{padding:12px 0;border-bottom:1px solid var(--line)}
.zone .zn{font:600 18px/1.2 var(--disp);margin-right:10px}
.zone .if{color:var(--mute)}
.zone .svc{margin-top:8px}
.quiet{color:var(--mute)}
.sample{margin-left:10px;vertical-align:middle}
footer{border-top:1px solid var(--line);padding:20px 0 44px;color:var(--mute);font-size:13px;display:flex;gap:26px;flex-wrap:wrap}
footer .d{color:var(--cream)}
#gate{min-height:100vh;display:grid;place-items:center;padding:24px}
#gate form{width:min(420px,100%)}
#gate svg{width:72px;height:72px}
#gate h1{font-size:54px;margin:14px 0 6px}
#gate input{width:100%;padding:11px 12px;margin:16px 0 12px;background:var(--turf2);border:1px solid var(--line);border-radius:6px;font-family:var(--data);font-size:13px}
#gate button{padding:10px 18px;border:0;border-radius:6px;background:var(--cream);color:var(--turf);font-weight:600;cursor:pointer}
#gate .err{color:#ff9b92;min-height:1.5em;margin:10px 0 0}
[hidden]{display:none!important}
@media (max-width:860px){.lead,.two{grid-template-columns:1fr;gap:30px}h1{font-size:34px}.bar{flex-wrap:wrap}}
</style></head><body>
<svg width="0" height="0" style="position:absolute" aria-hidden="true"><symbol id="logo" viewBox="0 0 48 48">
<rect x="9" y="15" width="6" height="29" rx="3" fill="#f4efe1"/><rect x="21" y="15" width="6" height="29" rx="3" fill="#f4efe1"/>
<rect x="33" y="15" width="6" height="29" rx="3" fill="#f4efe1"/>
<rect x="8.5" y="8" width="15" height="4.6" rx="2.3" fill="#e9b44c"/>
<rect x="25" y="4.2" width="15" height="4.6" rx="2.3" fill="#e9b44c" transform="rotate(-17 32.5 6.5)"/>
</symbol></svg>
<div id="gate"><form id="signin">
<svg role="img" aria-label="J-Wicket logo"><use href="#logo"/></svg>
<h1>J-Wicket</h1>
<p class="sub">The small door into your SRX. Paste the access token from the device to open it.</p>
<label for="tok">Access token</label>
<input id="tok" type="password" autocomplete="off" spellcheck="false" required>
<button type="submit">Sign in</button>
<p class="err" id="err" role="alert"></p>
</form></div>
<div id="app" hidden>
<div class="wrap">
<header class="bar"><div class="mark"><svg role="img" aria-label="J-Wicket logo"><use href="#logo"/></svg><b>J-Wicket</b></div>
<div class="host" id="host"></div><div class="sp"></div>
<span class="tag gold">Read-only preview</span><span class="tag" id="stamp"></span>
<button class="ghost" id="out" type="button">Sign out</button></header>
<section class="lead"><div><h1>Who can talk to whom</h1>
<p class="sub">Each square is a pair of zones. A filled square has policies. An empty one falls to the default policy.</p>
<div id="matrix"></div><p class="axis">Rows are the source zone. Columns are the destination zone.</p></div>
<aside><h2 id="model"></h2><p class="sub" id="junos"></p><dl class="facts" id="facts"></dl></aside></section>
<section class="two"><div><h2>Interfaces<span id="s-if"></span></h2><p class="sub">Link state, address and the zone each port belongs to.</p><div id="ifs"></div></div>
<div><h2>What may reach the firewall itself<span id="s-zn"></span></h2><p class="sub">Services each zone is allowed to open on this device.</p><div id="zones"></div></div></section>
<section class="full"><h2>Security policies<span id="s-pol"></span></h2><p class="sub">In evaluation order within each zone pair.</p><div id="pols"></div></section>
<footer id="foot"></footer>
</div></div>
<script>
"use strict";
const $=s=>document.querySelector(s);
function h(tag,attrs,...kids){const e=document.createElement(tag);for(const k in(attrs||{})){if(k==="class")e.className=attrs[k];else e.setAttribute(k,attrs[k]);}
for(const c of kids.flat()){if(c==null||c===false)continue;e.append(c.nodeType?c:document.createTextNode(String(c)));}return e;}
const SAMPLE={
interfaces:[{name:"ge-0/0/0",oper:"up",addresses:["203.0.113.2/30"]},{name:"ge-0/0/1",oper:"up",addresses:["10.10.0.1/24"]},{name:"ge-0/0/2",oper:"down",addresses:[]}],
zones:[{name:"trust",interfaces:["ge-0/0/1.0"],services:["ssh","https","ping"]},{name:"untrust",interfaces:["ge-0/0/0.0"],services:["ike"]}],
policies:[{from:"trust",to:"untrust",name:"allow-web",src:["any"],dst:["any"],app:["junos-https"],action:"permit"},{from:"untrust",to:"trust",name:"block-all",src:["any"],dst:["any"],app:["any"],action:"deny"}]};
let token="";
try{token=sessionStorage.getItem("wicket-token")||"";}catch(e){}
function use(panel,key,flagId){const real=panel&&panel.ok;const el=$(flagId);el.replaceChildren();
if(!real)el.append(h("span",{class:"tag sample"},"sample data"));return real?panel.rows:SAMPLE[key];}
function fmtUp(s){if(s==null)return "n/a";s=Math.floor(s);const d=Math.floor(s/86400),hh=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
return d?d+"d "+hh+"h":hh?hh+"h "+m+"m":m?m+"m "+(s%60)+"s":s+"s";}
function render(d){
const dev=d.device||{};
$("#host").replaceChildren(h("strong",null,dev.hostname||"unknown")," ",dev.address||"");
$("#model").textContent=dev.model||"SRX";$("#junos").textContent=dev.version?"Junos "+dev.version:"";
const facts=[["Active sessions",dev.sessions_active!=null?dev.sessions_active+(dev.sessions_max?" of "+dev.sessions_max:""):"n/a",1],
["Device uptime",dev.uptime||"n/a"],["Control plane memory",dev.mem_util!=null?dev.mem_util+"% used":"n/a"],
["Control plane CPU",dev.cpu_idle!=null?(100-dev.cpu_idle)+"% busy":"n/a"],
["Management services",(d.services||[]).join(", ")||"n/a"]];
$("#facts").replaceChildren(...facts.flatMap(f=>[h("dt",null,f[0]),h("dd",{class:f[2]?"big":""},f[1])]));
const zones=use(d.zones,"zones","#s-zn"),pols=use(d.policies,"policies","#s-pol"),ifs=use(d.interfaces,"interfaces","#s-if");
const names=[...new Set([...zones.map(z=>z.name),...pols.flatMap(p=>[p.from,p.to])])];
const mx=h("div",{class:"matrix",role:"table","aria-label":"Policies by zone pair"});
mx.style.gridTemplateColumns="minmax(70px,auto) repeat("+Math.max(names.length,1)+",minmax(0,1fr))";
mx.append(h("div",{class:"corner"},""),...names.map(n=>h("div",{class:"col"},"to "+n)));
for(const a of names){mx.append(h("div",{class:"row"},a));
for(const b of names){const hit=pols.filter(p=>p.from===a&&p.to===b);
if(!hit.length){mx.append(h("div",{class:"cell none"},"no policy"));continue;}
const deny=hit.every(p=>p.action!=="permit");
mx.append(h("div",{class:"cell "+(deny?"deny":"permit")},h("div",{class:"n"},hit.length+(hit.length===1?" policy":" policies")),
h("div",{class:"p"},hit.map(p=>p.name+" ("+p.action+")").join(", "))));}}
$("#matrix").replaceChildren(names.length?mx:h("p",{class:"quiet"},"No security zones are configured yet."));
const zoneOf={};for(const z of zones)for(const i of z.interfaces)zoneOf[i.split(".")[0]]=z.name;
$("#ifs").replaceChildren(ifs.length?h("table",null,h("thead",null,h("tr",null,h("th",null,"Port"),h("th",null,"Address"),h("th",null,"Zone"))),
h("tbody",null,ifs.map(i=>h("tr",null,h("td",{class:"d"},h("span",{class:"dot "+(i.oper==="up"?"up":"down"),title:i.oper||""}),i.name),
h("td",{class:"d"},i.addresses.length?i.addresses.join(", "):h("span",{class:"quiet"},"none")),
h("td",null,zoneOf[i.name]||h("span",{class:"quiet"},i.name.startsWith("fxp")?"management":"unassigned")))))):h("p",{class:"quiet"},"No interfaces reported."));
$("#zones").replaceChildren(...(zones.length?zones.map(z=>h("div",{class:"zone"},h("span",{class:"zn"},z.name),
h("span",{class:"if d"},z.interfaces.join(", ")||"no interfaces"),
h("div",{class:"svc"},z.services.length?z.services.map(s=>h("span",{class:"chip"},s)):h("span",{class:"quiet"},"Nothing. This zone cannot reach the device.")))):[h("p",{class:"quiet"},"No security zones are configured yet.")]));
$("#pols").replaceChildren(pols.length?h("table",null,h("thead",null,h("tr",null,...["From","To","Policy","Source","Destination","Application","Action"].map(t=>h("th",null,t)))),
h("tbody",null,pols.map(p=>h("tr",null,h("td",null,p.from),h("td",null,p.to),h("td",{class:"d"},p.name),h("td",{class:"d"},p.src.join(", ")),
h("td",{class:"d"},p.dst.join(", ")),h("td",{class:"d"},p.app.join(", ")),h("td",null,h("span",{class:"pill "+p.action},p.action)))))):h("p",{class:"quiet"},"No policies are configured. Traffic between zones is denied by default."));
const w=d.wicket||{};
$("#foot").replaceChildren(h("span",null,"Served from the routing engine by a Python process that Junos supervises."),
h("span",null,"Process ",h("span",{class:"d"},w.pid)),h("span",null,"Python ",h("span",{class:"d"},w.python)),
h("span",null,"Running for ",h("span",{class:"d"},fmtUp(w.uptime_s))),h("span",null,"Requests served ",h("span",{class:"d"},w.requests)));
$("#stamp").textContent="Updated "+new Date().toLocaleTimeString();
}
async function load(first){
let r;try{r=await fetch("/api/dashboard",{headers:{Authorization:"Bearer "+token},cache:"no-store"});}
catch(e){if(first)$("#err").textContent="The device did not answer. Check the address and try again.";return false;}
if(r.status===401){if(first)$("#err").textContent="That token was not accepted. Copy it again from the device.";signOut(false);return false;}
if(!r.ok){if(first)$("#err").textContent="The device answered, but could not read its own state (error "+r.status+").";return false;}
render(await r.json());$("#gate").hidden=true;$("#app").hidden=false;return true;}
function signOut(clearMsg){token="";try{sessionStorage.removeItem("wicket-token");}catch(e){}
$("#app").hidden=true;$("#gate").hidden=false;if(clearMsg)$("#err").textContent="";}
$("#signin").addEventListener("submit",async e=>{e.preventDefault();$("#err").textContent="";token=$("#tok").value.trim();
if(await load(true)){try{sessionStorage.setItem("wicket-token",token);}catch(x){}$("#tok").value="";}});
$("#out").addEventListener("click",()=>signOut(true));
if(token)load(true);
setInterval(()=>{if(token&&!$("#app").hidden&&!document.hidden)load(false);},15000);
</script></body></html>
"""


def serve(args: argparse.Namespace) -> int:
    token = load_token(args.token_file)
    tls = make_tls_context(args.cert, args.key)
    if tls is None and args.bind not in LOOPBACK and not args.allow_plaintext:
        raise ConfigError(
            f"refusing plaintext on {args.bind}: give --cert/--key, or --allow-plaintext for the spike"
        )
    if not 1024 <= args.port <= 65535:
        raise ConfigError(f"port {args.port} is outside 1024-65535")

    SpikeHandler.token = token
    SpikeHandler.junos = JunosLocal(args.rpc_timeout)

    try:
        httpd = ThreadingHTTPServer((args.bind, args.port), SpikeHandler)
    except OSError as exc:
        # This is test T2: a bind failure here is itself a spike result.
        raise ConfigError(f"cannot bind {args.bind}:{args.port}: {exc}") from exc
    httpd.daemon_threads = True
    if tls is not None:
        httpd.socket = tls.wrap_socket(httpd.socket, server_side=True)
    else:
        LOG.warning("TLS is off; the bearer token travels in clear text")

    def stop(signum: int, _frame: Any) -> None:
        LOG.info("signal %d received, shutting down", signum)
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    LOG.info("listening on %s:%d tls=%s", args.bind, args.port, tls is not None)
    try:
        httpd.serve_forever(poll_interval=0.5)
    finally:
        httpd.server_close()
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    raw = sys.argv[1:] if argv is None else argv
    if not raw and ARGS_FILE.is_file():
        raw = shlex.split(ARGS_FILE.read_text(encoding="utf-8"))
    args = parse_args(raw)
    if args.probe:
        return probe()
    setup_logging(args.log_level, args.log_file)
    try:
        return serve(args)
    except ConfigError as exc:
        LOG.error("startup refused: %s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
