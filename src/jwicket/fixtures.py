"""Fixture replay for development and tests. Excluded from the device bundle by tools/bundle.py."""

from __future__ import annotations

import copy
import ipaddress
import json
import math
import random
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from xml.etree import ElementTree

from jwicket.junos.errors import RpcDenied, RpcFailed, RpcUnsupported
from jwicket.junos.session import check_rpc
from jwicket.junos.xmlutil import Element, local, text


class FixtureSession:
    """Replays files from a fixture directory. Development and tests only; never on a device.

    Layout: ``config.xml`` (a <configuration> element), ``<rpc-name>.xml`` per operational RPC, and
    an optional ``errors.json`` mapping ``"<user>:<rpc-name>"`` or ``"*:<rpc-name>"`` to one of
    ``denied``, ``unsupported``, ``failed`` so that login-class and platform differences can be shown.
    ``get-configuration`` is the RPC name used for config reads.
    """

    backend = "fixture"

    def __init__(self, directory: Path, user: str, clock: Optional[Callable[[], float]] = None) -> None:
        self._dir = directory
        self._user = user
        errors_file = directory / "errors.json"
        self._errors: Dict[str, str] = {}
        if errors_file.is_file():
            loaded = json.loads(errors_file.read_text(encoding="utf-8"))
            self._errors = {str(k): str(v) for k, v in loaded.items()}
        self.closed = False
        self._live = live_model_for(directory, clock)

    @property
    def user(self) -> str:
        return self._user

    def _maybe_fail(self, name: str) -> None:
        kind = self._errors.get(f"{self._user}:{name}") or self._errors.get(f"*:{name}")
        if kind == "denied":
            raise RpcDenied(f"fixture: {name} denied for {self._user}")
        if kind == "unsupported":
            raise RpcUnsupported(f"fixture: {name} unsupported")
        if kind == "failed":
            raise RpcFailed(f"fixture: {name} failed")

    def _load(self, filename: str) -> Element:
        target = self._dir / filename
        if not target.is_file():
            raise RpcUnsupported(f"fixture has no {filename}")
        return ElementTree.parse(target).getroot()  # noqa: S314 - repository fixtures, not network input

    def get_configuration(self, filter_xml: str) -> Element:
        self._maybe_fail("get-configuration")
        return self._load("config.xml")

    def rpc(self, name: str, **params: Any) -> Element:
        check_rpc(name)
        self._maybe_fail(name)
        if self._live is not None and name == "get-flow-session-information":
            filters = {k: str(v) for k, v in params.items() if k != "summary"}
            if params.get("summary"):
                return self._live.summary_xml(filters)
            return self._live.sessions_xml(filters)
        if self._live is not None and name == "get-security-log-information":
            return self._live.buffer_xml(str(params.get("newer_than") or ""))
        if self._live is not None and name in HEALTH_RPCS:
            return self._live.health_xml(self._load(f"{name}.xml"))
        if name == "get-log":
            filename = str(params.get("filename", ""))
            base_file = self._dir / "logs" / f"{filename}.log"
            base = base_file.read_text(encoding="utf-8") if base_file.is_file() else ""
            if self._live is None and not base:
                raise RpcUnsupported(f"fixture has no log {filename}")
            body = self._live.log_text(filename, base) if self._live is not None else base
            reply = ElementTree.Element("file-content", {"filename": f"/var/log/{filename}"})
            reply.text = body
            return reply
        loaded = self._load(f"{name}.xml")
        if name.startswith("get-sec-log-report-detail-") and params.get("descending"):
            # Emulates the inferred device behaviour (newest first when ``descending`` is sent); the
            # fixture files hold records oldest first, like the documented sample output.
            for element in loaded.iter():
                if element.text and "\n" in element.text.strip():
                    rows = element.text.strip("\n").split("\n")
                    element.text = "\n" + "\n".join(reversed(rows)) + "\n"
        return loaded

    def close(self) -> None:
        self.closed = True


# --- live, time-driven fixture data (development server only) -------------------------------------

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
LOOKBACK_S = 900


def _bsd_time(ts: float) -> str:
    t = time.gmtime(ts)
    return f"{_MONTHS[t.tm_mon - 1]} {t.tm_mday:2d} {t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}"


def _iso_time(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts)) + f".{int((ts % 1) * 1000):03d}Z"


class LiveModel:
    """Synthetic traffic that follows the fixture's policies, so sessions and logs move over time.

    Deterministic: the flows that start in a given second depend only on the fixture seed and that
    second, so every poll sees a consistent table, sessions age and close, and new ones appear.
    """

    def __init__(self, spec: Dict[str, Any], clock: Callable[[], float] = time.time) -> None:
        self.spec = spec
        self.clock = clock
        self.host = str(spec.get("hostname", "fixture-fw"))
        self.seed = str(spec.get("seed", "jwicket"))
        self.rate = float(spec.get("flows_per_second", 2.0))
        self.profiles: List[Dict[str, Any]] = list(spec["profiles"])
        self.weights = [float(p.get("weight", 1)) for p in self.profiles]

    def _flows_in(self, slot: int) -> List[Dict[str, Any]]:
        rng = random.Random(f"{self.seed}:{slot}")  # noqa: S311 - synthetic fixture data, not security
        count = int(rng.random() * self.rate * 2 + 0.5)
        flows = []
        for k in range(count):
            prof = rng.choices(self.profiles, weights=self.weights)[0]
            src = rng.choice(prof["src"])
            dst = rng.choice(prof["dst"])
            sport = rng.randint(1024, 65000)
            dport = int(rng.choice(prof["dport"]))
            nat_src = None
            if prof.get("snat"):
                nat_src = (prof["snat"], rng.randint(1024, 65000))
            # Under destination NAT, the client targets the public address and the session is
            # translated to the private server address held in ``dst``.
            nat_dst = (dst, dport) if prof.get("public") else None
            dur = rng.uniform(float(prof["duration"][0]), float(prof["duration"][1]))
            flows.append(
                {
                    "sid": 100000 + (slot % 100000) * 8 + k,
                    "start": slot + rng.random(),
                    "duration": dur,
                    "rate": rng.uniform(float(prof["bps"][0]), float(prof["bps"][1])) / 8.0,
                    "prof": prof,
                    "src": src, "sport": sport, "dst": dst, "dport": dport,
                    "nat_src": nat_src, "nat_dst": nat_dst,
                    "reason": rng.choice(prof.get("close", ["TCP FIN"])),
                }
            )
        return flows

    def flows(self, now: float) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for slot in range(int(now) - LOOKBACK_S, int(now) + 1):
            out.extend(f for f in self._flows_in(slot) if f["start"] <= now)
        return out

    @staticmethod
    def _matches(flow: Dict[str, Any], filters: Dict[str, str]) -> bool:
        """Emulates the device applying get-flow-session-information filters."""
        prof = flow["prof"]
        for key, value in filters.items():
            if key == "source_prefix":
                ok = ipaddress.ip_address(flow["src"]) in ipaddress.ip_network(value, strict=False)
            elif key == "destination_prefix":
                ok = ipaddress.ip_address(flow["dst"]) in ipaddress.ip_network(value, strict=False)
            elif key == "source_port":
                ok = int(value) == flow["sport"]
            elif key == "destination_port":
                ok = int(value) == flow["dport"]
            elif key == "protocol":
                ok = value == prof["proto"]
            elif key == "application":
                ok = value == prof["app"]
            elif key == "interface":
                ok = value in (prof["in_iface"], prof["out_iface"])
            else:
                continue
            if not ok:
                return False
        return True

    def sessions_xml(self, filters: Dict[str, str]) -> Element:
        now = self.clock()
        root = ElementTree.Element("flow-session-information")
        shown = 0
        for f in self.flows(now):
            prof = f["prof"]
            if prof.get("action") == "deny" or not f["start"] <= now < f["start"] + f["duration"]:
                continue
            if not self._matches(f, filters):
                continue
            shown += 1
            age = now - f["start"]
            node = ElementTree.SubElement(root, "flow-session")
            for tag, value in (
                ("session-identifier", f["sid"]),
                ("status", "Normal"),
                ("session-state", "Valid"),
                ("policy", f"{prof['policy']}/{prof.get('policy_index', 4)}"),
                ("configured-timeout", prof.get("timeout", 1800)),
                ("timeout", max(1, int(prof.get("timeout", 1800) - (age % 10)))),
                ("start-time", int(f["start"])),
                ("duration", int(age)),
            ):
                ElementTree.SubElement(node, tag).text = str(value)
            fwd = f["rate"] * age
            # Forward wing: what the client sent (destination is the public address under DNAT).
            # Reverse wing: what the server answers to (source is the translated address under SNAT).
            public_dst = prof.get("public", {}).get(f["dst"], f["dst"]) if f["nat_dst"] else f["dst"]
            reply_dst, reply_dport = f["nat_src"] if f["nat_src"] else (f["src"], f["sport"])
            wings = (
                ("In", f["src"], f["sport"], public_dst, f["dport"], prof["in_iface"], fwd * 0.08),
                ("Out", f["dst"], f["dport"], reply_dst, reply_dport, prof["out_iface"], fwd),
            )
            for direction, sa, sp, da, dp, iface, nbytes in wings:
                w = ElementTree.SubElement(node, "flow-information")
                for tag, value in (
                    ("direction", direction), ("source-address", sa), ("source-port", sp),
                    ("destination-address", da), ("destination-port", dp), ("protocol", prof["proto"]),
                    ("interface-name", iface), ("pkt-cnt", int(nbytes / 700) + 1), ("byte-cnt", int(nbytes) + 60),
                ):
                    ElementTree.SubElement(w, tag).text = str(value)
        ElementTree.SubElement(root, "displayed-session-count").text = str(shown)
        return root

    def summary_xml(self, filters: Optional[Dict[str, str]] = None) -> Element:
        now = self.clock()
        live = [
            f for f in self.flows(now)
            if f["prof"].get("action") != "deny" and f["start"] <= now < f["start"] + f["duration"]
        ]
        if filters:
            # A filtered summary reports the matching count only (displayed-session-count).
            wrapper = ElementTree.Element("security-flow-information")
            info = ElementTree.SubElement(wrapper, "flow-session-information")
            count = sum(1 for f in live if self._matches(f, filters))
            ElementTree.SubElement(info, "displayed-session-valid").text = str(count)
            ElementTree.SubElement(info, "displayed-session-count").text = str(count)
            return wrapper
        active = len(live) + int(self.spec.get("extra_active", 0))
        root = ElementTree.Element("flow-session-information")
        summary = ElementTree.SubElement(root, "flow-session-summary-information")
        ElementTree.SubElement(summary, "active-sessions").text = str(active)
        ElementTree.SubElement(summary, "max-sessions").text = str(self.spec.get("max_sessions", 524288))
        ElementTree.SubElement(summary, "failed-sessions").text = "0"
        return root

    # -- logs --

    def buffer_xml(self, newer_than: str) -> Element:
        """get-security-log-information: the routing engine's security log buffer (event mode)."""
        now = self.clock()
        root = ElementTree.Element("security-log-information")
        for ts, tag, f in self._flow_events(now)[-300:]:
            stamp = time.strftime("%Y-%m-%d.%H:%M:%S", time.gmtime(ts))
            if newer_than and stamp <= newer_than:
                continue
            prof = f["prof"]
            ev = ElementTree.SubElement(root, "security-event")
            dst = prof.get("public", {}).get(f["dst"], f["dst"]) if f["nat_dst"] else f["dst"]
            verb = {"RT_FLOW_SESSION_CREATE": "session created", "RT_FLOW_SESSION_CLOSE":
                    f"session closed {f['reason']}:", "RT_FLOW_SESSION_DENY": "session denied"}[tag]
            for name, value in (
                ("security-event-time", stamp), ("security-event-id", tag),
                ("security-event-message", f"{verb} {f['src']}/{f['sport']}->{dst}/{f['dport']} {prof['app']} "
                                           f"{prof['policy']} {prof['from']} {prof['to']}"),
                ("severity", "info"), ("security-event-result", "deny" if "DENY" in tag else "permit"),
                ("security-event-policy-name", prof["policy"]), ("security-event-protocol", prof["proto"]),
                ("security-event-source-address", f["src"]), ("security-event-source-port", f["sport"]),
                ("security-event-destination-address", dst), ("security-event-destination-port", f["dport"]),
                ("security-event-interface-name", prof["in_iface"]),
            ):
                ElementTree.SubElement(ev, name).text = str(value)
            proc = ElementTree.SubElement(ev, "process")
            ElementTree.SubElement(proc, "name").text = "flowd"
        return root

    def _flow_events(self, now: float) -> List[Tuple[float, str, Dict[str, Any]]]:
        events = []
        for f in self.flows(now):
            if f["prof"].get("action") == "deny":
                events.append((f["start"], "RT_FLOW_SESSION_DENY", f))
            else:
                events.append((f["start"], "RT_FLOW_SESSION_CREATE", f))
                if f["start"] + f["duration"] <= now:
                    events.append((f["start"] + f["duration"], "RT_FLOW_SESSION_CLOSE", f))
        events.sort(key=lambda e: (e[0], e[2]["sid"], e[1]))
        return events

    def _sd_line(self, ts: float, tag: str, f: Dict[str, Any]) -> str:
        prof = f["prof"]
        nat_s = f["nat_src"] or (f["src"], f["sport"])
        nat_d = f["nat_dst"] or (f["dst"], f["dport"])
        dst_pub = prof.get("public", {}).get(f["dst"], f["dst"]) if f["nat_dst"] else f["dst"]
        fields = [
            ("source-address", f["src"]), ("source-port", f["sport"]),
            ("destination-address", dst_pub), ("destination-port", f["dport"]),
            ("connection-tag", 0), ("service-name", prof["app"]),
        ]
        if tag != "RT_FLOW_SESSION_DENY":
            fields += [
                ("nat-source-address", nat_s[0]), ("nat-source-port", nat_s[1]),
                ("nat-destination-address", nat_d[0]), ("nat-destination-port", nat_d[1]),
                ("nat-connection-tag", 0),
                ("src-nat-rule-type", "source rule" if f["nat_src"] else "N/A"),
                ("src-nat-rule-name", prof.get("snat_rule", "N/A") if f["nat_src"] else "N/A"),
                ("dst-nat-rule-type", "destination rule" if f["nat_dst"] else "N/A"),
                ("dst-nat-rule-name", prof.get("dnat_rule", "N/A") if f["nat_dst"] else "N/A"),
            ]
        fields += [
            ("protocol-id", {"tcp": 6, "udp": 17}.get(prof["proto"], 1)), ("policy-name", prof["policy"]),
            ("source-zone-name", prof["from"]), ("destination-zone-name", prof["to"]),
            ("session-id", f["sid"]), ("username", "N/A"), ("roles", "N/A"),
            ("packet-incoming-interface", prof["in_iface"]), ("application", prof.get("l7", "UNKNOWN")),
            ("nested-application", "UNKNOWN"), ("encrypted", "UNKNOWN"),
        ]
        text_msg = f"{f['src']}/{f['sport']}->{dst_pub}/{f['dport']}"
        if tag == "RT_FLOW_SESSION_CLOSE":
            fwd = f["rate"] * f["duration"]
            fields = [("reason", f["reason"]), *fields]
            fields += [
                ("packets-from-client", int(fwd * 0.08 / 700) + 1), ("bytes-from-client", int(fwd * 0.08) + 60),
                ("packets-from-server", int(fwd / 700) + 1), ("bytes-from-server", int(fwd) + 60),
                ("elapsed-time", int(f["duration"])),
            ]
            msg = f"session closed {f['reason']}: {text_msg}"
        elif tag == "RT_FLOW_SESSION_DENY":
            fields += [("reason", "policy deny")]
            msg = f"session denied {text_msg}"
        else:
            msg = f"session created {text_msg}"
        sd = " ".join(f'{k}="{v}"' for k, v in fields)
        return f"<14>1 {_iso_time(ts)} {self.host} RT_FLOW - {tag} [junos@2636.1.1.1.2.129 {sd}] {msg}"

    def _system_lines(self, now: float) -> List[Tuple[float, str]]:
        templates = self.spec.get("system_events", [])
        out: List[Tuple[float, str]] = []
        start = int(now) - LOOKBACK_S
        for slot in range(start - start % 20, int(now) + 1, 20):
            rng = random.Random(f"{self.seed}:sys:{slot}")  # noqa: S311 - synthetic fixture data
            if not templates or rng.random() < 0.35:
                continue
            ts = slot + rng.random() * 19
            if ts > now:
                continue
            tpl = rng.choice(templates)
            line = tpl.replace("{host}", self.host).replace("{pid}", str(rng.randint(1200, 9800)))
            line = line.replace("{ip}", rng.choice(self.spec.get("system_ips", ["10.10.0.20"])))
            line = line.replace("{port}", str(rng.randint(40000, 65000)))
            out.append((ts, f"{_bsd_time(ts)} {line}"))
        return out

    def health_xml(self, reply: Element) -> Element:
        """A health reply whose CPU, memory, load and session figures move with the clock."""
        return _vary_health(self, copy.deepcopy(reply))

    def log_text(self, name: str, base: str) -> str:
        now = self.clock()
        if name == self.spec.get("traffic_file", "traffic-log"):
            lines = [self._sd_line(ts, tag, f) for ts, tag, f in self._flow_events(now)]
        else:
            lines = [ln for _ts, ln in sorted(self._system_lines(now))]
            # Event-mode denies also reach the messages file in BSD format.
            for ts, tag, f in self._flow_events(now):
                if tag == "RT_FLOW_SESSION_DENY":
                    prof = f["prof"]
                    proto_id = {"tcp": 6, "udp": 17}.get(prof["proto"], 1)
                    lines.append(
                        f"{_bsd_time(ts)} {self.host} RT_FLOW: {tag}: session denied "
                        f"{f['src']}/{f['sport']}->{f['dst']}/{f['dport']} 0x0 {prof['app']} "
                        f"{proto_id}(0) {prof['policy']} {prof['from']} {prof['to']} "
                        f"UNKNOWN UNKNOWN N/A(N/A) {prof['in_iface']} No policy deny"
                    )
            lines.sort(key=_bsd_sort_key)
        return base + "\n".join(lines) + ("\n" if lines else "")


def _bsd_sort_key(line: str) -> str:
    # "Nov 24 06:47:16 ..." sorts correctly within one month, which is all a 15-minute window needs.
    return line[:15]


HEALTH_RPCS = frozenset({"get-route-engine-information", "get-performance-summary-information"})
# Health figures the development server moves over time: (element, swing, period in seconds). The
# fixture's value is the midpoint; each moves on its own slow wave plus a little deterministic noise.
_HEALTH_WAVES = {
    "cpu-user": (6.0, 180.0), "cpu-system": (4.0, 140.0), "cpu-interrupt": (1.0, 60.0),
    "memory-system-total-util": (3.0, 600.0), "memory-buffer-utilization": (2.0, 420.0),
    "load-average-one": (0.35, 120.0), "load-average-five": (0.2, 300.0), "load-average-fifteen": (0.1, 900.0),
    "spu-cpu-utilization": (9.0, 150.0), "spu-memory-utilization": (2.0, 500.0),
    "spu-current-flow-session": (25.0, 90.0),
}


def _wave(seed: str, name: str, now: float, swing: float, period: float) -> float:
    phase = (sum(map(ord, f"{seed}:{name}")) % 997) / 997 * 2 * math.pi
    noise = random.Random(f"{seed}:{name}:{int(now // 5)}").uniform(-.25, .25)  # noqa: S311 - synthetic fixture data
    return swing * (math.sin(2 * math.pi * now / period + phase) + noise)


def _vary_health(model: LiveModel, reply: Element) -> Element:
    now = model.clock()
    for el in reply.iter():
        tag = local(el.tag)
        if tag in _HEALTH_WAVES and el.text and el.text.strip():
            base = float(el.text)
            value = max(0.0, base + _wave(model.seed, tag, now, *_HEALTH_WAVES[tag]))
            if "." in el.text:
                el.text = f"{value:.2f}"
            else:
                el.text = str(int(round(value if tag == "spu-current-flow-session" else min(value, 100.0))))
    # Idle is what is left; used memory follows the percentage.
    for item in (e for e in reply.iter() if local(e.tag) == "route-engine"):
        busy = sum(float(text(item, k) or 0) for k in ("cpu-user", "cpu-background", "cpu-system", "cpu-interrupt"))
        idle = next((e for e in item if local(e.tag) == "cpu-idle"), None)
        if idle is not None:
            idle.text = str(int(max(0.0, 100.0 - busy)))
        fields = ("memory-system-total", "memory-system-total-used", "memory-system-total-util")
        total, used, util = (next((e for e in item if local(e.tag) == k), None) for k in fields)
        if total is not None and used is not None and util is not None:
            used.text = str(int(float(total.text or 0) * float(util.text or 0) / 100))
    return reply


def live_model_for(directory: Path, clock: Optional[Callable[[], float]] = None) -> Optional[LiveModel]:
    spec_file = directory / "live.json"
    if not spec_file.is_file():
        return None
    return LiveModel(json.loads(spec_file.read_text(encoding="utf-8")), clock or time.time)
