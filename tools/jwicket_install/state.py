"""Device replies to facts and prior state (Spec 006, sections 7.2, 7.11 and 8.3).

Standard library only, no I/O, no ``jnpr`` import, Python 3.7-compatible (the on-box op script embeds
it, and Junos 25.2R1-S1.4 ships Python 3.7.10, verified on SRX4100; plan.py lists what that excludes).
Every input is the XML *text* of one RPC reply (``str`` or ``bytes``; the caller serialises PyEZ's
element with ``lxml.etree.tostring``), so the 4 MB cap applies to everything parsed. Device replies are
semi-trusted: a reply with a DTD or entity declaration is refused before parsing (the standard library's
expat never fetches external entities; entity-expansion limits depend on the expat version, inferred,
so refusing declarations and the size cap are the controls).

FROZEN PUBLIC API
=================

``MAX_REPLY_BYTES`` (4 MB); ``Reply`` = ``Union[str, bytes]``; ``RpcErrorReply(message)`` for an RPC that
raised (the message is used only to classify, never kept); ``ReplyInput`` = ``Union[str, bytes,
RpcErrorReply, None]`` (None: not read); ``ReplyError``.

``parse_xml(data)``, ``facts_from_replies(software_info, cluster_status, chassis_inventory, config, *,
flow_sessions=None) -> DeviceFacts``, ``statements_from_config(config) -> StatementSet``,
``commit_state_from_reply(reply) -> CommitState``, ``history_from_reply(reply) -> (Pending, entries)``,
``file_list_from_reply(reply, directory) -> Optional[DirListing]``, ``checksum_from_reply(reply)``,
``file_text_from_reply(reply)``, ``receipt_from_text(text)``, ``flow_session_count(reply)``,
``parse_veriexec(text)``, ``is_absent_path_error(message)``, ``prior_from_replies(config_inherited,
config_raw, commit_information, file_lists, receipts, veriexec_text, *, checksums=None,
veriexec_source="shell read") -> PriorState``, ``strip_control(text)``.

Explicit parse rules (spec 8.3; every real reply shape is recorded by Q-INST-01, all fixtures are
synthetic):

* Cluster status: a ``chassis-cluster-status`` element means a cluster; a reply whose top element is a
  Junos ``<error>`` (not ``<rpc-error>``) means a standalone box, as PyEZ 2.8.3 treats it (verified,
  ``facts/get_chassis_cluster_status.py``: ``if rsp.tag == "error": srx_cluster = False``); an RPC that
  raised, an ``rpc-error`` or any other shape is None (R-MODEL: "not an SRX").
* file-list: a ``directory-list`` with entries is listed; an error or output text saying "No such file or
  directory", "does not exist" or "not found" (inferred wording) means absent, not unreadable; anything
  else is None.
* get-commit-information: no ``commit-information`` element, a non-integer or duplicate sequence number
  is unreadable; a ``pending-commit`` or ``prepared-commit`` element, or a non-empty ``commit-confirmed``
  on the newest entry, is pending (whether a comment lands in ``comment`` or ``log`` is unknown, so both
  are kept; the literal ``commit-confirmed`` text is unknown, so any non-empty value counts).
* Configuration: only the fixed subtrees are walked (``WALKED``, which includes the empty leaf ``system
  management-instance`` for ``[server] routing_instance``) and ``groups jwicket``; values are kept
  only for the leaves in ``KEEP_VALUE_LEAVES`` and only when they match the token set; every other value
  becomes ``h:<16 hex of its SHA-256>`` so a change is visible but no text (a ``source`` URL, a comment)
  survives; leaves named in ``SECRET_LEAVES`` are dropped entirely, value and name; a keyed-list name that
  fails the name pattern becomes ``invalid-name-<n>``; an ``inactive`` element's name is prefixed
  ``inactive:`` so it never counts as present.
* Every kept string matches a strict pattern; parsed state keeps no URL, no ``secret``, no ``$9$`` text
  and no ``encrypted-password`` (AC-006-22).
"""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET  # semi-trusted device replies: size cap and no DTD (module docstring)
from dataclasses import dataclass
from typing import Dict, Iterator, List, Mapping, Optional, Set, Tuple, Union

from . import plan
from .plan import (
    CommitEntry,
    DeviceFacts,
    FileInfo,
    Pair,
    Pending,
    PriorState,
    Receipt,
    StatementSet,
)

MAX_REPLY_BYTES = 4 * 1024 * 1024
Reply = Union[str, bytes]


class ReplyError(Exception):
    """A reply was too large, declared a DTD or entities, or is not XML."""


@dataclass(frozen=True)
class RpcErrorReply:
    """An RPC that raised instead of answering. ``message`` is only classified (absent path or not)."""

    message: str


ReplyInput = Union[str, bytes, RpcErrorReply, None]

# The subtrees statements_from_config walks (spec 8.3's select-only filters); nothing else is read. The
# select-only filter (transport.CONFIG_FILTER) must ask for each one; a test keeps the two equal.
# 'system management-instance' is an empty leaf (junos-es 23.2R1 conf-system YANG, verified; set on the lab
# SRX4100, verified): when set, the plan renders [server] routing_instance = mgmt_junos for --access tls.
WALKED: Tuple[Tuple[str, ...], ...] = (
    ("system", "management-instance"),
    ("system", "scripts"),
    ("system", "extensions"),
    ("system", "services", "netconf"),
    ("system", "services", "outbound-ssh"),
    ("system", "services", "web-management"),
    ("system", "services", "rest"),
    ("system", "fips"),
    ("event-options", "event-script"),
    ("chassis", "high-availability"),
)
KEEP_VALUE_LEAVES = frozenset({"language", "username", "sha-256", "port", "level", "apply-groups"})
SECRET_LEAVES = frozenset(
    {
        "secret",
        "encrypted-password",
        "plain-text-password",
        "plain-text-password-value",
        "pre-shared-key",
        "authentication-key",
        "key",
        "password",
        "simple-password",
        "community",
    }
)
_VALUE_RE = re.compile(r"^[A-Za-z0-9._@+-]{1,128}\Z")
_ABSENT_MARKERS = ("no such file or directory", "does not exist", "not found")
_VERIEXEC_PREFIX_RE = re.compile(r"^security\.mac\.veriexec\.state\s*:\s*(?P<value>.*)\Z")
_VERIEXEC_VALUE_RE = re.compile(r"^[a-z]+(?: [a-z]+){0,5}\Z")
_CONFIRMED_RE = re.compile(r"^[A-Za-z0-9 ,._:()/-]{1,80}\Z")
_CLIENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,31}\Z")
_SAFE_TEXT_RE = re.compile(r"^[A-Za-z0-9 ._:+!,=/@-]{1,512}\Z")
_PERM_RE = re.compile(r"^[dl-][rwxsStT-]{9}[.+@]?\Z")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


# ------------------------------------------------------------------------------------------------
# XML
# ------------------------------------------------------------------------------------------------


def parse_xml(data: Reply) -> ET.Element:
    """Parse one reply: at most MAX_REPLY_BYTES, no DTD and no entity declaration."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    if len(raw) > MAX_REPLY_BYTES:
        raise ReplyError(f"reply is {len(raw)} bytes, more than the 4 MB cap")
    lowered = raw.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise ReplyError("reply declares a DTD or an entity; refused before parsing")
    try:
        return ET.fromstring(raw)  # noqa: S314 - capped, declaration-free semi-trusted reply (module docstring)
    except ET.ParseError as exc:
        raise ReplyError(f"reply is not XML: {exc}") from exc


def _local(tag: object) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _kids(node: Optional[ET.Element], name: Optional[str] = None) -> Iterator[ET.Element]:
    if node is None:
        return
    for child in node:
        tag = _local(child.tag)
        if tag and (name is None or tag == name):
            yield child


def _kid(node: Optional[ET.Element], name: str) -> Optional[ET.Element]:
    return next(_kids(node, name), None)


def _text(node: Optional[ET.Element]) -> Optional[str]:
    if node is None or node.text is None:
        return None
    value = node.text.strip()
    return value or None


def _child_text(node: Optional[ET.Element], name: str) -> Optional[str]:
    return _text(_kid(node, name))


def _find(root: ET.Element, name: str, depth: int = 3) -> Optional[ET.Element]:
    """The first element named ``name`` at the root or within ``depth`` levels (rpc-reply wrapping)."""
    if _local(root.tag) == name:
        return root
    level = [root]
    for _ in range(depth):
        nxt: List[ET.Element] = []
        for node in level:
            for child in _kids(node):
                if _local(child.tag) == name:
                    return child
                nxt.append(child)
        level = nxt
    return None


def _unwrap(root: ET.Element) -> ET.Element:
    """Strip an rpc-reply (and output) wrapper: the first real element of the reply."""
    node = root
    while _local(node.tag) in ("rpc-reply", "output"):
        children = list(_kids(node))
        if not children:
            return node
        node = children[0]
    return node


def _try_parse(data: ReplyInput) -> Optional[ET.Element]:
    if data is None or isinstance(data, RpcErrorReply):
        return None
    try:
        return parse_xml(data)
    except ReplyError:
        return None


def strip_control(text: str, limit: int = 400) -> str:
    """Device text for display (UI-006-02): control characters removed, one line, bounded."""
    return plan.sanitize_display(text, limit)


def _safe_text(value: Optional[str]) -> Optional[str]:
    """Keep commit comments and logs only when plain and free of URLs and $9$ secrets (INV-08, INV-12)."""
    if value is None:
        return None
    flat = " ".join(value.split())
    if not flat or "://" in flat or "$9$" in flat or _SAFE_TEXT_RE.match(flat) is None:
        return None
    return flat


def _token_hash(text: str) -> str:
    return "h:" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


# ------------------------------------------------------------------------------------------------
# Facts
# ------------------------------------------------------------------------------------------------


def _match(value: Optional[str], pattern: re.Pattern[str]) -> Optional[str]:
    return value if value is not None and pattern.match(value) else None


def cluster_state(reply: ReplyInput) -> Optional[bool]:
    """True: a chassis cluster; False: a standalone SRX (Junos <error> reply); None: raised or unknown."""
    root = _try_parse(reply)
    if root is None:
        return None
    if _find(root, "chassis-cluster-status") is not None:
        return True
    if _find(root, "rpc-error") is not None:
        return None
    return False if _local(_unwrap(root).tag) == "error" else None


def _routing_engines(inventory: Optional[ET.Element]) -> Optional[int]:
    if inventory is None:
        return None
    chassis = _find(inventory, "chassis")
    count = 0
    if chassis is not None:
        for module in _kids(chassis, "chassis-module"):
            name = _child_text(module, "name") or ""
            if name.startswith("Routing Engine"):
                count += 1
    return count or None


def _config_root(reply: ReplyInput) -> Optional[ET.Element]:
    root = _try_parse(reply)
    return None if root is None else _find(root, "configuration")


def facts_from_replies(
    software_info: ReplyInput,
    cluster_status: ReplyInput,
    chassis_inventory: ReplyInput,
    config: ReplyInput,
    *,
    flow_sessions: Optional[int] = None,
) -> DeviceFacts:
    """DeviceFacts from get-software-information (host-name, product-model, junos-version: the elements
    PyEZ's facts read, verified), get-chassis-cluster-status, get-chassis-inventory (serial: inferred
    source) and the select-only configuration read (system fips, chassis high-availability). A string
    that does not match its pattern is None."""
    software = _try_parse(software_info)
    info = None if software is None else _find(software, "software-information", depth=4)
    routing_engines: Optional[int] = None
    if software is not None:
        items = [n for n in software.iter() if _local(n.tag) == "multi-routing-engine-item"]
        if items:
            routing_engines = len(items)
    inventory = _try_parse(chassis_inventory)
    chassis = None if inventory is None else _find(inventory, "chassis")
    if routing_engines is None:
        routing_engines = _routing_engines(inventory)
    conf = _config_root(config)
    fips: Optional[bool] = None
    mnha: Optional[bool] = None
    if conf is not None:
        fips = _kid(_kid(conf, "system"), "fips") is not None
        mnha = _kid(_kid(conf, "chassis"), "high-availability") is not None
    model = _child_text(info, "product-model")
    return DeviceFacts(
        hostname=_match(_child_text(info, "host-name"), plan.HOSTNAME_RE),
        model=_match(model.lower() if model else None, plan.MODEL_RE),
        junos_version=_match(_child_text(info, "junos-version"), plan.JUNOS_VERSION_RE),
        serial=_match(_child_text(chassis, "serial-number"), plan.SERIAL_RE),
        srx_cluster=cluster_state(cluster_status),
        mnha=mnha,
        routing_engines=routing_engines,
        fips_configured=fips,
        flow_sessions=flow_sessions if isinstance(flow_sessions, int) and flow_sessions >= 0 else None,
    )


def flow_session_count(reply: ReplyInput) -> Optional[int]:
    """The first 'active-sessions' count in a flow-session summary reply, the total 'show security flow
    session summary' prints as active (valid and invalidated together; the SRX4100 recording has
    'active-unicast-sessions' 21 before 'active-sessions' 43). Only a reply without it falls back to the
    first 'active-unicast-sessions' count (inferred shape)."""
    root = _try_parse(reply)
    if root is None:
        return None
    for name in ("active-sessions", "active-unicast-sessions"):
        for node in root.iter():
            if _local(node.tag) == name:
                value = _text(node)
                if value is not None and value.isdigit():
                    return int(value)
    return None


# ------------------------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------------------------


def _walk(
    node: ET.Element, path: Tuple[str, ...], out: Set[Pair], counter: List[int], skip: Optional[ET.Element] = None
) -> bool:
    """Add the model pairs under ``node`` to ``out``; True when it added any. ``skip`` is the keyed-list
    entry's own <name> element, which is part of the path, not a leaf."""
    added = False
    for child in _kids(node):
        if child is skip:
            continue
        tag = _local(child.tag)
        if tag in SECRET_LEAVES:
            continue
        if any(_local(k) == "inactive" for k in child.attrib):
            tag = "inactive:" + tag
        name_node = _kid(child, "name")
        has_children = any(c is not name_node for c in _kids(child))
        if name_node is not None:
            raw = _text(name_node) or ""
            if plan.NAME_RE.match(raw) is None:
                counter[0] += 1
                raw = f"invalid-name-{counter[0]}"
            entry_path = (*path, tag, raw)
            if not (has_children and _walk(child, entry_path, out, counter, skip=name_node)):
                out.add((" ".join(entry_path), ""))
            added = True
            continue
        if has_children:
            if not _walk(child, (*path, tag), out, counter):
                out.add((" ".join((*path, tag)), ""))
            added = True
            continue
        value = _text(child)
        key = " ".join((*path, tag))
        if value is None:
            out.add((key, ""))
        elif tag in KEEP_VALUE_LEAVES and _VALUE_RE.match(value):
            out.add((key, value))
        else:
            out.add((key, _token_hash(value)))
        added = True
    return added


def statements_from_config(config: ReplyInput) -> StatementSet:
    """The configuration model of the select-only read: the WALKED subtrees, groups jwicket and the
    top-level apply-groups, by the rules in the module docstring. An unreadable reply is empty; callers
    use prior_from_replies, which records it as unreadable."""
    conf = _config_root(config)
    out: Set[Pair] = set()
    if conf is None:
        return StatementSet()
    counter = [0]
    _walk_selected(conf, (), out, counter)
    for group in _kids(conf, "groups"):
        if _child_text(group, "name") == plan.GROUP_NAME:
            inner: Set[Pair] = set()
            _walk(group, plan.GROUP_PREFIX, inner, counter, skip=_kid(group, "name"))
            out |= inner or {(" ".join(plan.GROUP_PREFIX), "")}
    for node in _kids(conf, "apply-groups"):
        value = _text(node)
        if value is not None:
            out.add(("apply-groups", value if _VALUE_RE.match(value) else _token_hash(value)))
    return StatementSet.of(out)


def _walk_selected(conf: ET.Element, prefix: Tuple[str, ...], out: Set[Pair], counter: List[int]) -> None:
    for subtree in WALKED:
        node: Optional[ET.Element] = conf
        for part in subtree:
            node = _kid(node, part)
            if node is None:
                break
        if node is None:
            continue
        holder = ET.Element("holder")
        holder.append(node)
        if not _walk(holder, (*prefix, *subtree[:-1]), out, counter):
            out.add((" ".join((*prefix, *subtree)), ""))


# ------------------------------------------------------------------------------------------------
# Commit state and history (spec 8.5)
# ------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class CommitState:
    pending: Pending
    entries: Tuple[CommitEntry, ...]
    scheduled: bool = False
    prepared: bool = False


def commit_state_from_reply(reply: ReplyInput) -> CommitState:
    """get-commit-information (SRX YANG 23.2R1, verified) by the rules in the module docstring."""
    root = _try_parse(reply)
    info = None if root is None else _find(root, "commit-information")
    if info is None:
        return CommitState(Pending.UNREADABLE, ())
    scheduled = _kid(info, "pending-commit") is not None
    prepared = _kid(info, "prepared-commit") is not None
    entries: List[CommitEntry] = []
    seen: Set[int] = set()
    for node in _kids(info, "commit-history"):
        raw_sequence = _child_text(node, "sequence-number")
        if raw_sequence is None or not raw_sequence.isdigit() or int(raw_sequence) in seen:
            return CommitState(Pending.UNREADABLE, ())
        sequence = int(raw_sequence)
        seen.add(sequence)
        confirmed_raw = " ".join((_child_text(node, "commit-confirmed") or "").split())
        if confirmed_raw and _CONFIRMED_RE.match(confirmed_raw) is None:
            confirmed_raw = "unrecognized"
        client = _child_text(node, "client")
        entries.append(
            CommitEntry(
                sequence=sequence,
                user=_match(_child_text(node, "user"), plan.USER_RE),
                client=client if client is not None and _CLIENT_RE.match(client) else None,
                comment=_safe_text(_child_text(node, "comment")),
                log=_safe_text(_child_text(node, "log")),
                confirmed_state=confirmed_raw,
                date_time=_match(_child_text(node, "date-time"), plan.DATE_TIME_RE),
            )
        )
    entries.sort(key=lambda e: e.sequence)
    newest_pending = bool(entries) and entries[0].pending_confirm
    pending = Pending.OTHER if (scheduled or prepared or newest_pending) else Pending.NONE
    return CommitState(pending, tuple(entries), scheduled, prepared)


def history_from_reply(reply: ReplyInput) -> Tuple[Pending, Tuple[CommitEntry, ...]]:
    state = commit_state_from_reply(reply)
    return state.pending, state.entries


# ------------------------------------------------------------------------------------------------
# Files
# ------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class DirListing:
    state: str  # "listed" or "absent"
    entries: Tuple[FileInfo, ...] = ()


def is_absent_path_error(message: str) -> bool:
    """An error text that means the path does not exist (inferred wording; Q-INST-01 records it)."""
    lowered = message.lower()
    return any(marker in lowered for marker in _ABSENT_MARKERS)


def _mode_of(permissions: Optional[ET.Element]) -> Tuple[Optional[int], Optional[str]]:
    """Mode bits and type letter from file-permissions: its ``format`` attribute ('-rw-r--r--', as PyEZ
    reads it, verified) or its text (octal digits, which PyEZ reads as an int)."""
    if permissions is None:
        return None, None
    form = next((v for k, v in permissions.attrib.items() if _local(k) == "format"), None)
    if form is not None and _PERM_RE.match(form.strip()):
        text = form.strip()
        bits = 0
        for index, char in enumerate(text[1:10]):
            if char not in "-":
                bits |= 1 << (8 - index)
        return bits, text[0]
    raw = _text(permissions)
    if raw is not None and re.match(r"^[0-7]{3,4}\Z", raw):
        return int(raw, 8) & 0o777, None
    return None, None


def file_list_from_reply(reply: ReplyInput, directory: str) -> Optional[DirListing]:
    """file-list detail by the rules in the module docstring. File names that fail the name pattern are
    kept as invalid-name-<n>, so an unknown file still keeps the directory from being removed."""
    if isinstance(reply, RpcErrorReply):
        return DirListing("absent") if is_absent_path_error(reply.message) else None
    root = _try_parse(reply)
    if root is None:
        return None
    for node in root.iter():
        if _local(node.tag) in ("error", "rpc-error", "output", "message", "error-message"):
            text = " ".join(t.strip() for t in node.itertext() if t.strip())
            if is_absent_path_error(text):
                return DirListing("absent")
    listing = _find(root, "directory-list")
    if listing is None:
        return None
    entries: List[FileInfo] = []
    counter = 0
    for directory_node in _kids(listing, "directory"):
        base = _child_text(directory_node, "directory-name") or directory
        base = base.rstrip("/") or "/"
        for item in _kids(directory_node, "file-information"):
            raw_name = _child_text(item, "file-name") or ""
            name = raw_name.rstrip("/")
            relative = f"{base}/{name}" if base != "/" else f"/{name}"
            full = name if name.startswith("/") else relative
            leaf = full.rpartition("/")[2]
            if plan.NAME_RE.match(leaf) is None or not full.startswith("/"):
                counter += 1
                full = f"{directory.rstrip('/')}/invalid-name-{counter}"
            mode, kind = _mode_of(_kid(item, "file-permissions"))
            is_dir = _kid(item, "file-directory") is not None or kind == "d"
            is_link = _kid(item, "file-symlink") is not None or _kid(item, "file-symlink-target") is not None
            is_link = is_link or kind == "l"
            size_text = _child_text(item, "file-size")
            entries.append(
                FileInfo(
                    path=full,
                    owner=_match(_child_text(item, "file-owner"), plan.USER_RE),
                    mode=mode,
                    size=int(size_text) if size_text is not None and size_text.isdigit() else None,
                    is_dir=is_dir,
                    is_symlink=is_link,
                )
            )
    return DirListing("listed", tuple(entries))


def checksum_from_reply(reply: ReplyInput) -> Optional[str]:
    """get-sha256-checksum-information: the one file-checksum's checksum, 64 hex, compared lowercase
    (an error, several entries or another shape is None, which counts as a mismatch: spec 8.9)."""
    root = _try_parse(reply)
    if root is None:
        return None
    info = _find(root, "checksum-information")
    entries = list(_kids(info, "file-checksum"))
    if len(entries) != 1:
        return None
    value = (_child_text(entries[0], "checksum") or "").lower()
    return value if plan.SHA256_RE.match(value) else None


def file_text_from_reply(reply: ReplyInput, limit: int = 256 * 1024) -> Optional[str]:
    """file-show: the file-content text, at most ``limit`` characters (the device receipt is advisory)."""
    root = _try_parse(reply)
    if root is None:
        return None
    content = _find(root, "file-content")
    if content is None:
        return None
    text = "".join(content.itertext())
    return text if len(text) <= limit else None


def receipt_from_text(text: Optional[str]) -> Optional[Receipt]:
    """A receipt that passes schema 2 validation, else None (a device receipt is advisory: INV-11)."""
    if text is None:
        return None
    try:
        return Receipt.from_json(text)
    except plan.InputError:
        return None


def parse_veriexec(text: Optional[str]) -> Optional[str]:
    """Accept 'security.mac.veriexec.state: loaded active enforce' and the bare value (one line). A line
    with the prefix wins; otherwise exactly one non-empty line is taken as the bare value."""
    if text is None or len(text) > 4096:
        return None
    lines = [" ".join(line.split()) for line in text.splitlines() if line.strip()]
    for line in lines:
        match = _VERIEXEC_PREFIX_RE.match(line)
        if match is not None:
            value = match.group("value").strip()
            return value if _VERIEXEC_VALUE_RE.match(value) else None
    if len(lines) == 1 and _VERIEXEC_VALUE_RE.match(lines[0]):
        return lines[0]
    return None


# ------------------------------------------------------------------------------------------------
# Prior state
# ------------------------------------------------------------------------------------------------


def prior_from_replies(
    config_inherited: ReplyInput,
    config_raw: ReplyInput,
    commit_information: ReplyInput,
    file_lists: Mapping[str, ReplyInput],
    receipts: Mapping[str, Optional[str]],
    veriexec_text: Optional[str],
    *,
    checksums: Optional[Mapping[str, ReplyInput]] = None,
    veriexec_source: str = "shell read",
    script_lists: Optional[Mapping[str, ReplyInput]] = None,
) -> PriorState:
    """PriorState from the preflight reads (spec 8.3). ``file_lists`` maps a directory to its file-list
    reply; ``receipts`` maps "device" and "workstation" to receipt JSON text (the workstation one already
    matched to this device's host-key fingerprint by the caller); ``checksums`` maps a path to its
    get-sha256-checksum-information reply. A read that fails is named in ``unreadable``, which the plan
    refuses (R-UNREADABLE); it is never guessed. ``script_lists`` are the file-list replies of
    plan.S1_SCRIPT_DIRS: their files count for uninstall's S1 rule, and one that fails is recorded as an
    unreadable directory (which keeps S1) without refusing anything else."""
    unreadable: List[str] = []
    raw_root = _config_root(config_raw)
    inherited_root = _config_root(config_inherited)
    if raw_root is None:
        unreadable.append("configuration")
    direct = statements_from_config(config_raw)
    effective = statements_from_config(config_inherited) if inherited_root is not None else direct
    state = commit_state_from_reply(commit_information)
    files: Dict[str, FileInfo] = {}
    directories: Dict[str, str] = {}
    for directory, reply in sorted(file_lists.items()):
        listing = file_list_from_reply(reply, directory)
        if listing is None:
            directories[directory] = "unreadable"
            unreadable.append(f"file list {directory}")
            continue
        directories[directory] = listing.state
        for entry in listing.entries:
            files[entry.path] = entry
    for directory, reply in sorted((script_lists or {}).items()):
        listing = file_list_from_reply(reply, directory)
        directories[directory] = "unreadable" if listing is None else listing.state
        for entry in listing.entries if listing is not None else ():
            files[entry.path] = entry
    sums: Dict[str, str] = {}
    for path, reply in sorted((checksums or {}).items()):
        value = checksum_from_reply(reply)
        if value is not None:
            sums[path] = value
    return PriorState(
        effective=effective,
        direct=direct,
        pending=state.pending,
        scheduled_commit=state.scheduled,
        prepared_commit=state.prepared,
        history=state.entries,
        files=files,
        directories=directories,
        checksums=sums,
        device_receipt=receipt_from_text(receipts.get("device")),
        workstation_receipt=receipt_from_text(receipts.get("workstation")),
        veriexec=parse_veriexec(veriexec_text),
        veriexec_source=veriexec_source if veriexec_text is not None else "not read",
        unreadable=tuple(unreadable),
    )
