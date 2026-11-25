"""SSH host-key trust for every connection the installer makes (Spec 006 section 8.10, INV-09). LAB ONLY.

* The key each port presents is fetched with a bare transport (no authentication) and looked up in the
  operator's ``~/.ssh/known_hosts`` and the installer's private known_hosts, under both ``host`` and
  ``[host]:port`` (as ncclient 0.7.1 does, verified). Unknown keys are refused (R-HOSTKEY) unless
  ``--accept-new-host-key``, which prints the key's SHA-256 fingerprint, asks the operator to compare
  it with one read on the lab console (how to read it from the Junos CLI is unknown, Q-INST-05), and
  writes it to the private file (0600). A key that differs from a recorded one is always refused.
* Two ports (the SSH port and a NETCONF fallback port) must present the same key, so a wrong ``--port``
  or lab port mapping cannot gate device A over NETCONF while files land on device B.
* Every later connection is pinned to that one verified key: ncclient (through PyEZ) gets a generated
  SSH configuration whose ``UserKnownHostsFile`` holds only that key; the own paramiko client uses a
  reject policy that accepts only that key (transport.pinned_policy).

The known_hosts parser is standard library only (plain and hashed ``|1|`` host names, ``[host]:port``,
patterns with ``*``, ``?`` and ``!``, ``@revoked``; ``@cert-authority`` lines are ignored: certificate
host keys are not supported). Device text never becomes a workstation path.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from . import plan

LOG = logging.getLogger("jwicket_install.hostkeys")

HostKeyBlob = Tuple[str, bytes]  # (key type, wire blob), as paramiko's get_name() and asbytes() give them

# A known_hosts key type and the host-key algorithms that present it (RFC 8332: rsa-sha2-* sign with an
# ssh-rsa key).
_ALGORITHMS: Mapping[str, Tuple[str, ...]] = {
    "ssh-rsa": ("rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"),
    "ssh-ed25519": ("ssh-ed25519",),
    "ecdsa-sha2-nistp256": ("ecdsa-sha2-nistp256",),
    "ecdsa-sha2-nistp384": ("ecdsa-sha2-nistp384",),
    "ecdsa-sha2-nistp521": ("ecdsa-sha2-nistp521",),
}
_KEYTYPE_RE = re.compile(r"^[a-z0-9@.-]{3,64}\Z")
MAX_KNOWN_HOSTS_BYTES = 4 * 1024 * 1024
_UNSAFE_CONFIG_PATH = re.compile(r"[\s\"'%~#=\\]")


class HostKeyError(Exception):
    """R-HOSTKEY: unknown key, a key that differs from the recorded one, or two ports with different keys."""


def fingerprint(key: HostKeyBlob) -> str:
    """OpenSSH's form: 'SHA256:' and the unpadded base64 of the blob's SHA-256 (plan.FINGERPRINT_RE)."""
    digest = hashlib.sha256(key[1]).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def algorithms_for(key_types: Iterable[str]) -> Tuple[str, ...]:
    out: List[str] = []
    for key_type in key_types:
        for algorithm in _ALGORITHMS.get(key_type, (key_type,)):
            if algorithm not in out:
                out.append(algorithm)
    return tuple(out)


def host_names(host: str, port: int) -> Tuple[str, ...]:
    """The names a known_hosts entry may use for this host and port."""
    return (host,) if port == 22 else (f"[{host}]:{port}", host)


@dataclass(frozen=True)
class KnownEntry:
    patterns: Tuple[str, ...]
    hashed: Optional[Tuple[bytes, bytes]]  # (salt, hash) of a |1| entry
    key_type: str
    blob: bytes
    revoked: bool
    source: str

    def matches(self, name: str) -> bool:
        if self.hashed is not None:
            salt, digest = self.hashed
            return hmac.compare_digest(hmac.new(salt, name.encode("utf-8"), hashlib.sha1).digest(), digest)
        matched = False
        for pattern in self.patterns:
            negated = pattern.startswith("!")
            body = pattern[1:] if negated else pattern
            if _pattern_match(name, body):
                if negated:
                    return False
                matched = True
        return matched


def _pattern_match(name: str, pattern: str) -> bool:
    """OpenSSH host patterns: '*' and '?' are wildcards; everything else, brackets included, is literal."""
    regex = "".join(".*" if ch == "*" else "." if ch == "?" else re.escape(ch) for ch in pattern)
    return re.fullmatch(regex, name) is not None


def parse_known_hosts(text: str, source: str) -> List[KnownEntry]:
    """Lines of an OpenSSH known_hosts file. A line that does not parse is skipped (and logged), never
    guessed into a trusted key."""
    entries: List[KnownEntry] = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        revoked = False
        if fields[0].startswith("@"):
            marker = fields.pop(0)
            if marker == "@revoked":
                revoked = True
            else:
                continue  # @cert-authority: certificate host keys are not supported
        if len(fields) < 3:
            LOG.info("%s line %d: not a known_hosts entry; skipped", source, number)
            continue
        names, key_type, blob_text = fields[0], fields[1], fields[2]
        if _KEYTYPE_RE.match(key_type) is None:
            continue
        try:
            blob = base64.b64decode(blob_text, validate=True)
        except (binascii.Error, ValueError):
            LOG.info("%s line %d: key is not base64; skipped", source, number)
            continue
        hashed: Optional[Tuple[bytes, bytes]] = None
        patterns: Tuple[str, ...] = ()
        if names.startswith("|1|"):
            parts = names.split("|")
            try:
                hashed = (base64.b64decode(parts[2], validate=True), base64.b64decode(parts[3], validate=True))
            except (IndexError, binascii.Error, ValueError):
                continue
        else:
            patterns = tuple(p for p in names.split(",") if p)
        entries.append(KnownEntry(patterns, hashed, key_type, blob, revoked, source))
    return entries


def read_known_hosts(paths: Sequence[Path]) -> List[KnownEntry]:
    entries: List[KnownEntry] = []
    for path in paths:
        try:
            if not path.is_file():
                continue
            if path.stat().st_size > MAX_KNOWN_HOSTS_BYTES:
                LOG.warning("%s is larger than 4 MB; not read", path)
                continue
            entries.extend(parse_known_hosts(path.read_text(encoding="utf-8", errors="replace"), str(path)))
        except OSError as exc:
            LOG.warning("cannot read %s: %s", path, exc.strerror or type(exc).__name__)
    return entries


def recorded(entries: Sequence[KnownEntry], host: str, port: int) -> List[KnownEntry]:
    names = host_names(host, port)
    return [e for e in entries if any(e.matches(n) for n in names)]


def key_types_for(entries: Sequence[KnownEntry], host: str, port: int) -> Tuple[str, ...]:
    """The key types recorded for this host and port, to steer the key exchange to one of them."""
    return tuple(dict.fromkeys(e.key_type for e in recorded(entries, host, port) if not e.revoked))


@dataclass(frozen=True)
class Verdict:
    key: HostKeyBlob
    known: bool  # True: recorded in a known_hosts file; False: unknown (only --accept-new-host-key)
    fingerprint: str


def judge(entries: Sequence[KnownEntry], host: str, port: int, key: HostKeyBlob) -> Verdict:
    """Raise HostKeyError for a revoked key or one that differs from the recorded key of its type."""
    matches = recorded(entries, host, port)
    for entry in matches:
        if entry.revoked and entry.blob == key[1]:
            raise HostKeyError(f"port {port} presented a key marked @revoked in {entry.source}")
    same_type = [e for e in matches if e.key_type == key[0] and not e.revoked]
    if any(e.blob == key[1] for e in same_type):
        return Verdict(key, True, fingerprint(key))
    if same_type:
        raise HostKeyError(
            f"port {port} presented a {key[0]} key ({fingerprint(key)}) that differs from the one recorded in "
            f"{same_type[0].source}: refused. If the lab device was rebuilt, remove its old line with "
            "'ssh-keygen -R <host>' and compare the new fingerprint with the lab console"
        )
    return Verdict(key, False, fingerprint(key))


def verify_ports(
    host: str,
    ports: Sequence[int],
    fetch: Callable[[int, Sequence[str]], HostKeyBlob],
    known_hosts: Sequence[Path],
) -> Dict[int, Verdict]:
    """Fetch and judge the key of every port; refuse different keys on two ports before anything else
    (INV-09). Unknown keys come back with ``known`` False; the caller decides (R-HOSTKEY)."""
    entries = read_known_hosts(known_hosts)
    keys: Dict[int, HostKeyBlob] = {}
    for port in ports:
        keys[port] = fetch(port, algorithms_for(key_types_for(entries, host, port)))
    if len(set(keys.values())) > 1:
        shown = ", ".join(f"port {p}: {fingerprint(k)}" for p, k in sorted(keys.items()))
        raise HostKeyError(
            f"the ports present different host keys ({shown}): they may be two devices. Nothing was written"
        )
    return {port: judge(entries, host, port, key) for port, key in keys.items()}


def known_line(host: str, port: int, key: HostKeyBlob) -> str:
    name = host if port == 22 else f"[{host}]:{port}"
    return f"{name} {key[0]} {base64.b64encode(key[1]).decode('ascii')}"


def append_private(path: Path, lines: Sequence[str]) -> None:
    """Append accepted keys to the private known_hosts file: created 0600, never followed if a link."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise HostKeyError(f"{path} is not a private file of this account (mode 0600); not written")
        os.write(fd, ("\n".join(lines) + "\n").encode("ascii"))
    finally:
        os.close(fd)


def pinned_files(directory: Path, host: str, ports: Sequence[int], key: HostKeyBlob) -> Tuple[Path, Path]:
    """A known_hosts holding only the verified key (under 'host' and '[host]:port') and an SSH
    configuration naming it, for ncclient through PyEZ (hostkey_verify=True). ncclient loads exactly one
    UserKnownHostsFile from the configuration (verified, ncclient 0.7.1 transport/ssh.py), so the one
    trusted entry is the only one it sees. Both files 0600 in a 0700 run directory."""
    if _UNSAFE_CONFIG_PATH.search(str(directory)):
        raise HostKeyError(
            f"the installer's state directory {directory} contains a space, quote or %; set "
            "JWICKET_INSTALL_STATE_DIR to a plain path"
        )
    known = directory / "known_hosts"
    lines: List[str] = []
    for port in sorted(set(ports)):
        lines.append(known_line(host, port, key))
        if port != 22:
            lines.append(f"{host} {key[0]} {base64.b64encode(key[1]).decode('ascii')}")
    _write_new(known, "\n".join(dict.fromkeys(lines)) + "\n")
    config = directory / "ssh_config"
    _write_new(
        config,
        "# Generated by jwicket-install for one run: trust only the host key verified for this device.\n"
        f"Host *\n    UserKnownHostsFile {known}\n    StrictHostKeyChecking yes\n",
    )
    return known, config


def _write_new(path: Path, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, text.encode("utf-8"))
    finally:
        os.close(fd)


def validate_fingerprints(values: Iterable[str]) -> Tuple[str, ...]:
    out = tuple(values)
    for value in out:
        if plan.FINGERPRINT_RE.match(value) is None:
            raise HostKeyError(f"{value!r} is not a SHA256 fingerprint")
    return out
