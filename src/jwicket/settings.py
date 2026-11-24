"""Settings: one INI file, validated completely before anything listens.

Junos cannot pass ``--flag`` options to a JET application (spike finding F1), so under Junos the
daemon takes no arguments and reads a fixed path. Every rule here fails closed: a setting that would
weaken the listener is refused at startup with a message that says which setting and why.
"""

from __future__ import annotations

import configparser
import ipaddress
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import FrozenSet, Optional, Tuple

DEFAULT_CONFIG_PATH = Path("/var/db/jwicket/jwicket.ini")

BACKENDS = ("netconf", "lab-token")
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
MIN_LAB_TOKEN_LEN = 32
_HOST_RE = re.compile(r"^(?=.{1,253}\Z)[A-Za-z0-9.\-\[\]:]+\Z")


KNOWN_KEYS = {
    "server": frozenset({
        "bind", "port", "tls_cert", "tls_key", "allowed_hosts", "max_connections", "socket_timeout_s",
        "max_body_bytes",
    }),
    "auth": frozenset({
        "backend", "netconf_host", "netconf_port", "rpc_timeout_s", "session_idle_s", "session_absolute_s",
        "max_sessions", "max_sessions_per_user", "login_failures_per_user_per_min", "login_failures_per_source_per_min",
        "login_concurrent", "lab_token_file",
    }),
    "log": frozenset({"level", "file", "audit_file", "max_bytes", "backups"}),
}


class ConfigError(Exception):
    """Startup configuration is unsafe or unusable. The message names the setting."""


@dataclass(frozen=True)
class ServerSettings:
    bind: str = "127.0.0.1"
    port: int = 8443
    tls_cert: Optional[Path] = None
    tls_key: Optional[Path] = None
    allowed_hosts: Tuple[str, ...] = ()
    max_connections: int = 8
    socket_timeout_s: float = 10.0
    max_body_bytes: int = 8192

    @property
    def tls_enabled(self) -> bool:
        return self.tls_cert is not None and self.tls_key is not None

    @property
    def loopback(self) -> bool:
        return ipaddress.ip_address(self.bind).is_loopback


@dataclass(frozen=True)
class AuthSettings:
    backend: str = "netconf"
    netconf_host: str = "127.0.0.1"
    netconf_port: int = 830
    rpc_timeout_s: int = 30
    session_idle_s: int = 900
    session_absolute_s: int = 28800
    max_sessions: int = 4
    # Sessions one Junos user may hold at once; a new sign-in closes that user's oldest (netconf only).
    max_sessions_per_user: int = 2
    # Failed sign-ins per minute for one user name from one source address.
    login_failures_per_user_per_min: int = 5
    # Failed sign-ins per minute from one source address over all user names (behind the SSH tunnel
    # every client is 127.0.0.1, so for tunnel users this is a daemon-wide budget). Successful
    # sign-ins and requests that never reach Junos do not count.
    login_failures_per_source_per_min: int = 20
    # Sign-ins the backend checks at once; more at the same moment get 429.
    login_concurrent: int = 2
    lab_token_file: Optional[Path] = None


@dataclass(frozen=True)
class LogSettings:
    level: str = "INFO"
    file: Optional[Path] = None
    audit_file: Optional[Path] = None
    max_bytes: int = 1_000_000
    backups: int = 3


@dataclass(frozen=True)
class Settings:
    server: ServerSettings
    auth: AuthSettings
    log: LogSettings
    source: Optional[Path] = None


# --- file trust ---------------------------------------------------------------------------------

MAX_SYMLINK_HOPS = 40


def _trusted_uids() -> FrozenSet[int]:
    """Accounts that may own a settings, token or TLS file and every directory above it."""
    return frozenset({0, os.geteuid()})


def _check_file_stat(st: os.stat_result, path: Path, *, label: str, secret: bool) -> None:
    if stat.S_ISLNK(st.st_mode):
        raise ConfigError(f"{label} {path} is a symbolic link; point the setting at the real file")
    if not stat.S_ISREG(st.st_mode):
        raise ConfigError(f"{label} {path} is not a regular file")
    if st.st_uid not in _trusted_uids():
        raise ConfigError(
            f"{label} {path} is owned by uid {st.st_uid}; it must belong to the account J-Wicket "
            f"runs as (uid {os.geteuid()}) or to root"
        )
    mode = stat.S_IMODE(st.st_mode)
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ConfigError(f"{label} {path} is writable by other accounts (mode {mode:o}); use 0600 or 0644")
    if secret and mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigError(f"{label} {path} must be mode 0600, found {mode:o}")


def _check_directory_stat(st: os.stat_result, directory: Path, label: str) -> None:
    if st.st_uid not in _trusted_uids():
        raise ConfigError(
            f"directory {directory} above {label} is owned by uid {st.st_uid}; every directory above it "
            f"must belong to root or to the account J-Wicket runs as (uid {os.geteuid()})"
        )
    mode = stat.S_IMODE(st.st_mode)
    if mode & (stat.S_IWGRP | stat.S_IWOTH) and not mode & stat.S_ISVTX:
        raise ConfigError(f"directory {directory} above {label} is writable by other accounts (mode {mode:o})")


def check_directories(path: Path, *, label: str) -> None:
    """Every directory above ``path`` must be one that no other account can rearrange.

    The directories are walked from ``/`` with ``lstat``, resolving symbolic links as the kernel
    would: each directory must belong to root or to the daemon's account and must not be writable
    by group or other unless it is sticky (like /tmp, where only an entry's owner may rename it); a
    symbolic link on the way is followed only if root owns it. Under these rules nobody else can
    swap a name between a check and a later open, so path-based checks hold for the settings file,
    the lab token and the TLS files, which ``ssl`` loads by path.
    """
    # Not os.path.abspath: it removes "x/.." as text, while the kernel resolves x first.
    absolute = path if path.is_absolute() else Path.cwd() / path
    pending = list(absolute.parent.parts[1:])
    current = Path("/")
    hops = 0

    def lstat_of(target: Path) -> os.stat_result:
        try:
            return os.lstat(target)
        except OSError as exc:
            raise ConfigError(f"directory {target} above {label} cannot be read: {exc.strerror or exc}") from exc

    _check_directory_stat(lstat_of(current), current, label)
    while pending:
        part = pending.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            current = current.parent
            continue
        candidate = current / part
        st = lstat_of(candidate)
        if stat.S_ISLNK(st.st_mode):
            if st.st_uid != 0:
                raise ConfigError(
                    f"{candidate} above {label} is a symbolic link owned by uid {st.st_uid}; only a link "
                    "owned by root is followed"
                )
            hops += 1
            if hops > MAX_SYMLINK_HOPS:
                raise ConfigError(f"too many symbolic links above {label} {path}")
            try:
                link = candidate.readlink()
            except OSError as exc:
                raise ConfigError(f"{candidate} above {label} cannot be read: {exc.strerror or exc}") from exc
            if link.is_absolute():
                current = Path("/")
                pending = list(link.parts[1:]) + pending
            else:
                pending = list(link.parts) + pending
            continue
        if not stat.S_ISDIR(st.st_mode):
            raise ConfigError(f"{candidate} above {label} {path} is not a directory")
        _check_directory_stat(st, candidate, label)
        current = candidate


def check_trusted_file(path: Path, *, label: str, secret: bool) -> None:
    """Refuse files another local account could have written (or, for secrets, read).

    Rules: a regular file, not a symlink, owned by this process's user or root, not writable by
    group or other, and for secrets not readable by group or other; and every directory above it
    passes :func:`check_directories`.
    """
    check_directories(path, label=label)
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise ConfigError(f"{label} {path} cannot be read: {exc.strerror or exc}") from exc
    _check_file_stat(st, path, label=label, secret=secret)


def read_trusted_text(path: Path, *, label: str, secret: bool) -> str:
    """Open first, then check the opened file itself (``fstat``), so the checked file is the file
    that is read; then require the name to still lead to that same file (device and inode).

    Directories are checked before the file, as in :func:`check_trusted_file`, so both report the
    outermost problem: a file below a directory another account owns cannot be trusted whatever
    its own owner and mode. Every check still runs before anything is read.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ConfigError(f"{label} {path} cannot be opened: {exc.strerror or exc}") from exc
    try:
        st = os.fstat(fd)
        check_directories(path, label=label)
        _check_file_stat(st, path, label=label, secret=secret)
        try:
            now = os.lstat(path)
        except OSError as exc:
            raise ConfigError(f"{label} {path} changed while it was being read") from exc
        if (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino):
            raise ConfigError(f"{label} {path} changed while it was being read")
        with os.fdopen(os.dup(fd), "r", encoding="utf-8") as handle:
            return handle.read(1_000_000)
    finally:
        os.close(fd)


# --- parsing ------------------------------------------------------------------------------------


def _get_int(sec: configparser.SectionProxy, key: str, default: int, lo: int, hi: int) -> int:
    raw = sec.get(key)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw.strip())
    except ValueError as exc:
        raise ConfigError(f"[{sec.name}] {key} = {raw!r} is not a whole number") from exc
    if not lo <= value <= hi:
        raise ConfigError(f"[{sec.name}] {key} = {value} is outside {lo}..{hi}")
    return value


def _get_path(sec: configparser.SectionProxy, key: str) -> Optional[Path]:
    raw = (sec.get(key) or "").strip()
    if not raw:
        return None
    path = Path(raw)
    if not path.is_absolute():
        raise ConfigError(f"[{sec.name}] {key} = {raw!r} must be an absolute path")
    return path


def _get_choice(sec: configparser.SectionProxy, key: str, default: str, choices: Tuple[str, ...]) -> str:
    raw = (sec.get(key) or default).strip()
    if raw not in choices:
        raise ConfigError(f"[{sec.name}] {key} = {raw!r} must be one of: {', '.join(choices)}")
    return raw


def _get_ip(sec: configparser.SectionProxy, key: str, default: str) -> str:
    raw = (sec.get(key) or default).strip()
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError as exc:
        raise ConfigError(f"[{sec.name}] {key} = {raw!r} must be an IP address, not a host name") from exc


def parse_settings(text: str, source: Optional[Path] = None) -> Settings:
    cp = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=(";", "#"))
    try:
        cp.read_string(text, source=str(source) if source else "<settings>")
    except configparser.Error as exc:
        raise ConfigError(f"settings file {source or ''} is not valid INI: {exc}") from exc
    unknown = set(cp.sections()) - set(KNOWN_KEYS)
    if unknown:
        raise ConfigError(f"unknown settings section(s): {', '.join(sorted(unknown))}")
    for name, keys in KNOWN_KEYS.items():
        if not cp.has_section(name):
            cp.add_section(name)
        # A misspelt key would otherwise fall back to its default without a word.
        stray = sorted(set(cp[name]) - keys)
        if stray:
            raise ConfigError(f"unknown setting(s) in [{name}]: {', '.join(stray)}")

    s = cp["server"]
    hosts = tuple(h.strip() for h in (s.get("allowed_hosts") or "").split(",") if h.strip())
    for host in hosts:
        if not _HOST_RE.match(host):
            raise ConfigError(f"[server] allowed_hosts entry {host!r} is not a host name or address")
    server = ServerSettings(
        bind=_get_ip(s, "bind", "127.0.0.1"),
        port=_get_int(s, "port", 8443, 1024, 65535),
        tls_cert=_get_path(s, "tls_cert"),
        tls_key=_get_path(s, "tls_key"),
        allowed_hosts=hosts,
        max_connections=_get_int(s, "max_connections", 8, 2, 64),
        socket_timeout_s=float(_get_int(s, "socket_timeout_s", 10, 2, 60)),
        max_body_bytes=_get_int(s, "max_body_bytes", 8192, 1024, 65536),
    )

    a = cp["auth"]
    auth = AuthSettings(
        backend=_get_choice(a, "backend", "netconf", BACKENDS),
        netconf_host=_get_ip(a, "netconf_host", "127.0.0.1"),
        netconf_port=_get_int(a, "netconf_port", 830, 1, 1023),
        rpc_timeout_s=_get_int(a, "rpc_timeout_s", 30, 5, 300),
        session_idle_s=_get_int(a, "session_idle_s", 900, 60, 3600),
        session_absolute_s=_get_int(a, "session_absolute_s", 28800, 600, 86400),
        max_sessions=_get_int(a, "max_sessions", 4, 1, 16),
        max_sessions_per_user=_get_int(a, "max_sessions_per_user", 2, 1, 16),
        login_failures_per_user_per_min=_get_int(a, "login_failures_per_user_per_min", 5, 1, 60),
        login_failures_per_source_per_min=_get_int(a, "login_failures_per_source_per_min", 20, 1, 600),
        login_concurrent=_get_int(a, "login_concurrent", 2, 1, 8),
        lab_token_file=_get_path(a, "lab_token_file"),
    )

    lg = cp["log"]
    log = LogSettings(
        level=_get_choice(lg, "level", "INFO", LOG_LEVELS),
        file=_get_path(lg, "file"),
        audit_file=_get_path(lg, "audit_file"),
        max_bytes=_get_int(lg, "max_bytes", 1_000_000, 10_000, 50_000_000),
        backups=_get_int(lg, "backups", 3, 1, 20),
    )

    settings = Settings(server=server, auth=auth, log=log, source=source)
    validate(settings)
    return settings


def validate(settings: Settings) -> None:
    """Cross-setting rules. Each one closes a door the spike left open."""
    srv, auth = settings.server, settings.auth
    if (srv.tls_cert is None) != (srv.tls_key is None):
        raise ConfigError("[server] tls_cert and tls_key must be set together")
    if not srv.loopback and not srv.tls_enabled:
        raise ConfigError(
            f"[server] bind = {srv.bind} is not a loopback address, so TLS is required: set tls_cert and "
            "tls_key, or bind to 127.0.0.1 and reach J-Wicket through an SSH tunnel"
        )
    if auth.session_idle_s > auth.session_absolute_s:
        raise ConfigError("[auth] session_idle_s cannot be longer than session_absolute_s")
    if auth.backend == "netconf" and not ipaddress.ip_address(auth.netconf_host).is_loopback:
        raise ConfigError(
            "[auth] netconf_host must be a loopback address: J-Wicket manages only the device it runs on"
        )
    if auth.backend == "lab-token":
        if not srv.loopback:
            raise ConfigError(
                "[auth] backend = lab-token is allowed only with a loopback bind: a shared token cannot "
                "tell people apart, so it must never face a network"
            )
        if auth.lab_token_file is None:
            raise ConfigError("[auth] backend = lab-token needs lab_token_file")


def load_settings(path: Path = DEFAULT_CONFIG_PATH) -> Settings:
    text = read_trusted_text(path, label="settings file", secret=False)
    return parse_settings(text, source=path)


def load_lab_token(path: Path) -> bytes:
    token = read_trusted_text(path, label="lab token file", secret=True).strip()
    if len(token) < MIN_LAB_TOKEN_LEN:
        raise ConfigError(f"lab token in {path} is shorter than {MIN_LAB_TOKEN_LEN} characters")
    try:
        return token.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ConfigError(f"lab token in {path} must be ASCII") from exc


def check_tls_files(server: ServerSettings) -> None:
    if server.tls_cert is not None:
        check_trusted_file(server.tls_cert, label="TLS certificate", secret=False)
    if server.tls_key is not None:
        check_trusted_file(server.tls_key, label="TLS private key", secret=True)
