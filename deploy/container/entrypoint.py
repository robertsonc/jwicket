#!/usr/bin/env python3
"""Entry point of the ``jwicket-install`` container image (Spec 006 section 6.4, method M3). LAB ONLY.

The image wraps the workstation installer (M1) unchanged. This file only checks the container's own
set-up, then replaces itself with the installer (``os.execve``), passing every argument through:

* It refuses to run as uid 0. The image's default user is 10001; ``README.md`` runs it with
  ``--user "$(id -u):$(id -g)"`` so the state directory and the SSH agent socket belong to the caller.
* It refuses ``open`` (unless with ``-h``/``--help``). ``open`` forwards nothing (Spec 006 revision R3):
  it names the way in and, with ``--access tls``, checks it with C8's pinned HTTPS read, which from here
  would test the container's network, not the path from the caller's browser. With ``--access tls``
  (the installer's default) the browser goes to ``https://<listen address>:<port>/``. With
  ``--access tunnel`` the ``ssh -L`` line the installer prints runs on the workstation, and SSH
  forwarding was refused on a lab SRX4100 running 25.2R1-S1.4 (verified,
  docs/evidence/2026-11-24-srx4100-lab).
* Every other command that contacts a device or downloads (``install``, ``uninstall``, ``status``,
  ``render``, ``fetch``; dry runs included, because the installer keeps a run directory with the pinned
  SSH configuration and a downloaded bundle in its state directory, and the image's own ``/state``
  belongs to uid 10001, not to the caller), and any option that writes (``--apply``,
  ``--rollback-now``, ``--device-diff``, ``--accept-new-host-key``, or any abbreviation of one that
  argparse would accept, even with ``--help``), is refused unless ``/state`` is a mount point, read
  from ``/proc/self/mountinfo``, that outlives the container: not read-only, not ``tmpfs`` or
  ``ramfs``, not an anonymous volume (which ``--rm`` deletes), and a directory owned by this process's
  uid that no group or other user can write. So the receipt, the journal, the evidence directory and
  the private known-hosts file survive ``--rm``. Only ``bootstrap`` (it prints paste units and writes
  nothing), ``-h``/``--help`` and ``--version`` without such an option, and no command at all, run
  without the mount.
* It sets ``JWICKET_INSTALL_STATE_DIR=/state`` for the installer, overriding any value given with
  ``-e``, so the installer keeps its state in the directory checked here.

Every other argument reaches the installer unchanged, the access and hardware options among them
(``--access``, ``--listen-address``, ``--daemon-port``, ``--lab-hardware``): none of them writes on its own,
and with ``--apply`` the guard above applies. The installer asks for the host name, and after
``--lab-hardware`` for 'lab only', on the terminal ``docker run -it`` gives it. With ``--access tls`` it
makes the device's TLS key in memory and copies it to the device without writing it to ``/state`` or
anywhere else here (Spec 006 section 8.10; the installer's rule, not this file's), and its check C8 is an
HTTPS read from this container to the listen address.

What this rests on: the ``/proc/self/mountinfo`` format is the Linux kernel's (proc(5): fields 5 and 6
are the mount point and the per-mount options, ``-`` ends the optional fields, the filesystem type
follows it, and space, tab, newline and backslash are escaped as three-digit octal). That a bind
mount made with ``docker run -v`` appears there with its container path as the mount point is
**inferred** Linux and Docker behaviour, not tested here (there is no Docker daemon in the
environment this was written in). Recognising an anonymous volume by a mount root ending in
``/volumes/<64 hex>/_data`` is **inferred** from where Docker's and Podman's local volume drivers
keep volumes. None of it has run against a device: every device step of the installer is unverified
until lab test Q-INST-06.

Standard library only; no network; diagnostics go to standard error through ``logging``. Exit status:
2 (Spec 006 section 9.7, "bad arguments or inputs") when this file refuses; otherwise whatever the
installer returns, because the process becomes the installer.
"""

from __future__ import annotations

import logging
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple

LOG = logging.getLogger("jwicket.container")

# --- configuration (paths are the image's, set in the Dockerfile) --------------------------------

STATE_DIR = "/state"
STATE_ENV = "JWICKET_INSTALL_STATE_DIR"
MOUNTINFO = "/proc/self/mountinfo"
MAX_MOUNTINFO_BYTES = 4 * 1024 * 1024
KNOWN_HOSTS = "/home/app/.ssh/known_hosts"
# The installer's console script, run with the virtual environment's interpreter in isolated mode
# (-I: no PYTHON* variables, no user site directory, neither the script's nor the current directory
# on sys.path).
INSTALLER_ARGV: Tuple[str, ...] = (
    "/opt/jwicket-install/bin/python",
    "-I",
    "/opt/jwicket-install/bin/jwicket-install",
)
# Options that change the device or write to the state directory (Spec 006 sections 7.10, 8.3, 8.8
# and 8.10). A run with none of them is a dry run.
GUARDED_OPTIONS: Tuple[str, ...] = ("--apply", "--rollback-now", "--device-diff", "--accept-new-host-key")
# Commands that run without the /state mount: bootstrap prints paste units and touches no state. Every
# other command, a misspelt one included, needs it (refusing too often is safe).
STATELESS_COMMANDS: FrozenSet[str] = frozenset({"bootstrap"})
# Commands that cannot work from inside the container, with the reason and the way that does.
UNAVAILABLE_COMMANDS: Mapping[str, str] = {
    "open": (
        "it forwards nothing, and its check of the way in would test this container's network, not the path "
        "from your browser. With --access tls (the default) browse to https://<listen address>:<port>/ "
        "and compare the certificate's SHA-256 fingerprint the install printed. With --access tunnel, run the "
        "'ssh -L 127.0.0.1:<port>:127.0.0.1:<port> <account>@<device>' line the install printed on the "
        "workstation itself (SSH forwarding was refused on a lab SRX4100 running 25.2R1-S1.4)"
    ),
}
# Exact spellings only: an abbreviation is not taken as a request for help.
HELP_OPTIONS: FrozenSet[str] = frozenset({"-h", "--help", "--version"})
# Filesystems whose contents are gone when the container stops.
MEMORY_FS_TYPES: FrozenSet[str] = frozenset({"tmpfs", "ramfs"})
# Where Docker's and Podman's local volume drivers keep an anonymous volume (inferred, see above).
ANONYMOUS_VOLUME_ROOT = re.compile(r"/volumes/[0-9a-f]{64}/_data\Z")
EXIT_REFUSED = 2

STATE_HINT = (
    'create the directory on the host first (install -d -m 0700 "$HOME/.local/state/jwicket-install"), '
    'then add -v "$HOME/.local/state/jwicket-install:/state" --user "$(id -u):$(id -g)" to docker run'
)

_OCTAL_ESCAPE = re.compile(r"\\([0-7]{3})")

Execve = Callable[[str, Sequence[str], Mapping[str, str]], object]


def _execve(path: str, args: Sequence[str], env: Mapping[str, str]) -> object:
    """``os.execve``: replaces this process and returns only by raising ``OSError``."""
    os.execve(path, list(args), dict(env))  # noqa: S606 - a fixed absolute path and an argument list, no shell


class MountinfoError(Exception):
    """``/proc/self/mountinfo`` could not be read or has a line this parser does not understand."""


@dataclass(frozen=True)
class Mount:
    """One line of ``/proc/self/mountinfo`` (proc(5)); the fields this file uses, unescaped."""

    root: str  # field 4: the directory of the source filesystem that is mounted
    mount_point: str  # field 5: relative to this process's root directory
    options: FrozenSet[str]  # field 6: per-mount options, e.g. {"rw", "relatime"}
    fs_type: str  # the first field after the "-" separator


def unescape(field: str) -> str:
    """Undo the kernel's three-digit octal escapes (space is ``\\040``, backslash ``\\134``)."""
    return _OCTAL_ESCAPE.sub(lambda m: chr(int(m.group(1), 8)), field)


def parse_mountinfo(text: str) -> List[Mount]:
    """Every mount in ``text``, in file order. Any line that does not have the proc(5) shape is an error."""
    mounts: List[Mount] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line:
            continue
        fields = line.split(" ")
        try:
            separator = fields.index("-", 6)
        except ValueError:
            raise MountinfoError(f"line {number} has no '-' separator after the optional fields") from None
        if separator + 1 >= len(fields) or not fields[separator + 1]:
            raise MountinfoError(f"line {number} has no filesystem type after the '-' separator")
        root, mount_point, options = fields[3], fields[4], fields[5]
        # The root is not always a path (an nsfs mount's is "net:[4026531840]"); the mount point is.
        if not root or not mount_point.startswith("/") or not options:
            raise MountinfoError(f"line {number} does not have a root, a mount point and mount options")
        mounts.append(
            Mount(unescape(root), unescape(mount_point), frozenset(options.split(",")), fields[separator + 1])
        )
    return mounts


def read_mountinfo(path: str = MOUNTINFO) -> List[Mount]:
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(MAX_MOUNTINFO_BYTES + 1)
    except OSError as exc:
        raise MountinfoError(f"cannot read {path}: {exc.strerror or exc}") from exc
    if len(data) > MAX_MOUNTINFO_BYTES:
        raise MountinfoError(f"{path} is larger than {MAX_MOUNTINFO_BYTES} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MountinfoError(f"{path} is not UTF-8 text: {exc}") from exc
    return parse_mountinfo(text)


def guarded_options(argv: Sequence[str]) -> List[str]:
    """The guarded options ``argv`` asks for, by full name.

    argparse accepts an unambiguous prefix of a long option (``--app`` for ``--apply``) unless
    ``allow_abbrev`` is off, and the ``--option=value`` form. The installer turns abbreviations off, but
    this guard does not rely on it: an argument counts when its name is a prefix of a guarded option.
    Every argument is looked at, including those after ``--``: refusing too often is safe, too rarely is
    not.
    """
    found = set()
    for arg in argv:
        if not arg.startswith("--") or arg == "--":
            continue
        name = arg.split("=", 1)[0]
        for option in GUARDED_OPTIONS:
            if option.startswith(name):
                found.add(option)
    return sorted(found)


def command_of(argv: Sequence[str]) -> Optional[str]:
    """The installer subcommand: the first argument that is not an option (the top-level options -h,
    --version and -v take no value)."""
    return next((arg for arg in argv if not arg.startswith("-")), None)


def unavailable(argv: Sequence[str]) -> Optional[str]:
    """Why this run's command cannot work in the container, or ``None``. Help for it is still shown."""
    command = command_of(argv)
    if command is None or command not in UNAVAILABLE_COMMANDS or any(arg in HELP_OPTIONS for arg in argv):
        return None
    return UNAVAILABLE_COMMANDS[command]


def needs_state(argv: Sequence[str]) -> bool:
    """Whether this run must have the /state mount (see the module docstring)."""
    if guarded_options(argv):
        return True
    command = command_of(argv)
    if command is None or command in STATELESS_COMMANDS:
        return False
    return not any(arg in HELP_OPTIONS for arg in argv)


def mount_refusal(mounts: Sequence[Mount], state_dir: str = STATE_DIR) -> Optional[str]:
    """Why ``state_dir`` is not a mount that outlives the container, or ``None`` when it is."""
    on_state = [m for m in mounts if m.mount_point == state_dir]
    if not on_state:
        return f"{state_dir} is not a mount point, so the receipt and the journal would be lost with the container"
    mount = on_state[-1]  # mounts stacked on one path: the last one mounted is the one in use
    if mount.fs_type in MEMORY_FS_TYPES:
        return f"{state_dir} is a {mount.fs_type} mount, whose contents are lost when the container stops"
    if "ro" in mount.options:
        return f"{state_dir} is mounted read-only, so the installer cannot write its receipt and journal there"
    if ANONYMOUS_VOLUME_ROOT.search(mount.root):
        return f"{state_dir} is an anonymous volume, which docker run --rm deletes with the container"
    return None


def directory_refusal(path: str, euid: int) -> Optional[str]:
    """Why ``path`` is not a private directory of ``euid``, or ``None`` when it is."""
    try:
        info = Path(path).lstat()
    except OSError as exc:
        return f"cannot read {path}: {exc.strerror or exc}"
    if not stat.S_ISDIR(info.st_mode):
        return f"{path} is not a directory"
    if info.st_uid != euid:
        return f"{path} belongs to uid {info.st_uid}, not to this process's uid {euid}"
    mode = stat.S_IMODE(info.st_mode)
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        return f"{path} has mode {mode:04o}: group or other users can write it (use 0700)"
    if mode & stat.S_IRWXU != stat.S_IRWXU:
        return f"{path} has mode {mode:04o}: its owner cannot read, write and enter it (use 0700)"
    return None


def state_refusal(state_dir: str, mountinfo_path: str, euid: int) -> Optional[str]:
    try:
        mounts = read_mountinfo(mountinfo_path)
    except MountinfoError as exc:
        return f"cannot tell whether {state_dir} is a mount point: {exc}"
    return mount_refusal(mounts, state_dir) or directory_refusal(state_dir, euid)


def warn_about_inputs(environ: Mapping[str, str], known_hosts: str) -> None:
    """Warnings, not refusals: the installer itself refuses what it cannot verify."""
    if os.path.lexists(known_hosts) and not os.access(known_hosts, os.R_OK):
        LOG.warning(
            "%s is mounted but this uid cannot read it, so every host key will look unknown; "
            'run with --user "$(id -u):$(id -g)"',
            known_hosts,
        )
    sock = environ.get("SSH_AUTH_SOCK")
    if sock:
        try:
            is_socket = stat.S_ISSOCK(Path(sock).stat().st_mode)
        except OSError:
            is_socket = False
        if not is_socket:
            LOG.warning("SSH_AUTH_SOCK=%s is not a socket in the container; mount the agent socket there", sock)


def installer_environment(environ: Mapping[str, str], state_dir: str = STATE_DIR) -> Dict[str, str]:
    """The installer's environment: the caller's, with the state directory forced to the one checked here."""
    env = dict(environ)
    env[STATE_ENV] = state_dir
    return env


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    environ: Optional[Mapping[str, str]] = None,
    euid: Optional[int] = None,
    state_dir: str = STATE_DIR,
    mountinfo_path: str = MOUNTINFO,
    known_hosts: str = KNOWN_HOSTS,
    execve: Execve = _execve,
) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    env = os.environ if environ is None else environ
    uid = os.geteuid() if euid is None else euid
    if uid == 0:
        LOG.error(
            "refusing to run as uid 0: the installer needs no root rights; "
            'run with --user "$(id -u):$(id -g)" (the image default is uid 10001)'
        )
        return EXIT_REFUSED
    why_not = unavailable(args)
    if why_not is not None:
        LOG.error("refusing '%s' in the container: %s", command_of(args), why_not)
        return EXIT_REFUSED
    if needs_state(args):
        reason = state_refusal(state_dir, mountinfo_path, uid)
        if reason is not None:
            what = " ".join(guarded_options(args)) or f"'{command_of(args)}'"
            LOG.error("refusing %s: %s; %s", what, reason, STATE_HINT)
            return EXIT_REFUSED
    warn_about_inputs(env, known_hosts)
    command = [*INSTALLER_ARGV, *args]
    try:
        execve(command[0], command, installer_environment(env, state_dir))
    except OSError as exc:
        LOG.error("cannot start the installer %s: %s", command[0], exc.strerror or exc)
        return EXIT_REFUSED
    return 0  # reached only when execve is a test double


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, stream=sys.stderr, format="jwicket-install container: %(levelname)s: %(message)s"
    )
    sys.exit(main())
