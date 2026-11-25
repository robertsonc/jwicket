"""The shared install plan (Spec 006, sections 5.1 and 7, and the pure rules of section 8).

Standard library only, no I/O, no ``jnpr`` import, Python 3.7-compatible: the on-box op script embeds
this module, and Junos 25.2R1-S1.4 ships Python 3.7.10 (verified on a lab SRX4100,
docs/evidence/2026-11-24-srx4100-lab). So no assignment expressions, positional-only parameters,
``f"{x=}"``, run-time ``typing.Protocol``/``Literal``/``Final``/``TypedDict``, ``functools.cached_property``,
``str.removeprefix``/``removesuffix``, dict union, ``math.prod`` or ``Path.readlink``; a test parses every
installer module with ``feature_version=(3, 7)``. Every Junos statement, CLI command and warning text the
installers use lives here, so no method carries its own copy (principle P1). The installer itself has not
run against a device: every device-facing fact below is labelled verified (a Juniper source, the
2026-11-23 vSRX spike or the 2026-11-24 SRX4100 lab run, "verified on SRX4100"), inferred or unknown, and
every installer step is unverified until lab test Q-INST-06.

Scope cuts and revisions applied (lead engineer): the setup mode (bundle change D1, ``jwicket_setup.py``,
statements S6/S7, the ``setup`` stage, check C1) is deferred, so S6 and S7 are reserved and never planned.
The state directory is never created by the installer (revision R4): a super-user-class account may not
create /var/db/jwicket (verified on SRX4100: 'mkdir' and 'file make-directory' refused), so root does it
once (``STATE_DIR_ROOT_STEP``) and the plan refuses R-STATEDIR until it is there and trusted. Access
(revision R2): ``--access tls`` (default) listens with TLS on the device address the operator reaches;
``--access tunnel`` keeps 127.0.0.1 behind 'ssh -L', which SRX4100 25.2R1-S1.4 refused. No check uses an
SSH channel (R3): C8 is an HTTPS GET pinned to the generated certificate, C9 is retired. Hardware
(R5): R-MODEL refuses anything but vSRX unless ``--lab-hardware``, which adds a typed 'lab only'
attestation. ZTP is documented only (``Method.ZTP`` is refused here). The R-PENDING exception for the
installer's own unconfirmed bootstrap (cut C5) is built as designed and is an owner decision open for veto.

FROZEN PUBLIC API (the INSTALLER and ONBOX packages build on these names; change only with them)
====================================================================================================

Errors: ``PlanError`` (base); ``InputError`` (bad input, exit 2); ``InvariantError`` (a plan that breaks
INV-06 or a statement rule: a defect, never sent); ``PlanBlocked`` (rendering a blocked plan).

Constants: ``PLAN_SCHEMA`` = 2 (the plan JSON; new fields are additive), ``RECEIPT_SCHEMA`` = 3; paths
``JET_DIR``, ``OP_DIR``, ``VAR_DB``, ``SCRIPT_DIRS``, ``STATE_DIR``, ``SETTINGS_PATH``,
``SETTINGS_PREV_PATH``, ``RECEIPT_PATH``, ``LOG_PATH``, ``AUDIT_PATH``, ``LAB_TOKEN_PATH``, ``LAB_CA_PATH``,
``TLS_KEY_PATH``, ``TLS_CERT_PATH``, ``STARTUP_REFUSED_PATH``, ``SELFTEST_RESULT_PATH``,
``PROBE_RESULT_PATH``, ``UNINSTALL_CLI_PATH``; file names ``DAEMON_FILE``, ``STAGING_FILE``, ``BACKUP_FILE``,
``SELFTEST_FILE``, ``PROBE_FILE``, ``DIAGNOSTIC_FILES``, ``JWICKET_JET_FILES``, ``OP_FILE``,
``STATE_DIR_KNOWN_FILES``; ``READ_DIRS`` (the P5 listings) and ``S1_SCRIPT_DIRS``; ``REQUIRED_MODULES`` /
``RECORDED_MODULES`` per backend; ``FEATURES`` (bundle header features the installers understand:
``result-files`` = D2, ``build-line`` = D3); ``BACKENDS``, ``TRANSFERS``, ``ACCESS_MODES`` (``tls``,
``tunnel``), ``DEFAULT_ACCESS``, ``DEFAULT_PORT`` (8443, tunnel), ``DEFAULT_TLS_PORT`` (9443, tls),
``MGMT_INSTANCE`` (``mgmt_junos``), ``MANAGEMENT_INSTANCE_KEY``, ``TLS_KEY_MODE``, ``TLS_CERT_MODE``,
``TLS_KEY_BITS``, ``TLS_CERT_DAYS``, ``TLS_SOURCES``; ``PROVENANCE_KINDS``, ``OVERRIDES`` (with
``LAB_HARDWARE_FLAG``), ``NOT_EVIDENCE_OVERRIDES``; ``VERIEXEC_ENFORCING``; ``CONFIRM_MINUTES_RANGE``,
``BOOTSTRAP_MINUTES_RANGE``, ``CONFIRM_MARGIN_S``; ``TIMEOUTS`` (seconds per call class, SC-17),
``READ_RETRY_BACKOFF_S``; exit codes ``EXIT_OK`` .. ``EXIT_UNINSTALL_INCOMPLETE``.

Texts (one constant each, SC-03/AC-006-10): ``DEVICE_STATUS``, ``POSTURE_WARNING``,
``POSTURE_ALREADY_SET``, ``TLS_POSTURE_WARNING`` and ``TUNNEL_WARNING`` (``ACCESS_POSTURE_WARNING`` maps
each access mode to its id), ``NETCONF_WARNING``, ``ALLOW_URL_WARNING``, ``ROOT_BLAST_RADIUS`` (contains
the marker ``<user>``; use ``root_blast_radius(user)``), ``REMOVE_NETCONF_WARNING``,
``REMOVE_LANGUAGE_WARNING``, ``LAB_GATE_PROMPT`` (never contains a host name), ``DIRECTORY_FALLBACK``
(R-STATEDIR's explanation with the one-time root step; ``<user>`` marker, use ``directory_fallback(user)``),
``STATE_DIR_ROOT_STEP`` (the verified root command; ``state_dir_root_step(user)``), ``STATE_DIR_LEFT``,
``STATE_DIR_ROOT_REMOVE``, ``LAB_HARDWARE_WARNING``, ``LAB_HARDWARE_PROMPT`` and ``LAB_HARDWARE_ANSWER``
(``lab_hardware_matches(typed)``), ``MANAGED_WARNING``, ``COMMIT_SCRIPTS_WARNING``, ``VERIEXEC_WARNING``,
``NOT_EVIDENCE``, ``PLAIN_HTTP_WARNING``, ``GROUP_LAYOUT_WARNING``, ``OFFLINE_STAMP``, ``KEEP_SESSION_OPEN``,
``NOT_REMOVED_BY_TOOL``, ``NETCONF_NOT_CHECKED``, ``TUNNEL_C8_REASON``; ``WARNINGS`` maps each warning id
(the constant's name) to its text; ``warning_text(id, user)``. ``REFUSALS`` maps each refusal code to
``(message, override flag or None)``.

CLI text (render.py composes these; nothing else spells Junos commands): ``CLI_CONFIGURE``,
``CLI_SHOW_COMMIT``, ``CLI_COMPARE``, ``CLI_EXIT``, ``CLI_ROLLBACK_0``, ``cli_commit_confirmed``,
``cli_confirm``, ``cli_load_set``, ``cli_run``, ``cli_file_*``, ``cli_start``, ``cli_ext_status``,
``cli_scp``, ``SHOW_MANAGEMENT_INSTANCE``, ``SHELL_VERIEXEC`` (the spike's fixed command), the shell lines
and ``shell_tls_lines(address)`` (deploy-lab's TLS variant, verified on SRX4100).

Access helpers: ``default_listen_address(host)``, ``canonical_address(text)``, ``host_port(address,
port)``, ``listen_url(address, port)``, ``fingerprint_display(sha256)``.

Enums: ``Layout`` (DIRECT default, GROUP after Q-INST-04); ``Method`` (WORKSTATION, ANSIBLE,
CONTAINER, ONBOX_LOCAL="op", ONBOX_URL="op-url", CLI, ZTP); ``Pending`` (NONE, OWN_BOOTSTRAP, OTHER,
UNREADABLE). ``Minutes`` is ``NewType("Minutes", int)``.

Inputs (frozen dataclasses, validated in ``__post_init__``): ``BundleId`` (``from_header``),
``Provenance``, ``Options`` (no ``use_setup_alias``: cut C1; ``access`` "" resolves to tls, or tunnel with
lab-token; ``listen_address``, required by what listens (``LISTEN_ADDRESS_REQUIRED``); ``port`` 0 means the
access mode's default; properties ``bind_address``, ``tls``), ``DeviceFacts`` (``unknown()``),
``CommitEntry``, ``FileInfo``, ``StatementSet`` (pairs of path key and leaf value; ``""`` for a
presence leaf), ``Receipt`` (schema 3; ``to_json``/``from_json``), ``PriorState`` (``fresh()``;
derived properties ``language``, ``load_scripts_from_flash``, ``configured_python``, ``commit_scripts``,
``outbound_ssh_clients``, ``jwicket_stanzas``, ``jwicket_group_paths``, ``apply_groups``, ``web_ports``,
``rest_ports``, ``fips_configured``, ``mnha_configured``, ``management_instance``).

Outputs: ``StatementSpec`` / ``STATEMENT_TABLE`` (S1..S14; S6/S7 reserved), ``STANZA_KEYS``
(F-SELFTEST, F-PROBE, F-DAEMON, F-OP: whole-stanza removals), ``G-APPLY`` / ``G-GROUP`` (group
layout), ``Statement``, ``FileStep``, ``Check`` / ``CHECKS`` (C1 reserved, C9 retired), ``Stage``,
``Bootstrap``, ``Refusal``, ``InstallPlan`` (``blocked``, ``no_change``, ``routing_instance``,
``lab_hardware``, ``settings_text``, ``url``), ``OwnershipEvidence``, ``KeptStatement``, ``UninstallPlan``
(``state_dir_left``), ``PatchDelta``.

Functions: ``make_statement``, ``stage_lines``, ``build_bootstrap``, ``bootstrap_comment``,
``recognise_bootstrap``, ``own_bootstrap_pending``, ``mark_own_bootstrap``, ``build_install_plan``,
``build_revert_stage``, ``ownership_from_history``, ``build_uninstall_plan``, ``check_invariants``,
``render_settings``, ``settings_sha256``, ``lab_gate_matches``, ``lab_hardware_matches``,
``structural_unexpected``, ``headers_outside``, ``parse_patch``, ``patch_text``, ``apply_lines``,
``expand_groups``, ``statement_key_of``, ``receipt_for_run``, ``confirm_allowed``, ``is_installer_comment``,
``stage_comment``, ``sanitize_display``.

Configuration model: a ``StatementSet`` is a set of ``(path key, value)`` pairs, the path key being
the space-joined tokens of a ``set`` line without its value (``"system scripts language"``,
``"python3"``); presence leaves have the value ``""``; ``apply-groups`` is a leaf-list. The model is
the tests' and the structural check's view of a configuration, not a claim about Junos internals.
"""

from __future__ import annotations

import dataclasses
import datetime
import enum
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, List, Mapping, NewType, Optional, Sequence, Set, Tuple, Union

# ------------------------------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------------------------------

PLAN_SCHEMA = 2  # the plan JSON; fields added since (access, listen address, ...) are additive
RECEIPT_SCHEMA = 3  # 3: the access mode, listener, certificate fingerprint and lab-hardware attestation
INSTALLER_NAME = "jwicket-install"

LOOPBACK = "127.0.0.1"
# Access (revision R2). tls: the daemon listens with TLS on the device address the operator reaches
# (deploy-lab's TLS-on-fxp0 variant, verified on SRX4100 25.2R1-S1.4 on port 9443). tunnel: 127.0.0.1
# behind 'ssh -L', which that SRX4100 refused ('administratively prohibited', verified).
ACCESS_MODES = ("tls", "tunnel")
DEFAULT_ACCESS = "tls"
DEFAULT_PORT = 8443  # --access tunnel (deploy-lab step 3)
DEFAULT_TLS_PORT = 9443  # --access tls: the port the SRX4100 lab run used
DEFAULT_PORTS: Mapping[str, int] = {"tls": DEFAULT_TLS_PORT, "tunnel": DEFAULT_PORT}
NETCONF_LOOPBACK_PORT = 830  # the daemon's own NETCONF session (settings.py default)
# 'system management-instance' (an empty leaf, junos-es 23.2R1 conf-system YANG, verified) puts fxp0 in the
# mgmt_junos routing instance; the daemon then creates its listener there ([server] routing_instance,
# verified on SRX4100: without it 'Can't assign requested address', with it the listener answered).
MGMT_INSTANCE = "mgmt_junos"
MANAGEMENT_INSTANCE_KEY = "system management-instance"

JET_DIR = "/var/db/scripts/jet"
OP_DIR = "/var/db/scripts/op"
VAR_DB = "/var/db"
SCRIPT_DIRS = (
    "/var/db/scripts/commit",
    "/var/db/scripts/event",
    "/var/db/scripts/jet",
    "/var/db/scripts/op",
    "/var/db/scripts/snmp",
)
# The settings path is fixed in the daemon: jwicket.settings.DEFAULT_CONFIG_PATH (a test keeps them equal).
STATE_DIR = "/var/db/jwicket"
SETTINGS_PATH = STATE_DIR + "/jwicket.ini"
SETTINGS_PREV_PATH = SETTINGS_PATH + ".prev"
RECEIPT_PATH = STATE_DIR + "/install-receipt.json"
LOG_PATH = STATE_DIR + "/jwicket.log"
AUDIT_PATH = STATE_DIR + "/audit.jsonl"
LAB_TOKEN_PATH = STATE_DIR + "/lab-token"
LAB_CA_PATH = STATE_DIR + "/lab-ca.pem"
# --access tls: a self-signed certificate the executor makes in memory (the key never touches the
# workstation's disk) and uploads; the daemon trusts only files owned by its account, the key not
# readable by group or other (settings.py check_trusted_file). Mode 0644 on the certificate: it is public.
TLS_KEY_PATH = STATE_DIR + "/tls.key"
TLS_CERT_PATH = STATE_DIR + "/tls.crt"
TLS_KEY_MODE = 0o600
TLS_CERT_MODE = 0o644
TLS_KEY_BITS = 2048  # RSA, as the lab's on-box 'openssl req -newkey rsa:2048' (verified on SRX4100)
TLS_CERT_DAYS = 90  # as the lab run's certificate; a lab certificate, never a provisioning path (Q-TLS-01)
# A recorded pair is renewed (a new pair and fingerprint) once its certificate is this close to its
# notAfter, or past it (SEC-R1): the receipt records notAfter next to the fingerprint.
TLS_RENEW_DAYS = 14
# Where a certificate comes from (FileStep.source of the two TLS files): "in-memory" (a NETCONF executor
# makes it with the cryptography library and uploads it over SCP), "device-openssl" (M6: the operator runs
# deploy-lab's 'openssl req' unit on the device, so the key never leaves it), "op-script" (M4, M4U: the
# operator's own pair, made once in the shell with shell_tls_lines; the on-box script only checks it and
# never writes it; unverified).
TLS_SOURCES = ("in-memory", "device-openssl", "op-script")
STARTUP_REFUSED_PATH = STATE_DIR + "/startup-refused.txt"
SELFTEST_RESULT_PATH = STATE_DIR + "/selftest-result.json"
PROBE_RESULT_PATH = STATE_DIR + "/probe-result.json"
UNINSTALL_CLI_PATH = STATE_DIR + "/uninstall-cli.txt"

DAEMON_FILE = "jwicket.py"
STAGING_FILE = "jwicket-next.py"  # never configured, never started: every transfer lands here (INV-06)
BACKUP_FILE = "jwicket-prev.py"  # upgrade only: the old bytes until the new runtime stage is confirmed
SELFTEST_FILE = "jwicket_selftest.py"
PROBE_FILE = "jwicket_probe.py"
# Equal to the bundle's file-name ALIASES keys (tools/bundle.py); a test keeps them equal.
DIAGNOSTIC_FILES = (SELFTEST_FILE, PROBE_FILE)
JWICKET_JET_FILES = (DAEMON_FILE, SELFTEST_FILE, PROBE_FILE)
OP_FILE = "jwicket-install-op.py"
STAGING_PATH = JET_DIR + "/" + STAGING_FILE
BACKUP_PATH = JET_DIR + "/" + BACKUP_FILE
DAEMON_PATH = JET_DIR + "/" + DAEMON_FILE
OP_PATH = OP_DIR + "/" + OP_FILE

# The only names the uninstaller deletes in STATE_DIR (spec 7.9). setup-result.json belongs to the
# deferred setup mode (D1); it stays a known name so a later bundle's file is not left behind.
STATE_DIR_KNOWN_FILES: Tuple[str, ...] = (
    "jwicket.ini",
    "jwicket.ini.prev",
    "jwicket.log",
    *(f"jwicket.log.{n}" for n in range(1, 21)),
    "audit.jsonl",
    *(f"audit.jsonl.{n}" for n in range(1, 21)),
    "startup-refused.txt",
    "selftest-result.json",
    "probe-result.json",
    "setup-result.json",
    "install-receipt.json",
    "uninstall-cli.txt",
    "lab-token",
    "lab-ca.pem",
    "tls.key",
    "tls.crt",
)

# Directories the preflight lists with file-list detail (spec 8.3), all read only. An unreadable one is
# R-UNREADABLE. /var/db and /var/db/jwicket tell whether the root step of R-STATEDIR has been done.
READ_DIRS: Tuple[str, ...] = (JET_DIR, OP_DIR, VAR_DB, STATE_DIR)
# The other script directories, also listed by every preflight but only for uninstall's S1 rule (spec 7.9:
# a listed *.py there keeps 'language python3'). An absent one is fine; an unreadable one keeps S1 and
# blocks nothing else.
S1_SCRIPT_DIRS: Tuple[str, ...] = tuple(d for d in SCRIPT_DIRS if d not in READ_DIRS)
# Where each kind of script is configured (junos-es 23.2R1 conf YANG, verified): commit, op and snmp under
# 'system scripts'; event scripts under 'event-options event-script', which 'system scripts' does not hold.
SCRIPT_FILE_PATHS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("commit", ("system", "scripts", "commit", "file")),
    ("op", ("system", "scripts", "op", "file")),
    ("event", ("event-options", "event-script", "file")),
    ("snmp", ("system", "scripts", "snmp", "file")),
)

BACKENDS = ("netconf", "lab-token")
TRANSFERS = ("scp", "file-copy", "refresh-from")
# What check C3 requires of the probe (spec 7.6), per backend; --access tls also requires ssl
# (ACCESS_MODULES), which --access tunnel only records. The SRX4100 25.2R1-S1.4 probe reported every one
# of these ok (verified, docs/evidence/2026-11-24-srx4100-lab/probe.json).
REQUIRED_MODULES: Mapping[str, Tuple[str, ...]] = {
    "netconf": ("http.server", "json", "hmac", "threading", "jnpr.junos", "lxml", "ncclient", "paramiko"),
    "lab-token": ("http.server", "json", "hmac", "threading"),
}
ACCESS_MODULES: Mapping[str, Tuple[str, ...]] = {"tls": ("ssl",), "tunnel": ()}
RECORDED_MODULES: Tuple[str, ...] = ("ssl",)
# Bundle header 'features:' the installers understand (spec 10). D1 ("setup") is deferred (cut C1).
FEATURES = ("result-files", "build-line")

PROVENANCE_KINDS = (
    "immutable-release",
    "attestation",
    "release-record",
    "reproduced",
    "operator-hash",
    "release-page-only",
    "none",
)
NO_EVIDENCE_PROVENANCE = ("release-page-only", "none")

# Override flags the plan understands; each is recorded in the receipt (spec 7.10).
LAB_HARDWARE_FLAG = "--lab-hardware"  # revision R5: R-MODEL's override, with the typed 'lab only' attestation
OVERRIDES: FrozenSet[str] = frozenset(
    {
        "--adopt",
        LAB_HARDWARE_FLAG,
        "--ack-managed",
        "--ack-commit-scripts",
        "--veriexec-not-enforcing-ok",
        "--trust-release-page-only",
        "--accept-new-host-key",
        "--accept-unchecked-diagnostics",
        "--allow-plain-http",
        "--no-jet-checksum",
    }
)
NOT_EVIDENCE_OVERRIDES: FrozenSet[str] = frozenset({"--trust-release-page-only", "--veriexec-not-enforcing-ok"})

VERIEXEC_ENFORCING = "loaded active enforce"
CONFIRM_MINUTES_RANGE = (3, 30)
BOOTSTRAP_MINUTES_RANGE = (5, 30)
CONFIRM_MARGIN_S = 60  # every check must pass at least this long before the confirm deadline (INV-04)
MAX_BUNDLE_SIZE = 16 * 1024 * 1024
NONCE_LENGTH = 6
NONCE_ALPHABET = "abcdefghijkmnopqrstuvwxyz0123456789"  # the executor draws NONCE_LENGTH with secrets

# SC-17: a timeout on every call (seconds); reads retried with this back-off, writes never.
TIMEOUTS: Mapping[str, int] = {
    "ssh-connect": 30,
    "netconf-open": 30,
    "rpc": 60,
    "commit": 120,
    "scp": 30,
    "http": 30,
    "health-poll": 90,
    "veriexec-read": 5,
}
READ_RETRY_BACKOFF_S: Tuple[int, ...] = (1, 2, 4)

# Exit codes (spec 9.7), shared by every executor.
EXIT_OK = 0
EXIT_REFUSED = 1  # refused (R-STATEDIR included, before any write), unreadable, or NETCONF off (bootstrap printed)
EXIT_INPUT = 2
EXIT_GATE = 3
EXIT_DEVICE_REFUSED = 4
EXIT_CHECK_FAILED = 5
EXIT_UNEXPECTED_DIFF = 6
EXIT_INTEGRITY = 7
EXIT_UNINSTALL_INCOMPLETE = 8

Minutes = NewType("Minutes", int)

# ------------------------------------------------------------------------------------------------
# Texts. Plain words for an SE new to the tool; each names the Junos command it concerns (ADR 0010).
# ------------------------------------------------------------------------------------------------

DEVICE_STATUS = (
    "This installer has not yet run on any device. Every device step is unverified until lab test "
    "Q-INST-06 is certified."
)

POSTURE_WARNING = (
    "LAB ONLY. This adds 'set system scripts language python3'. That lets any unsigned Python script "
    "owned by a super-user-class account run on this device's routing engine, not only J-Wicket: a "
    "change to the device's security posture. J-Wicket is not qualified for production (gate G1 has "
    "not passed). Continue only on a disposable lab device you are allowed to change."
)

POSTURE_ALREADY_SET = (
    "LAB ONLY. 'set system scripts language python3' is already set on this device; this install "
    "relies on it. It lets any unsigned Python script owned by a super-user-class account run on this "
    "device's routing engine, not only J-Wicket: a change to the device's security posture that "
    "someone made before. J-Wicket is not qualified for production (gate G1 has not passed). Continue "
    "only on a disposable lab device you are allowed to change."
)

TLS_POSTURE_WARNING = (
    "LAB ONLY. With --access tls the runtime commit opens a new HTTPS listener on this device's management "
    "address: the --listen-address, by default --host, which the installer does not check is the management "
    "address (an address of a revenue interface would put the listener there; in the mgmt_junos routing "
    "instance when 'system management-instance' is set). It is reachable by anything that reaches that "
    "address: J-Wicket's sign-in page becomes one more way into this device, beside SSH and NETCONF. Its "
    "certificate is self-signed; compare its SHA-256 fingerprint in the browser with the one the installer "
    "prints. J-Wicket has not passed gate G1 or a security review (Q-SEC-01). Continue only on a lab device "
    "whose management network you control."
)

TUNNEL_WARNING = (
    "With --access tunnel, J-Wicket listens on 127.0.0.1 only and is reached through 'ssh -L', which needs "
    "SSH TCP forwarding on the device. On a lab SRX4100 running Junos 25.2R1-S1.4 the tunnel was refused "
    "('administratively prohibited') and 'set system services ssh tcp-forwarding' is a syntax error there "
    "(verified, docs/evidence/2026-11-24-srx4100-lab). The SRX configuration schema at 23.2R1 marks "
    "tcp-forwarding deprecated and names 'set system services ssh allow-tcp-forwarding'; that statement was "
    "not tried (unverified, Q-NET-03). Health check C8 is not available with this mode. --access tls is the "
    "alternative."
)

NETCONF_WARNING = (
    "This adds 'set system services netconf ssh': NETCONF over SSH on TCP 830 and on the SSH port, "
    "reachable on fxp0 and on any interface whose security zone admits netconf (830) or ssh (22), not "
    "only J-Wicket's loopback session."
)

ALLOW_URL_WARNING = (
    "This adds 'set system scripts op allow-url-for-python': while it is set, any user with the "
    "maintenance permission can run Python op scripts fetched from a URL. The installer removes it "
    "at the end."
)

ROOT_BLAST_RADIUS = (
    "J-Wicket will run with the rights of <user>, a super-user-class account that can commit "
    "configuration ('username <user>' under 'system extensions extension-service application file "
    "jwicket.py'). A compromise of J-Wicket is a compromise of this device."
)

REMOVE_NETCONF_WARNING = (
    "Removing netconf ssh ('delete system services netconf ssh') stops new NETCONF sessions to this device "
    "and may end every open one (unverified, lab test Q-INST-05), including tools that started using it "
    "after J-Wicket was installed."
)

REMOVE_LANGUAGE_WARNING = (
    "Removing 'language python3' ('delete system scripts language') stops every unsigned Python script "
    "on this device from running, not only J-Wicket."
)

LAB_GATE_PROMPT = (
    "This installer is for lab devices only. J-Wicket has not passed gate G1. Type the host name of the "
    "lab device you intend to change (the name set with 'set system host-name'). Typing it confirms "
    "that this device is a disposable lab device you are allowed to change; it does not prove it. "
    "Press Enter to stop: "
)

# Revision R4: the state directory is made once by root, never by the installer. Verified on SRX4100
# 25.2R1-S1.4: a super-user-class account's 'mkdir /var/db/jwicket' and 'file make-directory' were refused
# (Permission denied); root made it and chowned it to the account (verified). The evidence records that,
# not root's command line: this command and its '-m 700' are deploy-lab step 3's, inferred to give mode
# 0700, and R-STATEDIR checks the mode it gave ('drwx------').
STATE_DIR_ROOT_STEP = "mkdir -m 700 " + STATE_DIR + " && chown <user> " + STATE_DIR
# Its counterpart after an uninstall. Removing an entry of /var/db takes the same write permission on
# /var/db as creating one, so the account cannot do it either (inferred from the verified refusal).
STATE_DIR_ROOT_REMOVE = "rmdir " + STATE_DIR  # non-recursive: refuses a directory that is not empty

# R-STATEDIR's explanation, printed with the refusal and quoted in docs/install.md.
DIRECTORY_FALLBACK = (
    "J-Wicket keeps its settings in /var/db/jwicket, and that directory is absent or J-Wicket cannot trust "
    "it: it must be a real directory, not a symbolic link, owned by <user>, mode 700, so that 'file list "
    "/var/db detail' shows 'drwx------' and '<user>'. A super-user-class account cannot create it: on a lab "
    "SRX4100 running Junos 25.2R1-S1.4 both 'mkdir' and 'file make-directory' were refused with 'Permission "
    "denied' (verified). The installer never creates it, never logs in as root and never asks for the root "
    "password, and it writes nothing while the directory is not right. Once, in a shell on the lab device as "
    "root (outside Juniper support; how you become root is your lab's own procedure), run 'mkdir -m 700 "
    "/var/db/jwicket && chown <user> /var/db/jwicket' (docs/deploy-lab.md step 3; root's directory and chown "
    "were verified on that SRX4100, the '-m 700' mode is inferred), "
    "then run the installer "
    "again. If 'file list /var/db detail' lists jwicket as a symbolic link (its permissions start with 'l'), "
    "first remove the link itself, as root, with 'rm /var/db/jwicket' (never 'rm -r'), because chmod and "
    "chown change a link's target. If it is a real directory with another owner or mode, run instead, as "
    "root, 'chmod 700 /var/db/jwicket && chown <user> /var/db/jwicket' (unverified). Moving the settings file "
    "elsewhere is an owner decision, not a lab workaround."
)

STATE_DIR_LEFT = (
    "The uninstaller leaves /var/db/jwicket itself: its account cannot remove an entry of /var/db, as it "
    "could not create one (inferred from the verified refusal). Once 'file list /var/db/jwicket detail' shows "
    "nothing of J-Wicket's, in a shell on the lab device as root: 'rmdir /var/db/jwicket' (it refuses a "
    "directory that is not empty; unverified)."
)

LAB_HARDWARE_WARNING = (
    "--lab-hardware: this device is not a vSRX ('show version' reports its model). J-Wicket has run on one "
    "lab SRX4100 by hand (docs/deploy-lab.md); this installer has run on no hardware, and the hardware "
    "procedure of governance decision D12 is not written: the lab owner decides. The production signs below "
    "are what a production firewall would show. After the host name, the installer asks you to type 'lab "
    "only'."
)

MANAGED_WARNING = (
    "Outbound-SSH clients are configured ('show configuration system services outbound-ssh'), so a "
    "central manager probably manages this device. This change is made on the box, out of band to the "
    "manager, which may report it or overwrite it."
)

COMMIT_SCRIPTS_WARNING = (
    "Commit scripts are configured ('show configuration system scripts commit'). A commit script can "
    "change what is committed; the installer compares the committed result with the plan before each "
    "confirming commit, but a change a script makes only while committing cannot be seen."
)

VERIEXEC_WARNING = (
    "Veriexec is not 'loaded active enforce' on this device, or it could not be read (the shell "
    "command 'sysctl security.mac.veriexec.state' shows it). Results from this device are not "
    "qualification evidence."
)

NOT_EVIDENCE = "not qualification evidence"

PLAIN_HTTP_WARNING = (
    "The device fetches the bundle over plain HTTP ('file copy http://...'), which anyone on the path "
    "can read or change in transit. The SHA-256 check stops changed bytes from being used; it does not "
    "stop them being read. Recorded as the lab owner's consent."
)

GROUP_LAYOUT_WARNING = (
    "Group layout: the statements go into 'groups jwicket', applied with 'set apply-groups jwicket'. "
    "That these hierarchies inherit from a configuration group exactly as direct statements behave is "
    "inferred, not verified (lab test Q-INST-04); a failed inheritance fails the health checks and is "
    "rolled back."
)

OFFLINE_STAMP = (
    "Rendered offline, without reading the device. Before unit 1, check that your CLI prompt shows "
    "<user>@<the lab device you intend>, and do every STOP check ('show system commit', 'show | compare'): "
    "nothing here knows what the device already has."
)

KEEP_SESSION_OPEN = (
    "Keep this CLI session open until the installer reports that it confirmed the bootstrap: whether "
    "closing a CLI session rolls back its pending 'commit confirmed' early is unknown (lab test "
    "Q-INST-03). Do not type 'commit' to confirm it yourself: the installer confirms it only after its "
    "own checks and your typed host name. If you stop here, Junos removes it at its deadline."
)

LAB_HARDWARE_ANSWER = "lab only"
LAB_HARDWARE_PROMPT = (
    "Type 'lab only' to state that this device carries only lab traffic: no production traffic, user or "
    "service depends on it, and its owner approved this run ('show chassis hardware' and 'show configuration "
    "system services outbound-ssh' help you check). Your statement is recorded in the install record; it does "
    "not prove anything. Press Enter to stop: "
)

NETCONF_NOT_CHECKED = (
    "The netconf backend's reach to the device's own NETCONF ('show configuration system services netconf') "
    "rests on the probe (check C3) only: it is not checked end to end, because no check uses an SSH channel "
    "(SSH forwarding was refused on the lab SRX4100). Sign in once to prove it."
)

TUNNEL_C8_REASON = (
    "not available with --access tunnel: no check uses an SSH channel (forwarding was refused on SRX4100 "
    "25.2R1-S1.4)"
)

NOT_REMOVED_BY_TOOL = (
    "Not removed by this tool: lab accounts or login classes created by hand ('system login'), "
    "'system services ssh allow-tcp-forwarding' or 'tcp-forwarding', whichever you added (deploy-lab step 7), "
    "and the device's "
    "rollback history ('show system rollback'), which still holds the old J-Wicket statements."
)

# JFR-05: an offline M6 pull cannot know whether the device has 'system management-instance'.
PULL_INSTANCE_NOTE = (
    "If 'show configuration system management-instance | display inheritance' prints the statement, fxp0 and "
    "its default route are in the mgmt_junos routing instance (verified on SRX4100), and a download from a "
    "server reached through fxp0 is expected to time out from the default instance (inferred): add "
    "'routing-instance mgmt_junos' at the end of the line that names the URL ('file copy' documents the "
    "option, F01; that it routes the download through fxp0 is inferred)."
)

# SEC-R1 and OPX-04: why a rerun does not keep the TLS pair the workstation's record names.
TLS_RENEW_EXPIRY = (
    f"The TLS certificate this installer recorded for this listen address has expired or expires within "
    f"{TLS_RENEW_DAYS} days (its notAfter is in the install record, and 'jwicket-install status' warns about it; the "
    "certificate itself is public: 'file show /var/db/jwicket/tls.crt'). "
    "This run makes and uploads a new pair: the browser will show a new SHA-256 fingerprint, printed below and "
    "recorded."
)
TLS_RENEW_CHANGED = (
    "/var/db/jwicket/tls.crt on the device is not the certificate this workstation recorded ('file checksum "
    "sha-256 /var/db/jwicket/tls.crt' differs or could not be read, or the record names no file SHA-256 or "
    "notAfter). This run makes and "
    "uploads a new pair: the browser will show a new SHA-256 fingerprint, printed below and recorded."
)
# OPX-05: files J-Wicket reads only when it starts, rewritten by a run with no runtime commit.
RESTART_NEEDED = (
    "J-Wicket reads its settings, TLS key and certificate only when it starts, and this run commits no "
    "runtime change: a running J-Wicket keeps the old ones (and serves the old certificate) until it "
    "restarts. Restart it in the shell with 'kill <pid>' ('show extension-service status jwicket.py' shows "
    "the pid; after SIGTERM it restarted by itself on SRX4100, verified, docs/evidence/2026-11-24-srx4100-lab), "
    "then run 'jwicket-install status'. Until then the read checks after this run fail C8."
)

WARNINGS: Mapping[str, str] = {
    "DEVICE_STATUS": DEVICE_STATUS,
    "TLS_RENEW_EXPIRY": TLS_RENEW_EXPIRY,
    "TLS_RENEW_CHANGED": TLS_RENEW_CHANGED,
    "RESTART_NEEDED": RESTART_NEEDED,
    "POSTURE_WARNING": POSTURE_WARNING,
    "POSTURE_ALREADY_SET": POSTURE_ALREADY_SET,
    "TLS_POSTURE_WARNING": TLS_POSTURE_WARNING,
    "TUNNEL_WARNING": TUNNEL_WARNING,
    "NETCONF_WARNING": NETCONF_WARNING,
    "ALLOW_URL_WARNING": ALLOW_URL_WARNING,
    "ROOT_BLAST_RADIUS": ROOT_BLAST_RADIUS,
    "REMOVE_NETCONF_WARNING": REMOVE_NETCONF_WARNING,
    "REMOVE_LANGUAGE_WARNING": REMOVE_LANGUAGE_WARNING,
    "DIRECTORY_FALLBACK": DIRECTORY_FALLBACK,
    "STATE_DIR_LEFT": STATE_DIR_LEFT,
    "LAB_HARDWARE_WARNING": LAB_HARDWARE_WARNING,
    "NETCONF_NOT_CHECKED": NETCONF_NOT_CHECKED,
    "MANAGED_WARNING": MANAGED_WARNING,
    "COMMIT_SCRIPTS_WARNING": COMMIT_SCRIPTS_WARNING,
    "VERIEXEC_WARNING": VERIEXEC_WARNING,
    "PLAIN_HTTP_WARNING": PLAIN_HTTP_WARNING,
    "GROUP_LAYOUT_WARNING": GROUP_LAYOUT_WARNING,
    "OFFLINE_STAMP": OFFLINE_STAMP,
    "KEEP_SESSION_OPEN": KEEP_SESSION_OPEN,
    "NOT_REMOVED_BY_TOOL": NOT_REMOVED_BY_TOOL,
}

USER_MARKER = "<user>"
# The posture warning of each access mode, printed after POSTURE_WARNING or POSTURE_ALREADY_SET.
ACCESS_POSTURE_WARNING: Mapping[str, str] = {"tls": "TLS_POSTURE_WARNING", "tunnel": "TUNNEL_WARNING"}

# Refusals of spec 8.11 (plus R-STATEDIR for revision R4 and R-UNREADABLE for exit 1 "could not be
# read"). code -> (message, override flag or None). Every refusal is decided before any write.
REFUSALS: Mapping[str, Tuple[str, Optional[str]]] = {
    "R-MODEL": (
        "This installer changes vSRX lab devices unless told otherwise. This device does not report a vSRX "
        "product model ('show version'), or it did not answer 'show chassis cluster status' the way an SRX "
        "does. --lab-hardware continues on a physical SRX that carries only lab traffic: after the host name "
        "you then type 'lab only', recorded. It never applies to a device that is not an SRX or did not "
        "answer as one.",
        LAB_HARDWARE_FLAG,
    ),
    "R-NOHOST": (
        "The device reports no host name ('show version' shows none, or not in the expected form). Set "
        "one with 'set system host-name <name>' and commit it, then run the installer again: the lab "
        "gate asks you to type that name.",
        None,
    ),
    "R-ROOT": (
        "J-Wicket must not run as root. Use a super-user-class account that is not root as --user. If "
        "files this account wrote are listed as owned by root ('file list /var/db/scripts/jet detail'), "
        "the account maps to root and cannot be used either.",
        None,
    ),
    "R-CLUSTER": (
        "This device is part of a chassis cluster ('show chassis cluster status'). One commit would start "
        "J-Wicket on both nodes while only this node has the files; cluster installs wait for lab test "
        "Q-HA-01.",
        None,
    ),
    "R-MNHA": (
        "Multinode high availability is configured ('show configuration chassis high-availability'). "
        "Each node commits on its own; installs on such pairs wait for lab test Q-HA-03.",
        None,
    ),
    "R-DUAL-RE": (
        "The device reports two routing engines ('show chassis hardware'), or, on hardware, their number "
        "could not be read. Scripts must be placed on each, and 'set system scripts synchronize' does not "
        "copy JET applications; dual routing engines wait for their own lab test.",
        None,
    ),
    "R-FLASH": (
        "'set system scripts load-scripts-from-flash' is configured. Where Junos then reads JET files "
        "from is not documented, so the installer cannot tell which copy would run.",
        None,
    ),
    "R-LANG": (
        "'system scripts language' is set to a value other than python3 ('show configuration system "
        "scripts'). Changing it would change how every other script on this device runs.",
        None,
    ),
    "R-PENDING": (
        "A commit is pending on this device that is not this installer's own bootstrap: a 'commit "
        "confirmed' waiting for its confirmation, a 'commit at' or a 'commit prepare' ('show system "
        "commit' shows it), or the commit state could not be read. Any commit the installer sent now "
        "would confirm that change too. Wait until it is confirmed or rolled back, then run the "
        "installer again.",
        None,
    ),
    "R-FOREIGN": (
        "A J-Wicket application stanza ('show configuration system extensions extension-service') or a "
        "'groups jwicket' configuration group exists that neither the commit history ('show system "
        "commit') nor this workstation's install record shows this installer added, for example a "
        "manual install from deploy-lab.md. Remove it, or pass --adopt to take it over (recorded).",
        "--adopt",
    ),
    "R-USER": (
        "An existing J-Wicket stanza or file belongs to another account ('username' under 'system "
        "extensions extension-service application file ...', or the owner in 'file list "
        "/var/db/scripts/jet detail'), or a configured J-Wicket file has the wrong mode. Use that "
        "account as --user, or uninstall first.",
        None,
    ),
    "R-PORT": (
        "J-Web ('system services web-management') or the REST API ('system services rest') is configured "
        "on the port J-Wicket would use. Choose another --daemon-port: the installers never change J-Web or "
        "REST.",
        None,
    ),
    "R-FIPS": (
        "'system fips' is configured ('show configuration system fips'). Junos-FIPS mode is not a target "
        "for an unsigned application.",
        None,
    ),
    "R-VERIEXEC": (
        "Veriexec is not 'loaded active enforce' (the shell command 'sysctl security.mac.veriexec.state' "
        "reads it), or it could not be read. --veriexec-not-enforcing-ok continues and stamps the record "
        "'not qualification evidence'.",
        "--veriexec-not-enforcing-ok",
    ),
    "R-MANAGED": (
        "Outbound-SSH clients are configured ('show configuration system services outbound-ssh'), so a "
        "central manager probably manages this device, and a change made on the box is out of band to "
        "it. --ack-managed continues (recorded).",
        "--ack-managed",
    ),
    "R-COMMIT-SCRIPTS": (
        "Commit scripts are configured ('show configuration system scripts commit'), and a commit script "
        "can change what is committed. --ack-commit-scripts continues (recorded); the installer still "
        "compares the committed result with the plan before every confirming commit.",
        "--ack-commit-scripts",
    ),
    "R-RELEASE": (
        "'request system scripts refresh-from' checks an HTTPS server's certificate only with 'cert-file', "
        "the documented way to validate it, which exists from Junos 21.2R1; releases without the fix for "
        "CVE-2022-22156 do not validate it. This device runs a release before 21.2R1, or its release could "
        "not be read ('show version'). Use --transfer scp or --transfer file-copy.",
        None,
    ),
    "R-UPGRADE-NOCHECKSUM": (
        "An upgrade without 'checksum sha-256' (--no-jet-checksum) would commit no configuration change, "
        "so it would have no 'commit confirmed' safety net and no restart. Uninstall, then install, "
        "instead.",
        None,
    ),
    "R-PROVENANCE": (
        "No source independent of the release page vouches for this bundle (an attestation, the release "
        "record on main, a local reproduction or a hash you supply). --trust-release-page-only "
        "continues and stamps the record 'not qualification evidence'.",
        "--trust-release-page-only",
    ),
    "R-HOSTKEY": (
        "The device's SSH host key is unknown, or two ports presented different keys. Log in once with "
        "'ssh <user>@<device>' on the same port to record the key, or pass --accept-new-host-key, which "
        "prints the key's SHA-256 fingerprint for you to compare with the lab console.",
        "--accept-new-host-key",
    ),
    "R-BIND": (
        "J-Wicket listens either on 127.0.0.1 behind an SSH tunnel (--access tunnel) or with TLS on one "
        "unicast IPv4 address of this device that the operator reaches (--access tls --listen-address), never "
        "on a wildcard (0.0.0.0), loopback, multicast, link-local, reserved or IPv6 address; the detail names "
        "which one this is ('show interfaces terse' lists the device's addresses). On a lab "
        "SRX4100 with 'system management-instance', a 0.0.0.0 listener received on fxp0 but answered through "
        "the default instance, so browsers timed out (verified). No installer option changes this.",
        None,
    ),
    "R-STATEDIR": (
        "/var/db/jwicket is absent, or J-Wicket cannot trust it ('file list /var/db detail' must show a "
        "directory, not a symbolic link, with 'drwx------' and the daemon's account as owner). The daemon's "
        "account cannot create or repair it, and the installer never does it as root: the one-time root step "
        "is printed below. Nothing was changed.",
        None,
    ),
    "R-UNREADABLE": (
        "A read the plan needs failed or returned an unexpected shape (named below), so the installer "
        "cannot tell what is on the device. Nothing was changed.",
        None,
    ),
    "R-MISMATCH": (
        "A configured J-Wicket file's bytes ('file checksum sha-256') differ from this bundle although its "
        "stanza already pins this bundle's checksum, so something other than this installer changed the "
        "file. The installer never overwrites a configured file outside the commit that changes its "
        "checksum (INV-06). Uninstall, then install.",
        None,
    ),
}

# ------------------------------------------------------------------------------------------------
# CLI and shell text (render.py composes these; spec 6.8 and 7.8)
# ------------------------------------------------------------------------------------------------

CLI_CONFIGURE = "configure exclusive"
CLI_SHOW_COMMIT = "run show system commit | no-more"  # 'run' verified ([run-cmd]); '| no-more' inferred
# What a pending commit looks like in 'show system commit', from Juniper's sample output
# ([show-system-commit], verified): "0   2022-05-06 06:33:42 PDT by root via cli commit confirmed,
# rollback in 10mins" (Rollback Pending) and "commit requested by root via cli at ..." (a 'commit at').
# '<rollback pending>' is only the field's name in the output-fields table, never the text to look for.
PENDING_SIGNS = (
    "the newest entry (0) ends with 'commit confirmed, rollback in <n>mins' (a commit confirmed is waiting) or "
    "the output starts with 'commit requested by' (a pending 'commit at'); Juniper's sample wording, unverified "
    "on 24.4 (Q-INST-01)"
)
CLI_COMPARE = "show | compare | no-more"
CLI_COMPARE_ROLLBACK_1 = "show | compare rollback 1 | no-more"  # documented form (LOAD-02); as C10 inferred
CLI_EXIT = "exit"
CLI_ROLLBACK_0 = "rollback 0"
SHELL_START = "start shell sh"
SHELL_VERIEXEC = "sysctl security.mac.veriexec.state"  # the spike's exact command (verified)
SHELL_EXIT = "exit"
SHOW_NETCONF = "run show configuration system services netconf | no-more"
OP_SHOW_COMMIT = "show system commit | no-more"  # operational mode
# deploy-lab step 0 (unverified command; the setting itself is verified on SRX4100): whether fxp0 is in
# mgmt_junos, for [server] routing_instance. '| display inheritance' shows a value set in a configuration
# group as well (GRP-01, documented), as the executors' inherit="inherit" read does (JFR-10); this
# combination of pipes is inferred.
SHOW_MANAGEMENT_INSTANCE = "show configuration system management-instance | display inheritance | no-more"
# Workstation lines for M6 (the lab token is generated where it is used, as deploy-lab's variant does).
# Created under umask 077 in a subshell, so the token file is 0600 from its first byte (never readable by
# other local users, even briefly); the chmod that follows is only a check. POSIX sh syntax.
WS_TOKEN_CREATE = "(umask 077 && openssl rand -hex 24 > lab-token)"  # noqa: S105 - a command line, not a secret
WS_TOKEN_CHMOD = "chmod 600 lab-token"  # noqa: S105 - a workstation command line, not a secret
WS_TOKEN_REMOVE = "rm lab-token"  # noqa: S105 - a workstation command line, not a secret
WS_SETTINGS_CHMOD = "chmod 600 jwicket.ini"


def cli_commit_confirmed(minutes: int, comment: str) -> str:
    """'commit confirmed N comment "..."'. 'commit confirmed 5', a check, then a confirming commit is the
    lab run's own sequence, and an unconfirmed one rolled back by itself (verified on SRX4100 25.2R1-S1.4);
    combining the minutes with 'comment' is inferred (documented form 'commit confirmed comment')."""
    _check_minutes(minutes, (1, 30), "commit confirmed minutes")
    _check_comment(comment)
    return f'commit confirmed {minutes} comment "{comment}"'


def cli_confirm(comment: str) -> str:
    """The confirming commit with a comment, which also satisfies force-commit-log (24.2R1+, verified)."""
    _check_comment(comment)
    return f'commit comment "{comment}"'


def cli_load_set(filename: str) -> str:
    """'load set <file>' (documented; a relative name loading from the home directory is inferred)."""
    _require(_SET_FILE_RE.match(filename) is not None, f"set file name {filename!r} is not jwicket-<stage>.set")
    return f"load set {filename}"


def cli_run(command: str) -> str:
    return "run " + command


def cli_file_delete(path: str) -> str:
    return "file delete " + _checked_path(path)


def cli_file_show(path: str) -> str:
    return "file show " + _checked_path(path) + " | no-more"


def cli_file_checksum(path: str) -> str:
    return "file checksum sha-256 " + _checked_path(path)  # verified (F05)


def cli_file_list(directory: str) -> str:
    return "file list " + _checked_path(directory) + " detail"  # verified (F10)


def cli_file_change_permission(path: str, mode: int) -> str:
    return f"file change-permission {_checked_path(path)} permission {mode:o}"  # verified for files (F08)


def _instance_tail(routing_instance: Optional[str]) -> str:
    _require(routing_instance in (None, MGMT_INSTANCE), f"a pull's routing instance must be None or {MGMT_INSTANCE}")
    return f" routing-instance {routing_instance}" if routing_instance else ""


def cli_file_copy(source: str, destination: str, routing_instance: Optional[str] = None) -> str:
    """'file copy <source> <destination> [routing-instance mgmt_junos]' (F01, verified syntax; the owner
    after a copy unknown). The routing instance is for a URL source on a management-instance device
    (JFR-05): that it routes the download through fxp0 is inferred."""
    return f"file copy {source} {_checked_path(destination)}{_instance_tail(routing_instance)}"


def cli_refresh_from(
    name: str, url: str, cert_file: Optional[str], routing_instance: Optional[str] = None
) -> str:
    """'request system scripts refresh-from extension-service file <f> url <u> [cert-file <pem>]' (F15,
    verified syntax). Whether it accepts a file name no stanza configures (the staging name) is unknown
    (Q-INST-05): the units say so, and the checksum read afterwards is the control. ``routing_instance``
    (JFR-05): the YANG input has a routing-instance leaf (verified, 23.2R1); its CLI position after the
    URL and its effect are inferred."""
    _require(name == STAGING_FILE, "refresh-from only ever targets the staging name (INV-06)")
    validate_url(url, allow_plain_http=True)
    tail = f" cert-file {_checked_path(cert_file)}" if cert_file else ""
    return (
        f"request system scripts refresh-from extension-service file {name} url {url}{tail}"
        f"{_instance_tail(routing_instance)}"
    )


def cli_start(app: str) -> str:
    _require(app in JWICKET_JET_FILES, f"{app!r} is not a J-Wicket application file")
    # Verified (deploy-lab step 4); on SRX4100 25.2R1-S1.4 it printed the self-test and probe JSON on the
    # CLI (verified). Whether the NETCONF RPC's reply carries that output is unknown (Q-INST-05).
    return "request extension-service start " + app


def cli_ext_status(app: str) -> str:
    _require(app in JWICKET_JET_FILES, f"{app!r} is not a J-Wicket application file")
    return f"show extension-service status {app} | no-more"


def cli_scp(local: str, user: str, remote: str) -> str:
    """OpenSSH legacy protocol copy, as the spike verified ('scp -O'); the device name stays a placeholder."""
    _require(_LOCAL_NAME_RE.match(local) is not None, f"local file {local!r} is not a plain relative name")
    target = remote if _SET_FILE_RE.match(remote) else _checked_path(remote)  # a .set file goes to the home directory
    return f"scp -O {local} {validate_user(user)}@<device>:{target}"


def state_dir_root_step(user: str) -> str:
    """R-STATEDIR's one-time root command, for the validated daemon account (verified on SRX4100)."""
    return STATE_DIR_ROOT_STEP.replace(USER_MARKER, validate_user(user))


def shell_chmod(mode: int, paths: Sequence[str]) -> str:
    return f"chmod {mode:o} " + " ".join(_checked_path(p) for p in paths)


def shell_tls_lines(address: str) -> Tuple[str, ...]:
    """M6 with --access tls: deploy-lab's TLS variant step 1, run in the shell as the daemon account, so the
    private key never leaves the device (verified on SRX4100 25.2R1-S1.4; the shell openssl's version was not
    recorded, Python's ssl reported OpenSSL 1.1.1zb; the shell is outside Juniper support). One command per
    line; the variant's 'chmod a; chmod b' is split in two."""
    ip = canonical_address(address)
    return (
        SHELL_START,
        "cd " + STATE_DIR,
        "umask 077",
        f"openssl req -x509 -newkey rsa:{TLS_KEY_BITS} -nodes -sha256 -days {TLS_CERT_DAYS} -keyout tls.key "
        f"-out tls.crt -subj /CN={ip} -addext subjectAltName=IP:{ip}",
        f"chmod {TLS_KEY_MODE:o} tls.key",
        f"chmod {TLS_CERT_MODE:o} tls.crt",
        "openssl x509 -in tls.crt -noout -fingerprint -sha256",
        SHELL_EXIT,
    )


# ------------------------------------------------------------------------------------------------
# Validation
# ------------------------------------------------------------------------------------------------


class PlanError(Exception):
    """Base class: the plan cannot be built or rendered. The message says what and why."""


class InputError(PlanError):
    """An input failed validation (spec 7.2): exit 2, before anything is rendered."""


class InvariantError(PlanError):
    """A plan breaks INV-06 or a statement rule. A defect in the planner: such a plan is never sent."""


class PlanBlocked(PlanError):
    """A renderer was asked to render a plan that an unoverridden refusal blocks."""


USER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,31}\Z")  # conservative subset; Junos's rule not researched
SHA256_RE = re.compile(r"^[0-9a-f]{64}\Z")
VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+!_-]{0,63}\Z")  # tools/bundle.py _VERSION
SOURCE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/+@-]{0,127}\Z")  # tools/bundle.py _SOURCE_REF
FEATURE_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}\Z")
NONCE_RE = re.compile(r"^[a-z0-9]{6}\Z")
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}\Z")
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}\Z")
JUNOS_VERSION_RE = re.compile(r"^[0-9]{1,2}\.[0-9][A-Za-z0-9.-]{0,40}\Z")
SERIAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,39}\Z")
TOKEN_RE = re.compile(r"^[A-Za-z0-9._:/@+=-]{1,200}\Z")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")  # file and keyed-list names
DATE_TIME_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9]{2}:[0-9]{2}:[0-9]{2}(?: ?[A-Z]{1,5}|Z)?\Z")
TIME_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
FINGERPRINT_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}=?\Z")
# A vSRX product-model string. Fixtures use "vsrx"; the 24.4 string is inferred (Q-INST-01 records it).
VSRX_MODEL_RE = re.compile(r"^vsrx[0-9.]*\Z", re.IGNORECASE)
# A physical SRX product model, as state.py lowercases it ('srx4100' on the lab run's box, 'srx345'); the
# family's naming is inferred. Only such a model can be overridden with --lab-hardware (R-MODEL).
SRX_HARDWARE_MODEL_RE = re.compile(r"^srx[0-9]{3,4}[a-z0-9-]{0,8}\Z")
_COMMENT_RE = re.compile(r"^[A-Za-z0-9 ._:+!-]{1,100}\Z")
_PATH_RE = re.compile(r"^/(?:[A-Za-z0-9._+-]+/)*[A-Za-z0-9._+-]+\Z")
_LOCAL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z")
_SET_FILE_RE = re.compile(r"^jwicket-[a-z-]{1,32}\.set\Z")
_LINE_RE = re.compile(r"^(?:set|delete) [A-Za-z0-9._-]+(?: [A-Za-z0-9._-]+)*\Z")
_URL_RE = re.compile(
    r"^(?P<scheme>https?)://(?P<host>[A-Za-z0-9](?:[A-Za-z0-9.-]{0,252}[A-Za-z0-9])?)(?::(?P<port>[0-9]{1,5}))?"
    r"(?P<path>/[A-Za-z0-9._/+-]{0,400})\Z"
)
_CERT_RE = re.compile(r"^/var/db/jwicket/[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise InputError(message)


def _bad(condition: bool, message: str) -> None:
    if not condition:
        raise InvariantError(message)


def validate_user(user: str) -> str:
    _require(
        isinstance(user, str) and USER_RE.match(user) is not None,
        f"--user {sanitize_display(str(user))!r} is not a Junos account name: use a letter, then up to 31 "
        "letters, digits, dots, underscores or hyphens",
    )
    return user


def validate_sha256(value: str, what: str) -> str:
    _require(
        isinstance(value, str) and SHA256_RE.match(value) is not None,
        f"{what} {sanitize_display(str(value))[:80]!r} is not 64 lowercase hexadecimal characters",
    )
    return value


def validate_url(url: str, *, allow_plain_http: bool) -> str:
    """https (or http only with --allow-plain-http); no user information, query or fragment."""
    _require(isinstance(url, str) and len(url) <= 512, "the URL is longer than 512 characters")
    match = _URL_RE.match(url)
    _require(
        match is not None,
        f"URL {sanitize_display(url)[:120]!r} is not https://host[:port]/path with plain characters "
        "(no user information, no query, no fragment)",
    )
    assert match is not None  # noqa: S101 - narrowed by _require above
    if match.group("scheme") == "http":
        _require(allow_plain_http, "a plain http URL needs --allow-plain-http (recorded as the lab owner's consent)")
    port = match.group("port")
    if port is not None:
        _require(1 <= int(port) <= 65535, f"URL port {port} is outside 1..65535")
    return url


def canonical_address(text: str) -> str:
    """An IPv4 or IPv6 literal written in its canonical form (``ipaddress``'s), else InputError: the address
    is compared with the daemon's start line, the Host header and the certificate's subjectAltName, so
    '192.0.2.010' or an upper-case IPv6 form is refused rather than normalised (and an IPv4 literal with
    leading zeros means different things to different parsers)."""
    _require(
        isinstance(text, str) and 0 < len(text) <= 45 and "%" not in text,
        "--listen-address is not an IP address (no zone index)",
    )
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        raise InputError(
            f"--listen-address {sanitize_display(text)[:60]!r} is not an IP address (a host name is not accepted: "
            "the daemon binds an address, and the certificate names it)"
        ) from None
    _require(
        str(parsed) == text,
        f"--listen-address {sanitize_display(text)[:60]!r}: write it as {parsed} (the canonical form)",
    )
    return text


def default_listen_address(host: Optional[str]) -> Optional[str]:
    """--listen-address's default: --host when it is a canonical IP literal, else None (then it is required)."""
    if not isinstance(host, str):
        return None
    try:
        return canonical_address(host)
    except InputError:
        return None


def host_port(address: str, port: int) -> str:
    """'<address>:<port>' as a browser sends it in the Host header ('[<IPv6>]:<port>'): allowed_hosts."""
    ip = canonical_address(address)
    _check_port(port, 1024, "--daemon-port")
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def listen_url(address: str, port: int) -> str:
    return f"https://{host_port(address, port)}/"


def fingerprint_display(sha256: str) -> str:
    """A certificate's SHA-256 in the colon form browsers and 'openssl x509 -fingerprint' print it."""
    value = validate_sha256(sha256, "certificate SHA-256")
    return ":".join(value[i : i + 2] for i in range(0, 64, 2)).upper()


def _checked_path(path: str) -> str:
    _require(_PATH_RE.match(path) is not None and "/../" not in path + "/", f"path {path!r} is not a plain path")
    return path


def _check_minutes(value: int, bounds: Tuple[int, int], what: str) -> None:
    _require(
        isinstance(value, int) and not isinstance(value, bool) and bounds[0] <= value <= bounds[1],
        f"{what} {value!r} is outside {bounds[0]}..{bounds[1]}",
    )


def _check_comment(comment: str) -> None:
    _require(
        _COMMENT_RE.match(comment) is not None,
        f"commit comment {sanitize_display(comment)[:120]!r} must be 1-100 plain ASCII characters, no quote or "
        "backslash (force-commit-log can require a comment on every commit)",
    )


def _check_port(value: int, lo: int, what: str) -> None:
    _require(
        isinstance(value, int) and not isinstance(value, bool) and lo <= value <= 65535,
        f"{what} {value!r} is outside {lo}..65535",
    )


_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def sanitize_display(text: str, limit: int = 400) -> str:
    """Device or operator text made safe to show: control characters removed, one line, bounded.

    For display only (UI-006-02). The result never becomes a path, a command or a rendered line.
    """
    flat = _CONTROL_RE.sub("", str(text).replace("\n", " ").replace("\r", " ").replace("\t", " "))
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."


# ------------------------------------------------------------------------------------------------
# Enums
# ------------------------------------------------------------------------------------------------


class Layout(enum.Enum):
    DIRECT = "direct"
    GROUP = "group"


class Method(enum.Enum):
    WORKSTATION = "workstation"
    ANSIBLE = "ansible"
    CONTAINER = "container"
    ONBOX_LOCAL = "op"
    ONBOX_URL = "op-url"
    CLI = "cli"
    ZTP = "ztp"  # documented only (cut C3): build_install_plan refuses it


class Pending(enum.Enum):
    NONE = "none"
    OWN_BOOTSTRAP = "own-bootstrap"
    OTHER = "other"
    UNREADABLE = "unreadable"


NETCONF_METHODS = (Method.WORKSTATION, Method.ANSIBLE, Method.CONTAINER)
ONBOX_METHODS = (Method.ONBOX_LOCAL, Method.ONBOX_URL)
# Bootstrap kind per method (spec 7.7): its comment is "jwicket-bootstrap <kind>[ <nonce>]".
BOOTSTRAP_KIND: Mapping[Method, str] = {
    Method.WORKSTATION: "netconf",
    Method.ANSIBLE: "netconf",
    Method.CONTAINER: "netconf",
    Method.ONBOX_LOCAL: "op",
    Method.ONBOX_URL: "op-url",
}

# ------------------------------------------------------------------------------------------------
# The statement set (spec 7.3)
# ------------------------------------------------------------------------------------------------

_EXT: Tuple[str, ...] = ("system", "extensions", "extension-service", "application", "file")
_OPF: Tuple[str, ...] = ("system", "scripts", "op", "file", OP_FILE)

# Leaves whose last token is a value (the model's rule for set lines and patch lines); every other leaf
# is a presence leaf. apply-groups is a leaf-list.
VALUE_LEAVES: FrozenSet[str] = frozenset({"language", "username", "sha-256", "port", "level"})
LEAF_LISTS: FrozenSet[str] = frozenset({"apply-groups"})
GROUP_NAME = "jwicket"
GROUP_PREFIX: Tuple[str, ...] = ("groups", GROUP_NAME)

# Never rendered (spec 7.3): a statement path containing one of these tokens is an invariant failure.
NEVER_RENDERED: FrozenSet[str] = frozenset(
    {
        "optional",
        "arguments",
        "routing-instance",
        "source",
        "refresh",
        "refresh-from",
        "traceoptions",
        "management-instance",
        "login",
        "security",
        "web-management",
        "port",
        "cert-file",
    }
)
RESERVED_KEYS = ("S6", "S7")  # jwicket_setup.py username/checksum: reserved, not used (cut C1)
# The lab run that verified statements S1, S2, S4, S10 to S12 with J-Wicket's own file names (revision R6).
EVIDENCE_SRX4100 = "docs/evidence/2026-11-24-srx4100-lab"
_ON_SRX4100 = "verified on SRX4100 25.2R1-S1.4 (" + EVIDENCE_SRX4100 + ")"


@dataclass(frozen=True)
class StatementSpec:
    """One row of spec 7.3. ``value_kind``: fixed, user, bundle-sha256, op-sha256 or presence."""

    key: str
    path: Tuple[str, ...]
    value_kind: str
    fixed_value: str
    stanza: Optional[str]
    owner_class: str  # "jwicket" or "shared"
    posture: bool
    wide_reach: bool
    status: str


STATEMENT_TABLE: Tuple[StatementSpec, ...] = (
    StatementSpec(
        "S1",
        ("system", "scripts", "language"),
        "fixed",
        "python3",
        None,
        "shared",
        True,
        False,
        "verified (spike); " + _ON_SRX4100,
    ),
    StatementSpec(
        "S2",
        (*_EXT, SELFTEST_FILE, "username"),
        "user",
        "",
        "F-SELFTEST",
        "jwicket",
        False,
        False,
        _ON_SRX4100,
    ),
    StatementSpec(
        "S3",
        (*_EXT, SELFTEST_FILE, "checksum", "sha-256"),
        "bundle-sha256",
        "",
        "F-SELFTEST",
        "jwicket",
        False,
        False,
        "in the SRX schema at 23.2R1 (verified, YANG); enforcement unknown (Q-INST-02)",
    ),
    StatementSpec(
        "S4",
        (*_EXT, PROBE_FILE, "username"),
        "user",
        "",
        "F-PROBE",
        "jwicket",
        False,
        False,
        _ON_SRX4100,
    ),
    StatementSpec(
        "S5",
        (*_EXT, PROBE_FILE, "checksum", "sha-256"),
        "bundle-sha256",
        "",
        "F-PROBE",
        "jwicket",
        False,
        False,
        "in the SRX schema at 23.2R1 (verified, YANG); enforcement unknown (Q-INST-02)",
    ),
    StatementSpec(
        "S8",
        ("system", "services", "netconf", "ssh"),
        "presence",
        "",
        None,
        "shared",
        False,
        True,
        "documented (verified); already configured on the lab SRX4100, whose daemon signed in over it to "
        "127.0.0.1:830 (verified, Q-AUTH-01 partial); never added by a lab run",
    ),
    StatementSpec(
        "S9",
        ("system", "scripts", "op", "allow-url-for-python"),
        "presence",
        "",
        None,
        "shared",
        True,
        False,
        "documented (verified)",
    ),
    StatementSpec(
        "S10",
        (*_EXT, DAEMON_FILE, "daemonize"),
        "presence",
        "",
        "F-DAEMON",
        "jwicket",
        False,
        False,
        "verified (spike); " + _ON_SRX4100,
    ),
    StatementSpec(
        "S11",
        (*_EXT, DAEMON_FILE, "respawn-on-normal-exit"),
        "presence",
        "",
        "F-DAEMON",
        "jwicket",
        False,
        False,
        "verified (spike); " + _ON_SRX4100,
    ),
    StatementSpec(
        "S12",
        (*_EXT, DAEMON_FILE, "username"),
        "user",
        "",
        "F-DAEMON",
        "jwicket",
        False,
        False,
        "verified (spike); " + _ON_SRX4100,
    ),
    StatementSpec(
        "S13",
        (*_EXT, DAEMON_FILE, "checksum", "sha-256"),
        "bundle-sha256",
        "",
        "F-DAEMON",
        "jwicket",
        False,
        False,
        "in the SRX schema at 23.2R1 (verified, YANG); enforcement unknown (Q-INST-02)",
    ),
    StatementSpec(
        "S14",
        (*_OPF, "checksum", "sha-256"),
        "op-sha256",
        "",
        "F-OP",
        "jwicket",
        False,
        False,
        "in the SRX schema at 23.2R1 (verified, YANG: system scripts op file <name> checksum sha-256); 24.4 inferred",
    ),
)
SPEC_BY_KEY: Mapping[str, StatementSpec] = {s.key: s for s in STATEMENT_TABLE}
# Whole-stanza removals (uninstall, revert): "delete system extensions extension-service application file X".
STANZA_KEYS: Mapping[str, Tuple[str, ...]] = {
    "F-SELFTEST": (*_EXT, SELFTEST_FILE),
    "F-PROBE": (*_EXT, PROBE_FILE),
    "F-DAEMON": (*_EXT, DAEMON_FILE),
    "F-OP": _OPF,
}
STANZA_FILE_PATHS: Mapping[str, str] = {
    "F-SELFTEST": JET_DIR + "/" + SELFTEST_FILE,
    "F-PROBE": JET_DIR + "/" + PROBE_FILE,
    "F-DAEMON": DAEMON_PATH,
    "F-OP": OP_PATH,
}
APPLY_KEY = "G-APPLY"  # set apply-groups jwicket (group layout)
GROUP_KEY = "G-GROUP"  # delete groups jwicket (group layout uninstall)
SHARED_KEYS = ("S1", "S8", "S9")
ALL_KEYS: FrozenSet[str] = frozenset({*SPEC_BY_KEY, *STANZA_KEYS, APPLY_KEY, GROUP_KEY})

STAGE_NAMES = ("bootstrap", "diagnostics", "runtime", "netconf-removal", "revert", "uninstall")
INSTALL_STAGE_ORDER = ("bootstrap", "diagnostics", "runtime", "netconf-removal")

# Roots under which each stage's changes may appear, direct layout (path keys). A group-layout stage
# uses the same roots under "groups jwicket" plus "apply-groups". headers_outside() narrows these to the
# stage's own statements; check_invariants() requires every statement to fall under its stage's roots.
_EXTK = " ".join(_EXT)
ALLOWED_DIFF_HEADERS: Mapping[str, Tuple[str, ...]] = {
    "bootstrap": ("system services netconf", "system scripts language", "system scripts op"),
    "diagnostics": (
        "system scripts language",
        "system services netconf",
        f"{_EXTK} {SELFTEST_FILE}",
        f"{_EXTK} {PROBE_FILE}",
    ),
    "runtime": (
        f"{_EXTK} {DAEMON_FILE}",
        f"{_EXTK} {SELFTEST_FILE}",
        f"{_EXTK} {PROBE_FILE}",
        "system scripts op allow-url-for-python",
    ),
    "netconf-removal": ("system services netconf",),
    "revert": (
        "system scripts language",
        "system scripts op",
        "system services netconf",
        f"{_EXTK} {DAEMON_FILE}",
        f"{_EXTK} {SELFTEST_FILE}",
        f"{_EXTK} {PROBE_FILE}",
    ),
    "uninstall": (
        "system scripts language",
        "system scripts op",
        f"{_EXTK} {DAEMON_FILE}",
        f"{_EXTK} {SELFTEST_FILE}",
        f"{_EXTK} {PROBE_FILE}",
    ),
}


@dataclass(frozen=True)
class Statement:
    """One configuration statement of the plan. ``path`` is the direct-layout path without the value.

    ``key`` is S1..S14, a whole-stanza key (F-*), or G-APPLY / G-GROUP. ``value`` is the leaf value
    (validated token) or None for a presence leaf or a stanza.
    """

    key: str
    path: Tuple[str, ...]
    value: Optional[str]
    stage: str
    owner_class: str
    posture: bool

    def form(self, layout: Layout) -> Tuple[str, ...]:
        """The path as it appears in ``layout`` (group statements live under groups jwicket)."""
        if layout is Layout.GROUP and self.key not in (APPLY_KEY, GROUP_KEY):
            return GROUP_PREFIX + self.path
        return self.path

    def path_key(self, layout: Layout = Layout.DIRECT) -> str:
        return " ".join(self.form(layout))

    def pair(self, layout: Layout = Layout.DIRECT) -> Tuple[str, str]:
        return (self.path_key(layout), self.value or "")

    def set_line(self, layout: Layout) -> str:
        _bad(self.key not in STANZA_KEYS and self.key != GROUP_KEY, f"{self.key} is removal-only")
        tail = f" {self.value}" if self.value else ""
        return f"set {self.path_key(layout)}{tail}"

    def delete_line(self, layout: Layout) -> str:
        form = self.form(layout)
        if form and form[-1] in LEAF_LISTS and self.value:
            return f"delete {' '.join(form)} {self.value}"
        return f"delete {' '.join(form)}"


def _value_for(
    spec: StatementSpec, user: Optional[str], bundle_sha: Optional[str], op_sha: Optional[str]
) -> Optional[str]:
    if spec.value_kind == "fixed":
        return spec.fixed_value
    if spec.value_kind == "presence":
        return None
    if spec.value_kind == "user":
        _require(user is not None, f"{spec.key} needs the daemon account")
        return validate_user(str(user))
    if spec.value_kind == "bundle-sha256":
        _require(bundle_sha is not None, f"{spec.key} needs the bundle SHA-256")
        return validate_sha256(str(bundle_sha), "bundle SHA-256")
    _require(op_sha is not None, f"{spec.key} needs the op script SHA-256")
    return validate_sha256(str(op_sha), "op script SHA-256")


def make_statement(
    key: str,
    stage: str,
    *,
    user: Optional[str] = None,
    bundle_sha256: Optional[str] = None,
    op_sha256: Optional[str] = None,
    value: Optional[str] = None,
) -> Statement:
    """Build statement ``key`` from validated tokens only (INV-12). ``value`` overrides the computed value
    (used for removals of a value the device holds; it must be a validated token)."""
    _require(stage in STAGE_NAMES, f"unknown stage {stage!r}")
    if key in STANZA_KEYS:
        return Statement(key, STANZA_KEYS[key], None, stage, "jwicket", False)
    if key == APPLY_KEY:
        return Statement(key, ("apply-groups",), GROUP_NAME, stage, "jwicket", False)
    if key == GROUP_KEY:
        return Statement(key, GROUP_PREFIX, None, stage, "jwicket", False)
    _require(key in SPEC_BY_KEY, f"unknown statement key {key!r} (S6 and S7 are reserved, not used)")
    spec = SPEC_BY_KEY[key]
    if value is not None:
        _require(TOKEN_RE.match(value) is not None and " " not in value, f"{key} value is not a plain token")
        computed: Optional[str] = value
    else:
        computed = _value_for(spec, user, bundle_sha256, op_sha256)
    return Statement(key, spec.path, computed, stage, spec.owner_class, spec.posture)


def statement_key_of(path_key: str) -> Optional[str]:
    """The statement key (S1..S14, G-APPLY) a model path key belongs to, or None for anything else."""
    tokens = tuple(path_key.split(" "))
    if tokens[: len(GROUP_PREFIX)] == GROUP_PREFIX:
        tokens = tokens[len(GROUP_PREFIX) :]
    if tokens == ("apply-groups",):
        return APPLY_KEY
    for spec in STATEMENT_TABLE:
        if tokens == spec.path:
            return spec.key
    return None


# ------------------------------------------------------------------------------------------------
# Inputs
# ------------------------------------------------------------------------------------------------

_HEADER_FIELDS = {
    "jwicket version": "version",
    "source ref": "source_ref",
    "payload sha256": "payload_sha256",
    "features": "features",
}


@dataclass(frozen=True)
class BundleId:
    """The bundle being installed: its file SHA-256 (as in SHA256SUMS), size, and its header's fields."""

    file_sha256: str
    size: int
    version: str
    source_ref: Optional[str]
    payload_sha256: str
    features: FrozenSet[str] = frozenset()

    def __post_init__(self) -> None:
        validate_sha256(self.file_sha256, "bundle file SHA-256")
        validate_sha256(self.payload_sha256, "bundle payload SHA-256")
        _require(
            isinstance(self.size, int) and not isinstance(self.size, bool) and 0 < self.size <= MAX_BUNDLE_SIZE,
            f"bundle size {self.size!r} is outside 1..{MAX_BUNDLE_SIZE} bytes",
        )
        _require(
            VERSION_RE.match(self.version) is not None, f"bundle version {sanitize_display(self.version)!r} is invalid"
        )
        if self.source_ref is not None:
            _require(SOURCE_REF_RE.match(self.source_ref) is not None, "bundle source ref is invalid")
        for feature in self.features:
            _require(FEATURE_RE.match(feature) is not None, f"bundle feature {sanitize_display(feature)!r} is invalid")
        object.__setattr__(self, "features", frozenset(self.features))

    @classmethod
    def from_header(cls, head: str, file_sha256: str, size: int) -> BundleId:
        """Parse the docstring header tools/bundle.py writes (``_header``), with the optional ``features:``
        line of bundle change D3. Only the first 4 KiB are read; a missing or malformed field is an
        InputError naming it."""
        found: Dict[str, str] = {}
        for raw in head[:4096].splitlines()[:40]:
            name, sep, value = raw.partition(":")
            key = _HEADER_FIELDS.get(name.strip())
            if sep and key is not None and key not in found:
                found[key] = value.strip()
        for needed in ("version", "payload_sha256"):
            _require(
                needed in found, f"bundle header has no '{needed.replace('_', ' ')}' line: not a tools/bundle.py bundle"
            )
        source = found.get("source_ref")
        features = frozenset(f.strip() for f in found.get("features", "").split(",") if f.strip())
        return cls(
            file_sha256=file_sha256,
            size=size,
            version=found["version"],
            source_ref=None if source in (None, "", "not recorded") else source,
            payload_sha256=found["payload_sha256"],
            features=features,
        )

    @property
    def short(self) -> str:
        return self.file_sha256[:12]

    @property
    def payload_short(self) -> str:
        return self.payload_sha256[:16]

    def has(self, feature: str) -> bool:
        return feature in self.features


@dataclass(frozen=True)
class Provenance:
    """Which source independent of the release page vouched for the bundle (spec 8.9)."""

    kind: str
    detail: Tuple[str, ...] = ()
    evidence: bool = True

    def __post_init__(self) -> None:
        _require(self.kind in PROVENANCE_KINDS, f"provenance kind {sanitize_display(self.kind)!r} is unknown")
        _require(
            self.evidence == (self.kind not in NO_EVIDENCE_PROVENANCE),
            f"provenance {self.kind} must have evidence={self.kind not in NO_EVIDENCE_PROVENANCE}",
        )
        for item in self.detail:
            _require(
                TOKEN_RE.match(item) is not None, f"provenance detail {sanitize_display(item)[:80]!r} is not a token"
            )
        object.__setattr__(self, "detail", tuple(self.detail))


@dataclass(frozen=True)
class Options:
    """Operator choices (spec 7.2), validated before anything is rendered. No setup alias (cut C1).

    ``access`` (revision R2): ``tls`` listens with TLS on ``listen_address``, which the CLI defaults to
    --host when that is an IP literal (``default_listen_address``) and requires otherwise; ``tunnel``
    listens on 127.0.0.1 and takes no listen address. ``""`` means the default, resolved here: ``tls``, or
    ``tunnel`` with the lab-token backend, which the daemon refuses on a non-loopback bind (an explicit
    ``tls`` with lab-token is an InputError). A listen address is validated whenever it is given; it is
    required by what listens (``build_install_plan``, ``render_settings``, ``bind_address``), not by a
    bootstrap, which never needs one. ``port`` 0 means the access mode's default (``DEFAULT_PORTS``: 9443
    for tls, 8443 for tunnel), resolved here, so ``options.port`` is always the daemon's port.
    """

    user: str
    backend: str = "netconf"
    port: int = 0
    ssh_port: int = 22
    netconf_port: Optional[int] = None
    layout: Layout = Layout.DIRECT
    jet_checksum: bool = True
    confirm_minutes: int = 5
    bootstrap_minutes: int = 10
    transfer: str = "scp"
    pull_url: Optional[str] = None
    cert_file: Optional[str] = None
    allow_plain_http: bool = False
    keep_diagnostics: bool = True
    remove_netconf_after: Optional[bool] = None
    keep_partial: bool = False
    access: str = ""
    listen_address: Optional[str] = None

    def __post_init__(self) -> None:
        validate_user(self.user)
        _require(
            self.backend in BACKENDS, f"--backend {sanitize_display(str(self.backend))!r} must be netconf or lab-token"
        )
        if self.access == "":
            object.__setattr__(self, "access", "tunnel" if self.backend == "lab-token" else DEFAULT_ACCESS)
        _require(self.access in ACCESS_MODES, f"--access {sanitize_display(str(self.access))!r} must be tls or tunnel")
        if self.access == "tls":
            if self.listen_address is not None:
                canonical_address(str(self.listen_address))
            _require(
                self.backend != "lab-token",
                "--backend lab-token needs --access tunnel: the daemon refuses a shared token on a listener "
                "that faces a network (settings.py)",
            )
        else:
            _require(self.listen_address is None, "--listen-address is only for --access tls")
        if isinstance(self.port, int) and not isinstance(self.port, bool) and self.port == 0:
            object.__setattr__(self, "port", DEFAULT_PORTS[self.access])
        _check_port(self.port, 1024, "--daemon-port")
        _check_port(self.ssh_port, 1, "--ssh-port")
        if self.netconf_port is not None:
            _check_port(self.netconf_port, 1, "--netconf-port")
        _require(isinstance(self.layout, Layout), "layout must be a Layout")
        _check_minutes(self.confirm_minutes, CONFIRM_MINUTES_RANGE, "--confirm-minutes")
        _check_minutes(self.bootstrap_minutes, BOOTSTRAP_MINUTES_RANGE, "--bootstrap-minutes")
        for name in ("jet_checksum", "allow_plain_http", "keep_diagnostics", "keep_partial"):
            _require(isinstance(getattr(self, name), bool), f"{name} must be true or false")
        _require(
            self.transfer in TRANSFERS,
            f"--transfer {sanitize_display(str(self.transfer))!r} must be one of {', '.join(TRANSFERS)}",
        )
        if self.transfer == "scp":
            _require(self.pull_url is None, "--url is only for --transfer file-copy or refresh-from")
        else:
            _require(self.pull_url is not None, f"--transfer {self.transfer} needs --url")
            validate_url(str(self.pull_url), allow_plain_http=self.allow_plain_http)
        if self.cert_file is not None:
            _require(
                _CERT_RE.match(self.cert_file) is not None and ".." not in self.cert_file,
                "--cert-file must be a plain file name under /var/db/jwicket/",
            )
        if self.transfer == "refresh-from" and str(self.pull_url).startswith("https://"):
            _require(self.cert_file is not None, "--transfer refresh-from over https needs --cert-file (verified)")
        if self.remove_netconf_after is True:
            _require(
                self.backend == "lab-token",
                "the netconf backend needs NETCONF: --remove-netconf-after is lab-token only",
            )

    @property
    def remove_netconf(self) -> bool:
        """Remove a bootstrap-added netconf ssh at the end: default on for lab-token, never for netconf."""
        if self.backend == "netconf":
            return False
        return self.remove_netconf_after is not False

    @property
    def tls(self) -> bool:
        return self.access == "tls"

    @property
    def bind_address(self) -> str:
        """The address the daemon binds: the listen address with --access tls, else 127.0.0.1 (INV-10)."""
        if self.access != "tls":
            return LOOPBACK
        _require(self.listen_address is not None, LISTEN_ADDRESS_REQUIRED)
        return str(self.listen_address)


LISTEN_ADDRESS_REQUIRED = (
    "--access tls (the default) needs --listen-address: the device address your browser reaches, fxp0's "
    "when the device is managed through fxp0 ('show interfaces terse' lists its addresses). It defaults to "
    "--host only when that is an IP address. --access tunnel listens on 127.0.0.1 instead."
)


def _optional_match(value: Optional[str], pattern: re.Pattern[str], what: str) -> None:
    if value is not None:
        _require(
            isinstance(value, str) and pattern.match(value) is not None, f"device {what} is not in the expected form"
        )


@dataclass(frozen=True)
class DeviceFacts:
    """What the device says about itself (spec 8.2), each string matched against a strict pattern.

    ``state.facts_from_replies`` builds it; a device string that does not match is None, and None where a
    value is needed is a refusal. ``hostname`` is the value the lab gate compares with (INV-05).
    """

    hostname: Optional[str]
    model: Optional[str]
    junos_version: Optional[str]
    serial: Optional[str]
    srx_cluster: Optional[bool]
    mnha: Optional[bool]
    routing_engines: Optional[int]
    fips_configured: Optional[bool]
    flow_sessions: Optional[int] = None

    def __post_init__(self) -> None:
        _optional_match(self.hostname, HOSTNAME_RE, "host name")
        _optional_match(self.model, MODEL_RE, "model")
        _optional_match(self.junos_version, JUNOS_VERSION_RE, "Junos version")
        _optional_match(self.serial, SERIAL_RE, "serial number")
        for name in ("routing_engines", "flow_sessions"):
            value = getattr(self, name)
            _require(value is None or (isinstance(value, int) and value >= 0), f"{name} must be a count")

    @classmethod
    def unknown(cls) -> DeviceFacts:
        """Facts of an offline rendering (M6 without --host): nothing is known."""
        return cls(None, None, None, None, None, None, None, None)

    @classmethod
    def of(cls, **raw: object) -> DeviceFacts:
        """Build from untrusted strings: a string that does not match its pattern becomes None."""

        def text(name: str, pattern: re.Pattern[str]) -> Optional[str]:
            value = raw.get(name)
            return value if isinstance(value, str) and pattern.match(value) else None

        def flag(name: str) -> Optional[bool]:
            value = raw.get(name)
            return value if isinstance(value, bool) else None

        def count(name: str) -> Optional[int]:
            value = raw.get(name)
            return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None

        return cls(
            hostname=text("hostname", HOSTNAME_RE),
            model=text("model", MODEL_RE),
            junos_version=text("junos_version", JUNOS_VERSION_RE),
            serial=text("serial", SERIAL_RE),
            srx_cluster=flag("srx_cluster"),
            mnha=flag("mnha"),
            routing_engines=count("routing_engines"),
            fips_configured=flag("fips_configured"),
            flow_sessions=count("flow_sessions"),
        )


@dataclass(frozen=True)
class CommitEntry:
    """One commit-history entry of get-commit-information (YANG 23.2R1: sequence-number, date-time, user,
    client, comment, log, commit-confirmed). Text that fails its pattern, or holds a URL or ``$9$``, is
    None: device text never becomes a rendered line (INV-12)."""

    sequence: int
    user: Optional[str]
    client: Optional[str]
    comment: Optional[str]
    log: Optional[str]
    confirmed_state: str  # "" when the commit-confirmed leaf is absent or empty; else a normalised token
    date_time: Optional[str] = None

    @property
    def texts(self) -> Tuple[str, ...]:
        """Comment and log: whether a commit comment lands in either is unknown (Q-INST-01)."""
        return tuple(t for t in (self.comment, self.log) if t)

    @property
    def pending_confirm(self) -> bool:
        return bool(self.confirmed_state)


@dataclass(frozen=True)
class FileInfo:
    """One file-list detail entry (YANG 23.2R1 directory-list-block); owner and mode as listed."""

    path: str
    owner: Optional[str]
    mode: Optional[int]
    size: Optional[int]
    is_dir: bool = False
    is_symlink: bool = False


Pair = Tuple[str, str]


@dataclass(frozen=True)
class StatementSet:
    """A configuration model: (path key, value) pairs; value "" for a presence leaf (see module docstring)."""

    pairs: FrozenSet[Pair] = frozenset()

    def __post_init__(self) -> None:
        object.__setattr__(self, "pairs", frozenset(self.pairs))

    @classmethod
    def of(cls, pairs: Iterable[Pair]) -> StatementSet:
        return cls(frozenset(pairs))

    @property
    def entries(self) -> Dict[str, Tuple[str, ...]]:
        out: Dict[str, List[str]] = {}
        for key, value in self.pairs:
            out.setdefault(key, []).append(value)
        return {k: tuple(sorted(v)) for k, v in sorted(out.items())}

    def keys(self) -> FrozenSet[str]:
        return frozenset(k for k, _ in self.pairs)

    def values(self, key: str) -> Tuple[str, ...]:
        return tuple(sorted(v for k, v in self.pairs if k == key))

    def value(self, key: str) -> Optional[str]:
        found = self.values(key)
        return found[0] if len(found) == 1 else None

    def has(self, key: str, value: Optional[str] = None) -> bool:
        return any(k == key and (value is None or v == value) for k, v in self.pairs)

    def under(self, prefix: str) -> FrozenSet[Pair]:
        return frozenset(p for p in self.pairs if p[0] == prefix or p[0].startswith(prefix + " "))

    def without_groups(self) -> StatementSet:
        return StatementSet.of(p for p in self.pairs if not p[0].startswith("groups ") and p[0] != "apply-groups")


@dataclass(frozen=True)
class ReceiptCommit:
    stage: str
    comment: str
    confirmed: bool


@dataclass(frozen=True)
class Receipt:
    """Receipt schema 3 (spec 7.10). Never holds a secret; every field is a validated token or a constant
    text. The device copy is advisory only (INV-11): the daemon's account can write it.

    Schema 3 adds the listener (``access``, ``listen_address``, ``port``, ``routing_instance``), the SHA-256
    of the certificate the run generated (``tls_cert_sha256``: the fingerprint, never the key), that
    certificate's notAfter (``tls_cert_not_after``) and the SHA-256 of the tls.crt file as uploaded
    (``tls_cert_file_sha256``, what 'file checksum sha-256' gives on the device), and
    ``lab_hardware_attested`` (the operator typed 'lab only' after --lab-hardware, R5). A rerun keeps a
    recorded pair only while the device's tls.crt still has that file SHA-256 and notAfter is more than
    TLS_RENEW_DAYS away (SEC-R1, OPX-04)."""

    installer: str
    method: str
    layout: str
    user: str
    backend: str
    bundle_version: str
    bundle_source_ref: Optional[str]
    bundle_file_sha256: str
    bundle_payload_sha256: str
    bundle_features: Tuple[str, ...] = ()
    host_name: Optional[str] = None
    model: Optional[str] = None
    serial: Optional[str] = None
    junos_version: Optional[str] = None
    host_key_sha256: Tuple[str, ...] = ()
    provenance_kind: str = "none"
    provenance_detail: Tuple[str, ...] = ()
    provenance_evidence: bool = False
    statements_added: Tuple[str, ...] = ()
    statements_present_before: Tuple[str, ...] = ()
    bootstrap_kind: Optional[str] = None
    bootstrap_nonce: Optional[str] = None
    bootstrap_added: Tuple[str, ...] = ()
    bootstrap_confirmed_by_installer: bool = False
    files_created: Tuple[str, ...] = ()
    state_dir_created: bool = False
    veriexec_state: Optional[str] = None
    veriexec_source: str = "not read"
    overrides: Tuple[str, ...] = ()
    commits: Tuple[ReceiptCommit, ...] = ()
    time: Optional[str] = None
    not_evidence: bool = False
    access: str = "tunnel"
    listen_address: Optional[str] = None
    port: Optional[int] = None
    routing_instance: Optional[str] = None
    tls_cert_sha256: Optional[str] = None
    lab_hardware_attested: bool = False
    tls_cert_not_after: Optional[str] = None
    tls_cert_file_sha256: Optional[str] = None
    schema: int = RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        _require(self.schema == RECEIPT_SCHEMA, f"receipt schema {self.schema!r} is not {RECEIPT_SCHEMA}")
        _require(self.access in ACCESS_MODES, "receipt access mode is unknown")
        if self.access == "tls":
            _require(self.listen_address is not None, "receipt of a tls install names no listen address")
            canonical_address(str(self.listen_address))
            if self.tls_cert_sha256 is not None:
                validate_sha256(self.tls_cert_sha256, "receipt certificate SHA-256")
            if self.tls_cert_file_sha256 is not None:
                validate_sha256(self.tls_cert_file_sha256, "receipt certificate file SHA-256")
            if self.tls_cert_not_after is not None:
                _require(
                    TIME_RE.match(self.tls_cert_not_after) is not None,
                    "receipt certificate notAfter is not YYYY-MM-DDTHH:MM:SSZ",
                )
            _require(
                self.tls_cert_sha256 is not None
                or (self.tls_cert_not_after is None and self.tls_cert_file_sha256 is None),
                "receipt names a certificate's notAfter or file SHA-256 without its fingerprint",
            )
        else:
            _require(
                self.listen_address is None
                and self.tls_cert_sha256 is None
                and self.tls_cert_not_after is None
                and self.tls_cert_file_sha256 is None,
                "receipt of a tunnel install has a listen address or certificate",
            )
        if self.port is not None:
            _check_port(self.port, 1024, "receipt port")
        _require(self.routing_instance in (None, MGMT_INSTANCE), "receipt routing instance is unknown")
        _require(isinstance(self.lab_hardware_attested, bool), "receipt lab_hardware_attested is not true or false")
        _require(
            not self.lab_hardware_attested or LAB_HARDWARE_FLAG in self.overrides,
            "receipt records a lab-hardware attestation without --lab-hardware",
        )
        _require(TOKEN_RE.match(self.installer.replace(" ", "_")) is not None, "receipt installer is not a token")
        _require(self.method in {m.value for m in Method}, "receipt method is unknown")
        _require(self.layout in {lay.value for lay in Layout}, "receipt layout is unknown")
        validate_user(self.user)
        _require(self.backend in BACKENDS, "receipt backend is unknown")
        _require(VERSION_RE.match(self.bundle_version) is not None, "receipt bundle version is invalid")
        if self.bundle_source_ref is not None:
            _require(SOURCE_REF_RE.match(self.bundle_source_ref) is not None, "receipt source ref is invalid")
        validate_sha256(self.bundle_file_sha256, "receipt bundle SHA-256")
        validate_sha256(self.bundle_payload_sha256, "receipt payload SHA-256")
        for feature in self.bundle_features:
            _require(FEATURE_RE.match(feature) is not None, "receipt bundle feature is invalid")
        _optional_match(self.host_name, HOSTNAME_RE, "receipt host name")
        _optional_match(self.model, MODEL_RE, "receipt model")
        _optional_match(self.serial, SERIAL_RE, "receipt serial")
        _optional_match(self.junos_version, JUNOS_VERSION_RE, "receipt Junos version")
        for fingerprint in self.host_key_sha256:
            _require(FINGERPRINT_RE.match(fingerprint) is not None, "receipt host-key fingerprint is invalid")
        _require(self.provenance_kind in PROVENANCE_KINDS, "receipt provenance kind is unknown")
        for item in self.provenance_detail:
            _require(TOKEN_RE.match(item) is not None, "receipt provenance detail is not a token")
        for key in (*self.statements_added, *self.statements_present_before, *self.bootstrap_added):
            _require(
                key in SPEC_BY_KEY or key == APPLY_KEY,
                f"receipt statement key {sanitize_display(key)[:20]!r} is unknown",
            )
        if self.bootstrap_kind is not None:
            _require(self.bootstrap_kind in ("netconf", "op", "op-url"), "receipt bootstrap kind is unknown")
        if self.bootstrap_nonce is not None:
            _require(NONCE_RE.match(self.bootstrap_nonce) is not None, "receipt bootstrap nonce is invalid")
        for path in self.files_created:
            _require(
                _PATH_RE.match(path) is not None and path.startswith(("/var/db/scripts/", STATE_DIR)),
                "receipt file path is invalid",
            )
        if self.veriexec_state is not None:
            _require(
                re.match(r"^[a-z]+(?: [a-z]+){0,5}\Z", self.veriexec_state) is not None,
                "receipt veriexec state is invalid",
            )
        _require(
            self.veriexec_source in ("shell read", "op script read", "read by hand", "not read", "manual step"),
            "receipt veriexec source is unknown",
        )
        for flag in self.overrides:
            _require(flag in OVERRIDES, f"receipt override {sanitize_display(flag)[:40]!r} is unknown")
        for commit in self.commits:
            _require(commit.stage in STAGE_NAMES, "receipt commit stage is unknown")
            _check_comment(commit.comment)
        if self.time is not None:
            _require(TIME_RE.match(self.time) is not None, "receipt time is not YYYY-MM-DDTHH:MM:SSZ")

    @property
    def blast_radius(self) -> str:
        return root_blast_radius(self.user)

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema": self.schema,
            "installer": self.installer,
            "method": self.method,
            "layout": self.layout,
            "device": {
                "host_name": self.host_name,
                "model": self.model,
                "serial": self.serial,
                "junos_version": self.junos_version,
                "host_key_sha256": list(self.host_key_sha256),
            },
            "user": self.user,
            "blast_radius": self.blast_radius,
            "backend": self.backend,
            "bundle": {
                "version": self.bundle_version,
                "source_ref": self.bundle_source_ref,
                "file_sha256": self.bundle_file_sha256,
                "payload_sha256": self.bundle_payload_sha256,
                "features": list(self.bundle_features),
            },
            "provenance": {
                "kind": self.provenance_kind,
                "detail": list(self.provenance_detail),
                "evidence": self.provenance_evidence,
            },
            "statements_added": list(self.statements_added),
            "statements_present_before": list(self.statements_present_before),
            "bootstrap": {
                "method": self.bootstrap_kind,
                "nonce": self.bootstrap_nonce,
                "added": list(self.bootstrap_added),
                "confirmed_by_installer": self.bootstrap_confirmed_by_installer,
            },
            "files_created": list(self.files_created),
            "state_dir_created": self.state_dir_created,
            "veriexec": {"state": self.veriexec_state, "source": self.veriexec_source},
            "overrides": list(self.overrides),
            "commits": [{"stage": c.stage, "comment": c.comment, "confirmed": c.confirmed} for c in self.commits],
            "time": self.time,
            "not_evidence": self.not_evidence,
            "listener": {
                "access": self.access,
                "listen_address": self.listen_address,
                "port": self.port,
                "routing_instance": self.routing_instance,
                "tls_cert_sha256": self.tls_cert_sha256,
                "tls_cert_not_after": self.tls_cert_not_after,
                "tls_cert_file_sha256": self.tls_cert_file_sha256,
            },
            "lab_hardware_attested": self.lab_hardware_attested,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_json(cls, text: str) -> Receipt:
        """Strict: any unknown field, wrong type or unvalidated value is an InputError. The caller treats a
        device receipt that fails as absent (it is advisory)."""
        _require(isinstance(text, str) and len(text) <= 256 * 1024, "receipt is larger than 256 KiB")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise InputError(f"receipt is not JSON: {exc.msg}") from exc
        _require(isinstance(data, dict), "receipt is not a JSON object")
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> Receipt:
        expected = {
            "schema",
            "installer",
            "method",
            "layout",
            "device",
            "user",
            "blast_radius",
            "backend",
            "bundle",
            "provenance",
            "statements_added",
            "statements_present_before",
            "bootstrap",
            "files_created",
            "state_dir_created",
            "veriexec",
            "overrides",
            "commits",
            "time",
            "not_evidence",
            "listener",
            "lab_hardware_attested",
        }
        _require(set(data) == expected, f"receipt fields differ from schema {RECEIPT_SCHEMA}")
        device = _obj(data["device"], {"host_name", "model", "serial", "junos_version", "host_key_sha256"})
        bundle = _obj(data["bundle"], {"version", "source_ref", "file_sha256", "payload_sha256", "features"})
        prov = _obj(data["provenance"], {"kind", "detail", "evidence"})
        boot = _obj(data["bootstrap"], {"method", "nonce", "added", "confirmed_by_installer"})
        veri = _obj(data["veriexec"], {"state", "source"})
        listener = _obj(
            data["listener"],
            {
                "access",
                "listen_address",
                "port",
                "routing_instance",
                "tls_cert_sha256",
                "tls_cert_not_after",
                "tls_cert_file_sha256",
            },
        )
        commits_raw = data["commits"]
        _require(isinstance(commits_raw, list), "receipt commits is not a list")
        assert isinstance(commits_raw, list)  # noqa: S101 - narrowed above
        commits = []
        for item in commits_raw:
            entry = _obj(item, {"stage", "comment", "confirmed"})
            commits.append(ReceiptCommit(_s(entry["stage"]), _s(entry["comment"]), _b(entry["confirmed"])))
        receipt = cls(
            schema=_i(data["schema"]),
            installer=_s(data["installer"]),
            method=_s(data["method"]),
            layout=_s(data["layout"]),
            user=_s(data["user"]),
            backend=_s(data["backend"]),
            bundle_version=_s(bundle["version"]),
            bundle_source_ref=_os(bundle["source_ref"]),
            bundle_file_sha256=_s(bundle["file_sha256"]),
            bundle_payload_sha256=_s(bundle["payload_sha256"]),
            bundle_features=_ls(bundle["features"]),
            host_name=_os(device["host_name"]),
            model=_os(device["model"]),
            serial=_os(device["serial"]),
            junos_version=_os(device["junos_version"]),
            host_key_sha256=_ls(device["host_key_sha256"]),
            provenance_kind=_s(prov["kind"]),
            provenance_detail=_ls(prov["detail"]),
            provenance_evidence=_b(prov["evidence"]),
            statements_added=_ls(data["statements_added"]),
            statements_present_before=_ls(data["statements_present_before"]),
            bootstrap_kind=_os(boot["method"]),
            bootstrap_nonce=_os(boot["nonce"]),
            bootstrap_added=_ls(boot["added"]),
            bootstrap_confirmed_by_installer=_b(boot["confirmed_by_installer"]),
            files_created=_ls(data["files_created"]),
            state_dir_created=_b(data["state_dir_created"]),
            veriexec_state=_os(veri["state"]),
            veriexec_source=_s(veri["source"]),
            overrides=_ls(data["overrides"]),
            commits=tuple(commits),
            time=_os(data["time"]),
            not_evidence=_b(data["not_evidence"]),
            access=_s(listener["access"]),
            listen_address=_os(listener["listen_address"]),
            port=None if listener["port"] is None else _i(listener["port"]),
            routing_instance=_os(listener["routing_instance"]),
            tls_cert_sha256=_os(listener["tls_cert_sha256"]),
            tls_cert_not_after=_os(listener["tls_cert_not_after"]),
            tls_cert_file_sha256=_os(listener["tls_cert_file_sha256"]),
            lab_hardware_attested=_b(data["lab_hardware_attested"]),
        )
        _require(data["blast_radius"] == receipt.blast_radius, "receipt blast_radius is not the constant text")
        return receipt


def _obj(value: object, keys: Set[str]) -> Mapping[str, object]:
    _require(
        isinstance(value, dict) and set(value) == keys, f"receipt section fields differ from schema {RECEIPT_SCHEMA}"
    )
    assert isinstance(value, dict)  # noqa: S101 - narrowed above
    return value


def _s(value: object) -> str:
    _require(isinstance(value, str), "receipt field is not a string")
    return str(value)


def _os(value: object) -> Optional[str]:
    return None if value is None else _s(value)


def _b(value: object) -> bool:
    _require(isinstance(value, bool), "receipt field is not true or false")
    return bool(value)


def _i(value: object) -> int:
    _require(isinstance(value, int) and not isinstance(value, bool), "receipt field is not a whole number")
    assert isinstance(value, int)  # noqa: S101 - narrowed above
    return value


def _ls(value: object) -> Tuple[str, ...]:
    _require(
        isinstance(value, list) and all(isinstance(v, str) for v in value), "receipt field is not a list of strings"
    )
    assert isinstance(value, list)  # noqa: S101 - narrowed above
    return tuple(str(v) for v in value)


@dataclass(frozen=True)
class Bootstrap:
    """The configuration a method needs before its executor can run (spec 7.7): never confirmed by the
    operator; the executor confirms it only after the gate, and Junos removes it otherwise."""

    kind: str  # netconf | op | op-url
    method: Method
    add: Tuple[Statement, ...]
    nonce: Optional[str]
    comment: str
    minutes: int
    warnings: Tuple[str, ...]
    user: str
    rollback_in: Optional[int] = None  # the 'rollback in <n>mins' the entry showed when read, if it did

    @property
    def confirm_comment(self) -> str:
        return self.comment + " confirmed"

    @property
    def keys(self) -> Tuple[str, ...]:
        return tuple(s.key for s in self.add)

    @property
    def deadline_text(self) -> str:
        """When Junos removes it if the installer does not confirm it, as far as the installer read it: the
        entry's own 'rollback in <n>mins' when it showed one, never an assumed window."""
        if self.rollback_in is not None:
            return f"the commit history showed 'rollback in {self.rollback_in}mins' when it was read"
        return (
            "at the end of the window its 'commit confirmed' gave, 10 minutes unless you chose "
            "--bootstrap-minutes; 'show system commit' shows it"
        )


@dataclass(frozen=True)
class PriorState:
    """What the device holds before this run (spec 7.2), from state.prior_from_replies.

    ``effective`` is the inherited view (configuration groups expanded); ``direct`` the raw view. The
    derived properties read the effective view, except the group paths and ``apply-groups``.
    """

    effective: StatementSet = field(default_factory=StatementSet)
    direct: StatementSet = field(default_factory=StatementSet)
    pending: Pending = Pending.NONE
    scheduled_commit: bool = False  # get-commit-information pending-commit ('commit at')
    prepared_commit: bool = False  # get-commit-information prepared-commit ('commit prepare')
    history: Tuple[CommitEntry, ...] = ()
    files: Mapping[str, FileInfo] = field(default_factory=dict)
    directories: Mapping[str, str] = field(default_factory=dict)  # path -> listed | absent | unreadable
    checksums: Mapping[str, str] = field(default_factory=dict)  # path -> SHA-256 read on the device
    device_receipt: Optional[Receipt] = None
    workstation_receipt: Optional[Receipt] = None
    veriexec: Optional[str] = None
    veriexec_source: str = "not read"
    own_bootstrap: Optional[Bootstrap] = None
    unreadable: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require(
            (self.pending is Pending.OWN_BOOTSTRAP) == (self.own_bootstrap is not None),
            "pending is own-bootstrap exactly when own_bootstrap is set (use mark_own_bootstrap)",
        )

    @classmethod
    def fresh(cls) -> PriorState:
        """An offline assumption: nothing installed, nothing pending, directory absent (M6 without --host)."""
        return cls(directories={d: ("absent" if d == STATE_DIR else "listed") for d in READ_DIRS})

    # Derived views -----------------------------------------------------------------------------

    def _names_under(self, prefix: Tuple[str, ...], view: Optional[StatementSet] = None) -> Tuple[str, ...]:
        source = self.effective if view is None else view
        names: Set[str] = set()
        width = len(prefix)
        for key, _ in source.pairs:
            tokens = key.split(" ")
            if tuple(tokens[:width]) == prefix and len(tokens) > width:
                names.add(tokens[width])
        return tuple(sorted(names))

    @property
    def language(self) -> Optional[str]:
        values = self.effective.values("system scripts language")
        return values[0] if values else None

    @property
    def load_scripts_from_flash(self) -> bool:
        return bool(self.effective.under("system scripts load-scripts-from-flash"))

    @property
    def configured_python(self) -> Tuple[str, ...]:
        """Python scripts configured that are not J-Wicket's: commit, op, event, snmp and JET *.py names.
        Event scripts are configured under 'event-options event-script file' (junos-es 23.2R1 YANG,
        verified; 'system scripts' has no event container)."""
        found: List[str] = []
        for kind, path in SCRIPT_FILE_PATHS:
            for name in self._names_under(path):
                if name.endswith(".py") and not (kind == "op" and name == OP_FILE):
                    found.append(f"{kind}:{name}")
        for name in self._names_under(_EXT):
            if name.endswith(".py") and not name.startswith("jwicket"):
                found.append(f"jet:{name}")
        return tuple(found)

    @property
    def other_python(self) -> Tuple[str, ...]:
        """Configured (see configured_python) plus listed *.py files in the script directories that are not
        J-Wicket's: what keeps S1 on uninstall (spec 7.9)."""
        listed = []
        own = {*JWICKET_JET_FILES, STAGING_FILE, BACKUP_FILE, OP_FILE}
        for path, info in sorted(self.files.items()):
            directory, _, name = path.rpartition("/")
            if directory in SCRIPT_DIRS and name.endswith(".py") and name not in own and not info.is_dir:
                listed.append(f"listed:{path}")
        # A script directory that could not be listed may hold Python scripts: fail closed (S1 stays).
        unread = [f"unreadable:{d}" for d in SCRIPT_DIRS if self.directories.get(d) == "unreadable"]
        return (*self.configured_python, *listed, *unread)

    @property
    def commit_scripts(self) -> Tuple[str, ...]:
        return self._names_under(("system", "scripts", "commit", "file"))

    @property
    def outbound_ssh_clients(self) -> Tuple[str, ...]:
        return self._names_under(("system", "services", "outbound-ssh", "client"))

    @property
    def jet_files(self) -> Tuple[str, ...]:
        """Every configured extension-service file name (configured paths for INV-06)."""
        return tuple(sorted(set(self._names_under(_EXT)) | set(self._names_under(_EXT, self.direct))))

    @property
    def op_files(self) -> Tuple[str, ...]:
        return tuple(
            sorted(
                set(self._names_under(("system", "scripts", "op", "file")))
                | set(self._names_under(("system", "scripts", "op", "file"), self.direct))
            )
        )

    @property
    def configured_paths(self) -> FrozenSet[str]:
        """Paths the committed configuration names (INV-06): every JET and op file, any name."""
        paths = {f"{JET_DIR}/{n}" for n in self.jet_files} | {f"{OP_DIR}/{n}" for n in self.op_files}
        for kind, path in SCRIPT_FILE_PATHS:
            if kind != "op":
                paths |= {f"/var/db/scripts/{kind}/{n}" for n in self._names_under(path)}
        return frozenset(paths)

    @property
    def jwicket_stanzas(self) -> Dict[str, FrozenSet[str]]:
        """Each configured jwicket* JET file (and the op stanza, as OP_FILE) -> its leaf path keys."""
        out: Dict[str, Set[str]] = {}
        width = len(_EXT)
        for key, _ in self.effective.pairs:
            tokens = key.split(" ")
            if tuple(tokens[:width]) == _EXT and len(tokens) > width and tokens[width].startswith("jwicket"):
                out.setdefault(tokens[width], set()).add(" ".join(tokens[width + 1 :]))
            elif tuple(tokens[: len(_OPF)]) == _OPF:
                out.setdefault(OP_FILE, set()).add(" ".join(tokens[len(_OPF) :]))
        return {k: frozenset(v) for k, v in sorted(out.items())}

    @property
    def jwicket_group_paths(self) -> Optional[FrozenSet[str]]:
        keys = {k for k, _ in self.direct.under("groups jwicket")}
        return frozenset(keys) if keys else None

    @property
    def apply_groups(self) -> Tuple[str, ...]:
        return self.direct.values("apply-groups")

    def _ports(self, service: str) -> Tuple[int, ...]:
        ports = []
        for proto in ("http", "https"):
            for value in self.effective.values(f"system services {service} {proto} port"):
                if value.isdigit():
                    ports.append(int(value))
        return tuple(sorted(set(ports)))

    @property
    def web_ports(self) -> Tuple[int, ...]:
        return self._ports("web-management")

    @property
    def rest_ports(self) -> Tuple[int, ...]:
        return self._ports("rest")

    @property
    def fips_configured(self) -> bool:
        return bool(self.effective.under("system fips"))

    @property
    def mnha_configured(self) -> bool:
        return bool(self.effective.under("chassis high-availability"))

    @property
    def management_instance(self) -> bool:
        """'system management-instance' is set (an active empty leaf; an inactive one does not count)."""
        return self.effective.has(MANAGEMENT_INSTANCE_KEY)

    @property
    def newest(self) -> Optional[CommitEntry]:
        return min(self.history, key=lambda e: e.sequence) if self.history else None

    def has_effective(self, statement: Statement) -> bool:
        """A value statement is present with exactly its value; a presence statement (netconf ssh,
        daemonize) is present when anything is configured at or under it ('ssh { port 830; }' counts)."""
        key, value = statement.pair(Layout.DIRECT)
        if statement.value is None:
            return bool(self.effective.under(key))
        return (key, value) in self.effective.pairs

    def effective_values(self, path: Tuple[str, ...]) -> Tuple[str, ...]:
        return self.effective.values(" ".join(path))


# ------------------------------------------------------------------------------------------------
# Plan outputs
# ------------------------------------------------------------------------------------------------

# No "mkdir" and no "rmdir" (revision R4): the state directory is root's, made once before the installer
# runs and removed by root after an uninstall. "require" is an offline plan's directory: what the M6 units
# check, and send to the root step when it is not there.
FILE_ACTIONS = ("require", "keep", "stage", "copy", "replace", "backup", "restore", "write", "delete")
FILE_PHASES = ("files", "pre-commit", "post-confirm", "on-failure", "final")
FILE_CONTENTS = (
    "directory",
    "bundle",
    "settings",
    "lab-token",
    "tls-key",
    "tls-cert",
    "receipt",
    "uninstall-cli",
    "any",
)


@dataclass(frozen=True)
class FileStep:
    """One file action (spec 7.5). ``source`` is a device path for on-device copies, "workstation" for an
    SCP push, the validated pull URL, or one of ``TLS_SOURCES`` for the TLS key and certificate.
    ``sha256`` is what the device must report afterwards (None for the lab token and the TLS key, whose
    content never enters the plan, for the certificate, which the run generates, and for directories and
    deletes)."""

    path: str
    content: str
    mode: int
    sha256: Optional[str]
    action: str
    phase: str = "files"
    stage: Optional[str] = None
    source: Optional[str] = None
    owner: Optional[str] = None


@dataclass(frozen=True)
class CheckSpec:
    kind: str
    proves: str


# Checks C1..C13 and K1..K2 as data (spec 7.6). C1 belongs to the deferred setup mode (cut C1). C9 is
# retired (revision R3): no check uses an SSH channel, because forwarding was refused on SRX4100
# 25.2R1-S1.4 (verified). Its id stays so that the others keep theirs.
RESERVED_CHECKS = ("C1",)
RETIRED_CHECKS = ("C9",)
CHECKS: Mapping[str, CheckSpec] = {
    "K1": CheckSpec(
        "bootstrap-pending",
        "The pending commit is exactly this installer's bootstrap: the newest entry of "
        "'show system commit', by the daemon account, with the bootstrap comment.",
    ),
    "K2": CheckSpec(
        "connected",
        "The installer is running through what the bootstrap enabled (the NETCONF session, or "
        "the op script): the bootstrap's health check.",
    ),
    "C1": CheckSpec("reserved", "Reserved: the setup-mode result (bundle change D1, deferred); never planned."),
    "C2": CheckSpec(
        "selftest",
        "The self-test copy ('request extension-service start jwicket_selftest.py') reports "
        "ok, with the version and payload SHA-256 of this bundle.",
    ),
    "C3": CheckSpec(
        "probe",
        "The probe copy ('request extension-service start jwicket_probe.py') reports every module "
        "the chosen backend needs as ok.",
    ),
    "C4": CheckSpec(
        "start-line",
        "Exactly one new 'listening on <address>:<port>' line in /var/db/jwicket/jwicket.log "
        "since the commit ('file show /var/db/jwicket/jwicket.log'); two mean a restart loop.",
    ),
    "C5": CheckSpec(
        "audit-start",
        "Exactly one new audit record with event start and this bundle's version in " "/var/db/jwicket/audit.jsonl.",
    ),
    "C6": CheckSpec(
        "no-refusal-file", "No new /var/db/jwicket/startup-refused.txt (a stale one is deleted before the " "commit)."
    ),
    "C7": CheckSpec(
        "process-stable",
        "'show extension-service status jwicket.py' shows the same process id at two "
        "reads at least 30 seconds apart.",
    ),
    "C8": CheckSpec(
        "api-session",
        "--access tls: an HTTPS GET /api/session from the workstation to <address>:<port>, trusting only the "
        "certificate whose SHA-256 the installer generated (pinned: no CA store, and the pin stands in for "
        "the host name check), answers 200 with this version (and build). --access tunnel: not available "
        "(no check uses an SSH channel).",
    ),
    "C9": CheckSpec(
        "retired",
        "Retired: the NETCONF banner through an SSH channel (forwarding was refused on SRX4100 25.2R1-S1.4). "
        "The netconf backend rests on the probe (C3) and is not checked end to end; never planned.",
    ),
    "C10": CheckSpec(
        "committed-delta",
        "Before confirming: the committed statements of the touched subtrees equal "
        "the plan, and the committed delta ('show | compare rollback 1') changes nothing outside them.",
    ),
    "C11": CheckSpec(
        "pending-reread",
        "Before confirming: 'show system commit' shows this stage's commit as the "
        "newest, by the daemon account, with this stage's comment, and no 'commit at' or prepared commit.",
    ),
    "C12": CheckSpec("statements-absent", "The removed statements are absent from the committed configuration."),
    "C13": CheckSpec(
        "no-process",
        "No J-Wicket process is listed ('show extension-service status jwicket.py') " "before any file is deleted.",
    ),
}


@dataclass(frozen=True)
class Check:
    id: str
    kind: str
    target: str
    expect: Mapping[str, str]
    timeout_s: int
    required: bool = True


def _check(check_id: str, target: str, expect: Mapping[str, str], timeout_s: int = 30, required: bool = True) -> Check:
    return Check(check_id, CHECKS[check_id].kind, target, dict(expect), timeout_s, required)


@dataclass(frozen=True)
class Stage:
    """One confirmed commit (spec 7.6, 8.6). ``already_committed`` marks the bootstrap stage: its commit is
    the operator's pending bootstrap, and the executor only re-reads (K1), checks (K2) and confirms it.

    A removal whose path equals an addition's path is a value change (an upgrade's new checksum): it is
    rendered as the set line alone and expected as old value removed, new value added."""

    name: str
    add: Tuple[Statement, ...]
    remove: Tuple[Statement, ...]
    files_before_commit: Tuple[FileStep, ...]
    comment: str
    confirm_comment: str
    confirm_minutes: Minutes
    checks: Tuple[Check, ...]
    files_after_confirm: Tuple[FileStep, ...] = ()
    restore_on_failure: Tuple[FileStep, ...] = ()
    post_confirm_checks: Tuple[Check, ...] = ()
    already_committed: bool = False

    @property
    def check_ids(self) -> Tuple[str, ...]:
        return tuple(c.id for c in self.checks)

    @property
    def changes(self) -> bool:
        return bool(self.add or self.remove)


@dataclass(frozen=True)
class Refusal:
    code: str
    message: str
    override: Optional[str]
    detail: str = ""
    overridden: bool = False


def make_refusal(code: str, detail: str = "", overrides: FrozenSet[str] = frozenset()) -> Refusal:
    """A refusal of spec 8.11 with its constant message; ``detail`` must be built from validated tokens."""
    _require(code in REFUSALS, f"unknown refusal code {code!r}")
    message, override = REFUSALS[code]
    return Refusal(
        code, message, override, sanitize_display(detail, 300), override is not None and override in overrides
    )


@dataclass(frozen=True)
class InstallPlan:
    """The frozen plan every method renders or executes (spec 7.1)."""

    schema: int
    method: Method
    bundle: BundleId
    provenance: Provenance
    options: Options
    facts: DeviceFacts
    bootstrap: Optional[Bootstrap]
    directory: Optional[FileStep]
    files: Tuple[FileStep, ...]
    stages: Tuple[Stage, ...]
    warnings: Tuple[str, ...]  # warning ids, in print order (WARNINGS maps them to texts)
    production_signs: Tuple[str, ...]
    refusals: Tuple[Refusal, ...]
    receipt: Receipt
    overrides: FrozenSet[str] = frozenset()
    upgrade: bool = False
    offline: bool = False
    status_checks: Tuple[Check, ...] = ()
    present_before: Tuple[str, ...] = ()
    final_files: Tuple[FileStep, ...] = ()
    routing_instance: Optional[str] = None  # MGMT_INSTANCE for --access tls on a management-instance device
    lab_hardware: bool = False  # not a vSRX, R-MODEL overridden: the executor asks for 'lab only' (R5)
    # JFR-05: MGMT_INSTANCE for a device pull (--transfer file-copy or refresh-from, M4's release URL) on a
    # management-instance device, where fxp0 and its default route are in mgmt_junos (verified on SRX4100)
    # and a default-instance download would leave through inet.0. That the option routes it is inferred.
    pull_routing_instance: Optional[str] = None

    @property
    def layout(self) -> Layout:
        return self.options.layout

    @property
    def settings_text(self) -> str:
        """The jwicket.ini this plan writes (executors write exactly this; its SHA-256 is in ``files``)."""
        return render_settings(self.options, routing_instance=self.routing_instance)

    @property
    def url(self) -> Optional[str]:
        """Where the operator's browser reaches J-Wicket with --access tls (None with --access tunnel)."""
        if not self.options.tls:
            return None
        return listen_url(self.options.bind_address, self.options.port)

    @property
    def blocked(self) -> bool:
        """Any refusal not overridden."""
        return any(not r.overridden for r in self.refusals)

    @property
    def no_change(self) -> bool:
        """Idempotent re-run: nothing to confirm, commit or write (SC-14)."""
        writes = [f for f in self.files if f.action != "keep"]
        directory_change = self.directory is not None and self.directory.action != "keep"
        return not self.stages and not writes and not directory_change and self.bootstrap is None

    def stage(self, name: str) -> Optional[Stage]:
        return next((s for s in self.stages if s.name == name), None)


@dataclass(frozen=True)
class OwnershipEvidence:
    """What Junos's own commit history says this installer added (INV-11, spec 7.9)."""

    history_available: bool
    added: FrozenSet[Pair]
    sequences: Tuple[int, ...] = ()

    @property
    def keys(self) -> FrozenSet[str]:
        return frozenset(k for k in (statement_key_of(p[0]) for p in self.added) if k is not None)

    def added_value(self, key: str) -> Optional[str]:
        for path_key, value in self.added:
            if statement_key_of(path_key) == key:
                return value
        return None

    @classmethod
    def none(cls) -> OwnershipEvidence:
        return cls(False, frozenset(), ())


@dataclass(frozen=True)
class KeptStatement:
    key: str
    reason: str


@dataclass(frozen=True)
class UninstallPlan:
    schema: int
    method: Method
    facts: DeviceFacts
    layout: Layout
    stages: Tuple[Stage, ...]
    files: Tuple[FileStep, ...]
    kept: Tuple[KeptStatement, ...]
    leftovers: Tuple[str, ...]
    unknown_leaves: Tuple[str, ...]
    warnings: Tuple[str, ...]
    refusals: Tuple[Refusal, ...]
    overrides: FrozenSet[str] = frozenset()
    remove_shared: bool = False
    user: Optional[str] = None
    file_checks: Tuple[Check, ...] = ()  # C13 before top-level deletes (files but no uninstall stage)
    state_dir_left: bool = False  # /var/db/jwicket stays for root to remove (STATE_DIR_LEFT, R4)
    lab_hardware: bool = False  # not a vSRX, R-MODEL overridden with --lab-hardware (R5)

    @property
    def blocked(self) -> bool:
        return any(not r.overridden for r in self.refusals)

    @property
    def no_change(self) -> bool:
        return not self.stages and not self.files


# ------------------------------------------------------------------------------------------------
# Small helpers
# ------------------------------------------------------------------------------------------------


def root_blast_radius(user: str) -> str:
    return ROOT_BLAST_RADIUS.replace(USER_MARKER, validate_user(user))


def directory_fallback(user: str) -> str:
    return DIRECTORY_FALLBACK.replace(USER_MARKER, validate_user(user))


def warning_text(warning_id: str, user: Optional[str] = None) -> str:
    """The text of a warning id, with the validated user substituted where the text names one."""
    _require(warning_id in WARNINGS, f"unknown warning id {warning_id!r}")
    text = WARNINGS[warning_id]
    if USER_MARKER in text and user is not None:
        text = text.replace(USER_MARKER, validate_user(user))
    return text


def lab_hardware_matches(typed: Optional[str]) -> bool:
    """R5's attestation: exactly 'lab only' (surrounding whitespace stripped, as the host-name gate does)."""
    return isinstance(typed, str) and typed.strip() == LAB_HARDWARE_ANSWER


def lab_gate_matches(typed: Optional[str], facts: DeviceFacts) -> bool:
    """The lab gate (spec 8.2): both stripped, compared exactly; empty or None never matches (INV-05)."""
    if typed is None or facts.hostname is None or not isinstance(typed, str):
        return False
    answer = typed.strip()
    expected = facts.hostname.strip()
    return bool(answer) and bool(expected) and answer == expected


def confirm_allowed(seconds_since_commit: float, minutes: int) -> bool:
    """INV-04: a confirming commit only while at least CONFIRM_MARGIN_S remain before the deadline."""
    return 0 <= seconds_since_commit <= minutes * 60 - CONFIRM_MARGIN_S


def stage_comment(bundle: BundleId, stage: str, *, confirmed: bool = False) -> str:
    suffix = "confirmed" if confirmed else "lab-install"
    comment = f"jwicket {bundle.version} sha256:{bundle.short} {stage} {suffix}"
    _check_comment(comment)
    return comment


def uninstall_comment(stage: str, *, confirmed: bool = False) -> str:
    middle = "" if stage == "uninstall" else " netconf"
    return f"jwicket uninstall{middle} {'confirmed' if confirmed else 'lab-install'}"


def rollback_now_comment(bundle: BundleId) -> str:
    comment = f"jwicket {bundle.version} sha256:{bundle.short} rolled back by installer"
    _check_comment(comment)
    return comment


INSTALLER_COMMENT_RE = re.compile(
    r"^(?:jwicket [0-9A-Za-z][0-9A-Za-z.+!_-]{0,63} sha256:[0-9a-f]{12} "
    r"(?:(?:bootstrap|diagnostics|runtime|netconf-removal|revert) (?:lab-install|confirmed)|rolled back by installer)"
    r"|jwicket uninstall(?: netconf)? (?:lab-install|confirmed)"
    r"|jwicket-bootstrap (?:netconf|op|op-url)(?: [a-z0-9]{6})?(?: confirmed)?)\Z"
)


def is_installer_comment(text: Optional[str]) -> bool:
    return text is not None and INSTALLER_COMMENT_RE.match(text) is not None


def bootstrap_comment(kind: str, nonce: Optional[str]) -> str:
    """'jwicket-bootstrap <kind> <nonce>'; the on-box kinds carry no nonce (spec 6.5: the method name and
    the running user identify them)."""
    _require(kind in ("netconf", "op", "op-url"), f"unknown bootstrap kind {kind!r}")
    if kind == "netconf":
        _require(
            nonce is not None and NONCE_RE.match(nonce) is not None, "the NETCONF bootstrap needs a 6-character nonce"
        )
        return f"jwicket-bootstrap netconf {nonce}"
    _require(
        nonce is None or NONCE_RE.match(nonce) is not None, "bootstrap nonce must be 6 lowercase letters or digits"
    )
    return f"jwicket-bootstrap {kind}" + (f" {nonce}" if nonce else "")


def settings_sha256(options: Options, *, routing_instance: Optional[str] = None) -> str:
    return hashlib.sha256(render_settings(options, routing_instance=routing_instance).encode("utf-8")).hexdigest()


def render_settings(options: Options, *, routing_instance: Optional[str] = None) -> str:
    """jwicket.ini for the access mode (INV-10, SC-20); executors write ``InstallPlan.settings_text``.

    --access tunnel: deploy-lab step 3's values, ``bind = 127.0.0.1``, ``allowed_hosts`` the tunnel's
    two names. --access tls: deploy-lab's TLS-on-fxp0 variant (verified on SRX4100 25.2R1-S1.4): ``bind``
    the listen address, ``tls_cert`` and ``tls_key``, ``allowed_hosts = <address>:<port>``, and
    ``routing_instance = mgmt_junos`` when the plan found 'system management-instance' (the only value it
    takes). Every other key stays at its default. Deterministic (no time, no version), so an unchanged
    file is recognised by its SHA-256 on a re-run. Must pass ``jwicket.settings.parse_settings``
    (AC-006-08). The extension-service 'routing-instance' statement is never rendered: it did not move the
    listener on the lab SRX4100 (verified), the daemon's own setting did.
    """
    _require(routing_instance in (None, MGMT_INSTANCE), f"routing_instance must be None or {MGMT_INSTANCE}")
    _require(options.tls or routing_instance is None, "routing_instance is only for --access tls")
    port = options.port
    if options.tls:
        address = options.bind_address
        server = [
            "# Every value is checked before anything listens. J-Wicket listens with TLS on the device's",
            "# management address (--access tls); run the installer again to change this file.",
            "",
            "[server]",
            f"bind = {address}",
            f"port = {port}",
            f"tls_cert = {TLS_CERT_PATH}",
            f"tls_key = {TLS_KEY_PATH}",
            f"allowed_hosts = {host_port(address, port)}",
        ]
        if routing_instance is not None:
            server.append(f"routing_instance = {routing_instance}")
    else:
        server = [
            "# Every value is checked before anything listens. J-Wicket listens on 127.0.0.1 only and is",
            "# reached through an SSH tunnel (--access tunnel); run the installer again to change this file.",
            "",
            "[server]",
            f"bind = {LOOPBACK}",
            f"port = {port}",
            f"allowed_hosts = 127.0.0.1:{port}, localhost:{port}",
        ]
    lines = [
        f"# {SETTINGS_PATH}: J-Wicket settings, written by {INSTALLER_NAME} (lab only).",
        *server,
        "",
        "[auth]",
        f"backend = {options.backend}",
    ]
    if options.backend == "lab-token":
        lines.append(f"lab_token_file = {LAB_TOKEN_PATH}")
    lines += ["", "[log]", f"file = {LOG_PATH}", f"audit_file = {AUDIT_PATH}", ""]
    return "\n".join(lines)


# ------------------------------------------------------------------------------------------------
# The configuration model: lines, patches, groups
# ------------------------------------------------------------------------------------------------


def _split_leaf(tokens: Sequence[str]) -> List[Pair]:
    """Tokens of one leaf (path included) to model pairs, by the VALUE_LEAVES / LEAF_LISTS rule."""
    toks = [t for t in tokens if t not in ("[", "]")]
    if not toks:
        return []
    for index, token in enumerate(toks):
        if token in LEAF_LISTS:
            base = " ".join(toks[: index + 1])
            return [(base, v) for v in toks[index + 1 :]] or [(base, "")]
    if len(toks) >= 2 and toks[-2] in VALUE_LEAVES:
        return [(" ".join(toks[:-1]), toks[-1])]
    return [(" ".join(toks), "")]


def apply_lines(model: StatementSet, lines: Iterable[str]) -> StatementSet:
    """Apply set/delete lines to a model (tests and plan diffs; not a claim about Junos internals).

    ``set`` replaces a single-valued leaf's value and appends to a leaf-list; ``delete <path>`` removes
    every pair at or under the path; ``delete <leaf-list> <value>`` removes that element only.
    """
    pairs = set(model.pairs)
    for line in lines:
        verb, _, rest = line.strip().partition(" ")
        tokens = rest.split()
        if verb == "set":
            for key, value in _split_leaf(tokens):
                if key.split(" ")[-1] not in LEAF_LISTS:
                    pairs = {p for p in pairs if p[0] != key}
                pairs.add((key, value))
        elif verb == "delete":
            leaf_list_at = next((i for i, t in enumerate(tokens) if t in LEAF_LISTS), None)
            if leaf_list_at is not None and leaf_list_at == len(tokens) - 2:
                pairs.discard((" ".join(tokens[:-1]), tokens[-1]))
            else:
                prefix = " ".join(tokens)
                pairs = {p for p in pairs if not (p[0] == prefix or p[0].startswith(prefix + " "))}
        else:
            raise InputError(f"model line {sanitize_display(line)[:80]!r} is neither set nor delete")
    return StatementSet.of(pairs)


def expand_groups(model: StatementSet) -> StatementSet:
    """The effective view of a model: groups jwicket applied when apply-groups lists it, direct values
    overriding group values (verified rule, [groups-usage]); groups and apply-groups dropped."""
    direct = model.without_groups()
    if ("apply-groups", GROUP_NAME) not in model.pairs:
        return direct
    out = set(direct.pairs)
    direct_keys = direct.keys()
    prefix = " ".join(GROUP_PREFIX) + " "
    for key, value in model.pairs:
        if key.startswith(prefix):
            inner = key[len(prefix) :]
            if inner.split(" ")[-1] in LEAF_LISTS or inner not in direct_keys:
                out.add((inner, value))
    return StatementSet.of(out)


@dataclass(frozen=True)
class PatchDelta:
    """A parsed patch-format diff ('show | compare'): what it adds and removes, its headers, the path of
    every changed line, and anything that did not parse (which makes a caller fail closed)."""

    added: FrozenSet[Pair]
    removed: FrozenSet[Pair]
    headers: Tuple[Tuple[str, ...], ...]
    changed: Tuple[Tuple[str, Tuple[str, ...]], ...]
    problems: Tuple[str, ...]


MAX_PATCH_BYTES = 4 * 1024 * 1024
_HEADER_RE = re.compile(r"^\[edit(?: (?P<path>[^\]]*))?\]\Z")


def _tokens(body: str) -> List[str]:
    out: List[str] = []
    for raw in body.replace("[", " [ ").replace("]", " ] ").split():
        out.append(raw.strip('"'))
    return out


def parse_patch(text: str) -> PatchDelta:
    """Parse Junos's patch-format text ([xml-compare], verified to be 'a patch format'; its exact rendering
    is undocumented and every fixture is synthetic, Q-INST-01). Rules: '[edit a b]' starts a block; '+' and
    '-' lines change, other lines are context; '{' opens a level and '}' closes it; a line ending in ';'
    is a leaf split by the model's leaf rule. Anything else is a problem, reported, never guessed."""
    if len(text) > MAX_PATCH_BYTES:
        return PatchDelta(frozenset(), frozenset(), (), (), ("diff text is larger than 4 MB",))
    added: Set[Pair] = set()
    removed: Set[Pair] = set()
    headers: List[Tuple[str, ...]] = []
    changed: List[Tuple[str, Tuple[str, ...]]] = []
    problems: List[str] = []
    header: Optional[Tuple[str, ...]] = None
    stack: List[Tuple[List[str], str]] = []  # (tokens, marker of the line that opened the level)
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not line.strip():
            continue
        match = _HEADER_RE.match(line.strip())
        if match is not None:
            if stack:
                problems.append(f"line {number}: header inside an open block")
            header = tuple((match.group("path") or "").split())
            headers.append(header)
            stack = []
            continue
        marker = line[0] if line[0] in "+-" else " "
        body = line[1:].strip() if marker != " " else line.strip()
        if body.startswith(("/*", "#", "!")):
            if marker != " ":
                problems.append(f"line {number}: changed comment or annotation")
            continue
        if header is None:
            problems.append(f"line {number}: text before any [edit] header")
            continue
        enclosing = next((m for _, m in reversed(stack) if m != " "), " ")
        if enclosing != " " and marker != enclosing:
            problems.append(f"line {number}: a '{marker.strip() or 'context'}' line inside a '{enclosing}' block")
            continue
        if body == "}":
            if not stack:
                problems.append(f"line {number}: unbalanced closing brace")
            else:
                stack.pop()
            continue
        prefix = header + tuple(t for level, _ in stack for t in level)
        if body.endswith("{"):
            tokens = _tokens(body[:-1])
            if marker != " ":
                changed.append((marker, prefix + tuple(tokens)))
            stack.append((tokens, marker))
            continue
        if not body.endswith(";"):
            problems.append(f"line {number}: neither a block, a leaf nor a header")
            continue
        if marker == " ":
            continue
        full = prefix + tuple(_tokens(body[:-1]))
        changed.append((marker, full))
        for pair in _split_leaf(list(full)):
            (added if marker == "+" else removed).add(pair)
    if stack:
        problems.append("unbalanced opening brace at the end of the diff")
    return PatchDelta(frozenset(added), frozenset(removed), tuple(headers), tuple(changed), tuple(problems))


def _pair_tokens(pair: Pair) -> Tuple[str, ...]:
    return tuple(pair[0].split(" ")) + ((pair[1],) if pair[1] else ())


def patch_text(before: StatementSet, after: StatementSet) -> str:
    """The patch-format text of the change from ``before`` to ``after`` (the plan's diff, spec 8.3).
    One block per parent path; ``parse_patch(patch_text(a, b))`` gives back exactly b-a and a-b."""
    blocks: Dict[Tuple[str, ...], List[Tuple[int, str]]] = {}
    for marker, pairs in (("-", before.pairs - after.pairs), ("+", after.pairs - before.pairs)):
        for pair in pairs:
            tokens = tuple(pair[0].split(" "))
            if tokens[-1] in LEAF_LISTS or (len(tokens) >= 1 and pair[1] and tokens[-1] in VALUE_LEAVES):
                parent, leaf = tokens[:-1], (tokens[-1], pair[1]) if pair[1] else (tokens[-1],)
            else:
                parent, leaf = tokens[:-1], (tokens[-1],)
            blocks.setdefault(parent, []).append((0 if marker == "-" else 1, f"{marker}    {' '.join(leaf)};"))
    out: List[str] = []
    for parent in sorted(blocks):
        out.append("[edit" + ("" if not parent else " " + " ".join(parent)) + "]")
        out.extend(line for _, line in sorted(blocks[parent]))
    return "\n".join(out) + ("\n" if out else "")


# Junos prints a list entry's keyword and name on one line ('file jwicket.py {'); every other token of the
# installer's paths is a level of its own (JFR-02). Only the installer's own paths are rendered this way.
_LIST_KEYWORDS = frozenset({"file"})


def _leaf_parts(pair: Pair) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    """A pair's parent tokens and its leaf words, by the rule patch_text uses."""
    tokens = tuple(pair[0].split(" "))
    if tokens[-1] in LEAF_LISTS or (pair[1] and tokens[-1] in VALUE_LEAVES):
        return tokens[:-1], ((tokens[-1], pair[1]) if pair[1] else (tokens[-1],))
    return tokens[:-1], (tokens[-1],)


def _levels(tokens: Sequence[str]) -> List[Tuple[str, ...]]:
    """Parent tokens grouped into display levels ('file' and its name are one level)."""
    levels: List[Tuple[str, ...]] = []
    index = 0
    while index < len(tokens):
        if tokens[index] in _LIST_KEYWORDS and index + 1 < len(tokens):
            levels.append((tokens[index], tokens[index + 1]))
            index += 2
        else:
            levels.append((tokens[index],))
            index += 1
    return levels


# Levels every device the installers reach is taken to have although the select-only read (8.3) cannot
# show them: 'system' (host name, root authentication) and 'system services' (it holds 'ssh', which every
# installer connects through). Inferred; used only to group the illustrative comparison (JFR-02).
ASSUMED_LEVELS: Tuple[Tuple[str, ...], ...] = (("system",), ("system", "services"))


def _holds_level(view: StatementSet, tokens: Sequence[str], assumed: Iterable[Tuple[str, ...]] = ()) -> bool:
    """Whether ``view`` has anything at or under the path ``tokens`` (the root always exists, and so does
    each ``assumed`` level)."""
    if not tokens or tuple(tokens) in set(assumed):
        return True
    prefix = " ".join(tokens)
    return any(key == prefix or key.startswith(prefix + " ") for key, _ in view.pairs)


# The order of the children of each level the installer's statements touch, as the SRX configuration
# schema lists them (junos-es-conf-system 23.2R1, the module whose SHA-256 tests/fixtures/install_rpc/
# README.md records: 'system' lists scripts, then services, then extensions; 'scripts' lists op before
# language; 'scripts op' lists file before allow-url-for-python; an extension-service 'file' lists checksum
# before daemonize, respawn-on-normal-exit and username; verified as the schema's order). A 24.4R2.25
# junos-es-conf-system module read by the research (SHA-256 in that README) has the same order at each of
# those levels, except that 'system services' lists netconf before ssh; 'system services' therefore names
# only netconf, since the installer never prints an ssh statement (ASSUMED_LEVELS keeps it out of a diff).
# That 'show | compare' prints in schema order, not in the order statements were entered, is inferred
# (Q-INST-01 records samples). Keys are display paths with 'groups jwicket' dropped and each list entry
# folded to its keyword ('file'), so the group layout orders the same way.
_COMPARE_SCHEMA_ORDER: Mapping[Tuple[str, ...], Tuple[str, ...]] = {
    ("system",): ("scripts", "services", "extensions"),
    ("system", "scripts"): ("op", "language"),
    ("system", "scripts", "op"): ("file", "allow-url-for-python"),
    ("system", "scripts", "op", "file"): ("checksum",),
    ("system", "scripts", "op", "file", "checksum"): ("sha-256",),
    ("system", "services"): ("netconf",),
    ("system", "services", "netconf"): ("ssh",),
    ("system", "extensions"): ("extension-service",),
    ("system", "extensions", "extension-service"): ("application",),
    ("system", "extensions", "extension-service", "application"): ("file",),
    ("system", "extensions", "extension-service", "application", "file"): (
        "checksum",
        "daemonize",
        "respawn-on-normal-exit",
        "username",
    ),
    ("system", "extensions", "extension-service", "application", "file", "checksum"): ("sha-256",),
}


def _compare_fold(tokens: Sequence[str], *, schema: bool) -> Tuple[str, ...]:
    """A display path with each list entry folded to its keyword ('file <name>' to 'file'); for a schema
    lookup (``schema``) also without 'groups jwicket', so the group layout orders as the direct one."""
    tokens = tuple(tokens)
    if schema and tokens[: len(GROUP_PREFIX)] == GROUP_PREFIX:
        tokens = tokens[len(GROUP_PREFIX) :]
    return tuple(level[0] for level in _levels(tokens))


def _compare_render_order() -> Dict[Tuple[Tuple[str, ...], str], int]:
    """Where the schema gives no order (the root, the groups list, which list entry comes first), the order
    in which the plan renders its statements (stage_lines: the statement table, the group layout's lines
    then 'apply-groups'): (folded parent, child as printed) -> first position. Illustrative too: Junos's
    order for those is not in the YANG read (the root's 'system' is an augment) and is not recorded."""
    paths = [GROUP_PREFIX + spec.path for spec in STATEMENT_TABLE]
    paths.append(("apply-groups",))
    paths.extend(spec.path for spec in STATEMENT_TABLE)
    rank: Dict[Tuple[Tuple[str, ...], str], int] = {}
    for path in paths:
        levels = _levels(path[:-1])
        for index, level in enumerate(levels):
            parent = _compare_fold([t for lv in levels[:index] for t in lv], schema=False)
            rank.setdefault((parent, " ".join(level)), len(rank))
        rank.setdefault((_compare_fold(path[:-1], schema=False), path[-1]), len(rank))
    return rank


_COMPARE_RENDER_ORDER = _compare_render_order()


def _compare_rank(parent: Sequence[str], item: Tuple[str, ...]) -> Tuple[int, int, str]:
    """Sort key of a child ``item`` (a level, or leaf words ending in ';') under ``parent``: its place in the
    schema's order, then in the plan's render order, then its name as printed (only for names neither one
    knows, such as another application's file on the device). A leaf's value is not part of it."""
    words = item[:-1] if item[-1] == ";" else item
    printed = words[0] if item[-1] == ";" else " ".join(words)
    schema = _COMPARE_SCHEMA_ORDER.get(_compare_fold(parent, schema=True), ())
    place = schema.index(words[0]) if words[0] in schema else len(schema)
    render = _COMPARE_RENDER_ORDER.get((_compare_fold(parent, schema=False), printed), len(_COMPARE_RENDER_ORDER))
    return (place, render, printed)


def compare_text(
    before: StatementSet, after: StatementSet, *, assumed: Iterable[Tuple[str, ...]] = ()
) -> str:
    """The change from ``before`` to ``after`` grouped the way Junos documents 'show | compare' (JFR-02):
    each statement under the deepest level that exists on both sides ('[edit <that level>]'), and every
    level below it that is new, or removed whole, as a braced block whose lines all carry the marker
    (Juniper's NETCONF guide shows a new 'ge-1/0/1 { unit 0 { ... } }' under '[edit interfaces]', verified
    as documented). Printed in configuration order, never alphabetically or leaves first: siblings, and the
    headers by their first change, follow the schema's order (_COMPARE_SCHEMA_ORDER), then the plan's render
    order, and a removed line comes just before the line that replaces it. Junos's exact spacing, and that
    it prints in this order, are undocumented: illustrative (Q-INST-01). ``assumed``: levels taken to exist
    on both sides though the views do not show them (ASSUMED_LEVELS for a select-only read).
    ``parse_patch(compare_text(a, b))`` gives back exactly b-a and a-b, as for patch_text."""
    assumed = tuple(assumed)
    trees: Dict[Tuple[Tuple[str, ...], str], Dict[Tuple[str, ...], object]] = {}
    for marker, pairs, other in (("-", before.pairs - after.pairs, after), ("+", after.pairs - before.pairs, before)):
        for pair in pairs:
            parent, leaf = _leaf_parts(pair)
            levels = _levels(parent)
            depth = len(levels)
            while depth > 0 and not _holds_level(other, [t for level in levels[:depth] for t in level], assumed):
                depth -= 1
            header = tuple(t for level in levels[:depth] for t in level)
            node = trees.setdefault((header, marker), {})
            for level in levels[depth:]:
                child = node.setdefault(level, {})
                assert isinstance(child, dict)  # noqa: S101 - a level is never also a leaf here
                node = child
            node[(*leaf, ";")] = {}
    out: List[str] = []

    def ordered(
        parent: Tuple[str, ...], nodes: Sequence[Tuple[str, Mapping[Tuple[str, ...], object]]]
    ) -> List[Tuple[str, Tuple[str, ...], object]]:
        items = [(marker, key, node[key]) for marker, node in nodes for key in node]
        return sorted(items, key=lambda item: (_compare_rank(parent, item[1]), item[0] != "-", item[1]))

    def emit(
        parent: Tuple[str, ...], nodes: Sequence[Tuple[str, Mapping[Tuple[str, ...], object]]], depth: int
    ) -> None:
        pad = "    " * depth
        for marker, key, child in ordered(parent, nodes):
            if key[-1] == ";":
                out.append(f"{marker}{pad}{' '.join(key[:-1])};")
                continue
            assert isinstance(child, dict)  # noqa: S101 - built above
            out.append(f"{marker}{pad}{' '.join(key)} {{")
            emit(parent + key, [(marker, child)], depth + 1)
            out.append(f"{marker}{pad}}}")

    def position(header: Tuple[str, ...]) -> Tuple[Tuple[int, int, str], ...]:
        levels = _levels(header)
        path = tuple(_compare_rank([t for lv in levels[:i] for t in lv], level) for i, level in enumerate(levels))
        first = ordered(header, [(m, trees[(header, m)]) for m in ("-", "+") if (header, m) in trees])[0]
        return (*path, _compare_rank(header, first[1]))

    for header in sorted({h for h, _ in trees}, key=position):
        out.append("[edit" + ("" if not header else " " + " ".join(header)) + "]")
        emit(header, [(m, trees[(header, m)]) for m in ("-", "+") if (header, m) in trees], 1)
    return "\n".join(out) + ("\n" if out else "")


# ------------------------------------------------------------------------------------------------
# Stage lines, roots, structural and header checks (SC-06, spec 8.7)
# ------------------------------------------------------------------------------------------------


def _value_changes(stage: Stage) -> FrozenSet[Tuple[str, ...]]:
    added_paths = {s.path for s in stage.add}
    return frozenset(s.path for s in stage.remove if s.path in added_paths)


def stage_layout(stage: Stage, layout: Layout) -> Layout:
    """The layout a stage is rendered in: the bootstrap is always direct (it is pasted before any group
    exists, and on-box methods publish it as fixed units)."""
    return Layout.DIRECT if stage.name == "bootstrap" else layout


def stage_lines(stage: Stage, layout: Layout) -> Tuple[str, ...]:
    """The set and delete lines of a stage, in statement-table order: sets first, then deletes (a value
    change is the set line alone). The one source every rendering takes its lines from (P1)."""
    layout = stage_layout(stage, layout)
    order = {key: index for index, key in enumerate([*SPEC_BY_KEY, APPLY_KEY, *STANZA_KEYS, GROUP_KEY])}
    changes = _value_changes(stage)
    sets = [s.set_line(layout) for s in sorted(stage.add, key=lambda s: order[s.key])]
    deletes = [s.delete_line(layout) for s in sorted(stage.remove, key=lambda s: order[s.key]) if s.path not in changes]
    lines = tuple(dict.fromkeys([*sets, *deletes]))
    for line in lines:
        _bad(_LINE_RE.match(line) is not None, f"rendered line {line!r} has characters outside the token set")
    return lines


def stage_roots(stage: Stage, layout: Layout) -> Tuple[Tuple[str, ...], ...]:
    layout = stage_layout(stage, layout)
    roots = {s.form(layout) for s in (*stage.add, *stage.remove)}
    return tuple(sorted(roots))


def _expected_change(stage: Stage, layout: Layout, before: StatementSet) -> Tuple[Set[Pair], Set[Pair]]:
    """What a stage's lines do to a model: a delete removes everything at or under its path (a leaf-list
    delete only its element); a value change removes the old value and adds the new one."""
    added = {s.pair(layout) for s in stage.add}
    changes = _value_changes(stage)
    removed: Set[Pair] = set()
    for statement in stage.remove:
        form = statement.form(layout)
        if statement.path in changes or form[-1] in LEAF_LISTS and statement.value:
            removed.add(statement.pair(layout))
        else:
            removed |= set(before.under(statement.path_key(layout)))
    return added, removed


def structural_unexpected(
    stage: Stage, layout: Layout, before: StatementSet, after: StatementSet, *, view: str = "raw"
) -> Tuple[str, ...]:
    """SC-06: candidate (or committed) minus before must be exactly the stage's additions, and before
    minus candidate exactly its removals, leaf values included. ``view="effective"`` compares inherited
    views (group layout: expected in direct form). Returns what differs, empty when it matches."""
    if view not in ("raw", "effective"):
        raise InputError("view must be raw or effective")
    layout = stage_layout(stage, layout)
    form = layout if view == "raw" else Layout.DIRECT
    stage_for_view = stage
    if view == "effective":
        stage_for_view = dataclasses.replace(
            stage,
            add=tuple(s for s in stage.add if s.key != APPLY_KEY),
            remove=tuple(s for s in stage.remove if s.key not in (APPLY_KEY, GROUP_KEY)),
        )
    expected_add, expected_remove = _expected_change(stage_for_view, form, before)
    actual_add = set(after.pairs - before.pairs)
    actual_remove = set(before.pairs - after.pairs)
    out: List[str] = []
    for key, value in sorted(actual_add - expected_add):
        out.append(sanitize_display(f"unexpected + {key} {value}".rstrip(), 300))
    for key, value in sorted(expected_add - actual_add):
        out.append(sanitize_display(f"missing + {key} {value}".rstrip(), 300))
    for key, value in sorted(actual_remove - expected_remove):
        out.append(sanitize_display(f"unexpected - {key} {value}".rstrip(), 300))
    for key, value in sorted(expected_remove - actual_remove):
        out.append(sanitize_display(f"missing - {key} {value}".rstrip(), 300))
    return tuple(out)


def _related(path: Tuple[str, ...], root: Tuple[str, ...]) -> bool:
    width = min(len(path), len(root))
    return path[:width] == root[:width]


UNREADABLE_DIFF = (
    "the text diff could not be read (no <configuration-output> text, or empty although the stage changes "
    "something), so a change outside the select-only read cannot be ruled out (R-UNREADABLE)"
)


def headers_outside(stage: Stage, layout: Layout, text_diff: Optional[str]) -> Tuple[str, ...]:
    """SC-06 part 2: every '[edit ...]' header, and the path of every changed line, must lie on the way to
    or under a statement this stage touches. A header above the stage's statements (Junos prints the
    deepest existing parent of a new container) is allowed, and then its changed lines are checked one
    by one, so '[edit system]' cannot carry a 'system login' change. The text is never compared line by
    line with the plan; anything unparsable is reported (fail closed). Returns what is outside.

    The text diff is the only check that sees changes outside the select-only configuration read, so a
    diff that is missing (None: the reply had no text) or empty while the stage adds or removes something
    is itself a failure (spec 8.7 (2) and (4), R-UNREADABLE); the reply's real shape is Q-INST-01's."""
    if not (text_diff or "").strip():
        return (UNREADABLE_DIFF,) if (stage.add or stage.remove) else ()
    assert text_diff is not None  # noqa: S101 - checked just above
    roots = stage_roots(stage, layout)
    delta = parse_patch(text_diff)
    out = [sanitize_display(f"unparsed: {p}", 300) for p in delta.problems]
    for header in delta.headers:
        if not any(_related(header, root) for root in roots):
            out.append(sanitize_display("header [edit " + " ".join(header) + "]", 300))
    for marker, path in delta.changed:
        if not any(_related(path, root) for root in roots):
            out.append(sanitize_display(f"line {marker} " + " ".join(path), 300))
    return tuple(dict.fromkeys(out))


# ------------------------------------------------------------------------------------------------
# Bootstrap (spec 7.7)
# ------------------------------------------------------------------------------------------------


def _bootstrap_warnings(kind: str, adds_language: bool) -> Tuple[str, ...]:
    warnings = ["DEVICE_STATUS"]
    if kind in ("op", "op-url"):
        warnings.append("POSTURE_WARNING" if adds_language else "POSTURE_ALREADY_SET")
    if kind == "netconf":
        warnings.append("NETCONF_WARNING")
    if kind == "op-url":
        warnings.append("ALLOW_URL_WARNING")
    warnings.append("KEEP_SESSION_OPEN")
    return tuple(warnings)


def build_bootstrap(
    method: Method,
    options: Options,
    prior: Optional[PriorState],
    nonce: Optional[str],
    *,
    op_sha256: Optional[str] = None,
) -> Optional[Bootstrap]:
    """The bootstrap a method needs, or None when the device already has it. ``prior`` None means unknown
    (NETCONF is off, so nothing could be read; on-box units published in docs): the language statement
    is then included and the units say to leave it out when it is already set."""
    _require(method in BOOTSTRAP_KIND, f"method {method.value} has no bootstrap")
    kind = BOOTSTRAP_KIND[method]
    comment = bootstrap_comment(kind, nonce)
    adds: List[Statement] = []
    if kind == "netconf":
        statement = make_statement("S8", "bootstrap")
        if prior is not None and prior.has_effective(statement):
            return None
        adds.append(statement)
    else:
        language = make_statement("S1", "bootstrap")
        if prior is None or not prior.has_effective(language):
            adds.append(language)
        if kind == "op":
            last = make_statement("S14", "bootstrap", op_sha256=op_sha256)
        else:
            last = make_statement("S9", "bootstrap")
        if prior is not None and prior.has_effective(last):
            if not adds:
                return None
        else:
            adds.append(last)
    adds_language = any(s.key == "S1" for s in adds)
    return Bootstrap(
        kind=kind,
        method=method,
        add=tuple(adds),
        nonce=nonce,
        comment=comment,
        minutes=options.bootstrap_minutes,
        warnings=_bootstrap_warnings(kind, adds_language),
        user=options.user,
    )


_ROLLBACK_IN_RE = re.compile(r"rollback in (\d{1,5}) ?mins?\b")


def confirmed_minutes(confirmed_state: str) -> Optional[int]:
    """The <n> of 'rollback in <n>mins', as in Juniper's sample 'commit confirmed, rollback in 10mins'
    ([show-system-commit], verified for the CLI). Whether the XML commit-confirmed leaf carries that text,
    and whether <n> is the window or the time left, are Q-INST-01's, so it is only ever quoted back."""
    match = _ROLLBACK_IN_RE.search(confirmed_state or "")
    return int(match.group(1)) if match else None


def recognise_bootstrap(
    prior: PriorState,
    *,
    method: Method,
    user: str,
    nonce: Optional[str],
    delta_text: str,
    op_sha256: Optional[str] = None,
    minutes: Optional[int] = None,
) -> Optional[Bootstrap]:
    """The installer's own unconfirmed bootstrap, or None (then the pending commit is R-PENDING).

    Exactly: the newest history entry has commit-confirmed set, is by ``user``, carries the comment
    'jwicket-bootstrap <kind>[ <nonce>]' (in comment or log), nothing is scheduled or prepared, and the
    entry's committed delta adds exactly the bootstrap's statements (the language statement optional for
    the on-box kinds) and removes nothing. ``delta_text`` is that delta in patch form, '+' meaning added by
    the newest commit: get-rollback-information with rollback 1 (the base) and compare 0 ([netconf-pdf],
    verified direction; the reply shape is Q-INST-01's).
    Cut C5: this narrow exception to R-PENDING is an owner decision open for veto."""
    if method not in BOOTSTRAP_KIND:
        return None
    kind = BOOTSTRAP_KIND[method]
    try:
        expected_comment = bootstrap_comment(kind, nonce)
        validate_user(user)
        if op_sha256 is not None:
            validate_sha256(op_sha256, "op script SHA-256")
    except InputError:
        return None
    newest = prior.newest
    if (
        prior.pending is not Pending.OTHER
        or prior.scheduled_commit
        or prior.prepared_commit
        or newest is None
        or not newest.pending_confirm
        or newest.user != user
        or expected_comment not in newest.texts
    ):
        return None
    delta = parse_patch(delta_text)
    if delta.problems or delta.removed or not delta.added:
        return None
    if kind == "netconf":
        required = {make_statement("S8", "bootstrap")}
        optional: Set[Statement] = set()
    else:
        optional = {make_statement("S1", "bootstrap")}
        if kind == "op":
            if op_sha256 is None:
                op_value = next((v for k, v in delta.added if statement_key_of(k) == "S14"), None)
                if op_value is None or SHA256_RE.match(op_value) is None:
                    return None
                op_sha256 = op_value
            required = {make_statement("S14", "bootstrap", op_sha256=op_sha256)}
        else:
            required = {make_statement("S9", "bootstrap")}
    allowed = {s.pair() for s in required | optional}
    if not delta.added <= allowed:
        return None
    # The required statement must now be committed; it is in the delta unless it was already there.
    if not all(prior.has_effective(s) for s in required):
        return None
    adds = tuple(
        sorted(
            (s for s in required | optional if s.pair() in delta.added), key=lambda s: list(SPEC_BY_KEY).index(s.key)
        )
    )
    if not all(prior.has_effective(s) for s in adds):
        return None
    return Bootstrap(
        kind=kind,
        method=method,
        add=adds,
        nonce=nonce,
        comment=expected_comment,
        minutes=10 if minutes is None else minutes,
        warnings=_bootstrap_warnings(kind, any(s.key == "S1" for s in adds)),
        user=user,
        rollback_in=confirmed_minutes(newest.confirmed_state),
    )


def own_bootstrap_pending(
    prior: PriorState,
    *,
    method: Method,
    user: str,
    nonce: Optional[str],
    delta_text: str,
    op_sha256: Optional[str] = None,
) -> bool:
    return (
        recognise_bootstrap(prior, method=method, user=user, nonce=nonce, delta_text=delta_text, op_sha256=op_sha256)
        is not None
    )


def mark_own_bootstrap(prior: PriorState, bootstrap: Bootstrap) -> PriorState:
    """The prior state with its pending commit recognised as the installer's own bootstrap."""
    _require(prior.pending is Pending.OTHER, "only a pending confirmed commit can be the own bootstrap")
    return dataclasses.replace(prior, pending=Pending.OWN_BOOTSTRAP, own_bootstrap=bootstrap)


# ------------------------------------------------------------------------------------------------
# Ownership (INV-11, spec 7.9)
# ------------------------------------------------------------------------------------------------


def ownership_from_history(
    history: Sequence[CommitEntry], deltas: Mapping[int, str], *, user: Optional[str] = None
) -> OwnershipEvidence:
    """Replay the installer's own commits, oldest first: an entry counts when its comment or log is an
    installer comment (and, with ``user``, it was committed by that account) and its committed delta
    ('show system rollback <n+1> compare <n>': the older configuration is the base, so in patch form '+'
    is what entry n added, [netconf-pdf], verified; the reply shape is Q-INST-01's) was read
    and parses. Other commits are ignored; a delta that does not parse is not evidence."""
    net: Set[Pair] = set()
    sequences: List[int] = []
    for entry in sorted(history, key=lambda e: e.sequence, reverse=True):
        if not any(is_installer_comment(t) for t in entry.texts):
            continue
        if user is not None and entry.user != user:
            continue
        delta_text = deltas.get(entry.sequence)
        if delta_text is None:
            continue
        delta = parse_patch(delta_text)
        if delta.problems:
            continue
        net -= set(delta.removed)
        net |= set(delta.added)
        sequences.append(entry.sequence)
    return OwnershipEvidence(bool(sequences), frozenset(net), tuple(sequences))


def _receipt_added(receipt: Optional[Receipt]) -> FrozenSet[str]:
    if receipt is None:
        return frozenset()
    return frozenset({*receipt.statements_added, *receipt.bootstrap_added})


def _owned_shared(key: str, evidence: OwnershipEvidence, prior: PriorState) -> Tuple[bool, str]:
    """Spec 7.9: history and workstation record agree, or (history unavailable) both receipts agree."""
    ws = key in _receipt_added(prior.workstation_receipt)
    dev = key in _receipt_added(prior.device_receipt)
    if key in (prior.workstation_receipt.statements_present_before if prior.workstation_receipt else ()):
        return False, "present before install (workstation record)"
    if evidence.history_available:
        history = key in evidence.keys
        if history and ws:
            return True, "history and workstation record agree"
        return False, (
            f"sources disagree: history says {'added' if history else 'not added'}, workstation record says "
            f"{'added' if ws else 'not added'}"
        )
    if ws and dev:
        return True, "history unavailable; both receipts agree"
    return False, (
        f"history unavailable; workstation record says {'added' if ws else 'not added'}, device receipt "
        f"(advisory) says {'added' if dev else 'not added'}"
    )


def _stanza_owned(name: str, evidence: OwnershipEvidence, prior: PriorState) -> bool:
    keys = {s.key for s in STATEMENT_TABLE if s.stanza is not None and STANZA_KEYS[s.stanza][-1] == name}
    return bool(keys & evidence.keys) or bool(keys & _receipt_added(prior.workstation_receipt))


# ------------------------------------------------------------------------------------------------
# Building the install plan
# ------------------------------------------------------------------------------------------------


def _version_at_least(version: Optional[str], major: int, minor: int, release: int) -> Optional[bool]:
    if version is None:
        return None
    match = re.match(r"^([0-9]{1,2})\.([0-9])R([0-9]+)", version)
    if match is None:
        return None
    found = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    return found >= (major, minor, release)


def _file_matches(prior: PriorState, path: str, sha: Optional[str], owner: str, mode: int) -> bool:
    info = prior.files.get(path)
    if info is None or info.is_dir or info.is_symlink or info.owner != owner or info.mode != mode:
        return False
    return sha is None or prior.checksums.get(path) == sha


def state_dir_untrusted(info: FileInfo, user: str) -> Optional[str]:
    """Why the listed /var/db/jwicket fails the trust rule (R4), or None when it passes: a directory, not
    a symbolic link, owned by the daemon account, mode 0700 (so not group- or other-writable, the daemon's
    own rule, and private). The one copy of the rule: the plan and the executors' re-read after the gate
    use it (SPEC-05)."""
    if info.is_symlink:
        return f"{STATE_DIR} is a symbolic link"
    if not info.is_dir:
        return f"{STATE_DIR} is not a directory"
    if info.owner != user:
        return f"{STATE_DIR} is owned by {info.owner or 'an unknown account'}, not {user}"
    if info.mode != 0o700:
        shown = "unknown" if info.mode is None else f"{info.mode:04o}"
        return f"{STATE_DIR} has mode {shown}, not 0700"
    return None


def _state_dir_status(prior: PriorState, user: str) -> Tuple[str, str]:
    """('absent' | 'trusted' | 'untrusted' | 'unknown', why), from the read-only listings of /var/db and
    /var/db/jwicket, by state_dir_untrusted's rule."""
    info = prior.files.get(STATE_DIR)
    listing = prior.directories.get(VAR_DB)
    if info is None:
        if listing == "listed" or prior.directories.get(STATE_DIR) == "absent":
            return "absent", f"{STATE_DIR} is absent"
        return "unknown", f"listing of {VAR_DB}"
    why = state_dir_untrusted(info, user)
    return ("trusted", "") if why is None else ("untrusted", why)


def _platform_refusals(facts: DeviceFacts, prior: PriorState, overrides: FrozenSet[str]) -> Tuple[List[Refusal], bool]:
    """R-MODEL (with R5's --lab-hardware for a physical SRX only), R-CLUSTER, R-MNHA, R-DUAL-RE, R-FIPS.
    Returns the refusals and whether this is lab hardware the operator must attest to ('lab only')."""
    out: List[Refusal] = []
    no_hardware = frozenset(overrides) - {LAB_HARDWARE_FLAG}
    hardware = False
    model = facts.model
    if model is None or VSRX_MODEL_RE.match(model) is None:
        if model is not None and SRX_HARDWARE_MODEL_RE.match(model) is not None and facts.srx_cluster is not None:
            hardware = True
            out.append(make_refusal("R-MODEL", f"model: {model}, a physical SRX", overrides))
        else:
            out.append(
                make_refusal(
                    "R-MODEL",
                    f"model: {model or 'not reported'}; not an SRX: --lab-hardware does not apply",
                    no_hardware,
                )
            )
    elif facts.srx_cluster is None:
        out.append(
            make_refusal(
                "R-MODEL",
                "chassis cluster status: not answered as an SRX answers it; --lab-hardware does not apply",
                no_hardware,
            )
        )
    if facts.srx_cluster:
        out.append(make_refusal("R-CLUSTER", "", overrides))
    if facts.mnha or prior.mnha_configured:
        out.append(make_refusal("R-MNHA", "", overrides))
    # A vSRX has one routing engine (inferred), so an unread count is accepted there; hardware may have two.
    if facts.routing_engines is not None and facts.routing_engines > 1:
        out.append(make_refusal("R-DUAL-RE", f"routing engines: {facts.routing_engines}", overrides))
    elif hardware and facts.routing_engines is None:
        out.append(make_refusal("R-DUAL-RE", "routing engines: not read, on hardware", overrides))
    if facts.fips_configured or prior.fips_configured:
        out.append(make_refusal("R-FIPS", "", overrides))
    return out, hardware and LAB_HARDWARE_FLAG in overrides


def _bind_refusal(options: Options, overrides: FrozenSet[str]) -> Optional[Refusal]:
    """R-BIND: --access tls never listens on a wildcard, loopback, multicast, link-local or reserved address,
    nor on an IPv6 address (SEC-R3, SPEC-07: INV-10 and spec 8.10 take IPv4 only, as --host and the Ansible
    play do; the lab run listened on IPv4)."""
    if not options.tls:
        return None
    address = ipaddress.ip_address(options.bind_address)
    kinds = (
        ("an IPv6 address (the installers take IPv4 only; IPv6 is unverified, Q-NET-01)", address.version == 6),
        ("a wildcard", address.is_unspecified),
        ("loopback (use --access tunnel)", address.is_loopback),
        ("multicast", address.is_multicast),
        ("link-local", address.is_link_local),
        ("reserved", address.is_reserved),
    )
    for kind, hit in kinds:
        if hit:
            return make_refusal("R-BIND", f"--listen-address {address} is {kind}", overrides)
    return None


def required_modules(options: Options) -> Tuple[str, ...]:
    """What C3 requires: the backend's modules, and ssl with --access tls."""
    return (*REQUIRED_MODULES[options.backend], *ACCESS_MODULES[options.access])


def recorded_modules(options: Options) -> Tuple[str, ...]:
    """What C3 records without requiring it (ssl with --access tunnel)."""
    required = set(required_modules(options))
    return tuple(m for m in RECORDED_MODULES if m not in required)


def start_line(bundle: BundleId, options: Options, routing_instance: Optional[str]) -> Tuple[str, str]:
    """C4's (line, build) of app.py's start line: 'listening on <bind>:<port> tls=<bool> backend=<b>
    routing_instance=<instance or default>' and, with D3, 'version=<v> payload=<16 hex>'. A bundle without
    D3 may predate the routing_instance field, so only the prefix up to the backend is expected then."""
    prefix = f"listening on {options.bind_address}:{options.port} tls={options.tls} backend={options.backend}"
    if not bundle.has("build-line"):
        return prefix, ""
    return (
        f"{prefix} routing_instance={routing_instance or 'default'}",
        f"version={bundle.version} payload={bundle.payload_short}",
    )


def _c8(bundle: BundleId, options: Options, method: Method) -> Check:
    """R3: HTTPS from the workstation, pinned to the generated certificate; never through an SSH channel."""
    build = bundle.payload_short if bundle.has("build-line") else ""
    if not options.tls:
        return _check(
            "C8",
            "not-available",
            {"access": "tunnel", "if_unavailable": "not-available", "reason": TUNNEL_C8_REASON},
            required=False,
        )
    address = options.bind_address
    expect = {
        "access": "tls",
        "url": listen_url(address, options.port) + "api/session",
        "host": host_port(address, options.port),
        "pin": "tls_cert_sha256",
        "status": "200",
        "version": bundle.version,
        "build": build,
    }
    if method in NETCONF_METHODS:
        expect.update({"from": "workstation", "if_unavailable": "fail"})
        return _check("C8", expect["url"], expect, timeout_s=TIMEOUTS["http"])
    if method is Method.CLI:
        expect.update({"from": "operator", "if_unavailable": "by-hand"})
        return _check("C8", expect["url"], expect, timeout_s=TIMEOUTS["http"], required=False)
    # An on-box installer has no workstation, and whether an op script reaches a mgmt_junos address is
    # unknown: the operator browses there and compares the fingerprint (the ONBOX package's own check).
    expect.update({"from": "operator", "if_unavailable": "not-available"})
    return _check("C8", expect["url"], expect, timeout_s=TIMEOUTS["http"], required=False)


def _checks_for(
    name: str,
    bundle: BundleId,
    options: Options,
    comment: str,
    overrides: FrozenSet[str],
    removed_keys: Sequence[str] = (),
    *,
    method: Method = Method.WORKSTATION,
    routing_instance: Optional[str] = None,
) -> Tuple[Check, ...]:
    user = options.user
    c10 = _check("C10", name, {"structural": "exact", "headers": "stage-roots"})
    c11 = _check(
        "C11",
        name,
        {"newest_user": user, "newest_comment": comment, "pending_commit": "absent", "prepared_commit": "absent"},
    )
    results = bundle.has("result-files")
    unchecked = "yes" if "--accept-unchecked-diagnostics" in overrides else "no"
    if name == "diagnostics":
        source = "result-file" if results else "start-output"
        return (
            _check(
                "C2",
                SELFTEST_RESULT_PATH if results else f"extension-service-start {SELFTEST_FILE}",
                {
                    "ok": "true",
                    "version": bundle.version,
                    "payload_sha256": bundle.payload_sha256,
                    "source": source,
                    "delete_before_start": "yes" if results else "no",
                    "unchecked_override": unchecked,
                },
            ),
            _check(
                "C3",
                PROBE_RESULT_PATH if results else f"extension-service-start {PROBE_FILE}",
                {
                    "modules": ",".join(required_modules(options)),
                    "recorded": ",".join(recorded_modules(options)),
                    "source": source,
                    "delete_before_start": "yes" if results else "no",
                    "unchecked_override": unchecked,
                },
            ),
            c10,
            c11,
        )
    if name == "runtime":
        build = bundle.has("build-line")
        line, build_text = start_line(bundle, options, routing_instance)
        checks = [
            _check(
                "C4",
                LOG_PATH,
                {"line": line, "build": build_text, "count": "1", "poll_s": "5"},
                timeout_s=TIMEOUTS["health-poll"],
            ),
            _check(
                "C5",
                AUDIT_PATH,
                {
                    "event": "start",
                    "version": bundle.version,
                    "payload_sha256": bundle.payload_sha256 if build else "",
                    "count": "1",
                },
            ),
            _check("C6", STARTUP_REFUSED_PATH, {"present": "false", "delete_before_commit": "yes"}),
            _check("C7", DAEMON_FILE, {"interval_s": "30", "reads": "2"}, timeout_s=60),
            _c8(bundle, options, method),
        ]
        return (*checks, c10, c11)
    if name in ("netconf-removal", "revert", "uninstall"):
        return (_check("C12", name, {"keys": ",".join(removed_keys)}), c10, c11)
    return (c10, c11)


def _status_checks(
    bundle: BundleId, options: Options, method: Method, routing_instance: Optional[str]
) -> Tuple[Check, ...]:
    checks = _checks_for(
        "runtime", bundle, options, "status", frozenset(), method=method, routing_instance=routing_instance
    )
    return tuple(c for c in checks if c.id in ("C4", "C5", "C6", "C7", "C8"))


def _stage(
    name: str,
    bundle: BundleId,
    options: Options,
    add: Sequence[Statement],
    remove: Sequence[Statement],
    overrides: FrozenSet[str],
    *,
    before: Sequence[FileStep] = (),
    after: Sequence[FileStep] = (),
    restore: Sequence[FileStep] = (),
    method: Method = Method.WORKSTATION,
    routing_instance: Optional[str] = None,
) -> Stage:
    comment = stage_comment(bundle, name)
    removed_keys = [s.key for s in remove if s.path not in {a.path for a in add}]
    return Stage(
        name=name,
        add=tuple(add),
        remove=tuple(remove),
        files_before_commit=tuple(before),
        comment=comment,
        confirm_comment=stage_comment(bundle, name, confirmed=True),
        confirm_minutes=Minutes(options.confirm_minutes),
        checks=_checks_for(
            name, bundle, options, comment, overrides, removed_keys, method=method, routing_instance=routing_instance
        ),
        files_after_confirm=tuple(after),
        restore_on_failure=tuple(restore),
    )


def _production_signs(facts: DeviceFacts, prior: PriorState) -> Tuple[str, ...]:
    """Shown before the gate, never judged (spec 8.2), and before R5's 'lab only' attestation: model,
    release, serial, flow sessions, central-manager outbound-ssh client names, committers and the last
    commit time. Never the host name."""
    signs = [
        f"model: {facts.model or 'unknown'}",
        f"release: {facts.junos_version or 'unknown'}",
        f"serial: {facts.serial or 'unknown'}",
        f"active flow sessions: {facts.flow_sessions if facts.flow_sessions is not None else 'not read'}",
        f"outbound-ssh clients: {len(prior.outbound_ssh_clients)}",
    ]
    signs.extend(f"outbound-ssh client: {name}" for name in prior.outbound_ssh_clients)
    users = sorted({e.user for e in prior.history if e.user})
    signs.append(f"distinct committers in history: {len(users)}")
    if users:
        signs.append("committers: " + ", ".join(users[:10]) + (", ..." if len(users) > 10 else ""))
    newest = prior.newest
    if newest is not None and newest.date_time:
        signs.append(f"last commit: {newest.date_time}")
    return tuple(signs)


def _utc(text: str, what: str) -> datetime.datetime:
    _require(TIME_RE.match(text) is not None, f"{what} is not YYYY-MM-DDTHH:MM:SSZ")
    return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")


def utc_now_text() -> str:
    """The current UTC time as YYYY-MM-DDTHH:MM:SSZ (the receipt's form)."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def certificate_expiry(not_after: Optional[str], now: Optional[str] = None) -> Optional[str]:
    """A warning when a recorded certificate has expired or expires within TLS_RENEW_DAYS of ``now``
    (UTC text; the current time when None), else None. A record without notAfter gives None: nothing to
    judge (an operator-made pair's expiry is the operator's, deploy-lab's TLS unit)."""
    if not_after is None:
        return None
    end = _utc(not_after, "certificate notAfter")
    at = _utc(now or utc_now_text(), "the current time")
    if end <= at:
        return f"the TLS certificate expired on {not_after}: 'install --apply' makes a new pair"
    if end - at <= datetime.timedelta(days=TLS_RENEW_DAYS):
        return f"the TLS certificate expires on {not_after}: 'install --apply' makes a new pair"
    return None


def certificate_expired(not_after: Optional[str], now: Optional[str] = None) -> bool:
    """Whether a recorded notAfter is at or before ``now`` (the current UTC time when None)."""
    if not_after is None:
        return False
    return _utc(not_after, "certificate notAfter") <= _utc(now or utc_now_text(), "the current time")


def tls_renewal(previous: Optional[Receipt], cert_file_sha256: Optional[str], now: Optional[str]) -> Optional[str]:
    """The warning id when the recorded TLS pair must not be kept (SEC-R1, OPX-04), else None: the record
    names no notAfter or file SHA-256, the device's tls.crt (``cert_file_sha256``, read with
    get-sha256-checksum-information; None when unread) is not the recorded file, or the certificate is
    within TLS_RENEW_DAYS of its notAfter or past it."""
    if previous is None or previous.tls_cert_not_after is None or previous.tls_cert_file_sha256 is None:
        return "TLS_RENEW_CHANGED"
    if cert_file_sha256 is None or cert_file_sha256 != previous.tls_cert_file_sha256:
        return "TLS_RENEW_CHANGED"
    if certificate_expiry(previous.tls_cert_not_after, now) is not None:
        return "TLS_RENEW_EXPIRY"
    return None


def build_install_plan(
    bundle: BundleId,
    provenance: Provenance,
    options: Options,
    facts: DeviceFacts,
    prior: PriorState,
    *,
    method: Method,
    overrides: FrozenSet[str] = frozenset(),
    evidence: Optional[OwnershipEvidence] = None,
    op_sha256: Optional[str] = None,
    offline: bool = False,
    now: Optional[str] = None,
) -> InstallPlan:
    """Plan an install, upgrade, repair or idempotent re-run (spec 7, 8.11, 8.12, 9.2, 9.4).

    Refusals are computed, not raised: ``plan.blocked`` tells. ``evidence`` (from ownership_from_history)
    tells which jwicket stanzas this installer added (R-FOREIGN otherwise). ``offline`` is for the CLI
    renderer without --host: facts unknown, prior ``PriorState.fresh()``, the units stamped OFFLINE_STAMP.
    A pending own bootstrap must already be in ``prior`` (mark_own_bootstrap); it becomes the first stage.
    ``prior.checksums`` must hold the device's SHA-256 of every J-Wicket JET file and of SETTINGS_PATH
    that is listed (get-sha256-checksum-information); a configured J-Wicket file without one refuses.
    ``prior.checksums`` should also hold TLS_CERT_PATH's: a recorded TLS pair is kept only while the
    device's tls.crt has the recorded file SHA-256 and the certificate's notAfter is more than
    TLS_RENEW_DAYS after ``now`` (YYYY-MM-DDTHH:MM:SSZ, UTC; the current time when None).
    """
    unknown_flags = set(overrides) - OVERRIDES
    _require(not unknown_flags, f"unknown override(s): {', '.join(sorted(unknown_flags))}")
    _require(method is not Method.ZTP, "ZTP is documented only (cut C3): there is no ZTP installer")
    _require(not options.tls or options.listen_address is not None, LISTEN_ADDRESS_REQUIRED)
    _require(not offline or method is Method.CLI, "only the CLI renderer plans offline")
    if op_sha256 is not None:
        validate_sha256(op_sha256, "op script SHA-256")
    has_op_stanza = bool(prior.effective.under(" ".join(_OPF)))
    _require(
        method is not Method.ONBOX_LOCAL or op_sha256 is not None or prior.own_bootstrap is not None or has_op_stanza,
        "the on-box installer needs its own SHA-256 (statement S14)",
    )
    evidence = evidence or OwnershipEvidence.none()
    user = options.user
    layout = options.layout
    refusals: List[Refusal] = []

    def refuse(code: str, detail: str = "") -> None:
        refusals.append(make_refusal(code, detail, overrides))

    # -- facts (8.2, 8.11) -----------------------------------------------------------------------
    lab_hardware = False
    if not offline:
        if facts.hostname is None:
            refuse("R-NOHOST")
        platform, lab_hardware = _platform_refusals(facts, prior, frozenset(overrides))
        refusals.extend(platform)
    bind = _bind_refusal(options, frozenset(overrides))
    if bind is not None:
        refusals.append(bind)
    if user == "root":
        refuse("R-ROOT", "--user root")
    own_names = (*JWICKET_JET_FILES, STAGING_FILE, BACKUP_FILE)
    for listed_path, listed in sorted(prior.files.items()):
        parent, _, base = listed_path.rpartition("/")
        ours = (parent == JET_DIR and base in own_names) or listed_path == OP_PATH or parent == STATE_DIR
        if ours and listed.owner == "root":
            refuse("R-ROOT", f"{listed_path} is owned by root")
    if prior.unreadable:
        refuse("R-UNREADABLE", "not read: " + ", ".join(prior.unreadable))
    if prior.load_scripts_from_flash:
        refuse("R-FLASH")
    if prior.language not in (None, "python3"):
        refuse("R-LANG", f"language: {prior.language}")
    own = prior.own_bootstrap
    if prior.pending in (Pending.OTHER, Pending.UNREADABLE):
        refuse("R-PENDING", f"commit state: {prior.pending.value}")
    elif prior.scheduled_commit or prior.prepared_commit:
        refuse("R-PENDING", "a 'commit at' or 'commit prepare' is pending")
    elif own is not None and own.kind != BOOTSTRAP_KIND.get(method):
        refuse("R-PENDING", f"the pending bootstrap is a {own.kind} bootstrap, not this method's")
    if options.port in (*prior.web_ports, *prior.rest_ports):
        refuse("R-PORT", f"port {options.port}")
    if prior.outbound_ssh_clients:
        refuse("R-MANAGED", f"outbound-ssh clients: {len(prior.outbound_ssh_clients)}")
    if prior.commit_scripts:
        refuse("R-COMMIT-SCRIPTS", f"commit scripts: {len(prior.commit_scripts)}")
    if method is not Method.CLI and prior.veriexec != VERIEXEC_ENFORCING:
        refuse("R-VERIEXEC", f"veriexec: {prior.veriexec or 'not read'}")
    refresh_https = options.transfer == "refresh-from" and str(options.pull_url).startswith("https://")
    if refresh_https and not offline and _version_at_least(facts.junos_version, 21, 2, 1) is not True:
        refuse("R-RELEASE", f"release: {facts.junos_version or 'not read'}")
    if provenance.kind in NO_EVIDENCE_PROVENANCE:
        refuse("R-PROVENANCE", f"provenance: {provenance.kind}")
    # R4: the directory is root's to make, once; the installer only reads /var/db and /var/db/jwicket.
    state_dir, state_dir_why = ("offline", "") if offline else _state_dir_status(prior, user)
    if state_dir in ("absent", "untrusted"):
        refuse("R-STATEDIR", f"{state_dir_why}; as root, once: {state_dir_root_step(user)}")
    elif state_dir == "unknown":
        refuse("R-UNREADABLE", state_dir_why)
    routing_instance = MGMT_INSTANCE if options.tls and prior.management_instance else None

    stanzas = prior.jwicket_stanzas
    for name in sorted(stanzas):
        if not _stanza_owned(name, evidence, prior):
            refuse("R-FOREIGN", f"stanza {name}")
    group_pairs = prior.direct.under("groups jwicket")
    if group_pairs and not group_pairs <= evidence.added:
        refuse("R-FOREIGN", "groups jwicket holds statements the ownership sources did not add")
    for name in sorted(stanzas):
        for value in prior.effective.values(" ".join((*_EXT, name, "username"))):
            if value != user:
                refuse("R-USER", f"stanza {name} username {value}")

    # -- statements ---------------------------------------------------------------------------------
    def wanted(key: str, stage: str) -> Statement:
        return make_statement(key, stage, user=user, bundle_sha256=bundle.file_sha256, op_sha256=op_sha256)

    def change(key: str, stage: str, adds: List[Statement], removes: List[Statement]) -> None:
        statement = wanted(key, stage)
        if prior.has_effective(statement):
            return
        adds.append(statement)
        for old in prior.effective_values(statement.path):
            if old != (statement.value or "") and TOKEN_RE.match(old) is not None:
                removes.append(make_statement(key, stage, value=old))

    stages: List[Stage] = []
    if own is not None:
        stages.append(
            Stage(
                name="bootstrap",
                add=own.add,
                remove=(),
                files_before_commit=(),
                comment=own.comment,
                confirm_comment=own.confirm_comment,
                confirm_minutes=Minutes(own.minutes),
                checks=(
                    _check("K1", "commit-history", {"newest_user": own.user, "newest_comment": own.comment}),
                    _check("K2", "executor", {"connected": "yes"}),
                    _check("C10", "bootstrap", {"structural": "exact", "headers": "stage-roots"}),
                    _check(
                        "C11",
                        "bootstrap",
                        {
                            "newest_user": own.user,
                            "newest_comment": own.comment,
                            "pending_commit": "absent",
                            "prepared_commit": "absent",
                        },
                    ),
                ),
                already_committed=True,
            )
        )

    diag_add: List[Statement] = []
    diag_remove: List[Statement] = []
    change("S1", "diagnostics", diag_add, diag_remove)
    for key in ("S2", "S3", "S4", "S5"):
        if key in ("S3", "S5") and not options.jet_checksum:
            continue
        change(key, "diagnostics", diag_add, diag_remove)
    if method in (*ONBOX_METHODS, Method.CLI) and options.backend == "netconf":
        change("S8", "diagnostics", diag_add, diag_remove)

    run_add: List[Statement] = []
    run_remove: List[Statement] = []
    for key in ("S10", "S11", "S12", "S13"):
        if key == "S13" and not options.jet_checksum:
            continue
        change(key, "runtime", run_add, run_remove)
    if method is Method.ONBOX_URL and own is not None and "S9" in own.keys:
        run_remove.append(make_statement("S9", "runtime"))
    if not options.keep_diagnostics:
        for stanza in ("F-SELFTEST", "F-PROBE"):
            run_remove.append(make_statement(stanza, "runtime"))

    if layout is Layout.GROUP and (diag_add or run_add) and ("apply-groups", GROUP_NAME) not in prior.direct.pairs:
        (diag_add if diag_add else run_add).append(make_statement(APPLY_KEY, "diagnostics" if diag_add else "runtime"))

    # -- files (7.5, 9.2 A3-A5, 9.4; INV-06) ------------------------------------------------------
    files: List[FileStep] = []
    directory = FileStep(
        STATE_DIR, "directory", 0o700, None, "keep" if state_dir == "trusted" else "require", "files", owner=user
    )
    source = "workstation" if options.transfer == "scp" else str(options.pull_url)
    sha = bundle.file_sha256
    checksum_key = {DAEMON_FILE: "S13", SELFTEST_FILE: "S3", PROBE_FILE: "S5"}
    before: Dict[str, List[FileStep]] = {"diagnostics": [], "runtime": []}
    after: Dict[str, List[FileStep]] = {"diagnostics": [], "runtime": []}
    restore: Dict[str, List[FileStep]] = {"diagnostics": [], "runtime": []}
    copies: List[FileStep] = []
    upgrade = False
    for name in JWICKET_JET_FILES:
        path = f"{JET_DIR}/{name}"
        info = prior.files.get(path)
        configured = name in prior.jet_files
        if configured and path not in prior.checksums:
            refuse("R-UNREADABLE", f"SHA-256 of {path}")
            continue
        if _file_matches(prior, path, sha, user, 0o644):
            copies.append(FileStep(path, "bundle", 0o644, sha, "keep", "files", owner=user))
            continue
        if not configured:
            copies.append(FileStep(path, "bundle", 0o644, sha, "copy", "files", source=STAGING_PATH, owner=user))
            continue
        # A configured file with other bytes: replaced only inside the stage whose confirmed commit
        # changes its checksum (INV-06), with the old bytes restorable by copy.
        upgrade = upgrade or prior.checksums.get(path) != sha
        if info is not None and (info.owner != user or info.mode != 0o644):
            refuse("R-USER", f"{path} is not mode 644 owned by {user}")
        if not options.jet_checksum:
            refuse("R-UPGRADE-NOCHECKSUM", f"{path} differs from this bundle")
            continue
        pinned = prior.effective.values(" ".join(SPEC_BY_KEY[checksum_key[name]].path))
        if pinned == (sha,):
            refuse("R-MISMATCH", f"{path}")
            continue
        stage_name = "runtime" if name == DAEMON_FILE else "diagnostics"
        old = prior.checksums.get(path)
        if name == DAEMON_FILE:
            before["runtime"].append(
                FileStep(
                    BACKUP_PATH, "bundle", 0o644, old, "backup", "pre-commit", stage="runtime", source=path, owner=user
                )
            )
            restore["runtime"].append(
                FileStep(
                    path, "bundle", 0o644, old, "restore", "on-failure", stage="runtime", source=BACKUP_PATH, owner=user
                )
            )
            after["runtime"].append(
                FileStep(BACKUP_PATH, "any", 0o644, None, "delete", "post-confirm", stage="runtime")
            )
        else:
            daemon_old = prior.checksums.get(DAEMON_PATH)
            restore["diagnostics"].append(
                FileStep(
                    path,
                    "bundle",
                    0o644,
                    daemon_old,
                    "restore",
                    "on-failure",
                    stage="diagnostics",
                    source=DAEMON_PATH,
                    owner=user,
                )
            )
        before[stage_name].append(
            FileStep(
                path, "bundle", 0o644, sha, "replace", "pre-commit", stage=stage_name, source=STAGING_PATH, owner=user
            )
        )
    staging_needed = any(c.action == "copy" for c in copies) or bool(before["diagnostics"] or before["runtime"])
    if staging_needed:
        files.append(FileStep(STAGING_PATH, "bundle", 0o644, sha, "stage", "files", source=source, owner=user))
    files.extend(copies)
    if staging_needed:
        if any(s.action == "replace" for s in before["runtime"]):
            after["runtime"].append(
                FileStep(STAGING_PATH, "any", 0o644, None, "delete", "post-confirm", stage="runtime")
            )
        elif before["diagnostics"]:
            after["diagnostics"].append(
                FileStep(STAGING_PATH, "any", 0o644, None, "delete", "post-confirm", stage="diagnostics")
            )
        else:
            files.append(FileStep(STAGING_PATH, "any", 0o644, None, "delete", "files"))

    settings_sha = settings_sha256(options, routing_instance=routing_instance)
    if _file_matches(prior, SETTINGS_PATH, settings_sha, user, 0o600):
        files.append(FileStep(SETTINGS_PATH, "settings", 0o600, settings_sha, "keep", "files", owner=user))
    else:
        if SETTINGS_PATH in prior.files:
            files.append(
                FileStep(
                    SETTINGS_PREV_PATH,
                    "settings",
                    0o600,
                    prior.checksums.get(SETTINGS_PATH),
                    "backup",
                    "files",
                    source=SETTINGS_PATH,
                    owner=user,
                )
            )
            restore["runtime"].append(
                FileStep(
                    SETTINGS_PATH,
                    "settings",
                    0o600,
                    prior.checksums.get(SETTINGS_PATH),
                    "restore",
                    "on-failure",
                    stage="runtime",
                    source=SETTINGS_PREV_PATH,
                    owner=user,
                )
            )
        files.append(
            FileStep(SETTINGS_PATH, "settings", 0o600, settings_sha, "write", "files", source="workstation", owner=user)
        )
    previous = prior.workstation_receipt
    tls_cert_sha: Optional[str] = None
    tls_not_after: Optional[str] = None
    tls_file_sha: Optional[str] = None
    tls_warnings: List[str] = []
    if options.tls:
        # The pair is kept only when this workstation's record says this installer made it for the same
        # address (its SHA-256 is then the C8 pin); otherwise a new pair is generated and uploaded.
        same = (
            previous is not None
            and previous.access == "tls"
            and previous.listen_address == options.listen_address
            and previous.tls_cert_sha256 is not None
        )
        files_ok = _file_matches(prior, TLS_KEY_PATH, None, user, TLS_KEY_MODE) and _file_matches(
            prior, TLS_CERT_PATH, None, user, TLS_CERT_MODE
        )
        renew = tls_renewal(previous, prior.checksums.get(TLS_CERT_PATH), now) if same and files_ok else None
        pair_ok = same and files_ok and renew is None
        if renew is not None:
            tls_warnings.append(renew)
        if pair_ok and previous is not None:
            tls_cert_sha = previous.tls_cert_sha256
            tls_not_after = previous.tls_cert_not_after
            tls_file_sha = previous.tls_cert_file_sha256
        if method in NETCONF_METHODS:
            tls_source = "in-memory"
        elif method is Method.CLI:
            tls_source = "device-openssl"
        else:
            tls_source = "op-script"
        for path, content, mode in (
            (TLS_KEY_PATH, "tls-key", TLS_KEY_MODE),
            (TLS_CERT_PATH, "tls-cert", TLS_CERT_MODE),
        ):
            files.append(
                FileStep(
                    path,
                    content,
                    mode,
                    None,
                    "keep" if pair_ok else "write",
                    "files",
                    source=None if pair_ok else tls_source,
                    owner=user,
                )
            )
    if options.backend == "lab-token":
        token_ok = _file_matches(prior, LAB_TOKEN_PATH, None, user, 0o600)
        files.append(
            FileStep(
                LAB_TOKEN_PATH,
                "lab-token",
                0o600,
                None,
                "keep" if token_ok else "write",
                "files",
                source=None if token_ok else "workstation",
                owner=user,
            )
        )
    if not options.keep_diagnostics:
        for name in DIAGNOSTIC_FILES:
            after["runtime"].append(
                FileStep(f"{JET_DIR}/{name}", "any", 0o644, None, "delete", "post-confirm", stage="runtime")
            )

    if diag_add or diag_remove or before["diagnostics"]:
        stages.append(
            _stage(
                "diagnostics",
                bundle,
                options,
                diag_add,
                diag_remove,
                overrides,
                before=before["diagnostics"],
                after=after["diagnostics"],
                restore=restore["diagnostics"],
            )
        )
    if run_add or run_remove or before["runtime"]:
        stages.append(
            _stage(
                "runtime",
                bundle,
                options,
                run_add,
                run_remove,
                overrides,
                before=before["runtime"],
                after=after["runtime"],
                restore=restore["runtime"],
                method=method,
                routing_instance=routing_instance,
            )
        )
    if own is not None and "S8" in own.keys and options.remove_netconf:
        stages.append(
            _stage("netconf-removal", bundle, options, (), (make_statement("S8", "netconf-removal"),), overrides)
        )

    # -- warnings (SC-03, 8.4) ------------------------------------------------------------------------
    all_adds = [s for st in stages for s in st.add]
    s1_before = prior.has_effective(make_statement("S1", "diagnostics")) and not (own is not None and "S1" in own.keys)
    warnings = [
        "DEVICE_STATUS",
        "POSTURE_ALREADY_SET" if s1_before else "POSTURE_WARNING",
        ACCESS_POSTURE_WARNING[options.access],
        "ROOT_BLAST_RADIUS",
    ]
    if lab_hardware:
        warnings.append("LAB_HARDWARE_WARNING")
    if any(s.key == "S8" for s in all_adds):
        warnings.append("NETCONF_WARNING")
    if any(s.key == "S9" for s in all_adds):
        warnings.append("ALLOW_URL_WARNING")
    if any(st.name == "netconf-removal" for st in stages):
        warnings.append("REMOVE_NETCONF_WARNING")
    if layout is Layout.GROUP:
        warnings.append("GROUP_LAYOUT_WARNING")
    if prior.outbound_ssh_clients:
        warnings.append("MANAGED_WARNING")
    if prior.commit_scripts:
        warnings.append("COMMIT_SCRIPTS_WARNING")
    if method is not Method.CLI and prior.veriexec != VERIEXEC_ENFORCING:
        warnings.append("VERIEXEC_WARNING")
    if options.allow_plain_http and str(options.pull_url).startswith("http://"):
        warnings.append("PLAIN_HTTP_WARNING")
    if options.backend == "netconf" and any(st.name == "runtime" for st in stages):
        warnings.append("NETCONF_NOT_CHECKED")
    warnings.extend(tls_warnings)
    # OPX-05: an existing file J-Wicket reads at start, rewritten by this run. The on-box and CLI methods'
    # TLS 'write' is the operator's own pair (checked, never written by the installer), so it does not count.
    rewrites = any(
        f.action == "write"
        and f.path in prior.files
        and (
            f.content in ("settings", "lab-token")
            or (f.content in ("tls-key", "tls-cert") and f.source == "in-memory")
        )
        for f in files
    )
    if rewrites and not any(st.name == "runtime" for st in stages) and DAEMON_FILE in prior.jwicket_stanzas:
        warnings.append("RESTART_NEEDED")
    if offline:
        warnings.append("OFFLINE_STAMP")

    # -- receipt (7.10) -----------------------------------------------------------------------------
    recorded_overrides = set(overrides)
    if not options.jet_checksum:
        recorded_overrides.add("--no-jet-checksum")
    if options.allow_plain_http:
        recorded_overrides.add("--allow-plain-http")
    owned_keys = evidence.keys | _receipt_added(prior.workstation_receipt) | (set(own.keys) if own else set())
    added_keys = {
        s.key for st in stages if st.name != "bootstrap" for s in st.add if s.key in SPEC_BY_KEY or s.key == APPLY_KEY
    }
    present_shared: List[str] = []
    for key in SHARED_KEYS:
        if prior.has_effective(make_statement(key, "diagnostics")) and key not in owned_keys:
            present_shared.append(key)
    # Statements under J-Wicket's own names that are already there (an owned or --adopt'ed stanza) are
    # recorded as J-Wicket's: their names are J-Wicket's alone (spec 8.11, R-FOREIGN).
    adopted = {
        spec.key
        for spec in STATEMENT_TABLE
        if spec.owner_class == "jwicket" and spec.key != "S14" and prior.effective.under(" ".join(spec.path))
    }
    created = [f.path for f in files if f.action in ("copy", "write") and f.path not in prior.files]
    not_evidence = bool(recorded_overrides & NOT_EVIDENCE_OVERRIDES) or provenance.kind in NO_EVIDENCE_PROVENANCE
    receipt = Receipt(
        installer=f"{INSTALLER_NAME} {_installer_version()}",
        method=method.value,
        layout=layout.value,
        user=user,
        backend=options.backend,
        bundle_version=bundle.version,
        bundle_source_ref=bundle.source_ref,
        bundle_file_sha256=bundle.file_sha256,
        bundle_payload_sha256=bundle.payload_sha256,
        bundle_features=tuple(sorted(bundle.features)),
        host_name=facts.hostname,
        model=facts.model,
        serial=facts.serial,
        junos_version=facts.junos_version,
        provenance_kind=provenance.kind,
        provenance_detail=provenance.detail,
        provenance_evidence=provenance.evidence,
        statements_added=_ordered_keys({*(previous.statements_added if previous else ()), *added_keys, *adopted}),
        statements_present_before=_ordered_keys(
            set(previous.statements_present_before) if previous else set(present_shared)
        ),
        bootstrap_kind=own.kind if own else (previous.bootstrap_kind if previous else None),
        bootstrap_nonce=own.nonce if own else (previous.bootstrap_nonce if previous else None),
        bootstrap_added=own.keys if own else (previous.bootstrap_added if previous else ()),
        bootstrap_confirmed_by_installer=bool(previous and previous.bootstrap_confirmed_by_installer),
        files_created=tuple(dict.fromkeys([*(previous.files_created if previous else ()), *sorted(created)])),
        state_dir_created=bool(previous and previous.state_dir_created),  # R4: never by this installer
        veriexec_state=prior.veriexec,
        veriexec_source="manual step" if method is Method.CLI else prior.veriexec_source,
        overrides=tuple(sorted(recorded_overrides)),
        not_evidence=not_evidence,
        access=options.access,
        listen_address=options.listen_address,
        port=options.port,
        routing_instance=routing_instance,
        tls_cert_sha256=tls_cert_sha,
        tls_cert_not_after=tls_not_after,
        tls_cert_file_sha256=tls_file_sha,
    )
    changes = bool(stages) or directory.action != "keep" or any(f.action != "keep" for f in files)
    final_files: Tuple[FileStep, ...] = ()
    if changes:
        final_files = (
            FileStep(RECEIPT_PATH, "receipt", 0o600, None, "write", "final", source="workstation", owner=user),
        )
        if method in ONBOX_METHODS:
            final_files += (FileStep(UNINSTALL_CLI_PATH, "uninstall-cli", 0o600, None, "write", "final", owner=user),)

    plan = InstallPlan(
        schema=PLAN_SCHEMA,
        method=method,
        bundle=bundle,
        provenance=provenance,
        options=options,
        facts=facts,
        bootstrap=own,
        directory=directory,
        files=tuple(files),
        stages=tuple(stages),
        warnings=tuple(dict.fromkeys(warnings)),
        production_signs=() if offline else _production_signs(facts, prior),
        refusals=tuple(dict.fromkeys(refusals)),
        receipt=receipt,
        overrides=frozenset(overrides),
        upgrade=upgrade,
        offline=offline,
        status_checks=_status_checks(bundle, options, method, routing_instance),
        present_before=tuple(present_shared),
        final_files=final_files,
        routing_instance=routing_instance,
        lab_hardware=lab_hardware,
        pull_routing_instance=MGMT_INSTANCE if prior.management_instance else None,
    )
    if not plan.blocked:
        check_invariants(plan, prior)
    return plan


def _ordered_keys(keys: Iterable[str]) -> Tuple[str, ...]:
    order = [*SPEC_BY_KEY, APPLY_KEY]
    return tuple(k for k in order if k in set(keys))


def _installer_version() -> str:
    try:
        from . import __version__
    except ImportError:  # embedded without its package __init__ (the on-box op script sets its own)
        return "embedded"
    return str(__version__)


def receipt_for_run(
    plan: InstallPlan,
    *,
    host_key_sha256: Sequence[str] = (),
    time: Optional[str] = None,
    commits: Sequence[ReceiptCommit] = (),
    bootstrap_confirmed: Optional[bool] = None,
    tls_cert_sha256: Optional[str] = None,
    lab_hardware_attested: Optional[bool] = None,
    tls_cert_not_after: Optional[str] = None,
    tls_cert_file_sha256: Optional[str] = None,
) -> Receipt:
    """The plan's receipt completed with what only the run knows: host-key fingerprints, time, commits,
    the SHA-256 of the certificate the run generated (its fingerprint; never the key), its notAfter and
    the SHA-256 of the tls.crt file as uploaded (SEC-R1, OPX-04; None for an operator-made pair the run
    did not make), and R5's attestation. ``lab_hardware_attested`` must be True for a plan with
    ``lab_hardware`` (the executor asked and the operator typed 'lab only'); a plan that wrote a new
    certificate needs ``tls_cert_sha256``."""
    receipt = plan.receipt
    attested = receipt.lab_hardware_attested if lab_hardware_attested is None else lab_hardware_attested
    _require(not plan.lab_hardware or attested, "lab hardware: the receipt needs the operator's 'lab only'")
    cert = receipt.tls_cert_sha256 if tls_cert_sha256 is None else validate_sha256(tls_cert_sha256, "certificate")
    wrote_cert = any(f.content == "tls-cert" and f.action == "write" for f in plan.files)
    _require(not wrote_cert or tls_cert_sha256 is not None, "a new certificate's SHA-256 belongs in the receipt")
    not_after = receipt.tls_cert_not_after if tls_cert_sha256 is None else tls_cert_not_after
    file_sha = receipt.tls_cert_file_sha256 if tls_cert_sha256 is None else tls_cert_file_sha256
    return dataclasses.replace(
        receipt,
        host_key_sha256=tuple(host_key_sha256),
        time=time,
        commits=tuple(commits),
        bootstrap_confirmed_by_installer=receipt.bootstrap_confirmed_by_installer
        if bootstrap_confirmed is None
        else bootstrap_confirmed,
        tls_cert_sha256=cert,
        tls_cert_not_after=not_after,
        tls_cert_file_sha256=file_sha,
        lab_hardware_attested=attested,
    )


# ------------------------------------------------------------------------------------------------
# Revert (spec 8.8)
# ------------------------------------------------------------------------------------------------


def build_revert_stage(plan: InstallPlan, confirmed_stages: Sequence[str], *, include_bootstrap: bool = False) -> Stage:
    """Remove exactly what this run's confirmed stages added, then delete the files this run created,
    after their stanzas are gone. A stanza this run created is removed whole; leaves added to a stanza that
    existed before are removed one by one. The bootstrap's statements only with ``include_bootstrap``
    (M4, M4U; for M1's NETCONF bootstrap only with --remove-shared). The state directory stays: root made
    it, and its account cannot remove it (R4)."""
    for name in confirmed_stages:
        _require(name in ("bootstrap", "diagnostics", "runtime"), f"stage {name!r} cannot be reverted")
    # An upgrade changes values (the pinned checksums) instead of adding statements: deleting them would
    # leave the diagnostic copies unpinned. A failed upgrade is not reverted (spec 9.4): its failed stage
    # rolls back, and a confirmed diagnostics stage keeps the new bytes with their committed checksums.
    _require(not plan.upgrade, "an upgrade is not reverted by a revert stage (spec 9.4)")
    adds: List[Statement] = []
    for stage in plan.stages:
        if stage.name in confirmed_stages and (stage.name != "bootstrap" or include_bootstrap):
            adds.extend(stage.add)
    _require(bool(adds), "nothing to revert: no confirmed stage added a statement")
    added_keys = {s.key for s in adds}
    present_before = set(plan.present_before) | set(plan.receipt.statements_present_before)
    removes: List[Statement] = []
    stanza_done: Set[str] = set()
    for statement in adds:
        spec = SPEC_BY_KEY.get(statement.key)
        stanza = spec.stanza if spec is not None else None
        if stanza is not None:
            members = {s.key for s in STATEMENT_TABLE if s.stanza == stanza}
            wanted_members = members if plan.options.jet_checksum else members - {"S3", "S5", "S13"}
            if stanza in stanza_done:
                continue
            if wanted_members <= added_keys and not (members & present_before):
                removes.append(make_statement(stanza, "revert"))
                stanza_done.add(stanza)
                continue
        removes.append(dataclasses.replace(statement, stage="revert"))
    created = set(plan.receipt.files_created)
    after: List[FileStep] = []
    for step in plan.files:
        if step.path in created and step.action in ("copy", "write"):
            after.append(FileStep(step.path, "any", step.mode, None, "delete", "post-confirm", stage="revert"))
    return _stage("revert", plan.bundle, plan.options, (), removes, plan.overrides, after=after, method=plan.method)


# ------------------------------------------------------------------------------------------------
# Uninstall (spec 7.9, 9.5)
# ------------------------------------------------------------------------------------------------


def build_uninstall_plan(
    evidence: OwnershipEvidence,
    facts: DeviceFacts,
    prior: PriorState,
    *,
    method: Method,
    remove_shared: bool = False,
    overrides: FrozenSet[str] = frozenset(),
    layout: Optional[Layout] = None,
    user: Optional[str] = None,
) -> UninstallPlan:
    """The inverse (spec 7.9, 9.5): jwicket stanzas whole; shared statements S1, S8, S9 only by the
    ownership rules; files by exact known name, deleted only after the stanzas are gone and no process is
    listed (C13). The directory itself stays (``state_dir_left``, R4): root made it, and its account cannot
    remove an entry of /var/db. ``remove_shared`` allows S8 (the executor adds its own typed
    confirmation). In the group layout the group and apply-groups go whole when nothing kept remains in
    the group; otherwise statement by statement. ``user`` is the account the executor commits as: C11 then
    requires the newest entry to be by it (SC-04); without it, the receipt's account, else the executor's.
    The platform refusals are the install's (R-MODEL with --lab-hardware, R-CLUSTER, R-MNHA, R-DUAL-RE)."""
    unknown_flags = set(overrides) - OVERRIDES
    _require(not unknown_flags, f"unknown override(s): {', '.join(sorted(unknown_flags))}")
    _require(method is not Method.ZTP, "ZTP is documented only (cut C3)")
    if user is not None:
        validate_user(user)
    refusals: List[Refusal] = []

    def refuse(code: str, detail: str = "") -> None:
        refusals.append(make_refusal(code, detail, overrides))

    if facts.hostname is None:
        refuse("R-NOHOST")
    platform, hardware = _platform_refusals(facts, prior, frozenset(overrides))
    refusals.extend(r for r in platform if r.code != "R-FIPS")
    if prior.pending is not Pending.NONE or prior.scheduled_commit or prior.prepared_commit:
        refuse("R-PENDING", f"commit state: {prior.pending.value}")
    if prior.unreadable:
        refuse("R-UNREADABLE", "not read: " + ", ".join(prior.unreadable))
    if prior.commit_scripts:
        refuse("R-COMMIT-SCRIPTS")
    if prior.outbound_ssh_clients:
        refuse("R-MANAGED")

    receipt = prior.workstation_receipt or prior.device_receipt
    committer = user if user is not None else (receipt.user if receipt is not None else None)
    if layout is None:
        if receipt is not None:
            layout = Layout(receipt.layout)
        else:
            layout = Layout.GROUP if prior.jwicket_group_paths else Layout.DIRECT
    view = prior.direct
    remove: List[Statement] = []
    kept: List[KeptStatement] = []
    unknown_leaves: List[str] = []
    known = {" ".join(s.path[len(_EXT) + 1 :]) for s in STATEMENT_TABLE if s.path[: len(_EXT)] == _EXT}
    known.add(" ".join(SPEC_BY_KEY["S14"].path[len(_OPF) :]))
    stanzas = prior.jwicket_stanzas
    for stanza_key, stanza_path in STANZA_KEYS.items():
        statement = make_statement(stanza_key, "uninstall")
        if view.under(statement.path_key(layout)):
            remove.append(statement)
            name = stanza_path[-1]
            unknown_leaves.extend(f"{name}: {leaf}" for leaf in sorted(stanzas.get(name, frozenset()) - known))
    for other in sorted(set(stanzas) - {p[-1] for p in STANZA_KEYS.values()}):
        unknown_leaves.append(f"{other}: a jwicket stanza this tool does not know (kept)")

    warnings = ["DEVICE_STATUS"]
    netconf_removal: Optional[Statement] = None
    for key in SHARED_KEYS:
        statement = make_statement(key, "uninstall")
        path_key = statement.path_key(layout)
        if not view.under(path_key):
            continue
        owned, reason = _owned_shared(key, evidence, prior)
        added_value = evidence.added_value(key) if evidence.history_available else None
        expected = (added_value if added_value is not None else (statement.value or ""),)
        if not owned:
            kept.append(KeptStatement(key, reason))
            continue
        if view.under(path_key) != frozenset({(path_key, expected[0])}):
            kept.append(KeptStatement(key, "changed since this installer added it"))
            continue
        if key == "S1":
            others = prior.other_python
            if others:
                kept.append(KeptStatement(key, "other Python scripts rely on it: " + ", ".join(others[:5])))
                continue
            remove.append(statement)
            warnings.append("REMOVE_LANGUAGE_WARNING")
        elif key == "S8":
            if not remove_shared:
                kept.append(
                    KeptStatement(
                        key, "kept by default; --remove-shared, with its own typed confirmation, " "removes it"
                    )
                )
            elif prior.outbound_ssh_clients:
                kept.append(KeptStatement(key, "outbound-SSH clients are configured and may use NETCONF"))
            else:
                netconf_removal = make_statement("S8", "netconf-removal")
                warnings.append("REMOVE_NETCONF_WARNING")
        else:
            remove.append(statement)

    netconf_stage_extra: List[Statement] = []
    group = view.under("groups jwicket")
    if group and not group <= evidence.added and "--adopt" not in overrides:
        refuse("R-FOREIGN", "groups jwicket holds statements the ownership sources did not add")
    if layout is Layout.DIRECT and group:
        # A group under J-Wicket's name next to a direct-layout install: removed whole when the history shows
        # this installer added it, or when it was adopted (--adopt); otherwise R-FOREIGN above.
        if ("apply-groups", GROUP_NAME) in view.pairs:
            remove.append(make_statement(APPLY_KEY, "uninstall"))
        remove.append(make_statement(GROUP_KEY, "uninstall"))
    if layout is Layout.GROUP:
        model = apply_lines(view, [s.delete_line(layout) for s in remove])
        if group and not model.under("groups jwicket"):
            remove = [make_statement(GROUP_KEY, "uninstall")]
            if ("apply-groups", GROUP_NAME) in view.pairs:
                remove.insert(0, make_statement(APPLY_KEY, "uninstall"))
        elif netconf_removal is not None:
            after_netconf = apply_lines(model, [netconf_removal.delete_line(layout)])
            if not after_netconf.under("groups jwicket"):
                netconf_stage_extra = [make_statement(GROUP_KEY, "netconf-removal")]
                if ("apply-groups", GROUP_NAME) in view.pairs:
                    netconf_stage_extra.insert(0, make_statement(APPLY_KEY, "netconf-removal"))

    files: List[FileStep] = []
    leftovers: List[str] = []
    for path in sorted(prior.files):
        info = prior.files[path]
        directory, _, name = path.rpartition("/")
        ours = (directory == JET_DIR and name in (*JWICKET_JET_FILES, STAGING_FILE, BACKUP_FILE)) or path == OP_PATH
        if directory == STATE_DIR:
            if name in STATE_DIR_KNOWN_FILES and not info.is_dir and not info.is_symlink:
                ours = True
            else:
                leftovers.append(path)
        if ours:
            files.append(FileStep(path, "any", info.mode or 0, None, "delete", "post-confirm", stage="uninstall"))
    state_info = prior.files.get(STATE_DIR)
    state_dir_left = state_info is not None and state_info.is_dir and not state_info.is_symlink
    c13 = _check("C13", DAEMON_FILE, {"process": "absent", "stop_wait_s": "10"})
    c11_expect = {"newest_comment": "", "pending_commit": "absent", "prepared_commit": "absent"}
    if committer is not None:
        c11_expect["newest_user"] = committer

    def removal_stage(name: str, statements: Sequence[Statement], after: Sequence[FileStep]) -> Stage:
        comment = uninstall_comment(name)
        keys = [s.key for s in statements]
        return Stage(
            name=name,
            add=(),
            remove=tuple(statements),
            files_before_commit=(),
            comment=comment,
            confirm_comment=uninstall_comment(name, confirmed=True),
            confirm_minutes=Minutes(5),
            checks=(
                _check("C12", name, {"keys": ",".join(keys)}),
                _check("C10", name, {"structural": "exact", "headers": "stage-roots"}),
                _check("C11", name, {**c11_expect, "newest_comment": comment}),
            ),
            files_after_confirm=tuple(after),
            post_confirm_checks=(c13,) if after else (),
        )

    stages: List[Stage] = []
    if remove:
        stages.append(removal_stage("uninstall", remove, files))
    if netconf_removal is not None:
        stages.append(removal_stage("netconf-removal", [netconf_removal, *netconf_stage_extra], ()))
    if state_dir_left:
        warnings.append("STATE_DIR_LEFT")
    warnings.append("NOT_REMOVED_BY_TOOL")
    uplan = UninstallPlan(
        schema=PLAN_SCHEMA,
        method=method,
        facts=facts,
        layout=layout,
        stages=tuple(stages),
        files=() if remove else tuple(files),
        kept=tuple(kept),
        leftovers=tuple(leftovers),
        unknown_leaves=tuple(unknown_leaves),
        warnings=tuple(dict.fromkeys(warnings)),
        refusals=tuple(dict.fromkeys(refusals)),
        overrides=frozenset(overrides),
        remove_shared=remove_shared,
        user=committer,
        file_checks=(c13,) if files and not remove else (),
        state_dir_left=state_dir_left,
        lab_hardware=hardware,
    )
    if not uplan.blocked:
        check_invariants(uplan, prior)
    return uplan


# ------------------------------------------------------------------------------------------------
# Invariants (INV-06 and the statement rules; AC-006-04)
# ------------------------------------------------------------------------------------------------

_INSTALL_REMOVALS = frozenset({"S9", "F-SELFTEST", "F-PROBE", "S8"})


def check_invariants(plan: Union[InstallPlan, UninstallPlan], prior: PriorState) -> None:
    """Raise InvariantError for a plan that writes in place, renames over or deletes a configured path
    outside the copy-before-checksum-commit step (INV-06), or that breaks a statement rule: unknown keys,
    never-rendered statements, values outside the token set, statements outside their stage's roots,
    adding what is already effective, removing what was present before, comments or windows out of
    range, a confirmed stage without C10 and C11; or a step on the state directory itself (R4: root's), a
    TLS key whose content or hash would enter the plan, or TLS files with other modes."""
    _bad(plan.schema == PLAN_SCHEMA, "plan schema is not 2")
    layout = plan.layout
    configured = prior.configured_paths
    present_before = set(prior.workstation_receipt.statements_present_before) if prior.workstation_receipt else set()
    for stage in plan.stages:
        _bad(stage.name in STAGE_NAMES, f"unknown stage {stage.name!r}")
        stage_lay = stage_layout(stage, layout)
        roots = [tuple(r.split(" ")) for r in ALLOWED_DIFF_HEADERS.get(stage.name, ())]
        if stage_lay is Layout.GROUP:
            roots = [GROUP_PREFIX + r for r in roots] + [("apply-groups",), GROUP_PREFIX]
        elif stage.name in ("uninstall", "revert"):
            roots += [("apply-groups",), GROUP_PREFIX]  # an adopted group goes whole (G-APPLY, G-GROUP)
        for statement in (*stage.add, *stage.remove):
            _bad(statement.key in ALL_KEYS, f"stage {stage.name}: unknown statement key {statement.key!r}")
            _bad(not (set(statement.path) & NEVER_RENDERED), f"{statement.key}: a never-rendered statement")
            if statement.value is not None:
                _bad(
                    TOKEN_RE.match(statement.value) is not None and " " not in statement.value,
                    f"{statement.key}: value outside the token set",
                )
            if statement.key in SPEC_BY_KEY:
                _bad(statement.path == SPEC_BY_KEY[statement.key].path, f"{statement.key}: path differs from 7.3")
            form = statement.form(stage_lay)
            _bad(
                any(form[: len(r)] == r for r in roots), f"stage {stage.name}: {statement.key} outside its hierarchies"
            )
        if not stage.already_committed:
            for statement in stage.add:
                if statement.path not in {s.path for s in stage.remove}:
                    _bad(
                        not prior.has_effective(statement) or statement.key == APPLY_KEY,
                        f"stage {stage.name}: {statement.key} is already effective",
                    )
        if isinstance(plan, InstallPlan):
            for statement in stage.remove:
                if statement.path in {s.path for s in stage.add}:
                    continue
                _bad(
                    statement.key in _INSTALL_REMOVALS, f"stage {stage.name}: an install never removes {statement.key}"
                )
        for statement in stage.remove:
            _bad(statement.key not in present_before, f"stage {stage.name}: {statement.key} was present before install")
        if not stage.already_committed:
            _check_minutes(stage.confirm_minutes, CONFIRM_MINUTES_RANGE, "confirm minutes")
        else:
            _check_minutes(stage.confirm_minutes, BOOTSTRAP_MINUTES_RANGE, "bootstrap minutes")
        _check_comment(stage.comment)
        _check_comment(stage.confirm_comment)
        _bad(
            is_installer_comment(stage.comment) and is_installer_comment(stage.confirm_comment),
            f"stage {stage.name}: comment is not an installer comment",
        )
        _bad({"C10", "C11"} <= set(stage.check_ids), f"stage {stage.name}: C10 and C11 must run before the confirm")
        stage_lines(stage, layout)  # every rendered line within the token set

        checksum_changes: Dict[str, str] = {}
        for statement in stage.add:
            spec = SPEC_BY_KEY.get(statement.key)
            if spec is not None and spec.value_kind in ("bundle-sha256", "op-sha256") and spec.stanza is not None:
                checksum_changes[STANZA_FILE_PATHS[spec.stanza]] = statement.value or ""
        removed_stanzas = {STANZA_FILE_PATHS[s.key] for s in stage.remove if s.key in STANZA_FILE_PATHS}
        if stage.remove and any(s.key == GROUP_KEY for s in stage.remove):
            removed_stanzas |= set(STANZA_FILE_PATHS.values())
        replaced: Set[str] = set()
        for step in stage.files_before_commit:
            _bad(step.phase == "pre-commit", f"{step.path}: a pre-commit step outside its phase")
            if step.action == "replace":
                _bad(
                    step.path in checksum_changes and checksum_changes[step.path] == step.sha256,
                    f"{step.path}: replaced without the confirmed commit that changes its checksum (INV-06)",
                )
                replaced.add(step.path)
            elif step.action == "backup":
                _bad(step.path not in configured, f"{step.path}: backup onto a configured path (INV-06)")
            else:
                _bad(False, f"{step.path}: action {step.action} is not allowed before a commit")
        for step in stage.restore_on_failure:
            _bad(
                step.action == "restore" and (step.path in replaced or step.path not in configured),
                f"{step.path}: a restore of a configured path without the replace it undoes (INV-06)",
            )
        for step in stage.files_after_confirm:
            _bad(step.action == "delete", f"{step.path}: only deletes follow a confirm (never a directory, R4)")
            _bad(step.path != STATE_DIR, f"{step.path}: the state directory is root's to remove (R4)")
            if step.path in configured:
                _bad(step.path in removed_stanzas, f"{step.path}: deleted while its stanza exists (INV-06)")
    top_files: Tuple[FileStep, ...] = plan.files
    if isinstance(plan, InstallPlan):
        top_files = (*plan.files, *plan.final_files)
        if plan.directory is not None:
            _bad(plan.directory.path == STATE_DIR and plan.directory.mode == 0o700, "the directory step is fixed")
            _bad(plan.directory.action in ("keep", "require"), "the installer never creates the directory (R4)")
    for step in top_files:
        _bad(step.action in FILE_ACTIONS and step.phase in FILE_PHASES, f"{step.path}: unknown action or phase")
        _bad(_PATH_RE.match(step.path) is not None, f"{step.path!r}: not a plain path")
        _bad(step.content != "directory" and step.path != STATE_DIR, f"{step.path}: a directory step (R4)")
        if step.content == "tls-key":
            _bad(
                step.path == TLS_KEY_PATH and step.mode == TLS_KEY_MODE and step.sha256 is None,
                "the TLS key is 0600 and never in the plan",
            )
        if step.content == "tls-cert":
            _bad(step.path == TLS_CERT_PATH and step.mode == TLS_CERT_MODE, "the TLS certificate is 0644")
        if step.action == "keep":
            continue
        if isinstance(plan, InstallPlan):
            _bad(
                step.path not in configured, f"{step.path}: {step.action} on a configured path outside a stage (INV-06)"
            )
            _bad(
                step.action != "stage" or step.path == STAGING_PATH,
                f"{step.path}: transfers land only in {STAGING_PATH}",
            )
            _bad(step.action not in ("replace", "restore"), f"{step.path}: {step.action} outside a stage")
        else:
            _bad(step.action == "delete", f"{step.path}: an uninstall only deletes files")
            _bad(step.path not in configured, f"{step.path}: deleted while configured (INV-06)")
