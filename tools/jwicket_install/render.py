"""Text renderings of the shared plan (Spec 006, sections 6.8, 7.7 and 7.8).

Standard library only, no I/O, Python 3.7-compatible (the on-box op script embeds it; plan.py lists what
that excludes). Every Junos statement, command and warning comes from :mod:`jwicket_install.plan`; this
module only arranges them. Rendered values come from validated tokens and constants only (INV-12); device
text never reaches a rendered line or the plan JSON.

FROZEN PUBLIC API
=================

``PasteUnit`` (number, title, where, lines, before, after, opens_configuration, status, filename);
``WHERE`` values: workstation, file, device-operational, device-configuration, device-shell.

``render_cli_units(plan, *, prior=None, set_files=False, stamp_host=None, stamp_time=None) ->
Tuple[PasteUnit, ...]`` (M6; the plan's method must be Method.CLI; a blocked plan raises PlanBlocked; an
offline plan's directory step is "require", rendered as the one-time root step; --access tls adds the
on-device certificate unit and ends with the URL);
``render_cli_uninstall_units(uplan, *, prior=None) -> Tuple[PasteUnit, ...]`` (ends with the root step that
removes the empty state directory);
``render_bootstrap_units(bootstrap, *, follow_up=()) -> Tuple[PasteUnit, ...]``;
``render_set(stage, layout) -> str``; ``render_set_file(stage, layout) -> str``; ``set_file_name(stage)``;
``render_plan_diff(plan, prior) -> str`` (patch form, for the read-only dry run);
``render_plan_text(plan, prior) -> str`` (the whole dry-run printout in UI-006-04 order);
``plan_to_json(plan) -> str`` (schema 2, validated tokens only; every string matches ``JSON_TOKEN_RE``;
``access``, ``listen_address``, ``routing_instance`` and ``lab_hardware`` are additive fields);
``op_payload(bundle, urls, *, plan=None) -> Dict[str, object]`` (the constants the op script embeds,
with ``lab_hardware_prompt``, ``lab_hardware_answer``, ``state_dir_root_step``, ``access_modes`` and the TLS
paths);
``payload_lines(payload, keys, *, user, bundle_sha256, op_sha256=None)`` (set lines from the payload's
statement table; the no-drift test compares them with ``plan.stage_lines``);
``render_tunnel(user, port, *, host=None, ssh_port=22) -> str`` (explicit 127.0.0.1 bind, INV-10; --access
tunnel only); ``render_open(plan, *, cert_sha256=None) -> Tuple[str, ...]`` (how to reach the UI: the URL
and the certificate fingerprint to compare with --access tls, the tunnel line with --access tunnel);
``units_to_text(units) -> str``; ``set_lines_of_units(units) -> Tuple[str, ...]``.

Paste-unit rules (AC-006-09, each tested): a unit that contains 'commit confirmed' ends with it, so
nothing follows it in that unit; a confirming commit is alone in its unit with 'exit'; every unit that
opens configuration mode starts with 'configure exclusive' and 'run show system commit | no-more';
no unit contains 'commit check', 'load ... terminal' or a literal Ctrl-D; every 'show' carries
'| no-more' (that it stops the pager is inferred). Prose with the expected output and the STOP rule
sits between units, never inside one.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from . import plan as p
from .plan import (
    Bootstrap,
    BundleId,
    InstallPlan,
    Layout,
    Method,
    PriorState,
    Stage,
    StatementSet,
    UninstallPlan,
)

WHERE = ("workstation", "file", "device-operational", "device-configuration", "device-shell")
JSON_TOKEN_RE = re.compile(r"^[A-Za-z0-9 ._:/@=+,()!-]{0,512}\Z")


@dataclass(frozen=True)
class PasteUnit:
    """A block the operator may paste whole. ``before``/``after`` are prose printed around it."""

    number: str
    title: str
    where: str
    lines: Tuple[str, ...]
    before: Tuple[str, ...] = ()
    after: Tuple[str, ...] = ()
    opens_configuration: bool = False
    status: str = ""
    filename: Optional[str] = None


def _unit(
    number: str,
    title: str,
    where: str,
    lines: Sequence[str],
    *,
    before: Sequence[str] = (),
    after: Sequence[str] = (),
    opens: bool = False,
    status: str = "",
    filename: Optional[str] = None,
) -> PasteUnit:
    if where not in WHERE:
        raise p.InputError(f"unknown unit place {where!r}")
    return PasteUnit(number, title, where, tuple(lines), tuple(before), tuple(after), opens, status, filename)


# ------------------------------------------------------------------------------------------------
# Set lines and files
# ------------------------------------------------------------------------------------------------


def render_set(stage: Stage, layout: Layout) -> str:
    """The stage's set and delete lines, one per line (spec 7.8)."""
    return "\n".join(p.stage_lines(stage, layout)) + "\n"


def render_set_file(stage: Stage, layout: Layout) -> str:
    """The .set file variant: the same lines, nothing else (loaded with 'load set <file>')."""
    return render_set(stage, layout)


def set_file_name(stage: Stage) -> str:
    return f"jwicket-{stage.name}.set"


def set_lines_of_units(units: Sequence[PasteUnit]) -> Tuple[str, ...]:
    """Every set and delete line typed on the device in ``units`` (the no-drift test's extractor)."""
    out: List[str] = []
    for unit in units:
        if unit.where == "device-configuration":
            out.extend(line for line in unit.lines if line.startswith(("set ", "delete ")))
        if unit.where == "file" and unit.filename and unit.filename.endswith(".set"):
            out.extend(line for line in unit.lines if line.startswith(("set ", "delete ")))
    return tuple(out)


# ------------------------------------------------------------------------------------------------
# Tunnel
# ------------------------------------------------------------------------------------------------


def render_tunnel(user: str, port: int, *, host: Optional[str] = None, ssh_port: int = 22) -> str:
    """'ssh -L 127.0.0.1:<port>:127.0.0.1:<port> <u>@<device>': the explicit bind keeps the forward off
    the workstation's LAN whatever GatewayPorts says ([ssh1], verified). The host is printed only after
    the gate; before it, the placeholder <device> stands."""
    p.validate_user(user)
    if not isinstance(port, int) or isinstance(port, bool) or not 1024 <= port <= 65535:
        raise p.InputError(f"port {port!r} is outside 1024..65535")
    if not isinstance(ssh_port, int) or isinstance(ssh_port, bool) or not 1 <= ssh_port <= 65535:
        raise p.InputError(f"SSH port {ssh_port!r} is outside 1..65535")
    target = "<device>"
    if host is not None:
        if p.HOSTNAME_RE.match(host) is None and re.match(r"^[0-9.]{7,15}\Z", host) is None:
            raise p.InputError("host is not a plain host name or IPv4 address")
        target = host
    port_option = f" -p {ssh_port}" if ssh_port != 22 else ""
    return f"ssh{port_option} -L {p.LOOPBACK}:{port}:{p.LOOPBACK}:{port} {user}@{target}"


# ------------------------------------------------------------------------------------------------
# Stage units (M6)
# ------------------------------------------------------------------------------------------------


def _warning_prose(ids: Sequence[str], user: str) -> Tuple[str, ...]:
    return tuple(p.warning_text(wid, user) for wid in ids)


# JFR-02: what the STOP rule says when the device's configuration is known (rendered the way Junos groups
# 'show | compare') and when it is not (offline, or a unit printed before any read).
COMPARE_KNOWN = (
    "STOP unless 'show | compare' shows exactly these statements and nothing else. Junos prints each change "
    "under the deepest level that already exists, and a new level as a braced block; the grouping below is "
    "rendered from the configuration the installer read, a select-only read, so a level it cannot see may "
    "make Junos print a deeper header for the same statements (illustrative; real samples are recorded by "
    "lab test Q-INST-01):"
)
COMPARE_UNKNOWN = (
    "STOP unless 'show | compare' shows the same statements and nothing else. This rendering does not know "
    "which levels the device already has: Junos prints each change under the deepest level that already "
    "exists, and a new level (for example a new 'file jwicket.py' entry) as a braced block of '+' lines under "
    "that header, so the same statements may appear grouped that way rather than one leaf per header "
    "(illustrative; real samples are recorded by lab test Q-INST-01). For example:"
)


def _expected_compare(stage: Stage, layout: Layout, before: Optional[StatementSet]) -> Tuple[str, ...]:
    """The STOP rule and the comparison it expects: grouped as Junos prints it when ``before`` (the device's
    configuration) is known, otherwise the unknown-device wording with each statement under its own header."""
    return compare_expectation(p.stage_lines(stage, layout), before=before)[:-1]


def compare_expectation(
    lines: Sequence[str], *, before: Optional[StatementSet] = None, notes: Sequence[str] = ()
) -> Tuple[str, ...]:
    """The STOP check after a unit's set or delete lines: what 'show | compare' should print, in Junos's
    patch form ('[edit ...]' headers, '+' added, '-' removed; [xml-compare], verified), never the typed
    lines themselves. With ``before``, the device's configuration, the change is grouped the way Junos
    documents it (plan.compare_text, JFR-02). Without it, the levels the device already has are unknown:
    each statement is shown under its own leaf-level header, from a base that holds exactly what the lines
    delete, and the rule asks for the same statements in either grouping. Illustrative either way: real
    samples are recorded by lab test Q-INST-01. The last line is always the 'rollback 0' instruction."""
    changes = [line for line in lines if line.startswith(("set ", "delete "))]
    if before is None:
        deleted = ["set " + line.split(" ", 1)[1] for line in lines if line.startswith("delete ")]
        base = p.apply_lines(StatementSet(), deleted)
        rule = COMPARE_UNKNOWN
        text = p.patch_text(base, p.apply_lines(base, changes))
    else:
        rule = COMPARE_KNOWN
        text = p.compare_text(before, p.apply_lines(before, changes), assumed=p.ASSUMED_LEVELS)
    return (
        rule,
        *("    " + line for line in text.splitlines()),
        *notes,
        "If it shows anything else, type 'rollback 0' and 'exit'.",
    )


# Shared statements a device may already hold; offline (no prior read) the comparison then omits them.
_MAY_PRE_EXIST = {"S1": "language python3", "S8": "netconf ssh"}


def _offline_notes(stage: Stage, offline: bool) -> Tuple[str, ...]:
    """Offline units (render without --host) cannot know what the device has: a shared statement that is
    already set is not in the comparison, and that is fine (OPD-02)."""
    if not offline:
        return ()
    return tuple(
        f"If the comparison does not list '{_MAY_PRE_EXIST[s.key]}', it was already set: that is fine."
        for s in stage.add
        if s.key in _MAY_PRE_EXIST
    )


def _check_prose(stage: Stage, plan_user: str, port: int, fingerprint_hint: str = "") -> List[str]:
    out: List[str] = []
    for check in stage.checks:
        out.append(f"{check.id}: {p.CHECKS[check.id].proves}".replace("<port>", str(port)))
        if check.id == "C2":
            out.append(
                f"    expect \"ok\": true, \"version\": \"{check.expect['version']}\", "
                f"\"payload_sha256\": \"{check.expect['payload_sha256']}\""
            )
        elif check.id == "C3":
            out.append("    expect ok for: " + check.expect["modules"].replace(",", ", "))
        elif check.id == "C4":
            build = check.expect["build"]
            out.append(
                "    expect exactly one new line containing: " + check.expect["line"] + (f" {build}" if build else "")
            )
        elif check.id == "C6":
            out.append("    expect an error saying the file does not exist")
        elif check.id == "C8":
            if check.expect.get("access") == "tls":
                out.append(
                    f"    by hand, from your workstation: open {check.expect['url']} in the browser, compare the "
                    f"certificate's SHA-256 fingerprint with {fingerprint_hint or 'the one the installer printed'}, "
                    "and expect "
                    f"\"version\": \"{check.expect['version']}\""
                    + (f" and \"build\": \"{check.expect['build']}\"" if check.expect.get("build") else "")
                )
            else:
                out.append("    " + p.TUNNEL_C8_REASON)
        elif check.id == "C10":
            out.append("    expect 'show | compare rollback 1' to show only the change of unit B")
        elif check.id == "C11":
            out.append(
                f"    expect the newest commit by {plan_user} with the comment: {check.expect['newest_comment']}"
            )
        elif check.id == "C12":
            out.append("    expect the removed statements to be gone")
    return out


def _check_lines(stage: Stage, bundle_has_results: bool) -> Tuple[List[str], List[str]]:
    """(lines typed before the commit confirmed, lines typed after it) for a stage's checks."""
    pre: List[str] = []
    post: List[str] = []
    ids = set(stage.check_ids)
    if "C2" in ids:
        if bundle_has_results:
            pre.append(p.cli_run(p.cli_file_delete(p.SELFTEST_RESULT_PATH)))
            pre.append(p.cli_run(p.cli_file_delete(p.PROBE_RESULT_PATH)))
        post.append(p.cli_run(p.cli_start(p.SELFTEST_FILE)))
        post.append(p.cli_run(p.cli_start(p.PROBE_FILE)))
        if bundle_has_results:
            post.append(p.cli_run(p.cli_file_show(p.SELFTEST_RESULT_PATH)))
            post.append(p.cli_run(p.cli_file_show(p.PROBE_RESULT_PATH)))
    if "C4" in ids:
        pre.append(p.cli_run(p.cli_file_delete(p.STARTUP_REFUSED_PATH)))
        post.append(p.cli_run(p.cli_file_show(p.LOG_PATH)))
        post.append(p.cli_run(p.cli_file_show(p.AUDIT_PATH)))
        post.append(p.cli_run(p.cli_file_show(p.STARTUP_REFUSED_PATH)))
        post.append(p.cli_run(p.cli_ext_status(p.DAEMON_FILE)))
    if "C12" in ids and any(s.key == "S8" for s in stage.remove):
        post.append(p.SHOW_NETCONF)
    post.append(p.CLI_COMPARE_ROLLBACK_1)
    post.append(p.CLI_SHOW_COMMIT)
    return pre, post


def _stage_units(
    number: int,
    stage: Stage,
    layout: Layout,
    before: Optional[StatementSet],
    user: str,
    *,
    bundle_has_results: bool,
    set_files: bool,
    pre_copy: Sequence[str] = (),
    on_failure: Sequence[str] = (),
    port: int = p.DEFAULT_PORT,
    offline: bool = False,
    fingerprint_hint: str = "",
) -> List[PasteUnit]:
    lines = p.stage_lines(stage, layout)
    pre, post = _check_lines(stage, bundle_has_results)
    replaced = [f.path for f in stage.files_before_commit if f.action == "replace"]
    post = [p.cli_run(p.cli_file_checksum(path)) for path in replaced] + post
    units: List[PasteUnit] = []
    title = f"stage {stage.name}"
    units.append(
        _unit(
            f"{number}A",
            f"{title}: open configuration mode",
            "device-configuration",
            (p.CLI_CONFIGURE, p.CLI_SHOW_COMMIT),
            before=(
                f"Stage {stage.name}: {len(lines)} configuration line(s), one 'commit confirmed "
                f"{stage.confirm_minutes}', confirmed only after the checks.",
            ),
            after=(
                f"STOP if {p.PENDING_SIGNS}: type 'exit' and wait until it is settled. Otherwise paste the next "
                "unit.",
            ),
            opens=True,
            status="'run' verified ([run-cmd]); '| no-more' inferred",
        )
    )
    if set_files:
        body: Tuple[str, ...] = (p.cli_load_set(set_file_name(stage)), p.CLI_COMPARE)
        status = "'load set <file>' documented (verified); a relative name loading from the home directory inferred"
    else:
        body = (*lines, p.CLI_COMPARE)
        status = "statements: see each line's status in Spec 006 section 7.3"
    units.append(
        _unit(
            f"{number}B",
            f"{title}: the configuration change",
            "device-configuration",
            body,
            after=(
                *_expected_compare(stage, layout, None if offline else before),
                *_offline_notes(stage, offline),
                "If it shows anything else, type 'rollback 0' and 'exit'.",
            ),
            status=status,
        )
    )
    for index, copy in enumerate(pre_copy, start=1):
        units.append(
            _unit(
                f"{number}B{index}",
                f"{title}: overwrite a file before the commit",
                "device-configuration",
                (copy,),
                after=(
                    "STOP if 'file copy' prompts or refuses: paste nothing more, answer the prompt so that nothing "
                    "is overwritten, then type 'rollback 0' and 'exit'; a file an earlier unit already overwrote "
                    "is put back by the 'On failure' line of unit D. Whether 'file copy' overwrites an existing "
                    "file, refuses or prompts is unknown (Q-INST-01). Otherwise paste the next unit.",
                ),
                status="'file copy' verified (F01); overwrite behaviour unknown (Q-INST-01): stop if prompted",
            )
        )
    units.append(
        _unit(
            f"{number}C",
            f"{title}: commit confirmed",
            "device-configuration",
            (*pre, p.cli_commit_confirmed(stage.confirm_minutes, stage.comment)),
            after=(
                f"Deadline: {stage.confirm_minutes} minutes from now. Unless the confirming unit below is pasted "
                "before then, Junos rolls this stage back by itself.",
            ),
            status="'commit confirmed <minutes> comment' inferred to combine (documented: commit confirmed comment)",
        )
    )
    units.append(
        _unit(
            f"{number}D",
            f"{title}: checks",
            "device-configuration",
            post,
            after=(
                "Compare with what each check expects:",
                *(
                    f"The copy on {path}: expect its SHA256 to be the bundle's, as in unit B's checksum line."
                    for path in replaced
                ),
                *_check_prose(stage, user, port, fingerprint_hint),
                "Leave at least one minute before the deadline. Only if all of that matches, paste the next unit.",
                "Otherwise type 'exit' (answer 'yes' if asked to exit with uncommitted changes) and let Junos roll "
                "the stage back at the deadline.",
                *on_failure,
            ),
            status="checks unverified on a device (Q-INST-06)"
            + (
                "; 'request extension-service start' printed the self-test and probe JSON on the CLI on SRX4100 "
                "25.2R1-S1.4 (verified)"
                if "C2" in stage.check_ids
                else ""
            ),
        )
    )
    if "C7" in stage.check_ids:
        units.append(
            _unit(
                f"{number}D2",
                f"{title}: process still the same after 30 seconds",
                "device-configuration",
                (p.cli_run(p.cli_ext_status(p.DAEMON_FILE)),),
                before=("Wait at least 30 seconds after unit D, then paste:",),
                after=(
                    "STOP unless the process id is the same as in unit D and the log still has exactly one new "
                    "'listening on' line.",
                ),
                status="the status command verified ([show-ext]); its use for this inferred",
            )
        )
    units.append(
        _unit(
            f"{number}E",
            f"{title}: confirm",
            "device-configuration",
            (p.cli_confirm(stage.confirm_comment), p.CLI_EXIT),
            before=("Only if every check above matched:",),
            status="confirming with 'commit comment' (force-commit-log safe, verified)",
        )
    )
    return units


def _stamp(plan_user: str, offline: bool, host: Optional[str], time: Optional[str]) -> str:
    if offline or host is None:
        return p.warning_text("OFFLINE_STAMP", plan_user)
    if p.HOSTNAME_RE.match(host) is None or (time is not None and p.TIME_RE.match(time) is None):
        raise p.InputError("stamp host or time is not in the expected form")
    when = f" at {time}" if time else ""
    return (
        f"Rendered for {host}{when}, after the lab gate on its own facts. Before unit 1, check that your CLI "
        f"prompt shows {plan_user}@{host}."
    )


def _deleted_in_files(plan: InstallPlan, path: str) -> bool:
    """A staging file deleted in the files phase is checked before its copies, not after."""
    return path == p.STAGING_PATH and any(f.action == "delete" and f.path == path for f in plan.files)


def render_cli_units(
    plan: InstallPlan,
    *,
    prior: Optional[PriorState] = None,
    set_files: bool = False,
    stamp_host: Optional[str] = None,
    stamp_time: Optional[str] = None,
) -> Tuple[PasteUnit, ...]:
    """M6: the numbered paste units and prose of spec 6.8. The primary path is deploy-lab's spike-verified
    one ('scp -O' to each name); Junos file-command variants and the shell fallback are marked units."""
    if plan.blocked:
        raise p.PlanBlocked("the plan is blocked by a refusal: " + ", ".join(r.code for r in plan.refusals))
    if plan.method is not Method.CLI:
        raise p.InputError("render_cli_units renders plans made for Method.CLI")
    user = plan.options.user
    layout = plan.layout
    units: List[PasteUnit] = []
    header = (
        p.DEVICE_STATUS,
        _stamp(user, plan.offline, stamp_host, stamp_time),
        *_warning_prose([w for w in plan.warnings if w not in ("DEVICE_STATUS", "OFFLINE_STAMP")], user),
    )
    units.append(
        _unit(
            "1",
            "veriexec state",
            "device-shell",
            (p.SHELL_START, p.SHELL_VERIEXEC, p.SHELL_EXIT),
            before=(
                *header,
                "In an SSH or console session on the lab device (the shell is outside Juniper support; "
                "this is the one read the installers make there):",
            ),
            after=(
                f"STOP unless it printed '{p.VERIEXEC_ENFORCING}'. Otherwise results from this device are "
                f"{p.NOT_EVIDENCE}.",
            ),
            status="verified (spike ran exactly this command; 'loaded active enforce' also on SRX4100 25.2R1-S1.4)",
        )
    )
    tls = plan.options.tls
    reads = [p.OP_SHOW_COMMIT, p.cli_file_list(p.VAR_DB), p.cli_file_list(p.JET_DIR)]
    if tls and plan.offline:
        reads.append(p.SHOW_MANAGEMENT_INSTANCE)
    directory_needed = plan.directory is not None and plan.directory.action == "require"
    units.append(
        _unit(
            "2",
            "pending commits and the state directory",
            "device-operational",
            reads,
            after=(
                f"STOP if, in 'show system commit', {p.PENDING_SIGNS}.",
                f"In 'file list {p.VAR_DB} detail', jwicket must be listed as 'drwx------' and '{user}'. If it is "
                + (
                    "absent or listed otherwise, do unit 3 (once, as root), then paste this unit again."
                    if directory_needed
                    else "listed otherwise, stop: the installer's dry run reports R-STATEDIR and the root step."
                ),
                *(
                    (
                        "If 'show configuration system management-instance | display inheritance' printed the "
                        "statement ('management-instance;', the display form inferred; a value set in a "
                        "configuration group shows too, with a comment naming the group), fxp0 is in the "
                        f"{p.MGMT_INSTANCE} "
                        f"routing instance: add the line 'routing_instance = {p.MGMT_INSTANCE}' under [server] in the "
                        "settings file below (verified on SRX4100 25.2R1-S1.4), and expect "
                        "'routing_instance=mgmt_junos' in check C4.",
                    )
                    if tls and plan.offline
                    else ()
                ),
            ),
            status="commands documented (F10, CMT-01); not recorded on a device; output shapes unverified "
            "(Q-INST-01)",
        )
    )
    number = 3
    if directory_needed:
        units.append(
            _unit(
                str(number),
                "the state directory, once, as root",
                "device-shell",
                (p.state_dir_root_step(user),),
                before=(
                    p.directory_fallback(user),
                    "Only if unit 2 did not list jwicket as 'drwx------' and "
                    f"'{user}', in a shell on the lab device as root:",
                ),
                after=(
                    "Leave the root shell, and in your own session paste unit 2 again: jwicket must now be listed as "
                    f"'drwx------' and '{user}'. The installers never do this step and never ask for the root "
                    "password.",
                ),
                status="verified on SRX4100 25.2R1-S1.4 as root (the command: docs/deploy-lab.md step 3; that "
                "root made the directory: " + p.EVIDENCE_SRX4100 + "); outside Juniper support; how you become "
                "root is your lab's own procedure",
            )
        )
        number += 1
    copies = [f for f in plan.files if f.action == "copy"]
    staged = [f for f in plan.files if f.action == "stage"]
    if copies or staged:
        if plan.options.transfer == "scp":
            lines = [p.cli_scp("jwicket.py", user, f.path) for f in copies]
            if not copies:
                lines = [p.cli_scp("jwicket.py", user, p.STAGING_PATH)]
            units.append(
                _unit(
                    str(number),
                    "copy the bundle (workstation)",
                    "workstation",
                    lines,
                    before=(f"In the directory holding the verified jwicket.py (SHA-256 {plan.bundle.file_sha256}):",),
                    status="verified (spike: OpenSSH scp -O into /var/db/scripts/jet)",
                )
            )
            if copies:
                units.append(
                    _unit(
                        f"{number}-alt",
                        "alternative: one copy, then copies on the device",
                        "device-operational",
                        [p.cli_file_copy(p.STAGING_PATH, f.path) for f in copies] + [p.cli_file_delete(p.STAGING_PATH)],
                        before=(
                            "Instead of the three scp lines: copy once to the staging name with "
                            f"'{p.cli_scp('jwicket.py', user, p.STAGING_PATH)}', then on the device:",
                        ),
                        status="'file copy' verified (F01); the owner of an on-device copy unknown (Q-INST-01)",
                    )
                )
        else:
            instance = plan.pull_routing_instance
            if plan.options.transfer == "refresh-from":
                pull = [
                    p.cli_refresh_from(p.STAGING_FILE, str(plan.options.pull_url), plan.options.cert_file, instance)
                ]
            else:
                pull = [p.cli_file_copy(str(plan.options.pull_url), p.STAGING_PATH, instance)]
            pull += [p.cli_file_copy(p.STAGING_PATH, f.path) for f in copies]
            units.append(
                _unit(
                    str(number),
                    "the device fetches the bundle",
                    "device-operational",
                    pull,
                    before=(p.PULL_INSTANCE_NOTE,) if plan.offline else (),
                    status="'file copy <url>' verified to accept HTTP/HTTPS (F01), its certificate checking on Junos "
                    "OS unknown; refresh-from syntax verified (F15), an unconfigured file name unknown (Q-INST-05); "
                    "'routing-instance mgmt_junos' on a management-instance device inferred (JFR-05); the SHA-256 "
                    "check below is the control",
                )
            )
        number += 1
    settings = [f for f in plan.files if f.content == "settings" and f.action == "write"]
    if settings:
        units.append(
            _unit(
                str(number),
                "the settings file (workstation)",
                "file",
                plan.settings_text.splitlines(),
                before=("Save these lines on the workstation as jwicket.ini:",),
                filename="jwicket.ini",
                status="render_settings output; parsed by jwicket.settings in the tests"
                + ("; the TLS settings verified on SRX4100 25.2R1-S1.4 (deploy-lab TLS variant)" if tls else ""),
            )
        )
        number += 1
        ws = [p.WS_SETTINGS_CHMOD, p.cli_scp("jwicket.ini", user, p.SETTINGS_PATH)]
        if any(f.content == "lab-token" and f.action == "write" for f in plan.files):
            ws += [
                p.WS_TOKEN_CREATE,
                p.WS_TOKEN_CHMOD,
                p.cli_scp("lab-token", user, p.LAB_TOKEN_PATH),
                p.WS_TOKEN_REMOVE,
            ]
        units.append(
            _unit(
                str(number),
                "copy the settings (workstation)",
                "workstation",
                ws,
                status="scp -O verified (spike); the lab-token lines from deploy-lab's variant (not in the recorded "
                "results)",
            )
        )
        number += 1
    if any(f.content == "tls-cert" and f.action == "write" for f in plan.files):
        address = plan.options.bind_address
        units.append(
            _unit(
                str(number),
                "the TLS certificate (on the device)",
                "device-shell",
                p.shell_tls_lines(address),
                before=(
                    f"A self-signed RSA-{p.TLS_KEY_BITS} certificate for {address}, made on the device so that its "
                    "private key never leaves it. In an SSH session on the lab device as "
                    f"{user} (not root):",
                ),
                after=(
                    "Write down the 'SHA256 Fingerprint=' line it printed: the browser's certificate warning is "
                    "checked against it (unit 'open the UI'). Never copy tls.key off the device.",
                ),
                status="verified on SRX4100 25.2R1-S1.4 (deploy-lab TLS variant); the shell openssl's version was "
                "not recorded (Python's ssl: OpenSSL 1.1.1zb); outside Juniper support",
            )
        )
        number += 1
    verify = [
        p.cli_file_checksum(f.path)
        for f in plan.files
        if f.action in ("stage", "copy", "keep") and f.content == "bundle" and not _deleted_in_files(plan, f.path)
    ]
    verify += [p.cli_file_list(p.JET_DIR), p.cli_file_list(p.STATE_DIR)]
    tls_expect = (
        f" The same for tls.key, and '-rw-r--r--' and '{user}' for tls.crt."
        if any(f.content == "tls-key" for f in plan.files)
        else ""
    )
    units.append(
        _unit(
            str(number),
            "check the files",
            "device-operational",
            verify,
            after=(
                f"Expect SHA256 {plan.bundle.file_sha256} for each J-Wicket file, '-rw-r--r--' and '{user}' for "
                f"each in {p.JET_DIR}, and '-rw-------' and '{user}' for jwicket.ini.{tls_expect} If a mode is "
                f"wrong: '{p.cli_file_change_permission(p.DAEMON_PATH, 0o644)}' (and the same for the others); "
                "outside Juniper support, the shell's 'chmod' does the same.",
            ),
            status="'file checksum sha-256' and 'file list ... detail' verified (F05, F10)",
        )
    )
    number += 1
    if set_files:
        for stage in plan.stages:
            if stage.name != "bootstrap":
                units.append(
                    _unit(
                        f"{number}-{stage.name}",
                        f"the {stage.name} set file",
                        "file",
                        p.stage_lines(stage, layout),
                        filename=set_file_name(stage),
                        before=(f"Save these lines as {set_file_name(stage)}:",),
                    )
                )
        units.append(
            _unit(
                str(number),
                "copy the set files (workstation)",
                "workstation",
                [p.cli_scp(set_file_name(s), user, set_file_name(s)) for s in plan.stages if s.name != "bootstrap"],
                status="scp -O verified (spike); the home directory as target inferred",
            )
        )
        number += 1
    cert_sha = plan.receipt.tls_cert_sha256
    hint = _fingerprint_hint(plan)
    model: Optional[StatementSet] = (
        prior.direct if prior is not None else (PriorState().direct if plan.offline else None)
    )
    for stage in plan.stages:
        if stage.name == "bootstrap":
            continue
        pre_copy = [
            p.cli_run(p.cli_file_copy(str(f.source), f.path))
            for f in stage.files_before_commit
            if f.action in ("replace", "backup")
        ]
        on_failure = [
            f"On failure, before the deadline: '{p.cli_file_copy(str(f.source), f.path)}' (restores the " "old bytes)."
            for f in stage.restore_on_failure
            if f.content == "bundle"
        ]
        units.extend(
            _stage_units(
                number,
                stage,
                layout,
                model,
                user,
                bundle_has_results=plan.bundle.has("result-files"),
                set_files=set_files,
                pre_copy=pre_copy,
                on_failure=on_failure,
                port=plan.options.port,
                offline=plan.offline,
                fingerprint_hint=hint,
            )
        )
        model = None if model is None else p.apply_lines(model, p.stage_lines(stage, layout))
        number += 1
    if tls:
        units.append(
            _unit(
                str(number),
                "open the UI in a browser (workstation)",
                "workstation",
                (str(plan.url),),
                after=render_open(plan, cert_sha256=cert_sha)[1:],
                status="HTTPS on the management address verified on SRX4100 25.2R1-S1.4 (TLS 1.2 and 1.3)",
            )
        )
    else:
        units.append(
            _unit(
                str(number),
                "open the UI through an SSH tunnel (workstation)",
                "workstation",
                (render_tunnel(user, plan.options.port, ssh_port=plan.options.ssh_port),),
                after=(
                    f"Then browse to http://127.0.0.1:{plan.options.port}/ while the SSH session stays open.",
                    p.TUNNEL_WARNING,
                ),
                status="explicit 127.0.0.1 bind (INV-10); SSH forwarding refused on SRX4100 25.2R1-S1.4 (verified)",
            )
        )
    return tuple(units)


def _fingerprint_hint(plan: InstallPlan) -> str:
    """Where the operator finds the certificate fingerprint to compare in the browser (--access tls)."""
    if any(f.content == "tls-cert" and f.action == "write" for f in plan.files):
        if plan.method is Method.CLI:
            return "the 'SHA256 Fingerprint=' line unit 'the TLS certificate' printed"
        return "the SHA-256 fingerprint the installer printed"
    if plan.receipt.tls_cert_sha256 is not None:
        return f"{p.fingerprint_display(plan.receipt.tls_cert_sha256)} (this install's record)"
    return (
        "what 'openssl x509 -in /var/db/jwicket/tls.crt -noout -fingerprint -sha256' prints in a shell on the " "device"
    )


def render_open(plan: InstallPlan, *, cert_sha256: Optional[str] = None) -> Tuple[str, ...]:
    """How the operator reaches the UI after a run: --access tls, the URL and the certificate fingerprint to
    compare (the run's own, or the one the M6 openssl unit printed); --access tunnel, the 'ssh -L' line."""
    if plan.options.tls:
        fingerprint = p.fingerprint_display(cert_sha256) if cert_sha256 is not None else _fingerprint_hint(plan)
        return (
            str(plan.url),
            f"Browse to {plan.url} from a host on the management network. The browser warns about a self-signed "
            f"certificate: accept it only if its SHA-256 fingerprint is {fingerprint}.",
        )
    return (
        render_tunnel(plan.options.user, plan.options.port, ssh_port=plan.options.ssh_port),
        f"Then browse to http://127.0.0.1:{plan.options.port}/ while the SSH session stays open.",
    )


def render_cli_uninstall_units(uplan: UninstallPlan, *, prior: Optional[PriorState] = None) -> Tuple[PasteUnit, ...]:
    """M6 removal (and the on-box uninstall-cli.txt): the removal stages, then the file deletes once no
    J-Wicket process is listed, then what this tool does not remove."""
    if uplan.blocked:
        raise p.PlanBlocked("the uninstall plan is blocked by a refusal: " + ", ".join(r.code for r in uplan.refusals))
    user = uplan.user or "<user>"
    units: List[PasteUnit] = [
        _unit(
            "1",
            "pending commits",
            "device-operational",
            (p.OP_SHOW_COMMIT,),
            before=(
                p.DEVICE_STATUS,
                *(
                    p.warning_text(w, uplan.user)
                    for w in uplan.warnings
                    if w not in ("DEVICE_STATUS", "NOT_REMOVED_BY_TOOL", "STATE_DIR_LEFT")
                ),
            ),
            after=(
                f"STOP if, in 'show system commit', {p.PENDING_SIGNS}.",
                *(
                    f"Stays: {k.key} ({p.SPEC_BY_KEY[k.key].path[-1] if k.key in p.SPEC_BY_KEY else k.key}): {k.reason}"
                    for k in uplan.kept
                ),
            ),
            status="verified command",
        )
    ]
    model: Optional[StatementSet] = None if prior is None else prior.direct
    number = 2
    for stage in uplan.stages:
        units.extend(_stage_units(number, stage, uplan.layout, model, user, bundle_has_results=False, set_files=False))
        model = None if model is None else p.apply_lines(model, p.stage_lines(stage, uplan.layout))
        number += 1
    deletes = [
        p.cli_file_delete(f.path)
        for f in (*uplan.files, *(f for s in uplan.stages for f in s.files_after_confirm))
        if f.action == "delete"
    ]
    if deletes:
        units.append(
            _unit(
                str(number),
                "check that no J-Wicket process runs",
                "device-operational",
                (f"show extension-service status {p.DAEMON_FILE} | no-more",),
                after=(
                    "STOP unless no J-Wicket process is listed. If one still runs, stop here: the files stay, and "
                    "deploy-lab step 9 shows how to stop it by hand.",
                ),
                status="command verified ([show-ext]); deleting a stanza stopping the app unknown (Q-INST-03)",
            )
        )
        number += 1
        units.append(
            _unit(
                str(number),
                "delete J-Wicket's files",
                "device-operational",
                deletes,
                status="'file delete' verified (F10); every name is one of J-Wicket's fixed names",
            )
        )
        number += 1
    if uplan.state_dir_left:
        units.append(
            _unit(
                str(number),
                "the empty state directory, as root",
                "device-shell",
                (p.STATE_DIR_ROOT_REMOVE,),
                before=(p.STATE_DIR_LEFT, "In a shell on the lab device as root:"),
                status="outside Juniper support; unverified (its counterpart, the root step that made it, verified on "
                "SRX4100 25.2R1-S1.4)",
            )
        )
    units.append(
        _unit(
            "end",
            "not removed by this tool",
            "workstation",
            (),
            before=(
                p.NOT_REMOVED_BY_TOOL,
                *(f"Left in {p.STATE_DIR}: {path}" for path in uplan.leftovers),
                *(f"Not known to this tool: {leaf}" for leaf in uplan.unknown_leaves),
            ),
        )
    )
    return tuple(units)


def render_bootstrap_units(bootstrap: Bootstrap, *, follow_up: Sequence[str] = ()) -> Tuple[PasteUnit, ...]:
    """The bootstrap units of spec 7.7: they end at 'commit confirmed <minutes> comment "jwicket-bootstrap
    <kind>[ <nonce>]"' and never contain a confirming commit (SC-22). ``follow_up`` are the executor's
    own next command lines (sanitised), printed after the units."""
    user = bootstrap.user
    stage = Stage(
        "bootstrap",
        bootstrap.add,
        (),
        (),
        bootstrap.comment,
        bootstrap.confirm_comment,
        p.Minutes(bootstrap.minutes),
        (),
    )
    lines = p.stage_lines(stage, Layout.DIRECT)
    prose = [p.warning_text(w, user) for w in bootstrap.warnings if w != "KEEP_SESSION_OPEN"]
    prose.append(f"Check that your CLI prompt shows {user}@<the lab device you intend> before unit A.")
    language_note: Tuple[str, ...] = ()
    if any(s.key == "S1" for s in bootstrap.add) and bootstrap.kind != "netconf":
        language_note = ("If the comparison does not list 'language python3', it was already set: that is fine.",)
    units = [
        _unit(
            "A",
            "bootstrap: open configuration mode",
            "device-configuration",
            (p.CLI_CONFIGURE, p.CLI_SHOW_COMMIT),
            before=tuple(prose),
            opens=True,
            after=(f"STOP if {p.PENDING_SIGNS}: type 'exit'. Otherwise paste unit B.",),
            status="'run' verified; '| no-more' inferred",
        ),
        _unit(
            "B",
            "bootstrap: the configuration change",
            "device-configuration",
            (*lines, p.CLI_COMPARE),
            after=compare_expectation(lines, notes=language_note),
            status="statements documented (Spec 006 section 7.3); unverified on a device",
        ),
        _unit(
            "C",
            "bootstrap: commit confirmed (not confirmed by you)",
            "device-configuration",
            (p.cli_commit_confirmed(bootstrap.minutes, bootstrap.comment),),
            after=(
                f"Deadline: {bootstrap.minutes} minutes. The installer confirms this commit only after its own "
                "checks and your typed host name; otherwise Junos removes it.",
            ),
            status="inferred to combine minutes and comment",
        ),
        _unit(
            "D",
            "bootstrap: leave configuration mode",
            "device-configuration",
            (p.CLI_EXIT,),
            after=(p.KEEP_SESSION_OPEN,),
        ),
    ]
    if follow_up:
        units.append(
            _unit(
                "E", "then, within the deadline", "workstation", [p.sanitize_display(line, 400) for line in follow_up]
            )
        )
    return tuple(units)


def units_to_text(units: Sequence[PasteUnit]) -> str:
    """Plain text: prose, then each unit fenced, so a terminal's copy keeps a unit whole (UI-006-07)."""
    out: List[str] = []
    for unit in units:
        out.extend(unit.before)
        if unit.lines or unit.number != "end":
            label = f"Unit {unit.number} ({unit.where}): {unit.title}"
            if unit.filename:
                label += f" [file {unit.filename}]"
            out.append(label)
            if unit.status:
                out.append(f"Status: {unit.status}")
            out.append("```")
            out.extend(unit.lines)
            out.append("```")
        out.extend(unit.after)
        out.append("")
    return "\n".join(out)


# ------------------------------------------------------------------------------------------------
# Plan diff and dry-run text (spec 8.3, UI-006-04)
# ------------------------------------------------------------------------------------------------


def render_plan_diff(plan: InstallPlan, prior: PriorState) -> str:
    """The plan's diff in Junos's patch form, stage by stage, from the committed configuration (reads
    only). Junos's own 'show | compare' is printed after the gate, before each confirmed commit."""
    model = prior.direct
    out: List[str] = []
    for stage in plan.stages:
        lines = p.stage_lines(stage, plan.layout)
        if stage.already_committed:
            out.append(
                f"# stage {stage.name}: already committed by you, unconfirmed; the installer confirms it "
                "after the gate (comment: " + stage.comment + ")"
            )
            out.extend(lines)
            continue
        after = p.apply_lines(model, lines)
        out.append(f"# stage {stage.name}: commit confirmed {stage.confirm_minutes} (comment: {stage.comment})")
        out.append(p.patch_text(model, after).rstrip("\n") or "(no configuration change)")
        model = after
    return "\n".join(out) + "\n"


def _file_line(step: p.FileStep) -> str:
    sha = f" sha256 {step.sha256}" if step.sha256 else ""
    source = f" from {step.source}" if step.source else ""
    return f"  {step.action:8} {step.path} mode {step.mode:04o}{sha}{source}"


def _kept_line(key: str) -> str:
    """A present-before statement as the set line an operator recognises, not its internal key."""
    spec = p.SPEC_BY_KEY.get(key)
    if spec is None:
        return key
    value = f" {spec.fixed_value}" if spec.value_kind == "fixed" and spec.fixed_value else ""
    return "set " + " ".join(spec.path) + value


def render_plan_text(plan: InstallPlan, prior: PriorState, *, status: bool = True) -> str:
    """The dry-run printout in UI-006-04's order. Never contains the host name (the gate asks for it).
    ``status`` False leaves out DEVICE_STATUS when the caller already printed it (every warning and the
    status line appear once)."""
    user = plan.options.user
    out = [p.DEVICE_STATUS, ""] if status else []
    out.append(
        f"Device: model {plan.facts.model or 'unknown'}, release {plan.facts.junos_version or 'unknown'}, "
        f"serial {plan.facts.serial or 'unknown'}"
    )
    out.append("")
    out.extend(p.warning_text(w, user) for w in plan.warnings if w not in ("DEVICE_STATUS", "ROOT_BLAST_RADIUS"))
    out.append("")
    if plan.production_signs:
        out.append("Shown, not judged (a production device would show these):")
        out.extend(f"  {s}" for s in plan.production_signs)
        out.append("")
    if plan.refusals:
        out.append("Refusals:")
        for refusal in plan.refusals:
            state = f"overridden by {refusal.override}" if refusal.overridden else "blocks"
            out.append(f"  {refusal.code} ({state}): {refusal.message}")
            if refusal.detail:
                out.append(f"    {refusal.detail}")
        out.append("")
    out.append("The plan's change (patch form, from the committed configuration):")
    out.append(render_plan_diff(plan, prior).rstrip("\n"))
    out.append("")
    out.append("Files:")
    if plan.directory is not None:
        out.append(_file_line(plan.directory))
    out.extend(_file_line(f) for f in plan.files)
    for stage in plan.stages:
        out.extend(_file_line(f) for f in (*stage.files_before_commit, *stage.files_after_confirm))
    if plan.present_before:
        out.append("")
        out.append("Already present and kept (never removed by this tool):")
        out.extend(f"  {_kept_line(key)}" for key in plan.present_before)
    options = plan.options
    where = f" in routing instance {plan.routing_instance}" if plan.routing_instance else ""
    if options.tls:
        listener = (
            f"HTTPS on {p.host_port(options.bind_address, options.port)}{where}, reachable by anything that "
            "reaches that address"
        )
    else:
        listener = f"{p.LOOPBACK}:{options.port} only, through an SSH tunnel"
    if any(s.name == "runtime" and not s.already_committed for s in plan.stages):
        out.append("")
        if options.tls:
            out.append(
                f"The runtime commit starts J-Wicket, listening with TLS on "
                f"{p.host_port(options.bind_address, options.port)}{where}: browse to {plan.url} and compare "
                "the certificate's SHA-256 fingerprint with the one the installer prints."
            )
        else:
            out.append(
                f"The runtime commit starts J-Wicket, listening on {p.LOOPBACK}:{options.port} only (reach it "
                "through an SSH tunnel; 'jwicket-install open' prints the 'ssh -L' line)."
            )
    out.append("")
    # OPX-11: what this plan's stages do, not only whether the statement was there before someone else.
    adds_s1 = any(s.key == "S1" for stage in plan.stages for s in stage.add) or (
        plan.bootstrap is not None and any(s.key == "S1" for s in plan.bootstrap.add)
    )
    posture = "adds language python3" if adds_s1 else "language python3 already set"
    netconf = (
        "adds netconf ssh (reachable wherever SSH is)"
        if any(s.key == "S8" for stage in plan.stages for s in stage.add)
        else "netconf ssh already set or not needed"
    )
    out.append(
        f"Blast radius: posture: {posture}; listener: {listener}; NETCONF: {netconf}; account: "
        + p.root_blast_radius(user)
    )
    windows = ", ".join(f"{s.name} {s.confirm_minutes} min" for s in plan.stages)
    out.append("Confirm windows: " + (windows or "none (nothing to commit)"))
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------------------------------------
# Plan JSON (M1 --json, M2's from_json)
# ------------------------------------------------------------------------------------------------


def _json_safe(value: object, where: str) -> object:
    if isinstance(value, str):
        if JSON_TOKEN_RE.match(value) is None:
            raise p.InvariantError(f"plan JSON field {where} holds characters outside the token set")
        return value
    if isinstance(value, bool) or value is None or isinstance(value, int):
        return value
    if isinstance(value, (list, tuple)):
        return [_json_safe(v, f"{where}[]") for v in value]
    if isinstance(value, dict):
        return {_json_safe(k, where): _json_safe(v, f"{where}.{k}") for k, v in value.items()}
    raise p.InvariantError(f"plan JSON field {where} has an unsupported type")


def _file_json(step: p.FileStep) -> Dict[str, object]:
    return {
        "path": step.path,
        "content": step.content,
        "mode": f"{step.mode:04o}",
        "sha256": step.sha256,
        "action": step.action,
        "phase": step.phase,
        "stage": step.stage,
        "source": step.source,
    }


def plan_to_json(plan: InstallPlan) -> str:
    """Schema 2, validated tokens only (INV-12): stage names, statement keys and lines, file paths, modes,
    hashes, check ids, refusal codes and warning ids. No host name (INV-05), no prose, no device text."""
    stages = []
    for stage in plan.stages:
        layout = p.stage_layout(stage, plan.layout)
        stages.append(
            {
                "name": stage.name,
                "comment": stage.comment,
                "confirm_comment": stage.confirm_comment,
                "confirm_minutes": int(stage.confirm_minutes),
                "already_committed": stage.already_committed,
                "add": [{"key": s.key, "line": s.set_line(layout)} for s in stage.add],
                "remove": [{"key": s.key, "line": s.delete_line(layout)} for s in stage.remove],
                "lines": list(p.stage_lines(stage, plan.layout)),
                "checks": list(stage.check_ids),
                "post_confirm_checks": [c.id for c in stage.post_confirm_checks],
                "files_before_commit": [_file_json(f) for f in stage.files_before_commit],
                "files_after_confirm": [_file_json(f) for f in stage.files_after_confirm],
                "restore_on_failure": [_file_json(f) for f in stage.restore_on_failure],
            }
        )
    bootstrap = None
    if plan.bootstrap is not None:
        b = plan.bootstrap
        bootstrap = {
            "kind": b.kind,
            "nonce": b.nonce,
            "comment": b.comment,
            "confirm_comment": b.confirm_comment,
            "minutes": b.minutes,
            "keys": list(b.keys),
        }
    document: Dict[str, object] = {
        "schema": p.PLAN_SCHEMA,
        "installer": plan.receipt.installer,
        "method": plan.method.value,
        "layout": plan.layout.value,
        "backend": plan.options.backend,
        "user": plan.options.user,
        "port": plan.options.port,
        "access": plan.options.access,
        "listen_address": plan.options.listen_address,
        "routing_instance": plan.routing_instance,
        "pull_routing_instance": plan.pull_routing_instance,
        "lab_hardware": plan.lab_hardware,
        "blocked": plan.blocked,
        "no_change": plan.no_change,
        "upgrade": plan.upgrade,
        "offline": plan.offline,
        "bundle": {
            "version": plan.bundle.version,
            "source_ref": plan.bundle.source_ref,
            "file_sha256": plan.bundle.file_sha256,
            "payload_sha256": plan.bundle.payload_sha256,
            "size": plan.bundle.size,
            "features": sorted(plan.bundle.features),
        },
        "provenance": {
            "kind": plan.provenance.kind,
            "detail": list(plan.provenance.detail),
            "evidence": plan.provenance.evidence,
        },
        "device": {"model": plan.facts.model, "junos_version": plan.facts.junos_version, "serial": plan.facts.serial},
        "bootstrap": bootstrap,
        "directory": None if plan.directory is None else _file_json(plan.directory),
        "files": [_file_json(f) for f in plan.files],
        "final_files": [_file_json(f) for f in plan.final_files],
        "stages": stages,
        "status_checks": [c.id for c in plan.status_checks],
        "warnings": list(plan.warnings),
        "production_signs": list(plan.production_signs),
        "refusals": [
            {
                "code": r.code,
                "override": r.override,
                "overridden": r.overridden,
                "detail": r.detail if JSON_TOKEN_RE.match(r.detail) else "",
            }
            for r in plan.refusals
        ],
        "present_before": list(plan.present_before),
        "overrides": sorted(plan.overrides),
    }
    return json.dumps(_json_safe(document, "plan"), indent=2, sort_keys=True) + "\n"


# ------------------------------------------------------------------------------------------------
# The op script's payload (ONBOX build_op.py)
# ------------------------------------------------------------------------------------------------


def op_payload(bundle: BundleId, urls: Mapping[str, str], *, plan: Optional[InstallPlan] = None) -> Dict[str, object]:
    """The constants the on-box op script embeds: the bundle's identity, the per-tag URLs (https only),
    the modules C3 requires, every warning text and the gate prompt, the statement table (S1..S14) and
    the plan schema. With ``plan``, also that plan's stage lines (tests; a release build has no user)."""
    checked: Dict[str, str] = {}
    for name, url in sorted(urls.items()):
        if re.match(r"^[a-z][a-z0-9-]{0,31}\Z", name) is None:
            raise p.InputError(f"payload URL name {name!r} is not a token")
        checked[name] = p.validate_url(url, allow_plain_http=False)
        if "/releases/latest" in url:
            raise p.InputError("per-tag URLs only: /releases/latest cannot point at a pre-release (verified)")
    payload: Dict[str, object] = {
        "schema": p.PLAN_SCHEMA,
        "installer_version": p._installer_version(),
        "bundle": {
            "version": bundle.version,
            "source_ref": bundle.source_ref,
            "file_sha256": bundle.file_sha256,
            "payload_sha256": bundle.payload_sha256,
            "size": bundle.size,
            "features": sorted(bundle.features),
        },
        "urls": checked,
        "required_modules": {k: list(v) for k, v in p.REQUIRED_MODULES.items()},
        "recorded_modules": list(p.RECORDED_MODULES),
        "warnings": dict(p.WARNINGS),
        "lab_gate_prompt": p.LAB_GATE_PROMPT,
        "lab_hardware_prompt": p.LAB_HARDWARE_PROMPT,
        "lab_hardware_answer": p.LAB_HARDWARE_ANSWER,
        "state_dir_root_step": p.STATE_DIR_ROOT_STEP,
        "access_modes": list(p.ACCESS_MODES),
        "device_status": p.DEVICE_STATUS,
        "veriexec_enforcing": p.VERIEXEC_ENFORCING,
        "statements": [
            {"key": s.key, "path": list(s.path), "value_kind": s.value_kind, "fixed_value": s.fixed_value}
            for s in p.STATEMENT_TABLE
        ],
        "paths": {
            "jet_dir": p.JET_DIR,
            "op_dir": p.OP_DIR,
            "state_dir": p.STATE_DIR,
            "staging": p.STAGING_PATH,
            "settings": p.SETTINGS_PATH,
            "tls_key": p.TLS_KEY_PATH,
            "tls_cert": p.TLS_CERT_PATH,
            "receipt": p.RECEIPT_PATH,
            "uninstall_cli": p.UNINSTALL_CLI_PATH,
        },
    }
    if plan is not None:
        payload["stages"] = [{"name": s.name, "lines": list(p.stage_lines(s, plan.layout))} for s in plan.stages]
    return payload


def payload_lines(
    payload: Mapping[str, object],
    keys: Sequence[str],
    *,
    user: str,
    bundle_sha256: str,
    op_sha256: Optional[str] = None,
) -> Tuple[str, ...]:
    """Direct-layout set lines for ``keys`` built only from the payload's statement table."""
    table = payload.get("statements")
    if not isinstance(table, list):
        raise p.InputError("payload has no statement table")
    rows = {row["key"]: row for row in table if isinstance(row, dict)}
    out: List[str] = []
    for key in keys:
        row = rows[key]
        kind = row["value_kind"]
        value = {
            "fixed": row["fixed_value"],
            "presence": "",
            "user": p.validate_user(user),
            "bundle-sha256": p.validate_sha256(bundle_sha256, "bundle SHA-256"),
            "op-sha256": p.validate_sha256(str(op_sha256), "op SHA-256") if kind == "op-sha256" else "",
        }[kind]
        out.append("set " + " ".join(row["path"]) + (f" {value}" if value else ""))
    return tuple(out)
