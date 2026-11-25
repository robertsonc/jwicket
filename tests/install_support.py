"""Shared helpers for the installer tests (stdlib only, Python 3.7 syntax). Nothing here talks to a device.

Importing this module puts ``tools/`` on ``sys.path`` so ``jwicket_install`` imports without
installing anything; the CI command stays ``PYTHONPATH=src python -m unittest discover -s tests``.
Junos-eznc, paramiko and scp are never needed here.

Fixtures live in tests/fixtures/install/ (synthetic; see its README.md): ``base/`` is a fresh lab vSRX,
and each ``scenarios/<name>/`` directory overrides some of base's files and describes itself in
``scenario.json``.
"""

from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple, Union

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from jwicket_install import plan, state  # noqa: E402 - tools/ must be on sys.path first

FIXTURES = REPO / "tests" / "fixtures" / "install"
BASE = FIXTURES / "base"
SCENARIOS = FIXTURES / "scenarios"
GOLDEN = FIXTURES / "golden"

# The synthetic bundle and account every fixture uses (tests/fixtures/install/README.md).
USER = "labadmin"
BUNDLE_SHA = "1f" * 32
PAYLOAD_SHA = "2e" * 32
OLD_SHA = "3d" * 32
OP_SHA = "4c" * 32
SOURCE_REF = "a1" * 20
NONCE = "k3v9qt"
HOST = "lab-vsrx-1"
FINGERPRINT = "SHA256:" + "A" * 43
# --access tls (the default): the fixtures' management address (TEST-NET-1, RFC 5737) and the SHA-256 of
# the certificate a run generated (receipts of the installs in the fixtures carry it).
LISTEN = "192.0.2.10"
CERT_SHA = "5b" * 32
# The SHA-256 of that certificate's tls.crt file (what 'file checksum sha-256' reads on the device) and its
# notAfter, as the fixtures' receipts record them (SEC-R1, OPX-04). notAfter is far in the future so that no
# test depends on today's date; the renewal tests pass their own ``now``.
CERT_FILE_SHA = "6a" * 32
CERT_NOT_AFTER = "2099-01-01T00:00:00Z"

# Secrets planted in the fixtures that must never survive parsing or reach any output (AC-006-22).
PLANTED_SECRETS = (
    "$9$",
    "FIXTURE-PLACEHOLDER-NOT-A-SECRET",
    "$6$",
    "FIXTURE-PLACEHOLDER-HASH",
    "fixture-pass",
    "fixture-user",
    "FIXTURE-DEVICE-ID",
    "mirror.example.net",
    "encrypted-password",
)

# file name in a fixture directory -> the directory it lists, or the path its checksum belongs to
LIST_FILES = {
    "file-list-var-db-scripts-jet.xml": plan.JET_DIR,
    "file-list-var-db-scripts-op.xml": plan.OP_DIR,
    "file-list-var-db.xml": plan.VAR_DB,
    "file-list-var-db-jwicket.xml": plan.STATE_DIR,
}


def bundle(sha: str = BUNDLE_SHA, features: Sequence[str] = ("build-line", "result-files")) -> plan.BundleId:
    return plan.BundleId(sha, 1_783_074, "0.1.0.dev1", SOURCE_REF, PAYLOAD_SHA, frozenset(features))


def provenance(kind: str = "release-record") -> plan.Provenance:
    return plan.Provenance(kind, ("v0.1.0.dev1",), kind not in plan.NO_EVIDENCE_PROVENANCE)


def options(**overrides: Any) -> plan.Options:
    """Options with the product's defaults: --access tls on LISTEN. With ``access="tunnel"``, or the
    lab-token backend (whose default access is the tunnel), no listen address unless one is given."""
    values: Dict[str, Any] = {"user": USER}
    values.update(overrides)
    access = values.get("access") or ("tunnel" if values.get("backend") == "lab-token" else plan.DEFAULT_ACCESS)
    if access == "tls":
        values.setdefault("listen_address", LISTEN)
    return plan.Options(**values)


def scenario_names() -> List[str]:
    return sorted(d.name for d in SCENARIOS.iterdir() if d.is_dir())


def meta(name: str) -> Dict[str, Any]:
    data = json.loads((SCENARIOS / name / "scenario.json").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def raw_files(name: str) -> Dict[str, str]:
    """Base files overlaid with the scenario's own (scenario.json excluded)."""
    files = {p.name: p.read_text(encoding="utf-8") for p in BASE.iterdir() if p.is_file()}
    for path in (SCENARIOS / name).iterdir():
        if path.is_file() and path.name != "scenario.json":
            files[path.name] = path.read_text(encoding="utf-8")
    return files


def replies(name: str) -> Dict[str, state.ReplyInput]:
    """Replies keyed by the base name without extension; scenario.json's rpc_errors become RpcErrorReply."""
    out: Dict[str, state.ReplyInput] = {}
    for file_name, text in raw_files(name).items():
        out[file_name.rsplit(".", 1)[0] if file_name.endswith((".xml", ".txt", ".json")) else file_name] = text
    for key, message in meta(name).get("rpc_errors", {}).items():
        out[key] = state.RpcErrorReply(message)
    return out


def facts_of(name: str) -> plan.DeviceFacts:
    r = replies(name)
    return state.facts_from_replies(
        r.get("software-information"),
        r.get("chassis-cluster-status"),
        r.get("chassis-inventory"),
        r.get("config-raw"),
        flow_sessions=state.flow_session_count(r.get("flow-session-summary")),
    )


def deltas_of(name: str) -> Dict[int, str]:
    out: Dict[int, str] = {}
    for file_name, text in raw_files(name).items():
        if file_name.startswith("rollback-delta-") and file_name.endswith(".txt"):
            out[int(file_name[len("rollback-delta-") : -4])] = text
    return out


def _text(value: state.ReplyInput) -> Optional[str]:
    return value if isinstance(value, str) else None


def prior_of(name: str) -> plan.PriorState:
    r = replies(name)
    file_lists = {directory: r.get(file_name.rsplit(".", 1)[0]) for file_name, directory in LIST_FILES.items()}
    checksums: Dict[str, state.ReplyInput] = {}
    for key, value in r.items():
        if key.startswith("sha256-"):
            base_name = key[len("sha256-") :]
            if base_name == "jwicket.ini":
                path = plan.SETTINGS_PATH
            elif base_name == "tls.crt":
                path = plan.TLS_CERT_PATH
            else:
                path = f"{plan.JET_DIR}/{base_name}"
            checksums[path] = value
    receipts = {"workstation": _text(r.get("workstation-receipt")), "device": _text(r.get("device-receipt"))}
    return state.prior_from_replies(
        r.get("config-inherited", r.get("config-raw")),
        r.get("config-raw"),
        r.get("commit-information"),
        file_lists,
        receipts,
        _text(r.get("veriexec")),
        checksums=checksums,
    )


def evidence_of(name: str, prior: Optional[plan.PriorState] = None) -> plan.OwnershipEvidence:
    prior = prior if prior is not None else prior_of(name)
    return plan.ownership_from_history(prior.history, deltas_of(name), user=USER)


def prepared(name: str, method: plan.Method = plan.Method.WORKSTATION) -> Tuple[plan.DeviceFacts, plan.PriorState]:
    """Facts and prior of a scenario, with its own bootstrap marked when scenario.json names one."""
    facts = facts_of(name)
    prior = prior_of(name)
    boot = meta(name).get("bootstrap")
    if boot:
        found = plan.recognise_bootstrap(
            prior, method=method, user=USER, nonce=boot["nonce"], delta_text=deltas_of(name).get(0, "")
        )
        if found is not None:
            prior = plan.mark_own_bootstrap(prior, found)
    return facts, prior


def plan_for(
    name: str,
    *,
    method: plan.Method = plan.Method.WORKSTATION,
    overrides: Sequence[str] = (),
    bundle_id: Optional[plan.BundleId] = None,
    **option_overrides: Any,
) -> plan.InstallPlan:
    facts, prior = prepared(name, method)
    return plan.build_install_plan(
        bundle() if bundle_id is None else bundle_id,
        provenance(),
        options(**option_overrides),
        facts,
        prior,
        method=method,
        overrides=frozenset(overrides),
        evidence=evidence_of(name, prior),
        op_sha256=OP_SHA if method is plan.Method.ONBOX_LOCAL else None,
    )


# ------------------------------------------------------------------------------------------------
# Simulating a run on the configuration model (AC-006-03)
# ------------------------------------------------------------------------------------------------


def _model_prior(prior: plan.PriorState, direct: plan.StatementSet, **changes: Any) -> plan.PriorState:
    """``prior`` with the model ``direct`` as its raw view and the model's expansion as its effective view."""
    values: Dict[str, Any] = {"direct": direct, "effective": plan.expand_groups(direct)}
    values.update(changes)
    return dataclasses.replace(prior, **values)


def with_bootstrap(prior: plan.PriorState, bootstrap: plan.Bootstrap) -> Tuple[plan.PriorState, str]:
    """The prior state after the operator pasted ``bootstrap``'s units (pending, unconfirmed)."""
    stage = plan.Stage(
        "bootstrap",
        bootstrap.add,
        (),
        (),
        bootstrap.comment,
        bootstrap.confirm_comment,
        plan.Minutes(bootstrap.minutes),
        (),
    )
    lines = plan.stage_lines(stage, plan.Layout.DIRECT)
    after = plan.apply_lines(prior.direct, lines)
    delta = plan.patch_text(prior.direct, after)
    entry = plan.CommitEntry(
        0,
        bootstrap.user,
        "cli",
        bootstrap.comment,
        None,
        "commit confirmed, rollback in 10mins",
        "2026-11-24 20:48:00 UTC",
    )
    shifted = tuple(dataclasses.replace(e, sequence=e.sequence + 1) for e in prior.history)
    return _model_prior(prior, after, pending=plan.Pending.OTHER, history=(entry, *shifted)), delta


@dataclasses.dataclass(frozen=True)
class Run:
    prior: plan.PriorState  # the state after the run
    deltas: Dict[int, str]  # committed delta per history sequence (newest 0)


def simulate_install(install: plan.InstallPlan, prior: plan.PriorState, deltas: Mapping[int, str]) -> Run:
    """Apply every stage of ``install`` to the model, as confirmed commits with the installer's comments,
    and write the files and receipts it would write. The device side of this is unverified (Q-INST-06)."""
    model = prior.direct
    history: List[plan.CommitEntry] = list(prior.history)
    run_deltas: Dict[int, str] = dict(deltas)
    if prior.own_bootstrap is not None and history:
        history[0] = dataclasses.replace(history[0], confirmed_state="")

    def commit(comment: str, delta: str) -> None:
        nonlocal history, run_deltas
        history = [dataclasses.replace(e, sequence=e.sequence + 1) for e in history]
        run_deltas = {k + 1: v for k, v in run_deltas.items()}
        history.insert(0, plan.CommitEntry(0, install.options.user, "netconf", comment, None, "", None))
        run_deltas[0] = delta

    for stage in install.stages:
        if stage.already_committed:
            commit(stage.confirm_comment, "")
            continue
        after = plan.apply_lines(model, plan.stage_lines(stage, install.layout))
        commit(stage.comment, plan.patch_text(model, after))
        commit(stage.confirm_comment, "")
        model = after
    files = dict(prior.files)
    checksums = dict(prior.checksums)
    steps = [
        *install.files,
        *(f for s in install.stages for f in (*s.files_before_commit, *s.files_after_confirm)),
        *install.final_files,
    ]
    for step in steps:
        if step.action in ("stage", "copy", "write", "replace", "backup"):
            files[step.path] = plan.FileInfo(step.path, install.options.user, step.mode, 1, False)
            if step.sha256:
                checksums[step.path] = step.sha256
            elif step.content == "tls-cert" and step.action == "write":
                checksums[step.path] = CERT_FILE_SHA
        elif step.action == "delete":
            files.pop(step.path, None)
            checksums.pop(step.path, None)
    wrote_cert = any(f.content == "tls-cert" and f.action == "write" for f in install.files)
    receipt = plan.receipt_for_run(
        install,
        host_key_sha256=(FINGERPRINT,),
        time="2026-11-24T21:00:00Z",
        bootstrap_confirmed=install.bootstrap is not None or None,
        tls_cert_sha256=CERT_SHA if wrote_cert else None,
        lab_hardware_attested=True if install.lab_hardware else None,
        tls_cert_not_after=CERT_NOT_AFTER if wrote_cert else None,
        tls_cert_file_sha256=CERT_FILE_SHA if wrote_cert else None,
    )
    after_prior = _model_prior(
        prior,
        model,
        pending=plan.Pending.NONE,
        own_bootstrap=None,
        history=tuple(history),
        files=files,
        checksums=checksums,
        workstation_receipt=receipt,
        device_receipt=receipt,
    )
    return Run(after_prior, run_deltas)


def simulate_uninstall(uplan: plan.UninstallPlan, prior: plan.PriorState) -> plan.StatementSet:
    model = prior.direct
    for stage in uplan.stages:
        model = plan.apply_lines(model, plan.stage_lines(stage, uplan.layout))
    return model


def all_overrides(name: str) -> FrozenSet[str]:
    return frozenset(meta(name).get("needs", ()))


def strings_in(value: Any) -> List[str]:
    """Every string anywhere in a JSON-like value (for the token-only checks)."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in (*strings_in(k), *strings_in(v))]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in strings_in(v)]
    return []


def flatten_dataclass(value: Any) -> str:
    """repr of a dataclass tree, for 'no secret anywhere in parsed state' checks."""
    return repr(value)


Pathish = Union[str, Path]
