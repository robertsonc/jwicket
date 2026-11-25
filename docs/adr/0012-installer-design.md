# ADR 0012: Installer design: one shared plan, gated confirmed commits, provenance, nothing in the bundle

Status: Proposed (written 2026-11-24; revised 2026-11-25 from the lab SRX4100 run; owner acceptance
not recorded, governance D11), except decisions 4 and 11 and the R-MODEL part of decision 8, which
the owner accepted on 2026-11-25 ("go with those installer defaults", recorded in
[ADR 0011](0011-owner-decisions-lab-gated-install.md), decision 4). It changes a security control and the lab procedure, so the security
reviewer (D1) and, for the lab procedure, the lab owner (D2) must also review it; both roles are
unnamed.

## Context

[ADR 0011](0011-owner-decisions-lab-gated-install.md) records the owner's decisions: installation
as seamless as possible, by as many methods as are available; every installer lab-gated until G1
(dry run by default, the exact configuration diff, the posture warning, `commit confirmed` with a
health check, the operator typing the device's host name); CI pre-releases with their SHA-256; the
spec and the installers built together, every device step marked unverified.

Installing J-Wicket writes configuration and files on the routing engine, and the daemon itself must
stay read-only ([Spec 002](../specs/002-change-protocol.md) owns product writes, at G4). An installer
can go wrong in ways a read cannot: the wrong device, someone else's pending confirmed commit (a
`commit` or `commit check` confirms a pending confirmed commit, **verified**; that another user's or
another session's commit confirms it is **inferred**, Q-INST-03), a substituted bundle, a statement that
something else relied on, a health check that passes on the old process. None of the installers has
run on a device. [Spec 006](../specs/006-installation.md) is the design; this record holds its
choices, each a proposal, so that the owner can accept, amend or veto them one by one; the owner has
accepted three of them so far (see the status line). Its open questions (section 21) list the
alternatives.

On 2026-11-24 J-Wicket's own bundle ran by hand, following [deploy-lab.md](../deploy-lab.md), on
the owner's lab SRX4100 with Junos 25.2R1-S1.4
([evidence](../evidence/2026-11-24-srx4100-lab/README.md)). That run verified facts the first
design had only inferred or guessed, and some contradict it: the on-box Python is 3.7.10; a
super-user-class account cannot create `/var/db/jwicket` (root did, once); SSH local forwarding is
refused (`administratively prohibited`), and `set system services ssh tcp-forwarding` is a syntax
error there; with `system management-instance`, fxp0's address can be bound only in `mgmt_junos`,
which the daemon's `[server] routing_instance` does for its listener and the extension-service
`routing-instance` statement does not; TLS on fxp0 on port 9443 worked; the diagnostic and runtime
statements, `commit confirmed 5` with a check before the confirm, and an unconfirmed commit rolling
back by itself all behaved as the design assumes. The lead engineer decided revision 4 of Spec 006
from those facts (decisions 4, 8, 11, 12 and 13 below). No installer ran in that session.

## Decision (proposed)

1. **One shared plan.** `tools/jwicket_install/plan.py`, `state.py` and `render.py` (standard
   library, no I/O) compute one frozen plan from the bundle, its provenance, the options, the
   device's facts and its prior state; every method renders or executes that plan, and a test
   requires the set lines of every rendering to be equal (Spec 006 principle P1, section 7). The
   statements are a fixed set, S1 to S14, S6 and S7 reserved and never planned.
2. **Twelve security invariants**, INV-01 to INV-12 (Spec 006 section 5.1), which every built
   method meets and whose change needs the security reviewer. Among them: nothing written before the
   gate; no `commit check`, `<check/>` or `<validate>` on any path; the pending state re-read on the
   locked session before every commit and confirm; every write a confirmed commit, confirmed only
   after its checks pass; the compared host name read from the device, never supplied; no configured
   file written in place outside the copy right before its checksum commit; credentials and the TLS
   private key never in argv, logs, receipts or plan JSON, the key never on the workstation's disk,
   and no device secret read; every SSH connection checks the host key, and the health check trusts
   only the certificate the run generated; a listener on loopback without TLS, or with TLS on the
   one address the operator names, never off loopback without TLS; ownership of shared statements
   from Junos's commit history and the workstation record; device text never a template, path,
   command or configuration line.
3. **The bootstrap pattern and its R-PENDING exception.** What an executor cannot add for itself
   (`netconf ssh` for M1 to M3; `language python3` and the op stanza for M4; also
   `allow-url-for-python` for M4U) is a paste unit for the operator that ends at
   `commit confirmed 10 comment "jwicket-bootstrap <method> <nonce>"` (no nonce on the box) and is
   never confirmed by the operator. The executor treats a pending confirmed commit as a refusal
   (R-PENDING) unless it is exactly its own bootstrap (user, comment, nonce for M1, exact committed
   delta), and confirms that bootstrap only after the gate; a refusal or a failed gate leaves Junos
   to roll it back at its deadline. Built as designed (cut C5), and open for the owner's veto (Spec
   006 section 7.7, open question 10): without it the units would end with a confirm typed by hand
   after a manual check, which the design review found unsafe. The pattern is unverified on any
   device.
4. **No installer creates the state directory** (revision 4; **accepted by the owner, 2026-11-25**,
   ADR 0011 decision 4). A super-user-class account cannot
   create a directory under `/var/db`: `mkdir` and `file make-directory` were both refused on the
   SRX4100 (verified), and root created `/var/db/jwicket` and gave it to the account. So the
   installers never send `make-directory`, and never change or delete that directory. The dry run
   lists `/var/db` and `/var/db/jwicket` (reads only) and applies the daemon's trust rule (a
   directory, not a link, owned by the daemon's account, mode 0700, not group- or other-writable).
   When it is absent or untrusted, R-STATEDIR refuses `--apply` (exit 1) before any write and prints
   the lab run's one-time root step, `mkdir -m 700 /var/db/jwicket && chown <user> /var/db/jwicket`,
   for the lab owner to run in the shell. No tool logs in as root or asks for the root password;
   uninstall leaves the emptied directory and prints root's `rmdir`. Moving the settings path out of
   `/var/db` would remove the root step; the owner kept the path and the root step (Spec 006
   section 9.3, open question 28, decided).
5. **Provenance independent of the release page.** `SHA256SUMS` on a release page guards against
   corruption, not replacement, so `--apply` needs one source the release page does not control: the
   immutable release's attestation, the build-provenance attestation, the release record on `main`,
   a local reproduction, or an operator-supplied hash with its named source (P-A to P-E). Without one
   the run stops (exit 7), unless `--trust-release-page-only` stamps the receipt "not qualification
   evidence". Downloads use per-tag URLs only; every file's SHA-256 is checked again on the device,
   and `checksum sha-256` is pinned in the configuration (Spec 006 section 8.9; enforcement unknown,
   Q-INST-02).
6. **Installer code never ships in the bundle.** No configuration-writing code goes into
   `dist/jwicket.py`, and `ALLOWED_RPCS` is unchanged; the on-box op script is a separate artifact
   with its own SHA-256 (Spec 006 P10). The daemon gains two changes that send nothing to Junos: D2,
   the self-test and probe also write their JSON to result files in a trusted `/var/db/jwicket`, and
   D3, the build (version and payload digest) in the start line, the audit start record,
   `GET /api/session` and a `features:` header line, so the health checks can prove the new build is
   the one listening. Neither was in the build that ran on the SRX4100.
7. **Deferred and rejected daemon changes.** The setup mode D1 (a `jwicket_setup.py` alias creating
   the state directory) is deferred, not built: it would run as the daemon's account, which cannot
   create a directory under `/var/db` (verified on the SRX4100). Rejected: **starting with built-in
   defaults when `jwicket.ini` is absent** (an empty `allowed_hosts` reopens the DNS-rebinding gap,
   and logs would go to standard error, whose destination under Junos is unknown, so a deleted or
   tampered file would start a weaker daemon silently; the installers always write the file
   instead); the daemon creating its own directory at start; the probe reading veriexec; the
   installer inside the bundle. A weaker default would need the owner, the security reviewer and
   its own ADR (Spec 006 section 10, open questions 27 and 28).
8. **Refusals before any write** (Spec 006 section 8.11), each with its override or none: among
   them R-MODEL (anything but vSRX, unless `--lab-hardware` is given and, after the host name
   matches, the operator types `lab only` beneath a statement that the device carries only lab
   traffic; the production signs are shown first and the receipt records the attestation; the
   SRX4100 run, standalone with Security Director Cloud over `outbound-ssh`, is the reference case;
   governance D12's hardware procedure is still unwritten; this part **accepted by the owner,
   2026-11-25**, ADR 0011 decision 4, open question 20), R-CLUSTER, R-MNHA and R-DUAL-RE (until
   Q-HA-01 and Q-HA-03, also with `--lab-hardware`), R-ROOT, R-PENDING, R-VERIEXEC (override
   `--veriexec-not-enforcing-ok`, stamped "not qualification evidence"; the one fixed shell read is
   the spike's `sysctl security.mac.veriexec.state`), R-MANAGED and R-COMMIT-SCRIPTS
   (acknowledgements, recorded; R-MANAGED applies to lab hardware too), R-FOREIGN (`--adopt`,
   recorded), R-PORT (never a `web-management` or `rest` port) and R-STATEDIR (decision 4).
9. **The daemon's account.** The installing super-user-class account (never `root`) becomes the
   daemon's `username`: the settings and JET file trust rules leave no other choice today, and the
   installers never change a file's owner (whether a non-root account may is unknown). Every plan and
   receipt prints `ROOT_BLAST_RADIUS`. This is a recorded G1 least-privilege gap (Spec 006 open
   question 13), not a solution.
10. **Release repository settings required before the first pre-release.** A run uses the workflow
    as it is in the tagged commit, so whoever can push a `v*` tag controls it. Before the owner
    pushes `v0.1.0.dev1`: **immutable releases** on; **a tag ruleset** letting only the owner create
    `v*` tags; **branch protection with review on `main`**; **environment `lab-prerelease`** with the
    deployment tag rule `v*.*.*.dev*`, a required reviewer where the plan allows it and
    administrator bypass off; and the repository **variable `JWICKET_IMMUTABLE_RELEASES=true`**,
    which the workflow's `verify` job requires. Tags are PEP 440 `vX.Y.Z.devN` only; an attestation
    is required when the repository is public; a private repository without attestations keeps the
    release a draft until the owner signs `SHA256SUMS` with an SSH key held outside GitHub; each
    release's record reaches `main` by a reviewed pull request (Spec 006 section 11, open question 8).
11. **Two access modes, TLS by default** (revision 4; open question 30; **accepted by the owner,
    2026-11-25**, ADR 0011 decision 4). `--access tls` (the
    default) listens with TLS on the device address the operator reaches (`--listen-address`,
    defaulting to `--host` when that is an IP literal), port 9443 by default (the lab run's), with
    `allowed_hosts` set to that address and port, and `[server] routing_instance = mgmt_junos` when
    the configuration has `system management-instance`. The workstation installer makes a
    self-signed RSA-2048 certificate whose subjectAltName is the listen address, in memory with the
    `cryptography` library (hash-pinned), uploads the key (0600) and certificate by SCP, never writes
    the key to its own disk, logs or prints it, and prints and records only the certificate's
    SHA-256 fingerprint for the operator to compare in the browser. The rendered settings must pass
    the daemon's own `parse_settings`. `--access tunnel` keeps the loopback listener without TLS and
    the rendered `ssh -L`, with a warning that the SRX4100 refused the forward. The extension-service
    `routing-instance` statement is never rendered. The TLS posture warning says plainly that this
    opens a new HTTPS listener on the management address, reachable by anything that reaches that
    address, before G1 and before any security review (Q-SEC-01). Accepted, this replaces the
    lab-access part of [ADR 0003](0003-tls-off-loopback.md) (the SSH tunnel, which that device
    refused) for the workstation installers; ADR 0003's rule that a listener off loopback needs TLS
    stands. The access mode and certificate of the on-box methods M4 and M4U are not part of it and
    stay proposals (Spec 006 open question 31).
12. **Health checks without SSH channels** (revision 4). No check opens an SSH `direct-tcpip`
    channel. C8 is an HTTPS `GET /api/session` from the workstation to the listen address, trusting
    only the certificate the run generated (pinned by fingerprint, no CA store), and checks the
    version and build; with `tunnel` it is recorded "not available". C9 (the NETCONF banner through
    a channel) is retired, its number kept: the `netconf` backend's readiness rests on the probe
    (C3) and is recorded as not checked end to end.
13. **Python 3.7 for everything the op script embeds** (revision 4). The on-box Python is 3.7.10
    on 25.2R1-S1.4, and the 26.2R1-S2.3 image carries only 3.7. `plan.py`, `state.py`, `render.py`,
    `op_template.py` and every other module of `tools/jwicket_install/` must import and pass their
    unit tests on 3.7, which CI runs; a test parses each with `ast.parse(..., feature_version=(3,
    7))`, and `build_op.py` sets `MIN_PYTHON` to `(3, 7)`. The workstation installer's own floor with
    PyEZ is what the pinned `junos-eznc` 2.8.3 declares (`Requires-Python >=3.8`) and what
    `requirements-install.txt` is checked on.

## Consequences

- An installer is more code to review than the nine hand steps of
  [deploy-lab.md](../deploy-lab.md), whose verified steps (the spike's and the SRX4100 run's) stay
  the reference and the fallback. The workstation installer depends on PyEZ, `paramiko`, `scp` and
  `cryptography` on the workstation, hash-pinned; none of it reaches the device.
- For its window (10 minutes by default, up to 30 with `--bootstrap-minutes`) the bootstrap is active
  before the gate, and another administrator's commit in that window would confirm it (inferred,
  Q-INST-03). The gate is an attestation: R-MODEL, the production signs and the typed `lab only`
  cannot detect a production cloud vSRX or a falsely attested box.
- By default the install opens a new HTTPS listener on the management address, with a self-signed
  certificate whose private key passes through the workstation's memory and SCP (the lab run made
  its key on the box instead), and `/api/session` answers unauthenticated to whatever reaches that
  address ([SECURITY.md](../../SECURITY.md#known-gaps), known gap 10).
- Whoever can write `/var/db/scripts/jet` can still replace the bundle
  ([SECURITY.md](../../SECURITY.md#known-gaps), known gap 7); an enforced JET checksum would narrow
  that to whoever can also commit (Q-INST-02). The release settings are only as strong as the
  owner's account.
- Every first install on a box needs root, once, for the state directory, run by the lab owner in
  the shell, outside Juniper support.
- Every installer prints `DEVICE_STATUS` ("This installer has not yet run on any device. Every
  device step is unverified until lab test Q-INST-06 is certified.") until the lab owner certifies
  Q-INST-06.

## Would be proven wrong by

Q-INST-06, the end-to-end run of each built method on a lab vSRX (and on attested lab hardware):
bootstrap, dry run, install in both access modes, idempotent re-run, induced failure and revert,
upgrade and uninstall, with the configuration, history and listings compared before and after
([governance, section 4.12](../governance.md#412-proposed-additions)). If a method cannot do that
and leave the box as it was (the root-made directory aside), its part of this design is wrong. The
parts it rests on are settled by Q-INST-01 (reply shapes and file semantics, owner and mode after
the installer's SCP), Q-INST-02 (JET checksum enforcement), Q-INST-03 (the confirmed-commit
lifecycle: what a rolled-back stage does to the daemon, and whether a closed session rolls a pending
bootstrap back early), Q-INST-04 (the group layout), Q-INST-05 (transports and outputs) and
Q-TLS-01 (the installer's certificate on the listener).
