# ADR 0015: Verify installer profiles on the target SRX

Status: Accepted (2026-11-26, owner decision; confirmed by the merge of its pull request). Written
by a contributor on 2026-11-26 from the vSRX lab record; the owner's answer, in the owner's words,
was "Accept" ([Spec 006, open question 32](../specs/006-installation.md#21-open-questions-owner-decisions)).
It changes a trust boundary, the sign-in model and rules that protect the listener and the state
directory, so the security reviewer must also review it
([governance, who decides what](../governance.md#who-decides-what)). That role (D1) is unnamed and
has not reviewed this record. Until it is named, changes that need it "can be reviewed and merged
as documents or code on fixtures, but do not count toward a gate"
([CONTRIBUTING, Review](../../CONTRIBUTING.md#review)): this acceptance counts toward no gate, and
Q-SEC-01 still reviews the changed trust rules.

Supersedes, for the offered account-owned state directory alternative only,
[ADR 0011](0011-owner-decisions-lab-gated-install.md) decision 4 item 2 and
[ADR 0012](0012-installer-design.md) decision 4 ([Consequences](#consequences)). The default,
`/var/db/jwicket` made once by root, stays preferred, and both decisions still hold for it, so
neither earlier record's file or status line is changed.

Nothing here is built. Acceptance changes the design, not the installer or daemon code: today's
code still enforces the old rules until each part is implemented and qualified (Q-INST-06,
Q-AUTH-01, Q-NET-01, Q-TLS-01, Q-SEC-01).

## Context

The [SRX4100 lab](../evidence/2026-11-24-srx4100-lab/README.md) had working operator
NETCONF on loopback and TLS on fxp0. In the [vSRX lab](../evidence/2026-11-26-vsrx-vlab/README.md),
the same logical roles were available only through different paths. Binding, management
reachability, and the SSH library's ability to verify the device were distinct checks.
The temporary compatibility code is not suitable as an installer default.

## Decision

Until this design is built and qualified, today's installer and daemon defaults and refusals stay
exactly as [Spec 006](../specs/006-installation.md) sections 5.1, 7.2, 8.11 and 9.3 and the
daemon's settings rules state them. Treat alternate state, listener, and operator NETCONF paths as
independent candidates. The
listener's preferred path is the accepted default (TLS on the operator-named management address,
[ADR 0011](0011-owner-decisions-lab-gated-install.md) decision 4), not loopback. Use read-only
discovery to explain choices; gate active probes and configuration behind an exact approved plan.
Prefer working operator NETCONF on IP loopback. An alternative may use only an address verified
on the same device through the trusted management session, with its complete independently
verified SSH host key and an approved signature algorithm. Require that identity check before
sending operator credentials. A missing capability can lead to a new proposed plan. An identity
or authentication failure cannot lead to automatic fallback.

Pin the chosen characteristics in the install receipt, lock and recheck before
configuration changes, and confirm only after verification through the actual runtime
and intended client. No silent migration at startup. Hold the existing installer and
production gates, including the MNHA refusal. The full checks and negative cases are
in [Spec 006 section 7.12](../specs/006-installation.md#712-adaptive-preflight).

## Alternatives

- **Make this vSRX path the default.** Rejected: it would encode a particular platform,
  address, and old SSH library's behavior and change devices with working loopback.
- **Allow arbitrary NETCONF targets.** Rejected: it would send operator credentials
  outside the device trust boundary.
- **Keep loopback as the only option forever.** Preserves the current rule, but leaves
  otherwise usable SRXs without delegated reads. It stays the enforced rule until the accepted
  alternative is built and independently qualified.
- **NETCONF over SSH on loopback port 22, within today's rules.** Needs no ADR:
  `src/jwicket/settings.py:364` already accepts any `netconf_port` from 1 to 1023, and
  `set system services netconf ssh` serves NETCONF on the SSH port too (`NETCONF_WARNING`,
  `tools/jwicket_install/plan.py:357-361`). The installers render no `netconf_port` today, so the daemon uses its
  default 830 (`tools/jwicket_install/plan.py:135`); using 22 would be an installer change, not a
  trust-rule change. The vSRX record shows only TCP 830 probed on IP loopback; whether port 22 on
  loopback works there is **not recorded in the evidence**.

## Consequences

Each rule or code area below changes only when this record's design is built; until then the code
enforces the current rule. Each still needs the security reviewer (D1, unnamed), because each
changes a trust boundary, the sign-in model, or a default or rule that protects the listener or the
state directory ([CONTRIBUTING](../../CONTRIBUTING.md#propose-a-feature), step 3).

- **The loopback-only NETCONF host.** `src/jwicket/settings.py:402-404` refuses a `netconf_host`
  that is not a loopback address for the `netconf` backend. The same-device alternative would
  narrow that rule to "loopback, or an address pinned as this device's". It narrows
  [ADR 0002](0002-junos-delegated-sign-in.md) (its decision that the session goes to the device's
  own loopback, and that settings refuse a non-loopback NETCONF host). ADR 0002 is itself still
  Proposed (governance D11), so this record supersedes no accepted decision here; when the owner
  accepts, amends or rejects ADR 0002, that decision takes this narrowing into account.
- **SSH host-key verification in the daemon.** `PyEzUserSession.open`
  (`src/jwicket/junos/session.py:148-170`) passes PyEZ no host key and no host-key check: on
  loopback it relies on the target being the device itself. An off-loopback target would need the
  complete pinned key and an approved host-signature algorithm checked before the password is sent,
  which is new code and a new settings input. This also narrows ADR 0002.
- **The fixed settings path.** `src/jwicket/settings.py:19` fixes `DEFAULT_CONFIG_PATH` at
  `/var/db/jwicket/jwicket.ini`, and `tools/jwicket_install/plan.py:153` sets `STATE_DIR` to its
  parent ([Spec 006, section 7.11](../specs/006-installation.md#711-api)). An account-owned
  directory would change both.
- **The root-made state directory.** [ADR 0012](0012-installer-design.md) decision 4 (no installer
  creates the directory; root makes it once) and R-STATEDIR
  ([Spec 006, sections 8.11](../specs/006-installation.md#811-refusals) and
  [9.3](../specs/006-installation.md#93-the-state-directory-cut-c1)). The owner accepted that
  decision (ADR 0011 decision 4, item 2), which settled Spec 006 open question 28 (the path stays
  under `/var/db`). For the offered account-owned alternative only, this record supersedes ADR 0011
  decision 4 item 2 and ADR 0012 decision 4: when the default is unavailable, an installer may offer
  an operator-selected private account-owned directory that passes the State row's checks
  ([Spec 006, section 7.12](../specs/006-installation.md#712-adaptive-preflight)). The default,
  `/var/db/jwicket` made once by root and never by an installer, is unchanged and stays preferred,
  so open question 28's answer stands for it.
- **The listener rules.** INV-10 ([Spec 006, section 5.1](../specs/006-installation.md#51-security-invariants))
  and R-BIND (`tools/jwicket_install/plan.py:3644-3662`, `_bind_refusal`) gain proofs and refusals
  for an address other than the default: the address and routing instance read from the device,
  the certificate, and ingress from the intended client. This tightens them and supersedes nothing:
  ADR 0011 decision 4 item 1, ADR 0012 decision 11 and [ADR 0003](0003-tls-off-loopback.md)'s rule
  that a listener off loopback needs TLS stand. A listener that preferred loopback with a forwarding
  path would instead reopen Spec 006 open question 30 and supersede ADR 0011 decision 4 item 1; this
  record does not do that, so open question 30 is not reopened.
- **The receipt.** Once built, the install receipt ([Spec 006, section 7.10](../specs/006-installation.md#710-receipt-and-journal))
  records the selected profile, the release and digest, and each observed check.
- **Unchanged.** R-MNHA, R-CLUSTER and every other refusal of
  [Spec 006, section 8.11](../specs/006-installation.md#811-refusals), except the R-STATEDIR change
  above; the lab gate of ADR 0011 decision 1.

## Qualification

Require one run that preserves the existing SRX4100 path (TLS listener on the management address,
NETCONF on loopback) and one that selects the offered alternative on a vSRX, plus pin, signature,
ingress and rollback refusals: part of Q-INST-06's end-to-end run, with Q-AUTH-01 (the pinned
NETCONF sign-in and the wrong-password case), Q-NET-01 (ingress to the offered address), Q-TLS-01
(its certificate) and Q-SEC-01 (the review of the changed trust rules)
([governance, section 4](../governance.md#4-qualification-test-catalogue)). Qualification is
release- and platform-specific. Neither the current lab result nor this record's acceptance is
installer qualification or production approval.

## Would be proven wrong by

- **Q-INST-06:** a run that cannot keep the SRX4100's existing path selected unchanged, or whose
  refusals leave the box other than it was, shows the profile selection is wrong.
- **Q-AUTH-01:** on-box PyEZ that cannot refuse a mismatched key or a weak host signature before the
  password is sent, or that signs a user in with the daemon account's key despite a wrong password,
  rules out the same-device NETCONF alternative. NETCONF on IP loopback port 22 working on the vSRX
  would make the alternative unneeded there.
- **Q-NET-01:** ingress to an offered address that cannot be proved from the intended client without
  zone or filter changes makes the listener alternative unusable.
- **Q-TLS-01:** an offered listener whose certificate the client cannot verify rules it out.
- **Q-SEC-01:** an internal review finding that a pinned off-loopback NETCONF target, or an
  account-owned state directory, weakens what ADR 0002 or ADR 0012 decision 4 protect.
