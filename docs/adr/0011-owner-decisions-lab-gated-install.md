# ADR 0011: Owner decisions for installation: lab-gated, pre-released, built with its spec

Status: Accepted (2026-11-24, owner decision; written by a contributor from the owner's request and
answers, and confirmed when the owner merges the pull request that adds it). Decision 4 added
2026-11-25 (owner decision; written by a contributor from the owner's answer, and confirmed when the
owner merges the pull request that adds it)

This record holds the owner's own words and choices only. Every design choice made to carry them
out (the shared plan, the invariants, the bootstrap and its exception, the provenance rule, the
refusals, the repository settings for releases) is a proposal in
[ADR 0012](0012-installer-design.md), which the owner has not accepted, except the three installer
defaults the owner accepted on 2026-11-25 (decision 4).

## Context

On 2026-11-24 the owner asked: "It would be supercool if we could make the install as seamless as
possible. Provide as many ways to install it as are available."

Three facts stood in the way, each already recorded:

- J-Wicket has had no security review or penetration test (Q-SEC-01, Q-SEC-02), and every install
  sets `system scripts language python3`, which lets unsigned Python run on the routing engine
  ([charter, section 7](../charter.md#veriexec-and-unsigned-python);
  [SECURITY.md](../../SECURITY.md#known-gaps), known gap 7).
- Several install methods need a downloadable, checksummed `jwicket.py`, and the project had no
  release and no tag. The first tag is the owner's to decide.
- The project's rule is spec first, code after the owner accepts the spec
  ([governance, section 2.2](../governance.md#22-spec-reviews)).

A contributor asked the owner three questions, each with options. The owner chose the recommended
option of each.

On 2026-11-24 J-Wicket's own bundle then ran by hand on the owner's lab SRX4100, Junos 25.2R1-S1.4
([evidence](../evidence/2026-11-24-srx4100-lab/README.md)): SSH local forwarding was refused, TLS on
fxp0 on port 9443 in `mgmt_junos` worked, and a super-user-class account could not create
`/var/db/jwicket`. From those facts the lead engineer proposed three installer defaults (Spec 006
revision 4; [ADR 0012](0012-installer-design.md) decisions 4, 8 and 11), which were put to the
owner on 2026-11-25.

## Decision

Decisions 1 to 3 are quoted as they were asked and answered; decision 4 quotes the owner's answer
and lists the defaults it accepted, as they were proposed:

1. **Device gate.** Asked: "J-Wicket has had no security review or pen test, and every install sets
   'system scripts language python3' (unsigned Python on the routing engine). How far should the
   installers go?" Chosen, **"Lab-gated until G1"**: "Every installer shows the exact config diff
   and the posture warning, defaults to a dry run, uses commit confirmed with a health check, and
   only proceeds after the operator confirms the box is a lab device by typing its host name. The
   gate is lifted when G1 passes." Not chosen: "Any device, with warnings" and "Lab only, hard
   refusal".
2. **Releases.** Asked: "Several install methods (on-device fetch by URL, op url bootstrap, Ansible,
   ZTP) need a downloadable, checksummed jwicket.py. Should CI publish one?" Chosen, **"CI
   pre-releases"**: "CI builds the reproducible bundle and publishes it with its SHA-256 as a GitHub
   pre-release (marked pre-release, lab only). This cuts the project's first tag, which you listed
   as yours to decide." Not chosen: "CI artifacts only, no tag" and "Build locally only".
3. **Spec first?** Asked: "The project's rule is spec first, code after the owner accepts the spec.
   How should install work proceed?" Chosen, **"Spec and build together"**: "Write the install spec
   (Draft) and build the installers in the same PR, every device step marked unverified until a lab
   run; you review both at once." Not chosen: "Spec first, then build".
4. **Installer defaults from the SRX4100 run** (2026-11-25). Asked to accept or change the three
   defaults proposed from the SRX4100 lab facts, the owner answered, in their own words: **"go with
   those installer defaults"**. Accepted:
   1. **Access:** TLS on the management address by default, port 9443, with `[server]
      routing_instance mgmt_junos` when `system management-instance` is set; a self-signed
      certificate generated on the workstation, whose private key is uploaded with mode 0600 and
      never kept, and whose fingerprint is printed.
   2. **The state directory:** the one-time root step for `/var/db/jwicket` is printed and checked by
      the installers, and never run by them.
   3. **Lab hardware:** accepted only with `--lab-hardware` and a typed `lab only`, after the
      production signs.

[Spec 006, section 2.2](../specs/006-installation.md#22-owner-decisions-2026-11-24-binding) restates
the request and the answers as its binding decisions and says how it reads decision 2 where it meets
the safety rules; those readings are its open questions 10, 14 and 15, not part of this record.
Decision 4 settles its open questions 20, 28 and 30 and nothing else: the access mode and certificate
of the on-box methods (M4, M4U, now open question 31) and every other open question stay open.

## Consequences

- Every installer is lab-only until G1. Lifting the gate at G1 does not make J-Wicket installable on
  a production SRX: that stays a G5 matter ([governance, section 3](../governance.md#3-gates-g0-to-g5)).
  What the lab gate becomes between G1 and G5 is not decided here (Spec 006 open question 1); the
  answer would amend this record by a new ADR.
- The first tag is the owner's: the release workflow may exist in the tree, but no pre-release is
  published until the owner gives an explicit go for the first tag (`v0.1.0.dev1`). No contributor,
  tool or workflow creates a tag on its own.
- Spec 006 is a Draft while its code exists, an exception to "spec first" granted for the install
  work. Every device step it and the installers describe stays marked unverified until a lab run
  (Q-INST-06, proposed in [governance, section 4.12](../governance.md#412-proposed-additions)).
  Accepting Spec 006 still needs the owner, and the lab owner (D2) and the security reviewer (D1),
  because it changes the lab procedure and the device's security posture
  ([governance, who decides what](../governance.md#who-decides-what)).
- Decisions 1 to 3 rest on no device fact, so no qualification test overturns them. Decision 4
  rests on the SRX4100 run (one platform, one release) and accepts defaults, not device behaviour:
  every device step behind them stays unverified until Q-INST-06, and the default still opens a new
  HTTPS listener on the management address before any security review
  ([SECURITY.md](../../SECURITY.md#known-gaps), known gaps 10 and 11). A lab result that contradicts
  one of the facts behind them (for example SSH forwarding working on a release, Q-NET-03) is a
  reason to ask the owner again, not to change a default without them.
- With decision 4, ADR 0012's decisions 4 and 11 and the R-MODEL part of its decision 8 are owner
  decisions; the rest of ADR 0012 stays proposed (governance D11).
- A later owner decision supersedes this record in a new ADR.
