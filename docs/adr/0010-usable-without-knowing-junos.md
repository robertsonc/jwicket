# ADR 0010: Usable without knowing Junos

Status: Accepted (2026-11-24, owner decision; written by a contributor from the owner's answers, and
confirmed when the owner merges the pull request that adds it)

## Context

The owner's reason for the project is that J-Web is too thin for real work on the box, and that
someone who does not know Junos cannot get started quickly on an SRX. The J-Web 24.4 guide documents
specific gaps ([charter, section 1](../charter.md#1-the-problem-and-who-it-is-for);
[catalog, key findings](../catalog.md#key-findings)). Until now the charter named only customers who
already manage an SRX on the box as the audience.

Three facts limit what this can mean today:

- Getting started on an SRX is mostly configuration (interfaces, zones, NAT, policies), and
  J-Wicket has no write path before G4 ([governance, gates](../governance.md#3-gates-g0-to-g5)).
- Installing J-Wicket takes Junos skills: enabling unsigned Python, configuring an extension-service
  application, copying the file to the routing engine and committing with `commit confirmed`
  ([deploy-lab.md](../deploy-lab.md)).
- Security Director Cloud and Mist are another answer for teams without Junos skills. J-Wicket's
  place is the device that is managed on the box, with no central manager
  ([ADR 0009](0009-central-management-coexistence.md)).

## Decision

1. **Audience: both.** Success stays release-scoped parity with better tools
   ([charter, section 2](../charter.md#2-what-success-means)). Added as a binding design rule for
   every view and state: a screen must be usable by an operator who does not know Junos. Junos
   concepts are explained where they appear, in plain words, and the matching Junos command is shown
   alongside, so the operator learns Junos instead of having it hidden.
2. **Roadmap unchanged: read before write.** The rule is delivered first as a read-only "explain
   Junos in place" layer with its own spec, written next, before G2. It changes nothing
   about what J-Wicket reads or sends.
3. **Installation needs someone with Junos skills**, an SE or an administrator, once per device. The
   documentation states it as a prerequisite. J-Wicket does not assume it will ship inside Junos;
   that would be an HPE product decision (G5).

## Consequences

- Spec reviews check the rule for every new view and state
  ([governance 2.2](../governance.md#22-spec-reviews), check 9).
- Every explanation of Junos behaviour is sourced from Juniper documentation and labelled verified,
  or it is not shipped. The text is bundled with the application, with no runtime internet
  dependency ([ADR 0007](0007-offline-capable-meaning.md)).
- The rule lowers no other rule. Device text stays untrusted, and an explanation never claims which
  policy a flow matches ([ADR 0006](0006-device-explains-policy-decisions.md)).
- What would show it is not met: an operator new to Junos who cannot complete a read task unaided.
  Proposed, for the owner to accept or reject with the other G2 additions (governance D7): a G2
  check in which operators new to Junos complete the read tasks on a lab device without help.
