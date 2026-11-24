# ADR 0006: The device explains policy decisions; J-Wicket does not reimplement the matcher

Status: Accepted (2026-11-24)

## Context

"Explaining policy decisions" is a headline goal. Reimplementing Junos policy lookup in Python would
have to track zone-pair and global ordering, address-book scoping, application identification,
dynamic applications, user identity, URL categories, schedulers and release differences. A wrong
answer delivered with confidence is the failure mode that matters on a firewall.

## Decision

- Spec 001 explains **order**: for a zone pair, the zone-pair policies in configuration order, then
  the global policies that apply to that pair, then the default policy, with inactive rules shown
  as skipped. It gives the exact CLI to check a specific flow on the device.
- Flow-level answers ("which policy matches this packet") come from the device's own policy lookup
  (`show security match-policies`) when that RPC is added to the allowlist in a later spec, after
  its reply format is recorded (Q-REL-01).
- A local evaluator may exist only to preview proposed, uncommitted rules (Spec 003). Its output is
  always labelled as J-Wicket's model, never as the device's answer.

## Consequences

The first slice cannot answer "would this flow pass?" by itself. That is deliberate.
