# ADR 0005: Read the committed configuration with inheritance and group provenance

Status: Proposed (written 2026-11-24; owner acceptance not recorded, governance D11)

## Context

Brownfield SRX configurations use `apply-groups` (corporate baselines, `node0`/`node1` groups in
chassis clusters, wildcard groups). What the device enforces is the configuration after
inheritance; where an object is defined decides where it can be changed. The spike read
`format=json` without inheritance, so inherited policies were invisible and nothing said where an
object came from. Other users' uncommitted candidate changes are not in effect.

## Decision

- Reads use `<get-configuration database="committed" inherit="inherit" groups="groups">`, filtered to
  the subtrees the inventory needs (security policies, zones and address books, and applications,
  for the root and each logical and tenant system; outbound-ssh; Multinode HA). Never the whole
  configuration, and never all of `[edit security]`: the rest holds password hashes and secrets such
  as IKE pre-shared keys.
- Parsers match element and attribute local names, so `junos:group` is found whether or not PyEZ
  has stripped namespaces.
- Every object carries `group` (the group it came from, if any), `inherited` (which of its parts
  came from elsewhere) and `inactive` with a reason.
- Nothing is dropped silently: configuration the model does not understand is listed per object
  (policies, zones, interfaces, address entries, sets and books, applications and application sets)
  and warned per scope. Configuration comments are attached to what they annotate, not listed.
  Deactivated statements are never treated as in effect.

## Consequences

- Spec 002 can refuse to edit a group-owned object in place, and say which group owns it.
- Exact attribute and namespace behaviour must be confirmed from recorded replies (Q-REL-01).
- Predefined `junos-*` applications (the `junos-defaults` group) are not expanded in Spec 001.
