# ADR 0002: Sign-in is delegated to Junos through a per-operator NETCONF session

Status: Proposed (written 2026-11-24; owner acceptance not recorded, governance D11). The
mechanism is unproven on a device until Q-AUTH-01 passes.

## Context

The spike's local `Device()` session ran as the account in the extension-service `username`
statement, with that account's login class (spike T5, `j-super-user`). Every web user would share
those rights. J-Web's worst advisories (2023) came from a web tier doing its own security work.
Junos already has users, login classes and remote authentication (RADIUS, TACACS+).

## Decision

- At sign-in, J-Wicket opens a NETCONF-over-SSH session to the device's own loopback address as
  the operator, with the password they typed, and keeps that session for their web session.
- Junos authenticates (its own authentication order) and every RPC on that session runs with the
  operator's login class. J-Wicket stores no password and has no roles of its own.
- The loopback NETCONF port must be below 1024, so only a root-owned service (sshd) can be
  listening there; settings refuse anything else, and refuse a non-loopback NETCONF host.
- A shared "lab token" backend survives only for loopback binds, runs as the daemon's account, and
  says so on every screen and in the audit trail.

## Consequences

- Least privilege comes from Junos, not from J-Wicket code. A read-only class sees a read-only UI;
  a denied read shows as "denied", never as empty.
- Each signed-in operator holds one NETCONF session on the routing engine; sessions are capped
  (`max_sessions`, default 4), limited to one per Junos user by default (a new sign-in closes that
  user's older session, `max_sessions_per_user`), and closed on idle and absolute timeouts.
- Only the typed password may sign anyone in: J-Wicket tells PyEZ not to offer the daemon account's
  SSH keys and not to read its SSH client configuration, so the daemon account's own credentials
  cannot stand in for an operator's.
- Lab boxes need `set system services netconf ssh`. That is a configuration change and is not
  asked of production devices at this stage.
- Multi-factor prompts (keyboard-interactive challenges) are not supported by this flow. Open
  question for a future sign-in spec ([parity summary, gap 1](../parity/jweb-24.4.md#owner-decisions)).
- The password passes through the J-Wicket process in memory, as it does through J-Web. It is
  never logged or stored; Python cannot guarantee it is wiped from memory.

## Would be proven wrong by

- Q-AUTH-01: on-box Python cannot open an SSH/NETCONF session to loopback (for example paramiko is
  absent from on-box PyEZ), or the on-box PyEZ signs a user in with the daemon account's key despite
  a wrong password. Fallback options are recorded in `docs/architecture.md`.
- Q-AUTH-02: remote-authenticated (template) users do not receive their mapped class over NETCONF.
