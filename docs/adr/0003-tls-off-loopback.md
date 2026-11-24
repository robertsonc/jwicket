# ADR 0003: TLS for any non-loopback listener; SSH tunnel for lab access

Status: Proposed (written 2026-11-24; owner acceptance not recorded, governance D11)

## Context

During the spike the shared token crossed the internet in clear text; it is treated as burned.
The on-box `ssl` module was never exercised. The project does not ask anyone to open a listener on
a production firewall.

## Decision

- Default bind is `127.0.0.1`. Any other bind address requires a certificate and key; there is no
  "allow plaintext" switch in the product.
- Lab and qualification access uses `ssh -L 8443:127.0.0.1:8443 <user>@<device>`: no new listener
  is exposed, no zone change is needed, and SSH carries the traffic.
- TLS 1.2 minimum, compression off, handshakes in worker threads with timeouts (the spike wrapped
  the listening socket, which serialises every handshake on the accept thread).
- Key and certificate files must be owned by the daemon's account or root, not group- or
  world-writable, and the key must be mode 0600.

## Consequences

- Plain HTTP on loopback cannot set `Secure` cookies; the cookie is HttpOnly and SameSite=Strict,
  and the name drops the `__Host-` prefix in that mode.
- Certificate provisioning on the device (generate, rotate, use the Junos PKI store) is open:
  Q-TLS-01 and the Phase 1 spec decide it.

## Would be proven wrong by

- Q-TLS-01: the on-box `ssl` module is missing or cannot load a key the daemon's account can read.
