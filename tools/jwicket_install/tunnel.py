"""``jwicket-install open``: how to reach J-Wicket once it is installed (Spec 006 sections 6.2 step 4 and
7.5, UI-006-06). LAB ONLY.

The module's name is historical. Until revision R3 it forwarded connections itself, one SSH forwarding
channel per connection. SSH TCP forwarding was refused on a lab SRX4100 running Junos 25.2R1-S1.4
('administratively prohibited'; 'set system services ssh tcp-forwarding' is a syntax error there;
verified, docs/evidence/2026-11-24-srx4100-lab), and no part of the installer opens an SSH channel any
more. ``open`` prints the way in from this workstation's install record instead:

* ``--access tls`` (the default): ``https://<listen address>:<port>/`` and the SHA-256 fingerprint of the
  certificate the installer made, in the colon form browsers and openssl print, to compare before
  accepting the self-signed certificate. The executor also reads ``GET /api/session`` there with the
  certificate pinned (C8's read) to say whether it answers.
* ``--access tunnel``: the OpenSSH line ``ssh -L 127.0.0.1:<port>:127.0.0.1:<port> <u>@<device>``
  (``render.render_tunnel``; the explicit bind keeps the forward off the workstation's LAN) for the
  operator to run, with ``TUNNEL_WARNING``.

Pure: no I/O. The record is the workstation receipt (spec 7.10), found by the device's verified host key.
"""

from __future__ import annotations

from typing import Optional, Tuple

from . import plan, render

NO_RECORD = (
    "This workstation has no install record for this device (its records are keyed by the device's SSH host "
    "key). With --access tls, browse to https://<listen address>:<port>/ and compare the certificate's SHA-256 "
    "fingerprint with the one the install printed; with --access tunnel, run 'ssh -L 127.0.0.1:<port>:"
    "127.0.0.1:<port> <user>@<device>'."
)


def ssh_host(host: str) -> Optional[str]:
    """The host for the printed 'ssh -L' line: a plain host name or IPv4 address, else the placeholder."""
    if plan.HOSTNAME_RE.match(host) or all(part.isdigit() for part in host.split(".")):
        return host
    return None


def reach_lines(
    record: Optional[plan.Receipt],
    *,
    user: str,
    host: str,
    ssh_port: int = 22,
    port: Optional[int] = None,
) -> Tuple[str, ...]:
    """What ``open`` prints for ``record`` (``port`` overrides the recorded daemon port)."""
    if record is None:
        return (NO_RECORD,)
    daemon_port: int = plan.DEFAULT_PORTS.get(record.access, plan.DEFAULT_PORT)
    if port is not None:
        daemon_port = port
    elif record.port is not None:
        daemon_port = record.port
    if record.access == "tls" and record.listen_address is not None:
        url = plan.listen_url(record.listen_address, daemon_port)
        where = f" (routing instance {record.routing_instance})" if record.routing_instance else ""
        if record.tls_cert_sha256 is None:
            fingerprint = "not recorded: compare it with the one the install printed"
        else:
            fingerprint = plan.fingerprint_display(record.tls_cert_sha256)
        lines = (
            f"J-Wicket {record.bundle_version} listens with TLS on "
            f"{plan.host_port(record.listen_address, daemon_port)}{where}.",
            f"Browse to {url} from a host that reaches that address. The certificate is self-signed: accept it "
            f"only if the browser shows this SHA-256 fingerprint: {fingerprint}",
        )
        expiry = plan.certificate_expiry(record.tls_cert_not_after)
        return lines + ((f"Warning: {expiry}.",) if expiry is not None else ())
    line = render.render_tunnel(user, daemon_port, host=ssh_host(host), ssh_port=ssh_port)
    return (
        f"J-Wicket {record.bundle_version} listens on {plan.LOOPBACK}:{daemon_port} on the device only "
        "(--access tunnel).",
        f"Run on this workstation: {line}",
        f"Then browse to http://{plan.LOOPBACK}:{daemon_port}/ while that SSH session stays open.",
        plan.TUNNEL_WARNING,
    )
