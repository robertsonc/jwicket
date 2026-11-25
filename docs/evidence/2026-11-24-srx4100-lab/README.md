# Evidence: J-Wicket on a lab SRX4100, 24 November 2026

The first run of J-Wicket's own bundle on a device. One lab SRX4100 (hardware), owned by the
project owner, who directed the run. It carries lab traffic only and is not a production
firewall. The run did not follow a separate hardware procedure, because none has been written
(D12). It followed [deploy-lab.md](../../deploy-lab.md), with the deviations listed below. Times
are UTC unless marked CST (the device's clock).

Addresses, the host name and the central-management identifiers are left out. "Desk" means a
workstation on the lab management network.

| | |
| --- | --- |
| Platform | SRX4100, standalone (`show chassis cluster status`: not enabled) |
| Release | Junos 25.2R1-S1.4 |
| Veriexec | `loaded active enforce` |
| Management | `system management-instance` on: fxp0 is in `mgmt_junos` |
| Central manager | Security Director Cloud, over `outbound-ssh` (present before the run, untouched) |
| Commit | `d73ff3e` (branch `py37-junos-runtime`, [PR #6](https://github.com/robertsonc/jwicket/pull/6)) |
| Bundle | file SHA-256 `0a5a48a8a6b69111b46b32c9dfe2bcb0cda995ff4105d3c4fb5d0cce4477458a`, built with `--source-ref 892e4eef591e-py37-ri` from the tree committed as `d73ff3e` |
| `payload_sha256` | `323d357d3b01ce8529d3192214c3c5dc116824c3f7d643b540fad45f95e8fee2`. A rebuild of `d73ff3e` gives the same value. |
| Files | [`selftest.json`](selftest.json) and [`probe.json`](probe.json), as printed by `request extension-service start` |

## Results

| Test | Result on this cell |
| --- | --- |
| Q-RT-01 runtime probe | **Pass.** Python **3.7.10**, OpenSSL 1.1.1zb. Every module in `PROBE_MODULES` is `ok`, including `jnpr.junos`, `lxml`, `ncclient` and `paramiko`. Pass criteria revised to a 3.7 floor; see "Python 3.7" below. |
| Q-RT-02 daemonized bundle | **Partial.** Met: the bundle ran as a daemonized app with no arguments, and the self-test digest matched the build. A refused start wrote its reason to `startup-refused.txt`, and Junos stopped restarting it ("jwicket.py is thrashing, not restarted"). After `kill` (SIGTERM) it restarted on its own. Memory with one signed-in operator after about 10 minutes: 54 MB resident, 86 MB virtual. Not met: `kill -9` not tried, restart times not measured, idle-only memory not recorded. |
| Q-AUTH-01 per-operator NETCONF | **Partial.** A super-user account signed in from the desk over NETCONF to `127.0.0.1:830` (device log: `Accepted password for root from 127.0.0.1`). J-Wicket then read the policy inventory, the session table and the `messages` log as that account. A wrong password was refused by Junos (`SSHD_LOGIN_FAILED ... from host '127.0.0.1'`) and shown as "Sign-in failed. Check the user name and password." The audit trail recorded it as `user_hash`, not the name. Not done: the read-only-class account, `UI_NETCONF_CMD` attribution, the SSH-key case, sign-out and timeout checks, and the session caps. |
| Q-TLS-01 on-box TLS | **Partial.** The on-box `ssl` served a self-signed RSA-2048 certificate, generated on the box with `openssl req`. TLS 1.2 (`ECDHE-RSA-AES256-GCM-SHA384`) and TLS 1.3 (`TLS_AES_256_GCM_SHA384`) handshakes succeeded from the desk. Plain HTTP to the TLS port got no answer. The client could not offer TLS 1.0 or 1.1, so whether the server refuses them was not tested. |
| Q-NET-01 reachability | **fxp0 part met**, with the new `[server] routing_instance = mgmt_junos` (below). A request with a foreign `Host` header got 421. The revenue-zone part was not run. |
| Q-NET-02 port collisions | **Not run.** J-Wicket ran on 9443. 8443 refused connections normally when nothing listened on it. |
| Q-NET-03 SSH local forwarding | **Fails as documented.** The tunnel reported `administratively prohibited`, and `set system services ssh tcp-forwarding` is a syntax error on 25.2R1-S1.4. Not pursued: the UI was reached directly over TLS instead. |
| Q-REL-01 recorded replies | Not recorded. The reads worked, but no replies were captured as fixtures. |

The audit trail of the signed-in session (`/var/db/jwicket/audit.jsonl`), with the source
address replaced by "desk":

```json
{"backend": "netconf", "event": "login", "source": "desk", "ts": "2026-11-25T00:17:29Z", "user": "root"}
{"config": "ok", "event": "read_inventory", "policies": 3, "scope": "root", "source": "desk", "ts": "2026-11-25T00:17:30Z", "user": "root"}
{"event": "read_sessions", "filters": "", "rows": 40, "source": "desk", "status": "ok", "ts": "2026-11-25T00:17:34Z", "user": "root"}
{"event": "read_log", "log": "file:messages", "source": "desk", "status": "ok", "ts": "2026-11-25T00:18:43Z", "user": "root"}
```

## Findings

1. **Python 3.7.** Junos 25.2R1-S1.4 ships Python 3.7.10. The first bundle, built for 3.9, failed
   with `cannot import name 'Protocol' from 'typing'`. The Junos 26.2R1-S2.3 install image
   (`junos-srxmr-x86-64-26.2R1-S2.3.tgz`) also carries only `lib/python3.7`. That was read from
   the image's control-plane disk, not run, so upgrading would not raise the floor. The code now
   supports 3.7 ([ADR 0001](../../adr/0001-on-box-pure-python-single-file.md)).
2. **`mgmt_junos`.** With `system management-instance`, the fxp0 address cannot be bound from the
   default instance (`Can't assign requested address`). A listener on `0.0.0.0` in the default
   instance receives a SYN on fxp0, but its reply goes through `inet.0`, so the client times out.
   The extension-service statement `routing-instance mgmt_junos` did not change this.
   `jcs.set_routing_instance("mgmt_junos")` did, but it is process-wide: inside `mgmt_junos`,
   NETCONF to `127.0.0.1:830` timed out. After `jcs.set_routing_instance("default")`, NETCONF
   worked, and a socket already bound in `mgmt_junos` stayed there. J-Wicket now creates only its
   listener in the configured instance.
3. **No `/var/db` for a super-user account.** `mkdir /var/db/jwicket` as the super-user-class
   account was refused (`Permission denied`), and so was the CLI's `file make-directory`. Root
   created the directory and gave it to the account (`chown`).
4. **No shell Python.** `python3` from the shell is "Operation not permitted" under veriexec. Test
   code ran as a JET app (`request extension-service start`).
5. **Shell tools.** `pkill` is not on the box. `ps ax` and `kill <pid>` work.
6. **Commit trail.** Every change was a `commit confirmed 5` and was confirmed only after a check.
   One unconfirmed commit rolled back on its own (`UI_COMMIT_NOT_CONFIRMED ... automatic rollback
   complete`).

## Configuration left on the box

```
set system scripts language python3
set system extensions extension-service application file jwicket.py daemonize
set system extensions extension-service application file jwicket.py respawn-on-normal-exit
set system extensions extension-service application file jwicket.py username <user>
set system extensions extension-service application file jwicket_selftest.py username <user>
set system extensions extension-service application file jwicket_probe.py username <user>
```

`/var/db/jwicket/` holds `jwicket.ini`, `tls.crt`, `tls.key`, `jwicket.log` and `audit.jsonl`.
The settings that differ from the defaults:

```ini
[server]
bind = <fxp0 address>
port = 9443
routing_instance = mgmt_junos
tls_cert = /var/db/jwicket/tls.crt
tls_key = /var/db/jwicket/tls.key
allowed_hosts = <fxp0 address>:9443

[log]
file = /var/db/jwicket/jwicket.log
audit_file = /var/db/jwicket/audit.jsonl
```

Nothing is qualified on this cell ([governance 3.2](../../governance.md#32-what-qualified-platform-means)).
The security review (Q-SEC-01) has not happened.
