# Lab deployment: the J-Wicket bundle on a disposable vSRX

> [!WARNING]
> **Lab vSRX only. Never a production firewall.**
>
> J-Wicket is at the foundation stage and is **not installable on a production SRX**. This project
> does not ask you to enable a listener, disable J-Web or change a production firewall. Use this
> procedure only on a disposable virtual SRX (a vLabs sandbox, or an isolated lab VPC) that carries
> no traffic you care about and that you are allowed to change and then delete.
>
> Even on a lab box, `set system scripts language python3` lets unsigned Python run on the routing
> engine, which is a security posture change in its own right. Every configuration change below is
> made with `commit confirmed 5`, so Junos rolls it back by itself unless you confirm it.

This procedure puts one build of `dist/jwicket.py` on a lab vSRX so that qualification tests can be
run against a real Junos: the interpreter and module probe (Q-RT-01), the per-operator NETCONF
sign-in (Q-AUTH-01) and the read-only policy inventory. It does not cover TLS (Q-TLS-01), a listener
off loopback, a security-zone change or configuration writes; J-Wicket has no write path.

What the procedure changes on the lab box, and nothing else:

| Change | Where |
| --- | --- |
| Three copies of one file | `/var/db/scripts/jet/jwicket.py`, `jwicket_selftest.py`, `jwicket_probe.py` |
| One directory with the settings file, log and audit trail | `/var/db/jwicket/` |
| `system scripts language python3` and `system extensions extension-service` entries | Steps 4 and 6 |
| `system services netconf ssh`, for the `netconf` sign-in backend | Step 5 |

What it never does: bind anything but `127.0.0.1`, load `junos/zone-access.set`, touch J-Web
(`system services web-management`), or open TCP 8443 in a cloud security group. The UI is reached only
through an SSH tunnel (step 7).

## How to read the verification marks

The spike record is in [`docs/evidence/2026-11-23-vsrx-spike/`](evidence/2026-11-23-vsrx-spike/README.md):
one vSRX, Junos 24.4R2-S3.5, 24 November 2026 UTC, with the file name `wicket_spike.py`.

- **Verified**: the spike ran this command or statement and recorded the result. Here the file name
  is `jwicket.py` (or one of its two copies); the syntax is otherwise the same.
- **Unverified**: not exercised by the spike. Check a configuration statement with `?` in the CLI
  before you commit it, and write down what happened: that is qualification evidence too.

Shell steps (`ls`, `chmod`, `mkdir`, `rm`, `openssl`, `sysctl`) run in the Junos shell
(`start shell`), as the spike's did.

## 0. Before you start

You need:

- A disposable vSRX with veriexec enforcing. In the shell, `sysctl security.mac.veriexec.state`
  should print `loaded active enforce` (verified). A box without enforcement makes every result
  meaningless for hardware.
- A Junos account, written `<user>` below, in the super-user class. It copies the files, owns them,
  and is the extension-service `username`, so the daemon runs as this account (verified: the spike's
  daemon ran as the `username` account and class). With the `netconf` backend, reads run as whoever
  signs in, not as `<user>`.
- A workstation with an OpenSSH client and a browser.

Record the box's starting state, so that step 9 removes exactly what you added (unverified, standard
operational commands):

```
show configuration system scripts
show configuration system extensions
show configuration system services
```

## 1. Build and record the bundle (workstation)

From the repository, at the commit you mean to test:

```
python3 tools/bundle.py --source-ref "$(git rev-parse --short=12 HEAD)"
python3 -I dist/jwicket.py --bundle-self-test
sha256sum dist/jwicket.py
```

The self-test must end with `"ok": true`. Record the file SHA-256 and the `payload_sha256` that the
self-test prints; the same value is in the bundle's header. A bundle downloaded from CI (artifact
`jwicket-bundle-<commit>`) carries the checksum in that run's job summary. The build is
reproducible: the same tree and `--source-ref` always give the same bytes.

## 2. Copy the bundle to the device (verified)

```
scp -O dist/jwicket.py <user>@<device>:/var/db/scripts/jet/jwicket.py
scp -O dist/jwicket.py <user>@<device>:/var/db/scripts/jet/jwicket_selftest.py
scp -O dist/jwicket.py <user>@<device>:/var/db/scripts/jet/jwicket_probe.py
```

`-O` is needed because SFTP is off by default on Junos (verified). The two extra copies are the same
file under names that select a diagnostic (step 4); Junos cannot pass `--flag` options to a JET
application (spike finding F1).

Ownership and mode (verified): each file must be owned by a user in the super-user class, with write
permission for the owner only, mode `0644`. The `username` in step 6 should be that same account. In
the shell:

```
ls -l /var/db/scripts/jet/jwicket.py /var/db/scripts/jet/jwicket_selftest.py /var/db/scripts/jet/jwicket_probe.py
chmod 644 /var/db/scripts/jet/jwicket.py /var/db/scripts/jet/jwicket_selftest.py /var/db/scripts/jet/jwicket_probe.py
```

Each line of `ls -l` should read `-rw-r--r--` and name `<user>`. Juniper ships its own JET
applications in the same directory (`nc_grpc_app`, `bps_device_monitor`, verified); leave them alone.

## 3. Create the settings directory and file

The settings path is fixed: `/var/db/jwicket/jwicket.ini` (`DEFAULT_CONFIG_PATH` in
`src/jwicket/settings.py`), because the daemon takes no arguments under Junos. J-Wicket refuses to
start, and says which file and why, unless:

- the settings file is a regular file, not a symbolic link, owned by the daemon's account
  (`<user>`) or root, and not writable by group or other: use `0600`;
- its directory is not writable by group or other: use `0700`, owned by `<user>`. A root-owned `0700`
  directory would lock the daemon out of its own settings;
- a token or TLS key file, if you use one, is mode `0600`; every path in the file is absolute.

In the shell, as `<user>`:

```
mkdir -m 700 /var/db/jwicket
ls -ld /var/db/jwicket
```

Expect `drwx------` and `<user>`. Unverified: whether a super-user-class account may create a
directory under `/var/db`. If `mkdir` is refused, the lab fallback (also unverified) is to become root
in the shell with the lab's root password, create the directory, and `chown <user> /var/db/jwicket`.
If neither works, stop and record it: moving the settings file elsewhere is a code change, not a lab
workaround.

Write `jwicket.ini` on the workstation. This example lists every setting with its default; the three
values marked "lab" are the only departures from the defaults:

```ini
# /var/db/jwicket/jwicket.ini: J-Wicket settings (lab vSRX only).
# Every value is checked before anything listens. A value that would weaken the listener is refused
# at startup with a message naming the setting. Comments go on their own lines.

[server]
# IP address to listen on (not a host name). Default 127.0.0.1. Anything that is not a loopback
# address requires tls_cert and tls_key. Keep loopback for this procedure.
bind = 127.0.0.1
# TCP port, 1024..65535. Default 8443.
port = 8443
# PEM certificate and private key, absolute paths, set together. Default: unset (no TLS, which is
# allowed only on loopback). The key must be mode 0600. TLS on a device is not yet qualified.
tls_cert =
tls_key =
# Host header values to accept, comma-separated. Default: unset (any). Lab: the two names a browser
# uses through the step 7 tunnel; anything else gets HTTP 421. This blocks DNS-rebinding pages on
# the workstation from reaching the tunnel. Change the port here if you change the tunnel's port.
allowed_hosts = 127.0.0.1:8443, localhost:8443
# Concurrent connections, 2..64. Default 8. Over the cap, new connections are closed at once.
max_connections = 8
# Per-connection socket timeout in seconds, 2..60. Default 10.
socket_timeout_s = 10
# Largest request body in bytes, 1024..65536. Default 8192.
max_body_bytes = 8192

[auth]
# netconf: each operator signs in with their own Junos account over a NETCONF session to this
# device's loopback, and their login class governs every read (needs step 5).
# lab-token: one shared token, every read runs as the daemon's account; loopback bind only.
# Default netconf.
backend = netconf
# NETCONF address and port. Must be a loopback address; port 1..1023, so only a root-owned service
# can be listening there. Defaults 127.0.0.1 and 830.
netconf_host = 127.0.0.1
netconf_port = 830
# Timeout for each device call, seconds, 5..300. Default 30.
rpc_timeout_s = 30
# Sign-out after this many idle seconds, 60..3600, and after this many seconds in any case,
# 600..86400. The idle limit cannot exceed the absolute one. Defaults 900 and 28800.
session_idle_s = 900
session_absolute_s = 28800
# Signed-in operators at once, 1..16 (each holds a NETCONF session). Default 4.
max_sessions = 4
# Sign-in attempts per minute from one address (1..60) and in total (1..600). Defaults 5 and 20.
login_per_source_per_min = 5
login_global_per_min = 20
# lab-token backend only: absolute path of a file holding the token (at least 32 characters, ASCII,
# mode 0600). Default: unset.
lab_token_file =

[log]
# DEBUG, INFO, WARNING or ERROR. Default INFO.
level = INFO
# Diagnostic log file, absolute path. Default: unset (stderr only). Lab: a file, because where a
# daemonized app's stderr goes is not known.
file = /var/db/jwicket/jwicket.log
# Audit trail, one JSON object per line: who did what, from where, when. Default: unset (written
# to the diagnostic log). Lab: its own file, which is qualification evidence.
audit_file = /var/db/jwicket/audit.jsonl
# Rotate each file at this size in bytes (10000..50000000) and keep this many old copies (1..20).
# Defaults 1000000 and 3.
max_bytes = 1000000
backups = 3
```

Check it on the workstation first; the check applies the same file rules, so give the file mode
`0600` in a directory only you can write:

```
chmod 600 jwicket.ini
python3 -I dist/jwicket.py --check-config --config ./jwicket.ini
scp -O jwicket.ini <user>@<device>:/var/db/jwicket/jwicket.ini
```

Then in the shell, `chmod 600 /var/db/jwicket/jwicket.ini` and `ls -l /var/db/jwicket/jwicket.ini`
(`-rw-------`, `<user>`). Never commit a settings file; `*.ini` is ignored by git for that reason.

## 4. Self-test and probe on the device (no daemon, no listener)

Enable unsigned Python and register the two diagnostic copies, without `daemonize`. In configuration
mode:

```
set system scripts language python3
set system extensions extension-service application file jwicket_selftest.py username <user>
set system extensions extension-service application file jwicket_probe.py username <user>
commit confirmed 5
commit
```

The statements are verified syntax (with the spike's file name). The second `commit`, within five
minutes, confirms the change; without it Junos rolls back (verified procedure).

Then, in operational mode:

```
request extension-service start jwicket_selftest.py
request extension-service start jwicket_probe.py
```

`request extension-service start` is verified, and output prints to the terminal. The bundle picks
its mode from its own file name: `jwicket_selftest.py` runs the bundle self-test, `jwicket_probe.py`
runs the interpreter probe, and both exit without listening. That mechanism is new and has not yet
run on a device (unverified). Expect:

- self-test: JSON ending in `"ok": true`, with `payload_sha256` equal to the value from step 1;
- probe: JSON with the Python and OpenSSL versions and, for each module the daemon needs
  (`http.server`, `ssl`, `jnpr.junos`, `lxml`, `ncclient`, `paramiko` and others), `ok` or
  `missing: <reason>`. Keep the whole output: it is the Q-RT-01 record for this release. The probe's
  exit status is non-zero if any module is missing.

The argument form, `request extension-service start jwicket.py --bundle-self-test` (or `--probe`),
is unverified, and spike finding F1 suggests it fails: Junos's script runner parsed `--flag` options
itself and exited with "missing script filename" when they were given in the `arguments`
statement. It also needs the `jwicket.py` entry without `daemonize` (see "Debugging" below). If you
try it, record the result.

## 5. Enable NETCONF for the `netconf` backend (config change, lab box only)

The `netconf` backend opens a NETCONF session to `127.0.0.1:830` as the person signing in, so NETCONF
over SSH must be on. Unverified: the spike did not run this statement.

```
set system services netconf ssh
commit confirmed 5
commit
```

This is a configuration change with reach beyond J-Wicket: it starts NETCONF over SSH on TCP 830 for
every path that can reach the routing engine, including fxp0, and vLabs forwards port 830 to the vSRX
from outside (verified). J-Wicket needs it on loopback only; restricting it to loopback is a
firewall-filter change that this procedure does not cover. Do this on a lab box only.

To skip NETCONF, use the `lab-token` backend instead (see "Variant" below). Q-AUTH-01 is then not
exercised.

## 6. Start the daemon

The four baseline lines (verified with the spike's file name; the first is already set by step 4):

```
set system scripts language python3
set system extensions extension-service application file jwicket.py daemonize
set system extensions extension-service application file jwicket.py respawn-on-normal-exit
set system extensions extension-service application file jwicket.py username <user>
commit confirmed 5
```

Junos starts a daemonized application when the commit takes effect, and `respawn-on-normal-exit` is
what makes it restart after a clean exit as well as a crash (both verified). Before confirming, check
that it is listening:

```
file show /var/db/jwicket/jwicket.log
```

Expect `TLS is off; listening on loopback only (127.0.0.1)` and
`listening on 127.0.0.1:8443 tls=False backend=netconf`. If those lines are there, confirm with
`commit`. If not, do not confirm: let the change roll back, and use "Debugging" below. A refused start
writes its reason (`startup refused: ...`) to stderr, and also to `/var/db/jwicket/startup-refused.txt`
when that directory exists, because the log file is opened only after the settings are accepted:
`file show /var/db/jwicket/startup-refused.txt`. Junos stops restarting an application that keeps
exiting ("thrashing, not restarted", verified).

## 7. Open the UI through an SSH tunnel only

On the workstation:

```
ssh -L 8443:127.0.0.1:8443 <user>@<device>
```

Then browse to `http://127.0.0.1:8443/` on the workstation while the SSH session stays open. The
listener stays on the device's loopback: nothing listens on fxp0 or a revenue port, no security zone
changes, and `junos/zone-access.set` is not needed. Plain HTTP is acceptable only because both ends
are loopback and the hop between them is SSH. Keep the local port at 8443, or change `allowed_hosts`
to match.

Unverified: whether this release's SSH service allows TCP forwarding. If the tunnel reports
`administratively prohibited`, the statement to look for is `set system services ssh tcp-forwarding`
(unverified; a configuration change; lab box only; `commit confirmed 5`, then `commit`).

Sign in with a Junos user name and password. Each operator's login class decides what they see: a
panel their class may not read shows "denied" instead of data. For Q-AUTH-01, sign in once with a
super-user account and once with a lab-only account in a read-only class (creating that account is
a configuration change: `commit confirmed 5`, then `commit`), and record what each sees.

## Debugging a start failure (verified procedure)

A daemonized application cannot be started by hand (`request extension-service start` answers
"Can't start daemonize app", verified). Remove `daemonize`, then run it in the foreground, where its
errors print to the terminal:

```
delete system extensions extension-service application file jwicket.py daemonize
commit confirmed 5
commit
```

```
request extension-service start jwicket.py
```

With no arguments this is the daemon itself, reading `/var/db/jwicket/jwicket.ini`. How to stop a
foreground run (interrupting the CLI command, or `request extension-service stop jwicket.py`) is
unverified. This is also where the unverified argument form of step 4 would be tried. To go back to
daemon mode, `set system extensions extension-service application file jwicket.py daemonize`, then
`commit confirmed 5` and `commit`.

## Variant: `lab-token` backend

Use this only if NETCONF cannot be enabled. Every read runs as `<user>`, the daemon's account, and the
UI says so on every screen; settings refuse it on anything but a loopback bind. In the shell (verified
command, from the spike):

```
openssl rand -hex 24 > /var/db/jwicket/lab-token
chmod 600 /var/db/jwicket/lab-token
```

In `jwicket.ini`, set `backend = lab-token` and `lab_token_file = /var/db/jwicket/lab-token`, then
restart the daemon so it reads the file again: find it with `ps ax | grep jwicket` and `kill <pid>`;
with `respawn-on-normal-exit` configured, Junos starts it again within seconds (verified). Sign in by
pasting the token. Treat the token as burned when the lab ends.

## 8. Record the results

Keep, with the build's file SHA-256 and `payload_sha256`: the Junos release, the veriexec state, the
self-test and probe output, the log and audit lines from the session, and what each account could
and could not see. File them as a dated directory under `docs/evidence/`, next to the spike record.
Copy the log files off the device before step 9 removes them:

```
scp -O <user>@<device>:/var/db/jwicket/jwicket.log .
scp -O <user>@<device>:/var/db/jwicket/audit.jsonl .
```

## 9. Remove everything

In configuration mode, delete what this procedure added. Leave out any line that step 0 showed was
already configured before you started:

```
delete system extensions extension-service application file jwicket.py
delete system extensions extension-service application file jwicket_selftest.py
delete system extensions extension-service application file jwicket_probe.py
delete system services netconf ssh
delete system scripts language
commit confirmed 5
commit
```

Unverified: these `delete` statements are the inverses of the `set` statements above, but the spike
only ran `delete system services rest`. Check each with `?` first. Leave out
`delete system scripts language` if anything else on the box relies on unsigned Python, and add
`delete system services ssh tcp-forwarding` if you set it in step 7.

Whether deleting the configuration stops a running daemon is unverified. In the shell, check with
`ps ax | grep jwicket` (the spike's daemon showed as `cscript -mjet -Q3 -j -f <file> -J<user>`), and
stop a leftover process with `kill <pid>`; without `respawn-on-normal-exit` configured, Junos does
not restart it (verified). Then remove the files:

```
rm /var/db/scripts/jet/jwicket.py /var/db/scripts/jet/jwicket_selftest.py /var/db/scripts/jet/jwicket_probe.py
rm -r /var/db/jwicket
ls /var/db/scripts/jet/
```

The last listing should show only what was there before, such as Juniper's own applications. Finally,
delete the disposable vSRX itself if the lab allows it.
