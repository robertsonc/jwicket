# Lab deployment: the J-Wicket bundle on a lab SRX

> [!WARNING]
> **Lab devices only. Never a production firewall.**
>
> J-Wicket is at the foundation stage and is **not installable on a production SRX**. This project
> does not ask you to enable a listener, disable J-Web or change a production firewall. Use this
> procedure only on a disposable virtual SRX (a vLabs sandbox, or an isolated lab VPC), or on lab
> hardware whose owner approves the run, that carries no traffic you care about and that you are
> allowed to change.
>
> Even on a lab box, `set system scripts language python3` lets unsigned Python run on the routing
> engine, which is a security posture change in its own right. Every configuration change below is
> made with `commit confirmed 5`, so Junos rolls it back by itself unless you confirm it.

> [!NOTE]
> **Installers.** [docs/install.md](install.md) describes the lab-gated installers of
> [Spec 006](specs/006-installation.md), which automate these steps on a lab device: a dry run by
> default, the plan's diff and the posture warning, the lab device's host name typed by the
> operator, and a `commit confirmed` per stage that they confirm only after a health check. None
> has run on a device, so every device step of theirs is unverified until Q-INST-06, except where
> the SRX4100 run below verified the same statement by hand. This procedure stays the reference:
> its verified steps are the only ones that have run on a device, and it is the fallback when an
> installer step is refused. Revised from that run: they never create `/var/db/jwicket` (step 3's
> root step stays yours, and they refuse until it is done), and by default (`--access tls`) they set
> up the [TLS-on-fxp0 variant](#variant-tls-on-fxp0-when-the-tunnel-is-refused) instead of step 7's
> tunnel.

**Where this has run.** Written for a disposable vSRX. Run once end to end, on 24 November 2026, on
the project owner's lab SRX4100 (hardware, Junos 25.2R1-S1.4), at the owner's direction
([evidence](evidence/2026-11-24-srx4100-lab/README.md)). That run is the source of every "verified on SRX4100" mark below, and it
added the [TLS-on-fxp0 variant](#variant-tls-on-fxp0-when-the-tunnel-is-refused), because the SSH
tunnel was refused on 25.2. The separate hardware procedure that governance asks for (D12) is still
not written: on hardware, the lab owner decides.

This procedure puts one build of `dist/jwicket.py` on a lab SRX so that qualification tests can be
run against a real Junos: the interpreter and module probe (Q-RT-01), the per-operator NETCONF
sign-in (Q-AUTH-01) and the read-only policy inventory. It does not cover TLS (Q-TLS-01), a listener
off loopback, a security-zone change or configuration writes; J-Wicket has no write path. It does
not cover SRX hardware either: hardware runs need a separate procedure, approved by the lab owner
and the security reviewer, which is not written yet ([governance, D12](governance.md#25-decisions-pending)).

What the procedure changes on the lab box, and nothing else:

| Change | Where |
| --- | --- |
| Three copies of one file | `/var/db/scripts/jet/jwicket.py`, `jwicket_selftest.py`, `jwicket_probe.py` |
| One directory with the settings file, log and audit trail | `/var/db/jwicket/` |
| `system scripts language python3` and `system extensions extension-service` entries | Steps 4 and 6 |
| `system services netconf ssh`, for the `netconf` sign-in backend | Step 5 |
| A lab-only account in a read-only class (and that class, if you create one), for Q-AUTH-01 | Step 7 |
| `system services ssh allow-tcp-forwarding` (or, on older releases, `tcp-forwarding`), only if step 7 needed it | Step 7 |

What it never does: bind anything but `127.0.0.1` (except the
[TLS-on-fxp0 variant](#variant-tls-on-fxp0-when-the-tunnel-is-refused), which binds the fxp0
address with TLS, on the lab owner's approval), load `junos/zone-access.set`, touch J-Web
(`system services web-management`), or open TCP 8443 in a cloud security group. The UI is reached
through an SSH tunnel (step 7), or, in that variant, over TLS on fxp0.

## How to read the verification marks

The spike record is in [`docs/evidence/2026-11-23-vsrx-spike/`](evidence/2026-11-23-vsrx-spike/README.md):
one vSRX, Junos 24.4R2-S3.5, 24 November 2026 UTC, with the file name `wicket_spike.py`.

- **Verified on SRX4100**: the 24 November 2026 run on a lab SRX4100, Junos 25.2R1-S1.4
  ([evidence](evidence/2026-11-24-srx4100-lab/README.md)), ran this with J-Wicket's own bundle and recorded the result.
- **Verified**: the spike ran this command or statement and recorded the result. Here the file name
  is `jwicket.py` (or one of its two copies); the syntax is otherwise the same.
- **From the spike packet's run instructions**: written in the packet's
  [`PACKET-README.md`](evidence/2026-11-23-vsrx-spike/PACKET-README.md) run steps, but not in the
  recorded results.
- **Inferred**: read from a Juniper page about a neighbouring case; the page is cited.
- **Unverified**: not exercised by the spike. Check a configuration statement with `?` in the CLI
  before you commit it, and write down what happened: that is qualification evidence too. Each
  unverified item names the qualification test whose record settles it.
- **Proposed (Spec 006)**: a change to this procedure that [Spec 006](specs/006-installation.md)
  proposes, so that the manual steps follow the same safety rules as the installers. The lab owner
  decides each one (governance D2), with the security reviewer (D1) where a step changes the
  device's security posture; both roles are unnamed, so none is approved yet. Where the earlier form
  differs, it is named beside the change.

Shell steps (`ls`, `chmod`, `mkdir`, `rm`, `openssl`, `sysctl`) run in the Junos shell
(`start shell`), as the spike's did.

The proposed changes, all dated 2026-11-24:

| Step | Proposed change | Why |
| --- | --- | --- |
| 0, and before every commit | `show system commit`; stop while the newest entry (`0`) ends with `commit confirmed, rollback in <n>mins`, or the output starts with `commit requested by` (Juniper's sample wording) | A `commit` or `commit check` confirms a pending `commit confirmed` (verified); that yours confirms someone else's is inferred (Q-INST-03) |
| 4 to 7, 9, Debugging | Confirm with `commit comment "..."`, never `commit check` | 24.2R1 and later can require a comment on every commit (verified); `commit check` is not a dry run while a confirmed commit is pending |
| 6 | Check the build in the start line | The line names the version and payload digest (Spec 006 change D3), so the old process cannot pass for the new one |
| 7 | `ssh -L 127.0.0.1:8443:127.0.0.1:8443` | The explicit bind keeps the forwarded port off the workstation's network |
| 9 | Keep `language python3` while other Python scripts exist; delete files only once no J-Wicket process runs | Removing the statement stops every unsigned Python script on the box; whether deleting the stanzas stops the daemon is unverified, so a process still running is stopped first |

## 0. Before you start

You need:

- A disposable vSRX, or a lab SRX the lab owner has approved, with veriexec enforcing. In the
  shell, `sysctl security.mac.veriexec.state` should print `loaded active enforce` (verified; also
  on SRX4100). A box without enforcement makes every result meaningless for hardware.
- A Junos release whose Python is 3.7 or later. 25.2R1-S1.4 ships 3.7.10 (verified on SRX4100);
  the probe in step 4 records it for any other release.
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
show configuration system management-instance
```

If `system management-instance` is set, fxp0 is in the `mgmt_junos` routing instance; that
matters only for the [TLS-on-fxp0 variant](#variant-tls-on-fxp0-when-the-tunnel-is-refused).

**Proposed (Spec 006): check for a pending commit, and stop while one is there.**

```
show system commit
```

`show system commit` shows when a rollback is scheduled after a `commit confirmed` (verified,
Juniper's commit guide). If the newest entry (`0`) ends with `commit confirmed, rollback in <n>mins`
(Juniper's sample: `0   2022-05-06 06:33:42 PDT by root via cli commit confirmed, rollback in
10mins`), someone's confirmed commit is waiting for its confirmation; if the output starts with
`commit requested by`, a `commit at` is scheduled. Stop, and wait until neither shows. Any `commit` you type meanwhile, and any
`commit check`, would confirm their change and remove their safety net ("To confirm a commit, enter
either a commit or commit check command.", verified, Juniper's `commit` reference; that it confirms
another user's or session's commit is inferred, Q-INST-03). Repeat the
check, as `run show system commit` from configuration mode (`run` is verified), before each
`commit confirmed 5` below.

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
application (spike finding F1, [charter section 5](charter.md#5-spike-evidence)).

Ownership and mode (inferred for JET from Juniper's rules for commit, event, op and SNMP scripts,
[Python script requirements](https://networkingdocs.hpe.com/documentation/us/en/software/junos/automation-scripting/topics/concept/junos-script-automation-python-scripts-requirements-for-executing.html);
the spike packet's instructions use the same rule): each file must be owned by root or a user in the
super-user class, with write permission for the owner only, mode `0644`. What Junos actually
enforces for JET files is recorded by Q-RT-02 and Q-RT-03. The `username` in step 6 should be that
same account. In the shell:

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
- every directory from `/` down to the file belongs to root or `<user>` and is not writable by group
  or other unless it is sticky (like `/tmp`); a symbolic link on the way is followed only if root
  owns it. The same rule applies to the directories above a token or TLS file. Check the chain with
  `ls -ld / /var /var/db /var/db/jwicket`; who owns `/var` and `/var/db` on Junos has not been
  recorded (Q-RT-02 records it). A refusal names the directory and its owner;
- a token or TLS key file, if you use one, is mode `0600`; every path in the file is absolute.

The settings file and the token are opened first and checked through the open file, and their
names must still lead to the same file afterwards. TLS files are checked and then loaded by path,
because Python's `ssl` takes only a path; the directory rule above is what keeps another account
from swapping them in between.

In the shell, as `<user>`:

```
mkdir -m 700 /var/db/jwicket
ls -ld /var/db/jwicket
```

Expect `drwx------` and `<user>`. On SRX4100 25.2R1-S1.4 a super-user-class account may **not**
create a directory under `/var/db`: both this `mkdir` and the CLI's `file make-directory` were
refused with `Permission denied` (verified on SRX4100). The fallback: as root, in the shell,

```
mkdir -m 700 /var/db/jwicket && chown <user> /var/db/jwicket
```
On the SRX4100 root made the directory and gave it to the account with `chown` (verified on
SRX4100); the run did not record root's exact command, so that `-m 700` gives `drwx------` is
inferred: check it with `ls -ld /var/db/jwicket` as above.
If neither works, stop and record it: moving the settings file elsewhere is a code change, not a lab
workaround.

The installers never create this directory: their dry run lists `/var/db` (read only), and while
`jwicket` is absent or untrusted they refuse (R-STATEDIR) and print the root step above
([install guide](install.md#the-state-directory-once-as-root)).

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
# Junos routing instance to create the listening socket in. Default: unset (the default
# instance). Set it to mgmt_junos to listen on fxp0 when "system management-instance" is on; only
# the listener goes there, NETCONF stays in the default instance. Needs the on-box jcs module.
routing_instance =
# Concurrent connections, 2..64. Default 8. Over the cap, new connections are closed at once.
max_connections = 8
# Seconds, 2..60. Default 10. Each socket read times out after this long, and the TLS handshake,
# request line, headers and body together must arrive within it, or the connection is shut down
# without an answer. The request line and headers are capped at 16 KiB in total.
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
# Signed-in operators at once, 1..16 (each holds a NETCONF session). Default 4. A sign-in over the
# cap is refused; nobody else is signed out.
max_sessions = 4
# Sessions one Junos user may hold at once, 1..16. Default 2: a sign-in beyond that by the same user
# (compared case-insensitively) closes that user's oldest session. Not applied to lab-token.
max_sessions_per_user = 2
# Only sign-ins that reached Junos and failed count. Failed sign-ins per minute for one user name
# from one address (1..60), and from one address over all user names (1..600); behind the SSH
# tunnel every client is 127.0.0.1, so the second is shared by everyone on the tunnel. A success
# clears that user name's failures from that address. Defaults 5 and 20.
login_failures_per_user_per_min = 5
login_failures_per_source_per_min = 20
# Sign-ins checked by Junos at once, 1..8. Default 2. More at the same moment get HTTP 429.
login_concurrent = 2
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
# to the diagnostic log, which by default is stderr only). Lab: its own file, which is
# qualification evidence. A failed sign-in is recorded with a keyed hash of the user name
# (user_hash), never the name; refusals of clients without a session are counted per minute.
audit_file = /var/db/jwicket/audit.jsonl
# Rotate each file at this size in bytes (10000..50000000) and keep this many old copies (1..20).
# Defaults 1000000 and 3.
max_bytes = 1000000
backups = 3
```

Check it on the workstation first. The check applies the settings-file rules (owner, mode and the
directories above it, so give the file mode `0600` in a directory only you can write) and validates
every value; token and TLS files are checked only when the daemon starts on the device, where they
live:

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
commit comment "jwicket lab: diagnostics confirmed"
```

The statements are verified syntax (with the spike's file name). The second commit, within five
minutes, confirms the change; without it Junos rolls back (from the spike packet's run instructions,
where it is a plain `commit`; not in the recorded results). **Proposed (Spec 006):** confirm with
`commit comment "..."`, as here and in every step below. Junos 24.2R1 and later can require a
comment on every commit (`force-commit-log`, verified), and the comment marks your confirm in
`show system commit`. Never use `commit check` in this procedure: while a confirmed commit is pending it
is not a dry run, because it confirms that commit, and it cannot carry a comment (both verified).
On a box that requires a comment, give the first line one too:
`commit confirmed 5 comment "jwicket lab: diagnostics"` (inferred from the documented
`commit confirmed comment "..."`).

Then, in operational mode:

```
request extension-service start jwicket_selftest.py
request extension-service start jwicket_probe.py
```

`request extension-service start` is verified, and output prints to the terminal. The bundle picks
its mode from its own file name: `jwicket_selftest.py` runs the bundle self-test, `jwicket_probe.py`
runs the interpreter probe, and both exit without listening (verified on SRX4100). Expect:

- self-test: JSON ending in `"ok": true`, with `payload_sha256` equal to the value from step 1;
- probe: JSON with the Python and OpenSSL versions and, for each module the daemon needs
  (`http.server`, `ssl`, `jnpr.junos`, `lxml`, `ncclient`, `paramiko` and others), `ok` or
  `missing: <reason>`. Keep the whole output: it is the Q-RT-01 record for this release. The probe's
  exit status is non-zero if any module is missing. On SRX4100 25.2R1-S1.4: Python 3.7.10, OpenSSL
  1.1.1zb, every module `ok` (verified on SRX4100).

If the self-test fails with an `ImportError` naming a `typing` or standard-library name, the
bundle uses something newer than the device's Python: record the version and the error, and stop.
That is how the 3.9-era bundle failed on 25.2 before the floor moved to 3.7.

When `/var/db/jwicket` passes the daemon's trust rule (owned by `<user>`, not group- or
other-writable, not a link), both diagnostics also write the same JSON to
`/var/db/jwicket/selftest-result.json` and `probe-result.json`, mode 0600 (Spec 006 change D2; never
run on a device): `file show /var/db/jwicket/selftest-result.json` reads it back without the shell.
A file left from an earlier run is not removed by the bundle, so delete both
(`file delete /var/db/jwicket/selftest-result.json`, and the same for the probe's) before you start
the diagnostics again.

The argument form, `request extension-service start jwicket.py --bundle-self-test` (or `--probe`),
is unverified (Q-RT-01 records it if tried), and spike finding F1 suggests it fails: Junos's script
runner parsed `--flag` options itself and exited with "missing script filename" when they were
given in the `arguments` statement. It also needs the `jwicket.py` entry without `daemonize` (see
"Debugging" below). If you try it, record the result.

## 5. Enable NETCONF for the `netconf` backend (config change, lab box only)

The `netconf` backend opens a NETCONF session to `127.0.0.1:830` as the person signing in, so NETCONF
over SSH must be on. Unverified: the spike did not run this statement (Q-AUTH-01 records it).

```
set system services netconf ssh
commit confirmed 5
commit comment "jwicket lab: netconf confirmed"
```

This is a configuration change with reach beyond J-Wicket: it starts NETCONF over SSH on TCP 830 for
every path that can reach the routing engine, including fxp0, and vLabs forwards port 830 to the vSRX
from outside (verified). Check step 0's output first: the SRX4100 already had
`netconf ssh` configured, so there was nothing to add. J-Wicket needs it on loopback only; restricting it to loopback is a
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
`listening on 127.0.0.1:8443 tls=False backend=netconf routing_instance=default version=<version> payload=<16 hex>`,
where `<16 hex>` is the start of step 1's `payload_sha256`. The line up to
`routing_instance=default` is verified on SRX4100; the `version=` and `payload=` fields (Spec 006
change D3) were not in that build and have not run on a device.
**Proposed (Spec 006):** check that value, and that the line appears once after your commit: an
older process still running, or a daemon restarting in a loop, would otherwise pass. If those lines
are there, confirm with `commit comment "jwicket lab: daemon confirmed"` (earlier: `commit`). If
not, do not confirm: let the change roll back, and use "Debugging" below. A refused start
writes its reason (`startup refused: ...`) to stderr, and also to `/var/db/jwicket/startup-refused.txt`
when that directory exists, because the log file is opened only after the settings are accepted:
`file show /var/db/jwicket/startup-refused.txt`. One refusal happens before the settings are read:
if a module was loaded from the bundle's own directory, the bundle prints `jwicket: refusing to
start: code was loaded from this file's directory: ...` to stderr only and exits with status 2;
remove the file it names from `/var/db/scripts/jet/`. Junos stops restarting an application that
keeps exiting ("thrashing, not restarted", verified; also on SRX4100). After fixing the cause, it
stays stopped until its statements change: `deactivate system extensions extension-service
application file jwicket.py`, commit, then `activate` it and commit again (verified on SRX4100).

To restart the daemon after editing `jwicket.ini`, find its PID with `ps ax | grep jwicket` (it
shows as `cscript -mjet -Q3 -j -f jwicket.py -J<user>`) and `kill <pid>`; `respawn-on-normal-exit`
brings it back within seconds (verified on SRX4100). `pkill` is not on the box.

## 7. Open the UI through an SSH tunnel only

On the workstation:

```
ssh -L 127.0.0.1:8443:127.0.0.1:8443 <user>@<device>
```

**Proposed (Spec 006)**, earlier `ssh -L 8443:127.0.0.1:8443`: the leading `127.0.0.1:` binds the
workstation end to loopback whatever the SSH client's `GatewayPorts` setting says ("By default, the
local port is bound in accordance with the GatewayPorts setting.", verified, OpenSSH `ssh(1)`), so
nobody else on the workstation's network can use the tunnel.

Then browse to `http://127.0.0.1:8443/` on the workstation while the SSH session stays open. The
listener stays on the device's loopback: nothing listens on fxp0 or a revenue port, no security zone
changes, and `junos/zone-access.set` is not needed. Plain HTTP is acceptable only because both ends
are loopback and the hop between them is SSH. Keep the local port at 8443, or change `allowed_hosts`
to match.

Cookies are not separated by port (RFC 6265, section 8.5): any other service your browser reaches
on `127.0.0.1` while you are signed in, including another tunnel's far end, receives the J-Wicket
session cookie. Use a browser profile that opens nothing else on `127.0.0.1` during a lab session.
The cookie's name (`jwicket-<8 hex>`) changes at each daemon start, so two J-Wicket tunnels do not
overwrite each other's cookie, and a restart signs everyone out.

Whether the SSH service allows TCP forwarding depends on the release (Q-NET-03). On SRX4100
25.2R1-S1.4 it does not: the tunnel reports `channel 1: open failed: administratively prohibited`,
and `set system services ssh tcp-forwarding` is a syntax error there (verified on SRX4100). The
SRX configuration schema at 23.2R1 marks `tcp-forwarding` deprecated and names `set system services
ssh allow-tcp-forwarding` instead; it was not tried on the SRX4100 (**unverified**, Q-NET-03). Check
it with `?` (a configuration change; lab box only; `commit confirmed 5`, then `commit comment
"..."`). If the tunnel cannot work, use the
[TLS-on-fxp0 variant](#variant-tls-on-fxp0-when-the-tunnel-is-refused).

Sign in with a Junos user name and password. Each operator's login class decides what they see: a
panel their class may not read shows "denied" instead of data. For Q-AUTH-01, sign in once with a
super-user account and once with a lab-only account in a read-only class (creating that account,
and a class for it if you make one, is a configuration change: `commit confirmed 5`, then
`commit comment "..."`), and record what each sees. Give every lab account a unique, strong
password that is used nowhere else: in vLabs, SSH (22) and NETCONF (830) are forwarded to the vSRX
from the internet (step 5), so any account on the box can be tried from outside for as long as it
exists. Step 9 deletes the lab-only account.

A wrong password shows "Sign-in failed. Check the user name and password." and is audited as
`login_failed` with a `user_hash`, never the name; the device logs `SSHD_LOGIN_FAILED ... from
host '127.0.0.1'` (verified on SRX4100). A good one logs `Accepted password for <user> from
127.0.0.1` on the device and `login` in the audit trail (verified on SRX4100).

## Variant: TLS on fxp0 (when the tunnel is refused)

Verified on SRX4100 25.2R1-S1.4. This listens off loopback, on the management port, so it needs
TLS (J-Wicket refuses to start without it) and the lab owner's approval. It does not touch a
security zone: fxp0 is not in one. It does not cover revenue interfaces, which need a zone change
and are Q-NET-01's.

1. **Make a certificate on the box**, so the private key never leaves it. In the shell, as
   `<user>`:

   ```
   cd /var/db/jwicket && umask 077
   openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 90 -keyout tls.key -out tls.crt \
       -subj /CN=<fxp0 address> -addext subjectAltName=IP:<fxp0 address>
   chmod 600 tls.key; chmod 644 tls.crt
   openssl x509 -in tls.crt -noout -fingerprint -sha256
   ```

   Keep the fingerprint: it is how the browser's self-signed-certificate warning can be checked.
   Choosing a provisioning path for real certificates is Q-TLS-01's.

2. **Set the listener** in `jwicket.ini`:

   ```ini
   [server]
   bind = <fxp0 address>
   port = 9443
   tls_cert = /var/db/jwicket/tls.crt
   tls_key = /var/db/jwicket/tls.key
   allowed_hosts = <fxp0 address>:9443
   # Only if step 0 showed "system management-instance":
   routing_instance = mgmt_junos
   ```

   With `system management-instance`, fxp0's address is in `mgmt_junos`. Without
   `routing_instance`, the start is refused with `cannot listen on <address>:9443: Can't assign
   requested address`. Binding `0.0.0.0` instead starts, but a browser's connection times out: the
   SYN arrives, and the reply goes out through the default instance's table. The extension-service
   statement `routing-instance mgmt_junos` does not help (all verified on SRX4100). The port is
   your choice; the run used 9443.

3. **Restart the daemon** (`kill <pid>`, step 6) and check the log for
   `listening on <fxp0 address>:9443 tls=True backend=netconf routing_instance=mgmt_junos version=<version> payload=<16 hex>`.
   As in step 6, the line up to `routing_instance=mgmt_junos` is verified on SRX4100; the
   `version=` and `payload=` fields (Spec 006 change D3) have not run on a device.

4. **Browse** to `https://<fxp0 address>:9443/` from a host on the management network, accept the
   certificate after checking its fingerprint, and sign in as in step 7. TLS 1.2 and 1.3 were
   offered (verified on SRX4100); plain HTTP to the port gets no answer.

The installers' default, `--access tls`, sets up this variant: these settings, with
`routing_instance` from step 0's `system management-instance`, and the certificate (M1 to M3 make it
in memory on the workstation and send it by SCP; M4 and M6 use step 1 above). Unverified on a device
(Q-INST-06); see the [install guide](install.md#choose-the-access-mode).

## Debugging a start failure (verified procedure)

Two symptoms from the SRX4100 run, before the procedure below:

- `startup refused: cannot listen on <address>:<port>: Can't assign requested address`: the address
  is not in the instance the daemon creates its socket in, usually fxp0 under
  `system management-instance`. Set `routing_instance = mgmt_junos` (see the variant above).
- The daemon logs `listening on ...` but a browser times out (no refusal, no answer): the socket is
  in the wrong routing instance. It is not a port collision.
- Running test code: `python3` from the shell is "Operation not permitted" under veriexec (verified
  on SRX4100). Copy the script to `/var/db/scripts/jet/`, register it like `jwicket_probe.py`, and
  run it with `request extension-service start`.

A daemonized application cannot be started by hand (`request extension-service start` answers
"Can't start daemonize app", verified). Remove `daemonize`, then run it in the foreground, where its
errors print to the terminal:

```
delete system extensions extension-service application file jwicket.py daemonize
commit confirmed 5
commit comment "jwicket lab: debugging, no daemonize"
```

```
request extension-service start jwicket.py
```

With no arguments this is the daemon itself, reading `/var/db/jwicket/jwicket.ini`. How to stop a
foreground run (interrupting the CLI command, or `request extension-service stop jwicket.py`) is
unverified (record it with Q-RT-02). This is also where the unverified argument form of step 4
would be tried. To go back to daemon mode,
`set system extensions extension-service application file jwicket.py daemonize`, then
`commit confirmed 5` and `commit comment "..."`.

## Variant: `lab-token` backend

Use this only if NETCONF cannot be enabled. Every read runs as `<user>`, the daemon's account, and the
UI says so on every screen; settings refuse it on anything but a loopback bind. In the shell (from
the spike packet's run instructions; not in the recorded results):

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

In configuration mode, delete what this procedure added, including the lab-only account from
step 7. Leave out any line that step 0 showed was already configured before you started, and the
account line if you used the `lab-token` variant and created none:

```
delete system extensions extension-service application file jwicket.py
delete system extensions extension-service application file jwicket_selftest.py
delete system extensions extension-service application file jwicket_probe.py
delete system services netconf ssh
delete system scripts language
delete system login user <lab-only account>
commit confirmed 5
commit comment "jwicket lab: removal confirmed"
```

Unverified: these `delete` statements are the inverses of the `set` statements above, but the spike
only ran `delete system services rest`. Check each with `?` first. Leave out
`delete system scripts language` if anything else on the box relies on unsigned Python.
**Proposed (Spec 006), the ownership rule:** keep `system scripts language python3` while any other
Python script is configured (a commit, op, event or SNMP script whose name ends in `.py`, or an
extension-service file that is not one of J-Wicket's three) or present in `/var/db/scripts/commit`,
`op`, `event`, `snmp` or `jet`. Check with `show configuration system scripts` (commit, op and SNMP
scripts), `show configuration event-options event-script` (event scripts are configured there, not under
`system scripts`: junos-es 23.2R1 conf YANG, verified schema path; the command unverified on a device),
`show configuration system extensions` and `file list /var/db/scripts/<directory>` for each of the
five. Removing the statement stops every unsigned Python script on the box, not only J-Wicket.

If step 7 created a login class or set TCP forwarding, add these lines to the same commit (also
unverified; check each with `?`):

```
delete system login class <lab-only class>
delete system services ssh allow-tcp-forwarding
```

(or `delete system services ssh tcp-forwarding`, if that is the statement you added).

The lab-only account matters most: with SSH and NETCONF reachable from outside in vLabs, a leftover
account and its password stay exposed.

Whether deleting the configuration stops a running daemon is unverified. In the shell, check with
`ps ax | grep jwicket` (the spike's daemon showed as `cscript -mjet -Q3 -j -f <file> -J<user>`), and
stop a leftover process with `kill <pid>`; without `respawn-on-normal-exit` configured, Junos does
not restart it (verified). **Proposed (Spec 006), the process check:** remove the files only when no
J-Wicket process is left. Also check without the shell, in operational mode:

```
show extension-service status all
```

It lists the running Python extension-service applications with their `Process-id`, or prints
`warning: No active extension-services` (verified, Juniper's `show extension-service status`
reference); neither it nor `ps ax | grep jwicket` may show `jwicket.py`, `jwicket_selftest.py` or
`jwicket_probe.py`. The installers stop with exit 8 and keep the files in that case. Then remove the
files:

```
rm /var/db/scripts/jet/jwicket.py /var/db/scripts/jet/jwicket_selftest.py /var/db/scripts/jet/jwicket_probe.py
rm -r /var/db/jwicket        # also removes tls.key and tls.crt from the TLS variant
ls /var/db/scripts/jet/
```

The last listing should show only what was there before, such as Juniper's own applications.
Removing `/var/db/jwicket` itself likely needs root, as creating it did (inferred; this step was not
run on the SRX4100).

After an installer's uninstall, this step is still needed for what the installers never remove: a
lab-only account or class, or `allow-tcp-forwarding` (or `tcp-forwarding`), made by hand in step 7, and `/var/db/jwicket` itself,
which root removes once it is empty (`rmdir /var/db/jwicket`, unverified). Remove those as above. The
rollback history also keeps the removed statements (inferred). Finally, delete the disposable vSRX
itself if the lab allows it.
