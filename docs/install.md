# Installing J-Wicket on a lab SRX

> This installer has not yet run on any device. Every device step is unverified until lab test Q-INST-06 is certified.

**LAB ONLY. Pre-release. Unsupported.** J-Wicket is at its foundation stage and has passed neither
gate G1 ([governance](governance.md#3-gates-g0-to-g5)) nor a security review (Q-SEC-01). Nothing
here makes it installable on a production SRX. Use these installers only on a lab device you are
allowed to change: a disposable lab vSRX, or, with `--lab-hardware` ([below](#lab-hardware)), lab
hardware that carries only lab traffic and whose owner approves the run. No pre-release has been
published yet: the first tag would be `v0.1.0.dev1`, pushed only after the project owner's go.

This is the operator's guide. The design, with the Juniper source of every claim, is
[Spec 006](specs/006-installation.md); this guide repeats only what you need to run each method. It
is written for an SE or administrator who knows a little Junos
([ADR 0010](adr/0010-usable-without-knowing-junos.md)): each Junos command is explained where it
first appears, and the [Junos words](#junos-words-used-in-this-guide) table collects them.

Every device step in this guide is **unverified on a device** until lab test Q-INST-06 records it,
except where a step says "verified (spike)" or "verified on SRX4100". The spike ran its own daemon on
one vSRX 24.4R2-S3.5 on 2026-11-23 ([spike evidence](evidence/2026-11-23-vsrx-spike/README.md)). On
2026-11-24 J-Wicket's own bundle ran on the project owner's lab SRX4100, Junos 25.2R1-S1.4, installed
by hand with [deploy-lab.md](deploy-lab.md) ([SRX4100 evidence](evidence/2026-11-24-srx4100-lab/README.md)):
the statements and files the installers write, typed by a person, not sent by an installer. The only
install procedure that has run on a device is still that manual one.

What the SRX4100 run verified, by hand, that the installers rely on:

- `set system scripts language python3`, the `username` statements of the self-test and probe
  entries, and the daemon entry's `daemonize`, `respawn-on-normal-exit` and `username`: committed,
  and they worked;
- `commit confirmed 5`, a check, then a confirming commit; a commit left unconfirmed rolled back by
  itself (`UI_COMMIT_NOT_CONFIRMED ... automatic rollback complete`);
- `request extension-service start` printed the self-test and probe JSON on the CLI (whether the
  NETCONF reply the installers read carries it is **unknown**, Q-INST-05);
- Python 3.7.10 on the box, with `jnpr.junos`, `lxml`, `ncclient`, `paramiko` and `ssl` importable;
  veriexec `loaded active enforce`;
- a super-user-class account cannot create `/var/db/jwicket` (`mkdir` and `file make-directory`
  both `Permission denied`); root can, once;
- TLS on the fxp0 address, port 9443, with `[server] routing_instance = mgmt_junos` under
  `system management-instance`; SSH local forwarding refused (`administratively prohibited`).

Still **unverified**: `checksum sha-256` on JET files (Q-INST-02), every RPC an installer sends
(Q-INST-01), the bootstrap pattern (Q-INST-03), the owner and mode a file gets when an installer
copies it (Q-INST-01), and the installer's own certificate, its upload and check C8 (Q-INST-06).

## Contents

- [What every installer does](#what-every-installer-does)
- [Junos words used in this guide](#junos-words-used-in-this-guide)
- [Choose a method](#choose-a-method)
- [Before you start](#before-you-start), including [the state directory](#the-state-directory-once-as-root)
- [Choose the access mode](#choose-the-access-mode): `tls` (the default) or `tunnel`
- [Lab hardware](#lab-hardware) (`--lab-hardware`)
- [Get a pre-release and check where it came from](#get-a-pre-release-and-check-where-it-came-from)
- Built methods: [M1](#m1-workstation-installer-jwicket-install), [M2](#m2-ansible-playbooks),
  [M3](#m3-container-image), [M4](#m4-on-box-op-script-run-locally), [M4U](#m4u-the-same-op-script-with-op-url),
  [M5](#m5-the-device-pulls-the-bundle), [M6](#m6-cli-paste-units)
- [Methods documented but not built](#methods-documented-but-not-built)
- [Upgrade](#upgrade), [Uninstall](#uninstall), [Revert after a failure](#revert-after-a-failure),
  [Status and repair](#status-and-repair), [Exit codes](#exit-codes)
- [Troubleshooting](#troubleshooting)
- [What is verified, inferred and unknown](#what-is-verified-inferred-and-unknown)

## What every installer does

These rules are the owner's decision of 2026-11-24 and hold for every built method
([Spec 006, section 2.2](specs/006-installation.md#22-owner-decisions-2026-11-24-binding)):

1. **A dry run by default.** Without `--apply` (or its equivalent in each method) the installer only
   reads the device: no lock, no file, no commit. It lists `/var/db` and `/var/db/jwicket` too, read
   only, to check the state directory.
2. **The change first.** It prints the plan's configuration diff for each stage, the files with
   their modes and SHA-256, the state directory's check, what is already there and stays, and the
   warnings. The posture warning, exactly as every installer prints it:

   > LAB ONLY. This adds 'set system scripts language python3'. That lets any unsigned Python script owned by a super-user-class account run on this device's routing engine, not only J-Wicket: a change to the device's security posture. J-Wicket is not qualified for production (gate G1 has not passed). Continue only on a disposable lab device you are allowed to change.

   With `--access tls`, the default ([Choose the access mode](#choose-the-access-mode)), the listener
   warning:

   > LAB ONLY. With --access tls the runtime commit opens a new HTTPS listener on this device's management address: the --listen-address, by default --host, which the installer does not check is the management address (an address of a revenue interface would put the listener there; in the mgmt_junos routing instance when 'system management-instance' is set). It is reachable by anything that reaches that address: J-Wicket's sign-in page becomes one more way into this device, beside SSH and NETCONF. Its certificate is self-signed; compare its SHA-256 fingerprint in the browser with the one the installer prints. J-Wicket has not passed gate G1 or a security review (Q-SEC-01). Continue only on a lab device whose management network you control.

   With `--access tunnel`, instead:

   > With --access tunnel, J-Wicket listens on 127.0.0.1 only and is reached through 'ssh -L', which needs SSH TCP forwarding on the device. On a lab SRX4100 running Junos 25.2R1-S1.4 the tunnel was refused ('administratively prohibited') and 'set system services ssh tcp-forwarding' is a syntax error there (verified, docs/evidence/2026-11-24-srx4100-lab). The SRX configuration schema at 23.2R1 marks tcp-forwarding deprecated and names 'set system services ssh allow-tcp-forwarding'; that statement was not tried (unverified, Q-NET-03). Health check C8 is not available with this mode. --access tls is the alternative.

   And the account warning, where `<user>` is the account you install with:

   > J-Wicket will run with the rights of \<user>, a super-user-class account that can commit configuration ('username \<user>' under 'system extensions extension-service application file jwicket.py'). A compromise of J-Wicket is a compromise of this device.

3. **The production signs, shown and not judged:** model, release, serial, active flow sessions,
   outbound-SSH clients and their names (a central manager is likely), the accounts that have
   committed and when the last commit was. The installer refuses anything but a vSRX (R-MODEL)
   unless you pass `--lab-hardware` ([Lab hardware](#lab-hardware)), and always refuses chassis
   clusters, MNHA pairs and two routing engines.
4. **The lab gate.** You type the lab device's host name (the name set with `set system host-name`).
   The installer compares it with the name the device itself reports and never shows that name
   before you type it, so the answer comes from what you intend, not from the screen. Typing it is an
   attestation that this is a lab box; it does not prove it. On lab hardware you then also type
   `lab only`.
5. **Every write is a `commit confirmed`.** Junos rolls each change back by itself after a few
   minutes unless the installer confirms it (`commit confirmed 5`, a check, then a confirming commit
   is the SRX4100 run's own sequence, and a commit left unconfirmed there rolled back by itself:
   **verified on SRX4100**, by hand). The installer confirms only after its health checks pass on the
   device, at least 60 seconds before the deadline: the self-test and the module probe (C2, C3), the
   new build's start line in the log (C4), its audit record (C5), no refusal file (C6), a stable
   process (C7) and, with `--access tls`, an HTTPS read of J-Wicket's `/api/session` from your
   workstation that trusts only the certificate this run made (C8). With `--access tunnel` C8 is
   recorded "not available": no check opens an SSH forwarding channel, because the SRX4100 refused
   SSH forwarding. A failed check is never confirmed; the installer then removes what its earlier
   stages added (the revert stage). With the `netconf` backend it also prints:

   > The netconf backend's reach to the device's own NETCONF ('show configuration system services netconf') rests on the probe (check C3) only: it is not checked end to end, because no check uses an SSH channel (SSH forwarding was refused on the lab SRX4100). Sign in once to prove it.

What the installers add, and nothing else ([Spec 006, sections 7.3 and 7.5](specs/006-installation.md#73-the-statement-set)):

| What | Where |
| --- | --- |
| `set system scripts language python3` (unless already set) | Configuration (the posture change); **verified on SRX4100** by hand |
| `set system services netconf ssh`, if NETCONF is off (M1, M2, M3, and on-box installs with the `netconf` backend) | Configuration (NETCONF reachable wherever SSH is) |
| Three `system extensions extension-service application file` entries: `jwicket_selftest.py` and `jwicket_probe.py` (the diagnostics) and `jwicket.py` (the daemon), each with `username` and `checksum sha-256` | Configuration. `username`, and the daemon's `daemonize` and `respawn-on-normal-exit`: **verified on SRX4100**; `checksum sha-256`: **unverified** (Q-INST-02) |
| M4 and M4U only: `set system scripts op file jwicket-install-op.py checksum sha-256 <hash>`, or `set system scripts op allow-url-for-python` until the install ends | Configuration |
| Three copies of the bundle, 0644 | `/var/db/scripts/jet/jwicket.py`, `jwicket_selftest.py`, `jwicket_probe.py` |
| `jwicket.ini` (0600) and, later, the log and audit trail | `/var/db/jwicket/`, which root makes once ([below](#the-state-directory-once-as-root)); no installer creates or removes it |
| With `--access tls`: `tls.key` (0600) and `tls.crt` (0644), a self-signed RSA-2048 certificate for the listen address, valid 90 days | `/var/db/jwicket/` |

The settings with `--access tls` are the SRX4100 run's (**verified on SRX4100**, with a key made on
the box): `bind` and `allowed_hosts` the listen address, port 9443, `tls_cert` and `tls_key`, and
`routing_instance = mgmt_junos` when the configuration has `system management-instance`. With
`--access tunnel`: `bind = 127.0.0.1`, port 8443, `allowed_hosts = 127.0.0.1:8443, localhost:8443`.

What they never do: listen anywhere but the one address you name for `--access tls` (always with TLS)
or `127.0.0.1` (`--access tunnel`); render the extension-service `routing-instance` statement (it
did not move the listener on the SRX4100, **verified**); create or remove `/var/db/jwicket`, log in
as root or ask for the root password; write the TLS private key to the workstation's disk, log it or
print it; open an SSH forwarding channel; touch J-Web (`system services web-management`); change a
zone, filter or login account; read `system login` or any secret; run `commit check`; or run the
Junos shell themselves for anything but one fixed read of the veriexec state. Root's directory step
and, for M4 and M6, the on-box certificate are units you run.

## Junos words used in this guide

| Word | What it means here |
| --- | --- |
| Candidate configuration, `configure exclusive` | Junos edits a copy of the configuration (the candidate) and changes the device only when you commit it. `configure exclusive` enters configuration mode and locks the candidate, so nobody else edits it at the same time |
| `commit confirmed 5` | Commit now, and let Junos roll the change back by itself after 5 minutes unless a second commit confirms it (**verified**, Juniper's `commit` reference; a commit left unconfirmed rolled back by itself on the SRX4100, **verified**). The installers always add a comment: `commit confirmed 5 comment "..."` (minutes and comment together are **inferred** from the syntax) |
| `commit comment "..."` | The confirming commit. A `commit` or `commit check` confirms a pending `commit confirmed` ("To confirm a commit, enter either a commit or commit check command.", **verified**, Juniper's `commit` reference); that one typed by another user or in another session confirms it too is **inferred** (Q-INST-03), which is why the installers never send `commit check` and check first that nothing else is pending |
| `show system commit` | The commit history. Juniper's sample of a `commit confirmed` waiting for its confirmation: `0   2022-05-06 06:33:42 PDT by root via cli commit confirmed, rollback in 10mins`; a pending `commit at` starts the output with `commit requested by` (**verified** samples, `show system commit` reference; the wording on 24.4 Q-INST-01). `<rollback pending>` is only the name of that output field, not text to look for |
| `show \| compare` | The candidate's difference from the committed configuration, in Junos's patch form (`[edit ...]` headers, `+` added, `-` removed) |
| `rollback 0` | Throw away the candidate's uncommitted changes |
| `run <command>` | Run an operational command from configuration mode (**verified**) |
| `\| no-more` | Print without the pager, so pasted lines are not swallowed by a `---(more)---` prompt (**inferred**) |
| `set system scripts language python3` | Lets unsigned Python scripts run on the routing engine: the posture change of the warning above |
| `system extensions extension-service application file <name>` | A JET application: a Python file in `/var/db/scripts/jet` that Junos runs. `daemonize` keeps it running, `respawn-on-normal-exit` restarts it when it exits, `username` is the account it runs as (all three **verified on SRX4100**), and `checksum sha-256` the file's expected SHA-256 (schema **verified** at 23.2R1; whether Junos enforces it at start is **unknown**, Q-INST-02) |
| `request extension-service start <name>` | Runs a non-daemonized JET application once (the self-test and probe copies); on the SRX4100 it printed their JSON on the CLI (**verified**) |
| `system management-instance`, `mgmt_junos` | With this empty statement set, fxp0 is in the management routing instance `mgmt_junos`, and fxp0's address can be bound only there. The daemon's `[server] routing_instance = mgmt_junos` creates its listener there; the extension-service `routing-instance` statement does not (both **verified on SRX4100**). The installers read it with the configuration (inherited values included) and set `routing_instance` from it; the CLI units show `show configuration system management-instance | display inheritance` (that pipe combination **inferred**) |
| `set system services netconf ssh` | NETCONF over SSH, the XML management protocol the installers use; once set, Junos accepts it on the SSH port as well as 830 (**verified**) |
| Op script, `op <name>` | A script you run from the CLI. `set system scripts op file <name> checksum sha-256 <hash>` pins its bytes: a changed file does not run (**verified**) |
| `file list <dir> detail`, `file checksum sha-256 <file>`, `file copy`, `file change-permission`, `file show`, `file delete` | Junos's own file commands, run in operational mode; the installers use their NETCONF equivalents. `file make-directory` under `/var/db` was refused for a super-user-class account on the SRX4100 (**verified**); no installer sends it |
| Veriexec | The kernel's check that only verified executables run. In the shell, `sysctl security.mac.veriexec.state` prints `loaded active enforce` on a box whose results count as evidence (**verified**, spike; also on SRX4100). Under it, `python3` from the shell is "Operation not permitted" (**verified on SRX4100**) |
| The shell (`start shell`) | The FreeBSD shell under Junos. Juniper does not support operations there (**verified**); the installers use it for the veriexec read only |

## Choose a method

"Actions" counts a first install on one lab device after the one-time set-up, root's directory step
included. Every built method is **unverified on a device**.

| Method | Best when | One-time set-up | Actions per device: NETCONF already on | NETCONF off | Built |
| --- | --- | --- | --- | --- | --- |
| [M1](#m1-workstation-installer-jwicket-install) workstation installer | You have CPython 3.9.2 or later and SSH to the box | Download and check 5 files, a virtual environment, 2 `pip` commands | `ssh` once (records the host key), `install --apply`, type the host name | Also 4 short paste units on the device, then `install --apply` within 10 minutes | Yes |
| [M2](#m2-ansible-playbooks) Ansible playbooks | Several lab boxes, one at a time | As M1, on the controller, plus `ansible-core` | 1 playbook run for all hosts, 1 typed host name per host | Per host: 4 paste units, then a rerun for that host | Yes |
| [M3](#m3-container-image) container image | You cannot install Python packages, but have Docker on Linux | A checkout, `make container-context`, `docker build` | As M1, through `docker run` | As M1 | Yes (you build the image locally; never yet built or run with Docker) |
| [M4](#m4-on-box-op-script-run-locally) on-box op script | You have only the Junos CLI | None | 2 commands and a hash comparison (unit 0), 4 paste units, `op jwicket-install-op.py`, type the host name; with `tls`, first the certificate in the shell | The same (it adds NETCONF itself) | Yes |
| [M4U](#m4u-the-same-op-script-with-op-url) op script from a URL | As M4, without copying a file | None | 4 paste units, 1 `op url` command with the hash, type the host name | The same | Yes, only with the hash from `main` |
| [M5](#m5-the-device-pulls-the-bundle) device pull | The device should fetch the bundle itself | A URL the device can reach | An option of M1 (`--transfer`) | As M1 | Yes (options) |
| [M6](#m6-cli-paste-units) CLI paste units | You want to see and type every step | M1's set-up (it renders the units) | 20 units with `tls` (16 on the device, 4 on the workstation), 19 with `tunnel`; each checked by eye before its deadline | Included in the units | Yes (renderer) |
| [M7](deploy-lab.md) manual procedure | Qualification runs that need the reference steps | None | 9 steps by hand, several in the shell | Included | Exists; partly verified (spike, SRX4100) |

M1 is the reference: it automates every step and enforces every rule mechanically. M2 and M3 run
M1's executor; M4 and M4U run the same plan on the box. Use M6 to learn what the others do, or when
you cannot run anything but a terminal.

## Before you start

Every method needs the same box:

- **A lab device.** A disposable lab vSRX; a physical SRX only with `--lab-hardware`
  ([Lab hardware](#lab-hardware)). Any other model is refused (R-MODEL), and so are chassis clusters
  (R-CLUSTER), multinode HA (R-MNHA) and two routing engines (R-DUAL-RE), with or without
  `--lab-hardware`.
- **A Junos release whose Python is 3.7 or later.** 25.2R1-S1.4 ships 3.7.10 (**verified on
  SRX4100**); the module probe (check C3) records it for any other release.
- **A host name** (`set system host-name <name>`): the lab gate asks you to type it. A device without
  one is refused (R-NOHOST).
- **A super-user-class account that is not `root`.** It copies the files, owns them, and becomes the
  account J-Wicket runs as (the `username` of its application entries), as deploy-lab step 0
  requires. `root` is refused (R-ROOT).
- **`/var/db/jwicket`, made once by root** ([below](#the-state-directory-once-as-root)). Until it is
  there the installer refuses (R-STATEDIR).
- **SSH from your workstation**, with the device's host key recorded: log in once with `ssh
  <user>@<device>` on the same port the installer will use, and compare the fingerprint with the one
  the lab console or lab platform shows. The installer refuses unknown keys (R-HOSTKEY).
- **Nothing else pending.** In the CLI, `show system commit` must not show someone else's pending
  commit: stop if the newest entry (`0`) ends with `commit confirmed, rollback in <n>mins`, or the output starts with `commit requested by` (Juniper's sample wording). The installer refuses to run while
  one is waiting (R-PENDING).
- **Veriexec enforcing**, for results that count as evidence. Otherwise the installer stops
  (R-VERIEXEC) unless you pass `--veriexec-not-enforcing-ok`, which stamps the record "not
  qualification evidence".
- **J-Wicket's port free of J-Web and REST:** 9443 with `--access tls`, 8443 with `--access tunnel`.
  If `system services web-management` or `system services rest` listens on it, the installer refuses
  (R-PORT); choose another with `--daemon-port`. It never changes J-Web.
- **With `--access tls`** (the default): the address your browser will use, usually fxp0's
  (`--listen-address`; [Choose the access mode](#choose-the-access-mode)), and a route from your
  workstation to that address and port: check C8 and your browser both use it.

NETCONF can be on or off: if it is off, the installer prints a one-time bootstrap
([below](#netconf-off-the-bootstrap-units)).

### The state directory, once, as root

J-Wicket keeps its settings in `/var/db/jwicket`; the path is fixed, because the daemon takes no
arguments under Junos. A super-user-class account cannot create a directory under `/var/db`: on the
lab SRX4100 both `mkdir` and the CLI's `file make-directory` were refused with `Permission denied`,
and root made it and gave it to the account (**verified on SRX4100**). So, once per device, in a shell
on the lab device as root (outside Juniper support; how you become root is your lab's own procedure):

```
mkdir -m 700 /var/db/jwicket && chown <user> /var/db/jwicket
```

Then, as `<user>`, in operational mode: `file list /var/db detail` must list `jwicket` as
`drwx------` and `<user>`. The installers check exactly that: a directory, not a symbolic link,
owned by the account J-Wicket runs as, mode 0700, writable by nobody else (the daemon's own trust
rule). Their dry run lists `/var/db` and `/var/db/jwicket`, read only, and while the directory is
absent or fails that rule it reports R-STATEDIR with this step; `--apply` then stops with exit 1
before any write, and a pending bootstrap of yours stays unconfirmed, so Junos removes it at its
deadline. No installer runs this step, logs in as root or asks for the root password: the owner
chose this printed and checked root step as the installers' default on 2026-11-25
([ADR 0011](adr/0011-owner-decisions-lab-gated-install.md)). Moving the settings file elsewhere is an
owner decision, not a lab workaround. What the installer prints is in
[Troubleshooting](#vardbjwicket-absent-or-untrusted-r-statedir).

### A factory-default vSRX and lab platforms

**A factory-default vSRX** (KVM or EVE-NG, on the console) has none of these: no host name, no
account but `root`, and root without a password (**verified** for older releases by Juniper's vSRX
deployment guide for VMware, 2020; **unverified** for 24.4). Set root authentication first as that
guide describes (`system root-authentication`; this guide does not repeat it), then, in
configuration mode on the console:

```
set system host-name <lab-name>
set system login user <user> class super-user
set system login user <user> authentication ssh-ed25519 "<your public key>"
set system services ssh
commit
```

Each statement is in the SRX configuration schema at 23.2R1 (**verified**, junos-es YANG); their
use on a 24.4 factory-default box, and the quoting of the key, are **unverified**. The installers
never touch `system login`: accounts are yours to create and remove. Then root's directory step
above.

**Lab platforms** ([Spec 006, section 6.9](specs/006-installation.md#69-m7-and-m8-manual-procedure-and-lab-platforms)):

- **containerlab** (built here): [deploy/containerlab/README.md](../deploy/containerlab/README.md)
  starts one disposable vSRX with `make lab-up VSRX_IMAGE=<image>` and removes it with `make
  lab-down`. Its base configuration already has a host name, NETCONF and a super-user `admin`, and
  public default passwords: read that guide's credential section first. `admin` has a password and no
  SSH key there, so run M1 with `--password-prompt`, or add your key to `admin` first (that guide's
  section 4; M2 takes keys only). That guide also gives root's directory step for this lab, and uses
  `--access tunnel`, because its vSRX's management address is very likely not reachable from the host
  as the lab is built (**inferred**).
- **Juniper vLabs**: SSH reaches each device on its own address and port; pass that port with
  `--port <vLabs port>` (NETCONF then uses it too). Nothing is kept between sessions. vLabs forwards
  only SSH (22) and NETCONF (830) to the vSRX (deploy-lab step 7), so `--host` is the platform's
  forwarding address, not a device address, and the default `--access tls` would bind it, fail
  J-Wicket's start (check C4) and roll back (**inferred**). Use `--access tunnel` (whether vSRX
  24.4 allows the SSH forwarding it needs is unknown, Q-NET-03), or `--listen-address` set to the
  vSRX's own fxp0 address only if the platform lets your browser reach port 9443 there (not
  researched).
- **vSRX bootstrap ISO or OpenStack cloud-init**: use them for the prerequisites only (host name,
  account, SSH). Never pre-load J-Wicket's statements at boot: that would skip the gate, the diff and
  `commit confirmed`.
- **EVE-NG**: as a factory-default vSRX.

## Choose the access mode

How your browser reaches J-Wicket. `--access tls` is the default (the owner's decision of
2026-11-25, [ADR 0011](adr/0011-owner-decisions-lab-gated-install.md)); `--access tunnel` keeps the
earlier loopback design. `--backend lab-token` always uses `tunnel`, because the daemon refuses a shared
token off loopback (`--access tls` with it is refused, exit 2).

| | `--access tls` (default) | `--access tunnel` |
| --- | --- | --- |
| J-Wicket listens on | `--listen-address`, port 9443 (`--daemon-port`), in `mgmt_junos` when the configuration has `system management-instance` | `127.0.0.1`, port 8443 (`--daemon-port`) |
| You reach it at | `https://<listen address>:9443/`, from any host that reaches that address | `http://127.0.0.1:8443/` on your workstation, through `ssh -L 127.0.0.1:8443:127.0.0.1:8443 <user>@<device>` |
| Certificate | Self-signed RSA-2048, 90 days, subjectAltName the listen address. M1, M2 and M3 make it in memory with `cryptography` and send `tls.key` (0600) and `tls.crt` (0644) by SCP; the key is never written to your workstation's disk, logged or printed. M4 and M6 have you make it on the device, so the key never leaves it | None: plain HTTP, inside the SSH tunnel |
| Health check C8 | HTTPS `GET /api/session` from your workstation, trusting only this certificate (its SHA-256 fingerprint stands in for a CA store and the host-name check), version and build compared | Recorded "not available" |
| Status | The SRX4100 run's listener, **verified on SRX4100** with a key made on the box (TLS 1.2 and 1.3; a foreign `Host` header got 421). The installer's certificate, its upload and C8: **unverified** | SSH forwarding refused on SRX4100 25.2R1-S1.4 (**verified**); it works only where the release allows it (Q-NET-03) |

**The listen address** is an IPv4 address, written canonically (a host name is refused: the daemon
binds an address and the certificate names it; an IPv6 address is refused too). It defaults to
`--host` when that is an IP address; otherwise give `--listen-address`. On a box managed through
fxp0 it is fxp0's address (`show interfaces terse` lists the addresses). A wildcard, loopback,
multicast, link-local or reserved address is refused (R-BIND). The installer does not check that
the address is the management address: if you reach the box on a revenue-interface address, the
default puts J-Wicket's listener there, so give `--listen-address` (the plan prints the address
before the gate). It cannot tell whether the address belongs to the device either: a wrong one fails
J-Wicket's start, check C4 fails, and the stage rolls back.

**The fingerprint.** With `--access tls` the installer prints `TLS certificate for <address>: SHA-256
fingerprint` followed by 32 colon-separated hex pairs, the form browsers and `openssl x509
-fingerprint -sha256` show, and records it in the install record (never the key). When the browser
warns about the self-signed certificate, open its details and continue only if the SHA-256
fingerprint is the same. `jwicket-install open` prints it again. A rerun keeps the pair only when
this workstation's record names the same address and a certificate, both files still have their
owner and mode, the device's `tls.crt` is still the file this installer uploaded (its SHA-256, read
with `file checksum sha-256`, against the one recorded; the key is never read), and the certificate's
expiry date (notAfter, also recorded) is more than 14 days away. Otherwise it makes a new pair, with
a new fingerprint, and says why.

**Renewal.** The certificate is valid for 90 days. `jwicket-install status` and `open` warn once it
is within 14 days of its expiry date, and `status` reports an expired one as not healthy (C8 compares
the fingerprint, not the dates, so it alone would still pass). To renew, run `install --apply` again
from the workstation that holds the record: it makes and uploads a new pair. **J-Wicket reads its
key and certificate only when it starts**, and a renewal commits nothing, so the running J-Wicket
keeps serving the old certificate: the run says so, runs the read checks (C8, pinned to the new
certificate, fails until then) and exits 1. Restart J-Wicket in the shell with `kill <pid>` (`show
extension-service status jwicket.py` shows the pid; after SIGTERM it restarted by itself on SRX4100,
**verified**), then run `jwicket-install status`. The same holds for a run from a second workstation,
or after the record was lost: that workstation has no record of the pair, so it makes a new one.
Use one workstation per device, or copy its state directory. A pair made on the device (M4, M6) is
yours to renew: run the certificate unit again and restart J-Wicket.

Both modes print their warning before the gate ([rule 2](#what-every-installer-does)). With `tls`,
the HTTPS listener is reachable by anything that reaches the management address: J-Wicket's sign-in
page and its unauthenticated `GET /api/session` ([SECURITY.md](../SECURITY.md#known-gaps), known gap
10) become one more way into the device. Use it only on a lab management network you control.

## Lab hardware

R-MODEL refuses anything but a vSRX. `--lab-hardware` (on `install`, `uninstall` and `render`, and
typed at the op script's override prompt), with a typed `lab only` after the production signs, is
the only way a physical SRX gets through (the owner's decision of 2026-11-25,
[ADR 0011](adr/0011-owner-decisions-lab-gated-install.md)): only an SRX model whose
cluster status the installer could read, never a non-SRX or an unknown model. Chassis clusters, MNHA
pairs and two routing engines stay refused. With it, the plan prints:

> --lab-hardware: this device is not a vSRX ('show version' reports its model). J-Wicket has run on one lab SRX4100 by hand (docs/deploy-lab.md); this installer has run on no hardware, and the hardware procedure of governance decision D12 is not written: the lab owner decides. The production signs below are what a production firewall would show. After the host name, the installer asks you to type 'lab only'.

The production signs follow (model, release, serial, flow sessions, the outbound-SSH clients by
name, the committers and the last commit time). After your host name matches, it asks:

> Type 'lab only' to state that this device carries only lab traffic: no production traffic, user or service depends on it, and its owner approved this run ('show chassis hardware' and 'show configuration system services outbound-ssh' help you check). Your statement is recorded in the install record; it does not prove anything. Press Enter to stop:

Type exactly `lab only`. Anything else, or Enter, stops with exit 3 and nothing written. The install
record keeps the attestation (`lab_hardware_attested`) and the override. It is a statement, like the
host name: it proves nothing. The other refusals still apply: a central manager over outbound SSH is
R-MANAGED (`--ack-managed`), and an install made by hand is R-FOREIGN (`--adopt`).

The reference case is the project owner's SRX4100 (25.2R1-S1.4, standalone, Security Director Cloud
over outbound SSH, `system management-instance`, J-Wicket installed by hand with deploy-lab): the
installers' fixture of it needs `--lab-hardware`, `--ack-managed` and `--adopt`. On such a box:

```sh
jwicket-install install --release <tag> --host <device> --user <user> --listen-address <fxp0-address> --lab-hardware --ack-managed
jwicket-install install --apply --release <tag> --host <device> --user <user> --listen-address <fxp0-address> --lab-hardware --ack-managed
```

Add `--adopt` if J-Wicket is already there from deploy-lab. The installers' hardware path has never
run (Q-INST-06). The hardware procedure governance asks for (D12) is not written: on hardware, the
lab owner decides.

## Get a pre-release and check where it came from

Each lab pre-release has five files, always fetched from that tag's URLs
(`https://github.com/<owner>/<repo>/releases/download/<tag>/<file>`), never from `/releases/latest`,
which never points at a pre-release:

| File | What it is |
| --- | --- |
| `jwicket.py` | The J-Wicket daemon bundle |
| `jwicket-install-op.py` | The on-box op-script installer (M4, M4U) |
| `jwicket_install-<version>-py3-none-any.whl` | The workstation installer (M1, M2, M3) |
| `requirements-install.txt` | The installer's dependencies, each pinned by version and SHA-256 |
| `SHA256SUMS` | The SHA-256 of the four files above |

**`SHA256SUMS` on the release page is not enough.** It protects against a corrupted download, not
against a replaced release: whoever could replace the files could replace `SHA256SUMS` with them.
Check at least one source that is independent of the release page
([Spec 006, section 8.9](specs/006-installation.md#89-provenance-and-bundle-integrity-inv-07)):

| Source | How to check it |
| --- | --- |
| P-A, the immutable release's attestation | `gh release verify-asset <tag> <file> --repo <owner>/<repo>`, for each file (needs the GitHub CLI) |
| P-B, the build-provenance attestation | `gh attestation verify <file> --repo <owner>/<repo> --signer-workflow <owner>/<repo>/.github/workflows/release.yml --source-ref refs/tags/<tag> --source-digest <commit>`, where `<commit>` is the `source ref:` line of the bundle's header (so the attestation must name that commit), and that commit is on `main` |
| P-C, the release record on `main` | `docs/releases/<tag>.sha256sums` is byte-identical to `SHA256SUMS` ([docs/releases/README.md](releases/README.md)); it is added by a reviewed pull request after publication |
| P-D, a local reproduction | In a checkout of the tagged commit, `python3 tools/bundle.py --out dist/jwicket.py --source-ref <commit>` gives the same SHA-256 (the release notes list all four rebuild commands) |
| P-E, a hash you already hold | You pass it as `--expect-sha256 <hex> --expect-source <word>`; recorded as yours. The weakest source |

By hand, in an empty directory:

```sh
gh release download <tag> --repo <owner>/<repo> --dir . --pattern jwicket.py --pattern jwicket-install-op.py \
  --pattern 'jwicket_install-*.whl' --pattern requirements-install.txt --pattern SHA256SUMS
gh release verify-asset <tag> SHA256SUMS --repo <owner>/<repo>
curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/main/docs/releases/<tag>.sha256sums | cmp - SHA256SUMS
sha256sum -c SHA256SUMS
```

Without `gh`, `curl -fLO` each of the five per-tag URLs. The `verify-asset` line is P-A (repeat it
for every file you use); the `cmp` line is P-C (no output means identical). One of the two is
enough. On macOS, `shasum -a 256 -c SHA256SUMS` replaces `sha256sum -c`.

The workstation installer repeats these checks for `jwicket.py` itself whenever it downloads a
bundle: it tries P-E (if you gave a hash), then P-A, P-B, P-C and P-D (with `--checkout` and
`--reproduce`), and refuses `--apply` with exit 7 when none passes (R-PROVENANCE). A dry run shows
the refusal and exits 1. `--trust-release-page-only` continues anyway and stamps the record "not
qualification evidence". To download and check the bundle without touching a device:

```sh
jwicket-install fetch --release <tag> --out ./jwicket-<tag>
```

## M1: workstation installer (`jwicket-install`)

**Unverified on a device.** Every device step below has run only against fake device sessions. By
hand, the spike verified `scp -O`, the four daemon statements and the start at commit, and the
SRX4100 run verified the diagnostic and daemon statements, `commit confirmed 5` with a check before
the confirm, and the TLS listener's settings.

For an SE or administrator whose workstation reaches the lab device over SSH. The installer speaks
NETCONF on the SSH port through PyEZ (`junos-eznc` 2.8.3) and copies files with its own SSH client.

**Python on the workstation.** The installer's own floor is the pinned PyEZ's: `junos-eznc` 2.8.3
declares `Requires-Python: >=3.8` (its wheel's metadata, read 2026-11-25), and the installer wheel
says the same. The hash-pinned `requirements-install.txt` needs more: `cryptography` 50.0.2 (48.0.1
on Intel macOS) declares `>=3.9, !=3.9.0, !=3.9.1` and `paramiko` 5.1.0 `>=3.9` (PyPI metadata). So in
practice: **CPython 3.9.2 or later**. The plan and the op script, which run on the SRX's own Python,
need only 3.7.

### One-time set-up

From a checked pre-release ([above](#get-a-pre-release-and-check-where-it-came-from)), in the
directory holding its files:

```sh
python3 -m venv ~/.local/share/jwicket-install
~/.local/share/jwicket-install/bin/pip install --require-hashes -r requirements-install.txt
~/.local/share/jwicket-install/bin/pip install --no-deps ./jwicket_install-<version>-py3-none-any.whl
export PATH="$HOME/.local/share/jwicket-install/bin:$PATH"
```

`--require-hashes` installs exactly the dependency files whose SHA-256 the requirements file lists
(`cryptography`, which makes the TLS certificate, among them); `--no-deps` then adds the installer
without letting `pip` choose anything else. `pipx` and `uv tool install` cannot apply
`--require-hashes` to the dependencies the same way (**inferred**), so they are not recommended. From
a checkout, `make install-tool` does the same with a wheel it builds.

### Install

```sh
ssh <user>@<device>
jwicket-install install --release <tag> --host <device> --user <user>
jwicket-install install --apply --release <tag> --host <device> --user <user>
```

With `--access tls` and a `--host` that is a name, add `--listen-address <address>` to both lines.

1. The `ssh` login records the host key (once per device and port).
2. The dry run downloads the tag's `jwicket.py` and `SHA256SUMS`, checks them and their provenance,
   reads the device (`/var/db` and `/var/db/jwicket` among it) and prints the plan. Nothing is
   written. An absent or untrusted state directory is R-STATEDIR, with root's step
   ([above](#the-state-directory-once-as-root)), and exit 1.
3. `--apply` does the same, then asks for the host name. It prints this prompt, and never the name:

   > This installer is for lab devices only. J-Wicket has not passed gate G1. Type the host name of the lab device you intend to change (the name set with 'set system host-name'). Typing it confirms that this device is a disposable lab device you are allowed to change; it does not prove it. Press Enter to stop:

   On lab hardware, `lab only` next ([Lab hardware](#lab-hardware)). On a match, in this order: a
   second listing of `/var/db` (read only: a directory replaced since the dry run stops the run with
   R-STATEDIR, nothing written); the confirm of your NETCONF bootstrap, if you pasted one; one SCP to
   the staging name `/var/db/scripts/jet/jwicket-next.py`, checked with `file checksum sha-256`, then
   `file copy` on the device to the three names, each checked for SHA-256, owner and mode; the
   settings file; with `--access tls`, the certificate made in memory, `tls.key` sent by SCP with
   mode 0600 and checked by owner and mode only (never read back), `tls.crt` sent and checked, and its
   fingerprint printed; the **diagnostics** stage (a `commit confirmed 5` that adds `language python3`
   and the two diagnostic entries, runs the self-test and the probe, and is confirmed only if they
   pass); the **runtime** stage (a `commit confirmed 5` that adds the daemon's entries, which starts
   it, then the checks C4 to C8, C10 and C11 of
   [Spec 006, section 7.6](specs/006-installation.md#76-stages-and-checks) with the time left printed
   beside each); and the receipts. Each step prints the Junos command it equals.
4. The summary gives the way in (with `tls`, the URL and the certificate's fingerprint; with
   `tunnel`, the `ssh -L` line and the forwarding warning), how to sign in, and the uninstall command.

Defaults you may change: `--access` (`tls`; `tunnel` with `--backend lab-token`) and
`--listen-address` ([Choose the access mode](#choose-the-access-mode)); `--daemon-port` (9443 with
`tls`, 8443 with `tunnel`); `--backend lab-token` (one shared token instead of Junos sign-in; read it
on the device with `file show /var/db/jwicket/lab-token`, and NETCONF is removed again at the end if
the bootstrap added it, unless `--keep-netconf`; after that removal M1, M2 and M3 cannot reach the
device to uninstall or check it, see [Uninstall](#uninstall), so pass `--keep-netconf` if you will
use them for that); `--confirm-minutes` (5, from 3 to 30); `--bootstrap-minutes` (10, from 5 to 30);
`--remove-diagnostics` (delete the two diagnostic copies after the install); `--port` (the SSH port,
22; NETCONF uses it too; J-Wicket's own port is `--daemon-port`); `--netconf-port 830` (a NETCONF-only
port, the fallback when the SSH port does not carry NETCONF); and `--repo` (the release repository;
the project's own by default). `--layout group` puts the statements in a configuration group; leave
it off until lab test Q-INST-04 has shown that inheritance works for these hierarchies.
`--device-diff` prints Junos's own `show | compare` for each stage after the gate (it locks and loads
the candidate, then discards it). `-v` prints diagnostics on standard error; `--json` prints one JSON
document on standard output and nothing else.

**Credentials:** an SSH agent, a key (`--identity-file <path>`), or a password typed at a prompt
(`--password-prompt`). There is no password option, variable or file. The installer reads host keys
from `~/.ssh/known_hosts` (plain or hashed entries) and its own known-hosts file, and does not read
`~/.ssh/config`: name the key with `--identity-file`. `--host` takes a host name or an IPv4 address,
not IPv6.

### NETCONF off: the bootstrap units

The installer cannot add `netconf ssh` itself, so when NETCONF does not answer, the dry run reads
nothing, prints `NETCONF does not answer on the SSH port`, prints these units with a fresh six-letter
nonce, and exits 1. `jwicket-install bootstrap --user <user> --host <device>` prints them too, without
contacting the device. Paste them in an SSH or console session on the lab device, after checking that
your prompt shows `<user>@<the lab device you intend>`:

Unit A:

```
configure exclusive
run show system commit | no-more
```

STOP if the newest entry (`0`) ends with `commit confirmed, rollback in <n>mins`, or the output starts with `commit requested by`: type `exit`. Otherwise unit B:

```
set system services netconf ssh
show | compare | no-more
```

STOP unless `show | compare` shows this statement and nothing else. Junos prints a new level as a
braced block under the deepest level that already exists, so where `netconf` is new it shows
`[edit system services]` then `+    netconf {`, `+        ssh;`, `+    }` instead (illustrative;
real samples are recorded by lab test Q-INST-01):

```
[edit system services netconf]
+    ssh;
```

Otherwise type `rollback 0` and `exit`. Unit C (not confirmed by you):

```
commit confirmed 10 comment "jwicket-bootstrap netconf <nonce>"
```

Unit D:

```
exit
```

Then, within the 10 minutes, the command the units print:

```sh
jwicket-install install --apply --release <tag> --host <device> --user <user> --bootstrap-nonce <nonce>
```

Unit E repeats every option of your dry run that differs from its default, so the run installs what
you reviewed. A command longer than 400 characters is printed one option to a line, every line but
the last ending in ` \` so that it pastes as one command. A value is never cut or changed there: if
one option alone is longer than a unit line, or a value holds a control character, a tab or a line
break, unit E prints a `#` comment that names the option instead of a command, and you type the
command yourself with the same options and `--bootstrap-nonce <nonce>`.

The installer recognises your bootstrap only as the newest commit, by your account, with exactly
that comment and exactly that one added line; anything else pending is refused. It confirms it
only after the gate and the second listing of the state directory (an owner decision open for veto,
Spec 006 cut C5), then reads the commit history again to see that it is no longer pending;
connecting through it is its health check. Do root's directory step before you paste the units: a
bootstrap that meets R-STATEDIR stays unconfirmed and rolls back at its deadline. This is the rule
the units print:

> Keep this CLI session open until the installer reports that it confirmed the bootstrap: whether closing a CLI session rolls back its pending 'commit confirmed' early is unknown (lab test Q-INST-03). Do not type 'commit' to confirm it yourself: the installer confirms it only after its own checks and your typed host name. If you stop here, Junos removes it at its deadline.

While the bootstrap waits, NETCONF is reachable on `fxp0` and through any zone that admits `ssh` or
`netconf`, and another administrator's commit would confirm it (**inferred**). Keep the window short.
That the installer's NETCONF session confirms a commit typed in your CLI session is **inferred** too
(Q-INST-03); the re-read of the history after the confirm is how it finds out.

### Open the UI

```sh
jwicket-install open --host <device> --user <user>
```

It forwards nothing. It checks the device's host key, reads this workstation's install record for
that device, and prints the way in that the record names. With `--access tls`: the URL
`https://<listen address>:<port>/` and the certificate's SHA-256 fingerprint, then it runs check C8's
pinned HTTPS read and prints the result (exit 1 when there is no record or C8 fails). With `--access
tunnel`: the `ssh -L 127.0.0.1:8443:127.0.0.1:8443 <user>@<device>` line to run yourself (the explicit
`127.0.0.1` keeps the forward off your LAN) and the forwarding warning above; the forward needs the
device to allow SSH TCP forwarding, which the SRX4100 did not (deploy-lab step 7; the installer never
configures it). `--daemon-port` overrides the recorded port. With the `netconf` backend you sign in
with a Junos account.

### Developer path

From a checkout, after `make install-tool`:

```sh
make lab-install HOST=<device> USER=<user>
make lab-install HOST=<device> USER=<user> APPLY=1
```

It builds `dist/jwicket.py` and runs `install --bundle dist/jwicket.py --expect-sha256 <its sha256>
--expect-source local-build`: a dry run unless `APPLY=1`, and the gate still asks for the host name.
More of the installer's options pass through: `LISTEN=<address>` (`--listen-address`, needed when
`HOST` is a DNS name with the default `--access tls`), `ACCESS=tls` or `tunnel`, `DAEMON_PORT=<port>`,
`SSH_PORT=<port>`, `LAB_HARDWARE=1` (`--lab-hardware`), and `INSTALL_ARGS='<options>'` for anything
else, such as `INSTALL_ARGS='--ack-managed'` on a centrally managed lab box. `INSTALL_ARGS` may not
hold `--apply`: `APPLY=1` is the only switch that writes.

```sh
make lab-install HOST=lab-srx.example USER=<user> LISTEN=192.0.2.10 LAB_HARDWARE=1 INSTALL_ARGS='--ack-managed'
```

### Your records

The installer keeps its records in one private directory (0700, files 0600):
`$JWICKET_INSTALL_STATE_DIR` if set (an absolute path; a relative one is refused), else
`$XDG_STATE_HOME/jwicket-install`, else
`~/.local/state/jwicket-install`. It holds the receipt for each device (named by the SHA-256 of the
device's host-key fingerprint, never its name), written after every confirmed stage so a half-way run
can still be removed; the journal of each run; and the known-hosts file of keys accepted with
`--accept-new-host-key`. The receipt records the access mode, the listen address and port, the
routing instance, the certificate's SHA-256 and the lab-hardware attestation. The device keeps an
advisory copy in `/var/db/jwicket/install-receipt.json`. Uninstall evidence goes to
`./evidence-<fingerprint>-<time>/` in the current directory, or under `--evidence-dir`. None of these
files holds a password, the lab token, the TLS private key or a raw device reply.

## M2: Ansible playbooks

**Unverified on a device.** The playbooks hold no device logic: for each host they run M1's
`jwicket-install` on the controller, so every M1 step stays unverified as above.

[deploy/ansible/README.md](../deploy/ansible/README.md) is the full guide. In short: a Python 3.12
virtual environment on the controller with `pip install --require-hashes -r
deploy/ansible/requirements-ansible.txt` and the checked installer wheel `--no-deps`; copy
`inventory.example.ini` to `inventory.ini`; then, from `deploy/ansible`:

```sh
ansible-playbook -i inventory.ini install.yml -e jwicket_release=<tag>
ansible-playbook -i inventory.ini install.yml -e jwicket_release=<tag> -e jwicket_apply=true
```

The first line is the dry run. The second installs one host at a time (`serial: 1`): for each host
it shows the plan as M1 does, pauses for you to type that device's host name, and passes your answer
to `jwicket-install install --apply --method ansible --gate-from-stdin`, which compares it with the
name the device reports. `--gate-from-stdin` exists for this play only: without `--method ansible`
the installer refuses it (exit 2). Per host, the inventory may set `jwicket_access` (`tls` or
`tunnel`), `jwicket_listen_address` (needed with `tls` when `ansible_host` is a name),
`jwicket_daemon_port` and `jwicket_lab_hardware` (`true` passes `--lab-hardware` and adds a second
pause, for `lab only`). Each host needs root's directory step first; until then its dry run fails
with R-STATEDIR and the step. A host with NETCONF off fails with its
bootstrap units; paste units A to D on it, then rerun that host alone within 10 minutes with
`--limit <host> -e jwicket_bootstrap_nonce=<nonce>`. M2 takes an SSH agent or key only, never a
password, and offers no `--accept-new-host-key`, `--remove-shared`, `--device-diff`, `--rollback-now`
or device pull: use M1 for those. `upgrade.yml`, `uninstall.yml` and `status.yml` work the same way.

## M3: container image

**Unverified on a device**, and the image has not yet been built or run with Docker: CI's container
job will be its first build.

For a Linux workstation with Docker where you cannot install Python packages. The image wraps M1;
[deploy/container/README.md](../deploy/container/README.md) is the full guide. From a checkout:

```sh
make container-context TAG=<tag> REPO=<owner>/<repo>
docker build --tag jwicket-install:<version> deploy/container
install -d -m 0700 "$HOME/.local/state/jwicket-install"
```

`make container-context` downloads the installer wheel and `requirements-install.txt` for the tag,
checks their SHA-256 and provenance (`VERIFY=attestation` by default, or `signature` or `record`), and
puts them in `deploy/container/build/`; `LOCAL=1` builds them from the checkout instead. Then run M1's
commands through `docker run`, copied from that guide:

```sh
docker run --rm -it --user "$(id -u):$(id -g)" \
  --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp \
  -v "$HOME/.local/state/jwicket-install:/state" \
  -v "$HOME/.ssh/known_hosts:/home/app/.ssh/known_hosts:ro" \
  -v "$SSH_AUTH_SOCK:/ssh-agent" -e SSH_AUTH_SOCK=/ssh-agent \
  jwicket-install:<version> install --release <tag> --host <device> --user <user>
```

Add `--apply` to install; every M1 option, `--access`, `--listen-address` and `--lab-hardware`
among them, passes through unchanged. The entry point refuses every command but `bootstrap` and
`--help`, dry runs included, unless `/state` is a private, persistent mount, so the receipts survive
`--rm` (a dry run keeps its run directory and the downloaded bundle there). `uninstall` writes its
evidence directory under `/state` unless you give `--evidence-dir`. Mount an agent that holds
only the lab key, added with `ssh-add -c`: a mounted agent socket can sign with every key it holds.
The certificate's private key is made in the container's memory and never written to `/state`.
Limits: the entry point refuses `jwicket-install open` (exit 2): with `tls` nothing needs
forwarding, and with `tunnel` run the `ssh -L` line on the workstation; with `tls`, check C8 runs
from the container, so it needs a route to the listen address; and a containerlab vSRX needs
`--network clab`, while `--local-self-test` runs with the container's network.

## M4: on-box op script, run locally

**Unverified on a device.** No op script step has run on a device; whether an op script may write the
script directories, run `sysctl`, run `openssl` or open a connection to the listen address is
**unknown** (Q-INST-01, Q-INST-05).

For administrators with only the Junos CLI. The op script `jwicket-install-op.py` carries M1's plan
and checks and the SHA-256 of the tag's `jwicket.py`; Junos runs it with your account's rights, on
the box's Python 3.7. You pin the op script's own SHA-256 in the configuration, so a changed file
does not run. Its hash must come from `docs/releases/<tag>.sha256sums` on `main`
([release records](releases/README.md)) or a verified attestation, **never from the release page
alone**. Root's directory step ([Before you start](#the-state-directory-once-as-root)) comes first.

**Unit 0**, in operational mode:

```
file copy https://github.com/<owner>/<repo>/releases/download/<tag>/jwicket-install-op.py /var/db/scripts/op/jwicket-install-op.py
file checksum sha-256 /var/db/scripts/op/jwicket-install-op.py
```

STOP unless the checksum equals the `jwicket-install-op.py` line of `docs/releases/<tag>.sha256sums`
on `main`. Whether `file copy https://` checks the server certificate and follows GitHub's redirect
on Junos OS is **unknown** (Q-INST-05); the checksum is the control either way. The alternative is
`scp -O jwicket-install-op.py <user>@<device>:/var/db/scripts/op/jwicket-install-op.py` from any
machine (`scp -O` is OpenSSH's legacy SCP protocol, which Junos accepts; SFTP is off by default).

**With `tls` (the op script's default access too): the certificate, once.** The op script does not
make the TLS key pair: whether an op script may run `openssl` under veriexec is unknown, and the key
must never leave the device. Make the pair yourself in a shell on the device as `<user>` (not root),
deploy-lab's TLS unit, **verified on SRX4100** (outside Juniper support; the version of the shell's
`openssl` was not recorded, Python's `ssl` reported OpenSSL 1.1.1zb), with
your listen address in place of `<address>`:

```
start shell sh
cd /var/db/jwicket
umask 077
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 90 -keyout tls.key -out tls.crt -subj /CN=<address> -addext subjectAltName=IP:<address>
chmod 600 tls.key
chmod 644 tls.crt
openssl x509 -in tls.crt -noout -fingerprint -sha256
exit
```

Write down the `SHA256 Fingerprint=` line. Until both files are there, owned by `<user>`, the op script
refuses `tls` before any write and prints this unit. It reads only the certificate (never the key),
prints its fingerprint, which your browser must show too, and records it. With `tunnel`, skip this.

**Units A to D**, the op bootstrap (`jwicket-install bootstrap --method op --op-sha256 <hash> --user
<user>` prints the same units). Check that your prompt shows `<user>@<the lab device you intend>`.
Unit A:

```
configure exclusive
run show system commit | no-more
```

STOP if the newest entry (`0`) ends with `commit confirmed, rollback in <n>mins`, or the output starts with `commit requested by`: type `exit`. Otherwise unit B:

```
set system scripts language python3
set system scripts op file jwicket-install-op.py checksum sha-256 <hash>
show | compare | no-more
```

STOP unless `show | compare` shows these statements and nothing else (the `language python3` block
is absent if it was already set). Junos prints each change under the deepest level that already
exists, and a new level as a braced block of `+` lines, so the same statements may appear grouped
that way, for example `[edit system scripts]` then `+    op {` ... `+    }` (illustrative; real
samples are recorded by lab test Q-INST-01):

```
[edit system scripts]
+    language python3;
[edit system scripts op file jwicket-install-op.py checksum]
+    sha-256 <hash>;
```

Otherwise `rollback 0` and `exit`. Unit C, not confirmed by you:

```
commit confirmed 10 comment "jwicket-bootstrap op"
```

Unit D:

```
exit
```

Keep the CLI session open ([the rule in M1](#netconf-off-the-bootstrap-units)).
Then, within the 10 minutes:

```
op jwicket-install-op.py
```

That `op` takes the name with its `.py` suffix is **inferred**. The script checks its Python version
(3.7 or later) and the on-box PyEZ, reads the device, recognises its own pending bootstrap, asks how
J-Wicket will be reached, prints the plan, the warnings and the production signs, and asks for the
host name (`jcs.get_input`). Enter, a wrong name or a refusal (R-STATEDIR among them) writes nothing,
and Junos removes the bootstrap at its deadline. On a match it lists `/var/db` again, confirms the
bootstrap, places the bundle, runs the diagnostics and runtime stages as M1 does (adding `netconf
ssh` too, for the `netconf` backend), writes `/var/db/jwicket/uninstall-cli.txt` (0600) and the
device receipt. On any failure after the bootstrap's confirm it reverts what this run added.

Check C8 on the box: with `tls` and the listener in the default routing instance, the script sends
the pinned HTTPS read itself; with `mgmt_junos`, or with `tunnel`, C8 is recorded "not available",
because the script runs in the default instance and switching instances is process-wide (on the
SRX4100 `jcs.set_routing_instance` stopped the process's own NETCONF to `127.0.0.1:830`, **verified**).
C8 is never required for a confirm on the box: browse to the URL and compare the fingerprint
yourself.

What it may ask you, each typed exactly, in this order:

| Prompt | When |
| --- | --- |
| The veriexec state | It cannot run `sysctl` itself: in another session run `start shell sh`, `sysctl security.mac.veriexec.state`, `exit`, and type what it printed (recorded as "read by hand"), or press Enter |
| `uninstall` | J-Wicket is already installed: type `uninstall` to plan its removal, or Enter for an install, upgrade or repair |
| `tls` or `tunnel` | How J-Wicket will be reached; Enter takes the default (`tls`, or what the device receipt recorded) |
| The listen address | `tls` only: the device address your browser reaches, an IP address (fxp0's when you manage the device through fxp0) |
| An override flag, such as `--ack-managed` or `--lab-hardware` | A refusal that has an override: type the flag to continue (recorded), or Enter to stop |
| The host name | The lab gate |
| `lab only` | Lab hardware only, after the host name ([Lab hardware](#lab-hardware)); uninstall asks it too |
| `rollback` | After a failed check: roll back now instead of waiting for the deadline |

The bundle: if you copied it to your home directory as `jwicket.py` (for example `scp -O jwicket.py
<user>@<device>:jwicket.py`; that a relative name lands in the home directory is **inferred**), the
script reads that copy, which must be a regular file of yours that nobody else can write. Otherwise,
after the gate, it fetches the tag's `jwicket.py` with the `file copy` RPC. Either way the bytes land
only in the staging name and must match the SHA-256 the op script carries. A failed fetch is exit 7:
copy the bundle to your home directory and run `op jwicket-install-op.py` again.

The op script takes no options: the `netconf` backend, the access mode you type (`tls` on port 9443
or `tunnel` on 8443), direct statements, 5-minute stage windows and kept diagnostic copies. It never
removes `netconf ssh` and has no `--accept-unchecked-diagnostics`. Upgrade and uninstall: see
[Upgrade](#upgrade) and [Uninstall](#uninstall).

## M4U: the same op script with `op url`

**Unverified on a device.** How `op url` validates HTTPS, whether it follows GitHub's redirect, and
whether `jcs.get_input` prompts work under it are **unknown** (Q-INST-05).

Read M4 first: M4U is the same file run from its URL, with the same root step and, for `tls`, the
same certificate unit, and ranks below M4 because it adds a second posture change while it runs:

> This adds 'set system scripts op allow-url-for-python': while it is set, any user with the maintenance permission can run Python op scripts fetched from a URL. The installer removes it at the end.

Units A to D as in M4, except that unit B is (`jwicket-install bootstrap --method op-url --user
<user>` prints them):

```
set system scripts language python3
set system scripts op allow-url-for-python
show | compare | no-more
```

and unit C is `commit confirmed 10 comment "jwicket-bootstrap op-url"`. Then, with the op script's
hash from `docs/releases/<tag>.sha256sums` on `main` (`op url ... key sha-256` refuses other bytes,
**verified**):

```
op url https://github.com/<owner>/<repo>/releases/download/<tag>/jwicket-install-op.py key sha-256 <hash>
```

The rest is M4. The runtime stage removes `allow-url-for-python` when Junos's commit history shows
that this run's bootstrap added it.

## M5: the device pulls the bundle

**Unverified on a device.** Certificate checking by `file copy https://` on Junos OS, GitHub's
redirects, and whether `refresh-from` accepts a file name no entry configures are **unknown**
(Q-INST-05).

An option of M1 (and of M2's and M3's executor): instead of an SCP push, the device fetches
`jwicket.py` from a URL you give. The installer serves no files: use a lab web server you run, or the
tag's own asset URL. The workstation still downloads or reads the bundle to check its SHA-256 and
provenance; the device's copy lands on the staging name and must match that SHA-256 before anything
uses it.

```sh
jwicket-install install --apply --release <tag> --host <device> --user <user> --transfer file-copy --url https://github.com/<owner>/<repo>/releases/download/<tag>/jwicket.py
jwicket-install install --apply --release <tag> --host <device> --user <user> --transfer refresh-from --url https://<lab-server>/jwicket.py --cert-file /var/db/jwicket/lab-ca.pem
```

- `--transfer file-copy` is the RPC of `file copy <url> <file>`, which takes HTTP, HTTPS, FTP and SCP
  sources (**verified**).
- `--transfer refresh-from` is `request system scripts refresh-from extension-service file ... url
  ... cert-file ...`, which checks HTTPS against the PEM you name (**verified** on fixed releases;
  refused before Junos 21.2R1, R-RELEASE, CVE-2022-22156). The PEM must already be on the device
  under `/var/db/jwicket/`: the installer does not copy it. Copy it there after root's directory step
  (for example with `scp -O`), and name it `lab-ca.pem`, a name the uninstaller knows.
- Plain `http://` or FTP only with `--allow-plain-http`, recorded as the lab owner's consent: anyone on
  the path can read the bundle in transit; the SHA-256 check stops changed bytes from being used.
- The device needs an outbound path to the URL. A refused or missing pull is exit 7.
- On a device with `system management-instance` (fxp0 in `mgmt_junos`, **verified on SRX4100**), the
  installers fetch through `mgmt_junos`: they add `routing-instance mgmt_junos` to `file copy` and to
  `refresh-from` (M1, M4 and the M6 units), because the default instance's route does not go out of
  fxp0. That this routes the download through fxp0 is **inferred**; a pull that still times out is
  exit 7, and nothing is committed.

## M6: CLI paste units

**Unverified on a device.** The units follow deploy-lab's verified path where one exists (the spike,
and the SRX4100 run for the root step, the diagnostic and daemon statements and the on-box
certificate); the expected outputs shown with them are illustrative until lab test Q-INST-01 records
real ones.

`jwicket-install render` prints the whole install as numbered paste units for the Junos CLI, each
safe to paste whole. It needs M1's set-up to run, and contacts no device unless you give `--host`:

```sh
jwicket-install render --method cli --release <tag> --user <user> --listen-address <address>
jwicket-install render --method cli --release <tag> --user <user> --access tunnel
jwicket-install render --method cli --release <tag> --user <user> --host <device>
```

Offline (the first two lines; `tls` needs `--listen-address` there, `tunnel` does not), the units
carry a stamp telling you to check your CLI prompt and do every STOP check yourself, because nothing
has read the device; where a statement may already be set (`language python3`, `netconf ssh`), the
units say that its absence from `show | compare` is fine. With `--host`, the installer reads the
device first, applies the refusals (an untrusted state directory prints root's step and no units),
shows the production signs and asks for the host name (and `lab only` on lab hardware) before it
prints anything. The units for a fresh device, in order, with `tls` (with `tunnel` there is no unit 7,
and the later units are numbered one lower):

| Unit | Where | What |
| --- | --- | --- |
| 1 | Shell | The veriexec read (`start shell sh`, `sysctl security.mac.veriexec.state`, `exit`) |
| 2 | Operational mode | `show system commit`, `file list` of `/var/db` and `/var/db/scripts/jet` and, offline with `tls`, `show configuration system management-instance | display inheritance`: nothing pending, `jwicket` listed as `drwx------` and your account, and whether to add `routing_instance = mgmt_junos` to the settings |
| 3 | Shell, as root, once | Only if unit 2 did not list `jwicket` right: root's directory step (**verified on SRX4100**), printed after R-STATEDIR's explanation; then unit 2 again. Offline only: with `--host` a directory that is not right refuses the render |
| 4 | Workstation | `scp -O` of `jwicket.py` to the three names (**verified**, spike); unit 4-alt copies once and uses `file copy` on the device |
| 5, 6 | Workstation | Save `jwicket.ini` as printed, `chmod 600 jwicket.ini`, `scp -O` it to `/var/db/jwicket/jwicket.ini` |
| 7 | Shell, as your account | `tls` only: the certificate made on the device with `openssl`, so its key never leaves it (deploy-lab's TLS unit, **verified on SRX4100**); write down the fingerprint it prints |
| 8 | Operational mode | `file checksum sha-256` of each copy and `file list ... detail` of both directories |
| 9A to 9E | Configuration mode | The diagnostics stage |
| 10A to 10E | Configuration mode | The runtime stage (with 10D2, the process check 30 seconds later) |
| 11 | Workstation | `tls`: browse to `https://<address>:9443/` and compare the certificate's fingerprint with unit 7's; `tunnel`: the `ssh -L` line, with the forwarding warning |

Each stage is five units: A opens configuration mode (`configure exclusive`, `run show system commit
| no-more`); B holds the `set` lines and `show | compare | no-more`, with the exact change it must
show; C ends at the `commit confirmed` line, with nothing after it; D holds the checks, each with what
it must show (check C8, with `tls`, is your browser's read of `https://<address>:9443/api/session`
with the fingerprint compared); E is the confirm, pasted **only if every check matched**, at least
one minute before the deadline. For the diagnostics stage, units C and E (9C and 9E with `tls`, 8C
and 8E with `tunnel`) are:

```
run file delete /var/db/jwicket/selftest-result.json
run file delete /var/db/jwicket/probe-result.json
commit confirmed 5 comment "jwicket 0.1.0.dev1 sha256:<first 12 hex> diagnostics lab-install"
```

```
commit comment "jwicket 0.1.0.dev1 sha256:<first 12 hex> diagnostics confirmed"
exit
```

If a check does not match, type `exit` (answer `yes` if asked) and let Junos roll the stage back at
its deadline. The units never use `commit check` or `load ... terminal`, and every `show` carries `|
no-more`. `--set-files <dir>` also writes each stage's lines to `jwicket-<stage>.set`, which you copy
with `scp -O` to your home directory and load with `load set jwicket-<stage>.set` (that a relative
name loads from the home directory is **inferred**). `render --method cli --upgrade --host <device>`
and `render --method cli-uninstall --host <device>` print the other paths; both read the device, and
both take `--lab-hardware` on lab hardware.

## Methods documented but not built

| Method | Why not built |
| --- | --- |
| M7, [deploy-lab.md](deploy-lab.md) by hand | Exists: the reference and the fallback, several steps in the shell (outside Juniper support). Partly verified by the spike and by the SRX4100 run, which added its TLS-on-fxp0 variant |
| M8, lab platforms | Partly built: the containerlab topology ([above](#a-factory-default-vsrx-and-lab-platforms)). The other platforms are documented only; nothing J-Wicket-specific is ever pre-loaded |
| M9, central managers (Security Director, Mist, Junos Space) | A template deploy would bypass the typed gate, the structural check and the health check, and no file transfer is documented. Not before G1 |
| M10, ZTP and phone-home | A ZTP script runs with nobody to type the host name; vSRX has no DHCP ZTP. Documented only (Spec 006 cut C3) |
| M11, a signed JET package | Needs a commercial signing certificate from Juniper; a G4 and G5 matter |
| M12, a Juniper-shipped optional package | An HPE engineering and product decision |
| M13, a SLAX op script | Avoids `language python3`, but adds a second language to review, and its configuration-load helper has no confirmed commit; open |
| M14, an ncclient-only installer | Duplicates M1 |
| M15, Ansible `juniper.device` modules | **Rejected**: they do not verify host keys |
| M16, `source` and `set refresh` | Changes only where later updates come from, and anyone with configure rights can repoint it |
| M17, an SSH-CLI driver without NETCONF | **Deferred** until the 24.4 CLI's prompts and errors are recorded (Q-INST-05); guessing them would be unsafe |
| M18, an offline kit | Documented: on a connected machine, `pip download --require-hashes -r requirements-install.txt -d kit/wheels` for the lab workstation's platform (wheels are per platform, **inferred**), plus the wheel, `jwicket.py`, `SHA256SUMS` and the release record; offline, `pip install --no-index --find-links kit/wheels --require-hashes -r requirements-install.txt`, then the wheel `--no-deps` |
| M19, an Ansible role or collection | Adds only packaging to M2 |
| M20, NAPALM, Nornir, SaltStack, Terraform | Not researched |
| M21, a dev container or Codespaces | Whether a cloud workspace reaches your lab is unknown; then M1 |
| M22, a lab golden image | Documented: snapshot the vSRX disk after one M1 install; not possible on vLabs, which keeps nothing |
| M23, J-Web's CLI terminal for M6's units | Whether J-Web 24.4 offers a configuration-mode terminal is unverified |
| M24, the Junos REST API | **Rejected**: a posture change, and no file transfer |
| M25, an unsigned JET package | Likely refused by veriexec |
| M26, `juniper.device.junos_config` for NETCONF off | **Not built**: it commits in the loading task, without the diff first |

## Upgrade

Same command, newer tag: `install --apply --release <new tag>` (M1; M2 `upgrade.yml`; M3 through
`docker run`), with the same access options as the install. The installer recognises the earlier
build from Junos's commit history and its records, puts the new bytes on the staging name, then, in
the diagnostics stage, copies them onto the two diagnostic names right before the `commit confirmed`
that changes their checksums. In the runtime stage it keeps the old daemon as `jwicket-prev.py`,
copies the new bytes onto `jwicket.py` and commits the new checksum, which restarts J-Wicket
(**verified**, spike: a change to the application's statements restarted it). If a check fails, the
old bytes are copied back before the deadline and Junos rolls the checksum back. Whether copying onto
an existing file overwrites it is **unknown** (Q-INST-01): if the device refuses, the upgrade stops
before its commit (exit 4) with the old daemon still running; uninstall, then install. The TLS pair
is kept when this workstation's record names it ([Choose the access mode](#choose-the-access-mode)).
A run that rewrites `jwicket.ini` or the TLS pair without a runtime stage says so: the running daemon
reads them only when it starts, so restart it (`kill <pid>` in the shell; it came back by itself after
SIGTERM on the SRX4100, **verified**).

A failed upgrade is not reverted by a revert stage. When the runtime stage fails after the
diagnostics stage was confirmed, the device keeps the previous daemon (its old bytes copied back and
its old checksum rolled back), while the two diagnostic copies keep the new build's bytes with their
new, committed checksums: consistent, but not the state before the run. `jwicket-install status`
shows it; a later `install --apply` of either build pins them again (**unverified**, Q-INST-06).

- An install made with `--no-jet-checksum` cannot be upgraded this way (R-UPGRADE-NOCHECKSUM): without
  the checksum the upgrade would commit nothing, so it would have no `commit confirmed` safety net.
  Uninstall, then install.
- **M4 and M4U:** the designed upgrade is the new op script with a bootstrap that replaces the pinned
  checksum. The current plan recognises a pending bootstrap only when it adds statements, so that
  replacement is refused as R-PENDING. Until that is fixed, upgrade an on-box install by uninstalling
  with the old op script, then installing with the new one.
- **M6:** `jwicket-install render --method cli --upgrade --release <new tag> --user <user> --host <device>`.

## Uninstall

```sh
jwicket-install uninstall --host <device> --user <user>
jwicket-install uninstall --apply --host <device> --user <user>
```

On lab hardware, add `--lab-hardware`: the uninstall shares the install's platform refusals and asks
for `lab only` too. A device with `outbound-ssh` clients (a central manager, as the SRX4100 reference
case) also needs `--ack-managed`, and one with commit scripts `--ack-commit-scripts`: the uninstall
refuses R-MANAGED and R-COMMIT-SCRIPTS as the install does. The install's summary prints the
uninstall command with the overrides and ports it needs. The dry run lists what goes, what stays and why. `--apply` then asks for the host
name, fetches the evidence (the logs, audit trail, result files and device receipt, never
`jwicket.ini`, the lab token or `tls.key`; `--no-evidence` skips it), removes J-Wicket's statements
in one `commit confirmed`, checks that no J-Wicket entry is committed and confirms, checks that the
J-Wicket process has stopped, then deletes J-Wicket's files by their exact names (`tls.key` and
`tls.crt` among them). It never deletes recursively, and it leaves the state directory itself to
root, who made it:

> The uninstaller leaves /var/db/jwicket itself: its account cannot remove an entry of /var/db, as it could not create one (inferred from the verified refusal). Once 'file list /var/db/jwicket detail' shows nothing of J-Wicket's, in a shell on the lab device as root: 'rmdir /var/db/jwicket' (it refuses a directory that is not empty; unverified).

What it removes is decided by what this installer added, as Junos recorded it:

- J-Wicket's own entries (the three `jwicket*.py` applications, the op script's) are removed whole.
- Shared statements (`language python3`, `netconf ssh`, `allow-url-for-python`) are removed only when
  Junos's commit history and this workstation's receipt agree that this installer added them, and
  nothing else relies on them: `language python3` stays while any other Python script is configured
  or present. `netconf ssh` stays unless you pass `--remove-shared` and type `remove-netconf` at its own
  prompt, after this warning:

  > Removing netconf ssh ('delete system services netconf ssh') stops new NETCONF sessions to this device and may end every open one (unverified, lab test Q-INST-05), including tools that started using it after J-Wicket was installed.

- Anything present before the install stays, even with `--remove-shared`. Each kept statement is
  printed as a `Stays:` line with the reason.
- M4 and M6 installs write no workstation receipt, so their shared statements always stay; remove
  `language python3` yourself, with a `commit confirmed`, once nothing needs it.
- **After a lab-token install removed NETCONF** (the default when the bootstrap added it), M1, M2
  and M3 cannot reach the device: `uninstall` and `status` stop at "NETCONF does not answer", and
  `uninstall` has no bootstrap path, while pasting the NETCONF bootstrap units would leave a pending
  commit that `uninstall` refuses (R-PENDING). Either install with `--keep-netconf` when you will
  uninstall this way, or first add `netconf ssh` back yourself in a CLI session (`configure
  exclusive`, `set system services netconf ssh`, `commit confirmed 5 comment "netconf for uninstall"`,
  then, once `run show configuration system services netconf | no-more` shows `ssh;`, `commit comment
  "netconf for uninstall confirmed"` and `exit`; all **unverified**), then run `uninstall`. M6's
  `render --method cli-uninstall --host` needs NETCONF for its reads too. This `netconf ssh` was not
  added by the installer, so `uninstall` keeps it; remove it the same way afterwards if you want.

The installer also prints what it never removes:

> Not removed by this tool: lab accounts or login classes created by hand ('system login'), 'system services ssh allow-tcp-forwarding' or 'tcp-forwarding', whichever you added (deploy-lab step 7), and the device's rollback history ('show system rollback'), which still holds the old J-Wicket statements.

On the box (M4, M4U): run `op jwicket-install-op.py` and type `uninstall` at its first prompt, or
paste the units in `/var/db/jwicket/uninstall-cli.txt` (`file show /var/db/jwicket/uninstall-cli.txt`).
M6: `jwicket-install render --method cli-uninstall --user <user> --host <device>`; its last unit is
root's `rmdir`. M2: `uninstall.yml -e jwicket_apply=true`.

## Revert after a failure

When a check fails after a `commit confirmed`, the installer does not confirm. It prints which check
failed, the deadline and what Junos will roll back; for the runtime stage it also prints
`startup-refused.txt` and the end of the log. Junos rolls the stage back at the deadline (a commit
left unconfirmed rolled back by itself on the SRX4100, **verified**). Then the **revert stage**
removes, by its own `commit confirmed` with checks and a confirm, what this run's earlier confirmed
stages added (for example `language python3` and the diagnostic entries), deletes the files this run
created, and states the device's condition in one sentence. Exit 5. NETCONF added by the bootstrap
stays unless you passed `--remove-shared`. The state directory is never removed.

- `--rollback-now` asks you to type `rollback` after a failed check, to roll back at once instead of
  waiting for the deadline (a write, printed as such).
- `--keep-partial` skips the revert stage, for debugging; the device keeps what the confirmed stages
  added, and `uninstall --apply` removes it later.
- If the connection drops after a `commit confirmed`, Junos rolls the stage back at its deadline (or
  earlier when the session ends; documented for a killed NETCONF session, **inferred** for a drop).
  The installer reconnects only to read and never confirms from a new session.
- If someone else's `commit confirmed` appears between stages, the run stops (exit 1) and sends no
  revert commit, which would confirm theirs; it prints what is installed and how to finish or remove
  it once theirs is settled.

## Status and repair

```sh
jwicket-install status --host <device> --user <user>
```

Read-only: the J-Wicket entries, each file's owner, mode and SHA-256, the receipts, the process, the
end of the log and, with `--access tls`, check C8's pinned HTTPS read from your workstation (with
`tunnel`, "not available"). `--daemon-port` overrides the port the install record names.
`install --apply` on a device that is half installed does only the missing pieces; on a complete
install it commits nothing and runs the read checks only, exiting 1 if one fails. A run that rewrites
a file J-Wicket reads only at start (`jwicket.ini`, `tls.key`, `tls.crt`, `lab-token`) without a
runtime commit says that J-Wicket must restart, runs the same read checks against the process still
running and exits 1 if one fails ([Choose the access mode](#choose-the-access-mode), "Renewal", has the restart step). With
`--access tls`, `status` also warns when the recorded certificate is within 14 days of its expiry
date, and reports an expired one as not healthy.

## Exit codes

The same for every executor ([Spec 006, section 9.7](specs/006-installation.md#97-exit-codes)):

| Code | Meaning | What to do |
| --- | --- | --- |
| 0 | Done, dry run printed, or nothing to change | — |
| 1 | Refused (an `R-...` code is printed, with its override if it has one), R-STATEDIR among them; the device could not be read; NETCONF off (bootstrap units printed); an unknown host key; SSH sign-in failed; a dry run with no provenance source | Read the message: it names the setting or statement and the next step |
| 2 | Bad arguments or inputs, such as `--access tls` without a listen address when `--host` is a name | Fix the command line |
| 3 | The lab gate did not pass (the host name, or `lab only` on lab hardware), or there is no terminal to type at | Type the name the device reports (`show version` on the device), at a terminal |
| 4 | The device refused a step before that stage's commit (lock, load, commit, a file command), or the session was lost before it | Nothing was committed in that stage; read Junos's message |
| 5 | A check failed after `commit confirmed`; the stage was rolled back and, unless `--keep-partial`, reverted | [Revert after a failure](#revert-after-a-failure) |
| 6 | The device's change differed from the plan; the candidate was discarded, nothing committed in that stage | Report it with the printed statements and headers |
| 7 | Transfer, integrity or provenance failure: a refused copy or pull, a SHA-256, owner or mode mismatch, no provenance source with `--apply` (before any device contact) | [Owner or mode wrong](#owner-or-mode-wrong); [provenance](#get-a-pre-release-and-check-where-it-came-from) |
| 8 | Uninstall incomplete: the configuration is gone but a J-Wicket process still runs, so its files were kept | [Uninstall incomplete](#uninstall-incomplete-exit-8) |

## Troubleshooting

### NETCONF is off

`NETCONF does not answer on the SSH port`, the bootstrap units and exit 1: paste units A to D
([M1](#netconf-off-the-bootstrap-units)) and run `install --apply ... --bootstrap-nonce <nonce>` within
10 minutes. For `uninstall` and `status` there are no bootstrap units: see the lab-token note in
[Uninstall](#uninstall). If you missed the window, Junos removed the bootstrap: run the dry run again for a new
nonce. If NETCONF is on but only on port 830 (some lab images), add `--netconf-port 830`.

### `/var/db/jwicket` absent or untrusted (R-STATEDIR)

The dry run found no `/var/db/jwicket`, or one the daemon would not trust, or the second listing
after the gate found it changed. This is the expected first refusal on a new device: the account
cannot create the directory (**verified on SRX4100**). The installer prints this, with your account
in place of `<user>`, and exits 1:

> J-Wicket keeps its settings in /var/db/jwicket, and that directory is absent or J-Wicket cannot trust it: it must be a real directory, not a symbolic link, owned by \<user>, mode 700, so that 'file list /var/db detail' shows 'drwx------' and '\<user>'. A super-user-class account cannot create it: on a lab SRX4100 running Junos 25.2R1-S1.4 both 'mkdir' and 'file make-directory' were refused with 'Permission denied' (verified). The installer never creates it, never logs in as root and never asks for the root password, and it writes nothing while the directory is not right. Once, in a shell on the lab device as root (outside Juniper support; how you become root is your lab's own procedure), run 'mkdir -m 700 /var/db/jwicket && chown \<user> /var/db/jwicket' (docs/deploy-lab.md step 3; root's directory and chown were verified on that SRX4100, the '-m 700' mode is inferred), then run the installer again. If 'file list /var/db detail' lists jwicket as a symbolic link (its permissions start with 'l'), first remove the link itself, as root, with 'rm /var/db/jwicket' (never 'rm -r'), because chmod and chown change a link's target. If it is a real directory with another owner or mode, run instead, as root, 'chmod 700 /var/db/jwicket && chown \<user> /var/db/jwicket' (unverified). Moving the settings file elsewhere is an owner decision, not a lab workaround.

No tool runs this step or takes the root password; it is the lab owner's step
([deploy-lab step 3](deploy-lab.md#3-create-the-settings-directory-and-file)). Check the result with
`file list /var/db detail` before you rerun. Use another session than the one holding a pending
bootstrap; if that bootstrap has rolled back meanwhile, the rerun prints new units with a new nonce.

### Owner or mode wrong

Each copy is checked with `file list /var/db/scripts/jet detail`: it must show `-rw-r--r--` and your
account (`jwicket.ini` and `tls.key`: `-rw-------`; `tls.crt`: `-rw-r--r--`). A copy made on the
device with the wrong owner is deleted and sent by SCP instead; a wrong mode is fixed with `file
change-permission`, and a `tls.key` that cannot be set to 0600 is refused. Files listed as owned by
`root` mean your account maps to root: R-ROOT, exit 7, and you need another account. An existing
J-Wicket entry or file that belongs to another account is R-USER: use that account, or uninstall
first. The owner and mode Junos gives a copied file are **unknown** (Q-INST-01): record what you see.

### The checksum statement is refused

If the commit is refused and Junos's message says the `checksum` statement is unknown or unsupported,
the installer stops (exit 4) and suggests `--no-jet-checksum`, which installs without the `checksum
sha-256` lines (recorded). It never suggests it for a checksum mismatch. Such an install cannot be
upgraded in place (R-UPGRADE-NOCHECKSUM).

### A health check failed and the install was reverted

Exit 5. The output names the check (C2 self-test, C3 probe, C4 start line, C5 audit record, C6 refusal
file, C7 stable process, C8 the pinned HTTPS read of `/api/session`, C10 committed change, C11 commit
history; C1 is reserved and C9 retired), what it saw and how many seconds were left.
`startup-refused.txt` names the setting or file the daemon refused; the log shows a restart loop as
two `listening on` lines. Fix the cause, then run `install --apply` again; `--keep-partial` keeps the
state for a closer look. With `--access tunnel`, C8 is "not available", with a warning; that is not a
failure.

### J-Wicket does not answer on the listen address

With `--access tls`, check C8 (and your browser) reaches `https://<listen address>:<port>/` from the
workstation. From the SRX4100 run (**verified on SRX4100**, by hand):

- `startup refused: cannot listen on <address>:<port>: Can't assign requested address`: the address
  is not in the routing instance the daemon creates its socket in, usually fxp0 under
  `system management-instance` without `routing_instance = mgmt_junos`. The installer sets it from
  the configuration it read; if `system management-instance` was added since, run the installer again.
- J-Wicket logs `listening on ...`, but the connection times out: the socket is in the wrong routing
  instance. It is not a port collision.
- No route from the workstation to the management network: C8 fails with a timeout, and the stage
  rolls back. Run the installer from a host on that network, or use `--access tunnel` where the
  release allows SSH forwarding.

### Unknown host key

R-HOSTKEY and exit 1. Log in once with `ssh <user>@<device>` on the same port and compare the
fingerprint with the lab console or the lab platform's UI (how to read it in the Junos CLI is
**unknown**, Q-INST-05). Or pass `--accept-new-host-key` at a terminal: the installer prints the
SHA-256 fingerprint, asks you to type `yes`, records it in its own known-hosts file and in the
receipt's overrides. Two ports with different keys always stop the run. After `make lab-down` and
`make lab-up` the box has a new key: `ssh-keygen -R <device>` first.

### Uninstall incomplete (exit 8)

The configuration is removed but `show extension-service status jwicket.py` still lists a J-Wicket
process after a stop request, so the files were kept. Stop it by hand (deploy-lab step 9: `kill <pid>`
in the shell, outside Juniper support), then run `jwicket-install uninstall --apply --host <device>
--user <user>` again to delete the files.

### Other refusals

- **R-PENDING:** a `commit confirmed`, `commit at` or `commit prepare` is waiting (`show system
  commit`). Wait until it is confirmed or rolled back. If it is your own bootstrap, pass the nonce it
  carries with `--bootstrap-nonce`.
- **R-FOREIGN:** J-Wicket entries exist that this installer did not add, for example a deploy-lab
  install. Uninstall them by hand, or pass `--adopt` to take them over (recorded).
- **R-MANAGED** and **R-COMMIT-SCRIPTS:** outbound-SSH clients (a central manager) or commit scripts
  are configured. `--ack-managed` or `--ack-commit-scripts` continues (recorded).
- **R-MODEL:** not a vSRX. A physical SRX that carries only lab traffic: `--lab-hardware` and `lab
  only` ([Lab hardware](#lab-hardware)); anything else is refused.
- **R-BIND:** the listen address is a wildcard, loopback, multicast, link-local, reserved or IPv6 address (the message names which).
  Give the device address your browser reaches.
- **R-PORT:** J-Web or REST listens on J-Wicket's port. Choose another with `--daemon-port`.
- **SSH sign-in failed:** load the key into your agent, pass `--identity-file`, or use
  `--password-prompt`.

## What is verified, inferred and unknown

The full list, with sources, is [Spec 006, section 14](specs/006-installation.md#14-what-is-verified-inferred-and-unknown-in-one-place).
The ones an operator meets first:

| Claim | Status | Settled by |
| --- | --- | --- |
| `scp -O` into `/var/db/scripts/jet`, the four daemon statements, start at commit, restart on a statement change | **Verified** (spike, by hand) | — |
| `language python3`, the diagnostic and daemon `username` statements, `daemonize`, `respawn-on-normal-exit`; `request extension-service start` printing the self-test and probe JSON on the CLI | **Verified on SRX4100** (by hand) | — |
| `commit confirmed 5`, a check, then the confirm; an unconfirmed commit rolling back by itself | **Verified on SRX4100** (CLI, by hand) | — |
| Python 3.7.10 with `jnpr.junos`, `lxml`, `ncclient`, `paramiko`; veriexec `loaded active enforce` | **Verified on SRX4100** | Q-RT-01 (passed there) |
| A super-user-class account cannot create `/var/db/jwicket`; root can make it and `chown` it to the account | **Verified on SRX4100** | — |
| Root's exact `mkdir -m 700 ... && chown` gives `drwx------` | **Inferred** (deploy-lab step 3; the run recorded the chown, not the command line) | — |
| TLS on fxp0 with `routing_instance = mgmt_junos`; the JET `routing-instance` ineffective; SSH forwarding refused on 25.2R1-S1.4 | **Verified on SRX4100** | Q-TLS-01, Q-NET-01, Q-NET-03 |
| NETCONF answers on the SSH port once `netconf ssh` is set | **Verified** (Juniper's NETCONF guide); not yet on 24.4 | Q-INST-05 |
| The NETCONF reply of `request extension-service start` carries the JSON | **Unknown** (the CLI output is **verified on SRX4100**; the NETCONF reply is not) | Q-INST-05 |
| The installer's certificate made in memory, its upload by SCP, check C8 | **Unverified** | Q-INST-06 |
| Owner and mode after SCP and `file copy`; `file copy` onto an existing file | **Unknown** | Q-INST-01 |
| `checksum sha-256` enforced at start and respawn | **Unknown** | Q-INST-02 |
| Closing a CLI session rolls a pending bootstrap back early; another session's commit confirms it | **Unknown**; **inferred** | Q-INST-03 |
| Configuration-group inheritance for these hierarchies (`--layout group`) | **Inferred** | Q-INST-04 |
| `file copy https://` and `op url`: certificate checks and GitHub's redirect; `openssl` from an op script | **Unknown** | Q-INST-05 |
| Every installer step, end to end, both access modes, lab hardware | **Unverified** | Q-INST-06 |
