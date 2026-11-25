# J-Wicket with Ansible (M2)

> **LAB ONLY.** This installer has not yet run on any device. Every device step is unverified until
> lab test Q-INST-06 is certified. J-Wicket has not passed gate G1 or a security review (Q-SEC-01):
> use these playbooks only on lab devices you are allowed to change, a vSRX or, with
> `jwicket_lab_hardware`, lab hardware that carries only lab traffic.

[Spec 006](../../docs/specs/006-installation.md) section 6.3 is the design. These playbooks install,
upgrade, remove and read J-Wicket on several lab devices, one host at a time, with the same lab gate as
the workstation installer. They hold no device logic: for each host they run that installer,
`jwicket-install` (M1), on this controller, with an argument list. `jwicket-install` makes every
connection (with host-key checks), reads the device, shows the plan, compares the host name you type
with the one the device reports, and makes every change as a `commit confirmed` that it confirms only
after its health checks pass. No `juniper.device` or `ansible.netcommon` module touches the device, and
no Ansible collection is installed (section 6.14 says why each was not used).

| File | What it is |
| --- | --- |
| `install.yml` | Dry run by default; with `-e jwicket_apply=true`, the lab gate and the install, per host |
| `upgrade.yml` | `install.yml`'s play, plus a check that each host's plan is an upgrade of a recorded install |
| `uninstall.yml` | Dry run by default; with `-e jwicket_apply=true`, the lab gate, the evidence fetch and the removal |
| `status.yml` | Read-only status of each host (no gate, no write) |
| `inventory.example.ini` | An inventory to copy; documentation addresses only |
| `ansible.cfg` | Readable output, no syslog of module arguments, pipelining; read when you run from this directory |
| `requirements-ansible.txt` | `ansible-core==2.20.0` and the installer's dependencies, every package pinned by version and SHA-256 |
| `requirements-ansible.in` | The four top-level pins `requirements-ansible.txt` is generated from: `ansible-core`, `junos-eznc`, `scp`, and `cryptography`, which makes the `tls` certificate |

## What you need

| Need | Why |
| --- | --- |
| Python 3.12 or later on the controller | ansible-core 2.20 requires it (PyPI metadata, **verified** in research on 2026-11-24). The installer alone needs less: its pinned `junos-eznc` 2.8.3 declares `Requires-Python >=3.8` (Spec 006 section 6.2) |
| The installer wheel of the pre-release you install, checked as [docs/install.md](../../docs/install.md) says for M1 (SHA-256 and one provenance source independent of the release page) | The playbooks run that wheel's `jwicket-install` |
| An SSH agent or key holding the lab account's key (`ssh-add`) | M2 supports no passwords: `jwicket-install` asks for one only on a terminal, and the plays give it none |
| The device's host key in `~/.ssh/known_hosts`, for the address and port the inventory names | `jwicket-install` refuses unknown host keys; M2 cannot run its interactive `--accept-new-host-key`, so log in once with `ssh <user>@<device>` and compare the fingerprint first |
| A super-user-class device account that is not `root` | It becomes J-Wicket's account (spec 7.5) |
| `/var/db/jwicket` on each device, made once by root | That account cannot create it (**verified** on a lab SRX4100, below); until it exists the dry run reports R-STATEDIR and the host stops |
| With `--access tls` (the default): a path from this controller to the device's listen address and port (9443 unless `jwicket_daemon_port`) | The health check C8 is an HTTPS read from here to J-Wicket, pinned to the certificate the run made |

## Set-up, once per controller

```sh
python3.12 -m venv ~/.local/share/jwicket-ansible
~/.local/share/jwicket-ansible/bin/pip install --require-hashes -r deploy/ansible/requirements-ansible.txt
# The installer wheel, downloaded from the per-tag release page with SHA256SUMS and checked first:
~/.local/share/jwicket-ansible/bin/pip install --no-deps ./jwicket_install-0.1.0.dev1-py3-none-any.whl
cp deploy/ansible/inventory.example.ini deploy/ansible/inventory.ini   # then edit it
```

The plays look for `jwicket-install` beside the Python that runs `ansible-playbook` (the virtual
environment above), so one virtual environment holds both. `-e jwicket_install_executable=<absolute
path>` names another. `inventory.ini` is ignored by git, so lab addresses stay on your machine.

## Run

Run from this directory, so that `ansible.cfg` applies (Ansible ignores it in a world-writable
directory):

```sh
cd deploy/ansible
PATH="$HOME/.local/share/jwicket-ansible/bin:$PATH"
# Dry run: each host's plan, nothing written.
ansible-playbook -i inventory.ini install.yml -e jwicket_release=v0.1.0.dev1
# Install, one host at a time, typing each device's host name at its gate.
ansible-playbook -i inventory.ini install.yml -e jwicket_release=v0.1.0.dev1 -e jwicket_apply=true
```

For each host, in turn (`serial: 1`; the first failure stops the run, so later hosts stay unchanged):

1. The play refuses to start if `jwicket_gate_typed`, `jwicket_lab_typed`, `jwicket_device_hostname`
   or any name it registers or derives for itself is already defined. Extra variables "always win
   precedence" over registered ones (Ansible variable precedence, **verified**), so
   `-e jwicket_gate_typed=...` could otherwise stand in for your answer.
2. It checks every input against fixed patterns (the same ones `plan.py` uses), and with `--access tls`
   that there is an address to listen on. Then it runs two dry runs of
   `jwicket-install install --release <tag> --host <ansible_host> --user <jwicket_user>`, which only
   read. The first prints the plan as M1 shows it: `DEVICE_STATUS`, the posture warning and the other
   warnings, the production signs, the plan's diff per stage, the files and their modes. The second
   adds `--json`; the play parses that output with `from_json` from the registered result, never from a
   variable file, and prints a short summary: the model, release and serial, the access mode, listen
   address and port, the routing instance, and the production signs. Neither shows the device's host
   name.
3. With `-e jwicket_apply=true` only: the lab gate, a pause with the installer's `LAB_GATE_PROMPT`. It
   shows no host name. Type the device's host name (as `set system host-name` set it) and press Enter;
   Enter alone stops. With `jwicket_lab_hardware=true`, a second pause with `LAB_HARDWARE_PROMPT`
   follows: type `lab only` (see [Lab hardware](#lab-hardware)).
4. `jwicket-install install --apply ... --method ansible --gate-from-stdin --json` runs with your
   answers on its standard input, one per line. It reads the device again, compares your first answer
   with the host name the device reports, then (for lab hardware) your second with `lab only`, and
   only when both match makes its changes. Its output (the result document, then its diagnostics) is
   printed when it finishes; the task line itself shows only `changed` or `ok`, because its arguments
   include your answers.

Ansible prints inventory names (`lab-a`) in every task line. They are your labels, not the device's
host names; labels that differ from the host names keep the screen from giving the answer away.

## Variables

| Variable | Where | Meaning |
| --- | --- | --- |
| `ansible_host` | inventory | The device's IPv4 address or DNS name, passed as `--host` (defaults to the inventory name); `jwicket-install` takes no IPv6 address, so the play refuses one |
| `jwicket_user` | inventory | The device account, passed as `--user`; super-user class, not `root` |
| `jwicket_ssh_port` | inventory, optional | The device's SSH port, passed as `--port` (default 22); NETCONF runs on it too |
| `jwicket_access` | inventory, optional | `tls` (`jwicket-install`'s default) or `tunnel`, passed as `--access`; see [Access](#access) |
| `jwicket_listen_address` | inventory, optional | `tls` only: the IPv4 address J-Wicket listens on, passed as `--listen-address`; defaults to `ansible_host` when that is an IPv4 address, else required |
| `jwicket_daemon_port` | inventory, optional | J-Wicket's port, 1024 to 65535, passed as `--daemon-port` (default 9443 with `tls`, 8443 with `tunnel`); never J-Web's or REST's port (R-PORT) |
| `jwicket_lab_hardware` | inventory or `-e`, optional | `true` passes `--lab-hardware` and adds the `lab only` pause (install, upgrade and uninstall); see [Lab hardware](#lab-hardware) |
| `jwicket_release` | `-e` | The pre-release tag, such as `v0.1.0.dev1` (install and upgrade) |
| `jwicket_apply` | `-e` | `true` to pass the gate and change the device; anything else is a dry run. Refused with `--check` |
| `jwicket_bootstrap_nonce` | `-e` with `--limit`, or one host's inventory line | The nonce of a NETCONF bootstrap you pasted on that device (install and upgrade; `uninstall.yml` refuses it, because `jwicket-install uninstall` takes no bootstrap) |
| `jwicket_overrides` | `-e` (a JSON list) | Override flags passed to `jwicket-install`, from a fixed list: install and upgrade allow `--adopt`, `--ack-managed`, `--ack-commit-scripts`, `--veriexec-not-enforcing-ok`, `--trust-release-page-only`, `--accept-unchecked-diagnostics`, `--no-jet-checksum`; uninstall allows `--ack-managed`, `--ack-commit-scripts`. Each is recorded by `jwicket-install` as M1 records it. `--lab-hardware` is not among them: it comes only with its pause |
| `jwicket_expect_sha256`, `jwicket_expect_source` | `-e`, both or neither | An operator-supplied bundle hash and where it came from (provenance source P-E, spec 8.9) |
| `jwicket_evidence_dir` | `-e`, optional | Where `uninstall.yml` runs `jwicket-install`, which writes `evidence-<fingerprint>-<time>/` there; default `~/.local/state/jwicket-install/evidence`. The play creates it, or sets it, to mode 0700 after the gate, so name a directory of its own |
| `jwicket_install_executable` | `-e`, optional | Absolute path of `jwicket-install` |

Never set a password variable, in the inventory or anywhere else: the playbooks use none, and the
contract test fails if one appears in these files. Neither typed answer (the host name, `lab only`) is
ever a variable: the first task refuses `jwicket_gate_typed` and `jwicket_lab_typed` from outside.

## Access

`jwicket-install` decides how J-Wicket is reached (Spec 006 section 7.5); the plays only pass the
choice on.

- **`tls` (the default).** J-Wicket listens with TLS on the listen address and port, in the
  `mgmt_junos` routing instance when the device has `system management-instance`. The installer makes
  a self-signed certificate for that address in memory, copies the key and certificate to
  `/var/db/jwicket`, and prints and records only the certificate's SHA-256 fingerprint: compare it in
  the browser at `https://<listen address>:<port>/`. **This opens a new HTTPS listener on the
  management address, reachable by anything that reaches that address**, and J-Wicket has not passed
  G1 or a security review. The same listener settings ran on a lab SRX4100 (25.2R1-S1.4) by hand, with
  a key made on the box (**verified**, [lab evidence][srx4100]); the installer's certificate and copy
  are **unverified**.
- **`tunnel`.** J-Wicket stays on the device's `127.0.0.1`, reached through `ssh -L` (the installer
  prints the line). On that SRX4100 SSH refused the forward (`administratively prohibited`), and
  `set system services ssh tcp-forwarding` is a syntax error on 25.2R1-S1.4 (**verified**,
  [lab evidence][srx4100]), so the installer warns. Whether a vSRX allows it is **unknown**. C8 is then
  recorded "not available".

The play refuses `jwicket_listen_address` with `tunnel`, and stops a `tls` host whose `ansible_host`
is a name and that has no `jwicket_listen_address`, before anything runs.

## The state directory (R-STATEDIR)

J-Wicket keeps its settings, certificate and logs in `/var/db/jwicket`. On a lab SRX4100 running
25.2R1-S1.4, a super-user-class account could not create it: `mkdir` and the CLI's
`file make-directory` were both refused (`Permission denied`), and root created it and gave it to the
account (**verified**, [lab evidence][srx4100]). So the installer never creates it, never logs in as
root and never asks for the root password. Until the directory exists, owned by the account with mode
0700, the dry run reports R-STATEDIR with the one-time step, the host stops with exit 1, and nothing is
written. The step, in a shell on the lab device as root (how you become root is your lab's own
procedure, outside Juniper support):

```
mkdir -m 700 /var/db/jwicket && chown <jwicket_user> /var/db/jwicket
```

Then run the playbook again. The uninstaller leaves the directory; root removes it once it is empty
(`jwicket-install`'s output says how).

## Lab hardware

`jwicket-install` refuses any model but a vSRX (R-MODEL). With `jwicket_lab_hardware=true` for a host,
the plays pass `--lab-hardware`, and after the host-name gate a second pause asks you to type
`lab only`, stating that the device carries only lab traffic. The production signs (central-manager
outbound-SSH clients, the flow-session count, the committers and the last commit's time, model,
release and serial) are in the plan and the summary shown before both prompts. `jwicket-install`
compares your host name first and `lab only` only on a match (exactly, case-sensitive; anything else
exits 3), records the attestation in the receipt, and still applies R-MANAGED (`--ack-managed` in
`jwicket_overrides`) and the cluster, MNHA and dual-RE refusals. On a vSRX the second answer is not
used. The reference case is the lab SRX4100 run with Security Director Cloud over `outbound-ssh`
([lab evidence][srx4100]); the hardware procedure of governance decision D12 is not written, so the
lab owner decides.

The attestation is typed, never pre-supplied: the first task refuses `jwicket_lab_typed` from
outside, and `jwicket_overrides` cannot carry `--lab-hardware`.

## NETCONF off: the bootstrap

`jwicket-install` talks NETCONF over the SSH port. When NETCONF is off, the first dry run cannot
connect: the host fails, and its output holds the bootstrap paste units with a fresh nonce
(spec 7.7). Paste units A to D on that device from an SSH or console session. Unit C is
`commit confirmed 10 comment "jwicket-bootstrap netconf <nonce>"`: do not confirm it. Within its ten
minutes, run the playbook again for that host only:

```sh
ansible-playbook -i inventory.ini install.yml --limit lab-a \
  -e jwicket_release=v0.1.0.dev1 -e jwicket_apply=true -e jwicket_bootstrap_nonce=<nonce>
```

`jwicket-install` confirms its own bootstrap only after your answer matches; if you stop at the gate,
Junos removes the bootstrap by itself when its ten minutes end. With `ansible.cfg` in effect the units
print as a YAML block, so quotes are not escaped; the block is indented, and whether the Junos CLI
accepts the leading spaces of a pasted line is **unverified** (Q-INST-05). To see the units without
indentation, run the dry run directly: `jwicket-install install --release <tag> --host <device> --user <user>`.

## Upgrade, uninstall, status

```sh
ansible-playbook -i inventory.ini upgrade.yml -e jwicket_release=<new tag>                       # dry run
ansible-playbook -i inventory.ini upgrade.yml -e jwicket_release=<new tag> -e jwicket_apply=true
ansible-playbook -i inventory.ini uninstall.yml                                                  # dry run
ansible-playbook -i inventory.ini uninstall.yml -e jwicket_apply=true
ansible-playbook -i inventory.ini status.yml
```

- `upgrade.yml` is `install --apply --release <new tag>` (spec 9.4) and stops a host whose plan is not
  an upgrade, so a wrong inventory line cannot become a first install. Use `install.yml` to repair a
  half-finished install.
- `uninstall.yml` removes only what Junos's commit history and this workstation's record show
  `jwicket-install` added, after fetching the evidence (spec 9.5). Exit 8 means the configuration is
  gone but a J-Wicket process still runs, so the files were kept: stop it as the output says and run
  `uninstall.yml` again. Uninstall reads the device over NETCONF and takes no bootstrap: a host whose
  NETCONF does not answer fails its dry run and nothing is removed from it. It reads
  `jwicket-install uninstall --json`'s `uninstall` object (stages, files, kept statements, blocked);
  the contract test runs that command against the fake device to keep the two in step.
- `status.yml` only reads.

The exit codes in each failure message are `jwicket-install`'s (spec 9.7): 0 done, 1 refused
(R-STATEDIR among them) or unreadable or NETCONF off, 2 bad input, 3 gate not passed (host name or
`lab only`), 4 device refused a step before its commit, 5 a check failed and the stage was rolled back,
6 unexpected device diff, 7 transfer, integrity or provenance failure, 8 uninstall incomplete.

## What M2 does not do

Use `jwicket-install` directly (M1, [docs/install.md](../../docs/install.md)) for: passwords;
`--accept-new-host-key` (you must compare the fingerprint at a terminal); removing the shared NETCONF
statement at uninstall (it asks for a second typed confirmation); `--device-diff`; the device-pull
transfers (M5); `--rollback-now`; `--keep-partial`; the CLI paste units (M6); creating
`/var/db/jwicket` (root's step, above, for every method).

## Safety notes

- **The gate is an attestation.** Typing the host name, and `lab only` for hardware, confirms intent;
  it does not prove the device is a lab box. `jwicket-install` also refuses anything but a vSRX unless
  `--lab-hardware` and `lab only`, and shows the production signs first.
- **Nothing before the gate writes.** The dry runs never carry `--apply`; the only `--apply` command
  comes after the pauses and their empty-answer checks, and only with `jwicket_apply=true`.
- **No answer, no change.** Without a terminal, `ansible.builtin.pause` warns "Not waiting for response
  to prompt as stdin is not interactive" and returns an empty answer (ansible-core 2.20.0
  `plugins/action/pause.py`, **verified** by reading it and by the behaviour test); the play stops on an
  empty answer, and `jwicket-install` never matches one.
- **Device text is data.** Since ansible-core 2.19, module results are not trusted templates
  (porting guide 2.19, **verified**), so text the executor prints, or a value in its JSON, is shown and
  never evaluated; the behaviour test feeds it Jinja to check. The plan JSON carries validated tokens
  only (INV-12).
- **The typed answers stay out of logs.** The pauses and the apply task use `no_log`; a registered
  result keeps its output but not its arguments (ansible-core 2.20.0 `plugins/strategy/__init__.py`
  deletes `invocation`, **verified** by reading it); `ansible.cfg` and the plays turn off module syslog,
  and pipelining keeps module arguments out of temporary files. No log file is configured; do not set
  `log_path` for these runs.
- **The private key stays off this controller.** With `tls`, `jwicket-install` makes the key in memory,
  copies it to the device and never writes, logs or prints it (spec 8.10); the plays never see it.
- **Timeouts.** Each dry run may take 900 s and the apply step 3600 s. If Ansible's task timeout
  stops the apply step, any commit it left unconfirmed is rolled back by Junos at its deadline
  (`commit confirmed`, spec 13.4; an unconfirmed commit rolled back by itself on the lab SRX4100,
  **verified**); whether the timeout also ends the running `jwicket-install` process is **unknown**
  (not tested).

## Verified, inferred and unknown

| Claim | Status |
| --- | --- |
| `pause` registers `user_input`; with `serial: 1` it prompts once per host (it runs once per batch) | **Verified** (Ansible `pause` documentation; ansible-core 2.20.0 source: `BYPASS_HOST_LOOP = True`) |
| `pause` without a terminal returns an empty answer at once | **Verified** (ansible-core 2.20.0 source; behaviour test with a fake executor) |
| Extra variables override registered and task variables | **Verified** (Ansible variable precedence documentation) |
| Registered module output is never evaluated as a template | **Verified** (porting guide 2.19); tested here with a fake executor |
| `--syntax-check` passes for all four playbooks under ansible-core 2.20.0 | **Verified** here on 2026-11-25 (Python 3.12.3) |
| The typed answers reach the executor's standard input one per line, the host name first | **Verified** with a fake executor (behaviour test); that the real executor reads the second line only for lab hardware is **unverified** against it |
| The executor's flags and its `--json` documents behave as these plays expect | Flags: checked against the real argument parser (contract test). Documents: the install plan against `render.plan_to_json`, the uninstall document against the real CLI on the fake device. Otherwise **unverified**: the behaviour tests use a fake that records arguments |
| `/var/db/jwicket` cannot be made by the account; root's step works; the `tls` listener settings; `commit confirmed` rolls back by itself | **Verified** on a lab SRX4100 by hand ([lab evidence][srx4100]), not through these plays |
| Every device step | **Unverified**: they are M1's, and none has run on a device (Q-INST-06) |

## Checks

```sh
make ansible-check   # --syntax-check of every playbook, then tests/test_ansible_contract.py
```

The contract test (AC-006-31) runs in the unit-test suite too. Its YAML checks skip without PyYAML
and fail instead with `JWICKET_REQUIRE_YAML=1`; its behaviour checks run `ansible-playbook` against a
recording fake `jwicket-install` (no device, no network) only where ansible-core 2.20.0 is found, and
fail instead of skipping with `JWICKET_REQUIRE_ANSIBLE=1`.

## Updating the pins

`requirements-ansible.txt` was generated on 2026-11-24 with Python 3.12.3, pip 26.3 and
pip-tools 7.7.0, from `requirements-ansible.in`:

```sh
python3.12 -m venv /tmp/pip-tools && /tmp/pip-tools/bin/pip install pip-tools==7.7.0
cd deploy/ansible
/tmp/pip-tools/bin/pip-compile --allow-unsafe --generate-hashes --no-emit-index-url --strip-extras requirements-ansible.in
```

Every pin it shares with the installer's `requirements-install.txt` must stay equal (the contract test
checks it, as pip would select that file's pins for CPython 3.12 on Linux x86_64), so bump both
together. The file was resolved for that one environment: `cryptography` 49 and later publish no
Intel macOS wheel (`requirements-install.txt`'s header), so an Intel Mac controller is not covered.

[srx4100]: ../../docs/evidence/2026-11-24-srx4100-lab/README.md
