# jwicket-install container image (M3)

> **LAB ONLY. Pre-release, unsupported, not for production.** This image wraps the workstation
> installer (`jwicket-install`, method M1 in [Spec 006](../../docs/specs/006-installation.md)
> section 6.2) for operators who cannot install Python packages on their workstation. It adds no
> device logic of its own: the installer inside is lab-gated exactly as M1 is (dry run by default,
> the plan's diff and the posture warning first, every write a `commit confirmed` with a health check
> before the confirm, nothing written until you type the lab device's host name, and `lab only` too
> for hardware). J-Wicket has not passed gate G1 or a security review (Q-SEC-01). **No installer step
> has run on a device: every device step is unverified until lab test Q-INST-06.** Nothing in this
> directory has been built or run with Docker yet either: the environment it was written in had no
> Docker daemon. What was checked is listed under [What is verified](#what-is-verified).

Spec 006 section 6.4 is the design. This file is the operator's guide.

## Contents

| File | What it is |
| --- | --- |
| `Dockerfile` | Two stages from `python:3.12-slim` pinned by digest. The build stage checks `build/SHA256SUMS`, installs the hash-pinned dependencies (`--require-hashes`, wheels only; `cryptography`, which makes the `--access tls` certificate, among them) and then the installer wheel by its hash; the final stage copies the virtual environment and runs as uid 10001 |
| `entrypoint.py` | Checks the container's set-up, then becomes the installer (`os.execve`) with your arguments unchanged |
| `.dockerignore` | An allowlist: only `Dockerfile`, `entrypoint.py`, `build/SHA256SUMS`, `build/requirements-install.txt` and `build/jwicket_install-*-py3-none-any.whl` enter the build context |
| `build/` | Not in git. Written by `make container-context` |

## Build

From the repository root:

```sh
# From a published pre-release: downloads the installer wheel and requirements-install.txt for the
# tag, checks SHA-256 and provenance (VERIFY=attestation, signature or record; see the Makefile),
# and copies them with a SHA256SUMS of the two into deploy/container/build/.
make container-context TAG=v0.1.0.dev1 REPO=<owner>/<repo>

# Or from this checkout (what CI's container job does): a wheel built from tools/jwicket_install.
make container-context LOCAL=1

docker build --tag jwicket-install:0.1.0.dev1 deploy/container
```

The context is `deploy/container` only, and `.dockerignore` lets in nothing but the five files
above, so no `jwicket.ini`, lab token, key, receipt or evidence directory from a checkout can reach
an image layer. The build needs network access to PyPI for the dependencies; each is checked against
its hash in `requirements-install.txt`. The image is built locally (and in CI, never pushed);
publishing one is an owner decision (open in Spec 006).

## Run

Once per workstation, create the state directory, owned by you and private:

```sh
install -d -m 0700 "$HOME/.local/state/jwicket-install"
```

Then, every time (a dry run: it only reads the device, and it still needs the `/state` mount):

```sh
docker run --rm -it \
  --user "$(id -u):$(id -g)" \
  --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp \
  -v "$HOME/.local/state/jwicket-install:/state" \
  -v "$HOME/.ssh/known_hosts:/home/app/.ssh/known_hosts:ro" \
  -v "$SSH_AUTH_SOCK:/ssh-agent" -e SSH_AUTH_SOCK=/ssh-agent \
  jwicket-install:0.1.0.dev1 install --release v0.1.0.dev1 --host <device address> --user <account>
```

Add `--apply` to install. With `--host` a DNS name, add `--listen-address <device address>` (see
[Access](#access)). Upgrade, uninstall, status and repair are M1's commands, run the same way
(Spec 006 sections 6.2 and 9); every M1 option reaches the installer unchanged, `--access`,
`--listen-address`, `--daemon-port` and `--lab-hardware` among them. What each part is for:

| Part | Why |
| --- | --- |
| `-it` | The lab gate asks you to type the host name on a terminal, and after `--lab-hardware` `lab only`; without one the installer exits 3 |
| `--user "$(id -u):$(id -g)"` | Runs the installer as you, so it can write the 0700 state directory and use the 0600 agent socket and `known_hosts`. Without it the image's uid 10001 can do neither. The entry point refuses uid 0 |
| `-v ...:/state` | Required for every command but `bootstrap` and `--help`, dry runs included. Keeps the receipt, the journal, the evidence directory (`uninstall` writes it under `/state` unless you give `--evidence-dir`) and the private known-hosts file after `--rm`. The installer is told to use `/state` (`JWICKET_INSTALL_STATE_DIR`) |
| `known_hosts:ro` | The device's SSH host key, from one ordinary `ssh <account>@<device>` on your workstation. Read-only, so the container cannot change your trust store |
| `--cap-drop ALL`, `no-new-privileges`, `--read-only`, `--tmpfs /tmp` | The installer needs no capabilities and writes only to `/state` and temporary files. Not tested here (no Docker daemon); if the installer reports a write error elsewhere, drop `--read-only` and report it |

Never add `--privileged` or a mount of your whole `~/.ssh` (it holds your private keys; the
container needs only `known_hosts` and the agent socket).

### The state directory

The entry point refuses every command that contacts a device or downloads (`install`, `uninstall`,
`status`, `render`, `fetch`, dry runs included), and `--apply`, `--rollback-now`, `--device-diff` and
`--accept-new-host-key` (and any abbreviation of them that the installer's argument parser would
accept) even with `--help`, unless `/state` is a mount that outlives the container. A dry run writes
too: the installer keeps a run directory with the pinned SSH configuration and the downloaded bundle
in its state directory, and the image's own `/state` belongs to uid 10001, not to the `--user` you run
as. Only `bootstrap` (paste units, no state), `--help` and `--version` run without the mount. It reads
`/proc/self/mountinfo` and refuses when `/state` is:

- not a mount point (you forgot `-v`);
- mounted read-only;
- `tmpfs` or `ramfs` (gone when the container stops);
- an anonymous volume (`-v /state` with no host path), which `docker run --rm` deletes;
- not a directory owned by your uid, or writable by group or other users (receipts are one of the
  two records the uninstaller trusts to decide what it added, so nobody else may edit them).

It exits 2 with the reason and the fix. Reading mount
points from `/proc/self/mountinfo` is Linux behaviour; that `docker run -v` shows up there with the
container path as the mount point, and that an anonymous volume's mount root ends in
`/volumes/<64 hex>/_data`, are **inferred**, not tested here.

`--accept-new-host-key` writes the key it is asked to trust to `/state/known_hosts` (the installer's
private known-hosts file), because `~/.ssh/known_hosts` is mounted read-only. Prefer adding the key
on the workstation with one ordinary `ssh` login and comparing its fingerprint with one read on the
lab console or the lab platform's UI.

### The device's state directory (R-STATEDIR)

`/state` is this workstation's. J-Wicket's own directory on the device, `/var/db/jwicket`, is
different: the installing account cannot create it (`mkdir` and `file make-directory` were both
refused with `Permission denied` on a lab SRX4100 running 25.2R1-S1.4, **verified**,
[lab evidence][srx4100]), and the installer never creates it, never logs in as root and never asks for
the root password. Until it exists, owned by the account with mode 0700, the dry run reports
R-STATEDIR, `--apply` exits 1 before any write, and the one-time step is printed. Once, in a shell on
the lab device as root:

```
mkdir -m 700 /var/db/jwicket && chown <account> /var/db/jwicket
```

### Access

The installer decides how J-Wicket is reached (Spec 006 section 7.5); the container changes nothing
about it but where the installer's own connections start.

- **`--access tls` (the default).** J-Wicket listens with TLS on `--listen-address` (it defaults to
  `--host` when that is an IP address) on port 9443 (`--daemon-port`), in the `mgmt_junos` routing
  instance when the device has `system management-instance`. **This opens a new HTTPS listener on the
  management address, reachable by anything that reaches that address.** The installer makes a
  self-signed certificate for that address in memory and copies the key and certificate to the
  device; the key is never written to `/state`, logged or printed (spec 8.10). It prints and records
  only the certificate's SHA-256 fingerprint: browse to `https://<listen address>:<port>/` from the
  workstation and compare it. Its health check C8 is an HTTPS read **from this container** to that
  address and port, pinned to that certificate, so the container needs a route there: Docker's
  default bridge network lets a container open outbound connections (**inferred**, not tested here);
  for a containerlab vSRX see [Reaching the device](#reaching-the-device). The listener settings ran
  on the lab SRX4100 by hand (**verified**, [lab evidence][srx4100]); the installer's certificate and
  copy are **unverified**.
- **`--access tunnel`.** J-Wicket stays on the device's `127.0.0.1`, reached through `ssh -L`. On
  the lab SRX4100 SSH refused the forward (`administratively prohibited`), and
  `set system services ssh tcp-forwarding` is a syntax error on 25.2R1-S1.4 (**verified**,
  [lab evidence][srx4100]); the installer warns, and C8 is recorded "not available".

The entry point refuses `open` (exit 2, with the way that works). `open` forwards nothing; with
`tls` its pinned check (C8) would run from the container's network, not from where your browser is.
With `tls`, browse to the URL the install printed and compare the certificate's fingerprint. With
`tunnel`, run the installer's `ssh -L 127.0.0.1:8443:127.0.0.1:8443 <account>@<device>` line on the
workstation itself (Spec 006 section 6.2, step 4).

### Lab hardware

The installer refuses any model but a vSRX unless you add `--lab-hardware`; it then shows the
production signs (central-manager outbound-SSH clients, the flow-session count, the committers and the
last commit's time, model, release and serial) and, after the host name, asks you to type `lab only`
to state that the device carries only lab traffic. Both answers are typed on the terminal `-it`
gives; neither can come from an option or a variable. R-MANAGED (`--ack-managed`) and the cluster,
MNHA and dual-RE refusals still apply.

### A dedicated SSH agent, with confirmation

A mounted agent socket lets the container ask the agent to sign with **every key the agent holds**,
for as long as the container runs. Do not mount your everyday agent. Start one that holds only the
lab key, and add the key with `ssh-add -c` so that every use asks you first:

```sh
install -d -m 0700 "$HOME/.ssh/jwicket-lab-agent"
eval "$(ssh-agent -s -a "$HOME/.ssh/jwicket-lab-agent/agent.sock" -t 2h)"
ssh-add -c -t 2h ~/.ssh/<lab key>
# ... the docker run commands above, in this shell (SSH_AUTH_SOCK now names the lab agent) ...
ssh-agent -k
```

From the OpenSSH manual pages ([ssh-add(1)][ssh-add], [ssh-agent(1)][ssh-agent], **verified**):
`ssh-add -c` "Indicates that added identities should be subject to confirmation before being used for
authentication. Confirmation is performed by ssh-askpass(1)", so the workstation needs a working
`ssh-askpass` (with `SSH_ASKPASS` set where it is not the default); without one every signature is
refused. `-t life` sets "a maximum lifetime when adding identities to an agent"; `ssh-agent -a`
binds the agent "to the Unix-domain socket bind_address"; `ssh-agent -k` kills the agent named by
`SSH_AGENT_PID`. The installer itself takes an agent, a key, or a password typed at its prompt, and
never a password option or variable (Spec 006 section 8.10).

On macOS with Docker Desktop, how to mount an agent socket into a container is **unknown** (not
researched); so is how Docker Desktop maps the owner of a bind-mounted directory, which the
`/state` owner check depends on. Podman is not researched either. This guide is written for Docker
Engine on Linux.

### Reaching the device

- The container resolves names through Docker's DNS, not your workstation's `/etc/hosts`. Pass a
  name Docker can resolve, or the address, and keep it the same as the name in `known_hosts`.
- With `--access tls`, the installer's C8 read goes from the container to the listen address too;
  if the workstation reaches the device but the container does not, C8 fails and the stage rolls
  back.
- A containerlab vSRX ([../containerlab/README.md](../containerlab/README.md)) sits on the Docker
  network `clab`, which Docker isolates from the default bridge. Add `--network clab` to reach it by
  its container name, for example `--host clab-jwicket-lab-vsrx1` (that Docker's embedded DNS
  resolves container names on a user-defined network is **inferred**, not tested here). That guide
  says why `--access tls` may not be reachable on that lab as it is built.
- `--local-self-test` runs the downloaded bundle inside this container, with the container's
  network. Spec 006 section 8.9 asks for `--network none` in M3, which a process inside the
  container cannot apply to itself; that is open.

## What is verified

| Claim | Status | How |
| --- | --- | --- |
| The base image digest is `python:3.12-slim` (= `3.12.16-slim-trixie`) on 2026-11-24 | **Verified** (registry) | The registry's index body hashed to its `Docker-Content-Digest`; the Docker Hub tags API gave the same digest for the three tags |
| The build stage's script works and refuses tampering | **Verified outside Docker** | The `RUN` script, with paths moved to a scratch directory, ran under dash with CPython 3.12 against a wheel built by `tools/build_wheel.py` and a hash-pinned set of junos-eznc 2.8.3's dependency wheels (x86_64): it installed, and it stopped on a changed wheel, a second wheel, an extra `SHA256SUMS` line and a requirement without a hash |
| Every dependency of junos-eznc 2.8.3 and scp 0.16.2 has a wheel for CPython 3.12 on manylinux x86_64, so `--only-binary=:all:` can work | **Verified** for x86_64 (pip download) | aarch64 not checked |
| The image builds with `docker build` | **Not run here**; CI's `container` job builds it | `tests/test_container_contract.py` checks the Dockerfile's text |
| The entry point's checks, the `open` refusal, and that the access and hardware options pass through unchanged | **Unit-tested** against fake `mountinfo` files and a fake `execve` | `tests/test_container_contract.py` |
| `--user`, the hardening flags, `--network clab`, the agent and `known_hosts` mounts, C8 from the container | **Not tested** (no Docker daemon) | — |
| `/var/db/jwicket` needs root once; the `tls` listener settings; SSH forwarding refused | **Verified** on a lab SRX4100 by hand, not through this image | [lab evidence][srx4100] |
| Anything the installer does on a device | **Unverified** (Q-INST-06) | — |

To move the base image pin, resolve the new digest (for example
`docker buildx imagetools inspect python:3.12-slim`), check it against the Docker Hub tags API, and
change both `FROM` lines together; the contract test requires them to agree.

## Upgrade and removal

- A new installer release: `make container-context TAG=<new tag> REPO=<owner>/<repo>`, then build a
  new tag of the image. Old images: `docker image rm jwicket-install:<old version>`.
- J-Wicket on a device: `install --apply --release <new tag>` and `uninstall --apply` through the
  container, as M1 (Spec 006 sections 9.4 and 9.5). The uninstaller leaves `/var/db/jwicket` for root
  to remove once it is empty (its output says how).
- The state directory `~/.local/state/jwicket-install` is the same one M1 uses on a workstation;
  keep it while any device still has J-Wicket installed.

[ssh-add]: https://man.openbsd.org/ssh-add.1
[ssh-agent]: https://man.openbsd.org/ssh-agent.1
[srx4100]: ../../docs/evidence/2026-11-24-srx4100-lab/README.md
