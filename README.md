# J-Wicket

J-Wicket is a spec-driven project to replace J-Web for customers who want to manage an SRX on the
firewall itself. The target is a Junos-managed Python application with a modern, offline-capable
browser UI. Success means an authorized operator can complete the same tasks as on the reference
J-Web release, with better tools for reviewing scope, explaining policy decisions and recovering
from changes.

**Stage: foundation, not installable on a production SRX.** The supplied spike demonstrated a
Junos-supervised Python UI and local device reads on one vSRX. It did not qualify a customer
platform, a secure multi-user listener, or configuration writes. The prototype is not an installer,
and this project does not ask you to enable a listener, disable J-Web or change a firewall.

## Start here

| For this decision | Read |
| --- | --- |
| What are we building, for whom, and what did the lab actually prove? | [Product charter and spike evidence](docs/charter.md) |
| What counts as J-Web parity? | [Release-scoped parity ledger](docs/parity/README.md): the method, with its [summary](docs/parity/jweb-24.4.md) and [data](docs/parity/jweb-24.4.csv) |
| Which workflows must the design support? | [Wizard and operations catalog](docs/catalog.md) |
| How do tenants, groups, HA, Junos AAA and SDC fit? | [Architecture and trust boundaries](docs/architecture.md) |
| What can I see live, and how are logs shown? | [Spec 004: live sessions and logs](docs/specs/004-live-sessions-and-logs.md) |
| What makes a config change safe to apply or undo? | [Spec 002: shared change protocol](docs/specs/002-change-protocol.md) |
| Who decides, and what ships next? | [Governance and qualification roadmap](docs/governance.md) |
| How do I propose or extend a feature? | [Contributor guide](CONTRIBUTING.md) and [spec template](docs/specs/000-template.md) |
| How do I report a vulnerability, and what is the threat model? | [Security policy and threat summary](SECURITY.md) |

The first vertical slice is a scoped, read-only policy inventory
([Spec 001](docs/specs/001-policy-inventory.md)). Expanding the parity inventory and proving
least-privilege, TLS-protected on-box reads come before any live write path. The first planned
configuration wizard is a preview-only Firewall Policy Builder
([Spec 003](docs/specs/003-firewall-policy-builder.md)), with brownfield, group ownership and
recovery cases specified up front.

The owner has since added three binding requirements, all read-only
([Spec 004](docs/specs/004-live-sessions-and-logs.md)): the UI must be as good to look at as it is to
use; log viewing with syntax highlighting is a must; and `show security flow session` output must be
visible, with powerful inline, live filtering.

## What is in the repository today

| Path | What it is | State |
| --- | --- | --- |
| `src/jwicket/` | The daemon: bounded HTTP(S) server, Junos-delegated sign-in, read-only policy inventory, live sessions and logs, browser UI | Implements Spec 001 and the Spec 004 backend against fixtures; **not yet run on a device** |
| `tools/bundle.py` | Builds `dist/jwicket.py`, the single file Junos would run | Built and self-tested in CI |
| `tests/` | Unit and HTTP integration tests; synthetic fixtures (`tests/fixtures/README.md`) | Runs in CI on Python 3.9, 3.11, 3.13 |
| `docs/` | Charter, parity ledger, catalog, architecture, specs, ADRs, governance | Living documents |
| `docs/evidence/` | The spike packet, unedited | Evidence, not product |

## Try it without a firewall

The development server runs the real server and UI against synthetic fixture data, on loopback
only, with a "fixture data" banner on every page:

```
make dev            # or: PYTHONPATH=src python3 -m jwicket.devserver --fixture tests/fixtures/branch
```

Open `http://127.0.0.1:8080/` and sign in as `admin` (any non-empty password; fixture mode only).
Sign in as `auditor` to see how a login class that cannot read the configuration is shown.

```
make test           # unit and integration tests
make lint typecheck # ruff and mypy, pinned in requirements-dev.txt
make bundle         # dist/jwicket.py
```

Putting the bundle on a disposable lab vSRX for qualification is described in
[docs/deploy-lab.md](docs/deploy-lab.md). That procedure is for qualification tests on lab
equipment only.
