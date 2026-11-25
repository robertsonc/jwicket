# Contributing to J-Wicket

J-Wicket is at the **foundation stage**: it is not installable on a production SRX, and nothing in
this repository has run on a customer platform. Contributions arrive as pull requests. A feature
starts as a spec, not as code. Nothing in the daemon may change a device before gate G4; the lab
installers are lab-procedure tooling, not part of it ([below](#what-is-welcome-now)).

Read these first: the [README](README.md), the [charter](docs/charter.md) (what is proven and what
is not), [governance](docs/governance.md) (who decides, the gates, the qualification tests) and
[architecture](docs/architecture.md) (trust boundaries).

On this page:

- [What is welcome now](#what-is-welcome-now)
- [Propose a feature](#propose-a-feature)
- [Set up and run](#set-up-and-run)
- [Release a lab pre-release](#release-a-lab-pre-release)
- [Coding rules](#coding-rules)
- [Security rules](#security-rules)
- [Add a qualification result](#add-a-qualification-result)
- [Commits and pull requests](#commits-and-pull-requests)
- [Documentation rules](#documentation-rules)

## What is welcome now

| Welcome | Not accepted at this stage |
| --- | --- |
| Specs for read-only parity rows, with ledger rows and sources | Any code path that changes device configuration or state before G4 ([governance](docs/governance.md#3-gates-g0-to-g5)) |
| Code and tests for accepted specs | Third-party Python or JavaScript packages, C extensions, CDNs, web fonts, any external URL at runtime |
| Recorded replies and qualification evidence from **lab** equipment | Anything run against a production firewall, or instructions asking someone to enable a listener, disable J-Web or change a production firewall |
| Fixes for the [known code gaps](docs/architecture.md#15-known-gaps-in-the-current-code) | J-Wicket's own users, roles or password store ([ADR 0002](docs/adr/0002-junos-delegated-sign-in.md)) |
| Corrections to any claim about Junos or J-Web, with a source | "Sample" or placeholder data in a panel ([ADR 0004](docs/adr/0004-no-sample-data.md)) |
| Parity ledger corrections | Device data cached in the browser ([ADR 0007](docs/adr/0007-offline-capable-meaning.md)); managing more than one device |

The lab installers are not a product write path. They are lab-procedure tooling that the owner
asked for on 2026-11-24 ([ADR 0011](docs/adr/0011-owner-decisions-lab-gated-install.md)): they live
in [`tools/jwicket_install/`](tools/jwicket_install/) and [`deploy/`](deploy/), never ship in the
bundle, and change only the statements and files [Spec 006](docs/specs/006-installation.md) lists,
under its invariants (section 5.1). The daemon stays read-only and keeps the standard library plus
PyEZ; the installer's own dependencies (PyEZ, `paramiko`, `scp`, and `cryptography` for the TLS
certificate) run on the workstation only, pinned by hash in
[`requirements-install.txt`](requirements-install.txt). Everything the on-box op script embeds
(`plan.py`, `state.py`, `render.py`, `op_template.py`) runs on the SRX's Python 3.7, and every module
under `tools/jwicket_install/` imports there; the unit tests check that. A change to the installers
follows Spec 006: no Junos statement, path, mode or warning text outside `plan.py`, a test for every
behaviour, and the security reviewer for anything that touches an invariant.

Found a vulnerability? Do not open an issue or a pull request. Follow [SECURITY.md](SECURITY.md).

## Propose a feature

Spec first, then code. The decision rights are in
[governance, section 1](docs/governance.md#1-decision-rights).

1. **Find the ledger row.** Every J-Web 24.4 page or operation should have a row in
   [`docs/parity/jweb-24.4.csv`](docs/parity/jweb-24.4.csv), as the
   [ledger method](docs/parity/README.md) describes. If your feature covers a page with no row, add
   the row in the same pull request, with the menu path and the J-Web 24.4 guide URL. If the
   feature has no J-Web equivalent (a J-Wicket workflow such as the
   [catalog's](docs/catalog.md) N1 to N5), say so in the spec. Priorities and `out-of-scope` or
   `replace` decisions are the owner's: propose them, with a reason, and the row stays "owner
   approval pending" until the owner approves.
2. **Write the spec.** Copy [`docs/specs/000-template.md`](docs/specs/000-template.md) to
   `docs/specs/NNN-short-name.md` with the next free number. Fill every section that applies; the
   template says what each needs. Label every claim about Junos verified (with a source),
   inferred or unknown (with the Q-test that settles it).
3. **Write an ADR for a decision.** Open a new ADR in [`docs/adr/`](docs/adr/README.md),
   `Status: Proposed`, when the change:
   - reverses or narrows a decision in an accepted ADR (write a superseding ADR; accepted ADRs are
     not edited);
   - adds a runtime dependency, or changes the deployment unit;
   - changes a trust boundary, the sign-in model, or a default or rule that protects the listener;
   - adds a family of RPCs, or anything that writes;
   - changes the parity reference release.
4. **Open the pull request** with the spec at Status "Draft", its ledger rows moved to
   `specified` (a spec now covers them), and any ADR. The owner accepts the spec; the security
   reviewer also reviews any spec that touches sign-in, transport, the RPC allowlist, secrets or
   writes. On acceptance the spec's Status becomes "Accepted", and code may start. The review
   checklist is in [governance, section 2.2](docs/governance.md#22-spec-reviews).
5. **Then build.** Code pull requests name the spec sections and the acceptance criteria
   (`AC-NNN-xx`) they implement, and update each criterion's status in the spec. A ledger row
   becomes `implemented` when its spec's acceptance tests pass on fixtures, including the browser
   check for an operation done in the browser ([ledger method, section 5](docs/parity/README.md#5-statuses)),
   and `qualified` only on a qualified platform
   ([governance, section 3.2](docs/governance.md#32-what-qualified-platform-means)).

## Set up and run

You need Python 3.7 or later (CI tests 3.7, 3.9, 3.11 and 3.13; 3.7 is the floor because Junos
25.2 ships Python 3.7.10 on the SRX, Q-RT-01) and Node 22 for the browser-module tests. Nothing here talks to a
device.

```
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt   # ruff and mypy, pinned exactly

make test                                      # unit and HTTP integration tests (unittest)
make lint RUFF=.venv/bin/ruff                  # ruff check src tests tools deploy
make typecheck MYPY=.venv/bin/mypy             # mypy --strict, Python 3.8 target (oldest mypy accepts)
node --test tests/js/*.test.mjs                # query language and log parser (no packages)
make bundle                                    # build dist/jwicket.py, then self-test it isolated
make bundle-check                              # fail if dist/jwicket.py differs from a fresh build
make test PYTHON=python3.7                     # the floor interpreter, if you have it
```

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs the same checks on every pull
request: ruff and mypy; the tests and an isolated bundle self-test on Python 3.7, 3.9, 3.11 and 3.13;
the Node tests; and a bundle job that builds twice, fails if the builds differ, and publishes the
bundle with its SHA-256. The JS tests have no Makefile target; run the `node` command above.

### Installer, Ansible, container and workflow checks

`make test` already runs the installer's tests against fakes, without PyEZ, `paramiko` or `scp`
(the tests that need them skip). The other CI jobs, locally, each in its own virtual environment
outside the checkout (none of these contacts a device; CI uses Python 3.12):

```
# the installer and its hash-pinned dependencies in ~/.local/share/jwicket-install
make install-tool

# install-autospec: fakes built from the real PyEZ, paramiko and scp signatures
JWICKET_REQUIRE_PYEZ=1 PYTHONPATH=src ~/.local/share/jwicket-install/bin/python -m unittest discover -s tests

# install-test: the YAML contract tests (workflows, Ansible, containerlab) fail instead of skipping
make install-test PYTHON=<a Python with PyYAML>

# ansible: --syntax-check of every playbook, then the Ansible contract test
python3.12 -m venv ~/.local/share/jwicket-ansible
~/.local/share/jwicket-ansible/bin/pip install --require-hashes -r deploy/ansible/requirements-ansible.txt
make ansible-check ANSIBLE_PLAYBOOK="$HOME/.local/share/jwicket-ansible/bin/ansible-playbook" \
  PYTHON="$HOME/.local/share/jwicket-ansible/bin/python"

# actionlint: the version and SHA-256 the CI job pins (ci.yml, job actionlint)
make actionlint ACTIONLINT=<path to actionlint 1.7.12>

# container: the build context from this checkout, then a local image (never pushed)
make container-context LOCAL=1 && docker build --tag jwicket-install:dev deploy/container

# reproduce: the four release assets of HEAD, built with each interpreter, must be byte-identical
make reproduce PYTHONS="python3.12 python3.7 python3.9 python3.13"

# this checkout's bundle on a lab device you may change: a dry run unless APPLY=1
make lab-install HOST=<lab device> USER=<device account>
# with more installer options: LISTEN=, ACCESS=, DAEMON_PORT=, SSH_PORT=, LAB_HARDWARE=1, INSTALL_ARGS=
make lab-install HOST=<lab device> USER=<device account> LISTEN=<listen address> INSTALL_ARGS='--ack-managed'
```

CI runs the autospec, YAML, Ansible and actionlint checks as the `install-autospec`,
`install-test`, `ansible` and `actionlint` jobs, builds the image in the `container` job, and runs
`make reproduce`'s comparison as the `reproduce` job (name the interpreters you have in `PYTHONS`).
`make lab-install` is the only target here that contacts a device; it is a dry run unless
`APPLY=1`, and even then it writes nothing until you type the lab device's host name
([docs/install.md](docs/install.md)).

### The development server

```
make dev                                        # tests/fixtures/branch on http://127.0.0.1:8080/
make dev DEV_FIXTURE=tests/fixtures/cluster-lsys
```

It runs the real server and UI against a synthetic fixture
([`src/jwicket/devserver.py`](src/jwicket/devserver.py)). It binds to loopback only and refuses
anything else, and every page carries a "fixture data" banner. Fixture users sign in with any
non-empty password: `admin` and `auditor` in `branch` (the auditor's class is denied the
configuration read, to show how a denied read looks), `admin` and `lsys-a-admin` in
`cluster-lsys`. It is a demonstration harness, not an authentication test. Never point it at a
network.

## Release a lab pre-release

Pre-releases are lab-only and unsupported (owner decision,
[ADR 0011](docs/adr/0011-owner-decisions-lab-gated-install.md)); the process is
[Spec 006, section 11](docs/specs/006-installation.md#11-release-workflow). None has been published:
the first, `v0.1.0.dev1`, waits for the owner's go.

1. **Bump the three versions together** in one reviewed pull request to `main`:
   `src/jwicket/__init__.py`, `pyproject.toml` and `tools/jwicket_install/__init__.py`, in PEP 440
   form `X.Y.Z.devN` ([`tests/test_version.py`](tests/test_version.py) requires them equal).
2. **Before the tag**, the owner checks that the repository settings of Spec 006 section 11.2 are on
   (immutable releases; a tag ruleset letting only the owner create `v*` tags; branch protection with
   review on `main`; environment `lab-prerelease`; variable `JWICKET_IMMUTABLE_RELEASES=true`;
   governance D14), and runs the workflow's `verify` checks on the merged commit:
   `JWICKET_IMMUTABLE_RELEASES=true make release-check TAG=vX.Y.Z.devN`.
3. **The owner tags** that commit on `main` as `vX.Y.Z.devN` (exactly `v` plus the version) and
   pushes the tag. Nobody else creates a `v*` tag.
4. **What [`release.yml`](.github/workflows/release.yml) does:** `verify` (tag pattern, the three
   versions, the commit on `main`, the immutable-releases variable); `test` on Python 3.7 (the SRX's,
   on ubuntu-22.04), 3.9 and 3.13; `build` on 3.12 (`dist/jwicket.py` twice and compared, the
   isolated self-test, the op script, the installer wheel, `requirements-install.txt`, `SHA256SUMS`
   and the release notes); `rebuild` on 3.7, 3.9 and 3.13, which must give the same `SHA256SUMS`; `attest`; and `publish`, which creates a draft
   pre-release in the `lab-prerelease` environment, publishes it, runs `gh release verify` and
   `verify-asset`, and deletes the release (the tag stays) if that fails. A `workflow_dispatch` run
   is a dry run and never publishes.
5. **The release record.** After publication, run
   `make release-record TAG=vX.Y.Z.devN REPO=<owner>/<repo>`: it downloads the assets, verifies
   them, and writes `docs/releases/<tag>.sha256sums`, byte-identical to `SHA256SUMS`. Open a pull
   request with it; once the owner's review merges it to `main`, it is the provenance source the
   installers and the op script's operators read (P-C). In a private repository without attestations
   the release stays a draft until the owner signs `SHA256SUMS` (`VERIFY=signature`;
   [docs/releases/README.md](docs/releases/README.md)).
6. **Reproduce a release** from the tagged commit with the commands in its release notes (P-D):

   ```
   git checkout <commit>
   python3 tools/bundle.py --out dist/jwicket.py --source-ref <commit>
   PYTHONPATH=tools python3 -m jwicket_install.build_op --bundle dist/jwicket.py --tag <tag> --repo <owner>/<repo> --out dist/jwicket-install-op.py
   python3 tools/build_wheel.py --out dist --source-date-epoch "$(git log -1 --format=%ct <commit>)"
   cp requirements-install.txt dist/
   cd dist && sha256sum jwicket.py jwicket-install-op.py jwicket_install-<version>-py3-none-any.whl requirements-install.txt
   ```

   The four values must equal the release's `SHA256SUMS`.

## Coding rules

These come from the ADRs and from the code as it stands. A pull request that breaks one needs an
ADR first.

### Python

- **Python 3.7 syntax and library** ([ADR 0001](docs/adr/0001-on-box-pure-python-single-file.md)):
  modules with code start with `from __future__ import annotations`; no `match`; no `X | Y` unions
  evaluated at runtime; no `dataclass(slots=..., kw_only=...)`; typing spelled `List`, `Dict`,
  `Optional` (ruff's `UP006`, `UP007` and `UP035` are off for this reason,
  [`pyproject.toml`](pyproject.toml)). Also none of what 3.8 and 3.9 added: no walrus operator
  (`:=`), no positional-only parameters, no f-string `=`; `typing.Protocol`, `Literal`, `TypedDict`
  and `Final` only under `TYPE_CHECKING`; no `Path.readlink`, `str.removeprefix`,
  `functools.cached_property`, `shlex.join` or `ast.parse(feature_version=)` without a guard.
  mypy cannot target 3.7 and checks as 3.8, so CI's Python 3.7 job is the check.
- **Routing instances.** Code that opens a socket must not assume the default instance. Only the
  listener follows `[server] routing_instance`; `jcs.set_routing_instance()` is process-wide, so
  anything that switches it must switch back (`app.routing_instance()`).
- **Standard library plus the PyEZ Junos ships** (`jnpr.junos`, with the `lxml` and `ncclient` it
  brings), nothing else. `pyproject.toml` has `dependencies = []` and must keep it. No C
  extensions. When you import a standard-library module the shipped code does not already use,
  add it to `PROBE_MODULES` in [`app.py`](src/jwicket/app.py), so Q-RT-01 records whether the
  device has it.
- **Typed and strict.** `mypy --strict` passes; ruff's selected rules pass (security `S`, bugbear,
  blind-except and others). Every network call has a timeout. No bare `except`. Errors say what
  failed and why. Use `logging`, never `print`, outside the CLI entry points.
- **No arguments under Junos.** The daemon reads `/var/db/jwicket/jwicket.ini` and nothing else
  (spike finding F1, [charter section 5](docs/charter.md#5-spike-evidence)). Every new setting has a
  default, a range, a validation rule that fails closed, a test, and an entry in the example
  settings file in [`docs/deploy-lab.md`](docs/deploy-lab.md).
- **The bundle ships everything in `src/jwicket` except** `devserver.py`, `fixtures.py` and
  `__main__.py` (`EXCLUDED_MODULES` in [`tools/bundle.py`](tools/bundle.py)). Shipped code must
  never import those. Static assets are served only if their path matches the pattern in
  [`resources.py`](src/jwicket/resources.py): lowercase names, `.html`, `.js`, `.css` or `.svg`.
  `dist/` is generated and ignored by git; never commit it.

### Device access and the RPC allowlist

- Only [`junos/session.py`](src/jwicket/junos/session.py) sends anything to Junos.
- RPCs come only from `ALLOWED_RPCS`, and every name is checked against it before it is sent. An
  RPC name is a constant, or comes from a fixed module-level list selected by a parameter that was
  checked against that list (today only the report reads, `REPORT_TYPES`); never text from a
  request. Configuration reads go through a separate method with fixed filter constants, from the
  committed database with inheritance and group annotations
  ([ADR 0005](docs/adr/0005-committed-config-with-provenance.md)). No attribute, filter or
  configuration text is ever built from request input.
- Read the narrowest subtree the feature needs: the children you parse, not their parent. Never
  `system login`, all of `[edit security]` (IKE pre-shared keys), a whole logical system, or other
  secret-bearing hierarchies.
- Parsers match local names (namespaces ignored), tolerate what they do not know, and report it
  (`unmodeled` on the object, and a warning). Nothing is dropped silently. Configuration comments
  are not settings. A deactivated statement is never treated as in effect. A denied read is
  `denied`, never empty; a reply in an unexpected shape is `failed`, never an HTTP 500.
- **Adding an RPC to `ALLOWED_RPCS` is a reviewed change.** The pull request must:
  1. name the spec section that needs it, and update that spec's data-sources table;
  2. include a recorded reply from a lab device (the reply, the request, the release and the
     platform, filed as for [Q-REL-01](#add-a-qualification-result)), and the error the RPC returns
     when denied;
  3. add fixtures and tests for its parser, including the denied and unsupported states;
  4. be reviewed by the security reviewer, and approved by the owner with the spec.

  Only read-only RPCs are allowed before G4. Today `test_allowlist_is_read_only`
  ([`tests/test_session.py`](tests/test_session.py)) enforces that by requiring the `get-` prefix
  and must keep passing. A read-only RPC without the prefix (Spec 003 names
  `match-firewall-policies` and `shadow-firewall-policies`) needs that test changed to an explicit,
  reviewed list in the same pull request. Note: the RPCs on the list today were added before any
  device access, on synthetic fixtures; their reply formats are still pending Q-REL-01.

### Browser

- **No third-party JavaScript.** No frameworks, no npm packages, no CDN. ES modules served from the
  device. Tests use Node's built-in `node:test` only.
- **The browser check** (AC-001-21, AC-004-20, and the UI criterion of any new spec) runs against
  the development server, by hand or driven by an external browser-automation tool such as
  Playwright. Such a tool is development-only: it is installed outside the repository, never
  vendored, never shipped in the bundle, and never a dependency of `make test` or the Node tests.
  No tool or version is pinned in the repository yet, so the pull request's evidence names the tool
  and version used, the fixtures and users, the browser, and whether the console showed errors or
  CSP violations.
- **Strict Content-Security-Policy** ([`web/http.py`](src/jwicket/web/http.py)): no inline script,
  no inline style, no `style` attribute (`setAttribute('style', ...)`); setting CSSOM properties
  (`el.style.x = ...`) is fine. Trusted Types are required, so the UI never parses strings as HTML
  or code: no `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`,
  `new Function`, `DOMParser` or inline event handlers. Build DOM with `createElement` and
  `textContent`. [`tests/test_static.py`](tests/test_static.py) enforces this.
- **No external URLs** in any asset (`test_no_external_urls`).
- **No device data in browser storage.** `localStorage` holds UI preferences and query text the
  operator explicitly saved (Spec 004 UI-004-05), never device replies, every access wrapped in
  `try`/`catch`; `sessionStorage`, IndexedDB, caches and service workers are not used
  ([ADR 0007](docs/adr/0007-offline-capable-meaning.md)). Saved query text can name addresses,
  policies and users; whether that is acceptable is Spec 004 open question 14 (Q-SEC-01).
- **Every panel is device data or an explicit state** (`denied`, `unsupported`, `failed`,
  `session-lost`) with the server's operator-safe message
  ([ADR 0004](docs/adr/0004-no-sample-data.md)). The fixture banner shows whenever
  `meta.fixture` is true.

### Fixtures

- Everything in [`tests/fixtures/`](tests/fixtures/README.md) is **synthetic** unless its directory
  says `recorded-`. Say so in every new fixture: a comment in XML, a `_comment` key in JSON, a
  line in the directory's README.
- Addresses come from RFC 1918 and the documentation ranges (RFC 5737); secrets are obvious
  placeholders. Element names come from the device schema or a recorded reply, with the source
  noted; never invent them.
- Fixture data is never presented as device data. The development server labels it.
- Recorded replies live in `tests/fixtures/recorded-<platform>-<release>/`, for example
  `recorded-vsrx-24.4R2-S3.5/`, with a `SOURCE.md`
  ([below](#add-a-qualification-result)).

### Tests

- Every behaviour change comes with tests. Every acceptance criterion in a spec names the tests that
  prove it (`Class.method` in a linked file).
- Every security property has a test, listed in [SECURITY.md](SECURITY.md). A new control adds a
  row there.
- Test what a device would refuse too: denied reads, unsupported RPCs, malformed replies, lost
  sessions.
- Browser modules with logic (`query.js`, `logparse.js`) have Node tests in [`tests/js/`](tests/js/).
- Before you push: `make test`, `make lint`, `make typecheck`, `node --test tests/js/*.test.mjs`,
  `make bundle`.

## Security rules

- **No credentials in the repository.** No passwords, tokens, keys, certificates or settings
  files. `.gitignore` excludes `*.ini`, `*.pem`, `*.key`, `*.log` and `*.jsonl` for this reason;
  do not force-add them. The spike's lab token is burned; never reuse it.
- **No raw configuration to the browser.** Only modelled fields leave the adapters. Outbound-SSH
  `secret` and `device-id` are never copied out of the parser. Raw XML is never returned.
- **Never log** passwords, tokens, cookies, CSRF values or raw configuration. The audit trail also
  drops any field named like a credential (`password`, `token`, `cookie`, `secret`, `csrf` and
  others, in [`logs.py`](src/jwicket/logs.py)), but that is a safety net, not permission. Keep the
  PyEZ, ncclient and paramiko loggers at WARNING: PyEZ logs whole replies at INFO (spike finding).
- **Validators end in `\Z`, not `$`.** In Python, `$` also matches before a trailing newline, so
  `^[a-z]+$` accepts `"bob\n"`; the independent test suite found exactly that in the username
  check. Anchor every pattern with `^...\Z`, bound its length, and validate before anything
  reaches Junos.
- **Operator messages are fixed text.** Device error text goes to the diagnostic log (INFO, cut to
  500 characters), not to the browser, unless a spec says otherwise and the security reviewer
  agreed. The diagnostic handlers escape control characters in every message; keep it that way for
  any handler you add (`escape_handlers` in [`logs.py`](src/jwicket/logs.py)).
- **The audit trail records people, not guesses.** A failed sign-in is recorded under a keyed hash
  of the submitted name (`user_hash`), never the name, because a password typed into the user-name
  field is the commonest wrong value. Refusals of clients without a session go through
  `record_refusal`, which aggregates them, so nobody can rotate the audit history away with
  unauthenticated requests. Polled reads are recorded when what was read changes, not per poll.
- **The bundle imports nothing from its own directory.** The generated file removes that
  directory from `sys.path` before any other import, using built-in modules only. Keep it that
  way: nothing above the scrub in [`tools/bundle.py`](tools/bundle.py) may import a module that is
  read from disk, and the generated file has no `from __future__` import.
- **The listener fails closed.** Do not add a plaintext switch, a non-loopback default, or a way
  around the settings file-trust rules ([ADR 0003](docs/adr/0003-tls-off-loopback.md),
  [`settings.py`](src/jwicket/settings.py)).
- **No new route without a session check** and a test that the route returns 401 without one.
  Authentication is checked per handler today
  ([architecture, gap 4](docs/architecture.md#15-known-gaps-in-the-current-code)), so the test is
  the only safety net.
- **The security reviewer reviews** pull requests that touch: the RPC allowlist or configuration
  filters ([`junos/session.py`](src/jwicket/junos/session.py)), settings rules
  ([`settings.py`](src/jwicket/settings.py)), headers and cookies ([`web/`](src/jwicket/web/)),
  sign-in and sessions ([`auth/`](src/jwicket/auth/)), audit fields
  ([`logs.py`](src/jwicket/logs.py)), static asset serving
  ([`resources.py`](src/jwicket/resources.py)), the bundler ([`tools/bundle.py`](tools/bundle.py)),
  the installers ([`tools/jwicket_install/`](tools/jwicket_install/), [`deploy/`](deploy/)) or the
  release workflow ([`release.yml`](.github/workflows/release.yml)), or that add a route or a
  parameter.
- **Test only** against the development server, your own disposable lab equipment, or devices you
  are authorized to test. Never a production firewall.

## Add a qualification result

Qualification tests are defined in [governance, section 4](docs/governance.md#4-qualification-test-catalogue)
(and the Q-CHG tests in [Spec 002, section 19](docs/specs/002-change-protocol.md#19-qualification-tests-q-chg-01-to-q-chg-16)).
The rules for what counts are in [governance, section 6](docs/governance.md#6-evidence-rules).

1. **Before you run.** The test's entry must have its method and pass criterion, and any budget it
   needs, written down. Agree the device with the qualification lab owner. Use lab equipment only,
   follow [docs/deploy-lab.md](docs/deploy-lab.md), and make every configuration change with
   `commit confirmed 5`. deploy-lab.md covers a disposable virtual SRX only; a hardware run, or
   anything that binds off loopback (Q-NET-01), waits for the hardware variant the lab owner and
   the security reviewer approve ([governance, D12](docs/governance.md#25-decisions-pending)).
2. **Pin the build.** Record the commit, the bundle's SHA-256 and the `payload_sha256` printed by
   `python3 -I dist/jwicket.py --bundle-self-test`.
3. **Run the method as written.** Write down every deviation.
4. **File the evidence** in a new directory, `docs/evidence/<YYYY-MM-DD>-<platform>-<release>/`,
   next to the spike record. Its `README.md` says:
   - who ran it, and the date and time in UTC;
   - the device: model (and memory, for hardware), exact Junos release, the output of
     `sysctl security.mac.veriexec.state`;
   - the J-Wicket commit and both SHA-256 values;
   - each Q-ID run: the method followed, deviations, the result against the pass criterion
     (passed, failed or partial), and what the run does not prove;
   - what was redacted, and how.

   Keep the raw output beside it: probe and self-test JSON, J-Wicket's log and audit trail, syslog
   extracts, CLI transcripts. Save logs with a `.txt` extension (for example `jwicket-log.txt`,
   `audit-jsonl.txt`): git ignores `*.log` and `*.jsonl` so that local logs are never committed by
   accident. Remove passwords, tokens, keys and secrets before you commit anything.
5. **File recorded replies** under `tests/fixtures/recorded-<platform>-<release>/`, in the same
   layout as the synthetic fixtures (`config.xml`, `<rpc-name>.xml`, `errors.json`), with a
   `SOURCE.md` saying who captured them, when, with which request, and what was redacted. Add tests
   that run the parsers against them (for Spec 001 and 004, AC-001-22 and AC-004-21).
6. **Update the records** in the same pull request: the test's status line in governance section
   4, the cell in the [qualification matrix](docs/governance.md#5-qualification-matrix), and any
   spec claim the result confirms or contradicts. Do not mark a result certified yourself.
7. **The lab owner certifies** in review, by checking the evidence against the method and the pass
   criterion. Then the status becomes certified.
8. **A failed result is filed the same way.** If it contradicts an ADR's assumptions, open a
   superseding ADR proposal; if it contradicts a spec's verified or inferred label, correct the
   spec. Evidence directories are not edited after they merge; add a dated note instead.
9. **Ledger rows** move to `qualified` only under the qualified-platform rule
   ([governance, section 3.2](docs/governance.md#32-what-qualified-platform-means)), naming the
   cell.

## Commits and pull requests

### Commits

- One logical change per commit.
- A summary line of at most 72 characters, in plain words, optionally starting with the area
  (`CI: ...`, `Lab procedure: ...`, `Spec 004: ...`). The body says why, what changed in
  behaviour, and what you verified.
- Reference the spec section, acceptance criteria, ADR or Q-ID where one applies
  (`Spec 004 section 5.2`, `AC-004-02`, `Q-LOAD-02`).
- Never commit `dist/`, settings files, keys, logs, or captures that still hold secrets.

### Pull requests

Work on a branch and open the pull request against `main`. CI must pass. The description covers:

- **What and why**, in a few sentences.
- **Spec, ADR and ledger rows** it implements or changes.
- **Acceptance criteria** whose status changes, and to what.
- **Qualification impact:** the Q-tests it touches or that must be re-run, and why.
- **Security notes:** any new route, parameter, RPC, setting, browser API or file the daemon
  writes; anything that changes what leaves the device.
- **Evidence:** the commands you ran and their results. For UI changes, the browser check against
  the development server (fixtures and users) and whether the console showed errors or CSP
  violations.
- **Checklist:** `make test`, `make lint`, `make typecheck`, the Node tests and `make bundle` pass;
  docs updated; no secrets; fixtures labelled.

### Review

- At least one reviewer other than the author.
- The security reviewer for the files and changes listed under
  [Security rules](#security-rules).
- The owner for scope: specs, ADRs, ledger priorities and `out-of-scope` or `replace` rows.
- The lab owner for evidence and for changes to the lab procedure.

Until the security reviewer and the lab owner are named
([governance, section 2.5](docs/governance.md#25-decisions-pending)), changes that need them can be
reviewed and merged as documents or code on fixtures, but do not count toward a gate.

## Documentation rules

- Lead with the point. Short sentences, plain words, tables where they help, Mermaid diagrams for
  flows, state machines and trust boundaries.
- Label claims **verified** (with the URL or evidence file), **inferred** or **unknown** (with the
  Q-test). Never invent Junos CLI, RPC names, XML tags, J-Web menu names or behaviour.
- Describe implemented behaviour from the code, and link the file.
- Keep the honesty of the evidence: the spike ran on one vSRX; nothing here has run on a customer
  platform; fixtures are synthetic.
- Do not edit [`docs/evidence/`](docs/evidence/2026-11-23-vsrx-spike/README.md). Correct it with a
  dated note in the [charter](docs/charter.md#notes-on-the-evidence).
- Do not rename the documents the README links to.
