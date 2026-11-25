# Development tasks. Nothing here talks to a device except lab-install (the lab-gated installer: a dry
# run unless APPLY=1, and even then it asks for the lab device's host name) and lab-up/lab-down (a
# disposable containerlab vSRX). See docs/install.md and docs/deploy-lab.md.
# Override tools per invocation, e.g. `make lint RUFF=.venv/bin/ruff` or `make test PYTHON=python3.7`
# (3.7 is the SRX's Python and the floor of the bundle, the op script and the unit tests).

PYTHON ?= python3
RUFF ?= ruff
MYPY ?= mypy
ACTIONLINT ?= actionlint
ANSIBLE_PLAYBOOK ?= ansible-playbook
CLAB ?= containerlab
BUNDLE ?= dist/jwicket.py
OP_SCRIPT ?= dist/jwicket-install-op.py
WHEEL_DIR ?= build/wheel
# `make reproduce`: release.yml builds on 3.12 and rebuilds on 3.7, 3.9 and 3.13. The first interpreter's
# assets are the reference; name the ones this machine has, e.g. PYTHONS="python3 python3.8".
PYTHONS ?= python3.12 python3.7 python3.9 python3.13
DEV_FIXTURE ?= tests/fixtures/branch
# The workstation installer's virtual environment (Spec 006 section 6.2).
VENV ?= $(HOME)/.local/share/jwicket-install
# lab-install runs the installer from this checkout with the virtual environment's dependencies.
JWICKET_INSTALL ?= PYTHONPATH=tools $(VENV)/bin/python -m jwicket_install
CONTAINER_BUILD ?= deploy/container/build
CLAB_TOPOLOGY ?= deploy/containerlab/jwicket-lab.clab.yml
ANSIBLE_PLAYBOOKS ?= install.yml upgrade.yml uninstall.yml status.yml
# How release-record and container-context check a published release: attestation (the immutable
# release's, with gh), signature (the owner's SSH signature of SHA256SUMS) or, for container-context
# only, record (docs/releases/<tag>.sha256sums on origin/main).
VERIFY ?= attestation
TAG ?=
REPO ?=
HOST ?=
APPLY ?=
LOCAL ?=
IDENTITY ?=
NAMESPACE ?=
VSRX_IMAGE ?=

.PHONY: test lint typecheck bundle bundle-check dev clean wheel install-tool op-script lab-install lab-install-inputs \
	lab-up lab-down container-context release-check release-record reproduce install-test ansible-check actionlint

test:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v

lint:
	$(RUFF) check src tests tools deploy

typecheck:
	$(MYPY)

# Build the single-file bundle, then self-test it isolated (-I) so nothing is imported from src/.
bundle:
	$(PYTHON) tools/bundle.py --out $(BUNDLE)
	$(PYTHON) -I $(BUNDLE) --bundle-self-test

# Exit 1 if $(BUNDLE) differs from a fresh build of the current tree.
bundle-check:
	$(PYTHON) tools/bundle.py --out $(BUNDLE) --check

# The real server and UI on loopback, fed from a synthetic fixture. Never point this at a network.
dev:
	PYTHONPATH=src $(PYTHON) -m jwicket.devserver --fixture $(DEV_FIXTURE) --bind 127.0.0.1 --port 8080

# --- installation tooling (Spec 006); every device step is unverified until lab test Q-INST-06 ---

# The installer wheel, deterministic (timestamps from the HEAD commit), into $(WHEEL_DIR).
wheel:
	rm -rf $(WHEEL_DIR)
	$(PYTHON) tools/build_wheel.py --out $(WHEEL_DIR)

# The workstation installer in its own virtual environment: dependencies by hash, then the wheel.
install-tool: wheel
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/python -m pip install --require-hashes -r requirements-install.txt
	$(VENV)/bin/python -m pip install --no-deps --force-reinstall $(WHEEL_DIR)/jwicket_install-*.whl
	@echo "installed: $(VENV)/bin/jwicket-install"

# The on-box op-script installer (M4) for TAG, whose per-tag URLs on REPO it embeds.
op-script: bundle
	@test -n '$(TAG)' && test -n '$(REPO)' || { echo "op-script: give TAG=v<version> REPO=<owner>/<repo>" >&2; exit 2; }
	PYTHONPATH=tools $(PYTHON) -m jwicket_install.build_op --bundle $(BUNDLE) --tag '$(TAG)' --repo '$(REPO)' --out $(OP_SCRIPT)

# Developer path (Spec 006 section 6.2): install this checkout's bundle on a LAB device, with the
# local build's SHA-256 as its provenance. A dry run unless APPLY=1; with APPLY=1 the installer still
# shows the plan and the warnings and asks for the device's host name before it writes anything.
# USER must be given on the command line: the environment's USER is this workstation's login.
# Optional (OPX-06): LISTEN=<address> (--listen-address, needed when HOST is a DNS name with the default
# --access tls), ACCESS=tls|tunnel, DAEMON_PORT=<port>, SSH_PORT=<port>, LAB_HARDWARE=1 (--lab-hardware),
# and INSTALL_ARGS='<more installer options>' (for example '--ack-managed'), appended last. INSTALL_ARGS
# may not hold --apply: APPLY=1 is the only switch that writes. The installer checks every option itself.
lab-install: lab-install-inputs bundle
	sha=$$(sha256sum $(BUNDLE) | cut -d ' ' -f 1) && \
	$(JWICKET_INSTALL) install $(if $(filter 1,$(APPLY)),--apply) --bundle $(BUNDLE) \
		--expect-sha256 "$$sha" --expect-source local-build --host '$(HOST)' --user '$(USER)' \
		$(if $(LISTEN),--listen-address '$(LISTEN)') $(if $(ACCESS),--access '$(ACCESS)') \
		$(if $(DAEMON_PORT),--daemon-port '$(DAEMON_PORT)') $(if $(SSH_PORT),--port '$(SSH_PORT)') \
		$(if $(filter 1,$(LAB_HARDWARE)),--lab-hardware) $(INSTALL_ARGS)

lab-install-inputs:
	@test -n '$(HOST)' || { echo "lab-install: give HOST=<lab device> USER=<device account>" >&2; exit 2; }
	@test "$(origin USER)" = "command line" || { echo "lab-install: give USER=<device account> on the command line" >&2; exit 2; }
	@test -z '$(filter --apply --apply=%,$(INSTALL_ARGS))' || { echo "lab-install: use APPLY=1, not --apply in INSTALL_ARGS" >&2; exit 2; }
	@test -x $(VENV)/bin/python || { echo "lab-install: run 'make install-tool' first" >&2; exit 2; }

# A disposable containerlab vSRX (M8). VSRX_IMAGE is the vrnetlab image you built, e.g.
# vrnetlab/juniper_vsrx:24.4R2-S3.5; the topology reads it as JWICKET_VSRX_IMAGE.
lab-up:
	@test -n '$(VSRX_IMAGE)' || { echo "lab-up: give VSRX_IMAGE=vrnetlab/juniper_vsrx:<version> (deploy/containerlab/README.md)" >&2; exit 2; }
	JWICKET_VSRX_IMAGE='$(VSRX_IMAGE)' $(CLAB) deploy -t $(CLAB_TOPOLOGY)

lab-down:
	$(CLAB) destroy -t $(CLAB_TOPOLOGY)

# The container image's build context (M3) in $(CONTAINER_BUILD): the installer wheel, the
# hash-pinned requirements and their SHA256SUMS. From a published pre-release (TAG, REPO, VERIFY),
# or with LOCAL=1 from this checkout (what CI builds).
container-context:
	rm -rf $(CONTAINER_BUILD)
ifeq ($(LOCAL),1)
	$(PYTHON) tools/build_wheel.py --out $(CONTAINER_BUILD)
	cp requirements-install.txt $(CONTAINER_BUILD)/requirements-install.txt
	cd $(CONTAINER_BUILD) && sha256sum jwicket_install-*.whl requirements-install.txt > SHA256SUMS
else
	@test -n '$(TAG)' && test -n '$(REPO)' || { echo "container-context: give TAG= and REPO=, or LOCAL=1" >&2; exit 2; }
	$(PYTHON) tools/release_record.py fetch --tag '$(TAG)' --repo '$(REPO)' --verify '$(VERIFY)' \
		--out-dir $(CONTAINER_BUILD) $(if $(IDENTITY),--identity '$(IDENTITY)') $(if $(NAMESPACE),--namespace '$(NAMESPACE)')
endif

# The release workflow's verify checks, before the owner pushes TAG (needs JWICKET_IMMUTABLE_RELEASES=true).
release-check:
	@test -n '$(TAG)' || { echo "release-check: give TAG=v<version>" >&2; exit 2; }
	$(PYTHON) tools/release_check.py --tag '$(TAG)' --sha "$$(git rev-parse HEAD)"

# The release's reproducibility rule on this machine (as CI's reproduce job): the four assets of HEAD,
# built with each of PYTHONS, must be byte-identical. Each run builds into a new build/reproduce.XXXXXX
# directory (build/ is ignored by git) and deletes nothing; it talks to no device and no network.
reproduce:
	@mkdir -p build && dir=$$(mktemp -d build/reproduce.XXXXXX) && \
	sha=$$(git rev-parse HEAD) && epoch=$$(git log -1 --format=%ct HEAD) && \
	version=$$(PYTHONPATH=src $(firstword $(PYTHONS)) -c 'import jwicket; print(jwicket.__version__)') && \
	first= && for python in $(PYTHONS); do \
		out="$$dir/$$python" && mkdir "$$out" && \
		"$$python" tools/bundle.py --out "$$out/jwicket.py" --source-ref "$$sha" >/dev/null && \
		PYTHONPATH=tools "$$python" -m jwicket_install.build_op --bundle "$$out/jwicket.py" --tag "v$$version" \
			--repo '$(or $(REPO),example-owner/jwicket)' --out "$$out/jwicket-install-op.py" >/dev/null && \
		"$$python" tools/build_wheel.py --out "$$out" --source-date-epoch "$$epoch" >/dev/null && \
		cp requirements-install.txt "$$out/requirements-install.txt" && \
		(cd "$$out" && sha256sum jwicket.py jwicket-install-op.py jwicket_install-*.whl requirements-install.txt \
			> SHA256SUMS) || exit 1; \
		if [ -z "$$first" ]; then first="$$out/SHA256SUMS"; \
		elif ! cmp -s "$$first" "$$out/SHA256SUMS"; then \
			echo "reproduce: $$python differs from $(firstword $(PYTHONS)) ($$dir)" >&2; \
			diff "$$first" "$$out/SHA256SUMS" >&2; exit 1; \
		fi; \
		echo "reproduce: $$python ok"; \
	done && cat "$$first" && echo "reproduce: all equal ($$dir)"

# After publication: verify TAG's assets and write docs/releases/<tag>.sha256sums for a reviewed PR.
release-record:
	@test -n '$(TAG)' && test -n '$(REPO)' || { echo "release-record: give TAG= and REPO=<owner>/<repo>" >&2; exit 2; }
	$(PYTHON) tools/release_record.py record --tag '$(TAG)' --repo '$(REPO)' --verify '$(VERIFY)' \
		$(if $(IDENTITY),--identity '$(IDENTITY)') $(if $(NAMESPACE),--namespace '$(NAMESPACE)')

# The unit tests as CI's install-test job runs them: the YAML contract tests fail instead of skipping.
install-test:
	JWICKET_REQUIRE_YAML=1 PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v

# ansible-playbook --syntax-check for every playbook (contacts no device), then the contract test.
# ANSIBLE_PLAYBOOK must be on PATH or an absolute path (the check runs in deploy/ansible).
ansible-check:
	cd deploy/ansible && for playbook in $(ANSIBLE_PLAYBOOKS); do \
		$(ANSIBLE_PLAYBOOK) --syntax-check -i inventory.example.ini "$$playbook" || exit 1; done
	JWICKET_REQUIRE_YAML=1 JWICKET_REQUIRE_ANSIBLE=1 JWICKET_ANSIBLE_PLAYBOOK="$(ANSIBLE_PLAYBOOK)" \
		PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -p test_ansible_contract.py -v

actionlint:
	$(ACTIONLINT) .github/workflows/ci.yml .github/workflows/release.yml

clean:
	rm -rf dist build $(CONTAINER_BUILD) .mypy_cache .ruff_cache
	find src tests tools -name __pycache__ -type d -prune -exec rm -rf {} +
