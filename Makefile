# Development tasks. Nothing here talks to a device; see docs/deploy-lab.md for the lab procedure.
# Override tools per invocation, e.g. `make lint RUFF=.venv/bin/ruff` or `make test PYTHON=python3.9`.

PYTHON ?= python3
RUFF ?= ruff
MYPY ?= mypy
BUNDLE ?= dist/jwicket.py
DEV_FIXTURE ?= tests/fixtures/branch

.PHONY: test lint typecheck bundle bundle-check dev clean

test:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v

lint:
	$(RUFF) check src tests tools

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

clean:
	rm -rf dist build .mypy_cache .ruff_cache
	find src tests tools -name __pycache__ -type d -prune -exec rm -rf {} +
