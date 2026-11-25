# The workstation installer, jwicket-install, as a container image: Spec 006 section 6.4, method M3.
# LAB ONLY: a pre-release tool for lab devices (a vSRX, or lab hardware with --lab-hardware and a typed
# 'lab only'). Every device step the installer takes is unverified until lab test Q-INST-06; the image
# changes nothing about that.
#
# Build. The context is this directory, and .dockerignore lets in only this file, entrypoint.py and
# the three files that `make container-context` puts in build/ after it has checked the release's
# provenance and SHA-256 (Spec 006 section 8.9):
#   make container-context TAG=<tag> REPO=<owner>/<repo>   # or LOCAL=1: a wheel built from this checkout
#   docker build --tag jwicket-install:<version> deploy/container
# Run: README.md (a state directory mounted on /state, --user, a dedicated SSH agent).
#
# Base image: python:3.12-slim as published on 2026-11-24, which is 3.12.16-slim-trixie, pinned by
# the digest of its multi-platform OCI image index. Resolved on 2026-11-24 from
# registry-1.docker.io/v2/library/python/manifests/3.12-slim: the index body's SHA-256 equals its
# Docker-Content-Digest header, and the Docker Hub tags API gives the same digest for 3.12-slim,
# 3.12.16-slim and 3.12.16-slim-trixie. The tag is for people; the digest decides what is pulled.
# To move the pin, resolve a new digest the same way and change both FROM lines together.
# The juniper/pyez images are not used: their newest tag is PyEZ 2.7.2 (Spec 006 section 6.4).

FROM python:3.12.16-slim-trixie@sha256:191083cdf6c7bda8c76158983163ead5d5cf7b77cf3033e805bb0f5296f51b4b AS build

COPY build/SHA256SUMS build/requirements-install.txt /tmp/build/
COPY build/jwicket_install-*-py3-none-any.whl /tmp/build/

# 1. SHA256SUMS lists exactly the requirements file and one installer wheel, and both match it.
# 2. The dependencies: every one pinned by hash (--require-hashes), wheels only (--only-binary), so
#    no package's build code runs here.
# 3. The installer wheel, by the hash SHA256SUMS gives for it, with nothing resolved from an index.
RUN set -eu; \
    cd /tmp/build; \
    wheel_pattern='[0-9a-f]{64}  jwicket_install-[0-9]+\.[0-9]+\.[0-9]+(\.dev[0-9]+)?-py3-none-any\.whl'; \
    test "$(wc -l < SHA256SUMS)" -eq 2; \
    grep -Eqx '[0-9a-f]{64}  requirements-install\.txt' SHA256SUMS; \
    test "$(grep -Ecx "$wheel_pattern" SHA256SUMS)" -eq 1; \
    set -- jwicket_install-*-py3-none-any.whl; \
    test "$#" -eq 1; \
    sha256sum --check --strict SHA256SUMS; \
    line="$(grep -Ex "$wheel_pattern" SHA256SUMS)"; \
    test "${line#*  }" = "$1"; \
    printf '/tmp/build/%s --hash=sha256:%s\n' "$1" "${line%%  *}" > /tmp/wheel-requirement.txt; \
    python -m venv /opt/jwicket-install; \
    /opt/jwicket-install/bin/python -m pip install --no-cache-dir --disable-pip-version-check --no-input \
        --require-hashes --only-binary=:all: -r /tmp/build/requirements-install.txt; \
    /opt/jwicket-install/bin/python -m pip install --no-cache-dir --disable-pip-version-check --no-input \
        --require-hashes --no-deps --no-index -r /tmp/wheel-requirement.txt; \
    /opt/jwicket-install/bin/python -m pip check; \
    test -f /opt/jwicket-install/bin/jwicket-install

FROM python:3.12.16-slim-trixie@sha256:191083cdf6c7bda8c76158983163ead5d5cf7b77cf3033e805bb0f5296f51b4b

LABEL org.opencontainers.image.title="jwicket-install" \
      org.opencontainers.image.description="J-Wicket's lab-gated installer for lab SRX devices. LAB ONLY; every device step unverified (Q-INST-06)."

# The installer's account (uid and gid 10001, no login shell). README.md runs the container with
# --user "$(id -u):$(id -g)" instead, so that the state directory, the mounted known_hosts file and
# the agent socket belong to the caller. /home/app and /home/app/.ssh are 0755, readable and
# traversable by any uid, because that caller's uid is not 10001; they hold nothing but the
# read-only known_hosts mount. /state is 0700; a bind mount replaces it at run time. No VOLUME: an
# automatic anonymous volume on /state would pass for a mount and be deleted by --rm.
RUN set -eu; \
    groupadd --system --gid 10001 app; \
    useradd --system --uid 10001 --gid 10001 --home-dir /home/app --no-create-home --shell /usr/sbin/nologin app; \
    install -d -m 0755 -o 10001 -g 10001 /home/app /home/app/.ssh; \
    install -d -m 0700 -o 10001 -g 10001 /state

# Root-owned, so the account that runs the installer cannot change it.
COPY --from=build /opt/jwicket-install /opt/jwicket-install
COPY entrypoint.py /opt/jwicket/entrypoint.py

# HOME is set because a --user uid has no passwd entry in the image. No PYTHON* variables: the entry
# point and the installer run with -I, which ignores them.
ENV HOME=/home/app
WORKDIR /home/app
USER 10001:10001

ENTRYPOINT ["/opt/jwicket-install/bin/python", "-I", "/opt/jwicket/entrypoint.py"]
CMD ["--help"]
