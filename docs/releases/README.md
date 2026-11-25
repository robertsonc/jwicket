# Release records

> **LAB ONLY.** J-Wicket pre-releases are lab-only and unsupported until gate G1 passes. No
> pre-release has been published yet, so this directory holds no record: the first would be
> `v0.1.0.dev1.sha256sums`, added only after the owner has pushed that tag and the release has been
> published.

This directory holds one **release record** per published pre-release: `<tag>.sha256sums`, a copy of
that release's `SHA256SUMS`, added to `main` by a reviewed pull request after publication. It is the
provenance source P-C of [Spec 006, section 8.9](../specs/006-installation.md#89-provenance-and-bundle-integrity-inv-07):
a second place, independent of the release page, that says which bytes the release holds. Whoever
can replace a release's assets can replace its `SHA256SUMS` too; they cannot also change `main`
without a reviewed pull request. The release workflow cannot write the record itself, because the
tagged commit cannot contain the hashes of the files built from it
([section 11.5](../specs/006-installation.md#115-release-record-on-main-and-the-private-repository-path)).

## Format

- **Name:** the tag followed by `.sha256sums`, for example `v0.1.0.dev1.sha256sums`. A tag is
  always `v<major>.<minor>.<patch>.dev<N>` (`tools/release_check.py`).
- **Content:** the release's `SHA256SUMS`, byte for byte, so `cmp` and `sha256sum -c` read it as they
  read the original. That is ASCII, one line per asset, each line the lowercase 64-character SHA-256,
  two spaces and the file name, ending in a line feed, for exactly these four files in this order
  (the order the release workflow's `build` job writes them):

  ```
  <64 hex>  jwicket.py
  <64 hex>  jwicket-install-op.py
  <64 hex>  jwicket_install-<version>-py3-none-any.whl
  <64 hex>  requirements-install.txt
  ```

  `<version>` is the tag without its `v`. `tools/release_record.py` refuses a `SHA256SUMS` with any
  other line, a missing or extra file, or a file listed twice.
- **Never changed.** A record, once on `main`, is never edited or replaced: `make release-record`
  refuses to overwrite an existing record that differs from the release. A release that turns out
  to be wrong gets a new tag and a new record.
- **Mode 0644**, on purpose: the hashes are public.

## Who reads it

| Reader | How |
| --- | --- |
| `jwicket-install` (P-C), before it installs a downloaded bundle | `git show origin/main:docs/releases/<tag>.sha256sums` in the checkout given with `--checkout`, or `https://raw.githubusercontent.com/<owner>/<repo>/main/docs/releases/<tag>.sha256sums`. A record whose `jwicket.py` line differs from the download stops the install (exit 7) |
| An operator of the on-box installer (M4, M4U) | Compares `file checksum sha-256 /var/db/scripts/op/jwicket-install-op.py` with the `jwicket-install-op.py` line before pinning that hash ([install guide, M4](../install.md#m4-on-box-op-script-run-locally)) |
| An operator setting up the workstation installer | `cmp` of the record with the downloaded `SHA256SUMS` ([install guide](../install.md#get-a-pre-release-and-check-where-it-came-from)) |
| `make container-context VERIFY=record` | `tools/release_record.py fetch` compares the downloaded `SHA256SUMS` with `origin/main`'s record, byte for byte, before it copies the wheel into the image's build context |

The release notes of each pre-release link the record and say that a match with the release page
alone is not enough.

## Making a record: `make release-record`

After the release workflow has published a tag (and its own job summary says so), the owner, or
anyone the owner then reviews, runs from an up-to-date checkout of `main`:

```sh
make release-record TAG=<tag> REPO=<owner>/<repo>
```

That runs `tools/release_record.py record --tag <tag> --repo <owner>/<repo> --verify attestation`,
which only reads from GitHub and writes one local file:

1. **Download.** `gh release download <tag> --repo <owner>/<repo> --dir <temporary directory>` with a
   `--pattern` for each expected file: the four assets and `SHA256SUMS` (and `SHA256SUMS.sig` for
   `VERIFY=signature`). Each read has a timeout and is retried with back-off; the download must
   provide exactly those files.
2. **Check the files.** `SHA256SUMS` is parsed strictly (the format above); every listed file must be
   a regular file of at most 16 MB whose SHA-256 equals its line.
3. **Verify independently of the page**, by one of:
   - `VERIFY=attestation` (the default): `gh release verify <tag>` and then `gh release verify-asset
     <tag> <file>` for each of the four assets and `SHA256SUMS`. This checks the immutable release's
     own attestation, which GitHub creates when an immutable release is published.
   - `VERIFY=signature IDENTITY=<owner principal> NAMESPACE=<namespace>`: for a private repository
     without attestations (below), `ssh-keygen -Y verify -f docs/releases/allowed_signers -I
     <identity> -n <namespace> -s SHA256SUMS.sig`, with `SHA256SUMS` on its standard input.
4. **Write** `docs/releases/<tag>.sha256sums`: the verified `SHA256SUMS`, unchanged. An identical
   record already present is reported and left alone; a different one is refused.

Then open a pull request that adds only that file. The reviewer checks that the pull request adds
exactly one new file under `docs/releases/`, named after a published tag, and that its content equals
the `SHA256SUMS` shown in that release's notes. Once merged, P-C works for that tag.

`tools/release_record.py` exits 0 when every check passed, 1 when one failed or a tool it needs
(`gh`, `git` or `ssh-keygen`) is not on `PATH` (each failure printed with what was expected and what
was found), and 2 on bad arguments. It never uploads anything, and it never sees a token: `gh` keeps
its own login.

## The private-repository path and `allowed_signers`

A private repository on a plan without attestations gets no release attestation, so the workflow
leaves the release as a draft for the owner
([section 11.5](../specs/006-installation.md#115-release-record-on-main-and-the-private-repository-path)).
The owner reproduces the build locally (P-D, the commands in the draft's notes), signs `SHA256SUMS`
with an SSH key kept outside GitHub, uploads the signature, publishes the draft and runs `gh release
verify`:

```sh
ssh-keygen -Y sign -f <key> -n jwicket-release@<domain> SHA256SUMS
```

`ssh-keygen` writes `SHA256SUMS.sig`. The matching public key goes in `docs/releases/allowed_signers`
on `main`, by a reviewed pull request, before the first signed release. It uses OpenSSH's allowed
signers format, one line per key (from the `ssh-keygen(1)` manual): the principal, the option
`namespaces="jwicket-release@<domain>"`, then the key type and the base64 key, as they appear in the
`.pub` file. Then:

```sh
make release-record TAG=<tag> REPO=<owner>/<repo> VERIFY=signature IDENTITY=<principal> NAMESPACE=jwicket-release@<domain>
```

The file does not exist yet; it is needed only if the repository is private without attestations.
`jwicket-install` itself does not check this signature: for a release on this path its P-C source is
the record on `main`, which the signature check above guarded before it was written.

## Before a tag: `make release-check`

Before pushing a tag, the owner runs the release workflow's own pre-flight checks locally:

```sh
JWICKET_IMMUTABLE_RELEASES=true make release-check TAG=<tag>
```

`tools/release_check.py` checks that the tag is a `.devN` pre-release tag, that the three version
strings (`src/jwicket/__init__.py`, `pyproject.toml`, `tools/jwicket_install/__init__.py`) equal the
tag without its `v`, and that the commit is reachable from `origin/main`. `JWICKET_IMMUTABLE_RELEASES`
is the owner's assertion that immutable releases are turned on in the repository's settings (the
workflow reads the same name as a repository variable); the workflow's `publish` job checks it for
real with `gh release verify` and deletes the release if that fails. The repository settings the
release relies on are in
[section 11.2](../specs/006-installation.md#112-repository-settings-required-before-the-first-pre-release).
