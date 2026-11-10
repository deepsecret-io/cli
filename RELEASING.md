# Releasing the CLI

A release is a `vMAJOR.MINOR.PATCH` tag ([semver.org](https://semver.org)) on a commit that is on `main`. The tag is the version: nothing else in the repository holds it. Pushing the tag starts the [Release workflow](.github/workflows/release.yml), which checks, tests, scans, builds, signs, attests and publishes the release on GitHub. Nobody builds or uploads release files by hand, and no long-lived secret takes part: signing uses the workflow's short-lived OIDC identity.

While the major version is 0, a breaking change bumps the minor version. A fix bumps the patch version.

## Who can release

- Only the maintainers on the bypass list of the tag ruleset (below) can create a `v*` tag.
- The workflow signs and publishes only after a reviewer of the `release` environment approves the `publish` job. With Prevent self-review on, that reviewer cannot be the person who pushed the tag, so every release takes two maintainers. While there is only one maintainer, Prevent self-review stays off: the approval is still logged with who approved and when, and the missing second person is recorded as an accepted risk until a second maintainer joins.

## Cut a release

1. If the CLI needs a new SDK version, release the SDK first, then `GOWORK=off go get github.com/deepsecret-io/deepsecret-go@vX.Y.Z` and `GOWORK=off go mod tidy`, and merge that to `main`. The Windows build needs an SDK release that gives key files an owner-only ACL there (see Platforms): v0.4.0 does not, and the Windows tests fail on it.
2. From a clean, pushed `main`:

   ```bash
   task release VERSION=v0.1.0
   ```

   It refuses a version that is not `vMAJOR.MINOR.PATCH`, not newer than the last release, or already tagged; a dirty tree; a commit that is not on `origin/main`; a `replace` in go.mod, an SDK that is not a release, or a go.mod that is not tidy. Then it runs the security gate and builds every platform as a snapshot, and only then tags HEAD (annotated, and signed if you set `git config tag.gpgSign true`) and pushes the tag.
3. In the workflow run, check that `check`, `test`, `security` and `build` passed, read the `build` job's SHA256SUMS, then approve the `publish` job.
4. When it finishes, the release page lists the files below, and `releases/latest` points at it.

If the run fails before `publish` finished, nothing is public. A failure in the code is fixed on `main` and released as the next patch version: a tag is never moved or deleted. A failure outside the code (a runner or network outage) is fixed by re-running the failed jobs; `publish` replaces the draft it left behind, and it never changes a published release.

## What the workflow does

| Job | Token permissions | What it does |
|---|---|---|
| `check` | `contents: read` | `task release-check` on the tag: the same checks as step 2, and the tag must point at the checked-out commit. It also picks the Go version for the whole run. |
| `test` | `contents: read` | `ci.yml`: `go vet` and `go test -race` on Linux, and `go vet` and `go test` on Windows (`test (windows)`, built with `CGO_ENABLED=0` like the release). |
| `security` | `contents: read` | `security.yml`, which is `task security`: govulncheck, gosec, the license allowlist and gitleaks over the full history. Its reports are kept as the `security-reports` artifact. |
| `build` | `contents: read` | `task release-build`: GoReleaser builds every archive, an SPDX SBOM per archive and SHA256SUMS, without a cache. It publishes nothing. |
| `publish` | `contents: write`, `id-token: write`, `attestations: write` | In the `release` environment. Checks every file against SHA256SUMS, signs SHA256SUMS with Sigstore cosign (keyless), attests the build provenance of every file SHA256SUMS lists, verifies both, then creates the release as a draft, uploads everything and publishes it. |

Every third-party action is pinned to a full commit SHA, every checkout uses `persist-credentials: false`, and the tools (Task, GoReleaser, syft) are pinned Go modules checked against the Go checksum database.

The builds are reproducible: the same commit and Go version give byte-identical archives (`-trimpath`, an empty build ID, file times from the commit, `CGO_ENABLED=0`). The SBOMs record when they were made, so they differ from run to run.

## Platforms

| File | For |
|---|---|
| `secret_darwin_arm64.tar.gz` | macOS on Apple silicon, with security key (YubiKey) support |
| `secret_darwin_amd64.tar.gz` | macOS on Intel, with security key support |
| `secret_linux_amd64_fido2.tar.gz`, `secret_linux_arm64_fido2.tar.gz` | Linux with glibc, with security key support (libfido2 must be installed to use one) |
| `secret_linux_amd64.tar.gz`, `secret_linux_arm64.tar.gz` | Any Linux, Alpine and other musl systems included: fully static, without security key support |
| `secret_windows_amd64.zip`, `secret_windows_arm64.zip` | Windows on x64 and on Arm, without security key support |

Each archive holds a folder of the same name with `secret` (`secret.exe` on Windows) and `LICENSE`. The names carry no version, so `https://github.com/deepsecret-io/cli/releases/latest/download/<file>` always gives the latest release; the landing page and `scripts/install.sh` depend on these names, and the `build` job fails if one is missing.

Every target is pure Go and cross-compiles on a GitHub-hosted Ubuntu runner.

Windows ignores the 0600 and 0700 modes the CLI uses elsewhere, so there the CLI (`internal/safefile`) and the SDK (`internal/disk`) create the config, the login token, key files and decrypted files with an owner-only ACL: owned by the user, a protected DACL, full control for the user and nobody else. They refuse to read a config, token or key file that anyone but the user, SYSTEM and Administrators owns or may open, and say which `icacls` command fixes it. Key files are the SDK's, so a Windows release needs an SDK release with that code. The `test (windows)` job checks it: `internal/identity`'s `TestKeyFilesArePrivate` saves a key through the SDK version go.mod requires and fails when the file is not owner-only.

Each release also has `SHA256SUMS`, `SHA256SUMS.sigstore.json` (its signature), a `.spdx.json` SBOM per archive, the installers `install.sh` (macOS and Linux) and `install.ps1` (Windows), and `security-reports.tar.gz`.

## Verify a download

Download the archive with `SHA256SUMS` and `SHA256SUMS.sigstore.json` from the same release, then:

1. **Checksum.** It catches a damaged download.

   ```bash
   sha256sum --check --ignore-missing SHA256SUMS              # Linux
   shasum -a 256 --check --ignore-missing SHA256SUMS          # macOS
   ```

   On Windows, in PowerShell:

   ```powershell
   $want = (Select-String -Path SHA256SUMS -Pattern ' secret_windows_amd64\.zip$').Line.Split(' ')[0]
   if ((Get-FileHash secret_windows_amd64.zip -Algorithm SHA256).Hash -ne $want) { throw 'checksum mismatch' }
   ```

2. **Signature.** It proves that this repository's Release workflow, run for this tag, made SHA256SUMS, so a checksum file swapped on its way to you fails. Needs [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) v3. Use the tag you downloaded:

   ```bash
   cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
     --certificate-identity https://github.com/deepsecret-io/cli/.github/workflows/release.yml@refs/tags/v0.1.0 \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com
   ```

3. **Build provenance.** It shows which workflow run, commit and runner built the file. Needs the [GitHub CLI](https://cli.github.com):

   ```bash
   gh attestation verify secret_linux_amd64.tar.gz --repo deepsecret-io/cli \
     --signer-workflow deepsecret-io/cli/.github/workflows/release.yml
   ```

4. **Rebuild it** (optional). `go version -m secret` names the Go version and the commit. With that Go version, in a clean checkout of the tag, `task release-build VERSION=v0.1.0` builds the same archives, and their lines in `dist/SHA256SUMS` match the release's.

macOS puts a quarantine flag on files a browser downloads, and these binaries are not notarized, so download with `curl` (as the landing page shows), or clear the flag once with `xattr -d com.apple.quarantine secret`.

Windows marks files a browser downloads too, and `secret.exe` is not code signed, so SmartScreen may warn the first time it runs. Download with `curl.exe` (built into Windows 10 and later), or clear the mark once, after checking the download, with `Unblock-File secret.exe` in PowerShell.

## GitHub settings

Set these once, before the first tag:

- **Tag ruleset** (Settings, Rules, Rulesets, New tag ruleset): target `refs/tags/v*`, enforcement Active, with Restrict creations, Restrict updates, Restrict deletions and Block force pushes. The bypass list holds only the maintainers who may release.
- **Environment `release`** (Settings, Environments): required reviewers (the maintainers), Prevent self-review on once there are two maintainers (see Who can release), and Deployment branches and tags set to the tag pattern `v*.*.*` only. It needs no secrets.
- **Immutable releases** (Settings, General, Releases): on, so a published release's files and tag cannot change.
- **Actions** (Settings, Actions, General): default workflow permissions Read repository contents; Actions may not create or approve pull requests; require actions to be pinned to a full-length commit SHA.
- **`main`**: a ruleset that requires a reviewed pull request and the `test`, `test (windows)`, `lint` and `security` checks, so every commit a tag can point at was reviewed and tested.
- **Visibility**: the CLI and SDK repositories are public, and the SDK version go.mod requires is published, since the workflow fetches modules without credentials. Attestations for a private repository need GitHub Enterprise Cloud.

## Evidence each release leaves

- **The change:** the pull request that brought each commit to `main`, its review and its checks; the tag, with who pushed it and when (and its signature, if signed).
- **The run:** logs of every job, including the checks, the test results, each scan's report, SHA256SUMS and `go version -m` of every binary; the `release` environment's deployment, with who approved it and when. GitHub keeps run logs and artifacts for the repository's retention period (90 days by default), so save the run logs to the evidence store within that time.
- **The release:** the archives, SBOMs, SHA256SUMS, its Sigstore bundle, `install.sh`, `install.ps1` and `security-reports.tar.gz`, kept as long as the release, and unchangeable with immutable releases on.
- **Public logs:** the signature and the provenance attestation are recorded in Sigstore's Rekor transparency log, and the attestation is listed under the repository's Attestations.

These cover change management and release integrity for SOC 2 (CC8.1) and ISO 27001 (A.8.25, A.8.32): every release is a reviewed commit, built and signed by an automated, logged process with a recorded approval, and traceable from the binary back to the source.
