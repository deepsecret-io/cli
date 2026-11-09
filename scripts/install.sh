#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 DeepSecret
#
# Install the DeepSecret CLI.
#
# Usage:
#   curl -fsSL https://github.com/deepsecret-io/cli/releases/download/<version>/install.sh | bash -s -- <version>
#
# Examples:
#   curl -fsSL https://github.com/deepsecret-io/cli/releases/download/v0.1.0/install.sh | bash -s -- v0.1.0
#
# Detects OS (darwin/linux) and arch (amd64/arm64), downloads the matching
# archive from the version's GitHub release, checks it against the release's
# SHA256SUMS, and installs the binary to $INSTALL_DIR (default
# /usr/local/bin). Escalates to sudo only if $INSTALL_DIR (or its nearest
# existing ancestor) is not writable. When cosign is installed, it also
# checks that this repository's Release workflow signed SHA256SUMS for the
# version, and stops if it did not; set REQUIRE_SIGNATURE=1 to stop when
# cosign is missing too. RELEASING.md shows how to check the build
# provenance as well.
#
# Fetching via curl avoids the macOS Gatekeeper quarantine attribute that
# browser downloads attach, so the binary runs without `xattr` workarounds.
#
# Environment overrides:
#   INSTALL_DIR  install target directory (default /usr/local/bin)
#   BASE_URL     override the release base URL (default https://github.com/deepsecret-io/cli/releases/download/<version>)
#   REQUIRE_SIGNATURE  set to 1 to refuse to install without checking SHA256SUMS's signature
set -euo pipefail

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "error: version is required" >&2
  echo "usage: curl -fsSL https://github.com/deepsecret-io/cli/releases/download/<version>/install.sh | bash -s -- <version>" >&2
  exit 1
fi
# Releases are vMAJOR.MINOR.PATCH, and the version goes into the download
# URL, so nothing else is accepted.
if ! printf '%s' "$VERSION" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
  echo "error: version must look like v0.1.0, got: $VERSION" >&2
  exit 1
fi

BINARY="secret"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BASE_URL="${BASE_URL:-https://github.com/deepsecret-io/cli/releases/download/${VERSION}}"

# Archives are named secret_<os>_<arch>.tar.gz, with Go's names for the OS
# and the architecture (.goreleaser.yaml).
os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  darwin|linux) ;;
  *) echo "error: unsupported OS: $os" >&2; exit 1 ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64|amd64)  arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "error: unsupported arch: $arch" >&2; exit 1 ;;
esac

# On Linux with glibc, take the build with security key (YubiKey) support:
# it loads libfido2 only when a security key is used. Elsewhere (musl, as on
# Alpine) take the fully static build, which has no security key support.
flavor=""
if [ "$os" = linux ] && getconf GNU_LIBC_VERSION 2>/dev/null | grep -q "^glibc "; then
  flavor="_fido2"
fi

name="${BINARY}_${os}_${arch}${flavor}"
archive="${name}.tar.gz"
url="${BASE_URL}/${archive}"
sha_url="${BASE_URL}/SHA256SUMS"

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t deepsecret)
trap 'rm -rf "$tmp"' EXIT INT TERM HUP

fetch() {
  curl -fsSL --proto '=https' --tlsv1.2 -o "$1" "$2"
}

echo "downloading ${archive} (${VERSION})..."
fetch "${tmp}/${archive}" "$url"

if command -v shasum >/dev/null 2>&1; then
  hash_cmd="shasum -a 256"
elif command -v sha256sum >/dev/null 2>&1; then
  hash_cmd="sha256sum"
else
  hash_cmd=""
fi

# Nothing is installed unchecked: without a SHA-256 tool, stop.
if [ -z "$hash_cmd" ]; then
  echo "error: shasum or sha256sum is needed to check the download" >&2
  exit 1
fi

echo "verifying SHA-256..."
fetch "${tmp}/SHA256SUMS" "$sha_url"

# A checksum file from the same place as the archive only catches a damaged
# download. Its signature proves that this repository's Release workflow,
# run for this version's tag, made it.
if command -v cosign >/dev/null 2>&1; then
  echo "verifying the signature of SHA256SUMS..."
  fetch "${tmp}/SHA256SUMS.sigstore.json" "${sha_url}.sigstore.json"
  if ! cosign verify-blob "${tmp}/SHA256SUMS" --bundle "${tmp}/SHA256SUMS.sigstore.json" \
    --certificate-identity "https://github.com/deepsecret-io/cli/.github/workflows/release.yml@refs/tags/${VERSION}" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null 2>&1; then
    echo "error: SHA256SUMS is not signed by the DeepSecret CLI release workflow for ${VERSION}" >&2
    exit 1
  fi
elif [ "${REQUIRE_SIGNATURE:-}" = 1 ]; then
  echo "error: cosign is needed to check the signature (REQUIRE_SIGNATURE=1)" >&2
  exit 1
else
  echo "note: cosign is not installed, so the signature of SHA256SUMS was not checked (see RELEASING.md)" >&2
fi
expected=$(awk -v f="$archive" '$2 == f || $2 == "*"f { print $1; exit }' "${tmp}/SHA256SUMS")
actual=$($hash_cmd "${tmp}/${archive}" | awk '{ print $1 }')
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
  echo "error: SHA-256 mismatch for ${archive}" >&2
  echo "  expected: ${expected:-<not found in SHA256SUMS>}" >&2
  echo "  actual:   ${actual}" >&2
  exit 1
fi

echo "extracting..."
tar -xzf "${tmp}/${archive}" -C "$tmp"

# Validate the extracted layout matches what we expect. If a tampered archive
# (or future packaging change) lays things out differently we want to fail loud
# rather than installing whatever happened to land at the right path.
src="${tmp}/${name}/${BINARY}"
if [ ! -f "$src" ] || [ ! -x "$src" ]; then
  echo "error: archive layout is malformed; expected executable at ${name}/${BINARY}" >&2
  exit 1
fi

# Decide once whether we need sudo, then apply it consistently to both mkdir
# and install so we never have a half-created directory we cannot write to.
# Walk up to the first existing ancestor; its writability decides.
probe="$INSTALL_DIR"
while [ -n "$probe" ] && [ "$probe" != "/" ] && [ ! -e "$probe" ]; do
  probe=$(dirname "$probe")
done
if [ -w "$probe" ]; then
  sudo_cmd=""
else
  sudo_cmd="sudo"
fi

dest="${INSTALL_DIR}/${BINARY}"
echo "installing ${dest} ..."
if [ ! -d "$INSTALL_DIR" ]; then
  ${sudo_cmd:+sudo} mkdir -p "$INSTALL_DIR"
fi
${sudo_cmd:+sudo} install -m 755 "$src" "$dest"

echo
echo "installed: ${dest}"
echo "run 'secret --help' to get started."
