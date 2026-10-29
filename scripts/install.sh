#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 DeepSecret
#
# Install the DeepSecret CLI.
#
# Usage:
#   curl -fsSL https://get.deepsecret.io/install.sh | bash -s -- <version>
#
# Examples:
#   curl -fsSL https://get.deepsecret.io/install.sh | bash -s -- v0.1.0
#
# Detects OS (macos/linux) and arch (arm64/x86_64), downloads the matching
# archive from https://get.deepsecret.io/cli/<version>/, verifies SHA-256, and
# installs the binary to $INSTALL_DIR (default /usr/local/bin). Escalates to
# sudo only if $INSTALL_DIR (or its nearest existing ancestor) is not writable.
#
# Fetching via curl avoids the macOS Gatekeeper quarantine attribute that
# browser downloads attach, so the binary runs without `xattr` workarounds.
#
# Environment overrides:
#   INSTALL_DIR  install target directory (default /usr/local/bin)
#   BASE_URL     override the release base URL (default https://get.deepsecret.io/cli/<version>)
set -euo pipefail

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "error: version is required" >&2
  echo "usage: curl -fsSL https://get.deepsecret.io/install.sh | bash -s -- <version>" >&2
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
BASE_URL="${BASE_URL:-https://get.deepsecret.io/cli/${VERSION}}"

# Normalize OS. Matches the published artifact suffix: secret-<os>-<arch>.tar.gz.
os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  darwin) os=macos ;;
  linux)  os=linux ;;
  *) echo "error: unsupported OS: $os" >&2; exit 1 ;;
esac

# Normalize arch to match published artifact names. DeepSecret releases use
# x86_64 (not amd64); update the mapping if that ever changes.
arch=$(uname -m)
case "$arch" in
  x86_64|amd64)  arch=x86_64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "error: unsupported arch: $arch" >&2; exit 1 ;;
esac

name="${BINARY}-${os}-${arch}"
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

if [ -n "$hash_cmd" ]; then
  echo "verifying SHA-256..."
  fetch "${tmp}/SHA256SUMS" "$sha_url"
  expected=$(awk -v f="$archive" '$2 == f || $2 == "*"f { print $1; exit }' "${tmp}/SHA256SUMS")
  actual=$($hash_cmd "${tmp}/${archive}" | awk '{ print $1 }')
  if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
    echo "error: SHA-256 mismatch for ${archive}" >&2
    echo "  expected: ${expected:-<not found in SHA256SUMS>}" >&2
    echo "  actual:   ${actual}" >&2
    exit 1
  fi
else
  echo "warning: shasum/sha256sum not found; skipping verification" >&2
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
