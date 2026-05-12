#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 DeepSecret
#
# Upload the cross-compiled archives in $DIST to a Cloudflare R2 bucket under
# $R2_PREFIX/, then mirror the same files to $R2_LATEST_PREFIX/ so the static
# download URLs on the landing page serve the freshly built artifacts. Invoked
# by `make release-upload` after the release target has rebuilt the dist tree;
# can also be run directly with the same env vars.
#
# Required env vars:
#   BINARY                CLI binary name; matches Makefile's $(BINARY)
#   DIST                  Path to the dist directory containing the archives
#   VERSION               Release version string (e.g. v1.2.3 or git-describe)
#   R2_ACCOUNT_ID         Cloudflare R2 account ID
#   R2_BUCKET             Target bucket name
#   R2_ACCESS_KEY_ID      R2 access key (falls back to AWS_ACCESS_KEY_ID)
#   R2_SECRET_ACCESS_KEY  R2 secret (falls back to AWS_SECRET_ACCESS_KEY)
#
# Optional:
#   R2_PREFIX             Archived path in the bucket; default cli/$VERSION
#   R2_LATEST_PREFIX      Stable path the landing page links to; default cli
#                         (set to empty string to skip the latest mirror)
#   R2_ENDPOINT           Override endpoint; default derived from R2_ACCOUNT_ID
#   R2_PUBLIC_BASE_URL    Public origin used to print download URLs;
#                         default https://get.deepsecret.io (the bucket
#                         custom domain)
#   ALLOW_DIRTY           Set to 1 to permit uploading a *-dirty VERSION
set -euo pipefail

BINARY="${BINARY:-secret}"
DIST="${DIST:-dist}"
: "${VERSION:?VERSION is required}"

command -v aws >/dev/null 2>&1 || {
  echo "release-upload: aws CLI not found (install: https://aws.amazon.com/cli/)" >&2
  exit 1
}

acct="${R2_ACCOUNT_ID:-}"
bucket="${R2_BUCKET:-}"
prefix="${R2_PREFIX:-cli/$VERSION}"
latest_prefix="${R2_LATEST_PREFIX-cli}"
endpoint="${R2_ENDPOINT:-https://${acct}.r2.cloudflarestorage.com}"
public_base="${R2_PUBLIC_BASE_URL:-https://get.deepsecret.io}"
key_id="${R2_ACCESS_KEY_ID:-${AWS_ACCESS_KEY_ID:-}}"
key_secret="${R2_SECRET_ACCESS_KEY:-${AWS_SECRET_ACCESS_KEY:-}}"

missing=""
[ -n "$acct" ]       || missing="$missing R2_ACCOUNT_ID"
[ -n "$bucket" ]     || missing="$missing R2_BUCKET"
[ -n "$key_id" ]     || missing="$missing R2_ACCESS_KEY_ID(or AWS_ACCESS_KEY_ID)"
[ -n "$key_secret" ] || missing="$missing R2_SECRET_ACCESS_KEY(or AWS_SECRET_ACCESS_KEY)"
if [ -n "$missing" ]; then
  echo "release-upload: missing required vars:$missing" >&2
  echo "  tip: make does not see plain shell vars. Use one of:" >&2
  echo "    export R2_ACCOUNT_ID=... R2_BUCKET=... R2_ACCESS_KEY_ID=... R2_SECRET_ACCESS_KEY=..." >&2
  echo "    make release-upload R2_ACCOUNT_ID=... R2_BUCKET=... ..." >&2
  echo "    put KEY=VALUE lines in ./.env (auto-loaded by Makefile)" >&2
  exit 1
fi

case "$VERSION" in
  *-dirty)
    if [ "${ALLOW_DIRTY:-0}" != "1" ]; then
      echo "release-upload: refusing to upload dirty version $VERSION; commit or stash first, or pass ALLOW_DIRTY=1" >&2
      exit 1
    fi
    echo "release-upload: WARNING: uploading dirty version $VERSION (ALLOW_DIRTY=1)" >&2
    ;;
esac

# Shared aws options. R2 is S3-compatible via --endpoint-url; --checksum-algorithm
# CRC32 keeps newer aws CLI versions from negotiating an algorithm R2 rejects.
aws_cp() {
  local dest="$1"
  AWS_ACCESS_KEY_ID="$key_id" AWS_SECRET_ACCESS_KEY="$key_secret" AWS_DEFAULT_REGION=auto \
    aws s3 cp "$DIST/" "$dest" \
      --endpoint-url "$endpoint" \
      --recursive \
      --exclude "*" \
      --include "${BINARY}-*.tar.gz" \
      --include "SHA256SUMS" \
      --checksum-algorithm CRC32 \
      --only-show-errors
}

echo "uploading $VERSION to $public_base/$prefix/ ..."
aws_cp "s3://$bucket/$prefix/"

if [ -n "$latest_prefix" ]; then
  echo "mirroring to landing-page path $public_base/$latest_prefix/ ..."
  aws_cp "s3://$bucket/$latest_prefix/"
fi

echo "done. published:"
for f in "$DIST/${BINARY}"-*.tar.gz "$DIST/SHA256SUMS"; do
  [ -e "$f" ] || continue
  base="$(basename "$f")"
  echo "  $public_base/$prefix/$base"
done
if [ -n "$latest_prefix" ]; then
  echo "landing page URLs (now serving $VERSION):"
  for f in "$DIST/${BINARY}"-*.tar.gz "$DIST/SHA256SUMS"; do
    [ -e "$f" ] || continue
    base="$(basename "$f")"
    echo "  $public_base/$latest_prefix/$base"
  done
fi
