#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 DeepSecret
#
# Upload the cross-compiled archives in $DIST to a Cloudflare R2 bucket under
# $R2_PREFIX/ (default cli/$VERSION), then rewrite the landing page so its
# download links point at the freshly uploaded version. Invoked by
# `make release-upload` after the release target has rebuilt the dist tree;
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
#   R2_PREFIX             In-bucket key prefix; default cli/$VERSION
#   R2_ENDPOINT           Override endpoint; default derived from R2_ACCOUNT_ID
#   R2_PUBLIC_BASE_URL    Public origin used in printed URLs and landing-page
#                         rewrite; default https://get.deepsecret.io (the
#                         bucket custom domain)
#   LANDING_HTML          Path to the landing page HTML to rewrite;
#                         default ../landing/index.html (relative to this
#                         script's invocation directory)
#   SKIP_LANDING_UPDATE   Set to 1 to upload without touching the landing page
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
endpoint="${R2_ENDPOINT:-https://${acct}.r2.cloudflarestorage.com}"
public_base="${R2_PUBLIC_BASE_URL:-https://get.deepsecret.io}"
landing_html="${LANDING_HTML:-../landing/index.html}"
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

echo "uploading $VERSION to $public_base/$prefix/ ..."
# R2 is S3-compatible via --endpoint-url. --checksum-algorithm CRC32 keeps
# newer aws CLI versions from negotiating an algorithm R2 rejects.
AWS_ACCESS_KEY_ID="$key_id" AWS_SECRET_ACCESS_KEY="$key_secret" AWS_DEFAULT_REGION=auto \
  aws s3 cp "$DIST/" "s3://$bucket/$prefix/" \
    --endpoint-url "$endpoint" \
    --recursive \
    --exclude "*" \
    --include "${BINARY}-*.tar.gz" \
    --include "SHA256SUMS" \
    --checksum-algorithm CRC32 \
    --only-show-errors

# Rewrite the landing page's download links to point at the new version. The
# regex anchors on the literal filename (secret-<arch>.tar.gz) and replaces
# whatever path comes before it, so it works whether the page currently has
#   <public_base>/cli/secret-...
#   <public_base>/cli/v0.1.2/secret-...
# or any other previous version. Portable across BSD (macOS) and GNU sed.
if [ "${SKIP_LANDING_UPDATE:-0}" = "1" ]; then
  landing_updated=0
elif [ ! -f "$landing_html" ]; then
  echo "release-upload: landing page not found at $landing_html; skipping rewrite (set LANDING_HTML or SKIP_LANDING_UPDATE=1)" >&2
  landing_updated=0
else
  echo "updating $landing_html to point at $public_base/$prefix/ ..."
  base_re=$(printf '%s' "$public_base" | sed 's|\.|\\.|g')
  prefix_repl=$(printf '%s' "$prefix" | sed 's|[\&|]|\\&|g')
  sed -E -i.bak \
    "s|(\"${base_re}/)[^\"']*(secret-[A-Za-z0-9._-]+\\.tar\\.gz)|\\1${prefix_repl}/\\2|g" \
    "$landing_html"
  rm -f "${landing_html}.bak"
  landing_updated=1
fi

echo "done. published:"
for f in "$DIST/${BINARY}"-*.tar.gz "$DIST/SHA256SUMS"; do
  [ -e "$f" ] || continue
  base="$(basename "$f")"
  echo "  $public_base/$prefix/$base"
done

if [ "$landing_updated" = "1" ]; then
  echo "landing page rewritten. download links now point to $VERSION:"
  grep -oE "\"${public_base//./\\.}/[^\"']*\\.tar\\.gz\"" "$landing_html" \
    | sort -u \
    | sed 's/^/  /; s/"//g' || true
  echo "deploy $landing_html to publish the change."
fi
