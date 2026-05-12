# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 DeepSecret

BINARY  := secret
PKG     := .
DIST    := dist
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

# Release matrix. Format: os/arch[/goarm]. The optional third field sets GOARM
# (only meaningful for linux/arm). `go tool dist list` prints every (GOOS,
# GOARCH) pair Go knows about; `make platforms-all` runs it.
PLATFORMS := \
	darwin/arm64 \
	darwin/amd64 \
	linux/amd64 \
	linux/arm64

# R2 upload config. Auth comes from R2_ACCESS_KEY_ID / R2_SECRET_ACCESS_KEY,
# falling back to AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY so this also works
# from a workstation already configured for AWS. R2_BUCKET and R2_ACCOUNT_ID
# are required (no sensible defaults; must point at your tenant).
# R2_PREFIX controls the in-bucket key prefix; the default groups CLI uploads
# under cli/<version>/ so multiple versions can coexist in one bucket.
R2_ACCOUNT_ID ?=
R2_BUCKET     ?=
R2_PREFIX     ?= cli/$(VERSION)
R2_ENDPOINT   ?= https://$(R2_ACCOUNT_ID).r2.cloudflarestorage.com

.PHONY: all build release release-upload clean platforms platforms-all checksums

all: build

# Native build for the host.
build:
	@mkdir -p $(DIST)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY) $(PKG)
	@echo "built $(DIST)/$(BINARY)"

# Cross-compile for every entry in $(PLATFORMS) and package each as .tar.gz.
# Failed builds (e.g. cgo on an unsupported arch) print a warning and are
# skipped; the rest continue.
release: clean
	@mkdir -p $(DIST)
	@set -e; for p in $(PLATFORMS); do \
		os=$$(echo "$$p" | cut -d/ -f1); \
		arch=$$(echo "$$p" | cut -d/ -f2); \
		goarm=$$(echo "$$p" | cut -s -d/ -f3); \
		case "$$os/$$arch$${goarm:+/$$goarm}" in \
			darwin/arm64)   label=macos-arm64 ;; \
			darwin/amd64)   label=macos-x86_64 ;; \
			linux/amd64)    label=linux-x86_64 ;; \
			linux/arm64)    label=linux-arm64 ;; \
			*)              label="$$os-$$arch$${goarm:+v$$goarm}" ;; \
		esac; \
		stage="$(DIST)/$(BINARY)-$$label"; \
		mkdir -p "$$stage"; \
		printf "  %-18s -> %s.tar.gz\n" "$$os/$$arch$${goarm:+v$$goarm}" "$$stage"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch GOARM=$$goarm \
			go build -trimpath -ldflags "$(LDFLAGS)" -o "$$stage/$(BINARY)" $(PKG) \
			|| { echo "    skip ($$os/$$arch$${goarm:+v$$goarm} failed)"; rm -rf "$$stage"; continue; }; \
		cp LICENSE "$$stage/" 2>/dev/null || true; \
		tar -C "$(DIST)" -czf "$$stage.tar.gz" "$(BINARY)-$$label"; \
		rm -rf "$$stage"; \
	done
	@$(MAKE) --no-print-directory checksums

# Build a fresh release and upload every archive + SHA256SUMS to R2 under
# $(R2_PREFIX)/. Refuses to push a -dirty version so an in-progress edit can't
# overwrite a tagged build. Requires the `aws` CLI; R2 speaks S3 so the same
# binary works against a Cloudflare endpoint with --endpoint-url.
#
# Usage:
#   R2_ACCOUNT_ID=<id> R2_BUCKET=<name> \
#   R2_ACCESS_KEY_ID=<key> R2_SECRET_ACCESS_KEY=<secret> \
#   make release-upload
release-upload: release
	@command -v aws >/dev/null 2>&1 || { echo "release-upload: aws CLI not found (install: https://aws.amazon.com/cli/)"; exit 1; }
	@test -n "$(R2_ACCOUNT_ID)" || { echo "release-upload: R2_ACCOUNT_ID is required"; exit 1; }
	@test -n "$(R2_BUCKET)"     || { echo "release-upload: R2_BUCKET is required"; exit 1; }
	@case "$(VERSION)" in *-dirty) echo "release-upload: refusing to upload dirty version $(VERSION); commit or stash first"; exit 1 ;; esac
	@key_id="$${R2_ACCESS_KEY_ID:-$$AWS_ACCESS_KEY_ID}"; \
	 key_secret="$${R2_SECRET_ACCESS_KEY:-$$AWS_SECRET_ACCESS_KEY}"; \
	 test -n "$$key_id" -a -n "$$key_secret" || { echo "release-upload: R2_ACCESS_KEY_ID/R2_SECRET_ACCESS_KEY (or AWS_*) must be set"; exit 1; }; \
	 echo "uploading $(VERSION) to s3://$(R2_BUCKET)/$(R2_PREFIX)/ ..."; \
	 AWS_ACCESS_KEY_ID="$$key_id" AWS_SECRET_ACCESS_KEY="$$key_secret" AWS_DEFAULT_REGION=auto \
	   aws s3 cp $(DIST)/ "s3://$(R2_BUCKET)/$(R2_PREFIX)/" \
	     --endpoint-url "$(R2_ENDPOINT)" \
	     --recursive \
	     --exclude "*" \
	     --include "$(BINARY)-*.tar.gz" \
	     --include "SHA256SUMS" \
	     --checksum-algorithm CRC32 \
	     --only-show-errors
	@echo "done. published:"
	@for f in $(DIST)/$(BINARY)-*.tar.gz $(DIST)/SHA256SUMS; do \
		[ -e "$$f" ] || continue; \
		echo "  s3://$(R2_BUCKET)/$(R2_PREFIX)/$$(basename $$f)"; \
	done

# Generate SHA-256 checksums for every archive in $(DIST).
checksums:
	@cd $(DIST) && \
		(command -v shasum >/dev/null && shasum -a 256 $(BINARY)-*.tar.gz > SHA256SUMS \
		 || sha256sum $(BINARY)-*.tar.gz > SHA256SUMS) && \
		echo "wrote $(DIST)/SHA256SUMS"

# Print the platform list this Makefile builds for.
platforms:
	@for p in $(PLATFORMS); do echo "$$p"; done

# Print every platform Go knows about (for picking new entries).
platforms-all:
	@go tool dist list

clean:
	@rm -rf $(DIST)
	@echo "cleaned $(DIST)"
