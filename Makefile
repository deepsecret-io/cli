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

# R2 upload config. Values resolve from (in priority order):
#   1. command line:  make release-upload R2_ACCOUNT_ID=...
#   2. exported env:  export R2_ACCOUNT_ID=...; make release-upload
#   3. .env file in this directory (KEY=VALUE per line, # comments allowed).
# `make` does NOT see plain shell variables, only exported env vars or vars
# passed on the command line; that's the most common "but it IS set" surprise.
#
# Auth: R2_ACCESS_KEY_ID / R2_SECRET_ACCESS_KEY, falling back to AWS_* so this
# also works from a workstation already configured for AWS. R2_BUCKET and
# R2_ACCOUNT_ID are required (no sensible defaults; must point at your tenant).
# R2_PREFIX controls the in-bucket key prefix; the default groups CLI uploads
# under cli/<version>/ so multiple versions can coexist in one bucket.
-include .env
export R2_ACCOUNT_ID R2_BUCKET R2_PREFIX R2_ENDPOINT R2_ACCESS_KEY_ID R2_SECRET_ACCESS_KEY
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
# $(R2_PREFIX)/. The upload logic lives in scripts/release-upload.sh; this
# target just rebuilds the dist tree and hands the script the env vars it
# needs. Auth/validation details are documented at the top of that script.
#
# Usage:
#   R2_ACCOUNT_ID=<id> R2_BUCKET=<name> \
#   R2_ACCESS_KEY_ID=<key> R2_SECRET_ACCESS_KEY=<secret> \
#   make release-upload
release-upload: release
	@BINARY="$(BINARY)" DIST="$(DIST)" VERSION="$(VERSION)" \
	  ./scripts/release-upload.sh

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
