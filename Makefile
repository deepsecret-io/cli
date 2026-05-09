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
	linux/arm64 \
	linux/arm/7

.PHONY: all build release clean platforms platforms-all checksums

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
			linux/arm/7)    label=linux-armv7 ;; \
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
