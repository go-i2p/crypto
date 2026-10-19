RELEASE_TAG=0.0.1
RELEASE_VERSION=${RELEASE_TAG}
REPO := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
CGO_ENABLED=0
export DEBUG_I2P=debug

ifdef GOROOT
	GO = $(GOROOT)/bin/go
endif

GO ?= $(shell which go)

#check for gofumpt
check_gofumpt:
	@which gofumpt > /dev/null 2>&1 || (echo "gofumpt is required but not installed. Please install it from https://github.com/mvdan/gofumpt."; exit 1)

# This module is a library: there is no main package, so "build" compiles all
# packages rather than linking a binary.
build:
	$(GO) build ./...

test:
	$(GO) test ./...

test-race:
	$(GO) test -race -coverprofile=coverage.out ./...

cover: test-race
	$(GO) tool cover -func=coverage.out

vet:
	$(GO) vet ./...

lint: check_gofumpt
	@if [ -n "$$(gofumpt -l .)" ]; then \
		echo "Code is not formatted with gofumpt:"; \
		gofumpt -l .; \
		exit 1; \
	fi

.PHONY: build test test-race cover vet lint fmt clean info release godoc check_gofumpt

clean:
	$(GO) clean
	rm -f coverage.out

fmt: check_gofumpt
	find . -name '*.go' -exec gofumpt -w {} \;

info:
	echo "GOROOT: ${GOROOT}"
	echo "GO: ${GO}"
	echo "REPO: ${REPO}"

release:
	github-release release -u go-i2p -r crypto -n "${RELEASE_VERSION}" -t "${RELEASE_TAG}" -p

godoc:
	./callgraph.sh
