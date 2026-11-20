SHELL := /bin/sh
.DEFAULT_GOAL := all

BINARY := netkit
PACKAGE := ./cmd/netkit

.PHONY: all update build test vet check fmt clean help

# "make" updates this checkout safely, then builds the executable.
all: update build

update:
	@git diff --quiet && git diff --cached --quiet || { echo "Working tree has uncommitted changes; aborting pull."; exit 1; }
	@git pull --ff-only

build:
	@go build -o $(BINARY) $(PACKAGE)
	@echo "Built ./$(BINARY)"

test:
	@go test ./...

vet:
	@go vet ./...

check: test vet

fmt:
	@gofmt -w cmd/netkit/*.go

clean:
	@rm -f $(BINARY)

help:
	@printf 'make          update (fast-forward only) and build\n'
	@printf 'make build    compile without pulling\n'
	@printf 'make update   git pull --ff-only\n'
	@printf 'make check    go test and go vet\n'
	@printf 'make fmt      gofmt Go source files\n'
	@printf 'make clean    remove executable\n'
