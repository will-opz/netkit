SHELL := /bin/sh
.DEFAULT_GOAL := all

BINARY := netkit
PACKAGE := ./cmd/netkit
BREW_FORMULA := will-opz/tap/netkit

.PHONY: all update build deploy test vet check fmt clean help

# "make" updates this checkout safely, then builds the executable.
all: update build

update:
	@git diff --quiet && git diff --cached --quiet || { echo "Working tree has uncommitted changes; aborting pull."; exit 1; }
	@git pull --ff-only

build:
	@go build -o $(BINARY) $(PACKAGE)
	@echo "Built ./$(BINARY)"


# Deploy the published Tap version; this does not install the local checkout.
# "make build" remains available for developing the current source.
deploy:
	@command -v brew >/dev/null 2>&1 || { echo "Homebrew is required: https://brew.sh"; exit 1; }
	@brew update
	@if brew list --versions "$(BREW_FORMULA)" | grep -q .; then \
	  brew upgrade "$(BREW_FORMULA)"; \
	else \
	  brew install "$(BREW_FORMULA)"; \
	fi
	@echo "Homebrew NetKit: $(brew --prefix "$(BREW_FORMULA)")/bin/netkit"

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
	@printf 'make deploy   install/upgrade published NetKit via Homebrew Tap\n'
	@printf 'make update   git pull --ff-only\n'
	@printf 'make check    go test and go vet\n'
	@printf 'make fmt      gofmt Go source files\n'
	@printf 'make clean    remove executable\n'
