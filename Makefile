# cbase CLI — task runner: build/test/lint/fmt/clean/install, a cheap `smoke`
# check, and an aggregate `verify` gate. Thin wrappers over cargo so a green
# local run predicts a green CI run.

BIN := cbase
CARGO := cargo
# Where cargo builds: honours a shared CARGO_TARGET_DIR.
TARGET_DIR := $(or $(CARGO_TARGET_DIR),target)
VERSION := $(shell sed -n 's/^version = "\(.*\)"$$/\1/p' Cargo.toml | head -1)

# The MCP tools as a WebAssembly module for the deploy-your-own Cloudflare
# Worker (cli-common's connector/): the library alone, feature `wasm`.
WASM_TARGET := wasm32-unknown-unknown
WASM_FLAGS := --lib --target $(WASM_TARGET) --no-default-features --features wasm
WASM_OUT := $(TARGET_DIR)/$(WASM_TARGET)/release/cbase.wasm

.PHONY: all build release test lint fmt fmt-check clean install deps smoke verify dev wasm wasm-check

all: verify

build:
	$(CARGO) build

# Signed like `install`: `smoke` runs this binary against the real keychain
# (`auth status`), and an ad-hoc-signed release build is a brand-new code
# identity every rebuild -- each `make verify` would throw fresh "Always
# Allow" prompts, one per keychain entry. Signed with the stable identity,
# the grant made for the installed binary covers this one too.
release: SIGN_TARGET = $(TARGET_DIR)/release/$(BIN)
release:
	$(CARGO) build --release
	@$(SIGN)

# `wasm` adds the Worker module's tests (tests/worker.rs) to the native run.
test:
	$(CARGO) test --all --features wasm

lint:
	$(CARGO) clippy --all-targets -- -D warnings
	$(CARGO) clippy --all-targets --features wasm -- -D warnings

# The Worker module type-checks and lints for its real target.
wasm-check:
	$(CARGO) clippy $(WASM_FLAGS) -- -D warnings

# Build the module the release attaches as cbase-mcp-<version>.wasm, and check
# it against the host's contract (scripts/check-wasm.mjs; needs Node).
wasm:
	$(CARGO) rustc $(WASM_FLAGS) --crate-type cdylib --release --locked
	node scripts/check-wasm.mjs $(WASM_OUT) $(VERSION)

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

clean:
	$(CARGO) clean

# `cargo install` ad-hoc signs, which gives the binary a *new* code identity
# every time. macOS scopes keychain "Always Allow" grants to that identity, so
# an unsigned reinstall silently revokes them and the next run prompts again.
# Re-signing with the stable shared identity keeps one grant valid across every
# future install.
install: SIGN_TARGET = $${CARGO_INSTALL_ROOT:-$$HOME/.cargo}/bin/$(BIN)
install:
	$(CARGO) install --path . --force --locked
	@$(SIGN)

deps:
	$(CARGO) fetch

# Debug build re-signed with the same stable identity, so the dev loop doesn't
# re-prompt either.
dev: SIGN_TARGET = $(TARGET_DIR)/debug/$(BIN)
dev:
	cargo build
	@$(SIGN)

# Shared re-signing step. No-ops with a note when the helper or identity is
# absent (CI, Linux, a fresh machine that hasn't run setup-dev-signing.sh).
define SIGN
if [ -x "$$HOME/Dev/cli-common/scripts/dev-sign.sh" ]; then \
	"$$HOME/Dev/cli-common/scripts/dev-sign.sh" "$(SIGN_TARGET)"; \
else echo "cli-common/scripts/dev-sign.sh not found — $(SIGN_TARGET) left ad-hoc signed"; fi
endef

# Cheap sanity checks needing no credential or network: version, help, and the
# discovery commands that answer without a key.
smoke: release
	$(TARGET_DIR)/release/$(BIN) --version
	$(TARGET_DIR)/release/$(BIN) --help > /dev/null
	$(TARGET_DIR)/release/$(BIN) info > /dev/null
	$(TARGET_DIR)/release/$(BIN) mcp --list-tools > /dev/null
	$(TARGET_DIR)/release/$(BIN) auth status --json > /dev/null

verify: fmt-check lint test wasm-check smoke
