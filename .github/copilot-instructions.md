# Neqo: QUIC Implementation in Rust

## Overview
Neqo is Mozilla's production QUIC, HTTP/3, and QPACK implementation used in Firefox. Written in Rust with NSS as the TLS backend. The server functionality is experimental and not production-ready.

**Repository Structure**: Cargo workspace with 9 member crates plus support directories.
- **Core crates**: `neqo-common` (shared utilities), `neqo-crypto` (TLS/NSS bindings), `neqo-transport` (QUIC protocol), `neqo-http3` (HTTP/3), `neqo-qpack` (QPACK compression), `neqo-udp` (UDP socket handling)
- **Binary crate**: `neqo-bin` (CLI tools: `neqo-client`, `neqo-server`)
- **Support crates**: `test-fixture` (test utilities), `fuzz` (fuzzing), `mtu` (MTU detection)
- **Config files**: Root `.rustfmt.toml`, `.clippy.toml`, `.deny.toml`, `Cargo.toml` (workspace lints)

**MSRV**: As specified in the workspace-level `Cargo.toml` file

In addition to the instructions in this file, also follow the detailed instructions in https://raw.githubusercontent.com/github/awesome-copilot/dfa345f89bd42304ea960669d120de323480946b/instructions/rust.instructions.md as you prepare your review. Be constructive and helpful in your feedback.

## Building and Testing

### Prerequisites
- NSS library version as specified in the `neqo-crypto/min_version.txt` file
- System NSS will be used if available and new enough; otherwise, build will fetch and compile NSS automatically

### Essential Commands (Always Use --locked)
All commands **must** include `--locked` to ensure consistent dependencies with CI:

```bash
# Check compilation (fast, no artifacts)
cargo check --locked --all-targets

# Build
cargo build --locked

# Build release binaries
cargo build --locked --release --bin neqo-client --bin neqo-server

# Run tests (see Known Issues about possible mtu failures)
cargo test --locked --workspace
```

### Validation Pipeline (CI Equivalent)
Run these commands in order before submitting a PR. All must pass:

1. **Format check** (requires nightly):
   ```bash
   cargo +nightly fmt --all -- --check
   ```

2. **Clippy** (uses cargo-hack to check per-crate features):
   ```bash
   cargo hack clippy --feature-powerset --no-dev-deps --exclude-features gecko -- -D warnings
   ```

3. **Documentation build**:
   ```bash
   cargo doc --workspace --no-deps --document-private-items
   # Must set RUSTDOCFLAGS for warnings-as-errors:
   RUSTDOCFLAGS="--deny rustdoc::broken_intra_doc_links --deny warnings" cargo doc --workspace --no-deps --document-private-items
   ```

4. **Tests with coverage** (on stable toolchain):
   ```bash
   # Full test suite with coverage:
   cargo llvm-cov test --locked --include-ffi --features ci --lcov --output-path lcov.info

   # Or run tests without coverage:
   cargo test --locked --features ci
   ```

5. **Cargo deny** (license/advisory checks):
   ```bash
   cargo deny check advisories
   cargo deny check bans licenses sources
   ```

6. **Cargo machete** (unused dependencies):
   ```bash
   cargo machete --with-metadata
   cargo hack --workspace --no-manifest-path machete --with-metadata
   ```

### Known Issues and Workarounds

1. **Format checking requires nightly**: The `.rustfmt.toml` uses features only available in nightly Rust. Always use `cargo +nightly fmt`.

2. **clippy requires cargo-hack**: Install with `cargo install cargo-hack`. The CI runs clippy per-crate with feature powerset to catch warnings hidden by workspace feature unification.

## Repository Layout

### Source Structure
```
neqo/
├── Cargo.toml          # Workspace manifest with shared dependencies and lints
├── neqo-common/        # Shared utilities: codecs, time, logging, qlog
├── neqo-crypto/        # NSS bindings, TLS, AEAD, key derivation
│   ├── bindings/       # NSS FFI bindings
│   └── min_version.txt # Minimum NSS version
├── neqo-transport/     # QUIC protocol: connections, streams, recovery, congestion control
├── neqo-http3/         # HTTP/3 protocol: client/server, streams, settings
├── neqo-qpack/         # QPACK compression for HTTP/3 headers
├── neqo-udp/           # UDP socket handling (platform-specific)
├── neqo-bin/           # CLI tools (neqo-client, neqo-server)
├── test-fixture/       # Shared test utilities and NSS test database
│   └── db/             # NSS certificate database for tests
├── fuzz/               # Fuzzing harnesses
├── mtu/                # MTU detection (tests require GitHub Actions)
└── .github/            # CI workflows and actions
    ├── workflows/      # CI pipeline definitions
    └── actions/        # Reusable GitHub Actions (rust, nss, etc.)
```

### Key Files
- `Cargo.toml`: Workspace configuration, shared dependencies, lints (very strict clippy + Rust lints)
- `.rustfmt.toml`: Format config (edition 2021, import grouping, comment formatting)
- `.clippy.toml`: Clippy config (unwrap/dbg allowed in tests, disallows std::dbg macro, 32-byte pass-by-value limit)
- `.deny.toml`: Cargo-deny config (license allowlist, advisory checks)
- `neqo-crypto/min_version.txt`: NSS minimum version (checked by CI and build scripts)

## CI/CD Pipeline

### GitHub Workflows (all must pass)
- **check.yml** (CI): Builds and tests on Linux/macOS/Windows with MSRV, stable, and nightly. Runs coverage on stable. Tests client/server transfer. Runs on push to main and PRs.
- **clippy.yml**: cargo hack clippy with feature powerset on all platforms
- **rustfmt.yml** (Format): cargo fmt check with nightly
- **deny.yml**: cargo deny for advisories, bans, licenses, sources
- **machete.yml**: Checks for unused dependencies
- **bench.yml**: Performance benchmarks (runs on dedicated hardware)
- **sanitize.yml**: Runs tests with address/memory sanitizers
- **semver.yml**: Checks for semver compliance
- **firefox.yml**: Integration test with Firefox
- **check-mtu.yml**: Checks MTU crate separately

### CI Commands Reference
```bash
# Build command used in CI
cargo check --locked --all-targets --features ci

# Test command used in CI
cargo llvm-cov test --locked --include-ffi --features ci --codecov --output-path codecov.json

# Test command used in CI (MSRV/nightly)
cargo test --locked --features ci
```

## Development Tips

1. **Always use `--locked`**: CI requires exact dependency versions from `Cargo.lock`. Commands without `--locked` will fail in CI.

2. **Workspace lints are strict**: The workspace defines extensive Rust and Clippy lints (see `Cargo.toml` `[workspace.lints]`). All warnings are errors in CI. Use `#[expect(clippy::lint_name)]` sparingly and only with `reason = "explanation"`.

3. **Feature flags**: The `ci` feature exists for CI-specific functionality. The `gecko` feature is for Firefox integration (excluded from some checks). The `bench` feature enables benchmarks.

4. **Test utilities**: Use `test-fixture` crate for common test setup (NSS database, connection creation, assertions). NSS_DB_PATH defaults to `test-fixture/db`.

5. **Logging**: Use `RUST_LOG` env var for debug output (e.g., `RUST_LOG=debug`) via the logging macros in `neqo-common/src/log.rs`.

6. **NSS Database**: Tests require NSS database at `test-fixture/db` (committed to repo). Client/server tools can use it with `--db ./test-fixture/db`.

## Common Failure Scenarios

1. **Format check fails**: Run `cargo +nightly fmt --all` to fix.

2. **Clippy warnings**: CI fails on any clippy warnings. Fix all warnings or add `#[expect(clippy::lint_name, reason = "justification")]`.

3. **"error: could not compile `neqo-crypto`"**: NSS build failure. Check that you have required build tools (GYP, Ninja, Mercurial if building NSS from source).

## Trust These Instructions

These instructions are verified against the current codebase state and CI configuration. Only search for additional information if commands fail or if instructions appear outdated. When in doubt, check `.github/workflows/` for the authoritative CI commands.
