#!/usr/bin/env bash
# The Linux checks of rustfmt.yml, clippy.yml and check.yml, on the default toolchain and without coverage.
set -euo pipefail
cd "$(dirname "$0")/.."

export RUST_BACKTRACE=1 RUST_TEST_TIME_UNIT=10,30 RUST_TEST_TIME_INTEGRATION=10,30 RUST_TEST_TIME_DOCTEST=10,30

cargo +nightly fmt --all -- --check

cargo hack clippy --locked --feature-powerset --all-targets --exclude-features gecko,ci \
    --mutually-exclusive-features bench,blapi,build-fuzzing-corpus,default,disable-encryption -- -D warnings
RUSTFLAGS="--cfg fuzzing ${RUSTFLAGS:-}" cargo clippy --locked -p fuzz --bins -- -D warnings
RUSTDOCFLAGS="--deny rustdoc::broken_intra_doc_links --deny warnings" \
    cargo doc --locked --workspace --no-deps --document-private-items

# mtu tests need GitHub Actions.
RUST_LOG=debug cargo test --locked --workspace --exclude mtu
RUST_LOG=debug cargo hack test --locked --workspace --exclude mtu --feature-powerset --tests \
    --exclude-features gecko,ci,build-fuzzing-corpus --mutually-exclusive-features bench,blapi,default,disable-encryption
