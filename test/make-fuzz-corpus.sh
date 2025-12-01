#!/usr/bin/env bash

set -euo pipefail

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# First, let's run the test suite to generate initial fuzzing corpora.
# This will have failing tests, ignore them.
echo "Generating new fuzzing corpora under $TMP..."
RUST_BACKTRACE=0 NEQO_CORPUS=$TMP \
    cargo test --quiet --locked --features build-fuzzing-corpus --no-fail-fast || true

# Do dev builds, since we just merge corpora and don't actually run fuzzers here.
# LTO-linking otherwise takes longer than the merging.
echo "Building all fuzzers..."
cargo fuzz build --dev

# Now, only merge in those newly-generated samples that increase coverage.
# "cargo fuzz" cannot do this, so use the underlying LLVM fuzzer binary directly.
TRIPLE="$(rustc --print host-tuple)"
for fuzzer in $(cargo fuzz list); do
    echo
    generated="$TMP/$fuzzer"
    if [ ! -d "$generated" ]; then
        echo "$fuzzer fuzzer: WARNING, test suite generated no corpus"
        continue
    fi
    corpus="fuzz/corpus/$fuzzer"
    mkdir -p "$corpus" # In case we have a new fuzzer with no existing corpus.
    before=$(find "$corpus" -type f | wc -l | tr -d ' ')
    echo "$fuzzer fuzzer: Merging new unique samples into corpus ($before samples currently)..."
    "target/$TRIPLE/debug/$fuzzer" -detect_leaks=0 -merge=1 "$corpus" "$generated"
    after=$(find "$corpus" -type f | wc -l | tr -d ' ')
    diff=$((after - before))
    echo "$fuzzer fuzzer: $diff new samples added (now $after)"
done
