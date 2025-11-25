#!/usr/bin/env bash

set -euo pipefail

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# First, let's run the test suite to generate initial fuzzing corpora.
# This will have failing tests, ignore them.
echo "Generating new fuzzing corpora under $TMP..."
NEQO_CORPUS=$TMP cargo test --quiet --locked --features build-fuzzing-corpus --no-fail-fast > /dev/null 2>&1 || true

# Do dev builds, since we just merge corpora and don't actually run fuzzers here.
# LTO-linking otherwise takes longer than the merging.
echo "Building all fuzzers..."
cargo fuzz build --dev > /dev/null 2>&1

# Now, only merge in those newly-generated samples that increase coverage.
# "cargo fuzz" cannot do this, so use the underlying LLVM fuzzer binary directly.
TRIPLE="$(basename "$(dirname "$(rustc --print target-libdir)")")"
for fuzzer in $(cargo fuzz list); do
    generated="$TMP/$fuzzer"
    if [ ! -d "$generated" ]; then
        echo "$fuzzer fuzzer: WARNING, test suite generated no corpus"
        continue
    fi
    corpus="fuzz/corpus/$fuzzer"
    before=$(find "$corpus" -type f | wc -l | tr -d ' ')
    echo "$fuzzer fuzzer: Merging new unique samples into corpus ($before samples currently)..."
    "target/$TRIPLE/debug/$fuzzer" -merge=1 "$corpus" "$generated" 2> /dev/null
    after=$(find "$corpus" -type f | wc -l | tr -d ' ')
    diff=$((after - before))
    echo "$fuzzer fuzzer: $diff new samples added (now $after)"
done
