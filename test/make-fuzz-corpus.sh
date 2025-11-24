#!/usr/bin/env bash

set -euo pipefail

# First, let's run the test suite to generate initial fuzzing corpora.
# This will have failing tests, ignore them.
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
echo "Generating new fuzzing corpora under $TMP..."
NEQO_CORPUS=$TMP cargo test --quiet --locked --features build-fuzzing-corpus --no-fail-fast > /dev/null 2>&1 || true

# Now, only merge in those newly-generated samples that increase coverage.
# "cargo fuzz" cannot do this, so use the underlying LLVM fuzzer binary directly.
TRIPLE="$(basename "$(dirname "$(rustc --print target-libdir)")")"
for fuzzer in $(cargo fuzz list); do
    echo
    generated="$TMP/$fuzzer"
    if [ ! -d "$generated" ]; then
        echo "$fuzzer fuzzer: WARNING, test suite generated no corpus"
        continue
    fi
    echo "$fuzzer fuzzer: Building..."
    cargo fuzz build "$fuzzer" > /dev/null 2>&1
    corpus="fuzz/corpus/$fuzzer"
    before=$(find "$corpus" -type f | wc -l | tr -d ' ')
    echo "$fuzzer fuzzer: Merging new unique samples into corpus ($before samples before)..."
    "target/$TRIPLE/release/$fuzzer" -merge=1 "$corpus" "$generated" 2> /dev/null
    after=$(find "$corpus" -type f | wc -l | tr -d ' ')
    diff=$((after - before))
    echo "$fuzzer fuzzer: $diff new samples added (now $after)"
done
