#!/usr/bin/env bash

set -euo pipefail

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

TRIPLE="$(rustc --print host-tuple)"

# Minimize a corpus until the sample count stabilizes.
# Args: $1 = fuzzer name, $2 = corpus directory
#
# We shouldn;t need to do this, since merging one corpus into another
# should automatically minimize, but in practice it seems not to.
# @choller said this is likely because we have not been able to eliminate
# all randomization from the test suite.
minimize_corpus() {
    local fuzzer="$1"
    local corpus="$2"
    local minimize_tmp
    minimize_tmp=$(mktemp -d)

    local prev_count new_count
    prev_count=$(find "$corpus" -type f | wc -l | tr -d ' ')
    while
        "target/$TRIPLE/debug/$fuzzer" -detect_leaks=0 -merge=1 "$minimize_tmp" "$corpus"
        rm -rf "$corpus"
        mv "$minimize_tmp" "$corpus"
        minimize_tmp=$(mktemp -d)
        new_count=$(find "$corpus" -type f | wc -l | tr -d ' ')
        [ "$new_count" -lt "$prev_count" ]
    do
        echo "$fuzzer fuzzer: Minimized from $prev_count to $new_count samples, continuing..."
        prev_count=$new_count
    done
    rm -rf "$minimize_tmp"
}

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
for fuzzer in $(cargo fuzz list); do
    echo
    generated="$TMP/$fuzzer"
    if [ ! -d "$generated" ]; then
        echo "$fuzzer fuzzer: WARNING, test suite generated no corpus"
        continue
    fi
    corpus="fuzz/corpus/$fuzzer"
    mkdir -p "$corpus" # In case we have a new fuzzer with no existing corpus.

    # Minimize the newly generated corpus before merging.
    generated_count=$(find "$generated" -type f | wc -l | tr -d ' ')
    echo "$fuzzer fuzzer: Minimizing $generated_count newly generated samples..."
    minimize_corpus "$fuzzer" "$generated"
    minimized_count=$(find "$generated" -type f | wc -l | tr -d ' ')
    echo "$fuzzer fuzzer: Minimized to $minimized_count samples"

    before=$(find "$corpus" -type f | wc -l | tr -d ' ')
    echo "$fuzzer fuzzer: Merging into corpus ($before samples currently)..."
    "target/$TRIPLE/debug/$fuzzer" -detect_leaks=0 -merge=1 "$corpus" "$generated"
    after=$(find "$corpus" -type f | wc -l | tr -d ' ')
    diff=$((after - before))
    echo "$fuzzer fuzzer: $diff new samples added (now $after)"

    # Minimize the merged corpus.
    echo "$fuzzer fuzzer: Minimizing merged corpus..."
    minimize_corpus "$fuzzer" "$corpus"
    final=$(find "$corpus" -type f | wc -l | tr -d ' ')
    echo "$fuzzer fuzzer: Final corpus size: $final samples"
done
