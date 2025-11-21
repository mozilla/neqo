#! /usr/bin/env bash

set -euo pipefail

# First, let's run the test suite to generate initial fuzzing corpora.
# This will have failing tests, ignore them.
cargo test --quiet --features build-fuzzing-corpus --no-fail-fast || true

# Now, minimize the the various corpora.
for fuzzer in $(cargo fuzz list); do
    corpus="fuzz/corpus/$fuzzer"
    before=$(find "$corpus" | wc -l | tr -d ' ')
    cargo fuzz cmin "$fuzzer"
    after=$(find "$corpus" | wc -l | tr -d ' ')
    echo "Minimized corpus for $fuzzer: $before -> $after files"
    echo
done
