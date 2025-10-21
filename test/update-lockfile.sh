#!/usr/bin/env bash
set -euo pipefail

# This needs
# https://github.com/larseggert/check-lockfile-intersection/tree/feat-use-largest-version
# installed (while https://github.com/graydon/check-lockfile-intersection has
# not merged my PR.) Execute at the workspace root, i.e., not inside `test`. It
# will spit out a list of `cargo update` commands to apply.
#
# check-lockfile-intersection doesn't deal with deps that exist in multiple
# versions, so those are excluded below and will hence need manually updating in
# `Cargo.lock`. It also doesn't deal with Gecko's ".999" version patching
# scheme, so some updates will just fail.

if ! command -v check-lockfile-intersection >/dev/null 2>&1; then
    echo "Error: check-lockfile-intersection is not installed or not in PATH." >&2
    exit 1
fi

check-lockfile-intersection \
    https://raw.githubusercontent.com/mozilla-firefox/firefox/refs/heads/main/Cargo.lock \
    Cargo.lock 2> /dev/null | grep DIFFERENT | while read -r d ; do
        crate=$(echo "$d" | cut -d' ' -f2)
        version_a=$(echo "$d" | cut -d' ' -f3)
        version_b=$(echo "$d" | cut -d' ' -f5)
        # echo "Found differing versions for $crate: $version_a vs $version_b"
        # If version_a > version_b, then we want to update to version_a.
        if sort --version-sort <<<"$version_a"$'\n'"$version_b" | head -n1 | grep -q "^$version_b$"; then
            # But only if the version isn't ending in .999
            if echo "$version_a" | grep -q '\.999$'; then
                echo "# Skipping due to .999: cargo update -p $crate --precise $version_a"
            else
                echo "cargo update -p $crate --precise $version_a"
            fi
        fi
done
