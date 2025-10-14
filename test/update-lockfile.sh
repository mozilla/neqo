#!/usr/bin/env bash
set -euo pipefail

# This needs https://github.com/graydon/check-lockfile-intersection installed.
# Execute at the workspace root, i.e., not inside `test`. It will spit out a
# list of `cargo update` commands to apply.
#
# check-lockfile-intersection doesn't deal with deps that exist in multiple
# versions, so those are excluded below and will hence need manually updating in
# `Cargo.lock`. It also doesn't deal with Gecko's ".999" version patching scheme,
# so some updates will just fail.

if ! command -v check-lockfile-intersection >/dev/null 2>&1; then
    echo "Error: check-lockfile-intersection is not installed or not in PATH." >&2
    exit 1
fi
check-lockfile-intersection \
    --exclude-pkg-a wasi,thiserror,rustc-hash,itertools,base64,bindgen,bitflags,getrandom,half,hashbrown \
    https://raw.githubusercontent.com/mozilla-firefox/firefox/refs/heads/main/Cargo.lock \
    Cargo.lock |\
        grep 'path A' |\
        cut -d: -f2 |\
        sed -E -e 's/(.*)@(.*)/cargo update \1 --precise \2/g'
