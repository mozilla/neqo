#!/usr/bin/env bash
set -euo pipefail

# This needs
# https://github.com/larseggert/check-lockfile-intersection/tree/feat-use-largest-version
# installed (while https://github.com/graydon/check-lockfile-intersection has
# not merged my PR.) Execute at the workspace root, i.e., not inside `test`. It
# will spit out a list of `cargo update` commands to apply.

if ! command -v check-lockfile-intersection >/dev/null 2>&1; then
    echo "Error: check-lockfile-intersection is not installed or not in PATH." >&2
    exit 1
fi

check-lockfile-intersection \
    https://raw.githubusercontent.com/mozilla-firefox/firefox/refs/heads/main/Cargo.lock \
    Cargo.lock 2>/dev/null | while read -r line; do
        # Skip informational lines (not commands or comments)
        if [[ "$line" != "cargo update"* && "$line" != "#"* ]]; then
            continue
        fi
        # Skip .999 versions
        if [[ "$line" == *".999" ]]; then
            echo "# Skipping due to .999: ${line#cargo update -p }"
            continue
        fi
        echo "$line"
done
