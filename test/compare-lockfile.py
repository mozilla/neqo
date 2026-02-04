#!/usr/bin/env python3
# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

"""
Compare Cargo.lock versions with Gecko's and report alignment status.

This script provides a detailed comparison of all package versions between
our Cargo.lock and Firefox/Gecko's Cargo.lock, identifying matches and
mismatches while accounting for 999-version patches.

Usage: Run from the workspace root (not inside test/).
"""

import sys

from lockfile_utils import (
    find_dependents,
    find_dev_only_packages,
    find_neqo_only_deps,
    get_all_versions,
    load_lockfiles,
    semver_range,
)


def main():
    """Compare Cargo.lock versions with Gecko's and report alignment status."""
    our_lock, gecko_lock = load_lockfiles()

    gecko_versions = get_all_versions(gecko_lock)
    our_versions = get_all_versions(our_lock)

    common = sorted(set(gecko_versions) & set(our_versions))

    print(f"Comparing {len(common)} common packages:\n")
    print(f"{'Package':<30} {'Our Version(s)':<25} {'Gecko Version(s)':<25} {'Status'}")
    print("=" * 110)

    mismatches = []
    matches = []

    for name in common:
        ours = our_versions[name]
        theirs = gecko_versions[name]

        our_vers = set(v for v, s in ours)
        their_vers = set(v for v, s in theirs)

        our_str = ", ".join(sorted(our_vers))
        their_str = ", ".join(sorted(their_vers))

        their_ranges = {semver_range(v) for v in their_vers}

        # Track issues with the specific mismatched version
        issues: list[tuple[str, str, str | None]] = (
            []
        )  # (description, our_ver, gecko_ver)

        for v, s in ours:
            sv_range = semver_range(v)
            gecko_in_range = [gv for gv, gs in theirs if gv.startswith(sv_range)]

            if not gecko_in_range:
                if sv_range not in their_ranges:
                    issues.append(
                        (f"we have {v}, Gecko doesn't have {sv_range}.x", v, None)
                    )
            else:
                gecko_ver = gecko_in_range[0]
                if v != gecko_ver:
                    if "999" not in v and "999" not in gecko_ver:
                        issues.append((f"{v} vs {gecko_ver}", v, gecko_ver))

        if issues:
            status = "✗ " + "; ".join(desc for desc, _, _ in issues)
            mismatches.append((name, our_str, their_str, status, issues))
        else:
            matches.append((name, our_str, their_str))

    for name, our_str, their_str in matches:
        print(f"{name:<30} {our_str:<25} {their_str:<25} ✓ Match")

    if mismatches:
        print(f"\n{'=' * 110}")
        print(f"MISMATCHES ({len(mismatches)}):")
        print(f"{'=' * 110}")

        dev_only = find_dev_only_packages()
        neqo_only = find_neqo_only_deps(gecko_lock, our_lock)

        neqo_only_count = 0
        dev_mismatch_count = 0
        prod_mismatch_count = 0

        for name, our_str, their_str, status, issues in mismatches:
            # Determine the category for this mismatch.
            if name in neqo_only:
                category = "neqo-only"
                neqo_only_count += 1
            else:
                # Check if it's dev-only.
                is_dev_only = True
                for desc, our_ver, gecko_ver in issues:
                    dependents = find_dependents(our_lock, name, our_ver)
                    if not dependents:
                        dependents = find_dependents(our_lock, name)
                    all_dev = all(d.split()[0] in dev_only for d in dependents)
                    if not all_dev:
                        is_dev_only = False
                        break

                if is_dev_only:
                    category = "dev/build only"
                    dev_mismatch_count += 1
                else:
                    category = "PRODUCTION"
                    prod_mismatch_count += 1

            print(f"{name:<30} {our_str:<25} {their_str:<25} {status}")
            print(f"  ({category})")

        print(f"\nSummary: {len(matches)} matches, {len(mismatches)} mismatches")
        print(f"  - {neqo_only_count} neqo-only (we updated, Gecko will get on next vendor)")
        print(f"  - {dev_mismatch_count} dev/build-only (don't affect Gecko)")
        print(f"  - {prod_mismatch_count} production (need attention)")

        if prod_mismatch_count > 0:
            sys.exit(1)
    else:
        print(f"\nAll {len(matches)} common packages match!")


if __name__ == "__main__":
    main()
