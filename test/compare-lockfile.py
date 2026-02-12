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

from packaging.version import Version

from lockfile_utils import (
    find_dependents,
    find_dev_only_packages,
    find_neqo_or_workspace_deps,
    get_all_versions,
    group_by_semver_range,
    load_lockfiles,
    semver_range,
)


def find_version_issues(
    ours: list[tuple[str, str]], theirs: list[tuple[str, str]]
) -> list[tuple[str, str, str | None]]:
    """Find version mismatches between our and Gecko's versions of a package.

    Returns list of (description, our_ver, gecko_ver) tuples for each issue.
    """
    gecko_by_range = group_by_semver_range([v for v, _s in theirs])
    issues: list[tuple[str, str, str | None]] = []

    for v, _s in ours:
        sv_range = semver_range(v)
        gecko_in_range = gecko_by_range.get(sv_range, [])

        if not gecko_in_range:
            issues.append((f"we have {v}, Gecko doesn't have {sv_range}.x", v, None))
        else:
            gecko_ver = max(gecko_in_range, key=Version)
            if (
                v != gecko_ver
                and not v.endswith(".999")
                and not gecko_ver.endswith(".999")
            ):
                issues.append((f"{v} vs {gecko_ver}", v, gecko_ver))

    return issues


def compare_versions(
    our_versions: dict, gecko_versions: dict, common: list[str]
) -> tuple[list, list]:
    """Compare versions for common packages and classify as match or mismatch.

    Returns (matches, mismatches) where:
    - matches: [(name, our_str, their_str), ...]
    - mismatches: [(name, our_str, their_str, status, issues), ...]
    """
    mismatches = []
    matches = []

    for name in common:
        ours = our_versions[name]
        theirs = gecko_versions[name]

        our_str = ", ".join(sorted({v for v, _s in ours}))
        their_str = ", ".join(sorted({v for v, _s in theirs}))

        issues = find_version_issues(ours, theirs)

        if issues:
            status = "✗ " + "; ".join(desc for desc, _, _ in issues)
            mismatches.append((name, our_str, their_str, status, issues))
        else:
            matches.append((name, our_str, their_str))

    return matches, mismatches


def is_ahead_of_gecko(
    our_ver: str, gecko_ver: str | None, gecko_versions_for_name: list[tuple[str, str]]
) -> bool:
    """Check if our version is ahead of (newer than) the Gecko version.

    If gecko_ver is None, compares against Gecko's highest version for the package.
    """
    if gecko_ver is not None:
        return Version(our_ver) > Version(gecko_ver)
    gecko_max = max(
        (Version(v) for v, _ in gecko_versions_for_name),
        default=Version("0"),
    )
    return Version(our_ver) > gecko_max


def filter_neqo_only_mismatches(
    mismatches: list,
    matches: list,
    gecko_versions: dict,
    gecko_lock: dict,
    our_lock: dict,
) -> tuple[list, list, set[str]]:
    """Filter mismatches for neqo-only packages where our version is ahead.

    These are expected since update-lockfile.py updates neqo-only deps to latest.
    Also filters transitive cases: packages whose version in our lockfile is only
    pulled in by neqo-only (or workspace) crates.

    Returns (filtered_matches, filtered_mismatches, neqo_only).
    """
    neqo_only, neqo_or_workspace = find_neqo_or_workspace_deps(gecko_lock, our_lock)

    filtered = []
    for name, our_str, their_str, status, issues in mismatches:
        if name not in neqo_or_workspace:
            filtered.append((name, our_str, their_str, status, issues))
            continue

        remaining = [
            (desc, our_ver, gecko_ver)
            for desc, our_ver, gecko_ver in issues
            if not is_ahead_of_gecko(our_ver, gecko_ver, gecko_versions[name])
        ]

        if not remaining:
            matches.append((name, our_str, their_str))
        else:
            new_status = "✗ " + "; ".join(d for d, _, _ in remaining)
            filtered.append((name, our_str, their_str, new_status, remaining))

    return matches, filtered, neqo_only


def categorize_mismatch(
    name: str, issues: list, neqo_only: set[str], dev_only: set[str], our_lock: dict
) -> str:
    """Categorize a mismatch as neqo-only, dev/build only, or PRODUCTION."""
    if name in neqo_only:
        return "neqo-only"

    for _desc, our_ver, _gecko_ver in issues:
        dependents = find_dependents(our_lock, name, our_ver)
        if not dependents:
            dependents = find_dependents(our_lock, name)
        if not all(d.split()[0] in dev_only for d in dependents):
            return "PRODUCTION"

    return "dev/build only"


def print_mismatches(
    mismatches: list,
    matches: list,
    neqo_only: set[str],
    our_lock: dict,
) -> int:
    """Print mismatches with categories and summary. Returns exit code."""
    print(f"\n{'=' * 110}")
    print(f"MISMATCHES ({len(mismatches)}):")
    print(f"{'=' * 110}")

    dev_only = find_dev_only_packages()
    counts = {"neqo-only": 0, "dev/build only": 0, "PRODUCTION": 0}

    for name, our_str, their_str, status, issues in mismatches:
        category = categorize_mismatch(name, issues, neqo_only, dev_only, our_lock)
        counts[category] += 1
        print(f"{name:<30} {our_str:<25} {their_str:<25} {status}")
        print(f"  ({category})")

    print(f"\nSummary: {len(matches)} matches, {len(mismatches)} mismatches")
    print(
        f"  - {counts['neqo-only']} neqo-only "
        f"(we updated, Gecko will get on next vendor)"
    )
    print(f"  - {counts['dev/build only']} dev/build-only (don't affect Gecko)")
    print(f"  - {counts['PRODUCTION']} production (need attention)")

    return 1 if counts["PRODUCTION"] > 0 else 0


def main():
    """Compare Cargo.lock versions with Gecko's and report alignment status."""
    our_lock, gecko_lock = load_lockfiles()

    gecko_versions = get_all_versions(gecko_lock)
    our_versions = get_all_versions(our_lock)

    common = sorted(set(gecko_versions) & set(our_versions))

    print(f"Comparing {len(common)} common packages:\n")
    print(f"{'Package':<30} {'Our Version(s)':<25} {'Gecko Version(s)':<25} {'Status'}")
    print("=" * 110)

    matches, mismatches = compare_versions(our_versions, gecko_versions, common)

    if mismatches:
        matches, mismatches, neqo_only = filter_neqo_only_mismatches(
            mismatches, matches, gecko_versions, gecko_lock, our_lock
        )

    for name, our_str, their_str in matches:
        print(f"{name:<30} {our_str:<25} {their_str:<25} ✓ Match")

    if mismatches:
        exit_code = print_mismatches(mismatches, matches, neqo_only, our_lock)
        if exit_code:
            sys.exit(exit_code)
    else:
        print(f"\nAll {len(matches)} common packages match!")


if __name__ == "__main__":
    main()
