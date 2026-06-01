#!/usr/bin/env python3
# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

"""
Compare Cargo.lock versions with Gecko's and verify alignment invariants.

Checks three invariants:
  (A) HARD:     No package version duplicates unless Gecko has the same split.
  (B) ADVISORY: No shared dep newer than Gecko (warn; staged for next vendor).
  (C) HARD:     No shared production dep older than Gecko (update-lockfile missed it).

Exits 0 if no hard violations, 1 otherwise.

Usage: uv run --project test compare-lockfile
"""

import sys

from packaging.version import Version

from lockfile_utils import (
    classify_version_relation,
    find_dependents,
    find_dev_only_packages,
    find_neqo_or_workspace_deps,
    find_non_gecko_duplicates,
    get_all_versions,
    group_by_semver_range,
    is_ahead_of_gecko,
    load_lockfiles,
    semver_range,
)


# ---------------------------------------------------------------------------
# Version-comparison helpers
# ---------------------------------------------------------------------------

def find_version_issues(
    ours: list[tuple[str, str]], theirs: list[tuple[str, str]]
) -> list[tuple[str, str, str | None]]:
    """Find version mismatches between our and Gecko's versions of a package.

    Returns list of (description, our_ver, gecko_ver) tuples for each issue.
    gecko_ver is None when we have a version in a range Gecko doesn't carry.
    """
    gecko_by_range = group_by_semver_range([v for v, _s in theirs])
    issues: list[tuple[str, str, str | None]] = []

    for v, _s in ours:
        sv_rng = semver_range(v)
        gecko_in_range = gecko_by_range.get(sv_rng, [])
        relation = classify_version_relation(v, gecko_in_range)

        if relation == "no-range":
            issues.append((f"we have {v}, Gecko doesn't have {sv_rng}.x", v, None))
        elif relation != "match":
            gecko_ver = max(gecko_in_range, key=Version)
            issues.append((f"{v} vs {gecko_ver}", v, gecko_ver))

    return issues


def compare_versions(
    our_versions: dict, gecko_versions: dict, common: list[str]
) -> tuple[list, list]:
    """Compare versions for common packages and classify as match or mismatch.

    Returns (matches, mismatches) where:
    - matches:    [(name, our_str, their_str), ...]
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


def filter_neqo_only_mismatches(
    mismatches: list,
    matches: list,
    gecko_versions: dict,
    gecko_lock: dict,
    our_lock: dict,
) -> tuple[list, list, set[str]]:
    """Filter mismatches for neqo-only packages where our version is ahead.

    These are expected since update-lockfile updates neqo-only deps to latest.
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


# ---------------------------------------------------------------------------
# Invariant checking
# ---------------------------------------------------------------------------

def check_invariant_a(
    our_lock: dict, gecko_versions: dict
) -> list[tuple[str, str, str]]:
    """Check invariant A: no non-Gecko duplicate package versions.

    Returns list of (name, off_ver, description) hard violations.
    """
    violations = []
    for name, off_vers in find_non_gecko_duplicates(our_lock, gecko_versions).items():
        for off_ver in sorted(off_vers):
            violations.append((
                name, off_ver,
                f"extra version {off_ver} not present in Gecko"
            ))
    return violations


def classify_issues_by_severity(
    mismatches: list,
    neqo_only: set[str],
    dev_only: set[str],
    our_lock: dict,
) -> tuple[list, list]:
    """Split mismatches into hard violations and warnings.

    Hard violations: shared production deps that are BEHIND Gecko (invariant C).
    Warnings:        anything ahead of Gecko (invariant B), neqo-only mismatches,
                     dev/build-only mismatches, and "no Gecko range" cases.

    Returns (hard_violations, warnings) where each entry is
    (name, our_str, their_str, status, issues, category).
    """
    hard_violations = []
    warnings = []

    for name, our_str, their_str, status, issues in mismatches:
        category = categorize_mismatch(name, issues, neqo_only, dev_only, our_lock)

        # Check if any issue is a BEHIND move for a production dep.
        has_hard_behind = (
            category == "PRODUCTION"
            and any(
                gecko_ver is not None and Version(our_ver) < Version(gecko_ver)
                for _, our_ver, gecko_ver in issues
            )
        )

        entry = (name, our_str, their_str, status, issues, category)
        if has_hard_behind:
            hard_violations.append(entry)
        else:
            warnings.append(entry)

    return hard_violations, warnings


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_invariant_a_violations(violations: list[tuple[str, str, str]]) -> None:
    print(f"\n{'=' * 110}")
    print(f"HARD VIOLATIONS — Invariant A: non-Gecko duplicate versions ({len(violations)}):")
    print(f"{'=' * 110}")
    for name, off_ver, desc in violations:
        print(f"  {name}: {desc}")
    print("  Run update-lockfile to attempt auto-resolution.")


def print_version_violations(label: str, entries: list) -> None:
    print(f"\n{'=' * 110}")
    print(f"{label} ({len(entries)}):")
    print(f"{'=' * 110}")
    print(
        f"{'Package':<30} {'Our Version(s)':<25} {'Gecko Version(s)':<25} {'Status'}"
    )
    print("-" * 110)
    for name, our_str, their_str, status, _issues, category in entries:
        print(f"{name:<30} {our_str:<25} {their_str:<25} {status}")
        print(f"  ({category})")


def print_matches(matches: list) -> None:
    print(f"{'Package':<30} {'Our Version(s)':<25} {'Gecko Version(s)':<25} {'Status'}")
    print("=" * 110)
    for name, our_str, their_str in matches:
        print(f"{name:<30} {our_str:<25} {their_str:<25} ✓ Match")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    """Compare Cargo.lock versions with Gecko's and verify alignment invariants."""
    our_lock, gecko_lock = load_lockfiles()

    gecko_versions = get_all_versions(gecko_lock)
    our_versions = get_all_versions(our_lock)

    common = sorted(set(gecko_versions) & set(our_versions))

    # --- Invariant A: non-Gecko duplicates (HARD) ---
    dup_violations = check_invariant_a(our_lock, gecko_versions)

    # --- Invariants B/C: version alignment ---
    matches, mismatches = compare_versions(our_versions, gecko_versions, common)

    if mismatches:
        matches, mismatches, neqo_only = filter_neqo_only_mismatches(
            mismatches, matches, gecko_versions, gecko_lock, our_lock
        )
    else:
        neqo_only: set[str] = set()

    dev_only = find_dev_only_packages()
    hard_behind, warnings = classify_issues_by_severity(
        mismatches, neqo_only, dev_only, our_lock
    )

    # --- Print report ---
    print(f"Comparing {len(common)} common packages:\n")
    print_matches(matches)

    if dup_violations:
        print_invariant_a_violations(dup_violations)

    if hard_behind:
        print_version_violations(
            "HARD VIOLATIONS — Invariant C: shared production deps behind Gecko",
            hard_behind,
        )

    if warnings:
        print_version_violations("WARNINGS (advisory only)", warnings)

    # --- Summary ---
    n_hard = len(dup_violations) + len(hard_behind)
    print(f"\nSummary: {len(matches)} matches, {len(mismatches)} mismatches")
    print(f"  Duplicates:  {len(dup_violations)} hard violation(s)")
    print(f"  Behind Gecko: {len(hard_behind)} hard violation(s), {len(warnings)} warning(s)")
    if n_hard:
        print(f"\nTotal: {n_hard} hard violation(s) — run update-lockfile to fix.")
    else:
        print("\nAll invariants satisfied.")

    sys.exit(1 if n_hard else 0)


if __name__ == "__main__":
    main()
