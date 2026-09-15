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
  (B) ADVISORY: Deps ahead of Gecko that Gecko picks up when neqo is vendored, deps
                on a semver range Gecko doesn't carry (nothing to pin to), and deps
                another crate's version requirement rules out pinning.
  (C) HARD:     Every other shared dep, dev- and build-dependencies included, sits
                on Gecko's exact version (update-lockfile missed it).

Exits 0 if no hard violations, 1 otherwise.

Usage: uv run --project test compare-lockfile
"""

import sys
from typing import NamedTuple

from lockfile_utils import (
    PinPlan,
    PinPolicy,
    VersionIndex,
    collect_pin_targets,
    divergence_rationales,
    find_dependents,
    find_dev_only_packages,
    find_divergences,
    find_neqo_only_deps,
    find_non_gecko_duplicates,
    find_pinnable_packages,
    format_rationales,
    load_cargo_metadata,
    load_lockfiles,
    load_version_requirements,
    parse_packages,
    semver_range,
    versions_by_name,
)


class Issue(NamedTuple):
    """One of our versions of a package that doesn't line up with Gecko's."""

    description: str
    our_ver: str
    # None when we hold a version in a semver range Gecko doesn't carry at all.
    gecko_ver: str | None


class Mismatch(NamedTuple):
    """A package with at least one version that doesn't line up with Gecko's."""

    name: str
    our_vers: str
    gecko_vers: str
    status: str
    issues: list[Issue]
    category: str = ""


class Match(NamedTuple):
    """A package whose versions all line up with Gecko's."""

    name: str
    our_vers: str
    gecko_vers: str


# ---------------------------------------------------------------------------
# Version-comparison helpers
# ---------------------------------------------------------------------------

def find_version_issues(
    name: str,
    ours: set[str],
    theirs: set[str],
    plan: PinPlan,
) -> list[Issue]:
    """Find version mismatches between our and Gecko's versions of a package.

    Versions that update-lockfile pins, or would pin if a requirement allowed it,
    are reported against their pin target; the rest fall back to Gecko's version in
    the same semver range.
    """
    issues: list[Issue] = []
    for div in find_divergences(name, ours, theirs, plan):
        if div.pin_target:
            desc = f"{div.our_ver} vs. {div.pin_target}"
        elif div.blocked:
            desc = (
                f"{div.our_ver} vs. {div.blocked.gecko_ver}, ruled out by "
                f"{div.blocked.requirer}'s "
                f'`{name} = "{div.blocked.requirement}"`'
            )
        elif div.gecko_ver is None:
            rng = semver_range(div.our_ver)
            desc = f"we have {div.our_ver}, Gecko doesn't have {rng}.x"
        else:
            desc = f"{div.our_ver} vs. {div.gecko_ver}"
        issues.append(Issue(desc, div.our_ver, div.gecko_ver))

    return issues


def compare_versions(
    our_versions: VersionIndex,
    gecko_versions: VersionIndex,
    common: list[str],
    plan: PinPlan,
) -> tuple[list[Match], list[Mismatch]]:
    """Compare versions for common packages and split into matches and mismatches."""
    matches: list[Match] = []
    mismatches: list[Mismatch] = []

    for name in common:
        ours, theirs = our_versions[name], gecko_versions[name]
        our_str = ", ".join(sorted(ours))
        their_str = ", ".join(sorted(theirs))

        issues = find_version_issues(name, ours, theirs, plan)
        if issues:
            status = "✗ " + "; ".join(issue.description for issue in issues)
            mismatches.append(Mismatch(name, our_str, their_str, status, issues))
        else:
            matches.append(Match(name, our_str, their_str))

    return matches, mismatches


def categorize_mismatch(
    mismatch: Mismatch, neqo_only: set[str], dev_only: set[str], our_lock: dict
) -> str:
    """Categorize a mismatch as neqo-only, dev/build only, or PRODUCTION."""
    name = mismatch.name
    if name in neqo_only:
        return "neqo-only"

    for issue in mismatch.issues:
        # A dependency entry omits the version when the package appears only once,
        # so fall back to every dependent of the package.
        dependents = find_dependents(our_lock, name, issue.our_ver) or find_dependents(
            our_lock, name
        )
        if not all(dep in dev_only for dep, _ver in dependents):
            return "PRODUCTION"

    return "dev/build only"


# ---------------------------------------------------------------------------
# Invariant checking
# ---------------------------------------------------------------------------

def check_invariant_a(
    our_lock: dict, gecko_versions: VersionIndex
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
    mismatches: list[Mismatch],
    plan: PinPlan,
    pinnable: set[str],
    neqo_only: set[str],
    dev_only: set[str],
    our_lock: dict,
) -> tuple[list[Mismatch], list[Mismatch]]:
    """Split mismatches into hard violations and warnings, filling in the category.

    Hard violations: versions update-lockfile pins to Gecko that haven't been moved
                     yet (invariant C).  Dev- and build-dependencies count: Gecko
                     doesn't adopt them when neqo is vendored, so a mismatch in
                     either direction is a real misalignment.
    Warnings:        everything update-lockfile leaves alone — neqo-only deps ahead
                     of Gecko, versions in a semver range Gecko doesn't carry, and
                     pins another crate's requirement rules out (invariant B).
    """
    hard_violations: list[Mismatch] = []
    warnings: list[Mismatch] = []

    for mismatch in mismatches:
        categorized = mismatch._replace(
            category=categorize_mismatch(mismatch, neqo_only, dev_only, our_lock)
        )
        # Only a violation when the version could actually reach a Gecko build;
        # elsewhere we still aim for Gecko's version, but missing it harms nothing.
        is_hard = mismatch.name in pinnable and any(
            (mismatch.name, issue.our_ver) in plan.targets
            for issue in mismatch.issues
        )
        (hard_violations if is_hard else warnings).append(categorized)

    return hard_violations, warnings


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

TABLE_WIDTH = 110


def table_row(name: str, ours: str, theirs: str, status: str) -> str:
    """Format one row of the package comparison table."""
    return f"{name:<30} {ours:<25} {theirs:<25} {status}"


def print_section(label: str, count: int) -> None:
    """Print a rule-delimited section heading."""
    print(f"\n{'=' * TABLE_WIDTH}")
    print(f"{label} ({count}):")
    print("=" * TABLE_WIDTH)


def print_invariant_a_violations(violations: list[tuple[str, str, str]]) -> None:
    print_section(
        "HARD VIOLATIONS — Invariant A: non-Gecko duplicate versions", len(violations)
    )
    for name, _off_ver, desc in violations:
        print(f"  {name}: {desc}")
    print("  Run update-lockfile to attempt auto-resolution.")


def print_version_violations(label: str, entries: list[Mismatch]) -> None:
    print_section(label, len(entries))
    print(table_row("Package", "Our Version(s)", "Gecko Version(s)", "Status"))
    print("-" * TABLE_WIDTH)
    for entry in entries:
        print(table_row(entry.name, entry.our_vers, entry.gecko_vers, entry.status))
        print(f"  ({entry.category})")


def print_matches(matches: list[Match]) -> None:
    print(table_row("Package", "Our Version(s)", "Gecko Version(s)", "Status"))
    print("=" * TABLE_WIDTH)
    for match in matches:
        print(table_row(match.name, match.our_vers, match.gecko_vers, "✓ Match"))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    """Compare Cargo.lock versions with Gecko's and verify alignment invariants."""
    our_lock, gecko_lock = load_lockfiles()

    gecko_versions = versions_by_name(gecko_lock)
    our_versions = versions_by_name(our_lock)

    common = sorted(set(gecko_versions) & set(our_versions))

    # --- Invariant A: non-Gecko duplicates (HARD) ---
    dup_violations = check_invariant_a(our_lock, gecko_versions)

    # --- Invariants B/C: version alignment ---
    # pin_targets is the same set of moves update-lockfile applies, so anything
    # still listed here is a version it would have pinned.  Moves no requirement
    # in the graph allows come back as blocked and stay advisory.
    metadata = load_cargo_metadata()
    neqo_only = find_neqo_only_deps(gecko_lock, our_lock)
    pinnable = find_pinnable_packages(metadata, gecko_lock)
    plan = collect_pin_targets(
        set(common),
        neqo_only,
        parse_packages(gecko_lock),
        parse_packages(our_lock),
        load_version_requirements(metadata),
    )

    matches, mismatches = compare_versions(our_versions, gecko_versions, common, plan)

    dev_only = find_dev_only_packages(metadata)
    hard_misaligned, warnings = classify_issues_by_severity(
        mismatches, plan, pinnable, neqo_only, dev_only, our_lock
    )

    # --- Print report ---
    print(f"Comparing {len(common)} common packages:\n")
    print_matches(matches)

    if dup_violations:
        print_invariant_a_violations(dup_violations)

    if hard_misaligned:
        print_version_violations(
            "HARD VIOLATIONS — Invariant C: shared deps not pinned to Gecko",
            hard_misaligned,
        )

    if warnings:
        print_version_violations("WARNINGS (advisory only)", warnings)

    # --- Rationale for every package that differs from Gecko ---
    policy = PinPolicy.build(gecko_lock, metadata, neqo_only)
    entries = divergence_rationales(parse_packages(our_lock), policy, our_lock, plan)
    print(format_rationales("Why each version differs from Gecko", entries))

    # --- Summary ---
    n_hard = len(dup_violations) + len(hard_misaligned)
    print(f"\nSummary: {len(matches)} matches, {len(mismatches)} mismatches")
    print(f"  Duplicates:  {len(dup_violations)} hard violation(s)")
    print(
        f"  Not pinned to Gecko: {len(hard_misaligned)} hard violation(s), "
        f"{len(warnings)} warning(s)"
    )
    if n_hard:
        print(f"\nTotal: {n_hard} hard violation(s) — run update-lockfile to fix.")
    else:
        print("\nAll invariants satisfied.")

    sys.exit(1 if n_hard else 0)


if __name__ == "__main__":
    main()
