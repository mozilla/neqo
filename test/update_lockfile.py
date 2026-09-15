#!/usr/bin/env python3
# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

"""
Update Cargo.lock to align with Gecko's versions.

This script compares our Cargo.lock with Firefox/Gecko's Cargo.lock and runs
cargo update commands to align versions.  The rules are:

- Every dep Gecko carries is pinned to Gecko's exact version, up or down, dev- and
  build-dependencies included, so we stay as close to Gecko as cargo allows.  Pins
  another crate's version requirement rules out are reported, not attempted, and
  the version is left where it is rather than chasing latest.
- Deps Gecko has no version of, and deps only neqo uses within Gecko, are bumped to
  their newest compatible version.
- Non-Gecko duplicate versions are auto-resolved where possible.

Only deps whose version can reach a Gecko build of neqo — those reachable via
normal or build edges from the crates Gecko vendors — count as hard violations when
they drift; for the rest, matching Gecko is preferred but not required.

Usage: uv run --project test update-lockfile
"""

import sys
from collections import defaultdict
from graphlib import CycleError, TopologicalSorter

from packaging.version import Version

from lockfile_utils import (
    LOCKFILE,
    PackageIndex,
    PinPlan,
    PinPolicy,
    VersionIndex,
    build_dependents_map,
    change_rationales,
    collect_pin_targets,
    current_lock,
    divergence_rationales,
    current_packages,
    current_versions,
    find_dependents,
    find_dev_only_packages,
    find_non_gecko_duplicates,
    find_neqo_only_deps,
    format_rationales,
    get_duplicate_packages,
    is_registry_package,
    load_cargo_metadata,
    load_lockfiles,
    load_version_requirements,
    packages,
    parse_packages,
    run_cargo,
    versions_by_name,
)


def try_cargo_update(specs: list[str]) -> set[tuple[str, str]]:
    """Run cargo update for the given name@version specs, or roll back.

    Snapshots the lockfile first and restores it if cargo fails or if the update
    would add a duplicate version, so callers don't have to track it themselves.
    Returns the (name, version) entries present afterwards, or an empty set if the
    update was rolled back.
    """
    snapshot = LOCKFILE.read_text(encoding="utf-8")
    duplicates_before = get_duplicate_packages(current_lock())

    result = run_cargo(
        "update", *(arg for spec in specs for arg in ("-p", spec))
    )
    if result.returncode == 0:
        new_lock = current_lock()
        regressed = any(
            len(vers) > len(duplicates_before.get(name, ()))
            for name, vers in get_duplicate_packages(new_lock).items()
        )
        if not regressed:
            return {(pkg["name"], pkg["version"]) for pkg in packages(new_lock)}

    LOCKFILE.write_text(snapshot, encoding="utf-8")
    return set()


def update_to_latest(names: list[str]) -> tuple[dict[str, tuple[str, str]], list[str]]:
    """Update all named packages to their latest compatible versions.

    Tries a batch update first (allows transitive deps to unify), then falls
    back to per-package updates so that packages which would introduce duplicates
    are skipped while the rest still get updated.

    Returns ({package name: (old_version, new_version)}, rejected specs), where a
    rejected spec is one cargo refused or that would have added a duplicate.
    """
    if not names:
        return {}, []

    before = {(n, v) for n, v in current_versions() if n in names}
    # name@version, to disambiguate packages present at several versions.  Sorted
    # so the retry order, and so the report, are reproducible.
    specs = [f"{name}@{ver}" for name, ver in sorted(before)]

    rejected: list[str] = []
    after = try_cargo_update(specs)
    if not after:
        # The batch was rejected as a whole; retry one spec at a time.
        after = current_versions()
        for spec in specs:
            name, _, ver = spec.partition("@")
            if (name, ver) not in after:
                continue  # Already moved by a transitive update.
            if retried := try_cargo_update([spec]):
                after = retried
            else:
                rejected.append(spec)

    old_versions = dict(before)
    updated = {
        name: (old_versions[name], new_ver)
        for name, new_ver in {(n, v) for n, v in after if n in names} - before
        if name in old_versions
    }
    return updated, rejected


def run_free_updates(names: set[str], our_pkgs: PackageIndex, label: str) -> None:
    """Update a set of packages to their latest available versions."""
    packages_to_update = [
        name
        for name in sorted(names)
        if any(is_registry_package(info) for info in our_pkgs.get(name, {}).values())
    ]
    if not packages_to_update:
        return

    print(f"\nUpdating {len(packages_to_update)} {label}...")
    updated, rejected = update_to_latest(packages_to_update)
    for name, (old_ver, new_ver) in sorted(updated.items()):
        print(f"  {name}: {old_ver} -> {new_ver}")
    if updated:
        print(f"Updated {len(updated)} package(s)")
    if rejected:
        # Distinct from "nothing to do": cargo refused these, or taking them would
        # have added a duplicate version.
        print(f"Could not update {len(rejected)} package(s): {', '.join(rejected)}")
    elif not updated:
        print(f"All {label} already at newest compatible version")


def cargo_update_precise(name: str, our_ver: str, gecko_ver: str) -> str | None:
    """Run cargo update --precise for a single package.

    Returns None on success, or an error message on failure.
    """
    result = run_cargo(
        "update", "-p", f"{name}@{our_ver}", "--precise", gecko_ver
    )
    if result.returncode == 0:
        return None
    err_lines = [
        ln
        for ln in result.stderr.strip().split("\n")
        if not ln.startswith("Updating") and ln.strip()
    ]
    return err_lines[0] if err_lines else "Unknown error"


def build_dependency_graph(
    version_updates: dict[tuple[str, str], str],
) -> dict[str, list[str]]:
    """Build a dependency graph for the packages being updated.

    Nodes are package names, so a crate that dev-depends on itself (as several of
    ours do) would show up as a self-edge; those are dropped, since a cycle makes
    TopologicalSorter raise.
    Returns a dict suitable for TopologicalSorter: {name: [dependency_names]}.
    """
    all_names = {name for name, _ in version_updates}
    graph: dict[str, list[str]] = {name: [] for name in all_names}

    our_pkgs = current_packages()
    for name in all_names:
        for info in our_pkgs.get(name, {}).values():
            for dep in info["deps"]:
                if dep in all_names and dep != name:
                    graph[name].append(dep)

    return graph


def update_order(graph: dict[str, list[str]]) -> list[str]:
    """Order packages dependencies-first, falling back to any order on a cycle.

    Ordering is an optimisation — it lets a dependency move before its dependents
    retry — so a cycle we can't order is not worth aborting a partially applied
    update over.
    """
    try:
        return list(TopologicalSorter(graph).static_order())
    except CycleError as e:
        print(f"Note: dependency cycle {e.args[1]}; updating in arbitrary order.")
        return sorted(graph)


def apply_version_updates(
    version_updates: dict[tuple[str, str], str],
) -> tuple[
    list[tuple[str, str, str]],
    list[tuple[str, str, str]],
    dict[tuple[str, str], tuple[str, str]],
]:
    """Apply version updates via cargo update --precise.

    Uses topological sort and retries until no more progress is made.
    Returns (updated, downgraded, failed).
    """
    graph = build_dependency_graph(version_updates)
    moves: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for (name, our_ver), gecko_ver in version_updates.items():
        moves[name].append((our_ver, gecko_ver))

    updated = []
    downgraded = []
    failed: dict[tuple[str, str], tuple[str, str]] = {}

    made_progress = True
    while made_progress:
        made_progress = False
        failed.clear()
        our_pkgs = current_packages()

        for name in update_order(graph):
            for our_ver, gecko_ver in moves[name]:
                if our_ver == gecko_ver or our_ver not in our_pkgs.get(name, {}):
                    continue

                is_downgrade = Version(gecko_ver) < Version(our_ver)
                action = "Downgrading" if is_downgrade else "Updating"
                print(f"{action} {name}: {our_ver} -> {gecko_ver}")

                err = cargo_update_precise(name, our_ver, gecko_ver)
                if err:
                    failed[(name, our_ver)] = (gecko_ver, err)
                else:
                    made_progress = True
                    if is_downgrade:
                        downgraded.append((name, our_ver, gecko_ver))
                    else:
                        updated.append((name, our_ver, gecko_ver))

    return updated, downgraded, failed


def dedup_non_gecko_duplicates(
    gecko_versions: VersionIndex,
    safe_dependents: set[str],
) -> tuple[list[tuple[str, str]], list[tuple[str, str, str]]]:
    """Attempt to eliminate package version duplicates not present in Gecko.

    Collapses off-versions by bumping the safe dependent crates that pull them
    (mirrors the manual 'cargo update -p quinn-udp' approach).  Only bumps
    dependents in safe_dependents (dev/build or neqo-only; never shared
    Gecko-production crates).

    Returns (resolved, unresolved) where:
    - resolved:   [(name, off_ver), ...]         successfully eliminated
    - unresolved: [(name, off_ver, reason), ...]  could not be eliminated
    """
    resolved: list[tuple[str, str]] = []
    attempted: set[tuple[str, str]] = set()

    while True:
        offenders = find_non_gecko_duplicates(current_lock(), gecko_versions)
        pending = [
            (name, off_ver)
            for name, off_vers in offenders.items()
            for off_ver in off_vers
            if (name, off_ver) not in attempted
        ]
        if not pending:
            break

        progress = False
        for name, off_ver in pending:
            attempted.add((name, off_ver))

            safe_deps = [
                dep
                for dep in find_dependents(current_lock(), name, off_ver)
                if dep[0] in safe_dependents
            ]
            if not safe_deps:
                continue

            snapshot = LOCKFILE.read_text(encoding="utf-8")
            after = try_cargo_update([f"{n}@{v}" for n, v in safe_deps])

            if after and (name, off_ver) not in after:
                resolved.append((name, off_ver))
                progress = True
            else:
                # try_cargo_update only rolls back its own failures; also revert if
                # the off-version survived the update.
                LOCKFILE.write_text(snapshot, encoding="utf-8")

        if not progress:
            break

    # Build the unresolved report from whatever duplicates still remain.
    our_lock = current_lock()
    unresolved: list[tuple[str, str, str]] = []
    for name, off_vers in find_non_gecko_duplicates(our_lock, gecko_versions).items():
        for off_ver in off_vers:
            all_deps = find_dependents(our_lock, name, off_ver)
            if not all_deps:
                reason = "no dependents found"
            elif not any(n in safe_dependents for n, _ in all_deps):
                blockers = ", ".join(sorted({n for n, _ in all_deps}))
                reason = f"pinned by non-safe dependent(s): {blockers}"
            else:
                reason = "cargo could not collapse onto surviving version"
            unresolved.append((name, off_ver, reason))

    return resolved, unresolved


def report_failures(
    failed: dict[tuple[str, str], tuple[str, str]], dev_only: set[str]
) -> None:
    """Report failed version updates, categorized by dev-only vs. production."""
    dependents = build_dependents_map(current_lock())

    dev_failures = {}
    real_failures = {}
    for (name, our_ver), (gecko_ver, err) in failed.items():
        pkg_dependents = dependents.get(name, set())
        if pkg_dependents and all(d in dev_only for d in pkg_dependents):
            dev_failures[(name, our_ver)] = (gecko_ver, pkg_dependents, err)
        else:
            real_failures[(name, our_ver)] = (gecko_ver, err)

    if real_failures:
        print(f"Failed {len(real_failures)} package(s):")
        for (name, our_ver), (gecko_ver, err) in real_failures.items():
            print(f"  {name}: {our_ver} -> {gecko_ver}: {err}")

    if dev_failures:
        print(
            f"\nFailed {len(dev_failures)} package(s) "
            f"reachable only from dev/build dependencies:"
        )
        for (name, our_ver), (gecko_ver, blockers, err) in dev_failures.items():
            print(
                f"  {name}: {our_ver} -> {gecko_ver}: {err} "
                f"(pulled in by: {', '.join(sorted(blockers))})"
            )


def align_with_gecko(
    gecko_pkgs: PackageIndex, gecko_lock: dict, neqo_only: set[str]
) -> None:
    """Pin every shared dep to Gecko's version, and report what moved.

    Repeats until no new pin targets appear, since a `cargo update --precise` can
    pull transitive deps to versions that themselves need pinning.
    """
    before = current_versions()
    updated: list[tuple[str, str, str]] = []
    downgraded: list[tuple[str, str, str]] = []
    failed: dict[tuple[str, str], tuple[str, str]] = {}
    attempted: set[tuple[str, str]] = set()

    while True:
        plan = pin_targets_now(gecko_pkgs, neqo_only, load_cargo_metadata())
        pending = {k: v for k, v in plan.targets.items() if k not in attempted}
        if not pending:
            break

        attempted |= set(pending)
        round_updated, round_downgraded, round_failed = apply_version_updates(pending)
        updated += round_updated
        downgraded += round_downgraded
        failed.update(round_failed)

    if not (updated or downgraded or failed):
        print("\nAll shared packages aligned with Gecko versions")
        return

    # Anything that moved without being asked to came along as a transitive dep.
    explicit = {name for name, _, _ in updated + downgraded}
    silent = sorted({name for name, _ in current_versions() - before} - explicit)

    print()
    if updated:
        print(f"Updated {len(updated)} package(s)")
    if downgraded:
        print(f"Downgraded {len(downgraded)} package(s)")
    if silent:
        print(f"Also updated (transitive): {', '.join(silent)}")
    if failed:
        report_failures(failed, find_dev_only_packages(load_cargo_metadata()))


def report_dedup(
    gecko_versions: VersionIndex, gecko_pkgs: PackageIndex, neqo_only: set[str]
) -> None:
    """Collapse non-Gecko duplicate versions and report the outcome.

    Only safe dependents (dev/build or neqo-only, never shared Gecko crates) get
    bumped.  The set is derived from the current lockfile, so it reflects packages
    cargo added or removed while aligning.
    """
    safe_dependents = (set(current_packages()) - set(gecko_pkgs)) | neqo_only
    resolved, unresolved = dedup_non_gecko_duplicates(gecko_versions, safe_dependents)

    if resolved:
        print(f"\nCollapsed {len(resolved)} non-Gecko duplicate(s):")
        for name, off_ver in sorted(resolved):
            print(f"  {name} {off_ver}")
    if unresolved:
        print("\nUnresolvable non-Gecko duplicate(s) (upstream fix needed):")
        for name, off_ver, reason in sorted(unresolved):
            print(f"  {name} {off_ver}: {reason}")


def pin_targets_now(
    gecko_pkgs: PackageIndex, neqo_only: set[str], metadata: dict
) -> PinPlan:
    """The pin plan for the lockfile as it currently stands."""
    our_pkgs = current_packages()
    return collect_pin_targets(
        set(gecko_pkgs) & set(our_pkgs),
        neqo_only,
        gecko_pkgs,
        our_pkgs,
        load_version_requirements(metadata),
    )


def main():
    """Update Cargo.lock to align with Gecko's versions."""
    our_lock, gecko_lock = load_lockfiles()
    before = current_versions()

    gecko_pkgs = parse_packages(gecko_lock)
    gecko_versions = versions_by_name(gecko_lock)
    our_pkgs = parse_packages(our_lock)

    common = set(gecko_pkgs) & set(our_pkgs)
    print(
        f"{len(gecko_pkgs)} packages in Gecko, {len(our_pkgs)} in ours, "
        f"{len(common)} in common",
        file=sys.stderr,
    )

    neqo_only = find_neqo_only_deps(gecko_lock, our_lock)

    # Phase 1: bump packages Gecko has no version of, plus those only neqo uses
    # within Gecko, to their newest compatible version.  Everything Gecko does pin
    # is left for Phase 2 to match.  Transitive conflicts resolve there too.
    free_to_update = (set(our_pkgs) - set(gecko_pkgs)) | (neqo_only & common)
    run_free_updates(free_to_update, our_pkgs, "packages Gecko doesn't pin")

    # Phase 2: pin shared deps to Gecko's exact version, up or down.
    align_with_gecko(gecko_pkgs, gecko_lock, neqo_only)

    # Phase 3: collapse duplicate versions Gecko doesn't itself carry.
    report_dedup(gecko_versions, gecko_pkgs, neqo_only)

    # Phase 4: explain what moved, then what still differs and why that is safe.
    # Recomputed against the finished lockfile so both reflect where we ended up.
    metadata = load_cargo_metadata()
    policy = PinPolicy.build(gecko_lock, metadata, neqo_only)
    plan = pin_targets_now(gecko_pkgs, neqo_only, metadata)
    our_pkgs, our_lock = current_packages(), current_lock()

    changes = change_rationales(before, current_versions(), policy, our_lock, plan)
    print(format_rationales("Lockfile changes", changes) or "\nNo version changes.")
    print(
        format_rationales(
            "Why each version differs from Gecko",
            divergence_rationales(our_pkgs, policy, our_lock, plan),
        )
    )


if __name__ == "__main__":
    main()
