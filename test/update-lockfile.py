#!/usr/bin/env python3
# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

"""
Update Cargo.lock to align with Gecko's versions.

This script compares our Cargo.lock with Firefox/Gecko's Cargo.lock and runs
cargo update commands to align versions. Crate versions that Gecko patches
with 999-versions are skipped, since those patches are Gecko-specific and
compare-lockfile.py already treats them as matches.

Usage: Run from the workspace root (not inside test/).
"""

import argparse
import subprocess
import sys
from graphlib import TopologicalSorter
from pathlib import Path

from packaging.version import Version

from lockfile_utils import (
    build_dependents_map,
    find_dev_only_packages,
    find_neqo_or_workspace_deps,
    get_duplicate_packages,
    group_by_semver_range,
    is_registry_package,
    load_lockfile,
    load_lockfiles,
    parse_packages,
)


def update_neqo_only_packages(packages: list[str]) -> dict[str, tuple[str, str]]:
    """Update all neqo-only packages together to their latest versions.

    Updates all packages at once, which allows transitive dependencies to unify.
    For example, if both enumset and serde_with need darling, updating them together
    allows them to share a single darling version.

    Returns a dict of package name -> (old_version, new_version) for updated packages.
    """
    if not packages:
        return {}

    # Snapshot the lockfile for reliable revert.
    lockfile_path = Path("Cargo.lock")
    original_content = lockfile_path.read_text(encoding="utf-8")
    original_lock = load_lockfile("Cargo.lock")
    original_versions = {
        (pkg["name"], pkg["version"])
        for pkg in original_lock.get("package", [])
        if pkg["name"] in packages
    }
    original_duplicates = get_duplicate_packages(original_lock)

    # Update all packages at once.
    result = subprocess.run(
        ["cargo", "update"] + [arg for p in packages for arg in ["-p", p]],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        print(f"cargo update failed: {result.stderr.strip()}", file=sys.stderr)
        return {}

    # Check for new or worsened duplicate packages.
    new_lock = load_lockfile("Cargo.lock")
    new_duplicates = get_duplicate_packages(new_lock)
    regressed = {
        name
        for name, vers in new_duplicates.items()
        if len(vers) > len(original_duplicates.get(name, []))
    }
    if regressed:
        print("  Update would introduce duplicate dependencies:")
        for name in sorted(regressed):
            print(f"    {name}: {', '.join(new_duplicates[name])}")
        lockfile_path.write_text(original_content, encoding="utf-8")
        print("  Reverted to original lockfile")
        return {}

    # Collect updated packages.
    new_versions = {
        (pkg["name"], pkg["version"])
        for pkg in new_lock.get("package", [])
        if pkg["name"] in packages
    }
    updated = {}
    for name, new_ver in new_versions - original_versions:
        old = [v for n, v in original_versions if n == name]
        if old:
            updated[name] = (old[0], new_ver)

    return updated


def find_compatible_gecko_range(
    sv_range: str, gecko_by_range: dict[str, list[str]]
) -> list[str]:
    """Find Gecko versions in a compatible semver range.

    For major >= 1, looks for the closest higher range first,
    then falls back to the closest lower range.
    Returns the list of Gecko versions for the matched range, or [].
    """
    major = sv_range.split(".")[0]
    if major == "0":
        return []

    sv = Version(sv_range)

    # Prefer upgrading to a higher Gecko range.
    for gr in sorted(gecko_by_range, key=Version, reverse=True):
        if gr.split(".")[0] == major and Version(gr) > sv:
            return gecko_by_range[gr]

    # Fall back to downgrading to the closest lower range.
    for gr in sorted(gecko_by_range, key=Version, reverse=True):
        if gr.split(".")[0] == major and Version(gr) < sv:
            return gecko_by_range[gr]

    return []


def align_package_with_gecko(
    name: str,
    gecko_pkgs: dict,
    our_pkgs: dict,
) -> dict[tuple[str, str], str]:
    """Align a single package's versions with Gecko's.

    Skips 999-patched versions (Gecko-specific patches).
    Returns {(name, our_ver): gecko_ver} for versions that need updating.
    """
    updates: dict[tuple[str, str], str] = {}
    our_versions = our_pkgs[name]

    if all(not is_registry_package(info) for info in our_versions.values()):
        return updates

    # Only consider real (non-999) Gecko versions.
    gecko_real = [v for v in gecko_pkgs[name] if not v.endswith(".999")]
    if not gecko_real:
        return updates

    gecko_by_range = group_by_semver_range(gecko_real)
    registry_vers = [v for v, info in our_versions.items() if is_registry_package(info)]

    for sv_range, our_vers in group_by_semver_range(registry_vers).items():
        gecko_vers = gecko_by_range.get(sv_range) or find_compatible_gecko_range(
            sv_range, gecko_by_range
        )
        if not gecko_vers:
            continue

        gecko_ver = max(gecko_vers, key=Version)
        for our_ver in our_vers:
            if our_ver != gecko_ver:
                updates[(name, our_ver)] = gecko_ver

    return updates


def collect_version_updates(
    common: set[str],
    neqo_only: set[str],
    neqo_or_workspace: set[str],
    gecko_pkgs: dict,
    our_pkgs: dict,
) -> dict[tuple[str, str], str]:
    """Collect version updates needed to align with Gecko.

    Skips neqo-only packages entirely. Also skips downgrades for packages
    that are transitively neqo-only in our lockfile (all their dependents
    are neqo-only or workspace crates), since we're intentionally ahead.

    Returns {(name, our_ver): gecko_ver} for registry crates.
    """
    version_updates: dict[tuple[str, str], str] = {}

    for name in common:
        if name in neqo_only:
            continue
        for (n, our_ver), gecko_ver in align_package_with_gecko(
            name, gecko_pkgs, our_pkgs
        ).items():
            # Skip downgrades for transitively neqo-only packages.
            if name in neqo_or_workspace and Version(our_ver) > Version(gecko_ver):
                continue
            version_updates[(n, our_ver)] = gecko_ver

    return version_updates


def cargo_update_precise(name: str, our_ver: str, gecko_ver: str) -> str | None:
    """Run cargo update --precise for a single package.

    Returns None on success, or an error message on failure.
    """
    result = subprocess.run(
        ["cargo", "update", "-p", f"{name}@{our_ver}", "--precise", gecko_ver],
        capture_output=True,
        text=True,
        check=False,
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

    Returns a dict suitable for TopologicalSorter: {name: [dependency_names]}.
    """
    all_names = {name for name, _ in version_updates}
    graph: dict[str, list[str]] = {name: [] for name in all_names}

    our_pkgs = parse_packages(load_lockfile("Cargo.lock"))
    for name in all_names:
        for info in our_pkgs.get(name, {}).values():
            for dep in info["deps"]:
                if dep in all_names:
                    graph[name].append(dep)

    return graph


def apply_version_updates(
    version_updates: dict[tuple[str, str], str],
) -> tuple[list, list, dict]:
    """Apply version updates via cargo update --precise.

    Uses topological sort and retries until no more progress is made.
    Returns (updated, downgraded, failed).
    """
    graph = build_dependency_graph(version_updates)
    updated = []
    downgraded = []
    failed = {}

    made_progress = True
    while made_progress:
        made_progress = False
        failed.clear()
        our_pkgs = parse_packages(load_lockfile("Cargo.lock"))

        for name in TopologicalSorter(graph).static_order():
            pending = [
                (our_ver, gecko_ver)
                for (n, our_ver), gecko_ver in version_updates.items()
                if n == name
            ]
            for our_ver, gecko_ver in pending:
                if name not in our_pkgs or our_ver not in our_pkgs[name]:
                    continue
                if our_ver == gecko_ver:
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


def report_failures(failed: dict) -> None:
    """Report failed version updates, categorized by dev-only vs production."""
    dev_only = find_dev_only_packages()
    dependents = build_dependents_map(load_lockfile("Cargo.lock"))

    dev_failures = {}
    real_failures = {}
    for (name, our_ver), (gecko_ver, err) in failed.items():
        pkg_dependents = dependents.get(name, set())
        if pkg_dependents and all(d in dev_only for d in pkg_dependents):
            dev_failures[(name, our_ver)] = (gecko_ver, pkg_dependents)
        else:
            real_failures[(name, our_ver)] = (gecko_ver, err)

    if real_failures:
        print(f"Failed {len(real_failures)} package(s):")
        for (name, our_ver), (gecko_ver, err) in real_failures.items():
            print(f"  {name}: {our_ver} -> {gecko_ver}: {err}")

    if dev_failures:
        print(
            f"\nSkipped {len(dev_failures)} package(s) "
            f"due to dev-dependency constraints:"
        )
        print(
            "  (These don't affect Gecko integration "
            "since Gecko ignores dev-dependencies)"
        )
        for (name, our_ver), (gecko_ver, blockers) in dev_failures.items():
            print(
                f"  {name}: {our_ver} -> {gecko_ver} "
                f"(blocked by: {', '.join(sorted(blockers))})"
            )


def run_neqo_only_updates(neqo_only_in_common: set[str], our_pkgs: dict) -> None:
    """Update neqo-only packages to their latest available versions."""
    packages_to_update = [
        name
        for name in sorted(neqo_only_in_common)
        if any(is_registry_package(info) for info in our_pkgs.get(name, {}).values())
    ]
    if not packages_to_update:
        return

    print(f"\nUpdating {len(packages_to_update)} neqo-only packages...")
    print("(These only neqo depends on in Gecko, so we can update freely)")
    updated = update_neqo_only_packages(packages_to_update)
    if updated:
        for name, (old_ver, new_ver) in sorted(updated.items()):
            print(f"  {name}: {old_ver} -> {new_ver}")
        print(f"Updated {len(updated)} neqo-only package(s)")
    else:
        print("All neqo-only packages already at newest compatible version")


def main():
    """Update Cargo.lock to align with Gecko's versions."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--update-neqo-only",
        action="store_true",
        help="Also update neqo-only dependencies to their latest available versions.",
    )
    args = parser.parse_args()

    our_lock, gecko_lock = load_lockfiles()

    gecko_pkgs = parse_packages(gecko_lock)
    our_pkgs = parse_packages(our_lock)

    common = set(gecko_pkgs) & set(our_pkgs)
    print(
        f"{len(gecko_pkgs)} packages in Gecko, {len(our_pkgs)} in ours, "
        f"{len(common)} in common",
        file=sys.stderr,
    )

    neqo_only, neqo_or_workspace = find_neqo_or_workspace_deps(gecko_lock, our_lock)

    version_updates = collect_version_updates(
        common, neqo_only, neqo_or_workspace, gecko_pkgs, our_pkgs
    )

    # Optionally update neqo-only packages to latest.
    if args.update_neqo_only:
        run_neqo_only_updates(neqo_or_workspace & common, our_pkgs)

    if not version_updates:
        print("\nAll shared packages aligned with Gecko versions")
        return

    updated, downgraded, failed = apply_version_updates(version_updates)

    print()
    if updated:
        print(f"Updated {len(updated)} package(s)")
    if downgraded:
        print(f"Downgraded {len(downgraded)} package(s)")
    if failed:
        report_failures(failed)


if __name__ == "__main__":
    main()
