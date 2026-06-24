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

- Deps not in Gecko (dev/build tools) and deps only neqo uses within Gecko are
  bumped to their newest compatible version.
- Shared production deps are pinned to Gecko's exact version (up or down).
- Shared dev/build-only deps are upgraded to Gecko's version if behind, but
  left alone if ahead (they don't affect Gecko's runtime).
- Deps Gecko doesn't depend on (or only neqo uses) are bumped to latest.
- Non-Gecko duplicate versions are auto-resolved where possible.

Usage: uv run --project test update-lockfile
"""

import subprocess
import sys
from graphlib import TopologicalSorter
from pathlib import Path

from packaging.version import Version

from lockfile_utils import (
    build_dependents_map,
    classify_version_relation,
    find_dependents,
    find_dev_only_packages,
    find_non_gecko_duplicates,
    find_neqo_or_workspace_deps,
    get_all_versions,
    get_duplicate_packages,
    group_by_semver_range,
    is_registry_package,
    load_lockfile,
    load_lockfiles,
    parse_packages,
)


def _cargo_update_specs(
    specs: list[str],
    original_content: str,
    original_duplicates: dict,
    lockfile_path: Path,
) -> set[tuple[str, str]]:
    """Run cargo update for the given name@version specs.

    Returns the set of (name, version) entries present after the update,
    or an empty set (after reverting) if the update would introduce new
    duplicate dependencies.
    """
    result = subprocess.run(
        ["cargo", "update"] + [arg for s in specs for arg in ["-p", s]],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        lockfile_path.write_text(original_content, encoding="utf-8")
        return set()

    new_lock = load_lockfile("Cargo.lock")
    new_duplicates = get_duplicate_packages(new_lock)
    regressed = {
        name
        for name, vers in new_duplicates.items()
        if len(vers) > len(original_duplicates.get(name, []))
    }
    if regressed:
        lockfile_path.write_text(original_content, encoding="utf-8")
        return set()

    return {(pkg["name"], pkg["version"]) for pkg in new_lock.get("package", [])}


def update_neqo_only_packages(packages: list[str]) -> dict[str, tuple[str, str]]:
    """Update all listed packages together to their latest versions.

    Tries a batch update first (allows transitive deps to unify), then falls
    back to per-package updates so that packages which would introduce duplicates
    are skipped while the rest still get updated.

    Returns a dict of package name -> (old_version, new_version).
    """
    if not packages:
        return {}

    lockfile_path = Path("Cargo.lock")
    original_content = lockfile_path.read_text(encoding="utf-8")
    original_lock = load_lockfile("Cargo.lock")
    original_versions = {
        (pkg["name"], pkg["version"])
        for pkg in original_lock.get("package", [])
        if pkg["name"] in packages
    }
    original_duplicates = get_duplicate_packages(original_lock)

    # Use name@version to avoid ambiguity when a package has multiple versions.
    specs = [f"{name}@{ver}" for name, ver in original_versions]

    # Try batch update first; fall back to per-package if it introduces duplicates.
    new_versions = _cargo_update_specs(
        specs, original_content, original_duplicates, lockfile_path
    )
    if not new_versions:
        # Restore original and retry one spec at a time.
        lockfile_path.write_text(original_content, encoding="utf-8")
        current_content = original_content
        current_duplicates = original_duplicates
        new_versions = {
            (pkg["name"], pkg["version"]) for pkg in original_lock.get("package", [])
        }
        for spec in specs:
            name, ver = spec.split("@", 1)
            if (name, ver) not in new_versions:
                continue  # Already moved by a transitive update; skip.
            result_versions = _cargo_update_specs(
                [spec], current_content, current_duplicates, lockfile_path
            )
            if result_versions:
                current_content = lockfile_path.read_text(encoding="utf-8")
                current_duplicates = get_duplicate_packages(load_lockfile("Cargo.lock"))
                new_versions = result_versions

    new_versions_for_pkgs = {(n, v) for n, v in new_versions if n in packages}
    updated = {}
    for name, new_ver in new_versions_for_pkgs - original_versions:
        old = [v for n, v in original_versions if n == name]
        if old:
            updated[name] = (old[0], new_ver)

    return updated


def run_free_updates(names: set[str], our_pkgs: dict, label: str) -> None:
    """Update a set of packages to their latest available versions."""
    packages_to_update = [
        name
        for name in sorted(names)
        if any(is_registry_package(info) for info in our_pkgs.get(name, {}).values())
    ]
    if not packages_to_update:
        return

    print(f"\nUpdating {len(packages_to_update)} {label}...")
    updated = update_neqo_only_packages(packages_to_update)
    if updated:
        for name, (old_ver, new_ver) in sorted(updated.items()):
            print(f"  {name}: {old_ver} -> {new_ver}")
        print(f"Updated {len(updated)} package(s)")
    else:
        print(f"All {label} already at newest compatible version")


def find_compatible_gecko_range(
    sv_range: str, gecko_by_range: dict[str, list[str]]
) -> list[str]:
    """Find Gecko versions in a compatible semver range.

    For major >= 1, looks for the closest higher range first, then falls back
    to the closest lower range (to pin us to Gecko's version even if it means
    a cross-range downgrade for genuinely shared deps).
    Returns [] for 0.x packages (each minor is its own incompatible API).
    """
    major = sv_range.split(".")[0]
    if major == "0":
        return []

    sv = Version(sv_range)

    for gr in sorted(gecko_by_range, key=Version, reverse=True):
        if gr.split(".")[0] == major and Version(gr) > sv:
            return gecko_by_range[gr]

    for gr in sorted(gecko_by_range, key=Version, reverse=True):
        if gr.split(".")[0] == major and Version(gr) < sv:
            return gecko_by_range[gr]

    return []


def align_package_with_gecko(
    name: str,
    gecko_pkgs: dict,
    our_pkgs: dict,
) -> dict[tuple[str, str], str]:
    """Compute version moves to align a package's versions with Gecko's.

    Emits moves for versions that differ from Gecko's (both upgrades and
    downgrades). Callers are responsible for filtering out undesired directions
    (e.g. skipping downgrades of dev-only packages). Skips 999-patched versions.
    Returns {(name, our_ver): gecko_ver} for versions that need moving.
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

    for sv_rng, our_vers in group_by_semver_range(registry_vers).items():
        gecko_vers = gecko_by_range.get(sv_rng) or find_compatible_gecko_range(
            sv_rng, gecko_by_range
        )
        if not gecko_vers:
            continue

        gecko_ver = max(gecko_vers, key=Version)
        for our_ver in our_vers:
            relation = classify_version_relation(our_ver, gecko_vers)
            if relation in ("behind", "ahead"):
                updates[(name, our_ver)] = gecko_ver

    return updates


def collect_version_updates(
    common: set[str],
    neqo_only: set[str],
    dev_only: set[str],
    gecko_pkgs: dict,
    our_pkgs: dict,
) -> dict[tuple[str, str], str]:
    """Collect version moves needed to align shared packages with Gecko.

    Skips neqo-only packages (handled separately via free updates).
    Skips downgrades for dev/build-only packages — they don't affect Gecko's
    runtime so there is no benefit to pinning them to Gecko's version.
    Returns {(name, our_ver): gecko_ver} for registry crates that need moving.
    """
    version_updates: dict[tuple[str, str], str] = {}

    for name in common:
        if name in neqo_only:
            continue
        for (n, our_ver), gecko_ver in align_package_with_gecko(
            name, gecko_pkgs, our_pkgs
        ).items():
            if name in dev_only and Version(our_ver) > Version(gecko_ver):
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
    failed: dict[tuple[str, str], tuple[str, str]] = {}

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


def dedup_non_gecko_duplicates(
    gecko_versions: dict,
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
    lockfile_path = Path("Cargo.lock")
    resolved: list[tuple[str, str]] = []
    attempted: set[tuple[str, str]] = set()

    while True:
        our_lock = load_lockfile("Cargo.lock")
        offenders = find_non_gecko_duplicates(our_lock, gecko_versions)
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

            our_lock = load_lockfile("Cargo.lock")
            all_deps = find_dependents(our_lock, name, off_ver)
            safe_deps = [d for d in all_deps if d.split()[0] in safe_dependents]

            if not safe_deps:
                continue

            original_content = lockfile_path.read_text(encoding="utf-8")
            original_duplicates = get_duplicate_packages(our_lock)
            specs = [f"{d.split()[0]}@{d.split()[1]}" for d in safe_deps]

            after = _cargo_update_specs(
                specs, original_content, original_duplicates, lockfile_path
            )

            if after and (name, off_ver) not in after:
                resolved.append((name, off_ver))
                progress = True
            else:
                # _cargo_update_specs reverts on duplicate regression; also
                # revert here if the off-version wasn't actually eliminated.
                lockfile_path.write_text(original_content, encoding="utf-8")

        if not progress:
            break

    # Build the unresolved report from whatever duplicates still remain.
    our_lock = load_lockfile("Cargo.lock")
    final_offenders = find_non_gecko_duplicates(our_lock, gecko_versions)
    unresolved: list[tuple[str, str, str]] = []
    for name, off_vers in final_offenders.items():
        for off_ver in off_vers:
            all_deps = find_dependents(our_lock, name, off_ver)
            safe_deps = [d for d in all_deps if d.split()[0] in safe_dependents]
            if not all_deps:
                reason = "no dependents found"
            elif not safe_deps:
                blockers = ", ".join(sorted({d.split()[0] for d in all_deps}))
                reason = f"pinned by non-safe dependent(s): {blockers}"
            else:
                reason = "cargo could not collapse onto surviving version"
            unresolved.append((name, off_ver, reason))

    return resolved, unresolved


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


def main():
    """Update Cargo.lock to align with Gecko's versions."""
    our_lock, gecko_lock = load_lockfiles()

    gecko_pkgs = parse_packages(gecko_lock)
    gecko_versions = get_all_versions(gecko_lock)
    our_pkgs = parse_packages(our_lock)

    common = set(gecko_pkgs) & set(our_pkgs)
    print(
        f"{len(gecko_pkgs)} packages in Gecko, {len(our_pkgs)} in ours, "
        f"{len(common)} in common",
        file=sys.stderr,
    )

    neqo_only, _ = find_neqo_or_workspace_deps(gecko_lock, our_lock)

    # Phase 1: Bump packages Gecko doesn't pin to their latest versions.
    # Includes packages absent from Gecko entirely and packages only neqo
    # uses within Gecko.  Any transitive conflicts are resolved in Phase 2.
    free_to_update = (set(our_pkgs) - set(gecko_pkgs)) | (neqo_only & common)
    run_free_updates(free_to_update, our_pkgs, "packages Gecko doesn't pin")

    # Reload after free updates so Phase 2 sees the current lockfile.
    our_pkgs = parse_packages(load_lockfile("Cargo.lock"))
    common = set(gecko_pkgs) & set(our_pkgs)

    # Phase 2: Align shared deps to Gecko's exact version (up or down).
    # Dev/build-only deps are only upgraded, never downgraded (see collect_version_updates).
    dev_only = find_dev_only_packages()
    version_updates = collect_version_updates(
        common, neqo_only, dev_only, gecko_pkgs, our_pkgs
    )

    if version_updates:
        # Snapshot before alignment for the transitive-change report.
        before_versions = {
            (name, ver) for name, versions in our_pkgs.items() for ver in versions
        }

        updated, downgraded, failed = apply_version_updates(version_updates)

        # Re-align packages cargo silently moved to non-Gecko versions during
        # the above updates (transitive deps resolved to crates.io latest).
        # Track attempted keys to guarantee termination.
        attempted: set[tuple[str, str]] = set(version_updates.keys())
        while True:
            updated_our_pkgs = parse_packages(load_lockfile("Cargo.lock"))
            current_common = set(gecko_pkgs) & set(updated_our_pkgs)
            new_updates: dict[tuple[str, str], str] = {}
            for name in current_common:
                if name in neqo_only:
                    continue
                for key, gecko_ver in align_package_with_gecko(
                    name, gecko_pkgs, updated_our_pkgs
                ).items():
                    _, our_ver = key
                    if key not in attempted:
                        if name in dev_only and Version(our_ver) > Version(gecko_ver):
                            continue
                        new_updates[key] = gecko_ver
            if not new_updates:
                break
            attempted |= set(new_updates.keys())
            extra_updated, extra_downgraded, extra_failed = apply_version_updates(new_updates)
            updated.extend(extra_updated)
            downgraded.extend(extra_downgraded)
            failed.update(extra_failed)

        # Detect silently-changed packages not explicitly tracked.
        after_versions = {
            (pkg["name"], pkg["version"])
            for pkg in load_lockfile("Cargo.lock").get("package", [])
        }
        explicitly_changed = {name for name, _, _ in updated + downgraded}
        silent = sorted(
            {name for name, _ in after_versions - before_versions}
            - explicitly_changed
        )

        print()
        if updated:
            print(f"Updated {len(updated)} package(s)")
        if downgraded:
            print(f"Downgraded {len(downgraded)} package(s)")
        if silent:
            print(f"Also updated (transitive): {', '.join(silent)}")
        if failed:
            report_failures(failed)
    else:
        print("\nAll shared packages aligned with Gecko versions")

    # Phase 3: Auto-dedup — collapse non-Gecko duplicate versions.
    # Only safe dependents (dev/build or neqo-only, never shared Gecko crates)
    # are bumped during dedup.  Re-load after Phase 2 so the set reflects any
    # packages that cargo added or removed during alignment.
    current_pkgs = parse_packages(load_lockfile("Cargo.lock"))
    safe_dependents = (set(current_pkgs) - set(gecko_pkgs)) | neqo_only
    resolved, unresolved = dedup_non_gecko_duplicates(gecko_versions, safe_dependents)

    if resolved:
        print(f"\nCollapsed {len(resolved)} non-Gecko duplicate(s):")
        for name, off_ver in sorted(resolved):
            print(f"  {name} {off_ver}")
    if unresolved:
        print("\nUnresolvable non-Gecko duplicate(s) (upstream fix needed):")
        for name, off_ver, reason in sorted(unresolved):
            print(f"  {name} {off_ver}: {reason}")

    # Phase 4: Warn about packages we're ahead of Gecko on (staged for vendor).
    final_lock = load_lockfile("Cargo.lock")
    final_pkgs = parse_packages(final_lock)
    final_common = set(gecko_pkgs) & set(final_pkgs)

    ahead = []
    for name in sorted(final_common):
        if name in neqo_only:
            continue
        our_vers = list(final_pkgs[name].keys())
        gecko_vers = [v for v, _ in gecko_versions.get(name, [])]
        if not gecko_vers:
            continue
        gecko_max = max(gecko_vers, key=Version)
        our_max = max(our_vers, key=Version)
        if Version(our_max) > Version(gecko_max):
            ahead.append((name, our_max, gecko_max))

    if ahead:
        print("\nPackages ahead of Gecko (staged for next vendor):")
        for name, our_ver, gecko_ver in ahead:
            print(f"  {name}: {our_ver} > {gecko_ver}")


if __name__ == "__main__":
    main()
