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
from pathlib import Path
from urllib.request import urlopen

import tomlkit

GECKO_LOCKFILE_URL = (
    "https://raw.githubusercontent.com"
    "/mozilla-firefox/firefox/refs/heads/main/Cargo.lock"
)


def load_lockfile(src: str) -> dict:
    """Load a Cargo.lock from a path or URL."""
    if src.startswith(("http://", "https://")):
        with urlopen(src) as response:
            return tomlkit.loads(response.read().decode())
    with open(src, "r", encoding="utf-8") as f:
        return tomlkit.load(f)


def get_all_versions(lock: dict) -> dict[str, list[tuple[str, str]]]:
    """Parse lockfile into name -> [(version, source), ...]."""
    versions: dict[str, list[tuple[str, str]]] = {}
    for pkg in lock.get("package", []):
        name = pkg["name"]
        version = pkg["version"]
        source = pkg.get("source", "local")
        versions.setdefault(name, []).append((version, source))
    return versions


def semver_range(version: str) -> str:
    """Extract major.minor from a version string."""
    parts = version.split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return parts[0]


def find_dev_only_packages() -> set[str]:
    """Find packages only reachable via dev/build dependencies."""
    workspace_toml = Path("Cargo.toml")
    with open(workspace_toml, "r", encoding="utf-8") as f:
        workspace = tomlkit.load(f)

    members = workspace.get("workspace", {}).get("members", [])

    dev_build_roots = set()
    normal_deps = set()

    for member in members:
        member_toml = Path(member) / "Cargo.toml"
        if not member_toml.exists():
            continue
        with open(member_toml, "r", encoding="utf-8") as f:
            cargo = tomlkit.load(f)

        for dep in cargo.get("dependencies", {}):
            normal_deps.add(dep)
        for dep in cargo.get("dev-dependencies", {}):
            dev_build_roots.add(dep)
        for dep in cargo.get("build-dependencies", {}):
            dev_build_roots.add(dep)

    ws_deps = workspace.get("workspace", {})
    for dep in ws_deps.get("dev-dependencies", {}):
        dev_build_roots.add(dep)
    for dep in ws_deps.get("build-dependencies", {}):
        dev_build_roots.add(dep)

    with open("Cargo.lock", "r", encoding="utf-8") as f:
        lock = tomlkit.load(f)

    pkg_deps: dict[str, list[str]] = {}
    for pkg in lock.get("package", []):
        name = pkg["name"]
        deps = [d.split()[0] for d in pkg.get("dependencies", [])]
        pkg_deps[name] = deps

    dev_only = set()
    to_visit = list(dev_build_roots - normal_deps)

    while to_visit:
        pkg = to_visit.pop()
        if pkg in dev_only:
            continue
        dev_only.add(pkg)
        for dep in pkg_deps.get(pkg, []):
            if dep not in dev_only and dep not in normal_deps:
                to_visit.append(dep)

    return dev_only


def find_dependents(lock: dict, package: str, version: str | None = None) -> list[str]:
    """Find all packages that directly depend on the given package.

    If version is specified, only return dependents that use that specific version.
    """
    dependents = []
    for pkg in lock.get("package", []):
        deps = pkg.get("dependencies", [])
        for dep in deps:
            parts = dep.split()
            dep_name = parts[0]
            dep_ver = parts[1] if len(parts) > 1 else None

            if dep_name == package:
                if version is None or dep_ver == version:
                    dependents.append(f"{pkg['name']} {pkg['version']}")
    return dependents


def main():
    """Compare Cargo.lock versions with Gecko's and report alignment status."""
    print("Fetching Gecko lockfile...", file=sys.stderr)
    try:
        gecko_lock = load_lockfile(GECKO_LOCKFILE_URL)
    except Exception as e:
        sys.exit(f"Error fetching Gecko lockfile: {e}")

    try:
        our_lock = load_lockfile("Cargo.lock")
    except FileNotFoundError:
        sys.exit("Error: Cargo.lock not found. Run from the workspace root.")

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
        prod_mismatch_count = 0

        for name, our_str, their_str, status, issues in mismatches:
            print(f"{name:<30} {our_str:<25} {their_str:<25} {status}")

            # Check dependents for each mismatched version specifically
            is_dev_only = True
            for desc, our_ver, gecko_ver in issues:
                dependents = find_dependents(our_lock, name, our_ver)
                if not dependents:
                    # If no specific version match, fall back to package-level
                    dependents = find_dependents(our_lock, name)

                all_dev = all(d.split()[0] in dev_only for d in dependents)
                if not all_dev:
                    is_dev_only = False

                if dependents:
                    dep_status = " (dev/build only)" if all_dev else " (PRODUCTION)"
                    print(
                        f"  {our_ver + ' depended on by:':<28} {', '.join(dependents)}{dep_status}"
                    )

            if not is_dev_only:
                prod_mismatch_count += 1

        dev_mismatch_count = len(mismatches) - prod_mismatch_count

        print(f"\nSummary: {len(matches)} matches, {len(mismatches)} mismatches")
        print(f"  - {dev_mismatch_count} dev/build-only (don't affect Gecko)")
        print(f"  - {prod_mismatch_count} production (need attention)")

        if prod_mismatch_count > 0:
            sys.exit(1)
    else:
        print(f"\nAll {len(matches)} common packages match!")


if __name__ == "__main__":
    main()
