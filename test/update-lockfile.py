#!/usr/bin/env python3
# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

"""
Compare Cargo.lock with Gecko's and output cargo update commands.

This script compares our Cargo.lock with Firefox/Gecko's Cargo.lock and outputs
cargo update commands to align versions. For crates that Gecko patches to empty
stubs (platform-specific crates not needed on desktop), it creates matching
empty patches in build/rust/.

Usage: Run from the workspace root (not inside test/).
"""

import subprocess
import sys
from graphlib import TopologicalSorter
from pathlib import Path
from urllib.request import urlopen

import tomlkit
from packaging.version import Version

GECKO_LOCKFILE_URL = "https://raw.githubusercontent.com/mozilla-firefox/firefox/refs/heads/main/Cargo.lock"
GECKO_BUILD_RUST_URL = (
    "https://api.github.com/repos/mozilla-firefox/firefox/contents/build/rust"
)
GECKO_RAW_URL = (
    "https://raw.githubusercontent.com/mozilla-firefox/firefox/refs/heads/main"
)

PATCH_DIR = Path("build/rust")

# Threshold for determining if code content is substantial. Anything shorter
# (after stripping comments/whitespace) is considered an empty stub.
MIN_SUBSTANTIAL_CODE_LENGTH = 10

LICENSE_HEADER = """\
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Empty stub - this crate is not used on supported platforms.
"""


def fetch_gecko_empty_patches() -> set[str]:
    """Fetch Gecko's build/rust/ directory and identify empty patch crates.

    Empty patches are stubs for platform-specific crates that Gecko doesn't need.
    They contain only a license header, no actual code or re-exports.
    """
    import json
    import re

    empty_patches = set()

    # Fetch directory listing from GitHub API.
    try:
        with urlopen(GECKO_BUILD_RUST_URL) as response:
            entries = json.loads(response.read().decode())
    except Exception as e:
        print(f"Warning: Could not fetch Gecko patches list: {e}", file=sys.stderr)
        return empty_patches

    for entry in entries:
        if entry.get("type") != "dir":
            continue

        name = entry["name"]

        # Try to fetch lib.rs (could be at lib.rs or src/lib.rs).
        lib_content = None
        for lib_path in [f"build/rust/{name}/lib.rs", f"build/rust/{name}/src/lib.rs"]:
            try:
                with urlopen(f"{GECKO_RAW_URL}/{lib_path}") as response:
                    lib_content = response.read().decode()
                    break
            except Exception:
                continue

        if lib_content is None:
            continue

        # Check if it's empty (only comments and whitespace, no actual code).
        # Remove comments and check if anything substantial remains.
        code = lib_content
        # Remove block comments.
        code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
        # Remove line comments.
        code = re.sub(r"//.*", "", code)
        # Remove whitespace.
        code = code.strip()

        # If nothing remains, or only a single short line, it's empty.
        # Re-export patches have "pub use something::*;" which we exclude.
        if not code or (
            len(code) < MIN_SUBSTANTIAL_CODE_LENGTH and "pub use" not in lib_content
        ):
            empty_patches.add(name)

    return empty_patches


def find_dev_only_packages() -> set[str]:
    """Find packages that are only dev-dependencies or build-dependencies.

    These don't affect Gecko integration since Gecko doesn't use our dev/build deps.
    """
    # Parse workspace Cargo.toml to find members.
    workspace_toml = Path("Cargo.toml")
    with open(workspace_toml, "r") as f:
        workspace = tomlkit.load(f)

    members = workspace.get("workspace", {}).get("members", [])

    # Collect direct dev and build dependencies from all workspace members.
    dev_build_roots = set()
    normal_deps = set()

    for member in members:
        member_toml = Path(member) / "Cargo.toml"
        if not member_toml.exists():
            continue
        with open(member_toml, "r") as f:
            cargo = tomlkit.load(f)

        # Collect normal dependencies.
        for dep in cargo.get("dependencies", {}):
            normal_deps.add(dep)

        # Collect dev-dependencies.
        for dep in cargo.get("dev-dependencies", {}):
            dev_build_roots.add(dep)

        # Collect build-dependencies.
        for dep in cargo.get("build-dependencies", {}):
            dev_build_roots.add(dep)

    # Also check workspace-level dev/build dependencies.
    ws_deps = workspace.get("workspace", {})
    for dep in ws_deps.get("dev-dependencies", {}):
        dev_build_roots.add(dep)
    for dep in ws_deps.get("build-dependencies", {}):
        dev_build_roots.add(dep)

    # Load lockfile to trace transitive dependencies.
    with open("Cargo.lock", "r") as f:
        lock = tomlkit.load(f)

    pkg_deps = {}
    for pkg in lock.get("package", []):
        name = pkg["name"]
        deps = [d.split()[0] for d in pkg.get("dependencies", [])]
        pkg_deps[name] = deps

    # Find all packages transitively reachable from dev/build roots.
    dev_only = set()
    to_visit = list(dev_build_roots - normal_deps)  # Only those not also normal deps.

    while to_visit:
        pkg = to_visit.pop()
        if pkg in dev_only:
            continue
        dev_only.add(pkg)
        for dep in pkg_deps.get(pkg, []):
            if dep not in dev_only and dep not in normal_deps:
                to_visit.append(dep)

    return dev_only


def parse_version(v: str) -> Version:
    """Parse version string into a comparable Version object."""
    return Version(v)


def load_lockfile(src: str) -> dict:
    """Load a Cargo.lock from a path or URL."""
    if src.startswith(("http://", "https://")):
        with urlopen(src) as response:
            return tomlkit.loads(response.read().decode())
    with open(src, "r") as f:
        return tomlkit.load(f)


def parse_packages(lock: dict, prefer_registry: bool = False) -> dict[str, dict]:
    """Parse lockfile into a dict of name -> {version, deps, source}."""
    packages = {}
    for pkg in lock.get("package", []):
        name = pkg["name"]
        source = pkg.get("source")
        version = pkg["version"]

        # When prefer_registry is True, prefer crates.io versions over local patches.
        if name in packages:
            if prefer_registry:
                # Skip local patches (no source) and our own 999 patches.
                if not source or "999" in version:
                    continue
            elif not source:
                continue

        packages[name] = {
            "version": version,
            "deps": [d.split()[0] for d in pkg.get("dependencies", [])],
            "source": source,
        }
    return packages


def create_empty_patch(crate: str, version: str) -> bool:
    """Create an empty patch crate. Returns True if created, False if exists."""
    patch_path = PATCH_DIR / crate
    if patch_path.exists():
        return False

    # Use version as-is if it's already a 999 version, otherwise generate one.
    if "999" in version:
        patch_version = version
    else:
        parts = version.split(".")
        major, minor = parts[0], parts[1] if len(parts) > 1 else "0"
        patch_version = f"{major}.{minor}.999"

    patch_path.mkdir(parents=True, exist_ok=True)

    cargo_toml = f"""\
[package]
name = "{crate}"
version = "{patch_version}"
edition = "2021"
license = "MIT OR Apache-2.0"

[lib]
path = "lib.rs"
"""
    (patch_path / "Cargo.toml").write_text(cargo_toml)
    (patch_path / "lib.rs").write_text(LICENSE_HEADER)
    return True


def add_patch_to_cargo_toml(crate: str) -> bool:
    """Add a patch entry to Cargo.toml. Returns True if added, False if exists."""
    cargo_toml_path = Path("Cargo.toml")
    doc = tomlkit.parse(cargo_toml_path.read_text())

    # Ensure [patch.crates-io] section exists.
    if "patch" not in doc:
        doc["patch"] = {"crates-io": {}}
    if "crates-io" not in doc["patch"]:
        doc["patch"]["crates-io"] = {}

    # Check if patch already exists.
    if crate in doc["patch"]["crates-io"]:
        return False

    # Add the patch entry.
    doc["patch"]["crates-io"][crate] = {"path": f"{PATCH_DIR}/{crate}"}
    cargo_toml_path.write_text(tomlkit.dumps(doc))
    return True


def main():
    # Fetch list of Gecko's empty patches.
    print("Fetching Gecko empty patches list...", file=sys.stderr)
    gecko_empty_patches = fetch_gecko_empty_patches()

    # Load both lockfiles.
    print(f"Fetching {GECKO_LOCKFILE_URL}...", file=sys.stderr)
    try:
        gecko_lock = load_lockfile(GECKO_LOCKFILE_URL)
    except Exception as e:
        sys.exit(f"Error fetching Gecko lockfile: {e}")

    try:
        our_lock = load_lockfile("Cargo.lock")
    except FileNotFoundError:
        sys.exit("Error: Cargo.lock not found. Run from the workspace root.")

    gecko_pkgs = parse_packages(gecko_lock)
    our_pkgs = parse_packages(our_lock, prefer_registry=True)

    # Find common packages (intersection).
    common = set(gecko_pkgs) & set(our_pkgs)
    print(
        f"{len(gecko_pkgs)} packages in Gecko, {len(our_pkgs)} in ours, {len(common)} in common",
        file=sys.stderr,
    )

    # Find version differences, skipping workspace crates.
    different = {}
    patches_created = []

    for name in common:
        gecko_pkg = gecko_pkgs[name]
        our_pkg = our_pkgs[name]

        # Skip workspace crates (no source).
        if not our_pkg["source"]:
            continue

        if gecko_pkg["version"] == our_pkg["version"]:
            continue

        gecko_version = gecko_pkg["version"]

        # Handle Gecko 999 patches.
        if "999" in gecko_version:
            if name in gecko_empty_patches:
                # Use Gecko's version (e.g., 0.3.999) to match their semver patching.
                if create_empty_patch(name, gecko_version):
                    print(f"# Created empty patch: {PATCH_DIR}/{name}")
                patches_created.append(name)
            else:
                print(
                    f"# Skipping Gecko non-empty patch for {name} (requires manual handling)"
                )
            continue

        different[name] = gecko_pkg

    # Add created patches to Cargo.toml and update Cargo.lock to use them.
    for crate in patches_created:
        if add_patch_to_cargo_toml(crate):
            print(f"# Added {crate} to [patch.crates-io] in Cargo.toml")
        # Run cargo update to pick up the patch (even if already in Cargo.toml).
        result = subprocess.run(
            ["cargo", "update", "-p", crate],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            print(f"# Updated {crate} to use patch")

    if not different:
        print("All packages have the same versions (excluding Gecko patches)")
        return

    # Re-read our lockfile in case patches changed it.
    our_pkgs = parse_packages(load_lockfile("Cargo.lock"), prefer_registry=True)

    # Filter out packages no longer in our lockfile.
    different = {k: v for k, v in different.items() if k in our_pkgs}

    if not different:
        print("All packages have the same versions (excluding Gecko patches)")
        return

    # Topological sort: dependents before dependencies.
    graph = {
        name: [d for d in pkg["deps"] if d in different]
        for name, pkg in different.items()
    }

    updated = []
    downgraded = []
    failed = {}

    # Loop until no more updates succeed, since updating one crate can unlock others.
    made_progress = True
    while made_progress:
        made_progress = False
        failed.clear()

        # Re-read lockfile to get current versions after any updates.
        our_pkgs = parse_packages(load_lockfile("Cargo.lock"), prefer_registry=True)

        for name in TopologicalSorter(graph).static_order():
            if name not in our_pkgs:
                continue  # Package no longer in lockfile.

            gecko_version = different[name]["version"]
            our_version = our_pkgs[name]["version"]

            if gecko_version == our_version:
                continue  # Already at target version.

            is_downgrade = parse_version(gecko_version) < parse_version(our_version)

            action = "Downgrading" if is_downgrade else "Updating"
            # Use name@version to avoid ambiguity when multiple versions exist.
            cmd = [
                "cargo",
                "update",
                "-p",
                f"{name}@{our_version}",
                "--precise",
                gecko_version,
            ]
            print(f"{action} {name}: {our_version} -> {gecko_version}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                # Extract the actual error (skip "Updating crates.io index" line).
                err_lines = [
                    ln
                    for ln in result.stderr.strip().split("\n")
                    if not ln.startswith("Updating") and ln.strip()
                ]
                failed[name] = (
                    our_version,
                    gecko_version,
                    err_lines[0] if err_lines else "Unknown error",
                )
            else:
                made_progress = True
                if is_downgrade:
                    downgraded.append(name)
                else:
                    updated.append(name)

    # Summary
    print()
    if updated:
        print(f"Updated {len(updated)} package(s)")
    if downgraded:
        print(f"Downgraded {len(downgraded)} package(s)")
    if failed:
        # Determine which failures are due to dev-only dependencies.
        dev_only = find_dev_only_packages()

        # Parse lockfile to find what requires each failed package.
        with open("Cargo.lock", "r") as f:
            lock = tomlkit.load(f)
        dependents = {}
        for pkg in lock.get("package", []):
            for dep in pkg.get("dependencies", []):
                dep_name = dep.split()[0]
                if dep_name in failed:
                    dependents.setdefault(dep_name, []).append(pkg["name"])

        dev_failures = {}
        real_failures = {}
        for name, (ours, theirs, err) in failed.items():
            # Check if all dependents are dev-only packages.
            pkg_dependents = dependents.get(name, [])
            if pkg_dependents and all(d in dev_only for d in pkg_dependents):
                dev_failures[name] = (ours, theirs, pkg_dependents)
            else:
                real_failures[name] = (ours, theirs, err)

        if real_failures:
            print(f"Failed {len(real_failures)} package(s):")
            for name, (ours, theirs, err) in real_failures.items():
                print(f"  {name}: {ours} -> {theirs}: {err}")

        if dev_failures:
            print(
                f"\nSkipped {len(dev_failures)} package(s) due to dev-dependency constraints:"
            )
            print(
                "  (These don't affect Gecko integration since Gecko ignores dev-dependencies)"
            )
            for name, (ours, theirs, blockers) in dev_failures.items():
                print(
                    f"  {name}: {ours} -> {theirs} (blocked by: {', '.join(blockers)})"
                )


if __name__ == "__main__":
    main()
