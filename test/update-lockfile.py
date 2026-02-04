#!/usr/bin/env python3
# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

"""
Compare Cargo.lock with Gecko's and output cargo update commands.

This script compares our Cargo.lock with Firefox/Gecko's Cargo.lock and outputs
cargo update commands to align versions. For crates that Gecko patches, it
creates matching patches in build/rust/:

- Empty stubs: Platform-specific crates not needed on desktop
- Wrapper patches: Simple re-exports bridging API changes between versions

Usage: Run from the workspace root (not inside test/).
"""

import json
import re
import subprocess
import sys
from dataclasses import dataclass
from graphlib import TopologicalSorter
from pathlib import Path
from urllib.request import urlopen

import tomlkit
from packaging.version import Version

from lockfile_utils import (
    GECKO_BUILD_RUST_URL,
    GECKO_RAW_URL,
    build_dependents_map,
    find_dev_only_packages,
    find_neqo_only_deps,
    get_duplicate_packages,
    is_registry_package,
    load_lockfile,
    load_lockfiles,
    parse_packages,
    semver_range,
)

PATCH_DIR = Path("build/rust")

# Threshold for determining if code content is substantial. Anything shorter
# (after stripping comments/whitespace) is considered an empty stub.
MIN_SUBSTANTIAL_CODE_LENGTH = 10


@dataclass
class GeckoPatch:
    """Information about a Gecko patch crate."""

    kind: str  # "empty", "wrapper", or "complex"
    cargo_toml: str | None = None  # Content of Cargo.toml (for wrappers)
    lib_rs: str | None = None  # Content of lib.rs (for wrappers)
    lib_path: str | None = (
        None  # Relative path to lib.rs (e.g., "lib.rs" or "src/lib.rs")
    )


def is_simple_wrapper(code: str) -> bool:
    """Check if code consists only of `pub use` re-export statements.

    A simple wrapper patch only re-exports items from another crate,
    with no additional logic, type definitions, or implementations.
    """
    # Remove block comments.
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
    # Remove line comments.
    code = re.sub(r"//.*", "", code)
    # Remove whitespace and newlines for analysis.
    code = code.strip()

    if not code:
        return False

    # Split into statements (semicolon-terminated).
    # Handle the case where `pub use` might span multiple lines.
    statements = [s.strip() for s in code.split(";") if s.strip()]

    # All statements must be `pub use` or `pub(crate) use` etc.
    use_pattern = re.compile(r"^pub(\s*\([^)]*\))?\s+use\s+")
    return all(use_pattern.match(stmt) for stmt in statements)


def fetch_gecko_patches() -> dict[str, GeckoPatch]:
    """Fetch Gecko's build/rust/ directory and classify patch crates.

    Returns a dict mapping crate name to GeckoPatch with:
    - kind="empty": Stub crates with no code (just license header)
    - kind="wrapper": Simple re-export wrappers (only `pub use` statements)
    - kind="complex": Patches with actual logic (require manual handling)
    """
    patches = {}

    # Fetch directory listing from GitHub API.
    try:
        with urlopen(GECKO_BUILD_RUST_URL) as response:
            entries = json.loads(response.read().decode())
    except Exception as e:
        print(f"Warning: Could not fetch Gecko patches list: {e}", file=sys.stderr)
        return patches

    for entry in entries:
        if entry.get("type") != "dir":
            continue

        name = entry["name"]

        # Try to fetch lib.rs (could be at lib.rs or src/lib.rs).
        lib_content = None
        lib_rel_path = None
        for lib_path in [f"build/rust/{name}/lib.rs", f"build/rust/{name}/src/lib.rs"]:
            try:
                with urlopen(f"{GECKO_RAW_URL}/{lib_path}") as response:
                    lib_content = response.read().decode()
                    # Extract relative path within the patch directory.
                    lib_rel_path = lib_path.split(f"{name}/", 1)[1]
                    break
            except Exception:
                continue

        if lib_content is None:
            continue

        # Check if it's empty (only comments and whitespace, no actual code).
        code = lib_content
        code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
        code = re.sub(r"//.*", "", code)
        code = code.strip()

        # Determine patch kind based on code content.
        if not code or len(code) < MIN_SUBSTANTIAL_CODE_LENGTH:
            kind = "empty"
        elif is_simple_wrapper(code):
            kind = "wrapper"
        else:
            patches[name] = GeckoPatch(kind="complex")
            continue

        # Fetch Cargo.toml for empty and wrapper patches.
        cargo_toml = None
        try:
            cargo_url = f"{GECKO_RAW_URL}/build/rust/{name}/Cargo.toml"
            with urlopen(cargo_url) as response:
                cargo_toml = response.read().decode()
        except Exception:
            # Can't fetch Cargo.toml, treat as complex.
            patches[name] = GeckoPatch(kind="complex")
            continue

        patches[name] = GeckoPatch(
            kind=kind,
            cargo_toml=cargo_toml,
            lib_rs=lib_content,
            lib_path=lib_rel_path,
        )

    return patches


def parse_version(v: str) -> Version:
    """Parse version string into a comparable Version object."""
    return Version(v)


def create_gecko_patch(crate: str, patch: GeckoPatch) -> bool:
    """Create or update a patch by copying Gecko's files.

    Returns True if files were created or changed, False if unchanged.
    """
    if not patch.cargo_toml or not patch.lib_rs or not patch.lib_path:
        return False

    patch_path = PATCH_DIR / crate
    cargo_file = patch_path / "Cargo.toml"
    lib_file = patch_path / patch.lib_path

    # Check if files already exist with same content.
    unchanged = (
        cargo_file.exists()
        and cargo_file.read_text(encoding="utf-8") == patch.cargo_toml
        and lib_file.exists()
        and lib_file.read_text(encoding="utf-8") == patch.lib_rs
    )
    if unchanged:
        return False

    # Create directories and write files.
    patch_path.mkdir(parents=True, exist_ok=True)
    cargo_file.write_text(patch.cargo_toml, encoding="utf-8")
    lib_file.parent.mkdir(parents=True, exist_ok=True)
    lib_file.write_text(patch.lib_rs, encoding="utf-8")

    return True


def remove_patch_from_cargo_toml(crate: str) -> bool:
    """Remove a patch entry from Cargo.toml. Returns True if removed, False if not found."""
    cargo_toml_path = Path("Cargo.toml")
    doc = tomlkit.parse(cargo_toml_path.read_text(encoding="utf-8"))

    if "patch" not in doc or "crates-io" not in doc["patch"]:
        return False

    if crate not in doc["patch"]["crates-io"]:
        return False

    del doc["patch"]["crates-io"][crate]

    # Clean up empty sections.
    if not doc["patch"]["crates-io"]:
        del doc["patch"]["crates-io"]
    if not doc["patch"]:
        del doc["patch"]

    cargo_toml_path.write_text(tomlkit.dumps(doc), encoding="utf-8")
    return True


def remove_gecko_patch(crate: str) -> bool:
    """Remove a patch directory. Returns True if removed, False if not found."""
    import shutil

    patch_path = PATCH_DIR / crate
    if not patch_path.exists():
        return False

    shutil.rmtree(patch_path)
    return True


def cleanup_unused_patches(
    our_lock: dict, gecko_lock: dict, gecko_patches: dict[str, GeckoPatch]
) -> list[str]:
    """Remove patches that are no longer needed.

    A patch is no longer needed if:
    - We no longer depend on that crate, OR
    - Gecko no longer uses a 999 version for that crate, OR
    - Gecko's patch is now complex (requires manual handling)

    Returns list of removed patch names.
    """
    removed = []

    if not PATCH_DIR.exists():
        return removed

    # Get crates we depend on.
    our_crates = {pkg["name"] for pkg in our_lock.get("package", [])}

    for patch_path in PATCH_DIR.iterdir():
        if not patch_path.is_dir():
            continue

        crate = patch_path.name
        reason = None

        # Check if we still depend on this crate.
        if crate not in our_crates:
            reason = "no longer a dependency"
        else:
            # Check if Gecko still uses a 999 version for this crate.
            gecko_versions = [
                pkg["version"]
                for pkg in gecko_lock.get("package", [])
                if pkg["name"] == crate
            ]
            has_999_version = any("999" in v for v in gecko_versions)

            if not has_999_version:
                reason = "Gecko no longer uses 999 patch"
            elif gecko_patches.get(crate, GeckoPatch(kind="unknown")).kind == "complex":
                reason = "Gecko patch is now complex"

        if reason:
            if remove_patch_from_cargo_toml(crate):
                print(f"# Removed {crate} from [patch.crates-io] ({reason})")
            if remove_gecko_patch(crate):
                print(f"# Removed patch directory: {PATCH_DIR}/{crate}")
                removed.append(crate)

    return removed


def update_neqo_only_packages(packages: list[str]) -> dict[str, tuple[str, str]]:
    """Update all neqo-only packages together to their latest versions.

    Updates all packages at once, which allows transitive dependencies to unify.
    For example, if both enumset and serde_with need darling, updating them together
    allows them to share a single darling version.

    Returns a dict of package name -> (old_version, new_version) for updated packages.
    """
    if not packages:
        return {}

    # Save current lockfile state.
    original_lock = load_lockfile("Cargo.lock")
    original_versions = {
        pkg["name"]: pkg["version"]
        for pkg in original_lock.get("package", [])
        if pkg["name"] in packages
    }
    original_duplicates = get_duplicate_packages(original_lock)

    # Update all packages at once.
    cmd = ["cargo", "update"] + [arg for p in packages for arg in ["-p", p]]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return {}

    # Check results.
    new_lock = load_lockfile("Cargo.lock")
    new_versions = {
        pkg["name"]: pkg["version"]
        for pkg in new_lock.get("package", [])
        if pkg["name"] in packages
    }
    new_duplicates = get_duplicate_packages(new_lock)

    # Check for new duplicate packages (same name, multiple versions).
    added_duplicates = set(new_duplicates.keys()) - set(original_duplicates.keys())
    if added_duplicates:
        # New duplicates introduced. Revert and report.
        print(f"  Update would introduce duplicate dependencies:")
        for name in sorted(added_duplicates):
            print(f"    {name}: {', '.join(new_duplicates[name])}")

        # Revert all changes.
        for name, version in original_versions.items():
            subprocess.run(
                ["cargo", "update", "-p", name, "--precise", version],
                capture_output=True,
                check=False,
            )
        print(f"  Reverted to original versions")
        return {}

    # Collect updated packages.
    updated = {}
    for name in packages:
        old_ver = original_versions.get(name)
        new_ver = new_versions.get(name)
        if old_ver and new_ver and old_ver != new_ver:
            updated[name] = (old_ver, new_ver)

    return updated


def add_patch_to_cargo_toml(crate: str) -> bool:
    """Add a patch entry to Cargo.toml. Returns True if added, False if exists."""
    cargo_toml_path = Path("Cargo.toml")
    doc = tomlkit.parse(cargo_toml_path.read_text(encoding="utf-8"))

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
    cargo_toml_path.write_text(tomlkit.dumps(doc), encoding="utf-8")
    return True


def main():
    """Update Cargo.lock to align with Gecko's versions."""
    # Fetch and classify Gecko's patches.
    print("Fetching Gecko patches...", file=sys.stderr)
    gecko_patches = fetch_gecko_patches()

    # Load both lockfiles.
    our_lock, gecko_lock = load_lockfiles()

    gecko_pkgs = parse_packages(gecko_lock)
    our_pkgs = parse_packages(our_lock)

    # Find common packages (intersection).
    common = set(gecko_pkgs) & set(our_pkgs)
    print(
        f"{len(gecko_pkgs)} packages in Gecko, {len(our_pkgs)} in ours, {len(common)} in common",
        file=sys.stderr,
    )

    # Clean up patches that are no longer needed.
    removed_patches = cleanup_unused_patches(our_lock, gecko_lock, gecko_patches)
    if removed_patches:
        # Refresh lockfile after removing patches.
        subprocess.run(["cargo", "update"], capture_output=True, check=False)
        our_lock = load_lockfile("Cargo.lock")
        our_pkgs = parse_packages(our_lock)

    # Sync existing patches with Gecko's content.
    # This ensures we track any changes Gecko makes to their patches.
    for name, patch in gecko_patches.items():
        if patch.kind in ("empty", "wrapper") and (PATCH_DIR / name).exists():
            if create_gecko_patch(name, patch):
                print(f"# Synced {patch.kind} patch: {PATCH_DIR}/{name}")

    # Find packages that only neqo depends on in Gecko.
    # We'll update these to latest rather than aligning with Gecko.
    neqo_only = find_neqo_only_deps(gecko_lock, our_lock)

    # Collect version updates needed, grouped by (name, our_version) -> gecko_version.
    # This handles multiple versions of the same crate.
    # Exclude neqo-only packages since we want to update those to latest.
    patches_created: list[tuple[str, str]] = []  # [(name, our_version), ...]
    version_updates: dict[tuple[str, str], str] = {}  # (name, our_ver) -> gecko_ver

    for name in common:
        # Skip neqo-only packages - we'll update those to latest, not align with Gecko.
        if name in neqo_only:
            continue
        gecko_versions = gecko_pkgs[name]  # {version -> info}
        our_versions = our_pkgs[name]  # {version -> info}

        # Skip workspace crates (no source on any version).
        if all(not is_registry_package(info) for info in our_versions.values()):
            continue

        # Group versions by semver range (major.minor).
        gecko_by_range: dict[str, list[str]] = {}
        for ver in gecko_versions:
            gecko_by_range.setdefault(semver_range(ver), []).append(ver)

        our_by_range: dict[str, list[str]] = {}
        for ver, info in our_versions.items():
            if is_registry_package(info):
                our_by_range.setdefault(semver_range(ver), []).append(ver)

        # For each semver range we have, check what Gecko has.
        for sv_range, our_vers in our_by_range.items():
            gecko_vers = gecko_by_range.get(sv_range, [])

            if not gecko_vers:
                # Gecko doesn't have this range; nothing to align.
                continue

            # Find Gecko's version for this range (prefer 999 patch, else registry).
            gecko_999 = [v for v in gecko_vers if "999" in v]
            gecko_registry = [v for v in gecko_vers if "999" not in v]

            if gecko_999:
                # Gecko uses a 999 patch for this range.
                gecko_ver = gecko_999[0]
                patch = gecko_patches.get(name)

                if patch is None:
                    print(
                        f"# Skipping {name} {sv_range}.x: "
                        f"Gecko uses 999 patch but patch not found",
                        file=sys.stderr,
                    )
                    continue

                if patch.kind in ("empty", "wrapper"):
                    if create_gecko_patch(name, patch):
                        print(f"# Updated {patch.kind} patch: {PATCH_DIR}/{name}")
                    for our_ver in our_vers:
                        patches_created.append((name, our_ver))
                else:  # complex
                    print(
                        f"# Skipping Gecko complex patch for {name} "
                        f"(requires manual handling)"
                    )
            elif gecko_registry:
                # Gecko uses a registry version; update ours to match.
                gecko_ver = gecko_registry[0]
                for our_ver in our_vers:
                    if our_ver != gecko_ver:
                        version_updates[(name, our_ver)] = gecko_ver

    # Add created patches to Cargo.toml and update Cargo.lock to use them.
    patches_added: set[str] = set()
    for name, our_ver in patches_created:
        if name not in patches_added:
            if add_patch_to_cargo_toml(name):
                print(f"# Added {name} to [patch.crates-io] in Cargo.toml")
            patches_added.add(name)

        # Run cargo update to pick up the patch, specifying the version being replaced.
        result = subprocess.run(
            ["cargo", "update", "-p", f"{name}@{our_ver}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            print(f"# Updated {name}@{our_ver} to use patch")

    # Update neqo-only packages to latest (these were excluded from version alignment).
    neqo_only_in_common = neqo_only & common

    if neqo_only_in_common:
        # Filter to registry packages only.
        packages_to_update = []
        for name in sorted(neqo_only_in_common):
            our_versions = our_pkgs.get(name, {})
            if any(is_registry_package(info) for info in our_versions.values()):
                packages_to_update.append(name)

        if packages_to_update:
            print(f"\nUpdating {len(packages_to_update)} neqo-only packages...")
            print("(These only neqo depends on in Gecko, so we can update freely)")

            updated = update_neqo_only_packages(packages_to_update)

            if updated:
                for name, (old_ver, new_ver) in sorted(updated.items()):
                    print(f"  {name}: {old_ver} -> {new_ver}")
                print(f"Updated {len(updated)} neqo-only package(s)")
            else:
                print("All neqo-only packages already at newest compatible version")

    if not version_updates:
        print("\nAll shared packages aligned with Gecko versions")
        return

    # Build dependency graph for topological sort.
    # We need to update dependents before dependencies.
    all_names = {name for name, _ in version_updates}
    graph: dict[str, list[str]] = {name: [] for name in all_names}

    our_pkgs = parse_packages(load_lockfile("Cargo.lock"))
    for name in all_names:
        for ver, info in our_pkgs.get(name, {}).items():
            for dep in info["deps"]:
                if dep in all_names:
                    graph[name].append(dep)

    updated = []
    downgraded = []
    failed = {}

    # Loop until no more updates succeed, since updating one crate can unlock others.
    made_progress = True
    while made_progress:
        made_progress = False
        failed.clear()

        # Re-read lockfile to get current versions after any updates.
        our_pkgs = parse_packages(load_lockfile("Cargo.lock"))

        for name in TopologicalSorter(graph).static_order():
            # Find pending updates for this package.
            pending = [
                (our_ver, gecko_ver)
                for (n, our_ver), gecko_ver in version_updates.items()
                if n == name
            ]

            for our_ver, gecko_ver in pending:
                # Check if we still have this version.
                if name not in our_pkgs or our_ver not in our_pkgs[name]:
                    continue

                # Check if already at target.
                if our_ver == gecko_ver:
                    continue

                is_downgrade = parse_version(gecko_ver) < parse_version(our_ver)
                action = "Downgrading" if is_downgrade else "Updating"

                cmd = [
                    "cargo",
                    "update",
                    "-p",
                    f"{name}@{our_ver}",
                    "--precise",
                    gecko_ver,
                ]
                print(f"{action} {name}: {our_ver} -> {gecko_ver}")
                result = subprocess.run(
                    cmd, capture_output=True, text=True, check=False
                )

                if result.returncode != 0:
                    err_lines = [
                        ln
                        for ln in result.stderr.strip().split("\n")
                        if not ln.startswith("Updating") and ln.strip()
                    ]
                    failed[(name, our_ver)] = (
                        gecko_ver,
                        err_lines[0] if err_lines else "Unknown error",
                    )
                else:
                    made_progress = True
                    if is_downgrade:
                        downgraded.append((name, our_ver, gecko_ver))
                    else:
                        updated.append((name, our_ver, gecko_ver))

    # Summary.
    print()
    if updated:
        print(f"Updated {len(updated)} package(s)")
    if downgraded:
        print(f"Downgraded {len(downgraded)} package(s)")

    if failed:
        # Determine which failures are due to dev-only dependencies.
        dev_only = find_dev_only_packages()
        dependents = build_dependents_map(load_lockfile("Cargo.lock"))

        dev_failures = {}
        real_failures = {}
        for (name, our_ver), (gecko_ver, err) in failed.items():
            pkg_dependents = dependents.get(name, [])
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
                    f"(blocked by: {', '.join(blockers)})"
                )


if __name__ == "__main__":
    main()
