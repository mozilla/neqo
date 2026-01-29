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

GECKO_LOCKFILE_URL = (
    "https://raw.githubusercontent.com"
    "/mozilla-firefox/firefox/refs/heads/main/Cargo.lock"
)
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


def find_dev_only_packages() -> set[str]:
    """Find packages that are only dev-dependencies or build-dependencies.

    These don't affect Gecko integration since Gecko doesn't use our dev/build deps.
    """
    # Parse workspace Cargo.toml to find members.
    workspace_toml = Path("Cargo.toml")
    with open(workspace_toml, "r", encoding="utf-8") as f:
        workspace = tomlkit.load(f)

    members = workspace.get("workspace", {}).get("members", [])

    # Collect direct dev and build dependencies from all workspace members.
    dev_build_roots = set()
    normal_deps = set()

    for member in members:
        member_toml = Path(member) / "Cargo.toml"
        if not member_toml.exists():
            continue
        with open(member_toml, "r", encoding="utf-8") as f:
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
    with open("Cargo.lock", "r", encoding="utf-8") as f:
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
    with open(src, "r", encoding="utf-8") as f:
        return tomlkit.load(f)


def parse_packages(lock: dict) -> dict[str, dict[str, dict]]:
    """Parse lockfile into a dict of name -> {version -> {deps, source}}.

    Tracks all versions of each package, not just one.
    """
    packages: dict[str, dict[str, dict]] = {}
    for pkg in lock.get("package", []):
        name = pkg["name"]
        version = pkg["version"]
        source = pkg.get("source")

        if name not in packages:
            packages[name] = {}

        packages[name][version] = {
            "deps": [d.split()[0] for d in pkg.get("dependencies", [])],
            "source": source,
        }
    return packages


def semver_range(version: str) -> str:
    """Extract major.minor semver range from a version string."""
    parts = version.split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return parts[0]


def is_registry_version(info: dict) -> bool:
    """Check if a package version is from a registry (not a local patch)."""
    source = info.get("source")
    return source is not None and source.startswith("registry")


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
    our_pkgs = parse_packages(our_lock)

    # Find common packages (intersection).
    common = set(gecko_pkgs) & set(our_pkgs)
    print(
        f"{len(gecko_pkgs)} packages in Gecko, {len(our_pkgs)} in ours, {len(common)} in common",
        file=sys.stderr,
    )

    # Sync existing patches with Gecko's content.
    # This ensures we track any changes Gecko makes to their patches.
    for name, patch in gecko_patches.items():
        if patch.kind in ("empty", "wrapper") and (PATCH_DIR / name).exists():
            if create_gecko_patch(name, patch):
                print(f"# Synced {patch.kind} patch: {PATCH_DIR}/{name}")

    # Collect version updates needed, grouped by (name, our_version) -> gecko_version.
    # This handles multiple versions of the same crate.
    patches_created: list[tuple[str, str]] = []  # [(name, our_version), ...]
    version_updates: dict[tuple[str, str], str] = {}  # (name, our_ver) -> gecko_ver

    for name in common:
        gecko_versions = gecko_pkgs[name]  # {version -> info}
        our_versions = our_pkgs[name]  # {version -> info}

        # Skip workspace crates (no source on any version).
        if all(not is_registry_version(info) for info in our_versions.values()):
            continue

        # Group versions by semver range (major.minor).
        gecko_by_range: dict[str, list[str]] = {}
        for ver in gecko_versions:
            gecko_by_range.setdefault(semver_range(ver), []).append(ver)

        our_by_range: dict[str, list[str]] = {}
        for ver, info in our_versions.items():
            if is_registry_version(info):
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

    if not version_updates:
        print("All packages have the same versions (excluding Gecko patches)")
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

        # Parse lockfile to find what requires each failed package.
        with open("Cargo.lock", "r", encoding="utf-8") as f:
            lock = tomlkit.load(f)
        dependents: dict[str, list[str]] = {}
        for pkg in lock.get("package", []):
            for dep in pkg.get("dependencies", []):
                dep_name = dep.split()[0]
                dependents.setdefault(dep_name, []).append(pkg["name"])

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
