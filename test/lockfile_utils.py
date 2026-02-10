#!/usr/bin/env python3
# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

"""
Shared utilities for Cargo.lock comparison and update scripts.
"""

import os
import sys
from pathlib import Path
from urllib.request import Request, urlopen

import tomlkit

GECKO_RAW_URL = (
    "https://raw.githubusercontent.com/mozilla-firefox/firefox/refs/heads/main"
)
GECKO_LOCKFILE_URL = f"{GECKO_RAW_URL}/Cargo.lock"

# Timeout in seconds for HTTP requests.
HTTP_TIMEOUT = 30


def github_api_request(url: str) -> bytes:
    """Make a GitHub API request, using token from GITHUB_TOKEN env if available."""
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GITHUB_API_TOKEN")
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"

    headers["User-Agent"] = "neqo-lockfile-scripts"
    headers["Accept"] = "application/vnd.github+json"
    request = Request(url, headers=headers)
    with urlopen(request, timeout=HTTP_TIMEOUT) as response:
        return response.read()


def load_lockfile(src: str) -> dict:
    """Load a Cargo.lock from a path or URL."""
    if src.startswith(("http://", "https://")):
        with urlopen(src, timeout=HTTP_TIMEOUT) as response:
            return tomlkit.loads(response.read().decode())
    with open(src, "r", encoding="utf-8") as f:
        return tomlkit.load(f)


def load_lockfiles() -> tuple[dict, dict]:
    """Load our Cargo.lock and Gecko's Cargo.lock with error handling.

    Returns (our_lock, gecko_lock). Exits on error.
    """
    print("Fetching Gecko lockfile...", file=sys.stderr)
    try:
        gecko_lock = load_lockfile(GECKO_LOCKFILE_URL)
    except Exception as e:
        sys.exit(f"Error fetching Gecko lockfile: {e}")

    try:
        our_lock = load_lockfile("Cargo.lock")
    except FileNotFoundError:
        sys.exit("Error: Cargo.lock not found. Run from the workspace root.")

    return our_lock, gecko_lock


def semver_range(version: str) -> str:
    """Extract major.minor from a version string."""
    parts = version.split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return parts[0]


def group_by_semver_range(versions: list[str]) -> dict[str, list[str]]:
    """Group version strings by their major.minor semver range.

    Returns a dict of "major.minor" -> [version, ...].
    """
    by_range: dict[str, list[str]] = {}
    for ver in versions:
        by_range.setdefault(semver_range(ver), []).append(ver)
    return by_range


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


def get_duplicate_packages(lock: dict) -> dict[str, list[str]]:
    """Find packages that appear multiple times with different versions.

    Returns a dict of package name -> list of versions for packages with duplicates.
    """
    versions: dict[str, list[str]] = {}
    for pkg in lock.get("package", []):
        versions.setdefault(pkg["name"], []).append(pkg["version"])
    return {name: vers for name, vers in versions.items() if len(vers) > 1}


def get_all_versions(lock: dict) -> dict[str, list[tuple[str, str]]]:
    """Parse lockfile into name -> [(version, source), ...].

    Convenience wrapper around parse_packages for simple version listing.
    """
    packages = parse_packages(lock)
    return {
        name: [(ver, info.get("source") or "local") for ver, info in versions.items()]
        for name, versions in packages.items()
    }


def find_dependents(lock: dict, package: str, version: str | None = None) -> list[str]:
    """Find all packages that directly depend on the given package.

    If version is specified, only return dependents that use that specific version.
    Returns list of "name version" strings.
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


def build_dependents_map(lock: dict) -> dict[str, set[str]]:
    """Build a map of package name -> set of dependent package names.

    Unlike find_dependents, this builds the full map once for efficiency
    when checking multiple packages.
    """
    dependents: dict[str, set[str]] = {}
    for pkg in lock.get("package", []):
        for dep in pkg.get("dependencies", []):
            dep_name = dep.split()[0]
            dependents.setdefault(dep_name, set()).add(pkg["name"])
    return dependents


def workspace_crates(lock: dict) -> set[str]:
    """Return the set of workspace crate names (packages with no source)."""
    return {pkg["name"] for pkg in lock.get("package", []) if not pkg.get("source")}


def expand_dependents_closure(
    seeds: set[str], dependents_map: dict[str, set[str]]
) -> set[str]:
    """Expand a seed set by iteratively adding packages whose dependents are all in the set.

    Uses a fixed-point algorithm: if every dependent of a package is already
    in the result set, that package is added too. Repeats until stable.
    """
    result = set(seeds)
    changed = True
    while changed:
        changed = False
        for pkg, deps in dependents_map.items():
            if pkg not in result and deps and deps <= result:
                result.add(pkg)
                changed = True
    return result


def is_registry_package(info: dict) -> bool:
    """Check if a package version is from a registry (not a local patch)."""
    source = info.get("source")
    return source is not None and source.startswith("registry")


def fetch_netwerk_crates() -> set[str]:
    """Fetch the list of Rust crate names under Gecko's netwerk/ directory.

    Uses GitHub's code search API to find Cargo.toml files.
    """
    import json
    import urllib.parse

    crates = set()

    # Search for Cargo.toml files in netwerk/ (fewer than 100 expected).
    query = urllib.parse.quote(
        "filename:Cargo.toml path:netwerk repo:mozilla-firefox/firefox"
    )
    search_url = f"https://api.github.com/search/code?q={query}&per_page=100"

    try:
        data = json.loads(github_api_request(search_url).decode())
        if data.get("incomplete_results"):
            print(
                "Warning: GitHub search returned incomplete results.",
                file=sys.stderr,
            )
    except Exception as e:
        print(f"Warning: Could not search Gecko repo: {e}", file=sys.stderr)
        return crates

    # Fetch each Cargo.toml and extract the crate name.
    for item in data.get("items", []):
        path = item.get("path", "")
        try:
            raw_url = f"{GECKO_RAW_URL}/{path}"
            with urlopen(raw_url, timeout=HTTP_TIMEOUT) as response:
                content = response.read().decode()
                for line in content.split("\n"):
                    if line.strip().startswith("name"):
                        if "=" in line and '"' in line:
                            name = line.split('"')[1]
                            crates.add(name)
                            break
        except Exception as e:
            print(f"Warning: Could not fetch {path}: {e}", file=sys.stderr)

    return crates


def find_neqo_only_deps(gecko_lock: dict, our_lock: dict) -> set[str]:
    """Find packages in Gecko that only neqo (transitively) depends on.

    These packages can be freely updated since Gecko will get new versions
    when neqo is vendored.
    """
    our_crates = workspace_crates(our_lock)

    # Gecko crates that are part of the neqo/networking stack (under netwerk/).
    print("Fetching netwerk crates from Gecko...", file=sys.stderr)
    netwerk_crates = fetch_netwerk_crates()
    gecko_neqo_crates = {
        pkg["name"]
        for pkg in gecko_lock.get("package", [])
        if pkg["name"] in netwerk_crates or pkg["name"].startswith("neqo")
    }

    # Find all packages whose only dependents are neqo crates (transitively).
    seeds = our_crates | gecko_neqo_crates
    gecko_dependents = build_dependents_map(gecko_lock)
    neqo_only = expand_dependents_closure(seeds, gecko_dependents)

    return neqo_only - seeds  # Exclude seed crates.


def find_neqo_or_workspace_deps(
    gecko_lock: dict, our_lock: dict
) -> tuple[set[str], set[str]]:
    """Find neqo-only deps and expand transitively using our lockfile.

    Returns (neqo_only, neqo_or_workspace) where:
    - neqo_only: packages only neqo depends on in Gecko's graph
    - neqo_or_workspace: neqo_only expanded with packages whose dependents
      in our lockfile are all neqo-only or workspace crates
    """
    neqo_only = find_neqo_only_deps(gecko_lock, our_lock)
    neqo_or_workspace = expand_dependents_closure(
        neqo_only | workspace_crates(our_lock),
        build_dependents_map(our_lock),
    )
    return neqo_only, neqo_or_workspace


def collect_dep_categories() -> tuple[set[str], set[str]]:
    """Collect normal and dev/build dependency names from workspace Cargo.toml files.

    Returns (normal_deps, dev_build_roots).
    """
    with open("Cargo.toml", "r", encoding="utf-8") as f:
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

        normal_deps.update(cargo.get("dependencies", {}))
        dev_build_roots.update(cargo.get("dev-dependencies", {}))
        dev_build_roots.update(cargo.get("build-dependencies", {}))

    ws_deps = workspace.get("workspace", {})
    dev_build_roots.update(ws_deps.get("dev-dependencies", {}))
    dev_build_roots.update(ws_deps.get("build-dependencies", {}))

    return normal_deps, dev_build_roots


def find_dev_only_packages() -> set[str]:
    """Find packages that are only dev-dependencies or build-dependencies.

    These don't affect Gecko integration since Gecko doesn't use our dev/build deps.
    """
    normal_deps, dev_build_roots = collect_dep_categories()

    with open("Cargo.lock", "r", encoding="utf-8") as f:
        lock = tomlkit.load(f)

    pkg_deps: dict[str, list[str]] = {}
    for pkg in lock.get("package", []):
        pkg_deps[pkg["name"]] = [d.split()[0] for d in pkg.get("dependencies", [])]

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
