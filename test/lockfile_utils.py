#!/usr/bin/env python3
# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

"""
Shared utilities for Cargo.lock comparison and update scripts.
"""

import json
import os
import subprocess
import sys
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import NamedTuple, NoReturn
from urllib.request import Request, urlopen

import tomlkit
from packaging.version import Version
from semantic_version import SimpleSpec
from semantic_version import Version as SemVer

GECKO_RAW_URL = (
    "https://raw.githubusercontent.com/mozilla-firefox/firefox/refs/heads/main"
)
GECKO_LOCKFILE_URL = f"{GECKO_RAW_URL}/Cargo.lock"
GECKO_API_URL = "https://api.github.com/repos/mozilla-firefox/firefox"

# Gecko vendors neqo from this repository.  The packages it sources from here are
# the roots through which a version we pin can reach a Gecko build.
GECKO_NEQO_SOURCE = "github.com/mozilla/neqo"

# Our lockfile, relative to the workspace root both scripts must be run from.
LOCKFILE = Path("Cargo.lock")

# Timeout in seconds for HTTP requests.
HTTP_TIMEOUT = 30

# Exit code for environment and tooling errors, kept distinct from 1 so callers can
# tell "the check could not run" from "the check found violations".
EXIT_TOOL_ERROR = 2


# A lockfile's packages, as name -> {version -> {"deps": [...], "source": ...}}.
PackageIndex = dict[str, dict[str, dict]]

# A lockfile's versions, as name -> {version, ...}.
VersionIndex = dict[str, set[str]]

# Semver requirements on each package, as name -> [(requiring crate, requirement)].
Requirements = dict[str, list[tuple[str, str]]]


class BlockedPin(NamedTuple):
    """A pin to Gecko's version that a crate's requirement rules out."""

    gecko_ver: str
    requirer: str
    requirement: str


class Divergence(NamedTuple):
    """One of our versions that doesn't line up with Gecko's, and why."""

    our_ver: str
    # What we would move to; None when Gecko carries nothing in this semver line.
    gecko_ver: str | None
    pin_target: str | None = None
    blocked: BlockedPin | None = None


class PinPlan(NamedTuple):
    """What aligning with Gecko would do: versions to pin, and pins ruled out."""

    targets: dict[tuple[str, str], str]
    blocked: dict[tuple[str, str], BlockedPin]


class Rationale(NamedTuple):
    """Why a package sits where it does: a shared group label, plus any specifics."""

    category: str
    note: str
    detail: str = ""


class PinPolicy(NamedTuple):
    """The sets that decide how each package's version is treated.

    Bundled together because deciding "why is this version what it is" needs all of
    them, and both scripts ask that question.
    """

    gecko_versions: VersionIndex
    neqo_only: set[str]
    pinnable: set[str]
    dev_only: set[str]
    # Only Gecko's crates.io releases; its local shims and git forks carry crates.io
    # version numbers but different code, so they are never pin targets.
    gecko_releases: VersionIndex
    requirements: Requirements

    @classmethod
    def build(
        cls, gecko_lock: dict, metadata: dict, neqo_only: set[str]
    ) -> "PinPolicy":
        """Assemble the policy from Gecko's lockfile and our resolved graph."""
        gecko_pkgs = parse_packages(gecko_lock)
        return cls(
            versions_by_name(gecko_lock),
            neqo_only,
            find_pinnable_packages(metadata, gecko_lock),
            find_dev_only_packages(metadata),
            {
                name: {v for v, info in vers.items() if is_registry_package(info)}
                for name, vers in gecko_pkgs.items()
            },
            load_version_requirements(metadata),
        )


def run_cargo(*args: str) -> subprocess.CompletedProcess[str]:
    """Run a cargo subcommand, capturing its output and never raising."""
    return subprocess.run(
        ["cargo", *args], capture_output=True, text=True, check=False
    )


def fatal(message: str) -> NoReturn:
    """Report an environment or tooling error and exit with EXIT_TOOL_ERROR."""
    print(message, file=sys.stderr)
    sys.exit(EXIT_TOOL_ERROR)


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


def load_lockfile(src: str | Path) -> dict:
    """Load a Cargo.lock from a path or URL."""
    if isinstance(src, str) and src.startswith(("http://", "https://")):
        with urlopen(src, timeout=HTTP_TIMEOUT) as response:
            return tomlkit.loads(response.read().decode())
    return tomlkit.loads(Path(src).read_text(encoding="utf-8"))


def packages(lock: dict) -> list[dict]:
    """Return a lockfile's [[package]] entries."""
    return lock.get("package", [])


def current_lock() -> dict:
    """Load the lockfile as it stands in the working tree."""
    return load_lockfile(LOCKFILE)


def current_packages() -> PackageIndex:
    """Parse the working tree's lockfile into name -> {version -> info}."""
    return parse_packages(current_lock())


def current_versions() -> set[tuple[str, str]]:
    """Return the (name, version) pairs currently in the lockfile."""
    return version_pairs(current_lock())


def load_lockfiles() -> tuple[dict, dict]:
    """Load our Cargo.lock and Gecko's Cargo.lock with error handling.

    Returns (our_lock, gecko_lock). Exits on error.
    """
    print("Fetching Gecko lockfile...", file=sys.stderr)
    try:
        gecko_lock = load_lockfile(GECKO_LOCKFILE_URL)
    except Exception as e:
        fatal(f"Error fetching Gecko lockfile: {e}")

    try:
        our_lock = current_lock()
    except FileNotFoundError:
        fatal("Error: Cargo.lock not found. Run from the workspace root.")

    return our_lock, gecko_lock


def semver_range(version: str) -> str:
    """Extract major.minor from a version string."""
    major, _, rest = version.partition(".")
    minor = rest.partition(".")[0]
    return f"{major}.{minor}" if minor else major


def group_by_semver_range(versions: Iterable[str]) -> dict[str, list[str]]:
    """Group version strings by their major.minor semver range.

    Returns a dict of "major.minor" -> [version, ...].
    """
    by_range: dict[str, list[str]] = defaultdict(list)
    for ver in versions:
        by_range[semver_range(ver)].append(ver)
    return by_range


def parse_packages(lock: dict) -> PackageIndex:
    """Parse lockfile into a dict of name -> {version -> {deps, source}}.

    Tracks all versions of each package, not just one.
    """
    parsed: PackageIndex = defaultdict(dict)
    for pkg in packages(lock):
        parsed[pkg["name"]][pkg["version"]] = {
            "deps": [dep.partition(" ")[0] for dep in pkg.get("dependencies", [])],
            "source": pkg.get("source"),
        }
    return parsed


def version_pairs(lock: dict) -> set[tuple[str, str]]:
    """Return the (name, version) pairs a lockfile contains."""
    return {(pkg["name"], pkg["version"]) for pkg in packages(lock)}


def group_versions(pairs: Iterable[tuple[str, str]]) -> VersionIndex:
    """Group (name, version) pairs into name -> {version, ...}."""
    by_name: VersionIndex = defaultdict(set)
    for name, ver in pairs:
        by_name[name].add(ver)
    return by_name


def versions_by_name(lock: dict) -> VersionIndex:
    """Map each package name in a lockfile to the versions it appears at."""
    return group_versions(version_pairs(lock))


def get_duplicate_packages(lock: dict) -> VersionIndex:
    """Find packages that appear multiple times with different versions.

    Returns a dict of package name -> versions, for packages with duplicates.
    """
    return {
        name: vers for name, vers in versions_by_name(lock).items() if len(vers) > 1
    }


def find_dependents(
    lock: dict, package: str, version: str | None = None
) -> list[tuple[str, str]]:
    """Find all packages that directly depend on the given package.

    If version is specified, only return dependents that use that specific version.
    Returns a list of (name, version) pairs.
    """
    dependents = []
    for pkg in packages(lock):
        for dep in pkg.get("dependencies", []):
            dep_name, _, dep_ver = dep.partition(" ")
            if dep_name == package and version in (None, dep_ver or None):
                dependents.append((pkg["name"], pkg["version"]))
    return dependents


def build_dependents_map(lock: dict) -> dict[str, set[str]]:
    """Build a map of package name -> set of dependent package names.

    Unlike find_dependents, this builds the full map once for efficiency
    when checking multiple packages.
    """
    dependents: dict[str, set[str]] = defaultdict(set)
    for pkg in packages(lock):
        for dep in pkg.get("dependencies", []):
            dependents[dep.partition(" ")[0]].add(pkg["name"])
    return dependents


def workspace_crates(lock: dict) -> set[str]:
    """Return the set of workspace crate names (packages with no source)."""
    return {pkg["name"] for pkg in packages(lock) if not pkg.get("source")}


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

    Reads the netwerk/ subtree via GitHub's git tree API, which needs no
    authentication.  Failures are fatal: this set decides which packages count as
    neqo-only, and silently returning a short list would quietly change every
    verdict that follows.
    """
    tree_url = f"{GECKO_API_URL}/git/trees/main:netwerk?recursive=1"
    try:
        tree = json.loads(github_api_request(tree_url).decode())
    except Exception as e:
        fatal(f"Error: could not list Gecko's netwerk/ directory: {e}")

    if "tree" not in tree:
        fatal(f"Error: unexpected response listing netwerk/: {tree.get('message')}")
    if tree.get("truncated"):
        fatal("Error: GitHub truncated the netwerk/ listing; cannot enumerate crates.")

    manifests = [
        entry["path"] for entry in tree["tree"] if entry["path"].endswith("Cargo.toml")
    ]
    if not manifests:
        fatal("Error: no Cargo.toml files found under Gecko's netwerk/.")

    crates: set[str] = set()
    for path in manifests:
        raw_url = f"{GECKO_RAW_URL}/netwerk/{path}"
        try:
            with urlopen(raw_url, timeout=HTTP_TIMEOUT) as response:
                cargo = tomlkit.loads(response.read().decode())
        except Exception as e:
            fatal(f"Error: could not fetch netwerk/{path}: {e}")
        name = cargo.get("package", {}).get("name")
        if name:
            crates.add(str(name))

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
        for pkg in packages(gecko_lock)
        if pkg["name"] in netwerk_crates or pkg["name"].startswith("neqo")
    }

    # Find all packages whose only dependents are neqo crates (transitively).
    seeds = our_crates | gecko_neqo_crates
    gecko_dependents = build_dependents_map(gecko_lock)
    neqo_only = expand_dependents_closure(seeds, gecko_dependents)

    return neqo_only - seeds  # Exclude seed crates.


def classify_version_relation(our_ver: str, gecko_vers_in_range: list[str]) -> str:
    """Classify our version relative to Gecko's for the same semver range.

    Returns one of: "no-range", "match", "behind", "ahead".
    999-patched versions on either side are treated as "match".
    """
    if not gecko_vers_in_range:
        return "no-range"
    gecko_ver = max(gecko_vers_in_range, key=Version)
    if our_ver.endswith(".999") or gecko_ver.endswith(".999"):
        return "match"
    our_v = Version(our_ver)
    gecko_v = Version(gecko_ver)
    if our_v == gecko_v:
        return "match"
    return "behind" if our_v < gecko_v else "ahead"


def load_cargo_metadata() -> dict:
    """Run `cargo metadata` and return the parsed resolve graph.

    `--locked` keeps this read-only: cargo errors out rather than rewriting
    Cargo.lock.  Callers re-run it after changing the lockfile, since the resolved
    graph and its requirements move with it.
    """
    result = run_cargo(
        "metadata", "--format-version", "1", "--all-features", "--locked"
    )
    if result.returncode != 0:
        fatal(f"Error running cargo metadata: {result.stderr.strip()}")

    return json.loads(result.stdout)


def load_version_requirements(metadata: dict) -> Requirements:
    """Collect the semver requirements the dependency graph places on each package.

    Only requirements cargo actually resolves against are collected: registry deps
    that are normal or build dependencies, plus dev-dependencies of our own
    workspace crates (cargo ignores dev-dependencies of third-party crates).

    Returns {package name: [(requiring crate, requirement), ...]}.
    """
    members = set(metadata.get("workspace_members", []))

    # Edges cargo actually resolved, as {requiring package id: {dep package name}}.
    # Declared dependencies include optional ones no enabled feature turns on, and
    # their requirements constrain nothing.
    by_id = {pkg["id"]: pkg["name"] for pkg in metadata["packages"]}
    resolved = {
        node["id"]: {
            by_id[dep["pkg"]] for dep in node.get("deps", []) if dep["pkg"] in by_id
        }
        for node in metadata.get("resolve", {}).get("nodes", [])
    }

    requirements: Requirements = defaultdict(list)
    for pkg in metadata["packages"]:
        for dep in pkg["dependencies"]:
            if not (dep.get("source") or "").startswith("registry"):
                continue  # Path or git dep: a different crate that shares the name.
            if dep.get("kind") == "dev" and pkg["id"] not in members:
                continue
            if dep["name"] not in resolved.get(pkg["id"], ()):
                continue
            requirements[dep["name"]].append((pkg["name"], dep["req"]))

    return requirements


def _requirement_matches(req: str, version: str) -> bool:
    """Check a Cargo semver requirement against a concrete version.

    Build metadata is stripped, as Cargo ignores it when comparing.  Requirements
    we can't parse are treated as satisfied, so they never block a pin.
    """
    comparators = ",".join(part.strip().split("+")[0] for part in req.split(","))
    try:
        return SemVer(version.split("+")[0]) in SimpleSpec(comparators)
    except ValueError:
        return True


def find_blocking_requirements(
    name: str,
    our_ver: str,
    targets: Iterable[str],
    requirements: Requirements,
) -> list[tuple[str, str]]:
    """Find requirements that `our_ver` satisfies but no version in `targets` does.

    Only requirements `our_ver` currently satisfies are considered: those are the
    dependents cargo resolved onto this lockfile entry, and so the ones any move has
    to keep satisfying.  Requirements matching some other entry of the same package
    constrain that entry, not this one.

    Pass a single target to ask "can we make this one move?", or all of Gecko's
    releases to ask "is any of them reachable at all?".
    """
    candidates = list(targets)
    return [
        (requirer, req)
        for requirer, req in sorted(set(requirements.get(name, [])))
        if _requirement_matches(req, our_ver)
        and not any(_requirement_matches(req, target) for target in candidates)
    ]


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
    gecko_pkgs: PackageIndex,
    our_pkgs: PackageIndex,
) -> dict[tuple[str, str], str]:
    """Compute version moves to align a package's versions with Gecko's.

    Emits moves for versions that differ from Gecko's, in both directions.
    Returns {(name, our_ver): gecko_ver} for versions that need moving.
    """
    updates: dict[tuple[str, str], str] = {}
    our_versions = our_pkgs[name]

    if all(not is_registry_package(info) for info in our_versions.values()):
        return updates

    # Only pin against Gecko versions that come from a registry.  Gecko's local
    # shim crates (versioned x.y.999) and its git forks carry crates.io version
    # numbers but different code, so matching their version buys us nothing.
    gecko_real = [
        v for v, info in gecko_pkgs[name].items() if is_registry_package(info)
    ]
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
            if classify_version_relation(our_ver, gecko_vers) in ("behind", "ahead"):
                updates[(name, our_ver)] = gecko_ver

    return updates


def collect_pin_targets(
    common: set[str],
    neqo_only: set[str],
    gecko_pkgs: PackageIndex,
    our_pkgs: PackageIndex,
    requirements: Requirements,
) -> PinPlan:
    """Collect the version moves that pin shared packages to Gecko's versions.

    This is the single definition of "which of our package versions must move, and
    to what": update-lockfile applies these moves, compare-lockfile reports any that
    are still outstanding as hard violations.

    Skips neqo-only packages, which Gecko picks up when neqo is vendored and which
    are therefore free to run ahead.  Dev- and build-dependencies are pinned like
    any other shared dep, since Gecko never adopts our versions of them.

    Returns the plan for registry crates that need moving.
    """
    pins: dict[tuple[str, str], str] = {}
    blocked: dict[tuple[str, str], BlockedPin] = {}

    for name in common:
        if name in neqo_only:
            continue
        for key, gecko_ver in align_package_with_gecko(
            name, gecko_pkgs, our_pkgs
        ).items():
            _, our_ver = key
            blockers = find_blocking_requirements(
                name, our_ver, [gecko_ver], requirements
            )
            if blockers:
                blocked[key] = BlockedPin(gecko_ver, *blockers[0])
            else:
                pins[key] = gecko_ver

    return PinPlan(pins, blocked)


def find_non_gecko_duplicates(
    our_lock: dict, gecko_versions: VersionIndex
) -> dict[str, list[str]]:
    """Find package versions that are duplicates not sanctioned by Gecko (invariant A).

    Only considers registry packages — path and git dependencies with the same
    name are different crates and are excluded.  A duplicate is Gecko-sanctioned
    only when Gecko carries the same set of semver ranges for that package.
    Versions in extra ranges are "off-versions" that should be eliminated.

    Returns a dict of name -> [off_ver, ...] for packages with unsanctioned duplicates.
    """
    our_pkgs = parse_packages(our_lock)
    result: dict[str, list[str]] = {}

    for name, versions in our_pkgs.items():
        # Only registry packages participate in version dedup.
        registry_vers = [v for v, info in versions.items() if is_registry_package(info)]
        if len(registry_vers) <= 1:
            continue

        our_by_range = group_by_semver_range(registry_vers)

        if name in gecko_versions:
            gecko_ranges = set(group_by_semver_range(gecko_versions[name]))
            off_versions = [
                v for v in registry_vers if semver_range(v) not in gecko_ranges
            ]
        else:
            # Package not in Gecko: keep the range with the newest max version.
            keep_range = max(
                our_by_range,
                key=lambda r: max(Version(v) for v in our_by_range[r]),
            )
            off_versions = [v for v in registry_vers if semver_range(v) != keep_range]

        if off_versions:
            result[name] = off_versions

    return result


def reachable_packages(
    metadata: dict, roots: Iterable[str], kinds: set[str | None]
) -> set[str]:
    """Walk the resolved graph from `roots`, following only the given edge kinds.

    A dependency's kind is null for a normal dependency, "dev" or "build" otherwise.
    Returns the names of every package reached, roots included.
    """
    nodes = {node["id"]: node for node in metadata.get("resolve", {}).get("nodes", [])}
    names = {pkg["id"]: pkg["name"] for pkg in metadata["packages"]}

    reached: set[str] = set()
    to_visit = list(roots)
    while to_visit:
        pkg_id = to_visit.pop()
        if pkg_id in reached:
            continue
        reached.add(pkg_id)
        for dep in nodes.get(pkg_id, {}).get("deps", []):
            if any(k.get("kind") in kinds for k in dep.get("dep_kinds", [])):
                to_visit.append(dep["pkg"])

    return {names[pkg_id] for pkg_id in reached if pkg_id in names}


def find_dev_only_packages(metadata: dict) -> set[str]:
    """Find packages reachable only through dev- or build-dependency edges.

    Whatever a normal-edge walk from the workspace crates never reaches is
    dev/build-only.  Using the resolve graph rather than the Cargo.toml tables picks
    up `[target."cfg(...)".dependencies]` and renamed deps
    (`nss = { package = "nss-rs" }`) for free.
    """
    normal = reachable_packages(metadata, metadata.get("workspace_members", []), {None})
    return {pkg["name"] for pkg in metadata["packages"]} - normal


def find_vendored_crates(gecko_lock: dict) -> set[str]:
    """Return the names of our crates that Gecko vendors from our repository."""
    return {
        pkg["name"]
        for pkg in packages(gecko_lock)
        if GECKO_NEQO_SOURCE in (pkg.get("source") or "")
    }


def find_pinnable_packages(metadata: dict, gecko_lock: dict) -> set[str]:
    """Find packages whose version can reach a Gecko build of neqo.

    Walks our resolved graph from the crates Gecko vendors, following normal and
    build edges: Gecko builds a vendored crate's dependencies and runs its build
    scripts, but ignores its dev-dependencies.  Anything outside this set Gecko
    resolves from its own tree no matter what we hold, so pinning it to Gecko's
    version buys nothing — `cc`, reached only via our fuzz and bench harnesses,
    is the motivating case.
    """
    vendored = find_vendored_crates(gecko_lock)
    ids = [
        pkg["id"] for pkg in metadata["packages"] if pkg["name"] in vendored
    ]
    return reachable_packages(metadata, ids, {None, "build"})


# ---------------------------------------------------------------------------
# Explaining version choices
# ---------------------------------------------------------------------------

def explain_version(
    name: str,
    our_ver: str,
    policy: PinPolicy,
    our_lock: dict,
    *,
    pin_target: str | None = None,
    blocked: BlockedPin | None = None,
) -> Rationale:
    """Say why `name` sits at `our_ver`, as a group label plus any specifics.

    `pin_target` marks a version that should have been pinned but hasn't been;
    `blocked` marks one a requirement stops us pinning.  Everything else is derived
    from the policy sets, so the wording can't drift from the actual decision.
    """
    gecko_vers = policy.gecko_versions.get(name, set())

    if not our_ver:
        return Rationale(
            "Dropped", "nothing in our graph depends on them any more"
        )

    if pin_target:
        return Rationale(
            "Not pinned to Gecko yet",
            "these reach a Gecko build, so they have to match — run `update-lockfile`"
            if name in policy.pinnable
            else "we track Gecko even where it cannot affect Firefox — run "
            "`update-lockfile`",
            f"should be {pin_target}",
        )

    if blocked:
        return Rationale(
            "Cannot match Gecko",
            "another crate's requirement rules Gecko's version out; Gecko still "
            "builds neqo with its own copy",
            f"`{blocked.requirer}` needs `{blocked.requirement}`",
        )

    if not gecko_vers:
        return Rationale(
            "Not in Gecko at all",
            "no Gecko crate depends on them, so the version is ours to choose",
        )

    # Matching comes first: we now aim for Gecko's version everywhere, so landing on
    # it is the answer regardless of whether Gecko could have reached it through us.
    if our_ver in gecko_vers:
        return Rationale(
            "Pinned to Gecko",
            "identical to Gecko, so vendoring neqo changes nothing",
        )

    if not policy.gecko_releases.get(name):
        return Rationale(
            "Gecko's copy isn't the crates.io crate",
            "it is a local shim or a git fork, so matching the version number would "
            "not match the code behind it",
        )

    if name in policy.neqo_only:
        return Rationale(
            "Only neqo uses them in Gecko",
            "Gecko picks up whatever we hold at the next vendor",
        )

    if name not in policy.pinnable:
        pullers = sorted({dep for dep, _ver in find_dependents(our_lock, name)})
        return Rationale(
            "Gecko resolves these itself",
            "we reach them only from tooling Gecko doesn't vendor, so our version "
            "cannot change what it builds neqo with",
            "via " + ", ".join(f"`{p}`" for p in pullers) if pullers else "",
        )

    # No pin was attempted because Gecko's versions sit on another semver line.  A
    # requirement usually explains why we are on ours; name it rather than shrug.
    releases = policy.gecko_releases.get(name, set())
    blockers = find_blocking_requirements(
        name, our_ver, releases, policy.requirements
    )
    if blockers:
        return Rationale(
            "Cannot match Gecko",
            "another crate's requirement rules Gecko's version out; Gecko still "
            "builds neqo with its own copy",
            ", ".join(f"`{who}` needs `{req}`" for who, req in blockers),
        )

    return Rationale(
        "No compatible Gecko version",
        "Gecko's is on a different semver line and nothing in our graph pins us to "
        "ours, so moving would be an API change, not an alignment",
    )


def find_divergences(
    name: str,
    our_vers: Iterable[str],
    gecko_vers: Iterable[str],
    plan: PinPlan,
) -> list[Divergence]:
    """Find our versions of `name` that don't line up with Gecko's.

    The single definition of "diverging": a version update-lockfile pins, one a
    requirement stops it pinning, or one whose semver line disagrees with Gecko's.
    Callers render this differently but must agree on the set.
    """
    by_range = group_by_semver_range(gecko_vers)
    found = []
    for our_ver in sorted(our_vers):
        key = (name, our_ver)
        if (pinned := plan.targets.get(key)) is not None:
            found.append(Divergence(our_ver, pinned, pin_target=pinned))
        elif (pin := plan.blocked.get(key)) is not None:
            found.append(Divergence(our_ver, pin.gecko_ver, blocked=pin))
        else:
            in_range = by_range.get(semver_range(our_ver), [])
            relation = classify_version_relation(our_ver, in_range)
            if relation == "no-range":
                found.append(Divergence(our_ver, None))
            elif relation != "match":
                found.append(Divergence(our_ver, max(in_range, key=Version)))
    return found


def change_rationales(
    before: set[tuple[str, str]],
    after: set[tuple[str, str]],
    policy: PinPolicy,
    our_lock: dict,
    plan: PinPlan,
) -> list[tuple[str, str, Rationale]]:
    """Explain every version that moved between two lockfile states.

    Diffing the whole run rather than tracking each action means transitive moves,
    additions and removals are explained alongside the ones we asked for.
    """
    old, new = group_versions(before), group_versions(after)
    entries = []
    for name in sorted(set(old) | set(new)):
        if old.get(name) == new.get(name):
            continue
        was = ", ".join(sorted(old.get(name, set()))) or "absent"
        now = ", ".join(sorted(new.get(name, set())))
        why = explain_version(
            name,
            # Explain against the surviving version; a removed package has none.
            max(new.get(name, set()), key=Version, default=""),
            policy,
            our_lock,
            blocked=next(
                (p for (n, _v), p in plan.blocked.items() if n == name), None
            ),
        )
        entries.append((name, f"{was} → {now}" if now else "", why))
    return entries


def divergence_rationales(
    our_pkgs: PackageIndex,
    policy: PinPolicy,
    our_lock: dict,
    plan: PinPlan,
) -> list[tuple[str, str, Rationale]]:
    """Explain every version of ours that doesn't line up with Gecko's.

    Both scripts render this, so the decision of what counts as diverging lives
    here rather than in either of them.
    """
    entries = []
    for name in sorted(set(our_pkgs) & set(policy.gecko_versions)):
        gecko_vers = policy.gecko_versions[name]
        gecko_str = ", ".join(sorted(gecko_vers))
        for div in find_divergences(name, our_pkgs[name], gecko_vers, plan):
            why = explain_version(
                name,
                div.our_ver,
                policy,
                our_lock,
                pin_target=div.pin_target,
                blocked=div.blocked,
            )
            entries.append((name, f"{div.our_ver} vs. {gecko_str}", why))
    return entries


def format_rationales(heading: str, entries: list[tuple[str, str, Rationale]]) -> str:
    """Render (package, change, rationale) triples as markdown, grouped by reason.

    Most runs move a dozen packages for the same handful of reasons, so the reason
    is stated once per group rather than once per package.
    """
    if not entries:
        return ""

    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for name, change, why in entries:
        suffix = f" ({why.detail})" if why.detail else ""
        label = f"`{name}` {change}".strip()
        groups[(why.category, why.note)].append(f"{label}{suffix}")

    lines = [f"\n## {heading}\n"]
    for (category, note), items in groups.items():
        lines.append(f"- **{category}** — {note}:")
        lines.extend(f"  - {item}" for item in items)
    return "\n".join(lines)
