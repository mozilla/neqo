#!/usr/bin/env python3
"""Format Criterion benchmark results as Markdown collapsibles.

Reads benchmark output from stdin or a file and writes:
- all-bench-results.md: All benchmark results as collapsibles
- significant-results.md: Only results with regressions or improvements

Given a `perf stat` output directory as a second argument, also writes:
- perf-stat.md: Instructions per cycle per benchmark, for both sides
"""

import re
import sys
from pathlib import Path
from typing import NamedTuple

# Unseparated numbers only, so a locale-formatted value cannot parse to the wrong one.
COUNTER_RE = re.compile(
    r"^\s*(?P<value>\d+(?:\.\d+)?)\s+(?:msec\s+)?(?P<event>[\w:/=.-]+)"
)
# Prefer criterion's own variant name over the sanitized file name.
EXACT_RE = re.compile(r"counter stats for '.*--exact (?P<name>[^']+)'")
# perf appends an enable fraction when it time-shares counters, making them estimates.
MULTIPLEX_RE = re.compile(r"\((\d+\.\d+)%\)\s*$")


def extract_middle_pct(line: str) -> str:
    """Extract the middle percentage from a bracketed range like '[x% y% z%]'."""
    match = re.search(r"\[[^\]]*%[^\]]*%[^\]]*%\]", line)
    if match:
        bracket = match.group()[1:-1]  # Remove brackets
        parts = bracket.split("%")
        if len(parts) >= 2:
            return parts[1].strip() + "%"
    return ""


def bold_middle_pct(line: str) -> str:
    """Bold the middle percentage in lines like 'time: [x% y% z%]'."""
    match = re.search(r"\[[^\]]*%[^\]]*%[^\]]*%\]", line)
    if match:
        start, end = match.start(), match.end()
        bracket = line[start + 1 : end - 1]  # Content inside brackets
        parts = bracket.split("%")
        if len(parts) >= 3:
            new_bracket = f"{parts[0]}%<b>{parts[1]}</b>%{parts[2]}"
            return line[: start + 1] + new_bracket + line[end - 1 :]
    return line


def flush(
    name: str,
    content: str,
    status: str,
    time_pct: str,
    all_results: list[str],
    significant_results: list[str],
) -> bool:
    """Output a benchmark result as a collapsible, returning whether it changed."""
    if not name:
        return False

    # Determine status text and whether this is significant
    significant = False
    if status == "regressed":
        status_text = f":broken_heart: <b>Performance has regressed{f' by {time_pct}' if time_pct else ''}.</b>"
        significant = True
    elif status == "improved":
        status_text = f":green_heart: <b>Performance has improved{f' by {time_pct}' if time_pct else ''}.</b>"
        significant = True
    elif status == "no_change":
        status_text = "No change in performance detected."
    elif status == "noise":
        status_text = "Change within noise threshold."
    else:
        status_text = ""

    # Build the collapsible
    summary = name
    if status_text:
        summary += ": " + status_text
    collapsible = (
        f"<details><summary>{summary}</summary><pre>\n{content}</pre></details>"
    )

    all_results.append(collapsible)
    if significant:
        significant_results.append(collapsible)
    return significant


def _should_skip_line(line: str) -> bool:
    """Return True if the line should be skipped."""
    if re.match(r"^cset:.*last message", line):
        return True
    if line.startswith("Criterion.rs ERROR:"):
        return True
    if not line.strip():
        return True
    return False


def _detect_status(line: str, current_status: str) -> str:
    """Detect benchmark status from line content."""
    if "Performance has regressed." in line:
        return "regressed"
    if "Performance has improved." in line:
        return "improved"
    if "No change in performance detected." in line and not current_status:
        return "no_change"
    if "Change within noise threshold." in line and not current_status:
        return "noise"
    return current_status


def process_input(input_file) -> tuple[list[str], list[str], set[str]]:
    """Return (all_results, significant_results, names criterion says changed)."""
    all_results: list[str] = []
    significant_results: list[str] = []
    changed: set[str] = set()

    name = ""
    content = ""
    status = ""
    time_pct = ""
    in_change = False

    for line in input_file:
        line = line.rstrip("\n\r")

        if _should_skip_line(line):
            continue

        # New benchmark: starts at column 0, has content, not "Found"
        if line and not line[0].isspace() and not re.match(r"^Found.*outlier", line):
            if flush(name, content, status, time_pct, all_results, significant_results):
                changed.add(name)
            name = line
            content = ""
            status = ""
            time_pct = ""
            in_change = False
            continue

        # Content lines for current benchmark
        if name:
            processed_line = line

            # Track when we enter the "change:" section
            if re.match(r"^\s*change:", line):
                in_change = True

            # Capture time percentage from change section
            if in_change and not time_pct:
                if re.search(r"(?:change:|time:).*?\[.*?%.*?%.*?%\]", line):
                    time_pct = extract_middle_pct(line)

            # Strip up to 17 leading spaces
            processed_line = re.sub(r"^ {1,17}", "", processed_line)

            processed_line = bold_middle_pct(processed_line)
            status = _detect_status(line, status)
            if content:
                content += "\n"
            content += processed_line

    if flush(name, content, status, time_pct, all_results, significant_results):
        changed.add(name)
    return all_results, significant_results, changed


class Stat(NamedTuple):
    """One `perf stat` run."""

    name: str
    counters: dict[str, float]
    multiplexed: bool

    @property
    def ipc(self) -> float | None:
        """Instructions per cycle, both in user mode so the ratio is consistent."""
        instructions = self.counters.get("instructions:u")
        cycles = self.counters.get("cycles:u")
        return instructions / cycles if instructions and cycles else None


def parse_stat(path: Path) -> Stat:
    """Read one `perf stat` output file."""
    name = path.stem
    counters: dict[str, float] = {}
    multiplexed = False
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if match := EXACT_RE.search(line):
            name = match.group("name")
        elif match := COUNTER_RE.match(line):
            counters[match.group("event")] = float(match.group("value"))
            if scaled := MULTIPLEX_RE.search(line):
                multiplexed |= float(scaled.group(1)) < 100
    return Stat(name, counters, multiplexed)


def disturbance(*sides: Stat) -> str:
    """Describe counters that indicate a disturbed run, worst of the sides given."""
    notes = []
    # Not migrations: those benchmarks are threaded, and the cpuset has two CPUs.
    if worst := max(side.counters.get("major-faults", 0.0) for side in sides):
        notes.append(f"{worst:.0f} major fault{'s' if worst > 1 else ''}")
    if any(side.multiplexed for side in sides):
        notes.append("counters multiplexed, so these are estimates")
    return f":warning: {', '.join(notes)}" if notes else ""


class StatRow(NamedTuple):
    """One benchmark's IPC before and after, as a percentage change."""

    name: str
    before: float
    after: float
    delta: float
    note: str

    def markdown(self) -> str:
        return (
            f"| {self.name} | {self.before:.2f} | {self.after:.2f} "
            f"| {self.delta:+.1f}% | {self.note} |"
        )


def stat_rows(stats_dir: Path) -> list[StatRow]:
    """Compare each benchmark's `perf stat` output, largest change first."""
    rows = []
    for after_file in sorted((stats_dir / "neqo").glob("*.txt")):
        before_file = stats_dir / "neqo-baseline" / after_file.name
        if not before_file.is_file():
            print(f"::notice::no baseline `perf stat` output for {after_file.name}")
            continue
        after_stat, before_stat = parse_stat(after_file), parse_stat(before_file)
        before, after = before_stat.ipc, after_stat.ipc
        if before is None or after is None:
            print(f"::warning::no IPC counters in {after_file.name}")
            continue
        rows.append(
            StatRow(
                after_stat.name,
                before,
                after,
                100 * (after - before) / before,
                disturbance(before_stat, after_stat),
            )
        )
    return sorted(rows, key=lambda row: -abs(row.delta))


def write_stat_markdown(stats_dir: Path, changed: set[str]) -> None:
    """Write perf-stat.md, leading with the benchmarks criterion says moved."""
    # The runner keeps its workspace, so drop an earlier run's table.
    out = Path("perf-stat.md")
    out.unlink(missing_ok=True)
    rows = stat_rows(stats_dir)
    if not rows:
        # `rglob` on a missing directory is empty, not an error, so check separately.
        if not stats_dir.is_dir():
            print(f"::warning::{stats_dir} is not a directory")
        elif not any(stats_dir.rglob("*.txt")):
            print(f"::warning::no `perf stat` output under {stats_dir}")
        else:
            print(f"::warning::no IPC rows parsed from {stats_dir}")
        return

    def table(rows: list[StatRow]) -> list[str]:
        return [
            "| Benchmark | IPC before | IPC after | ΔIPC | Notes |",
            "|:---|---:|---:|---:|:---|",
            *(row.markdown() for row in rows),
        ]

    moved = [row for row in rows if row.name in changed]
    if changed and not moved:
        print("::warning::no IPC rows match the benchmarks criterion reported on")
    lines = [
        "### Instructions per cycle",
        "",
        *(
            table(moved)
            if moved
            else ["No instructions per cycle for benchmarks whose timing changed."]
        ),
        "",
        "<details><summary>All benchmarks</summary>",
        "",
        *table(rows),
        "",
        "</details>",
    ]
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    """Parse benchmark results and write Markdown output files."""
    # Read from file argument or stdin
    if len(sys.argv) > 1:
        with open(sys.argv[1], encoding="utf-8") as f:
            all_results, significant_results, changed = process_input(f)
    else:
        all_results, significant_results, changed = process_input(sys.stdin)

    if len(sys.argv) > 2:
        # Never let the secondary output take the benchmark comment down with it.
        try:
            write_stat_markdown(Path(sys.argv[2]), changed)
        except Exception as e:  # noqa: BLE001
            print(f"::warning::could not summarize perf stat output: {e}")

    with open("all-bench-results.md", "w", encoding="utf-8") as f:
        f.write("\n".join(all_results))
        if all_results:
            f.write("\n")

    if significant_results:
        with open("significant-results.md", "w", encoding="utf-8") as f:
            f.write("\n".join(significant_results))
            f.write("\n")


if __name__ == "__main__":
    main()
