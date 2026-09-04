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

# The machine's run-to-run IPC spread is around 0.5%, so flag several times that.
SIGNIFICANT_IPC_PCT = 2.0

# Only numeric values, so `<not counted>` and prose lines simply do not match.
COUNTER_RE = re.compile(
    r"^\s*(?P<value>[\d,]+(?:\.\d+)?)\s+(?:msec\s+)?(?P<event>[\w:/=.-]+)"
)
# Prefer criterion's own variant name over the sanitized file name.
EXACT_RE = re.compile(r"counter stats for '.*--exact (?P<name>[^']+)'")


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
) -> None:
    """Output a benchmark result as a collapsible."""
    if not name:
        return

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


def process_input(input_file) -> tuple[list[str], list[str]]:
    """Process benchmark input and return (all_results, significant_results)."""
    all_results: list[str] = []
    significant_results: list[str] = []

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
            flush(name, content, status, time_pct, all_results, significant_results)
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

    flush(name, content, status, time_pct, all_results, significant_results)
    return all_results, significant_results


def parse_stat(path: Path) -> tuple[str, dict[str, float]]:
    """Return the benchmark name and counters from one `perf stat` output file."""
    name = path.stem
    counters: dict[str, float] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if match := EXACT_RE.search(line):
            name = match.group("name")
        elif match := COUNTER_RE.match(line):
            counters[match.group("event")] = float(
                match.group("value").replace(",", "")
            )
    return name, counters


def ipc(counters: dict[str, float]) -> float | None:
    """Instructions per cycle, both in user mode so the ratio is consistent."""
    instructions = counters.get("instructions:u")
    cycles = counters.get("cycles:u")
    if not instructions or not cycles:
        return None
    return instructions / cycles


def disturbance(*sides: dict[str, float]) -> str:
    """Describe counters that should be zero, worst of the sides given."""
    notes = []
    for event, label in (
        ("context-switches", "context switches"),
        ("cpu-migrations", "CPU migrations"),
        ("major-faults", "major faults"),
    ):
        worst = max(side.get(event, 0) for side in sides)
        if worst > 0:
            notes.append(f"{int(worst)} {label}")
    return f":warning: {', '.join(notes)}" if notes else ""


class StatRow(NamedTuple):
    """One benchmark's IPC before and after, as a percentage change."""

    name: str
    before: float
    after: float
    delta: float
    note: str

    @property
    def significant(self) -> bool:
        return abs(self.delta) >= SIGNIFICANT_IPC_PCT

    def markdown(self) -> str:
        bold = "**" if self.significant else ""
        return (
            f"| {self.name} | {self.before:.2f} | {self.after:.2f} "
            f"| {bold}{self.delta:+.1f}%{bold} | {self.note} |"
        )


def stat_rows(stats_dir: Path) -> list[StatRow]:
    """Compare each benchmark's `perf stat` output, largest change first."""
    rows = []
    for after_file in sorted((stats_dir / "neqo").glob("*.txt")):
        before_file = stats_dir / "neqo-baseline" / after_file.name
        if not before_file.is_file():
            continue
        name, after_counters = parse_stat(after_file)
        _, before_counters = parse_stat(before_file)
        before, after = ipc(before_counters), ipc(after_counters)
        if before is None or after is None:
            continue
        rows.append(
            StatRow(
                name,
                before,
                after,
                100 * (after - before) / before,
                disturbance(before_counters, after_counters),
            )
        )
    return sorted(rows, key=lambda row: -abs(row.delta))


def write_stat_markdown(stats_dir: Path) -> None:
    """Write perf-stat.md, highlighting the benchmarks that moved."""
    rows = stat_rows(stats_dir)
    if not rows:
        if any(stats_dir.rglob("*.txt")):
            print(f"::warning::no IPC rows parsed from {stats_dir}", file=sys.stderr)
        return

    def table(rows: list[StatRow]) -> list[str]:
        return [
            "| Benchmark | IPC before | IPC after | ΔIPC | |",
            "|:---|---:|---:|---:|:---|",
            *(row.markdown() for row in rows),
        ]

    significant = [row for row in rows if row.significant]
    lines = [
        "### Instructions per cycle",
        "",
        (
            "Lower means more stalling for the same work. Counter totals are not "
            "comparable between runs, because criterion chooses its own iteration "
            "count, so only this ratio is."
        ),
        "",
        *(
            table(significant)
            if significant
            else ["No significant differences in instructions per cycle."]
        ),
        "",
        "<details><summary>All results</summary>",
        "",
        *table(rows),
        "",
        "</details>",
    ]
    Path("perf-stat.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    """Parse benchmark results and write Markdown output files."""
    # Read from file argument or stdin
    if len(sys.argv) > 1:
        with open(sys.argv[1], encoding="utf-8") as f:
            all_results, significant_results = process_input(f)
    else:
        all_results, significant_results = process_input(sys.stdin)

    if len(sys.argv) > 2:
        write_stat_markdown(Path(sys.argv[2]))

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
