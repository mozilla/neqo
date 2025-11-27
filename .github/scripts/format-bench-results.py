#!/usr/bin/env python3
"""Format Criterion benchmark results as Markdown collapsibles.

Reads benchmark output from stdin or a file and writes:
- all-bench-results.md: All benchmark results as collapsibles
- significant-results.md: Only results with regressions or improvements
"""

import re
import sys


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
            # Reconstruct with middle percentage bolded
            result = line[: start + 1] + parts[0] + "% <b>" + parts[1] + "%</b>"
            for i in range(2, len(parts)):
                if i < len(parts) - 1:
                    result += parts[i] + "%"
                else:
                    result += parts[i]
            return result + line[end - 1 :]
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
        status_text = ":broken_heart: <b>Performance has regressed"
        if time_pct:
            status_text += " by " + time_pct
        status_text += ".</b>"
        significant = True
    elif status == "improved":
        status_text = ":green_heart: <b>Performance has improved"
        if time_pct:
            status_text += " by " + time_pct
        status_text += "</b>"
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
                if re.search(r"change:.*\[.*%.*%.*%\]", line) or re.search(
                    r"time:.*\[.*%.*%.*%\]", line
                ):
                    time_pct = extract_middle_pct(line)

            # Strip up to 17 leading spaces
            processed_line = re.sub(r"^ {1,17}", "", processed_line)

            # Bold the middle percentage in bracketed ranges
            processed_line = bold_middle_pct(processed_line)

            # Detect status
            status = _detect_status(line, status)

            # Append to content
            if content:
                content += "\n"
            content += processed_line

    # Flush the last benchmark
    flush(name, content, status, time_pct, all_results, significant_results)

    return all_results, significant_results


def main() -> None:
    """Parse benchmark results and write Markdown output files."""
    # Read from file argument or stdin
    if len(sys.argv) > 1:
        with open(sys.argv[1], encoding="utf-8") as f:
            all_results, significant_results = process_input(f)
    else:
        all_results, significant_results = process_input(sys.stdin)

    # Write output files
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
