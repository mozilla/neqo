#!/usr/bin/env python3
"""Compare the baseline and PR builds of a benchmark over several criterion processes.

Each argument is a directory holding `<side>/<run>/{benchmark,estimates}.json`, one run
per process, for the sides `neqo-baseline` and `neqo`. Prints each comparison in
criterion's own text format, which format-bench-results.py and the regression gate parse.
"""

import json
import sys
from pathlib import Path
from statistics import median

from scipy.stats import mannwhitneyu

SIGNIFICANCE = 0.05
# Criterion's default, and the `noise_threshold` that the walltime benchmark groups set.
NOISE_THRESHOLD = 0.01
GROUP_NOISE_THRESHOLDS = {
    "streams": 0.03,
    "streams-flow-controlled": 0.03,
    "transfer": 0.03,
}


def short(n: float, sign: str = "") -> str:
    """Format a number like criterion's `format::short` or `signed_short`."""
    for limit, digits in ((10, 4), (100, 3), (1000, 2), (10000, 1)):
        if abs(n) < limit:
            return f"{n:{sign}.{digits}f}"
    return f"{n:{sign}.0f}"


def time(ns: float) -> str:
    """Format nanoseconds like criterion's `format::time`."""
    for scale, unit in ((1e9, "s"), (1e6, "ms"), (1e3, "µs"), (1, "ns")):
        if ns >= scale:
            return f"{short(ns / scale):>6} {unit}"
    return f"{short(ns * 1e3):>6} ps"


def change(ratio: float) -> str:
    """Format a relative change like criterion's `format::change`."""
    return f"{short(ratio * 1e2, '+'):>6}%"


def bracket(values: list[float], fmt) -> str:
    """Format the minimum, median and maximum of `values`."""
    return f"[{fmt(min(values))} {fmt(median(values))} {fmt(max(values))}]"


def read(path: Path) -> dict:
    """Read a JSON file criterion wrote."""
    return json.loads(path.read_text(encoding="utf-8"))


def means(side: Path) -> list[float]:
    """Return each run's mean, in nanoseconds."""
    return [read(f)["mean"]["point_estimate"] for f in side.glob("*/estimates.json")]


def compare(path: Path) -> list[str]:
    """Return criterion's output lines for one benchmark."""
    pr = means(path / "neqo")
    if not pr:
        return []
    base = means(path / "neqo-baseline")
    bench = read(next(path.glob("neqo/*/benchmark.json")))
    title = bench["title"]
    pad = " " * 24
    timing = f"time:   {bracket(pr, time)}"
    # Criterion puts ids of more than 23 characters on a line of their own.
    lines = [title, pad + timing] if len(title) > 23 else [f"{title:<24}{timing}"]
    if not base:
        return lines

    p = mannwhitneyu(base, pr, alternative="two-sided", method="exact").pvalue
    delta = median(pr) / median(base) - 1
    if p >= SIGNIFICANCE:
        verdict = "No change in performance detected."
    elif abs(delta) <= GROUP_NOISE_THRESHOLDS.get(bench["group_id"], NOISE_THRESHOLD):
        verdict = "Change within noise threshold."
    else:
        verdict = f"Performance has {'regressed' if delta > 0 else 'improved'}."
    relative = [v / median(base) - 1 for v in pr]
    p_text = f"p = {p:.2f} {'<' if p < SIGNIFICANCE else '>'} {SIGNIFICANCE:.2f}"
    return [
        *lines,
        f"{pad}baseline: {bracket(base, time)}",
        f"{' ' * 17}change:",
        f"{pad}time:   {bracket(relative, change)} ({p_text})",
        pad + verdict,
    ]


def main() -> None:
    """Print the comparison for each benchmark directory given."""
    for arg in sys.argv[1:]:
        for line in compare(Path(arg)):
            print(line)


if __name__ == "__main__":
    main()
