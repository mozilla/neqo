#!/usr/bin/env python3
# /// script
# dependencies = ["matplotlib"]
# ///
"""Visualize neqo .sqlog qlog files.

Usage:
    uv run --with matplotlib tools/qvis.py <file.sqlog> [--output chart.png]
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from itertools import pairwise
from pathlib import Path
from typing import Any

import matplotlib.patches as mpatches  # pylint: disable=import-error
import matplotlib.pyplot as plt  # pylint: disable=import-error
from matplotlib.axes import Axes  # pylint: disable=import-error
from matplotlib.ticker import EngFormatter  # pylint: disable=import-error

# ── Constants ──────────────────────────────────────────────────────────────

# Okabe-Ito palette — colorblind-safe, perceptually distinct
# https://jfly.uni-koeln.de/color/
OI_ORANGE = "#E69F00"
OI_SKY = "#56B4E9"
OI_GREEN = "#009E73"
OI_YELLOW = "#F0E442"
OI_BLUE = "#0072B2"
OI_VERMILLION = "#D55E00"
OI_PINK = "#CC79A7"
OI_BLACK = "#000000"

CC_STYLES: dict[str, tuple[str, float, str]] = {
    "slow_start": (OI_GREEN, 0.15, "Slow Start"),
    "congestion_avoidance": (OI_SKY, 0.12, "Congestion Avoidance"),
    "recovery_start": (OI_VERMILLION, 0.15, "Recovery (Loss)"),
    "recovery": (OI_VERMILLION, 0.15, "Recovery (Loss)"),
    "recovery:ecn": (OI_ORANGE, 0.18, "Recovery (ECN)"),
    "recovery:persistent_congestion": (
        OI_PINK,
        0.20,
        "Recovery (Persistent Congestion)",
    ),
}

LOSS_COLORS: dict[str, tuple[str, str]] = {
    "pto_expired": (OI_VERMILLION, "PTO Loss"),
    "time_threshold": (OI_PINK, "Time Threshold Loss"),
    "reordering_threshold": (OI_BLACK, "Reordering Threshold Loss"),
    "unknown": ("gray", "Unknown Loss"),
}

FC_COLOR = OI_PINK

METRIC_FIELDS = (
    "min_rtt",
    "smoothed_rtt",
    "latest_rtt",
    "congestion_window",
    "bytes_in_flight",
    "ssthresh",
    "pacing_rate",
)

# ── Data types ─────────────────────────────────────────────────────────────


@dataclass
class FcInterval:
    """A period during which the sender was flow-control blocked."""

    t_start: float
    t_end: float
    stream_id: int | None = None  # None → connection-level block


@dataclass
class TraceData:
    """All data extracted from a single qlog trace."""

    sent: list[tuple[float, int, int]] = field(default_factory=list)
    lost: list[tuple[float, int, str]] = field(default_factory=list)
    stream_bytes: list[tuple[float, int]] = field(default_factory=list)
    metrics_raw: list[tuple[float, dict[str, Any]]] = field(default_factory=list)
    cc_transitions: list[tuple[float, str]] = field(default_factory=list)
    fc_intervals: list[FcInterval] = field(default_factory=list)
    acked: list[tuple[float, int]] = field(default_factory=list)
    spurious_recoveries: list[float] = field(default_factory=list)
    max_t: float = 0.0
    initial_cwnd: float | None = None  # from recovery:parameters_set


@dataclass
class MetricSeries:
    """Forward-filled metric time series derived from sparse updates."""

    ts: list[float] = field(default_factory=list)
    values: dict[str, list[float | None]] = field(default_factory=dict)


@dataclass
class StepStyle:
    """Visual style for a step-line metric plot."""

    color: str
    label: str
    linestyle: str = "solid"
    linewidth: float = 1.5
    scale: float = 1.0


@dataclass
class PlotContext:
    """Shared state passed to each panel renderer."""

    cc_intervals: list[tuple[float, float, str]]
    fc_intervals: list[FcInterval]
    metrics: MetricSeries


# ── Parsing ────────────────────────────────────────────────────────────────


def parse_sqlog(path: str) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """Parse a JSON-SEQ .sqlog file into (header, events)."""
    with open(path, "rb") as f:
        raw = f.read()

    header: dict[str, Any] | None = None
    events: list[dict[str, Any]] = []

    for chunk in raw.split(b"\x1e"):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            obj: dict[str, Any] = json.loads(chunk)
        except json.JSONDecodeError:
            continue
        if "qlog_version" in obj:
            header = obj
        elif "time" in obj and "name" in obj:
            events.append(obj)

    return header, events


# ── Extraction ─────────────────────────────────────────────────────────────


def _extract_fc_intervals(events: list[dict[str, Any]]) -> list[FcInterval]:
    """Derive flow-control blocked intervals from sent/received frame sequences."""
    conn_blocked_at: float | None = None
    stream_blocked_at: dict[int, float] = {}
    intervals: list[FcInterval] = []
    max_t: float = 0.0

    for ev in events:
        t: float = ev["time"]
        max_t = max(max_t, t)
        name: str = ev["name"]
        frames: list[dict[str, Any]] = (ev.get("data") or {}).get("frames") or []

        if name == "transport:packet_sent":
            for fr in frames:
                ft = fr.get("frame_type", "")
                if ft == "data_blocked" and conn_blocked_at is None:
                    conn_blocked_at = t
                elif ft == "stream_data_blocked":
                    sid = int(fr.get("stream_id", 0))
                    stream_blocked_at.setdefault(sid, t)

        elif name == "transport:packet_received":
            for fr in frames:
                ft = fr.get("frame_type", "")
                if ft == "max_data" and conn_blocked_at is not None:
                    intervals.append(FcInterval(conn_blocked_at, t))
                    conn_blocked_at = None
                elif ft == "max_stream_data":
                    sid = int(fr.get("stream_id", 0))
                    if sid in stream_blocked_at:
                        intervals.append(FcInterval(stream_blocked_at.pop(sid), t, sid))

    # Close any intervals still open at trace end
    if conn_blocked_at is not None:
        intervals.append(FcInterval(conn_blocked_at, max_t))
    for sid, t_start in stream_blocked_at.items():
        intervals.append(FcInterval(t_start, max_t, sid))

    return intervals


def extract(events: list[dict[str, Any]]) -> TraceData:  # pylint: disable=too-many-branches
    """Extract all typed data series from a flat list of qlog events."""
    data = TraceData(
        max_t=max((ev["time"] for ev in events), default=0.0),
        fc_intervals=_extract_fc_intervals(events),
    )
    cumulative_stream_bytes = 0

    for ev in events:
        t: float = ev["time"]
        name: str = ev["name"]
        ev_data: dict[str, Any] = ev.get("data") or {}

        if name == "transport:packet_sent":
            hdr = ev_data.get("header") or {}
            if (pn := hdr.get("packet_number")) is not None:
                size = int((ev_data.get("raw") or {}).get("length") or 0)
                data.sent.append((t, int(pn), size))
            for fr in ev_data.get("frames") or []:
                if fr.get("frame_type") == "stream":
                    cumulative_stream_bytes += int(fr.get("length") or 0)
            if cumulative_stream_bytes > 0:
                data.stream_bytes.append((t, cumulative_stream_bytes))

        elif name == "recovery:packet_lost":
            hdr = ev_data.get("header") or {}
            if (pn := hdr.get("packet_number")) is not None:
                trigger = str(ev_data.get("trigger") or "unknown")
                data.lost.append((t, int(pn), trigger))

        elif name == "recovery:parameters_set":
            if (icwnd := ev_data.get("initial_congestion_window")) is not None:
                data.initial_cwnd = float(icwnd)
        elif name == "recovery:metrics_updated":
            data.metrics_raw.append((t, ev_data))

        elif name == "transport:packets_acked":
            for pn in ev_data.get("packet_numbers") or []:
                data.acked.append((t, int(pn)))

        elif name == "recovery:congestion_state_updated":
            new_state = str(ev_data.get("new") or "unknown")
            cc_trigger: str | None = ev_data.get("trigger")
            if new_state == "recovery" and cc_trigger:
                new_state = f"recovery:{cc_trigger}"
            data.cc_transitions.append((t, new_state))

    # Detect spurious recoveries: cwnd and ssthresh both jump UP in the same
    # metrics event (the CC restoring stored state).
    prev_cwnd: float = 0
    prev_sst: float = 0
    for t, ev_data in data.metrics_raw:
        cwnd = (
            float(ev_data["congestion_window"])
            if "congestion_window" in ev_data
            else prev_cwnd
        )
        sst = float(ev_data["ssthresh"]) if "ssthresh" in ev_data else prev_sst
        if cwnd > prev_cwnd * 1.2 and sst > prev_sst * 1.2 and prev_cwnd > 0:
            data.spurious_recoveries.append(t)
        prev_cwnd, prev_sst = cwnd, sst

    return data


def build_metrics(
    raw: list[tuple[float, dict[str, Any]]],
    initial_cwnd: float | None = None,
) -> MetricSeries:
    """Forward-fill sparse metric events into dense per-field time series.

    When *initial_cwnd* is provided and no ``congestion_window`` field ever
    appears in the event stream (e.g. app-limited connections), a synthetic
    constant sample is injected so the panel is not left blank.
    """
    series = MetricSeries(values={f: [] for f in METRIC_FIELDS})
    current: dict[str, float | None] = dict.fromkeys(METRIC_FIELDS)

    if initial_cwnd is not None:
        current["congestion_window"] = initial_cwnd

    for t, ev_data in raw:
        series.ts.append(t)
        for f in METRIC_FIELDS:
            if f in ev_data:
                current[f] = float(ev_data[f])
            series.values[f].append(current[f])

    return series


def build_cc_intervals(
    transitions: list[tuple[float, str]], max_t: float
) -> list[tuple[float, float, str]]:
    """Convert a list of CC state transitions into (t_start, t_end, state) spans."""
    sentinel = transitions + [(max_t, "")]
    return [(t, sentinel[i + 1][0], state) for i, (t, state) in enumerate(transitions)]


# ── Plotting helpers ───────────────────────────────────────────────────────


def _decorate_panel(ax: Axes, ctx: PlotContext) -> None:
    """Apply CC-state and FC-block background shading to an axis."""
    for t_start, t_end, state in ctx.cc_intervals:
        color, alpha, _ = CC_STYLES.get(state, ("#888888", 0.10, state))
        ax.axvspan(t_start, t_end, color=color, alpha=alpha, linewidth=0)
    for iv in ctx.fc_intervals:
        alpha = 0.20 if iv.stream_id is None else 0.12
        ax.axvspan(iv.t_start, iv.t_end, color=FC_COLOR, alpha=alpha, linewidth=0)


def _maybe_legend(ax: Axes, **kwargs: Any) -> None:
    """Call ax.legend() only when there are labeled artists to show."""
    if any(
        label and not label.startswith("_")
        for _, label in zip(*ax.get_legend_handles_labels())
    ):
        ax.legend(**kwargs)


def _metric_xy(
    ctx: PlotContext, field_name: str, scale: float = 1.0
) -> tuple[tuple[float, ...], tuple[float, ...]] | None:
    """Return (xs, ys) for a metric field, skipping None values. None if empty."""
    pairs = [
        (t, v * scale)
        for t, v in zip(ctx.metrics.ts, ctx.metrics.values[field_name])
        if v is not None
    ]
    if not pairs:
        return None
    return tuple(zip(*pairs))  # type: ignore[return-value]


def _plot_step(ax: Axes, ctx: PlotContext, field_name: str, style: StepStyle) -> None:
    """Plot one forward-filled metric as a step line."""
    if xy := _metric_xy(ctx, field_name, style.scale):
        ax.step(
            xy[0],
            xy[1],
            where="post",
            color=style.color,
            linewidth=style.linewidth,
            linestyle=style.linestyle,
            label=style.label,
        )


def _plot_line(
    ax: Axes,
    ctx: PlotContext,
    field_name: str,
    color: str,
    label: str,
) -> None:
    """Plot one forward-filled metric as a continuous line."""
    if xy := _metric_xy(ctx, field_name):
        ax.plot(xy[0], xy[1], color=color, linewidth=1, label=label, alpha=0.9)


# ── Panel renderers ────────────────────────────────────────────────────────


def _panel_packet_timeline(ax: Axes, ctx: PlotContext, data: TraceData) -> None:
    """Panel 1: packet number vs. time, with lost-packet markers."""
    _decorate_panel(ax, ctx)
    lost_pns = {pn for _, pn, _ in data.lost}

    ok_pts = [(t, pn) for t, pn, _ in data.sent if pn not in lost_pns]
    if ok_pts:
        xs, ys = zip(*ok_pts)
        ax.scatter(xs, ys, s=8, color=OI_BLUE, linewidths=0, zorder=3)

    for trigger, (color, label) in LOSS_COLORS.items():
        pts = [(t, pn) for t, pn, tr in data.lost if tr == trigger]
        if pts:
            xs, ys = zip(*pts)
            ax.scatter(
                xs,
                ys,
                s=12,
                color=color,
                linewidths=0,
                zorder=5,
                label=label,
            )

    if data.acked:
        ax_ts, ax_pns = zip(*data.acked)
        ax.scatter(
            ax_ts,
            ax_pns,
            s=4,
            color=OI_ORANGE,
            linewidths=0,
            alpha=0.5,
            zorder=2,
            label="ACK",
        )

    ax.set_ylabel("Packet #")
    ax.set_ylim(bottom=0)
    _maybe_legend(ax, loc="upper left", fontsize=7, framealpha=0.7)

    if data.stream_bytes:
        ax2 = ax.twinx()
        xs, ys = zip(*data.stream_bytes)
        ax2.plot(xs, ys, color=OI_GREEN, linewidth=1.5, alpha=0.8, label="Stream Bytes")
        ax2.yaxis.set_major_formatter(EngFormatter(unit="B"))
        ax2.set_ylabel("Cumulative Stream Bytes")
        ax2.set_ylim(bottom=0)
        _maybe_legend(ax2, loc="upper right", fontsize=7, framealpha=0.7)


def _panel_cwnd(ax: Axes, ctx: PlotContext, data: TraceData) -> None:
    """Panel 2: bytes-in-flight, cwnd, ssthresh (left) + pacing rate (right)."""
    _decorate_panel(ax, ctx)
    _plot_step(
        ax,
        ctx,
        "bytes_in_flight",
        StepStyle(OI_BLACK, "Bytes in Flight", linewidth=1.0),
    )
    _plot_step(ax, ctx, "congestion_window", StepStyle(OI_BLUE, "Congestion Window"))
    _plot_step(
        ax,
        ctx,
        "ssthresh",
        StepStyle(OI_VERMILLION, "Slow Start Threshold", "dashed", linewidth=1.0),
    )
    for t in data.spurious_recoveries:
        ax.axvline(
            t,
            color=OI_GREEN,
            linewidth=1.5,
            linestyle=":",
            alpha=0.9,
            label="Spurious Recovery",
        )
    ax.yaxis.set_major_formatter(EngFormatter(unit="B"))
    ax.set_ylabel("Bytes")
    ax.set_ylim(bottom=0)
    _maybe_legend(ax, loc="upper left", fontsize=7, framealpha=0.7)

    ax2 = ax.twinx()
    _plot_step(ax2, ctx, "pacing_rate", StepStyle(OI_ORANGE, "Pacing Rate"))
    ax2.yaxis.set_major_formatter(EngFormatter(unit="B/s"))
    ax2.set_ylabel("Pacing Rate")
    ax2.set_ylim(bottom=0)
    _maybe_legend(ax2, loc="upper right", fontsize=7, framealpha=0.7)


def _panel_rtt(ax: Axes, ctx: PlotContext, data: TraceData) -> None:
    """Panel 3: RTT (left axis) + inter-packet send gap (right axis)."""
    _decorate_panel(ax, ctx)
    _plot_line(ax, ctx, "smoothed_rtt", OI_BLUE, "Smoothed RTT")
    _plot_line(ax, ctx, "latest_rtt", OI_BLACK, "Latest RTT")
    _plot_line(ax, ctx, "min_rtt", OI_ORANGE, "Minimum RTT")
    ax.set_ylabel("RTT (ms)")
    ax.set_ylim(bottom=0)
    _maybe_legend(ax, loc="upper left", fontsize=7, framealpha=0.7)

    if len(data.sent) > 1:
        ax2 = ax.twinx()

        def _in_fc_block(t: float) -> bool:
            return any(iv.t_start <= t <= iv.t_end for iv in ctx.fc_intervals)

        pacing_x, pacing_y, blocked_x, blocked_y = [], [], [], []
        for a, b in pairwise(data.sent):
            mid = (a[0] + b[0]) / 2.0
            gap = b[0] - a[0]
            if _in_fc_block(mid):
                blocked_x.append(mid)
                blocked_y.append(gap)
            else:
                pacing_x.append(mid)
                pacing_y.append(gap)

        if pacing_x:
            ax2.scatter(
                pacing_x,
                pacing_y,
                s=6,
                color=OI_BLACK,
                linewidths=0,
                alpha=0.3,
                label="Send Gap",
            )
        if blocked_x:
            ax2.scatter(
                blocked_x,
                blocked_y,
                s=6,
                color=OI_VERMILLION,
                linewidths=0,
                alpha=0.4,
                label="FC-Blocked Gap",
            )
        ax2.set_ylabel("Send Gap (ms)")
        ax2.set_ylim(bottom=0)
        _maybe_legend(ax2, loc="upper right", fontsize=7, framealpha=0.7)

    ax.set_xlabel("Time (ms)")


# ── Main plot ──────────────────────────────────────────────────────────────


def _cc_legend_patches(
    cc_intervals: list[tuple[float, float, str]],
    fc_intervals: list[FcInterval],
) -> list[mpatches.Patch]:
    """Build figure-level legend patches for states and FC blocking that appear in data."""
    cc_states_present = {state for _, _, state in cc_intervals}
    patches: list[mpatches.Patch] = []
    seen_labels: set[str] = set()
    for state, (color, _, label) in CC_STYLES.items():
        if state in cc_states_present and label not in seen_labels:
            seen_labels.add(label)
            patches.append(mpatches.Patch(color=color, alpha=0.5, label=label))
    has_conn_fc = has_stream_fc = False
    for iv in fc_intervals:
        if iv.stream_id is None:
            has_conn_fc = True
        else:
            has_stream_fc = True
        if has_conn_fc and has_stream_fc:
            break
    if has_conn_fc:
        patches.append(
            mpatches.Patch(color=OI_PINK, alpha=0.5, label="FC Blocked (Connection)")
        )
    if has_stream_fc:
        patches.append(
            mpatches.Patch(color=OI_PINK, alpha=0.3, label="FC Blocked (Stream)")
        )
    return patches


def plot(
    header: dict[str, Any] | None,
    data: TraceData,
    output: str,
) -> None:
    """Render the 3-panel figure and save it to *output*."""
    metrics = build_metrics(data.metrics_raw, data.initial_cwnd)
    cc_intervals = build_cc_intervals(data.cc_transitions, data.max_t)
    ctx = PlotContext(
        cc_intervals=cc_intervals, fc_intervals=data.fc_intervals, metrics=metrics
    )

    fig, axes = plt.subplots(3, 1, sharex=True, figsize=(14, 14))
    fig.subplots_adjust(hspace=0.08, left=0.09, right=0.88, top=0.95, bottom=0.06)

    title = "neqo qlog"
    if header:
        vp = header.get("trace", {}).get("vantage_point", {})
        if vp.get("name"):
            title = str(vp["name"])
    fig.suptitle(title, fontsize=13)

    _panel_packet_timeline(axes[0], ctx, data)
    _panel_cwnd(axes[1], ctx, data)
    _panel_rtt(axes[2], ctx, data)
    axes[0].set_xlim(left=0)

    fig.legend(
        handles=_cc_legend_patches(cc_intervals, data.fc_intervals),
        loc="lower center",
        ncol=5,
        fontsize=8,
        framealpha=0.7,
        bbox_to_anchor=(0.5, 0.01),
    )

    fig.savefig(output, bbox_inches="tight")
    print(f"Saved to {output}")


# ── CLI ────────────────────────────────────────────────────────────────────


def main() -> None:
    """Entry point."""
    parser = argparse.ArgumentParser(
        description="Visualize one or more neqo .sqlog files, one PDF per file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:  uv run --with matplotlib tools/qvis.py /tmp/qlog/*.sqlog",
    )
    parser.add_argument("sqlog", nargs="+", help="Path(s) to .sqlog file(s)")
    parser.add_argument(
        "--output-dir",
        "-d",
        metavar="DIR",
        help="Directory for output PDFs (default: same directory as each input file)",
    )
    args = parser.parse_args()

    errors = 0
    for path in args.sqlog:
        stem = Path(path).stem
        out_dir = Path(args.output_dir) if args.output_dir else Path(path).parent
        output = str(out_dir / (stem + ".pdf"))

        header, events = parse_sqlog(path)
        if not events:
            print(f"{path}: no events found, skipping", file=sys.stderr)
            errors += 1
            continue

        data = extract(events)
        plot(header, data, output)

    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
