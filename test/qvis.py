#!/usr/bin/env python3
# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.
# /// script
# ///
"""Visualize neqo .sqlog files as interactive HTML.

Requires network access on first run to fetch uPlot from CDN (cached thereafter).

Usage:
    uv run test/qvis.py <file.sqlog> [...]
    uv run test/qvis.py --output-dir /tmp /path/to/*.sqlog
"""

from __future__ import annotations

import argparse
import base64
import gzip
import html
import json
import sys
import urllib.request
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

UPLOT_JS_URL = "https://cdn.jsdelivr.net/npm/uplot@1.6.32/dist/uPlot.iife.min.js"
UPLOT_CSS_URL = "https://cdn.jsdelivr.net/npm/uplot@1.6.32/dist/uPlot.min.css"

METRIC_FIELDS = (
    "min_rtt",
    "smoothed_rtt",
    "latest_rtt",
    "congestion_window",
    "bytes_in_flight",
    "ssthresh",
    "pacing_rate",
)
_INT_METRICS = {"congestion_window", "bytes_in_flight", "ssthresh", "pacing_rate"}
_EPS = 2.0**-23  # ~119ns; exact in IEEE 754, so no representation noise


class _Seq:
    """Generates epsilon-offset timestamps to disambiguate same-time events."""

    def __init__(self) -> None:
        self._t = -1.0
        self._n = 0

    def __call__(self, t: float) -> float:
        if t == self._t:
            self._n += 1
        else:
            self._n = 0
            self._t = t
        return t + self._n * _EPS


@dataclass
class TraceData:
    sent_t: list[float] = field(default_factory=list)
    send_gap_t: list[float] = field(default_factory=list)
    send_gap_v: list[float] = field(default_factory=list)
    sent_pn: list[int] = field(default_factory=list)
    sent_frames: list[list] = field(default_factory=list)
    lost_t: list[float] = field(default_factory=list)
    lost_pn: list[int] = field(default_factory=list)
    lost_trigger: list[str] = field(default_factory=list)
    acked_t: list[float] = field(default_factory=list)
    acked_pn: list[int] = field(default_factory=list)
    stream_bytes: dict[int, tuple[list[float], list[int]]] = field(default_factory=dict)
    metrics_t: list[float] = field(default_factory=list)
    metrics: dict[str, list[float | None]] = field(default_factory=dict)
    ack_ranges: dict[int, list[list[int]]] = field(default_factory=dict)
    ack_recv_pn: dict[int, int] = field(default_factory=dict)
    ecn_ce_t: list[float] = field(default_factory=list)
    ecn_ce_pn: list[int] = field(default_factory=list)
    cc_transitions: list[tuple[float, str]] = field(default_factory=list)
    fc_conn_intervals: list[tuple[float, float]] = field(default_factory=list)
    fc_stream_intervals: list[tuple[float, float]] = field(default_factory=list)
    max_t: float = 0.0
    title: str = ""


def parse_sqlog(path: str) -> list[dict[str, Any]]:
    raw = Path(path).read_bytes()
    events: list[dict[str, Any]] = []
    for chunk in raw.split(b"\x1e"):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            obj = json.loads(chunk)
        except json.JSONDecodeError:
            continue
        if "time" in obj and "name" in obj:
            events.append(obj)
    return events


def extract(  # noqa: C901  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    events: list[dict[str, Any]], filename: str = ""
) -> TraceData:
    events.sort(key=lambda ev: ev["time"])
    data = TraceData(
        max_t=max((ev["time"] for ev in events), default=0.0),
        metrics={f: [] for f in METRIC_FIELDS},
        title=filename,
    )
    pn_frames: dict[int, list] = {}
    cum_stream: dict[int, int] = {}
    acked_pns: set[int] = set()
    cur: dict[str, float | None] = dict.fromkeys(METRIC_FIELDS)
    fc_conn_blocked = False
    fc_stream_blocked: set[int] = set()
    last_stream_data_t: float = 0.0
    sent_seq, lost_seq, ack_seq, metrics_seq = _Seq(), _Seq(), _Seq(), _Seq()
    last_ce_count = 0
    last_recv_pn: int | None = None
    prev_sent_t: float = -1.0

    for ev in events:
        t: float = ev["time"]
        name: str = ev["name"]
        d: dict[str, Any] = ev.get("data") or {}
        frames = d.get("frames") or []

        if name == "transport:packet_sent":
            hdr = d.get("header") or {}
            if (pn := hdr.get("packet_number")) is not None:
                st = sent_seq(t)
                data.sent_t.append(st)
                data.sent_pn.append(int(pn))
                data.sent_frames.append(frames)
                if prev_sent_t >= 0:
                    data.send_gap_t.append((prev_sent_t + t) / 2.0)
                    data.send_gap_v.append(t - prev_sent_t)
                prev_sent_t = t
                pn_frames[int(pn)] = frames
                for fr in frames:
                    ft = fr.get("frame_type", "")
                    if ft == "stream":
                        last_stream_data_t = t
                    elif ft == "data_blocked":
                        fc_conn_blocked = True
                    elif ft == "stream_data_blocked":
                        fc_stream_blocked.add(int(fr.get("stream_id", 0)))
        elif name == "transport:packet_received":
            hdr = d.get("header") or {}
            for fr in frames:
                ft = fr.get("frame_type", "")
                if ft == "max_data" and fc_conn_blocked:
                    if last_stream_data_t < t:
                        data.fc_conn_intervals.append((last_stream_data_t, t))
                    fc_conn_blocked = False
                elif ft == "max_stream_data":
                    sid = int(fr.get("stream_id", 0))
                    if sid in fc_stream_blocked:
                        if last_stream_data_t < t:
                            data.fc_stream_intervals.append((last_stream_data_t, t))
                        fc_stream_blocked.discard(sid)
                if ft == "ack":
                    ack_ranges = fr.get("acked_ranges")
                    if ack_ranges:
                        last_recv_pn = (
                            int(hdr["packet_number"])
                            if hdr.get("packet_number") is not None
                            else None
                        )
                    ce = int(fr.get("ce", 0))
                    if ce > last_ce_count:
                        delta = ce - last_ce_count
                        # Pick top `delta` pns from acked_ranges (highest first)
                        pns_desc: list[int] = []
                        for r in ack_ranges or []:
                            for p in range(int(r[0]), int(r[1]) - 1, -1):
                                pns_desc.append(p)
                                if len(pns_desc) >= delta:
                                    break
                            if len(pns_desc) >= delta:
                                break
                        ecn_seq = _Seq()
                        for p in pns_desc:
                            data.ecn_ce_t.append(ecn_seq(t))
                            data.ecn_ce_pn.append(p)
                        last_ce_count = ce
        elif name == "recovery:packet_lost":
            hdr = d.get("header") or {}
            if (pn := hdr.get("packet_number")) is not None:
                data.lost_t.append(lost_seq(t))
                data.lost_pn.append(int(pn))
                data.lost_trigger.append(str(d.get("trigger") or "unknown"))
        elif name == "transport:packets_acked":
            pns = sorted(int(pn) for pn in d.get("packet_numbers") or [])
            # Compute ranges from newly-acked pns (not cumulative ACK frame)
            new_ranges: list[list[int]] = []
            for pn in pns:
                if new_ranges and pn == new_ranges[-1][1] + 1:
                    new_ranges[-1][1] = pn
                else:
                    new_ranges.append([pn, pn])
            for pn in pns:
                data.acked_t.append(ack_seq(t))
                data.acked_pn.append(pn)
                data.ack_ranges[pn] = new_ranges
                if last_recv_pn is not None:
                    data.ack_recv_pn[pn] = last_recv_pn
                if pn not in acked_pns:
                    acked_pns.add(pn)
                    for fr in pn_frames.get(pn, []):
                        if fr.get("frame_type") == "stream":
                            sid = int(fr.get("stream_id", 0))
                            cum_stream[sid] = cum_stream.get(sid, 0) + int(
                                fr.get("length") or 0
                            )
                            sb = data.stream_bytes.setdefault(sid, ([], []))
                            sb[0].append(t)
                            sb[1].append(cum_stream[sid])
        elif name == "recovery:parameters_set":
            if (v := d.get("initial_congestion_window")) is not None:
                cur["congestion_window"] = float(v)
        elif name == "recovery:metrics_updated":
            data.metrics_t.append(metrics_seq(t))
            for f in METRIC_FIELDS:
                if f in d:
                    cur[f] = float(d[f])
                data.metrics[f].append(cur[f])
        elif name == "recovery:congestion_state_updated":
            cc_state = str(d.get("new") or "unknown")
            tr: str | None = d.get("trigger")
            if cc_state == "recovery" and tr:
                cc_state = f"recovery:{tr}"
            data.cc_transitions.append((t, cc_state))

    if fc_conn_blocked:
        data.fc_conn_intervals.append((last_stream_data_t, data.max_t))
    if fc_stream_blocked:
        data.fc_stream_intervals.append((last_stream_data_t, data.max_t))
    return data


def _r4(v: float | None) -> float | None:
    return None if v is None else float(f"{v:.4g}")


def data_to_json(data: TraceData) -> str:  # noqa: PLR0914

    cc = []
    tr = data.cc_transitions
    if tr and tr[0][0] > 0:
        cc.append([0, tr[0][0], "slow_start"])
    for i, (t, s) in enumerate(tr):
        cc.append([t, tr[i + 1][0] if i + 1 < len(tr) else data.max_t, s])

    loss_by_trigger: dict[str, tuple[list[float], list[int]]] = {}
    for t, pn, trig in zip(data.lost_t, data.lost_pn, data.lost_trigger):
        loss_by_trigger.setdefault(trig, ([], []))
        loss_by_trigger[trig][0].append(t)
        loss_by_trigger[trig][1].append(pn)

    def _mv(f: str, v: float | None) -> float | int | None:
        if v is None:
            return None
        return int(v) if f in _INT_METRICS else _r4(v)

    metrics = [data.metrics_t] + [
        [_mv(f, v) for v in data.metrics[f]] for f in METRIC_FIELDS
    ]
    mi = {f: i + 1 for i, f in enumerate(METRIC_FIELDS)}

    # Deduplicate ack_ranges: many pns share the same range list.
    # Emit as [ranges_list, pn→index] instead of pn→ranges.
    # Each unique range list also carries its recv_pn (same for all pns in group).
    ranges_dedup: dict[int, int] = {}  # id(ranges) → index
    ranges_list: list[tuple[list[list[int]], int | None]] = []
    ack_idx: dict[str, int] = {}
    for pn, ranges in data.ack_ranges.items():
        rid = id(ranges)
        if rid not in ranges_dedup:
            ranges_dedup[rid] = len(ranges_list)
            ranges_list.append((ranges, data.ack_recv_pn.get(pn)))
        ack_idx[str(pn)] = ranges_dedup[rid]

    # Compact pktMeta: stream-only packets (99%+) as [stream_id, offset, length, fin].
    # Other packets as full frame list (prefixed with null marker).
    pkt_meta: dict[str, Any] = {}
    for pn, frames in zip(data.sent_pn, data.sent_frames):
        if len(frames) == 1 and frames[0].get("frame_type") == "stream":
            fr = frames[0]
            pkt_meta[str(pn)] = [
                int(fr.get("stream_id", 0)),
                int(fr.get("offset", 0)),
                int(fr.get("length", 0)),
                1 if fr.get("fin") else 0,
            ]
        else:
            pkt_meta[str(pn)] = [None, frames]

    return json.dumps(
        {
            "title": data.title,
            "maxT": data.max_t,
            "ccIntervals": cc,
            "fcStreamIntervals": data.fc_stream_intervals,
            "fcConnIntervals": data.fc_conn_intervals,
            "sent": [data.sent_t, data.sent_pn],
            "streamBytes": {
                str(sid): list(tv) for sid, tv in sorted(data.stream_bytes.items())
            },
            "acked": [data.acked_t, data.acked_pn],
            "lost": {trig: [lt, lpn] for trig, (lt, lpn) in loss_by_trigger.items()},
            "ecnCe": [data.ecn_ce_t, data.ecn_ce_pn],
            "metrics": metrics,
            "mi": mi,
            "sendGap": [data.send_gap_t, data.send_gap_v],
            "pktMeta": pkt_meta,
            "ackRanges": ranges_list,
            "ackIdx": ack_idx,
        },
        separators=(",", ":"),
    )


@lru_cache
def _fetch(url: str) -> str:
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:  # noqa: S310
            return resp.read().decode()
    except Exception as e:  # pylint: disable=broad-exception-caught
        raise SystemExit(f"Failed to fetch {url}: {e}") from e


_DIR = Path(__file__).parent


@lru_cache
def _template() -> str:
    html_tmpl = (_DIR / "qvis.html").read_text(encoding="utf-8")
    js = (_DIR / "qvis.js").read_text(encoding="utf-8")
    return html_tmpl.replace("__QVIS_JS__", js)


def generate_html(data: TraceData) -> str:
    import re

    data_b64 = base64.b64encode(gzip.compress(data_to_json(data).encode())).decode()
    subs = {
        "__TITLE__": html.escape(data.title),
        "__UPLOT_CSS__": _fetch(UPLOT_CSS_URL),
        "__UPLOT_JS__": _fetch(UPLOT_JS_URL),
        "__DATA_B64GZ__": data_b64,
    }
    return re.compile("|".join(re.escape(k) for k in subs)).sub(
        lambda m: subs[m.group()], _template()
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Visualize neqo .sqlog files as interactive HTML",
    )
    parser.add_argument("sqlog", nargs="+", help="Path(s) to .sqlog file(s)")
    parser.add_argument("--output-dir", "-d", metavar="DIR")
    parser.add_argument(
        "--title", "-t", metavar="TITLE", help="Plot title (default: filename)"
    )
    args = parser.parse_args()

    errors = 0
    for path in args.sqlog:
        stem = Path(path).stem
        out_dir = Path(args.output_dir) if args.output_dir else Path(path).parent
        output = str(out_dir / (stem + ".html"))
        events = parse_sqlog(path)
        if not events:
            print(f"{path}: no events, skipping", file=sys.stderr)
            errors += 1
            continue
        data = extract(events, args.title or Path(path).name)
        Path(output).write_text(generate_html(data), encoding="utf-8")
        print(output)
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
