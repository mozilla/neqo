#!/usr/bin/env python3
"""Compare QUIC implementations using hyperfine and perf."""

import argparse
import json
import math
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from collections import Counter
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, fields
from itertools import product
from pathlib import Path
from statistics import NormalDist, fmean, median, stdev
from typing import NamedTuple


class ImplConfig(NamedTuple):
    client_cmd: str
    server_cmd: str
    disk_flag: str
    interop_flag: str


# fmt: off
IMPLS = {
    "neqo": ImplConfig(
        "build-neqo/neqo/neqo-client _cc _pacing _disk _flags -Q 1 https://{host}:{port}/{size}",
        "build-neqo/neqo/neqo-server _cc _pacing _flags -Q 1 {host}:{port}",
        "--output-dir .", "",
    ),
    "google": ImplConfig(
        "build-google/quic_client --disable_certificate_verification https://{host}:{port}/{size}",
        "build-google/quic_server --generate_dynamic_responses --port {port} --certificate_file {tmp}/cert --key_file {tmp}/key",
        "", "",
    ),
    "quiche": ImplConfig(
        "build-quiche/quiche-client _disk --no-verify https://{host}:{port}/{size}",
        "build-quiche/quiche-server --root {tmp} --listen {host}:{port} --cert {tmp}/cert --key {tmp}/key",
        "--dump-responses .", "",
    ),
    "s2n": ImplConfig(
        "build-s2n/s2n-quic-qns interop client --tls rustls --disable-cert-verification _disk --local-ip {host} https://{host}:{port}/{size}",
        "build-s2n/s2n-quic-qns interop server --www-dir {tmp} --certificate {tmp}/cert --private-key {tmp}/key --ip {host} --port {port}",
        "--download-dir .", "-a hq-interop",
    ),
}
# fmt: on


@dataclass
class Cfg:
    """Benchmark configuration."""

    host: str
    port: int
    size: int
    runs: int
    workspace: Path
    perf_opt: str
    server_cpu: int = 0
    client_cpu: int = 1


def _tag(cmd: str) -> str:
    """Return a short process tag suitable for pkill from a command string."""
    return Path(cmd.split()[0]).name[:15]


# Deltas smaller than this are treated as measurement noise regardless of
# p-value (mirrors Criterion's noise_threshold).
NOISE_FLOOR_PCT = 1.0


def is_significant(s1: list[float], s2: list[float], pct: float) -> bool:
    """Mann-Whitney U test with a practical-significance floor.

    pct is the caller's already-computed percent change between the two
    samples' medians.
    """
    # Deferred, so that listing units and running one needs no SciPy.
    from scipy.stats import mannwhitneyu

    if not s1 or not s2 or abs(pct) < NOISE_FLOOR_PCT:
        return False
    return bool(mannwhitneyu(s1, s2, alternative="two-sided").pvalue < 0.05)


def mad(values: list[float], center: float) -> float:
    """Median absolute deviation, scaled to be comparable to a stddev."""
    return median(abs(v - center) for v in values) / NormalDist().inv_cdf(0.75)


QUIET = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}


def sh(cmd, **kw):
    """Run shell command."""
    kw.setdefault("check", False)
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    return subprocess.run(cmd, **kw)


def mangle(cmd, cc, pacing, flags, disk):
    """Replace placeholders."""
    cmd = (
        cmd.replace("_cc", f"--cc {cc}" if cc else "")
        .replace("_pacing", "" if pacing else "--no-pacing")
        .replace("_flags", flags)
        .replace("_disk", disk)
    )
    return " ".join(cmd.split())


def kill_port(port: int) -> None:
    """Kill any processes (including root-owned) listening on the given UDP/TCP port."""
    for proto in ("udp", "tcp"):
        sh(["sudo", "fuser", "-k", f"{port}/{proto}"], **QUIET)


def kill_servers() -> None:
    """Kill any lingering server processes from any known implementation."""
    for impl_config in IMPLS.values():
        sh(["sudo", "pkill", "-9", _tag(impl_config.server_cmd)], **QUIET)


@contextmanager
def _server(cmd, tag, **kw):
    """Run a server for the duration of the block, then stop it, forcibly if need be."""
    proc = subprocess.Popen(cmd, **QUIET, **kw)
    time.sleep(0.2)
    try:
        yield
    finally:
        sh(["sudo", "pkill", tag])
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            sh(["sudo", "pkill", "-9", tag])
            proc.wait(timeout=5)


def setup(cfg):
    """Create temp dir with cert/key and test files, set MTU."""
    kill_servers()
    kill_port(cfg.port)
    tmp = Path(tempfile.mkdtemp())
    (tmp / "out").mkdir()
    sh(
        f"openssl req -nodes -new -x509 -keyout {tmp / 'key'} -out {tmp / 'cert'} -subj /CN=DOMAIN",
        check=True,
        stderr=subprocess.DEVNULL,
    )
    # The warm-up size, which the file-serving implementations need to exist.
    for s in (cfg.size, cfg.size * 100, cfg.size // 32):
        sh(["truncate", "-s", str(s), str(tmp / str(s))], check=True)
    return tmp


def verify(cfg, tmp, client, server_cmd, client_cmd):
    """Run single transfer to verify it works."""
    cwd = tmp / "out"
    out = cwd / str(cfg.size)
    server = shlex.split(f"{cfg.workspace}/{server_cmd}")
    # The others write the response into `cwd`, google's client to stdout.
    to_file = client == "google"
    with (
        _server(server, _tag(server_cmd), cwd=cwd),
        open(out, "w", encoding="utf-8") if to_file else nullcontext(subprocess.DEVNULL) as stdout,
    ):
        sh(f"{cfg.workspace}/{client_cmd}", cwd=cwd, stdout=stdout, stderr=subprocess.DEVNULL)
    return out.exists() and out.stat().st_size >= cfg.size


def _pin(cpu: int) -> list[str]:
    """Prefix that pins a subprocess, and anything it forks, to one CPU."""
    return ["setarch", "--addr-no-randomize", "taskset", "-c", str(cpu)]


def _sudo_env() -> list[str]:
    """Prefix for `perf`, which needs root for the tracepoints: `sudo` resets the env, so
    restore the vars that neqo binaries need to find NSS libraries and certificates."""
    env = [f"{k}={os.environ[k]}" for k in ("LD_LIBRARY_PATH", "TEST_FIXTURE_DB") if k in os.environ]
    return ["sudo", *(["env", *env] if env else [])]


def _read_proc(path: str | Path) -> str:
    """Contents of a `/proc` file, empty if absent, e.g. IPv6 off. Says so, as empty
    counters otherwise read as "nothing moved"."""
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as e:
        print(f"note: {path} unreadable ({e}), its counters will be missing")
        return ""


COUNTER_FILES = ("/proc/net/snmp", "/proc/net/snmp6", "/proc/net/softnet_stat")


def _counters(*paths: str | Path) -> dict[str, int]:
    """UDP counters keyed by name, both families, as `--host` picks one, the softirq backlog
    drops per CPU, and the server's CPU time, from `COUNTER_FILES` or a copy of them."""
    text = "".join(map(_read_proc, paths))
    counters: dict[str, int] = {}
    # IPv4 spells these as a `Udp:` line naming the fields, then a `Udp:` line of values.
    udp = [line.split()[1:] for line in text.splitlines() if line.startswith("Udp: ")]
    for names, values in zip(udp[::2], udp[1::2], strict=False):
        counters.update(
            (f"Udp{n}", int(v)) for n, v in zip(names, values, strict=False)
        )
    # IPv6 spells them one `Udp6<name> <value>` per line.
    counters.update(
        (fields[0], int(fields[1]))
        for line in text.splitlines()
        if len(fields := line.split()) == 2 and fields[0].startswith("Udp6")
    )
    # `softnet_stat` has a line of hex fields per online CPU: the 2nd is drops, the 13th the CPU.
    cpus = filter(re.compile(r"[0-9a-f]{8}( [0-9a-f]{8}){12,}").fullmatch, text.splitlines())
    counters.update(
        (f"SoftnetDropped{int(f[12], 16)}", int(f[1], 16)) for f in map(str.split, cpus)
    )
    # `/proc/<pid>/task/*/schedstat` has a line per thread: ns on CPU, ns runnable, timeslices.
    tasks = filter(re.compile(r"\d+ \d+ \d+").fullmatch, text.splitlines())
    totals = map(sum, zip(*(map(int, line.split()) for line in tasks), strict=True))
    names = ("ServerCpuNs", "ServerRunqueueNs", "ServerTimeslices")
    counters.update(zip(names, totals, strict=False))
    return counters


def _deltas(before: dict[str, int], after: dict[str, int]) -> Counter:
    """The counters that moved, by how much."""
    return Counter({k: d for k, v in before.items() if (d := after.get(k, v) - v)})


def _jsonl(path: Path) -> list:
    """The records of a JSON Lines file, none if it is absent."""
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _measurements(path: Path) -> list[dict]:
    """The per-run measurements of a hyperfine --export-json result."""
    return json.loads(path.read_text(encoding="utf-8"))["results"][0]["measurements"]


def hyperfine(cfg, scmd, ccmd, name, out_dir, runs, part):
    """Run part `part` of a hyperfine benchmark."""
    tag = shlex.quote(_tag(scmd))
    ws = shlex.quote(str(cfg.workspace))
    out_dir.mkdir(exist_ok=True)

    # Untimed, so start-up cost lands before the sample; `&&` fails `--prepare` (not a cold
    # run) on failure. Only stderr is logged: stdout can be a response body without a disk flag.
    log = out_dir / f"{name}.warmup.log"
    warmup = (
        f"{ws}/{ccmd.replace(f'/{cfg.size}', f'/{cfg.size // 32}')}"
        f" >/dev/null 2>{shlex.quote(str(log))} && "
    )
    scratch = out_dir / f"{name}.{part}.runs"
    scratch.mkdir(exist_ok=True)
    # Both hooks run outside the timed region, so this is a before/after pair per run.
    run = f'{shlex.quote(str(scratch))}/"$HYPERFINE_ITERATION"'
    snapshot = f"cat /proc/net/snmp* /proc/net/softnet_stat > {run}"
    sched = f"cat /proc/$(cat {run}.pid)/task/*/schedstat > {run}.sched"  # Before `pkill`.
    if "neqo-server" in scmd:  # Unlike the client's, its stats I/O is outside the timed region.
        scmd += f" --stats-file {run}.server.jsonl"
    server = f"taskset -c {cfg.server_cpu} {ws}/{scmd} & echo $! > {run}.pid;"
    # Affinity survives fork and exec: pinning hyperfine pins the client it times.
    cmd = [
        *_pin(cfg.client_cpu),
        shutil.which("hyperfine") or "hyperfine",
        "--command-name",
        name,
        "--metrics",
        "time_wall_clock:ms,time_user:ms,time_system:ms",
        "--export-json",
        str(out_dir / f"{name}.{part}.json"),
        "--output",
        "null",
        "--warmup",
        str(5 if part == 0 else 0),
        "--runs",
        str(runs),
        "--prepare",
        f"{server} sleep 0.2; {warmup} {sched}.before && {snapshot}.before",
        "--conclude",
        f"{sched}.after; pkill -9 {tag}; {snapshot}.after",
        f"{ws}/{ccmd}",
    ]
    before = _counters(*COUNTER_FILES)
    result = sh(cmd, stderr=subprocess.PIPE, text=True)
    if result.returncode:
        print(result.stderr, end="")
        # hyperfine reports only *that* `--prepare` failed; the warm-up's log says why.
        if log.exists():
            print(log.read_text(encoding="utf-8"), end="")
        result.check_returncode()
    # `*RcvbufErrors` tells whether loss was a receive-queue overrun. Only what moved.
    deltas = _deltas(before, _counters(*COUNTER_FILES))
    # A record per timed run, in measurement order. A server reports the warm-up's connection,
    # then the timed one.
    with (out_dir / f"{name}.runs.jsonl").open("a" if part else "w", encoding="utf-8") as f:
        for i, m in enumerate(_measurements(out_dir / f"{name}.{part}.json")):
            snaps = (_counters(*scratch.glob(f"{i}.*{p}")) for p in ("before", "after"))
            record = {
                "part": part,
                "run": i,
                "time_wall_clock": m["time_wall_clock"]["value"],
                "time_user": m["time_user"]["value"],  # The client's, like the wall clock.
                "time_system": m["time_system"]["value"],
                "counters": _deltas(*snaps),
                "server": _jsonl(scratch / f"{i}.server.jsonl"),
            }
            f.write(f"{json.dumps(record)}\n")
    shutil.rmtree(scratch)
    udp = out_dir / f"{name}.udp"
    if part:  # Add up the earlier parts.
        lines = udp.read_text(encoding="utf-8").splitlines()
        deltas.update({key: int(delta) for key, delta in map(str.split, lines)})
    udp.write_text(
        "".join(f"{key} {delta}\n" for key, delta in deltas.items() if delta),
        encoding="utf-8",
    )
    if result.stderr:
        print(result.stderr, end="")


def perf(cfg, scmd, ccmd, name):
    """Run perf profiling with 100x larger file, also capturing per-connection stats."""
    tag, ws = _tag(scmd), cfg.workspace
    ccmd = ccmd.replace(str(cfg.size), str(cfg.size * 100))

    def with_stats(cmd: str, role: str) -> str:
        """Have neqo report PTOs and loss for this profiled transfer, not the timed hyperfine
        command, where serializing them would cost neqo I/O the other implementations don't pay."""
        if f"neqo-{role}" not in cmd:
            return cmd
        return f"{cmd} --stats-file {shlex.quote(f'{ws}/hyperfine/{name}.{role}.jsonl')}"

    scmd, ccmd = with_stats(scmd, "server"), with_stats(ccmd, "client")

    def perf_cmd(cpu, out, exe):
        perf_opt, exe = shlex.split(cfg.perf_opt), shlex.split(f"{ws}/{exe}")
        return [*_sudo_env(), *_pin(cpu), "perf", *perf_opt, "-o", f"{ws}/{out}", *exe]

    with _server(perf_cmd(cfg.server_cpu, f"{name}.server.perf", scmd), tag):
        sh(perf_cmd(cfg.client_cpu, f"{name}.client.perf", ccmd), **QUIET)


def _load_result(out_dir, name):
    """Summarize all parts of a hyperfine --export-json result, or None if there are none."""
    times = [
        m["time_wall_clock"]["value"]
        for path in sorted(out_dir.glob(f"{name}.*.json"))
        for m in _measurements(path)
    ]
    if not times:
        return None
    return {
        "times": times,
        "mean": fmean(times),
        "stddev": stdev(times) if len(times) > 1 else 0.0,
        "median": median(times),
        "min": min(times),
        "max": max(times),
    }


def process(cfg, unit, root):
    """Process the benchmark results under `root` into a table row."""
    name = unit.name
    res = _load_result(root / "hyperfine", name)
    if res is None:
        return None

    mean, times, med = res["mean"], res["times"], res["median"]
    md_dev = mad(times, med)

    outlier_flag = ""
    # hyperfine 1.x's outlier warning: a modified Z-score above 10.
    if any(abs(t - med) > 10 * md_dev for t in times):
        outliers = [t for t in times if abs(t - med) > 3 * md_dev]
        if outliers:
            detail = (
                f"{len(outliers)} of {len(times)} runs exceeded 3×MAD from the median "
                f"({med * 1000:.0f}ms); slowest was {max(times) * 1000:.0f}ms"
            )
            outlier_flag = f' <span title="{detail}">⚠️</span>'
    b = "**" if unit.bold else ""
    row = f"| {b}{name}{b}{outlier_flag} "
    row += f"| {mean * 1000:.1f} ± {res['stddev'] * 1000:.1f} "
    row += f"| {res['min'] * 1000:.1f} – {res['max'] * 1000:.1f} "
    row += f"| {med * 1000:.1f} ± {md_dev * 1000:.1f} "
    mibs = (cfg.size / 1048576) / mean
    mibs_err = (cfg.size / 1048576) * res["stddev"] / mean**2
    row += f"| {mibs:.1f} ± {mibs_err:.1f} "

    if (base := _load_result(root / "hyperfine-baseline", name)) is not None:
        base_med = base["median"]
        diff = med - base_med
        delta = diff * 1000
        pct = diff / base_med * 100
        change = f"{base_med} -> {med} (median)"
        if is_significant(base["times"], times, pct):
            regressed = delta > 0
            sym = ":broken_heart:" if regressed else ":green_heart:"
            line = f"{name}: Performance has {'regressed' if regressed else 'improved'}. {change}"
            print(line)
            with (cfg.workspace / "results.txt").open("a", encoding="utf-8") as f:
                f.write(f"{line}\n")
            row += f"| {sym} **{delta:+.1f} ({pct:+.1f}%)** |\n"
        else:
            print(f"No significant change: {change}")
            row += f"| {delta:+.1f} ({pct:+.1f}%) |\n"
    elif unit.has_neqo:
        print("No cached baseline found.")
        row += "| :question: |\n"
    else:
        row += "| |\n"
    return row


class Unit(NamedTuple):
    """One client/server pair in one congestion control configuration."""

    client: str
    server: str
    cc: str
    pacing: bool | None

    @property
    def name(self) -> str:
        cc = f"-{self.cc}" if self.cc else ""
        pacing = "-nopacing" if self.pacing is False else ""
        return f"{self.client}-{self.server}{cc}{pacing}"

    @property
    def bold(self) -> bool:
        """Emphasize an implementation measured against itself."""
        return self.client == self.server

    @property
    def has_neqo(self) -> bool:
        """Whether neqo takes part, and so has a baseline to compare against."""
        return "neqo" in (self.client, self.server)


def units() -> list[Unit]:
    """Every measurement the comparison is made of; one matrix job runs each."""
    out = []
    for server, client in product(IMPLS, repeat=2):
        if client == server == "neqo":
            opts = [(cc, p) for cc in ("newreno", "cubic") for p in (True, False)]
        elif "neqo" in (client, server):
            opts = [("cubic", True)]
        elif client == server:
            opts = [("", None)]
        else:
            continue
        out += [Unit(client, server, cc, pacing) for cc, pacing in opts]
    return out


def recopy(cfg, cmds):
    """Replace each command's executable with a fresh copy of itself.

    Where the page cache happens to hold a binary's code shifts its speed by up to ~1.5%, and that
    placement holds for the file's lifetime, so give each part a placement of its own.
    """
    for cmd in cmds:
        exe = cfg.workspace / cmd.split()[0]
        copy = exe.with_name(f"{exe.name}.copy")
        shutil.copy2(exe, copy)
        copy.replace(exe)


def run_unit(cfg, tmp, unit):
    """Run one unit's comparison; `merge` turns its results into a table row."""

    def command(template, flags, disk=""):
        template = template.format(host=cfg.host, port=cfg.port, size=cfg.size, tmp=tmp)
        return mangle(template, unit.cc, unit.pacing, flags, disk)

    print(f"*** {unit.name}")
    ccfg, scfg = IMPLS[unit.client], IMPLS[unit.server]
    for cmd in (ccfg.client_cmd, scfg.server_cmd):
        src = cfg.workspace / cmd.split()[0]
        if src.exists() and not (dst := cfg.workspace / "binaries" / src.name).exists():
            shutil.copy2(src, dst)
            dst.chmod(0o755)

    # When neqo is the server, apply the client's interop flags to it.
    # When neqo is the client, apply the server's interop flags to it.
    cf = ccfg.interop_flag if unit.server == "neqo" else ""
    sf = scfg.interop_flag if unit.client == "neqo" else ""

    scmd = command(scfg.server_cmd, cf)
    ccmd = command(ccfg.client_cmd, sf)

    if not verify(cfg, tmp, unit.client, scmd, command(ccfg.client_cmd, sf, ccfg.disk_flag)):
        raise RuntimeError(f"Transfer failed: {unit.client} vs. {unit.server}")

    sides = [((scmd, ccmd), cfg.workspace / "hyperfine")]
    base = None
    if unit.has_neqo:
        base = tuple(c.replace("/neqo/", "/neqo-baseline/") for c in (scmd, ccmd))
        sides.append((base, cfg.workspace / "hyperfine-baseline"))
    # Alternate baseline and PR in quarters, ABBABAAB, so that drift over the unit cancels out.
    schedule = [(1, 0), (0, 1), (0, 1), (1, 0)] if base else [(0,)]
    runs = math.ceil(cfg.runs / len(schedule))
    for part, order in enumerate(schedule):
        for side in order:
            cmds, out_dir = sides[side]
            recopy(cfg, cmds)
            hyperfine(cfg, *cmds, unit.name, out_dir, runs, part)
    # After the timed runs, so recording cannot drift them apart.
    perf(cfg, scmd, ccmd, unit.name)
    if base:
        perf(cfg, *base, f"{unit.name}-base")


def merge(cfg, artifacts):
    """Assemble one table from the per-unit artifacts, off the measuring runners."""
    header = (
        f"Transfer of {cfg.size} bytes over loopback, min. {cfg.runs} runs. "
        "All unit-less numbers are in milliseconds.\n\n"
        "| Client vs. server | Mean±σ | Min–Max | Median±MAD | MiB/s±σ | ΔMedian |\n"
        "|:---|---:|---:|---:|---:|---:|\n"
    )
    (cfg.workspace / "results.txt").write_text("", encoding="utf-8")
    rows = []
    for unit in units():
        res = next(artifacts.glob(f"*/hyperfine/{unit.name}.*.json"), None)
        row = process(cfg, unit, res.parents[1]) if res else None
        if row:
            rows.append(row)
    # Sort rows as if unbolded, so the emphasized ones stay next to their own kind.
    rows.sort(key=lambda r: re.sub(r"^\| \*\*", "| ", r))
    (cfg.workspace / "comparison.md").write_text(header + "".join(rows), encoding="utf-8")


def main():
    """Parse arguments, then list the units, run one of them, or merge their results."""
    p = argparse.ArgumentParser(description="Compare QUIC implementations")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=4433)
    p.add_argument("--size", type=int, default=33554432)
    p.add_argument("--runs", type=int, default=100)
    p.add_argument("--workspace", type=Path, default=Path.cwd())
    p.add_argument("--perf-opt", default="record -F2999 --call-graph fp -g")
    p.add_argument("--server-cpu", type=int, default=0, help="CPU to pin the server to")
    p.add_argument("--client-cpu", type=int, default=1, help="CPU to pin the client to")
    p.add_argument("--list-units", action="store_true", help="Print the unit names as JSON")
    p.add_argument("--unit", help="Name of the unit to run, one of --list-units")
    p.add_argument("--merge", type=Path, help="Directory holding the per-unit artifacts")
    a = p.parse_args()

    if a.list_units:
        print(json.dumps([u.name for u in units()]))
        return 0

    cfg = Cfg(**{f.name: getattr(a, f.name) for f in fields(Cfg)})

    if a.merge:
        merge(cfg, a.merge)
        return 0

    unit = next((u for u in units() if u.name == a.unit), None)
    if unit is None:
        p.error(f"--unit must name a unit, not {a.unit!r}; see --list-units")

    for d in ("binaries", "hyperfine", "hyperfine-baseline"):
        (cfg.workspace / d).mkdir(exist_ok=True)

    tmp = setup(cfg)
    try:
        run_unit(cfg, tmp, unit)
    finally:
        kill_servers()
        kill_port(cfg.port)
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
