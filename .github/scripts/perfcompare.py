#!/usr/bin/env python3
"""Compare QUIC implementations using hyperfine and perf."""

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from statistics import NormalDist, median
from typing import NamedTuple

from scipy.stats import mannwhitneyu


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
    server_set: str = "bench/server"
    client_set: str = "bench/client"


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
    if not s1 or not s2 or abs(pct) < NOISE_FLOOR_PCT:
        return False
    return bool(mannwhitneyu(s1, s2, alternative="two-sided").pvalue < 0.05)


def mad(values: list[float], center: float) -> float:
    """Median absolute deviation, scaled to be comparable to a stddev."""
    return median(abs(v - center) for v in values) / NormalDist().inv_cdf(0.75)


def sh(cmd, **kw):
    """Run shell command."""
    kw.setdefault("check", False)
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    return subprocess.run(cmd, **kw)


def mangle(cmd, cc, pacing, flags, disk):
    """Replace placeholders, return (command, filename_extension)."""
    ext = f"-{cc}" if cc else ""
    if pacing is False:
        ext += "-nopacing"
    cmd = (
        cmd.replace("_cc", f"--cc {cc}" if cc else "")
        .replace("_pacing", "" if pacing else "--no-pacing")
        .replace("_flags", flags)
        .replace("_disk", disk)
    )
    return re.sub(r"\s+", " ", cmd).strip(), ext


def kill_port(port: int) -> None:
    """Kill any processes (including root-owned) listening on the given UDP/TCP port."""
    for proto in ("udp", "tcp"):
        subprocess.run(
            ["sudo", "fuser", "-k", f"{port}/{proto}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def kill_servers() -> None:
    """Kill any lingering server processes from any known implementation."""
    for impl_config in IMPLS.values():
        tag = _tag(impl_config.server_cmd)
        subprocess.run(
            ["sudo", "pkill", "-9", tag],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def setup(cfg):
    """Create temp dir with cert/key and test files, set MTU."""
    kill_servers()
    kill_port(cfg.port)
    tmp = Path(tempfile.mkdtemp())
    (tmp / "out").mkdir()
    sh(
        [
            "openssl",
            "req",
            "-nodes",
            "-new",
            "-x509",
            "-keyout",
            str(tmp / "key"),
            "-out",
            str(tmp / "cert"),
            "-subj",
            "/CN=DOMAIN",
        ],
        check=True,
        stderr=subprocess.DEVNULL,
    )
    # The warm-up size, which the file-serving implementations need to exist.
    for s in (cfg.size, cfg.size * 20, cfg.size // 32):
        sh(["truncate", "-s", str(s), str(tmp / str(s))], check=True)
    return tmp


def verify(cfg, tmp, client, server_cmd, client_cmd):
    """Run single transfer to verify it works."""
    tag = _tag(server_cmd)
    os.chdir(tmp / "out")
    proc = subprocess.Popen(
        shlex.split(f"{cfg.workspace}/{server_cmd}"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.2)
    try:
        out = tmp / "out" / str(cfg.size)
        if client == "google":
            with open(out, "w", encoding="utf-8") as f:
                sh(f"{cfg.workspace}/{client_cmd}", stdout=f, stderr=subprocess.DEVNULL)
        else:
            sh(
                f"{cfg.workspace}/{client_cmd}",
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    finally:
        sh(["sudo", "pkill", tag])
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            sh(["sudo", "pkill", "-9", tag])
            proc.wait(timeout=5)
    os.chdir(cfg.workspace)
    out = tmp / "out" / str(cfg.size)
    return out.exists() and out.stat().st_size >= cfg.size


def _sudo_nice_env() -> list[str]:
    """Prefix for elevated-priority subprocesses: sudo resets env, so restore
    the vars that neqo binaries need to find NSS libraries and certificates."""
    env_vars = {k: os.environ[k] for k in ("LD_LIBRARY_PATH", "TEST_FIXTURE_DB") if k in os.environ}
    env_args = [f"{k}={v}" for k, v in env_vars.items()]
    return ["sudo", "nice", "-n", "-20"] + (["env"] + env_args if env_args else [])


def _read_proc(path: str) -> str:
    """Contents of a `/proc` file, empty if absent, e.g. IPv6 off. Says so, as empty
    counters otherwise read as "nothing moved"."""
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as e:
        print(f"note: {path} unreadable ({e}), its counters will be missing")
        return ""


def _udp_counters() -> dict[str, int]:
    """UDP counters keyed by name, both families, as `--host` picks one."""
    counters: dict[str, int] = {}
    # IPv4 spells these as a `Udp:` line naming the fields, then a `Udp:` line of values.
    udp = [
        line.split()[1:]
        for line in _read_proc("/proc/net/snmp").splitlines()
        if line.startswith("Udp: ")
    ]
    for names, values in zip(udp[::2], udp[1::2], strict=False):
        counters.update(
            (f"Udp{n}", int(v)) for n, v in zip(names, values, strict=False)
        )
    # IPv6 spells them one `Udp6<name> <value>` per line.
    counters.update(
        (fields[0], int(fields[1]))
        for line in _read_proc("/proc/net/snmp6").splitlines()
        if len(fields := line.split()) == 2 and fields[0].startswith("Udp6")
    )
    return counters


def hyperfine(cfg, scmd, ccmd, name, out_dir, md=False):
    """Run hyperfine benchmark."""
    tag = shlex.quote(_tag(scmd))
    ws = shlex.quote(str(cfg.workspace))
    out_dir.mkdir(exist_ok=True)

    # Untimed, so start-up cost lands before the sample; `&&` fails `--prepare` (not a cold
    # run) on failure. Only stderr is logged: stdout can be a response body without a disk flag.
    warmup_log = shlex.quote(str(out_dir / f"{name}.warmup.log"))
    warmup = (
        f"{ws}/{ccmd.replace(f'/{cfg.size}', f'/{cfg.size // 32}')}"
        f" >/dev/null 2>{warmup_log} && "
    )
    # Both hooks run outside the timed region, so this is a before/after pair per run.
    rcvbuf = (
        "awk '/^Udp:/{if(!h){for(i=2;i<=NF;i++)if($i==\"RcvbufErrors\")c=i;h=1}else print $c}'"
        f" /proc/net/snmp >> {shlex.quote(str(out_dir / f'{name}.rcvbuferrors'))}"
    )
    cmd = [
        *_sudo_nice_env(),
        "setarch",
        "--addr-no-randomize",
        shutil.which("hyperfine") or "hyperfine",
        "--command-name",
        name,
        "--time-unit",
        "millisecond",
        "--export-json",
        str(out_dir / f"{name}.json"),
        "--output",
        "null",
        "--warmup",
        "5",
        "--min-runs",
        str(cfg.runs),
        "--prepare",
        (
            f"{ws}/{scmd} & echo $! >> /cpusets/{shlex.quote(cfg.server_set)}/tasks; sleep 0.2;"
            f" echo $$ >> /cpusets/{shlex.quote(cfg.client_set)}/tasks; {warmup} {rcvbuf}"
        ),
        "--conclude",
        f"pkill -9 {tag}; {rcvbuf}",
    ]
    if md:
        cmd += ["--export-markdown", str(out_dir / f"{name}.md")]
    cmd.append(f"echo $$ >> /cpusets/{shlex.quote(cfg.client_set)}/tasks; {ws}/{ccmd}")
    before = _udp_counters()
    result = sh(cmd, stderr=subprocess.PIPE, text=True)
    if result.returncode:
        print(result.stderr, end="")
        # hyperfine reports only *that* `--prepare` failed; the warm-up's log says why.
        log = out_dir / f"{name}.warmup.log"
        if log.exists():
            print(log.read_text(encoding="utf-8"), end="")
        result.check_returncode()
    # `*RcvbufErrors` tells whether loss was a receive-queue overrun. Only what moved.
    after = _udp_counters()
    deltas = {key: after.get(key, value) - value for key, value in before.items()}
    (out_dir / f"{name}.udp").write_text(
        "".join(f"{key} {delta}\n" for key, delta in deltas.items() if delta),
        encoding="utf-8",
    )
    # Surface hyperfine's own outlier warnings in the PR summary, not just the raw log.
    if result.stderr:
        print(result.stderr, end="")
        if "outlier" in result.stderr.lower():
            (out_dir / f"{name}.outliers").write_text(result.stderr, encoding="utf-8")


def perf(cfg, scmd, ccmd, name):
    """Run perf profiling with 20x larger file, also capturing per-connection stats."""
    tag, ws = _tag(scmd), cfg.workspace
    ccmd = ccmd.replace(str(cfg.size), str(cfg.size * 20))

    def with_stats(cmd: str, role: str) -> str:
        """Have neqo report PTOs and loss for this profiled transfer, not the timed hyperfine
        command, where serializing them would cost neqo I/O the other implementations don't pay."""
        if f"neqo-{role}" not in cmd:
            return cmd
        return f"{cmd} --stats-file {shlex.quote(f'{ws}/hyperfine/{name}.{role}.jsonl')}"

    scmd, ccmd = with_stats(scmd, "server"), with_stats(ccmd, "client")

    def perf_cmd(cset, out, exe):
        return (
            [*_sudo_nice_env(), "setarch", "--addr-no-randomize",
             "cset", "proc", f"--set={cset}", "--exec", "perf", "--"]
            + shlex.split(cfg.perf_opt)
            + ["-o", f"{ws}/{out}"]
            + shlex.split(f"{ws}/{exe}")
        )

    proc = subprocess.Popen(
        perf_cmd(cfg.server_set, f"{name}.server.perf", scmd),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.2)
    client_cmd = perf_cmd(cfg.client_set, f"{name}.client.perf", ccmd)
    sh(client_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sh(["sudo", "pkill", tag])
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        sh(["sudo", "pkill", "-9", tag])
        proc.wait(timeout=5)


def _load_result(path):
    """Load a hyperfine --export-json result, or None if the file is missing."""
    if not path.exists():
        return None
    res = json.loads(path.read_text(encoding="utf-8"))["results"][0]
    res.setdefault("median", median(res["times"]))
    return res


def process(cfg, name, bold):
    """Process benchmark results into a table row."""
    out_dir = cfg.workspace / "hyperfine"
    res = _load_result(out_dir / f"{name}.json")
    if res is None:
        return None

    mean, times, med = res["mean"], res["times"], res["median"]
    md_dev = mad(times, med)

    outlier_flag = ""
    if (out_dir / f"{name}.outliers").exists():
        outliers = [t for t in times if abs(t - med) > 3 * md_dev]
        if outliers:
            detail = (
                f"{len(outliers)} of {len(times)} runs exceeded 3×MAD from the median "
                f"({med * 1000:.0f}ms); slowest was {max(times) * 1000:.0f}ms"
            )
            outlier_flag = f' <span title="{detail}">⚠️</span>'
    b = "**" if bold else ""
    row = f"| {b}{name}{b}{outlier_flag} "
    row += f"| {mean * 1000:.1f} ± {res['stddev'] * 1000:.1f} "
    row += f"| {res['min'] * 1000:.1f} – {res['max'] * 1000:.1f} "
    row += f"| {med * 1000:.1f} ± {md_dev * 1000:.1f} "
    mibs = (cfg.size / 1048576) / mean
    mibs_err = (cfg.size / 1048576) * res["stddev"] / mean**2
    row += f"| {mibs:.1f} ± {mibs_err:.1f} "

    if (base := _load_result(cfg.workspace / "hyperfine-baseline" / f"{name}.json")) is not None:
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
    elif "neqo" in name:
        print("No cached baseline found.")
        row += "| :question: |\n"
    else:
        row += "| |\n"
    return row


def run(cfg, tmp):
    """Run all comparisons."""

    def fmt(t):
        return t.format(host=cfg.host, port=cfg.port, size=cfg.size, tmp=tmp)

    steps = []
    for server, scfg in IMPLS.items():
        for client, ccfg in IMPLS.items():
            if client != server and client != "neqo" and server != "neqo":
                print(f"Skipping {client} vs. {server}")
                continue
            print(f"*** {client} vs. {server}")

            for impl in (client, server):
                impl_cfg = IMPLS[impl]
                cmd = impl_cfg.client_cmd if impl == client else impl_cfg.server_cmd
                src = cfg.workspace / cmd.split()[0]
                if (
                    src.exists()
                    and not (dst := cfg.workspace / "binaries" / src.name).exists()
                ):
                    shutil.copy2(src, dst)
                    dst.chmod(0o755)

            if client == "neqo" and server == "neqo":
                opts = [
                    ("newreno", True),
                    ("newreno", False),
                    ("cubic", True),
                    ("cubic", False),
                ]
            elif client == "neqo" or server == "neqo":
                opts = [("cubic", True)]
            else:
                opts = [("", None)]

            for cc, pacing in opts:
                # When neqo is the server, apply the client's interop flags to it.
                # When neqo is the client, apply the server's interop flags to it.
                cf = ccfg.interop_flag if server == "neqo" else ""
                sf = scfg.interop_flag if client == "neqo" else ""

                scmd, ext = mangle(fmt(scfg.server_cmd), cc, pacing, cf, "")
                ccmd_d, _ = mangle(fmt(ccfg.client_cmd), cc, pacing, sf, ccfg.disk_flag)
                ccmd, _ = mangle(fmt(ccfg.client_cmd), cc, pacing, sf, "")
                name = f"{client}-{server}{ext}"

                if not verify(cfg, tmp, client, scmd, ccmd_d):
                    raise RuntimeError(f"Transfer failed: {client} vs. {server}")

                if client == "neqo" or server == "neqo":
                    hyperfine(
                        cfg,
                        scmd.replace("/neqo/", "/neqo-baseline/"),
                        ccmd.replace("/neqo/", "/neqo-baseline/"),
                        name,
                        cfg.workspace / "hyperfine-baseline",
                    )

                hyperfine(cfg, scmd, ccmd, name, cfg.workspace / "hyperfine", md=True)
                perf(cfg, scmd, ccmd, name)

                bold = client == server or (
                    client == "neqo" and server == "neqo" and cc == "cubic" and pacing
                )
                if row := process(cfg, name, bold):
                    steps.append(row)
    return steps


def main():
    """Parse arguments, run all comparisons, and write the results tables."""
    p = argparse.ArgumentParser(description="Compare QUIC implementations")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=4433)
    p.add_argument("--size", type=int, default=33554432)
    p.add_argument("--runs", type=int, default=100)
    p.add_argument("--workspace", type=Path, default=Path.cwd())
    p.add_argument("--perf-opt", default="record -F2999 --call-graph fp -g")
    p.add_argument("--server-set", default="bench/server", help="cset name for the server CPU")
    p.add_argument("--client-set", default="bench/client", help="cset name for the client CPU")
    a = p.parse_args()
    cfg = Cfg(
        host=a.host, port=a.port, size=a.size, runs=a.runs,
        workspace=a.workspace, perf_opt=a.perf_opt,
        server_set=a.server_set, client_set=a.client_set,
    )

    for d in ("binaries", "hyperfine", "hyperfine-baseline"):
        (cfg.workspace / d).mkdir(exist_ok=True)
    (cfg.workspace / "results.txt").touch()

    tmp = setup(cfg)
    try:
        steps = run(cfg, tmp)
    finally:
        kill_servers()
        kill_port(cfg.port)
        shutil.rmtree(tmp, ignore_errors=True)

    (cfg.workspace / "steps.md").write_text("".join(steps), encoding="utf-8")
    header = (
        f"Transfer of {cfg.size} bytes over loopback, min. {cfg.runs} runs. "
        "All unit-less numbers are in milliseconds.\n\n"
        "| Client vs. server | Mean±σ | Min–Max | Median±MAD | MiB/s±σ | ΔMedian |\n"
        "|:---|---:|---:|---:|---:|---:|\n"
    )
    sorted_steps = sorted(steps, key=lambda r: re.sub(r"^\| \*\*", "| ", r))
    (cfg.workspace / "comparison.md").write_text(
        header + "".join(sorted_steps), encoding="utf-8"
    )


if __name__ == "__main__":
    raise SystemExit(main())
