#!/usr/bin/env python3
"""Compare QUIC implementations using hyperfine and perf."""

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from statistics import mean as avg, variance

# fmt: off
# (client_cmd, server_cmd, disk_flag, interop_flag)
IMPLS = {
    "neqo": (
        "binaries/neqo/neqo-client _cc _pacing _disk _flags -Q 1 https://{host}:{port}/{size}",
        "binaries/neqo/neqo-server _cc _pacing _flags -Q 1 {host}:{port}",
        "--output-dir .", "",
    ),
    "msquic": (
        "msquic/build/bin/Release/quicinterop -test:D -custom:{host} -port:{port} -urls:https://{host}:{port}/{size}",
        "msquic/build/bin/Release/quicinteropserver -root:{tmp} -listen:{host} -port:{port} -file:{tmp}/cert -key:{tmp}/key -noexit",
        "", "-a hq-interop",
    ),
    "google": (
        "google-quiche/bazel-bin/quiche/quic_client --disable_certificate_verification https://{host}:{port}/{size}",
        "google-quiche/bazel-bin/quiche/quic_server --generate_dynamic_responses --port {port} --certificate_file {tmp}/cert --key_file {tmp}/key",
        "", "",
    ),
    "quiche": (
        "quiche/target/release/quiche-client _disk --no-verify https://{host}:{port}/{size}",
        "quiche/target/release/quiche-server --root {tmp} --listen {host}:{port} --cert {tmp}/cert --key {tmp}/key",
        "--dump-responses .", "",
    ),
    "s2n": (
        "s2n-quic/target/release/s2n-quic-qns interop client --tls rustls --disable-cert-verification _disk --local-ip {host} https://{host}:{port}/{size}",
        "s2n-quic/target/release/s2n-quic-qns interop server --www-dir {tmp} --certificate {tmp}/cert --private-key {tmp}/key --ip {host} --port {port}",
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
    mtu: int


def is_significant(s1: list[float], s2: list[float]) -> bool:
    """Welch's t-test with normal approximation. Valid for n >= 30."""
    v1, v2, n1, n2 = variance(s1), variance(s2), len(s1), len(s2)
    se = math.sqrt(v1 / n1 + v2 / n2)
    return se > 0 and abs(avg(s1) - avg(s2)) / se > 1.96


def sh(cmd, **kw):
    """Run shell command."""
    kw.setdefault("check", False)
    return subprocess.run(cmd, shell=True, **kw)


def mangle(cmd, cc, pacing, flags, disk):
    """Replace placeholders, return (command, filename_extension)."""
    ext = f"-{cc}" if cc else ""
    if not pacing:
        ext += "-nopacing"
    cmd = (
        cmd.replace("_cc", f"--cc {cc}" if cc else "")
        .replace("_pacing", "" if pacing else "--no-pacing")
        .replace("_flags", flags)
        .replace("_disk", disk)
    )
    return re.sub(r"\s+", " ", cmd).strip(), ext


def setup(cfg):
    """Create temp dir with cert/key and test files, set MTU."""
    tmp = Path(tempfile.mkdtemp())
    (tmp / "out").mkdir()
    sh(
        f'openssl req -nodes -new -x509 -keyout "{tmp}/key" -out "{tmp}/cert" -subj "/CN=DOMAIN"',
        check=True,
        stderr=subprocess.DEVNULL,
    )
    for s in (cfg.size, cfg.size * 20):
        sh(f'truncate -s {s} "{tmp}/{s}"', check=True)
    sh(f"sudo ip link set dev lo mtu {cfg.mtu}")
    return tmp


def verify(cfg, tmp, client, server_cmd, client_cmd):
    """Run single transfer to verify it works."""
    tag = Path(server_cmd.split()[0]).name[:15]
    os.chdir(tmp / "out")
    proc = subprocess.Popen(
        f"{cfg.workspace}/{server_cmd}",
        shell=True,
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
        sh(f"pkill {tag}")
        proc.wait()
    os.chdir(cfg.workspace)
    out = tmp / "out" / str(cfg.size)
    return out.exists() and out.stat().st_size >= cfg.size


def hyperfine(cfg, scmd, ccmd, name, out_dir, md=False):
    """Run hyperfine benchmark."""
    tag = Path(scmd.split()[0]).name[:15]
    out_dir.mkdir(exist_ok=True)
    cmd = [
        "nice",
        "-n",
        "-20",
        "setarch",
        "--addr-no-randomize",
        "hyperfine",
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
        f"{cfg.workspace}/{scmd} & echo $! >> /cpusets/cpu2/tasks; sleep 0.2",
        "--conclude",
        f"pkill {tag}",
    ]
    if md:
        cmd += ["--export-markdown", str(out_dir / f"{name}.md")]
    cmd.append(f"echo $$ >> /cpusets/cpu3/tasks; {cfg.workspace}/{ccmd}")
    subprocess.run(cmd, check=True)


def perf(cfg, scmd, ccmd, name):
    """Run perf profiling with 20x larger file."""
    tag, ws = Path(scmd.split()[0]).name[:15], cfg.workspace
    ccmd = ccmd.replace(str(cfg.size), str(cfg.size * 20))
    base = f"nice -n -20 setarch --addr-no-randomize cset proc --set=cpu{{}} --exec perf -- {cfg.perf_opt}"
    proc = subprocess.Popen(
        f"{base.format(2)} -o {ws}/{name}.server.perf {ws}/{scmd}",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.2)
    sh(
        f"{base.format(3)} -o {ws}/{name}.client.perf {ws}/{ccmd}",
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    sh(f"pkill {tag}")
    proc.wait()


def process(cfg, name, bold):
    """Process benchmark results into a table row."""
    rj = cfg.workspace / "hyperfine" / f"{name}.json"
    rm = cfg.workspace / "hyperfine" / f"{name}.md"
    bj = cfg.workspace / "hyperfine-main" / f"{name}.json"
    if not rj.exists() or not rm.exists():
        return None

    res = json.loads(rj.read_text())["results"][0]
    mean, times = res["mean"], res["times"]
    md = rm.read_text()
    match = next(
        (
            x
            for x in md.splitlines()
            if x.startswith("|") and "Command" not in x and ":--" not in x
        ),
        None,
    )
    if not match:
        return None

    parts = match.replace("`", "").split("|")
    b = "**" if bold else ""
    row = f"| {b}{parts[1].strip()}{b} |{'|'.join(parts[2:5])}|"
    rng = float(m.group(1)) if (m := re.search(r"± *(\S+)", md)) else 1
    row += f" {(cfg.size/1048576)/mean:.1f} ± {(cfg.size/1048576)/rng:.1f} "

    if bj.exists():
        base = json.loads(bj.read_text())["results"][0]
        delta = (mean - base["mean"]) * 1000
        pct = (mean - base["mean"]) / base["mean"] * 100
        if is_significant(base["times"], times):
            sym = ":broken_heart:" if delta > 0 else ":green_heart:"
            print(
                f"Performance {'regressed' if delta > 0 else 'improved'}: {base['mean']} -> {mean}"
            )
            row += f"| {sym} **{delta:.1f}** | **{pct:.1f}%** |\n"
        else:
            print(f"No significant change: {base['mean']} -> {mean}")
            row += f"|  {delta:.1f} | {pct:.1f}% |\n"
    elif "neqo" in name:
        print("No cached baseline from main found.")
        row += "| :question: | :question: |\n"
    else:
        row += "| | |\n"
    return row


def run(cfg, tmp):
    """Run all comparisons."""
    steps = []
    for server, (_, scmd_t, _, sflags) in IMPLS.items():
        for client, (ccmd_t, _, disk, cflags) in IMPLS.items():
            if client != server and client != "neqo" and server != "neqo":
                print(f"Skipping {client} vs. {server}")
                continue
            print(f"*** {client} vs. {server}")

            for impl in (client, server):
                src = cfg.workspace / IMPLS[impl][0 if impl == client else 1].split()[0]
                if (
                    src.exists()
                    and not (dst := cfg.workspace / "binaries" / src.name).exists()
                ):
                    shutil.copy2(src, dst)
                    dst.chmod(0o755)

            if client == "neqo" and server == "neqo":
                opts = [
                    ("reno", True),
                    ("reno", False),
                    ("cubic", True),
                    ("cubic", False),
                ]
            elif client == "neqo" or server == "neqo":
                opts = [("cubic", True)]
            else:
                opts = [("", False)]

            for cc, pacing in opts:
                cf, sf = (sflags if client != "neqo" else ""), (
                    cflags if server != "neqo" else ""
                )

                def fmt(t):
                    return t.format(
                        host=cfg.host, port=cfg.port, size=cfg.size, tmp=tmp
                    )

                scmd, ext = mangle(fmt(scmd_t), cc, pacing, cf, "")
                ccmd_d, _ = mangle(fmt(ccmd_t), cc, pacing, sf, disk)
                ccmd, _ = mangle(fmt(ccmd_t), cc, pacing, sf, "")
                name = f"{client}-{server}{ext}"

                print(f"  Verify: {name}")
                if not verify(cfg, tmp, client, scmd, ccmd_d):
                    raise RuntimeError(f"Transfer failed: {client} vs. {server}")

                if client == "neqo" or server == "neqo":
                    print(f"  Hyperfine (main): {name}")
                    hyperfine(
                        cfg,
                        scmd.replace("neqo/", "neqo-main/"),
                        ccmd.replace("neqo/", "neqo-main/"),
                        name,
                        cfg.workspace / "hyperfine-main",
                    )

                print(f"  Hyperfine (PR): {name}")
                hyperfine(cfg, scmd, ccmd, name, cfg.workspace / "hyperfine", md=True)
                print(f"  Perf: {name}")
                perf(cfg, scmd, ccmd, name)

                bold = client == server or (
                    client == "neqo" and server == "neqo" and cc == "cubic" and pacing
                )
                if row := process(cfg, name, bold):
                    steps.append(row)
    return steps


def main():
    p = argparse.ArgumentParser(description="Compare QUIC implementations")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=4433)
    p.add_argument("--size", type=int, default=33554432)
    p.add_argument("--runs", type=int, default=100)
    p.add_argument("--workspace", type=Path, default=Path.cwd())
    p.add_argument("--perf-opt", default="record -F2999 --call-graph fp -g")
    p.add_argument("--mtu", type=int, default=1504)
    a = p.parse_args()
    cfg = Cfg(a.host, a.port, a.size, a.runs, a.workspace, a.perf_opt, a.mtu)

    for d in ("binaries", "hyperfine", "hyperfine-main"):
        (cfg.workspace / d).mkdir(exist_ok=True)
    (cfg.workspace / "results.txt").touch()

    tmp = setup(cfg)
    print(f"COMPARE_TMP={tmp}")
    try:
        steps = run(cfg, tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    (cfg.workspace / "steps.md").write_text("".join(steps))
    header = (
        f"Transfer of {cfg.size} bytes over loopback, {cfg.mtu}-byte MTU, min. {cfg.runs} runs. "
        "All unit-less numbers are in milliseconds.\n\n"
        "| Client vs. server (params) | Mean ± σ | Min | Max | MiB/s ± σ | Δ `main` | Δ `main` |\n"
        "|:---|---:|---:|---:|---:|---:|---:|\n"
    )
    sorted_steps = sorted(steps, key=lambda r: re.sub(r"^\| \*\*", "| ", r))
    (cfg.workspace / "comparison.md").write_text(header + "".join(sorted_steps))


if __name__ == "__main__":
    raise SystemExit(main())
