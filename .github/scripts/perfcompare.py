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
from dataclasses import dataclass
from pathlib import Path
from statistics import mean as avg, variance
from typing import NamedTuple


class ImplConfig(NamedTuple):
    client_cmd: str
    server_cmd: str
    disk_flag: str
    interop_flag: str


# fmt: off
IMPLS = {
    "neqo": ImplConfig(
        "binaries/neqo/neqo-client _cc _pacing _disk _flags -Q 1 https://{host}:{port}/{size}",
        "binaries/neqo/neqo-server _cc _pacing _flags -Q 1 {host}:{port}",
        "--output-dir .", "",
    ),
    "msquic": ImplConfig(
        "msquic/build/bin/Release/quicinterop -test:D -custom:{host} -port:{port} -urls:https://{host}:{port}/{size}",
        "msquic/build/bin/Release/quicinteropserver -root:{tmp} -listen:{host} -port:{port} -file:{tmp}/cert -key:{tmp}/key -noexit",
        "", "-a hq-interop",
    ),
    "google": ImplConfig(
        "google-quiche/bazel-bin/quiche/quic_client --disable_certificate_verification https://{host}:{port}/{size}",
        "google-quiche/bazel-bin/quiche/quic_server --generate_dynamic_responses --port {port} --certificate_file {tmp}/cert --key_file {tmp}/key",
        "", "",
    ),
    "quiche": ImplConfig(
        "quiche/target/release/quiche-client _disk --no-verify https://{host}:{port}/{size}",
        "quiche/target/release/quiche-server --root {tmp} --listen {host}:{port} --cert {tmp}/cert --key {tmp}/key",
        "--dump-responses .", "",
    ),
    "s2n": ImplConfig(
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


def is_significant(s1: list[float], s2: list[float]) -> bool:
    """Welch's t-test with normal approximation. Valid for n >= 30."""
    v1, v2, n1, n2 = variance(s1), variance(s2), len(s1), len(s2)
    se = math.sqrt(v1 / n1 + v2 / n2)
    return se > 0 and abs(avg(s1) - avg(s2)) / se > 1.96


def sh(cmd, **kw):
    """Run shell command."""
    kw.setdefault("check", False)
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    return subprocess.run(cmd, **kw)


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
    for s in (cfg.size, cfg.size * 20):
        sh(["truncate", "-s", str(s), str(tmp / str(s))], check=True)
    return tmp


def verify(cfg, tmp, client, server_cmd, client_cmd):
    """Run single transfer to verify it works."""
    tag = Path(server_cmd.split()[0]).name[:15]
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
        sh(["pkill", tag])
        proc.wait()
    os.chdir(cfg.workspace)
    out = tmp / "out" / str(cfg.size)
    return out.exists() and out.stat().st_size >= cfg.size


def hyperfine(cfg, scmd, ccmd, name, out_dir, md=False):
    """Run hyperfine benchmark."""
    tag = shlex.quote(Path(scmd.split()[0]).name[:15])
    ws = shlex.quote(str(cfg.workspace))
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
        f"{ws}/{scmd} & echo $! >> /cpusets/cpu2/tasks; sleep 0.2",
        "--conclude",
        f"pkill {tag}",
    ]
    if md:
        cmd += ["--export-markdown", str(out_dir / f"{name}.md")]
    cmd.append(f"echo $$ >> /cpusets/cpu3/tasks; {ws}/{ccmd}")
    subprocess.run(cmd, check=True)


def perf(cfg, scmd, ccmd, name):
    """Run perf profiling with 20x larger file."""
    tag, ws = Path(scmd.split()[0]).name[:15], cfg.workspace
    ccmd = ccmd.replace(str(cfg.size), str(cfg.size * 20))
    base = [
        "nice",
        "-n",
        "-20",
        "setarch",
        "--addr-no-randomize",
        "cset",
        "proc",
        "--set=cpu{}",
        "--exec",
        "perf",
        "--",
    ] + shlex.split(cfg.perf_opt)
    server_cmd = (
        [arg.format(2) for arg in base]
        + ["-o", f"{ws}/{name}.server.perf"]
        + shlex.split(f"{ws}/{scmd}")
    )
    proc = subprocess.Popen(
        server_cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.2)
    client_cmd = (
        [arg.format(3) for arg in base]
        + ["-o", f"{ws}/{name}.client.perf"]
        + shlex.split(f"{ws}/{ccmd}")
    )
    sh(client_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sh(["pkill", tag])
    proc.wait()


def process(cfg, name, bold):
    """Process benchmark results into a table row."""
    rj = cfg.workspace / "hyperfine" / f"{name}.json"
    rm = cfg.workspace / "hyperfine" / f"{name}.md"
    bj = cfg.workspace / "hyperfine-main" / f"{name}.json"
    if not rj.exists() or not rm.exists():
        return None

    res = json.loads(rj.read_text(encoding="utf-8"))["results"][0]
    mean, times = res["mean"], res["times"]
    md = rm.read_text(encoding="utf-8")
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
    m = re.search(r"± *(\S+)", md)
    if not m:
        raise ValueError(f"Could not parse standard deviation from {rm}")
    rng = float(m.group(1))
    row += f" {(cfg.size/1048576)/mean:.1f} ± {(cfg.size/1048576)/rng:.1f} "

    if bj.exists():
        base = json.loads(bj.read_text(encoding="utf-8"))["results"][0]
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
                # When neqo is the server, apply the client's interop flags to it.
                # When neqo is the client, apply the server's interop flags to it.
                cf = ccfg.interop_flag if server == "neqo" else ""
                sf = scfg.interop_flag if client == "neqo" else ""

                def fmt(t):
                    return t.format(
                        host=cfg.host, port=cfg.port, size=cfg.size, tmp=tmp
                    )

                scmd, ext = mangle(fmt(scfg.server_cmd), cc, pacing, cf, "")
                ccmd_d, _ = mangle(fmt(ccfg.client_cmd), cc, pacing, sf, ccfg.disk_flag)
                ccmd, _ = mangle(fmt(ccfg.client_cmd), cc, pacing, sf, "")
                name = f"{client}-{server}{ext}"

                if not verify(cfg, tmp, client, scmd, ccmd_d):
                    raise RuntimeError(f"Transfer failed: {client} vs. {server}")

                if client == "neqo" or server == "neqo":
                    hyperfine(
                        cfg,
                        scmd.replace("neqo/", "neqo-main/"),
                        ccmd.replace("neqo/", "neqo-main/"),
                        name,
                        cfg.workspace / "hyperfine-main",
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
    p = argparse.ArgumentParser(description="Compare QUIC implementations")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=4433)
    p.add_argument("--size", type=int, default=33554432)
    p.add_argument("--runs", type=int, default=100)
    p.add_argument("--workspace", type=Path, default=Path.cwd())
    p.add_argument("--perf-opt", default="record -F2999 --call-graph fp -g")
    a = p.parse_args()
    cfg = Cfg(a.host, a.port, a.size, a.runs, a.workspace, a.perf_opt)

    for d in ("binaries", "hyperfine", "hyperfine-main"):
        (cfg.workspace / d).mkdir(exist_ok=True)
    (cfg.workspace / "results.txt").touch()

    tmp = setup(cfg)
    try:
        steps = run(cfg, tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    (cfg.workspace / "steps.md").write_text("".join(steps), encoding="utf-8")
    header = (
        f"Transfer of {cfg.size} bytes over loopback, min. {cfg.runs} runs. "
        "All unit-less numbers are in milliseconds.\n\n"
        "| Client vs. server (params) | Mean ± σ | Min | Max | MiB/s ± σ | Δ `main` | Δ `main` |\n"
        "|:---|---:|---:|---:|---:|---:|---:|\n"
    )
    sorted_steps = sorted(steps, key=lambda r: re.sub(r"^\| \*\*", "| ", r))
    (cfg.workspace / "comparison.md").write_text(
        header + "".join(sorted_steps), encoding="utf-8"
    )


if __name__ == "__main__":
    raise SystemExit(main())
