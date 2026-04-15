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
        "build-neqo/neqo/neqo-client _cc _pacing _disk _flags -Q 1 https://{host}:{port}/{size}",
        "build-neqo/neqo/neqo-server _cc _pacing _flags -Q 1 {host}:{port}",
        "--output-dir .", "",
    ),
    "msquic": ImplConfig(
        "build-msquic/quicinterop -test:D -custom:{host} -port:{port} -urls:https://{host}:{port}/{size}",
        "build-msquic/quicinteropserver -root:{tmp} -listen:{host} -port:{port} -file:{tmp}/cert -key:{tmp}/key -noexit",
        "", "-a hq-interop",
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
        sh(["pkill", "-u", str(os.getuid()), tag])
        proc.wait()
    os.chdir(cfg.workspace)
    out = tmp / "out" / str(cfg.size)
    return out.exists() and out.stat().st_size >= cfg.size


def _sudo_nice_env() -> list[str]:
    """Prefix for elevated-priority subprocesses: sudo resets env, so restore
    the vars that neqo binaries need to find NSS libraries and certificates."""
    env_vars = {k: os.environ[k] for k in ("LD_LIBRARY_PATH", "NSS_DB_PATH") if k in os.environ}
    env_args = [f"{k}={v}" for k, v in env_vars.items()]
    return ["sudo", "nice", "-n", "-20"] + (["env"] + env_args if env_args else [])


def hyperfine(cfg, scmd, ccmd, name, out_dir, md=False):
    """Run hyperfine benchmark."""
    tag = shlex.quote(_tag(scmd))
    ws = shlex.quote(str(cfg.workspace))
    out_dir.mkdir(exist_ok=True)
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
        f"{ws}/{scmd} & echo $! >> /cpusets/{shlex.quote(cfg.server_set)}/tasks; sleep 0.2",
        "--conclude",
        f"pkill {tag}",
    ]
    if md:
        cmd += ["--export-markdown", str(out_dir / f"{name}.md")]
    cmd.append(f"echo $$ >> /cpusets/{shlex.quote(cfg.client_set)}/tasks; {ws}/{ccmd}")
    sh(cmd, check=True)


def perf(cfg, scmd, ccmd, name):
    """Run perf profiling with 20x larger file."""
    tag, ws = _tag(scmd), cfg.workspace
    ccmd = ccmd.replace(str(cfg.size), str(cfg.size * 20))

    def perf_cmd(out, exe):
        # Run as the current user (not root): perf record works because the
        # action sets perf_event_paranoid=-1, and pkill can signal user processes.
        return (
            ["setarch", "--addr-no-randomize", "perf", "--"]
            + shlex.split(cfg.perf_opt)
            + ["-o", f"{ws}/{out}"]
            + shlex.split(f"{ws}/{exe}")
        )

    proc = subprocess.Popen(
        perf_cmd(f"{name}.server.perf", scmd),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.2)
    client_cmd = perf_cmd(f"{name}.client.perf", ccmd)
    sh(client_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sh(["pkill", tag])
    proc.wait()


def process(cfg, name, bold):
    """Process benchmark results into a table row."""
    rj = cfg.workspace / "hyperfine" / f"{name}.json"
    rm = cfg.workspace / "hyperfine" / f"{name}.md"
    bj = cfg.workspace / "hyperfine-baseline" / f"{name}.json"
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
    row += f" {(cfg.size / 1048576) / mean:.1f} ± {(cfg.size / 1048576) / rng:.1f} "

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
        print("No cached baseline found.")
        row += "| :question: | :question: |\n"
    else:
        row += "| | |\n"
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
                opts = [("", False)]

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
        shutil.rmtree(tmp, ignore_errors=True)

    (cfg.workspace / "steps.md").write_text("".join(steps), encoding="utf-8")
    header = (
        f"Transfer of {cfg.size} bytes over loopback, min. {cfg.runs} runs. "
        "All unit-less numbers are in milliseconds.\n\n"
        "| Client vs. server (params) | Mean ± σ | Min | Max | MiB/s ± σ | Δ `baseline` | Δ `baseline` |\n"
        "|:---|---:|---:|---:|---:|---:|---:|\n"
    )
    sorted_steps = sorted(steps, key=lambda r: re.sub(r"^\| \*\*", "| ", r))
    (cfg.workspace / "comparison.md").write_text(
        header + "".join(sorted_steps), encoding="utf-8"
    )


if __name__ == "__main__":
    raise SystemExit(main())
