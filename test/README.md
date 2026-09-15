# Steps to run an upload test with neqo-client and neqo-server

1. Build the release version of neqo-client and neqo-server by running

   ```shell
   cargo build --release
   ```

1. Start neqo-server

   ```shell
   ./target/release/neqo-server
   ```

1. Start neqo-client and specify parameters to start the upload test

   ```shell
   ./target/release/neqo-client http://127.0.0.1:4433/ --test upload  --upload-size ${size_in_bytes}
   ```

## To enable log messages for analyzing upload performance

This can be done by setting the `RUST_LOG` environment variable to `neqo_transport=info`.
For example, the command below starts neqo-client and uploads 8MB of content to the server.

```shell
RUST_LOG=neqo_transport=info ./target/release/neqo-client http://127.0.0.1:4433/ --test upload --upload-size 8388608 &>upload.log
```

## To run the upload test with `upload_test.sh` script

### Overview

The `upload_test.sh` script automates testing network conditions for `neqo-client` and `neqo-server`. It runs the upload test under various network parameters like bandwidth, RTT (Round-Trip Time), and PLR (Packet Loss Rate).

### Configuration

- **Server Address and Port**: Defaults to `127.0.0.1` and `4433`.
- **Upload Size**: Set to 8MB by default.
- **Network Conditions**: Modify `network_conditions`, `network_bandwidths`, `network_rtts`, and `plrs` arrays for different conditions.
- **Runs**: Number of test iterations, default is `1`.

### Usage

1. **Start the Script**: Execute with `./upload_test.sh`.
2. **Root Password Prompt**: Enter the root password when prompted for executing network configuration commands.
3. **Automated Test Execution**: The script sets up network conditions and runs `neqo-client` and `neqo-server` tests.
4. **Cleanup**: At the end, it resets network conditions and stops the server.

## Visualize log file

Run `./mozlog-neqo-cwnd.py upload.log` to view the logs with matplotlib and python.

## Cargo.lock alignment tools

Two scripts help keep `Cargo.lock` aligned with Firefox/Gecko's lockfile.
Both must be run from the **workspace root** (not inside `test/`).
Dependencies are managed via `test/pyproject.toml` and resolved automatically by `uv`.

### Compare versions

```shell
uv run --project test compare-lockfile
```

Fetches Gecko's `Cargo.lock` and checks that ours is aligned with it. Hard
violations are duplicate versions Gecko doesn't itself carry, and shared
dependencies sitting on a version other than Gecko's. Everything else is
advisory: deps ahead of Gecko that the next vendor picks up, deps on a semver
range Gecko doesn't carry, and pins another crate's version requirement rules
out. Mismatches are labelled production-affecting or dev/build-only.

Exit status is `0` when every invariant holds, `1` when there are hard
violations, and `2` if the check could not run (no `Cargo.lock`, `cargo` or
network failure) — so a broken environment is distinguishable from a real
violation.

### Update versions

```shell
uv run --project test update-lockfile
```

Pins every dependency Gecko carries to Gecko's exact version, dev- and
build-dependencies included, staying as close to Gecko as cargo allows. Where a
requirement rules Gecko's version out, the version is left alone rather than
bumped to latest. Packages Gecko has no version of, and packages only neqo uses
within Gecko, are bumped to their newest compatible version.

Drift is only a hard violation for packages whose version can reach a Gecko build
of neqo — those reachable via normal or build edges from the crates Gecko vendors.
For the rest, matching Gecko is preferred but harmless to miss.

Both commands end with the same markdown block, `Why each version differs from
Gecko`, explaining per package why its version is what it is and why that is
safe. `update-lockfile` prefixes it with `Lockfile changes`, a before → after
list of what that run moved. Both are paste-ready for a commit message or PR
description. `Cargo.lock` itself cannot carry the rationale: cargo reserializes
the file on every write and drops any hand-added comments.

Both need a working `cargo` (they read the resolved dependency graph via `cargo
metadata --locked`). Setting `GITHUB_TOKEN` (or `GITHUB_API_TOKEN`) is optional
and only raises GitHub's rate limit for the one API call that lists Gecko's
`netwerk/` crates.

### Linting and type checking

```shell
uv run --project test --group dev ruff check test/
uv run --project test --group dev mypy --config-file test/pyproject.toml test/
```
