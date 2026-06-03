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

Fetches Gecko's `Cargo.lock` and reports which packages match, which differ,
and whether mismatches are production-affecting or dev/build-only.

### Update versions

```shell
uv run --project test update-lockfile
```

Aligns shared dependencies with Gecko's pinned versions and updates packages
Gecko doesn't depend on (dev/build tools and neqo-exclusive packages) to their
latest available versions.

Set `GITHUB_TOKEN` (or `GITHUB_API_TOKEN`) in the environment to avoid GitHub
API rate limits when fetching Gecko metadata.

### Linting and type checking

```shell
uv run --project test --group dev ruff check test/
uv run --project test --group dev mypy --config-file test/pyproject.toml test/
```
