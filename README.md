# Neqo, an Implementation of QUIC in Rust

![neqo logo](https://github.com/mozilla/neqo/raw/main/neqo.png "neqo logo")

To build Neqo:

```shell
cargo build
```

This will use a system-installed [NSS][NSS] library if it is new enough. (See "Build with Separate NSS/NSPR" below if NSS is not installed or it is deemed too old.)

To run test HTTP/3 programs (`neqo-client` and `neqo-server`):

```shell
./target/debug/neqo-server '[::]:12345'
./target/debug/neqo-client 'https://[::]:12345/'
```

## Build with separate NSS/NSPR

You can clone [NSS][NSS] and [NSPR][NSPR] into the same directory and export an
environment variable called `NSS_DIR` pointing to NSS.  This causes the build to
use the existing NSS checkout.  However, in order to run anything that depends
on NSS, you need to set an environment as follows:

### Linux

```shell
export LD_LIBRARY_PATH="$(find . -name libssl3.so -print | head -1 | xargs dirname | xargs realpath)"
```

### macOS

```shell
export DYLD_LIBRARY_PATH="$(find . -name libssl3.dylib -print | head -1 | xargs dirname | xargs realpath)"
```

Note: If you did not already compile NSS separately, you need to have
[Mercurial (hg)][HG], installed. NSS builds require [GYP][GYP] and
[Ninja][NINJA] to be installed.

## Debugging Neqo

### QUIC logging

Enable generation of [QLOG][QLOG] logs with:

```shell
target/debug/neqo-server '[::]:12345' --qlog-dir .
target/debug/neqo-client 'https://[::]:12345/' --qlog-dir .
```

You can of course specify a different directory for the QLOG files.
You can upload QLOG files to [qvis][QVIS] to visualize the flows.

To export QLOG files for [Neqo Simulator](./test-fixture/src/sim) runs, set the
environment variable `QLOGDIR`. For example:

```shell
QLOGDIR=/tmp/qlog cargo bench --profile=dev --bench min_bandwidth --features bench
```

### Using `SSLKEYLOGFILE` to decrypt Wireshark logs

You can export TLS keys by setting the `SSLKEYLOGFILE` environment variable
to a filename to instruct NSS to dump keys in the
[standard format](https://datatracker.ietf.org/doc/draft-ietf-tls-keylogfile/)
to enable decryption by [Wireshark](https://wiki.wireshark.org/TLS) and other tools.

### Using RUST_LOG effectively

As documented in the [env_logger documentation](https://docs.rs/env_logger/),
the `RUST_LOG` environment variable can be used to selectively enable log messages
from Rust code. This works for Neqo's command line tools, as well as for when Neqo is
incorporated into Gecko, although [Gecko needs to be built in debug mode](https://developer.mozilla.org/en-US/docs/Mozilla/Developer_guide/Build_Instructions/Configuring_Build_Options).

Some examples:

1. ```shell
   RUST_LOG=neqo_transport::dump ./mach run
   ```

   lists sent and received QUIC packets and their frames' contents only.

1. ```shell
   RUST_LOG=neqo_transport=debug,neqo_http3=trace,info ./mach run
   ```

   sets a `debug` log level for `transport`, `trace` level for `http3`, and `info` log
   level for all other Rust crates, both Neqo and others used by Gecko.

1. ```shell
   RUST_LOG=neqo=trace,error ./mach run
   ```

   sets `trace` level for all modules starting with `neqo`, and sets `error` as minimum log level for other unrelated Rust log messages.

### Trying in-development Neqo code in Gecko

In a checked-out copy of Gecko source, set `[patches.*]` values for the four
Neqo crates to local versions in the root `Cargo.toml`. For example, if Neqo
was checked out to `/home/alice/git/neqo`, add the following lines to the root
`Cargo.toml`.

```toml
[patch."https://github.com/mozilla/neqo"]
neqo-bin = { path = "/home/alice/git/neqo/neqo-bin" }
neqo-common = { path = "/home/alice/git/neqo/neqo-common" }
neqo-crypto = { path = "/home/alice/git/neqo/neqo-crypto" }
neqo-http3 = { path = "/home/alice/git/neqo/neqo-http3" }
neqo-qpack = { path = "/home/alice/git/neqo/neqo-qpack" }
neqo-transport = { path = "/home/alice/git/neqo/neqo-transport" }
neqo-udp = { path = "/home/alice/git/neqo/neqo-udp" }
```

Then run the following:

```shell
./mach vendor rust
```

Compile Gecko as usual with

```shell
./mach build
```

Note: Using newer Neqo code with Gecko may also require changes (likely to `neqo_glue`) if
something has changed.

### Connect with Firefox to local neqo-server

1. Run `neqo-server` via `cargo run --bin neqo-server -- 'localhost:12345' --db ./test-fixture/db`.
2. On Firefox, set `about:config` preferences:
  - `network.http.http3.alt-svc-mapping-for-testing` to `localhost;h3=":12345"`
  - `network.http.http3.disable_when_third_party_roots_found` to `false`
3. Optionally enable logging via `about:logging` or profiling via <https://profiler.firefox.com/>.
4. Navigate to <https://localhost:12345> and accept self-signed certificate.

[NSS]: https://hg.mozilla.org/projects/nss
[NSPR]: https://hg.mozilla.org/projects/nspr
[GYP]: https://github.com/nodejs/gyp-next
[HG]: https://www.mercurial-scm.org/
[NINJA]: https://ninja-build.org/
[QLOG]: https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-main-schema/
[QVIS]: https://qvis.quictools.info/
