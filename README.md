# Neqo, an Implementation of QUIC in Rust

![neqo logo](https://github.com/mozilla/neqo/raw/main/neqo.png "neqo logo")

Neqo is the QUIC implementation used by Mozilla in Firefox and other products.
It is written in Rust and provides a library for QUIC transport, HTTP/3, and
QPACK. The TLS security backend is the Mozilla NSS library, which is also used
by Firefox.

Neqo is designed to be used in Firefox, but it can also be used
standalone. We include command line tools for testing and debugging, such as
`neqo-client` and `neqo-server`, which can be used to test HTTP/3 servers
and clients.

**Note: The neqo server functionality is experimental**, since
it is not in production use at Mozilla, and it is not as mature as the
client functionality. It is intended to be standards-compliant when
interoperating with a compliant client, but it may not implement all
optional protocol features, and it may not handle all edge cases.
It is also not optimized for performance or resource usage, and
while it implements many of the necessary features for a server,
it does not include configuration of a number of options that
is suited to a live deployment.
**Do not use the neqo server code in production.**

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

1. Clone [NSS][NSS] and [NSPR][NSPR] into the same directory and export an environment variable called `NSS_DIR` pointing to NSS.
   For example if you have a folder `$HOME/neqo-dependencies` and cloned NSS and NSPR into it you'd set `NSS_DIR=$HOME/neqo-dependencies/nss`.

2. If you did not already compile NSS separately, you need to have [Mercurial (hg)][HG] installed.
   NSS builds require [GYP][GYP] and [Ninja][NINJA] to be installed.

3. Run `cargo build` in your `neqo` checkout. The prior steps enable `cargo build` to use the existing NSS build or build it from the existing checkout if it hasn't been built yet.

4. Now that NSS has been built you need to set another environment variable to be able to actually do anything that depends on NSS.
   - For Linux:

     ```shell
     export LD_LIBRARY_PATH="$(find $NSS_DIR/.. -name libssl3.so -print | head -1 | xargs dirname | xargs realpath)"
     ```

   - For MacOS:

     ```shell
     export DYLD_LIBRARY_PATH="$(find $NSS_DIR/.. -name libssl3.dylib -print | head -1 | xargs dirname | xargs realpath)"
     ```

5. (optional) After having an NSS build you can set the `NSS_PREBUILT=1` environment variable to skip building NSS again on future `cargo build` invocations.

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
QLOGDIR=/tmp/qlog cargo bench --bench min_bandwidth --features bench
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
