# Threat model

## What this project does and where untrusted input enters

Neqo is Mozilla's QUIC, HTTP/3 and QPACK implementation, used by Firefox for all HTTP/3 traffic. TLS is provided by
NSS through the `nss-rs` crate.

Every byte received from the network is untrusted, from the first packet on, including before the handshake has
authenticated the peer. The main parsers are:

- `neqo-transport`: packet headers and protection removal, frames, transport parameters, version negotiation, Retry,
  connection IDs, stream reassembly, flow control, ACK processing, and the connection and stream state machines.
- `neqo-http3`: HTTP/3 frames, SETTINGS, PRIORITY_UPDATE and priority header parsing, request/response framing, and
  WebTransport and CONNECT-UDP (datagram) handling.
- `neqo-qpack`: the encoder and decoder streams and header block decoding (Huffman, dynamic table).
- `neqo-udp`: receiving datagrams and their metadata (ECN, GRO segments).

The application calling neqo's API (Firefox) is trusted; the data the peer sends is not.

## Components that matter most / least

- Most important: client-side code paths in `neqo-transport`, `neqo-http3`, `neqo-qpack`, `neqo-udp` and
  `neqo-common`, because that is what Firefox ships.
- In scope but lower priority: server-side code paths. The server is experimental and not used in production.
- Out of scope: `neqo-bin` (the `neqo-client`/`neqo-server` test tools), `test-fixture`, `fuzz`, `qns`, benchmarks,
  and anything that needs the `bench`, `disable-encryption` or `build-fuzzing-corpus` features.
- NSS and third-party crates: in scope only where neqo or `nss-rs` misuses them, or where a bug in them is reachable
  through neqo with peer-controlled data. NSS is scanned separately.

## How to exercise it

- `cargo test --locked --workspace --exclude mtu` runs the test suite. The workspace and fuzz targets are prebuilt in
  this image.
- `fuzz/fuzz_targets/` holds libFuzzer targets for packets, frames, transport parameters, Initial/SNI parsing, HTTP/3
  frames and settings, priorities, QPACK and WebTransport frames, with seed corpora in `fuzz/corpus/`. They are built
  with ASan under `target/x86_64-unknown-linux-gnu/release/` (`cargo +nightly fuzz run <target>`). `LSAN_OPTIONS`
  points at `.oss-scanner/lsan.supp`, which suppresses a known one-time leak in NSS initialisation.
- `test-fixture` has helpers to build connected client/server pairs and a network simulator, which are the easiest way
  to write a reproducer as a Rust test.

## How you rate severity

### Critical or high

Memory corruption that a peer controls and that may lead to code execution is critical; so is a bypass of packet
protection or peer authentication.

- Memory safety issues reachable with peer-controlled data.
- Breaking a QUIC security property: key update or key discard errors, version-negotiation downgrade, ECH leaking the
  inner ClientHello, bypassing address validation (Retry, NEW_TOKEN), exceeding the anti-amplification limit,
  accepting a forged Retry or stateless reset, accepting 0-RTT data where RFC 9001 forbids it, or linking connection
  IDs across migration.
- A peer-reachable `debug_assert!` that guards memory safety or one of the properties above. Tests and fuzz targets
  enable debug assertions; Firefox release builds do not.

### Low

These should still be reported:

- Denial of service: panics, aborts, infinite loops, and peer-driven unbounded memory or CPU use. A panic without
  memory corruption is a denial of service, not a memory-safety issue (Mozilla rates these sec-low, see
  https://wiki.mozilla.org/Security_Severity_Ratings/Client).
- Peer-reachable `debug_assert!` failures without the consequences above.
- Issues that require the application to misuse neqo's API.
- Protocol violations without a security impact.

Issues only reachable in server code rate one level lower than the same issue in client code.

## Reports

- Include a reproducer, preferably a Rust test using `test-fixture` or a fuzz input, and the exact commit.
- Proposed patches should be minimal, follow the existing code style, be formatted with `cargo +nightly fmt` and pass
  `cargo clippy --locked --all-targets -- -D warnings`.
