#![cfg_attr(not(windows), no_main)]

#[cfg(not(windows))]
use libfuzzer_sys::fuzz_target;

#[cfg(not(windows))]
fuzz_target!(|data: &[u8]| {
    use std::sync::OnceLock;

    use neqo_transport::{packet::PublicPacket, RandomConnectionIdGenerator};

    static DECODER: OnceLock<RandomConnectionIdGenerator> = OnceLock::new();
    let decoder = DECODER.get_or_init(|| RandomConnectionIdGenerator::new(20));
    neqo_crypto::init().unwrap();

    // Run the fuzzer
    let _ = PublicPacket::decode(data, decoder);
});

#[cfg(windows)]
fn main() {}
