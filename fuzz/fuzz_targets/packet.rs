#![cfg_attr(not(windows), no_main)]

#[cfg(not(windows))]
use libfuzzer_sys::fuzz_target;

#[cfg(not(windows))]
fuzz_target!(|data: &[u8]| {
    use neqo_transport::{packet::PublicPacket, RandomConnectionIdGenerator};

    lazy_static::lazy_static! {
        static ref DECODER: RandomConnectionIdGenerator = RandomConnectionIdGenerator::new(20);
    }

    neqo_crypto::init().unwrap();

    // Run the fuzzer
    let _ = PublicPacket::decode(data, &*DECODER);
});

#[cfg(windows)]
fn main() {}
