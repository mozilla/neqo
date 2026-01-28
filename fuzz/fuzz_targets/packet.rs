#![cfg_attr(all(fuzzing, not(windows)), no_main)]

#[cfg(all(fuzzing, not(windows)))]
use libfuzzer_sys::fuzz_target;

#[cfg(all(fuzzing, not(windows)))]
fuzz_target!(|data: &[u8]| {
    use std::sync::OnceLock;

    use neqo_transport::{RandomConnectionIdGenerator, packet};

    static DECODER: OnceLock<RandomConnectionIdGenerator> = OnceLock::new();
    let decoder = DECODER.get_or_init(|| RandomConnectionIdGenerator::new(20));
    neqo_crypto::init().unwrap();

    // Run the fuzzer
    _ = packet::Public::decode(&mut data.to_vec(), decoder);
});

#[cfg(any(not(fuzzing), windows))]
fn main() {}
