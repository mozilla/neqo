#![cfg_attr(all(fuzzing, not(windows)), no_main)]

#[cfg(all(fuzzing, not(windows)))]
use libfuzzer_sys::fuzz_target;

#[cfg(all(fuzzing, not(windows)))]
fuzz_target!(|data: &[u8]| {
    use std::sync::LazyLock;

    use neqo_transport::{RandomConnectionIdGenerator, packet};

    static DECODER: LazyLock<RandomConnectionIdGenerator> =
        LazyLock::new(|| RandomConnectionIdGenerator::new(20));
    nss::init().unwrap();

    // Run the fuzzer
    _ = packet::Public::decode(&mut data.to_vec(), &*DECODER);
});

#[cfg(any(not(fuzzing), windows))]
fn main() {}
