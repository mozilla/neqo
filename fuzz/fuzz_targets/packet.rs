#![no_main]
use std::sync::Once;

use libfuzzer_sys::fuzz_target;
use neqo_transport::{packet::PublicPacket, RandomConnectionIdGenerator};

static INIT: Once = Once::new();
static mut DECODER: Option<neqo_transport::RandomConnectionIdGenerator> = None;

fuzz_target!(|data: &[u8]| {
    // Initialize things
    unsafe {
        INIT.call_once(|| {
            neqo_crypto::init();
            DECODER = Some(RandomConnectionIdGenerator::new(20));
        });
    }
    let decoder = unsafe { DECODER.as_ref().unwrap() };

    // Run the fuzzer
    let _ = PublicPacket::decode(data, decoder);
});
