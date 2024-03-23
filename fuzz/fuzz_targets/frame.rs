#![no_main]

use libfuzzer_sys::fuzz_target;
use neqo_common::Decoder;
use neqo_transport::frame::Frame;

fuzz_target!(|data: &[u8]| {
    // Run the fuzzer
    let mut decoder = Decoder::new(data);
    let _ = Frame::decode(&mut decoder);
});
