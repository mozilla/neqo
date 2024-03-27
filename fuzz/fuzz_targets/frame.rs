#![cfg_attr(not(windows), no_main)]

#[cfg(not(windows))]
use libfuzzer_sys::fuzz_target;

#[cfg(not(windows))]
fuzz_target!(|data: &[u8]| {
    use neqo_common::Decoder;
    use neqo_transport::frame::Frame;

    // Run the fuzzer
    let mut decoder = Decoder::new(data);
    let _ = Frame::decode(&mut decoder);
});

#[cfg(windows)]
fn main() {}
