#![cfg_attr(all(fuzzing, not(windows)), no_main)]

#[cfg(all(fuzzing, not(windows)))]
use libfuzzer_sys::fuzz_target;

#[cfg(all(fuzzing, not(windows)))]
fuzz_target!(|data: &[u8]| {
    use neqo_common::Decoder;
    use neqo_transport::frame::Frame;

    // Run the fuzzer
    let mut decoder = Decoder::new(data);
    let _ = Frame::decode(&mut decoder);
});

#[cfg(any(not(fuzzing), windows))]
fn main() {}
