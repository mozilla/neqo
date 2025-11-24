#![cfg_attr(all(fuzzing, not(windows)), no_main)]

#[cfg(all(fuzzing, not(windows)))]
use libfuzzer_sys::fuzz_target;

#[cfg(all(fuzzing, not(windows)))]
fuzz_target!(|data: &[u8]| {
    // Run the fuzzer
    _ = neqo_transport::tparams::TransportParameters::decode_pub(&mut neqo_common::Decoder::new(
        data,
    ));
});

#[cfg(any(not(fuzzing), windows))]
fn main() {}
