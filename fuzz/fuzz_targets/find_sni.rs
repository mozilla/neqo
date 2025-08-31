#![cfg_attr(all(fuzzing, not(windows)), no_main)]

#[cfg(all(fuzzing, not(windows)))]
use libfuzzer_sys::fuzz_target;

#[cfg(all(fuzzing, not(windows)))]
fuzz_target!(|data: &[u8]| {
    // Run the fuzzer
    _ = neqo_transport::find_sni(data);
});

#[cfg(any(not(fuzzing), windows))]
fn main() {}
