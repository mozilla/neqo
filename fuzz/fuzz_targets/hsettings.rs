#![cfg_attr(all(fuzzing, not(windows)), no_main)]

#[cfg(all(fuzzing, not(windows)))]
use libfuzzer_sys::fuzz_target;

#[cfg(all(fuzzing, not(windows)))]
fuzz_target!(|data: &[u8]| {
    use neqo_common::Decoder;
    use neqo_http3::HSettings;

    // Fuzz the HSettings::decode_frame_contents() function which parses
    // HTTP/3 SETTINGS frame contents (RFC 9114 Section 7.2.4).
    let mut dec = Decoder::from(data);
    let mut settings = HSettings::default();
    _ = settings.decode_frame_contents(&mut dec);
});

#[cfg(any(not(fuzzing), windows))]
fn main() {}
