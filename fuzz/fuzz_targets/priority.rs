#![cfg_attr(all(fuzzing, not(windows)), no_main)]

#[cfg(all(fuzzing, not(windows)))]
use libfuzzer_sys::fuzz_target;

#[cfg(all(fuzzing, not(windows)))]
fuzz_target!(|data: &[u8]| {
    use neqo_http3::Priority;

    // Fuzz the Priority::from_bytes() function which parses
    // Structured Field Values (RFC 8941) for HTTP Extensible Priorities (RFC 9218).
    // This is used to parse the Priority header field value and
    // PRIORITY_UPDATE frame content.
    _ = Priority::from_bytes(data);
});

#[cfg(any(not(fuzzing), windows))]
fn main() {}
