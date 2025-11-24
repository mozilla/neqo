#![cfg_attr(all(fuzzing, not(windows)), no_main)]

#[cfg(all(fuzzing, not(windows)))]
use libfuzzer_sys::fuzz_target;

#[cfg(all(fuzzing, not(windows)))]
fuzz_target!(|data: &[u8]| {
    const U64_BYTES: usize = size_of::<u64>();

    // Use first 64 bits of data for stream ID.
    let (stream_id, data) = if data.len() >= U64_BYTES {
        let (left, right) = data.split_at(U64_BYTES);
        (
            u64::from_le_bytes(left.try_into().unwrap_or_default()),
            right,
        )
    } else {
        (0, data)
    };

    // Run the fuzzer
    let mut decoder =
        neqo_qpack::Decoder::new(neqo_http3::Http3Parameters::default().get_qpack_settings());
    _ = decoder.decode_header_block(data, stream_id.into());
});

#[cfg(any(not(fuzzing), windows))]
fn main() {}
