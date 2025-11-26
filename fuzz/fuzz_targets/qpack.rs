#![cfg_attr(all(fuzzing, not(windows)), no_main)]

#[cfg(all(fuzzing, not(windows)))]
use libfuzzer_sys::fuzz_target;

#[cfg(all(fuzzing, not(windows)))]
fuzz_target!(|data: &[u8]| {
    const U64_BYTES: usize = size_of::<u64>();
    const U16_BYTES: usize = size_of::<u16>();

    // Parse: stream_id (u64) | encoder_stream_len (u16) | encoder_stream | header_block
    let (stream_id, data) = if data.len() >= U64_BYTES {
        let (left, right) = data.split_at(U64_BYTES);
        (
            u64::from_le_bytes(left.try_into().unwrap_or_default()),
            right,
        )
    } else {
        (0, data)
    };

    let (encoder_stream_len, data) = if data.len() >= U16_BYTES {
        let (left, right) = data.split_at(U16_BYTES);
        (
            u16::from_le_bytes(left.try_into().unwrap_or_default()) as usize,
            right,
        )
    } else {
        (0, data)
    };

    // Split remaining data into encoder stream and header block.
    let (encoder_stream, header_block) = if encoder_stream_len <= data.len() {
        data.split_at(encoder_stream_len)
    } else {
        (data, &[][..])
    };

    let mut decoder =
        neqo_qpack::Decoder::new(neqo_http3::Http3Parameters::default().get_qpack_settings());

    // Process encoder stream data to populate the dynamic table.
    _ = decoder.receive_encoder_stream(encoder_stream);

    // Decode the header block.
    _ = decoder.decode_header_block(header_block, stream_id.into());
});

#[cfg(any(not(fuzzing), windows))]
fn main() {}
