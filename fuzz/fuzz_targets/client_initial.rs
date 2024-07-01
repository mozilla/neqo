#![cfg_attr(all(fuzzing, not(windows)), no_main)]

#[cfg(all(fuzzing, not(windows)))]
use libfuzzer_sys::fuzz_target;

#[cfg(all(fuzzing, not(windows)))]
fuzz_target!(|data: &[u8]| {
    use neqo_common::{Datagram, Encoder, Role};
    use neqo_transport::Version;
    use test_fixture::{
        default_client, default_server,
        header_protection::{
            apply_header_protection, decode_initial_header, initial_aead_and_hp,
            remove_header_protection,
        },
        now,
    };

    let mut client = default_client();
    let ci = client.process(None, now()).dgram().expect("a datagram");
    let Some((header, d_cid, s_cid, payload)) = decode_initial_header(&ci, Role::Client) else {
        return;
    };
    let (aead, hp) = initial_aead_and_hp(d_cid, Role::Client);
    let (_, pn) = remove_header_protection(&hp, header, payload);

    let mut payload_enc = Encoder::with_capacity(MIN_INITIAL_PACKET_SIZE);
    payload_enc.encode(data); // Add fuzzed data.

    // Make a new header with a 1 byte packet number length.
    let mut header_enc = Encoder::new();
    header_enc
        .encode_byte(0xc0) // Initial with 1 byte packet number.
        .encode_uint(4, Version::default().wire_version())
        .encode_vec(1, d_cid)
        .encode_vec(1, s_cid)
        .encode_vvec(&[])
        .encode_varint(u64::try_from(payload_enc.len() + aead.expansion() + 1).unwrap())
        .encode_byte(u8::try_from(pn).unwrap());

    let mut ciphertext = header_enc.as_ref().to_vec();
    ciphertext.resize(header_enc.len() + payload_enc.len() + aead.expansion(), 0);
    let v = aead
        .encrypt(
            pn,
            header_enc.as_ref(),
            payload_enc.as_ref(),
            &mut ciphertext[header_enc.len()..],
        )
        .unwrap();
    assert_eq!(header_enc.len() + v.len(), ciphertext.len());
    // Pad with zero to get up to MIN_INITIAL_PACKET_SIZE.
    ciphertext.resize(MIN_INITIAL_PACKET_SIZE, 0);

    apply_header_protection(
        &hp,
        &mut ciphertext,
        (header_enc.len() - 1)..header_enc.len(),
    );
    let fuzzed_ci = Datagram::new(ci.source(), ci.destination(), ci.tos(), ciphertext);

    let mut server = default_server();
    let _response = server.process(Some(&fuzzed_ci), now());
});

#[cfg(any(not(fuzzing), windows))]
fn main() {}
