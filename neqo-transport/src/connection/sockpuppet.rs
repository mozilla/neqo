// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_common::{qdebug, Encoder};
use neqo_crypto::random;

use super::AddressValidationInfo;
use crate::{
    crypto::{CryptoDxState, CryptoSpace, CryptoStreams},
    path::PathRef,
    recovery::LossRecovery,
    stats::FrameStats,
    tracking::PacketNumberSpace,
    Connection, Version,
};

/// See <https://tls13.xargs.org/#client-hello/annotated>
#[expect(clippy::too_many_lines)]
fn generate_ch() -> Vec<u8> {
    // Extensions
    let mut extensions = Encoder::new();

    let mut list_entry = Encoder::new();
    list_entry.encode_uint(1, 0x00_u8); // list entry is type 0x00 "DNS hostname"
    list_entry.encode_vec(2, b"github.com");

    let mut server_name_list = Encoder::new();
    server_name_list.encode_vec(2, list_entry.as_ref()); // first (and only) list entry

    let mut server_name_extension = Encoder::new();
    server_name_extension.encode_vec(2, server_name_list.as_ref()); // "server name" extension data

    extensions.encode_uint(2, 0x00_u8); // assigned value for extension "server name"
    extensions.encode_vec(2, server_name_extension.as_ref()); // server name extension data

    let mut ec_points_formats = Encoder::new();
    ec_points_formats.encode_vec(
        1,
        &[
            0x00, // assigned value for format "uncompressed"
            0x01, // assigned value for format "ansiX962_compressed_prime"
            0x02, // assigned value for format "ansiX962_compressed_char2"
        ],
    );

    extensions.encode_uint(2, 0x0b_u8); // assigned value for extension "ec point formats"
    extensions.encode_vec(2, ec_points_formats.as_ref()); // ec point formats extension data

    let mut supported_groups = Encoder::new();
    supported_groups.encode_vec(
        2,
        &[
            0x00, 0x1d, // assigned value for the curve "x25519"
            0x00, 0x17, // assigned value for the curve "secp256r1"
            0x00, 0x1e, // assigned value for the curve "x448"
            0x00, 0x19, // assigned value for the curve "secp521r1"
            0x00, 0x18, // assigned value for the curve "secp384r1"
            0x01, 0x00, // assigned value for the curve "ffdhe2048"
            0x01, 0x01, // assigned value for the curve "ffdhe3072"
            0x01, 0x02, // assigned value for the curve "ffdhe4096"
            0x01, 0x03, // assigned value for the curve "ffdhe6144"
            0x01, 0x04, // assigned value for the curve "ffdhe8192"
        ],
    );

    extensions.encode_uint(2, 0x0a_u8); // assigned value for extension "supported groups"
    extensions.encode_vec(2, supported_groups.as_ref()); // supported groups extension data

    extensions.encode_uint(2, 0x23_u8); // assigned value for extension "Session Ticket"
    extensions.encode_vec(2, &[]); // 0 bytes of "Session Ticket" extension data

    extensions.encode_uint(2, 0x17_u8); // assigned value for extension "Extended Master Secret"
    extensions.encode_vec(2, &[]); // 0 bytes of "Extended Master Secret" extension data

    let mut signature_algorithms = Encoder::new();
    signature_algorithms.encode_vec(
        2,
        &[
            0x04, 0x03, // assigned value for ECDSA-SECP256r1-SHA256
            0x05, 0x03, // assigned value for ECDSA-SECP384r1-SHA384
            0x06, 0x03, // assigned value for ECDSA-SECP521r1-SHA512
            0x08, 0x07, // assigned value for ED25519
            0x08, 0x08, // assigned value for ED448
            0x08, 0x09, // assigned value for RSA-PSS-PSS-SHA256
            0x08, 0x0a, // assigned value for RSA-PSS-PSS-SHA384
            0x08, 0x0b, // assigned value for RSA-PSS-PSS-SHA512
            0x08, 0x04, // assigned value for RSA-PSS-RSAE-SHA256
            0x08, 0x05, // assigned value for RSA-PSS-RSAE-SHA384
            0x08, 0x06, // assigned value for RSA-PSS-RSAE-SHA512
            0x04, 0x01, // assigned value for RSA-PKCS1-SHA256
            0x05, 0x01, // assigned value for RSA-PKCS1-SHA384
            0x06, 0x01, // assigned value for RSA-PKCS1-SHA512
        ],
    );

    extensions.encode_uint(2, 0x0d_u8); // assigned value for extension "Signature Algorithms"
    extensions.encode_vec(2, signature_algorithms.as_ref()); // "Signature Algorithms" extension data

    let mut supported_versions = Encoder::new();
    supported_versions.encode_vec(1, &[0x03, 0x04]); // assigned value for TLS 1.3

    extensions.encode_uint(2, 0x2b_u8); // assigned value for extension "Supported Versions"
    extensions.encode_vec(2, supported_versions.as_ref()); // "Supported Versions" extension data

    let mut psk_key_exchange_modes = Encoder::new();
    psk_key_exchange_modes.encode_vec(1, &[0x01]); // assigned value for "PSK with (EC)DHE key establishment"

    extensions.encode_uint(2, 0x2d_u8); // assigned value for extension "PSK Key Exchange Modes"
    extensions.encode_vec(2, psk_key_exchange_modes.as_ref()); // "PSK Key Exchange Modes" extension data

    let mut key_share = Encoder::new();
    key_share.encode_uint(2, 0x1d_u8); // assigned value for x25519 (key exchange via curve25519)
    key_share.encode_vec(2, &random::<32>()); // 32 bytes of public key

    let mut key_share_list = Encoder::new();
    key_share_list.encode_vec(2, key_share.as_ref()); // first (and only) key share entry

    extensions.encode_uint(2, 0x33_u8); // assigned value for extension "Key Share"
    extensions.encode_vec(2, key_share_list.as_ref()); // "Key Share" extension data

    // Handshake Header
    let mut handshake_data = Encoder::new();
    handshake_data.encode(&[0x03, 0x03]); // Client Version
    handshake_data.encode(&random::<32>()); // Client Random
    handshake_data.encode_vec(1, &random::<32>()); // 32 bytes of session ID
    handshake_data.encode_vec(
        2,
        &[
            // Cipher Suites
            0x13, 0x02, // assigned value for TLS_AES_256_GCM_SHA384
            0x13, 0x03, // assigned value for TLS_CHACHA20_POLY1305_SHA256
            0x13, 0x01, // assigned value for TLS_AES_128_GCM_SHA256
            0x00, 0xff, // assigned value for TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        ],
    );
    handshake_data.encode_vec(
        1,
        &[
            // Compression Methods
            0x00, // assigned value for "null" compression
        ],
    );
    handshake_data.encode_vec(2, extensions.as_ref()); // Extensions

    let mut handshake_message = Encoder::new();
    handshake_message.encode(&[0x01]); // handshake message type 0x01 (client hello)
    handshake_message.encode_vec(3, handshake_data.as_ref()); // client hello data

    // Record Header
    let mut record_header = Encoder::new();
    record_header.encode(&[
        0x16, // type is 0x16 (handshake record)
        0x03, 0x01, // protocol version is "3,1" (also known as TLS 1.0)
    ]);
    record_header.encode_vec(2, handshake_message.as_ref()); // handshake message

    record_header.as_ref().to_vec()
}

pub fn sock_puppet(
    tx: &mut CryptoDxState,
    path: &PathRef,
    address_validation: &AddressValidationInfo,
    version: Version,
    loss_recovery: &LossRecovery,
) -> Vec<u8> {
    let encoder = Encoder::new();
    let (_pt, mut builder) = Connection::build_packet_header(
        &path.borrow(),
        CryptoSpace::Initial,
        encoder,
        tx,
        address_validation,
        version,
        false,
    );
    let _pn = Connection::add_packet_number(
        &mut builder,
        tx,
        loss_recovery.largest_acknowledged_pn(PacketNumberSpace::Initial),
    );
    let sp = generate_ch();
    qdebug!("XXX SOCK PUPPET {:02x?}", sp);
    let mut cstreams = CryptoStreams::default();
    cstreams.send(PacketNumberSpace::Initial, &sp).unwrap();
    cstreams.write_frame(
        PacketNumberSpace::Initial,
        false,
        &mut builder,
        &mut Vec::new(),
        &mut FrameStats::default(),
    );
    builder.build(tx).unwrap().into()
}
