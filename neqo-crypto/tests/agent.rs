// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::ffi::CStr;

use neqo_crypto::{
    agent::CertificateCompressor, generate_ech_keys, AuthenticationStatus, Client, Error,
    HandshakeState, Res, SecretAgentPreInfo, Server, ZeroRttCheckResult, ZeroRttChecker,
    TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_GRP_EC_SECP256R1, TLS_GRP_EC_X25519,
    TLS_VERSION_1_3,
};

mod handshake;
use test_fixture::{damage_ech_config, fixture_init, now};

use crate::handshake::{
    connect, connect_fail, forward_records, resumption_setup, PermissiveZeroRttChecker, Resumption,
    ZERO_RTT_TOKEN_DATA,
};

#[test]
fn make_client() {
    fixture_init();
    let _c = Client::new("server", true).expect("should create client");
}

#[test]
fn make_server() {
    fixture_init();
    let _s = Server::new(&["key"]).expect("should create server");
}

#[test]
fn basic() {
    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    println!("client {:p}", &client);
    let mut server = Server::new(&["key"]).expect("should create server");
    println!("server {:p}", &server);

    let bytes = client.handshake(now(), &[]).expect("send CH");
    assert!(!bytes.is_empty());
    assert_eq!(*client.state(), HandshakeState::InProgress);

    let bytes = server
        .handshake(now(), &bytes[..])
        .expect("read CH, send SH");
    assert!(!bytes.is_empty());
    assert_eq!(*server.state(), HandshakeState::InProgress);

    let bytes = client.handshake(now(), &bytes[..]).expect("send CF");
    assert!(bytes.is_empty());
    assert_eq!(*client.state(), HandshakeState::AuthenticationPending);

    client.authenticated(AuthenticationStatus::Ok);
    assert_eq!(*client.state(), HandshakeState::Authenticated(0));

    // Calling handshake() again indicates that we're happy with the cert.
    let bytes = client.handshake(now(), &[]).expect("send CF");
    assert!(!bytes.is_empty());
    assert!(client.state().is_connected());

    let client_info = client.info().expect("got info");
    assert_eq!(TLS_VERSION_1_3, client_info.version());
    assert_eq!(TLS_AES_128_GCM_SHA256, client_info.cipher_suite());

    let bytes = server.handshake(now(), &bytes[..]).expect("finish");
    assert!(bytes.is_empty());
    assert!(server.state().is_connected());

    let server_info = server.info().expect("got info");
    assert_eq!(TLS_VERSION_1_3, server_info.version());
    assert_eq!(TLS_AES_128_GCM_SHA256, server_info.cipher_suite());
}

fn check_client_preinfo(client_preinfo: &SecretAgentPreInfo) {
    assert_eq!(client_preinfo.version(), None);
    assert_eq!(client_preinfo.cipher_suite(), None);
    assert!(!client_preinfo.early_data());
    assert_eq!(client_preinfo.early_data_cipher(), None);
    assert_eq!(client_preinfo.max_early_data(), Ok(0));
    assert_eq!(client_preinfo.alpn(), None);
}

fn check_server_preinfo(server_preinfo: &SecretAgentPreInfo) {
    assert_eq!(server_preinfo.version(), Some(TLS_VERSION_1_3));
    assert_eq!(server_preinfo.cipher_suite(), Some(TLS_AES_128_GCM_SHA256));
    assert!(!server_preinfo.early_data());
    assert_eq!(server_preinfo.early_data_cipher(), None);
    assert_eq!(server_preinfo.max_early_data(), Ok(0));
    assert_eq!(server_preinfo.alpn(), None);
}

#[test]
fn raw() {
    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    println!("client {client:?}");
    let mut server = Server::new(&["key"]).expect("should create server");
    println!("server {server:?}");

    let client_records = client.handshake_raw(now(), None).expect("send CH");
    assert!(!client_records.is_empty());
    assert_eq!(*client.state(), HandshakeState::InProgress);

    check_client_preinfo(&client.preinfo().expect("get preinfo"));

    let server_records =
        forward_records(now(), &mut server, client_records).expect("read CH, send SH");
    assert!(!server_records.is_empty());
    assert_eq!(*server.state(), HandshakeState::InProgress);

    check_server_preinfo(&server.preinfo().expect("get preinfo"));

    let client_records = forward_records(now(), &mut client, server_records).expect("send CF");
    assert!(client_records.is_empty());
    assert_eq!(*client.state(), HandshakeState::AuthenticationPending);

    client.authenticated(AuthenticationStatus::Ok);
    assert_eq!(*client.state(), HandshakeState::Authenticated(0));

    // Calling handshake() again indicates that we're happy with the cert.
    let client_records = client.handshake_raw(now(), None).expect("send CF");
    assert!(!client_records.is_empty());
    assert!(client.state().is_connected());

    let server_records = forward_records(now(), &mut server, client_records).expect("finish");
    assert!(server_records.is_empty());
    assert!(server.state().is_connected());

    // The client should have one certificate for the server.
    let certs = client.peer_certificate().unwrap();
    assert_eq!(1, certs.into_iter().count());

    // The server shouldn't have a client certificate.
    assert!(server.peer_certificate().is_none());
}

#[test]
fn chacha_client() {
    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");
    client
        .set_ciphers(&[TLS_CHACHA20_POLY1305_SHA256])
        .expect("ciphers set");

    connect(&mut client, &mut server);

    assert_eq!(
        client.info().unwrap().cipher_suite(),
        TLS_CHACHA20_POLY1305_SHA256
    );
    assert_eq!(
        server.info().unwrap().cipher_suite(),
        TLS_CHACHA20_POLY1305_SHA256
    );
}

#[test]
fn server_prefers_first_client_share() {
    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");
    server
        .set_groups(&[TLS_GRP_EC_X25519, TLS_GRP_EC_SECP256R1])
        .expect("groups set");
    client
        .set_groups(&[TLS_GRP_EC_X25519, TLS_GRP_EC_SECP256R1])
        .expect("groups set");
    client
        .send_additional_key_shares(1)
        .expect("should set additional key share count");

    connect(&mut client, &mut server);

    assert_eq!(client.info().unwrap().key_exchange(), TLS_GRP_EC_X25519);
    assert_eq!(server.info().unwrap().key_exchange(), TLS_GRP_EC_X25519);
}

#[test]
fn server_prefers_second_client_share() {
    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");
    server
        .set_groups(&[TLS_GRP_EC_SECP256R1, TLS_GRP_EC_X25519])
        .expect("groups set");
    client
        .set_groups(&[TLS_GRP_EC_X25519, TLS_GRP_EC_SECP256R1])
        .expect("groups set");
    client
        .send_additional_key_shares(1)
        .expect("should set additional key share count");

    connect(&mut client, &mut server);

    assert_eq!(client.info().unwrap().key_exchange(), TLS_GRP_EC_SECP256R1);
    assert_eq!(server.info().unwrap().key_exchange(), TLS_GRP_EC_SECP256R1);
}

#[test]
fn p256_server() {
    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");
    server
        .set_groups(&[TLS_GRP_EC_SECP256R1])
        .expect("groups set");

    connect(&mut client, &mut server);

    assert_eq!(client.info().unwrap().key_exchange(), TLS_GRP_EC_SECP256R1);
    assert_eq!(server.info().unwrap().key_exchange(), TLS_GRP_EC_SECP256R1);
}

#[test]
fn p256_server_hrr() {
    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");
    server
        .set_groups(&[TLS_GRP_EC_SECP256R1])
        .expect("groups set");
    client
        .set_groups(&[TLS_GRP_EC_X25519, TLS_GRP_EC_SECP256R1])
        .expect("groups set");
    client
        .send_additional_key_shares(0)
        .expect("should set additional key share count");

    connect(&mut client, &mut server);

    assert_eq!(client.info().unwrap().key_exchange(), TLS_GRP_EC_SECP256R1);
    assert_eq!(server.info().unwrap().key_exchange(), TLS_GRP_EC_SECP256R1);
}

#[test]
fn alpn() {
    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    client.set_alpn(&["alpn"]).expect("should set ALPN");
    let mut server = Server::new(&["key"]).expect("should create server");
    server.set_alpn(&["alpn"]).expect("should set ALPN");

    connect(&mut client, &mut server);

    let expected = Some(String::from("alpn"));
    assert_eq!(expected.as_ref(), client.info().unwrap().alpn());
    assert_eq!(expected.as_ref(), server.info().unwrap().alpn());
}

#[test]
fn bad_alpn() {
    fixture_init();
    let mut client = Client::new("server.example", true).unwrap();
    client.set_alpn::<&[u8]>(&[]).expect_err("empty list");
    client.set_alpn(&[""]).expect_err("list with empty value");
    client
        .set_alpn(&[[0; 256]])
        .expect_err("list with too long value");
}

#[test]
fn alpn_multi() {
    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    client
        .set_alpn(&["dummy", "alpn"])
        .expect("should set ALPN");
    let mut server = Server::new(&["key"]).expect("should create server");
    server
        .set_alpn(&["alpn", "other"])
        .expect("should set ALPN");

    connect(&mut client, &mut server);

    let expected = Some(String::from("alpn"));
    assert_eq!(expected.as_ref(), client.info().unwrap().alpn());
    assert_eq!(expected.as_ref(), server.info().unwrap().alpn());
}

#[test]
fn alpn_server_pref() {
    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    client
        .set_alpn(&["dummy", "alpn"])
        .expect("should set ALPN");
    let mut server = Server::new(&["key"]).expect("should create server");
    server
        .set_alpn(&["alpn", "dummy"])
        .expect("should set ALPN");

    connect(&mut client, &mut server);

    let expected = Some(String::from("alpn"));
    assert_eq!(expected.as_ref(), client.info().unwrap().alpn());
    assert_eq!(expected.as_ref(), server.info().unwrap().alpn());
}

#[test]
fn alpn_no_protocol() {
    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    client.set_alpn(&["a"]).expect("should set ALPN");
    let mut server = Server::new(&["key"]).expect("should create server");
    server.set_alpn(&["b"]).expect("should set ALPN");

    connect_fail(&mut client, &mut server);

    // TODO(mt) check the error code
}

#[test]
fn alpn_client_only() {
    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    client.set_alpn(&["alpn"]).expect("should set ALPN");
    let mut server = Server::new(&["key"]).expect("should create server");

    connect(&mut client, &mut server);

    assert_eq!(None, client.info().unwrap().alpn());
    assert_eq!(None, server.info().unwrap().alpn());
}

#[test]
fn alpn_server_only() {
    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");
    server.set_alpn(&["alpn"]).expect("should set ALPN");

    connect(&mut client, &mut server);

    assert_eq!(None, client.info().unwrap().alpn());
    assert_eq!(None, server.info().unwrap().alpn());
}

#[test]
fn resume() {
    let (_, token) = resumption_setup(Resumption::WithoutZeroRtt);

    let mut client = Client::new("server.example", true).expect("should create second client");
    let mut server = Server::new(&["key"]).expect("should create second server");

    client
        .enable_resumption(token)
        .expect("should accept token");
    connect(&mut client, &mut server);

    assert!(client.info().unwrap().resumed());
    assert!(server.info().unwrap().resumed());
}

#[test]
fn zero_rtt() {
    let (anti_replay, token) = resumption_setup(Resumption::WithZeroRtt);

    // Finally, 0-RTT should succeed.
    let mut client = Client::new("server.example", true).expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");
    client
        .enable_resumption(token)
        .expect("should accept token");
    client.enable_0rtt().expect("should enable 0-RTT");
    server
        .enable_0rtt(
            anti_replay.as_ref().unwrap(),
            0xffff_ffff,
            Box::<PermissiveZeroRttChecker>::default(),
        )
        .expect("should enable 0-RTT");

    connect(&mut client, &mut server);
    assert!(client.info().unwrap().early_data_accepted());
    assert!(server.info().unwrap().early_data_accepted());
}

#[test]
fn zero_rtt_no_eoed() {
    let (anti_replay, token) = resumption_setup(Resumption::WithZeroRtt);

    // Finally, 0-RTT should succeed.
    let mut client = Client::new("server.example", true).expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");
    client
        .enable_resumption(token)
        .expect("should accept token");
    client.enable_0rtt().expect("should enable 0-RTT");
    client
        .disable_end_of_early_data()
        .expect("should disable EOED");
    server
        .enable_0rtt(
            anti_replay.as_ref().unwrap(),
            0xffff_ffff,
            Box::<PermissiveZeroRttChecker>::default(),
        )
        .expect("should enable 0-RTT");
    server
        .disable_end_of_early_data()
        .expect("should disable EOED");

    connect(&mut client, &mut server);
    assert!(client.info().unwrap().early_data_accepted());
    assert!(server.info().unwrap().early_data_accepted());
}

#[derive(Debug)]
struct RejectZeroRtt {}
impl ZeroRttChecker for RejectZeroRtt {
    fn check(&self, token: &[u8]) -> ZeroRttCheckResult {
        assert_eq!(ZERO_RTT_TOKEN_DATA, token);
        ZeroRttCheckResult::Reject
    }
}

#[test]
fn reject_zero_rtt() {
    let (anti_replay, token) = resumption_setup(Resumption::WithZeroRtt);

    // Finally, 0-RTT should succeed.
    let mut client = Client::new("server.example", true).expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");
    client
        .enable_resumption(token)
        .expect("should accept token");
    client.enable_0rtt().expect("should enable 0-RTT");
    server
        .enable_0rtt(
            anti_replay.as_ref().unwrap(),
            0xffff_ffff,
            Box::new(RejectZeroRtt {}),
        )
        .expect("should enable 0-RTT");

    connect(&mut client, &mut server);
    assert!(!client.info().unwrap().early_data_accepted());
    assert!(!server.info().unwrap().early_data_accepted());
}

#[test]
fn close() {
    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");
    connect(&mut client, &mut server);
    client.close();
    server.close();
}

#[test]
fn close_client_twice() {
    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");
    connect(&mut client, &mut server);
    client.close();
    client.close(); // Should be a noop.
}

#[test]
fn ech() {
    fixture_init();
    let mut server = Server::new(&["key"]).expect("should create server");
    let (sk, pk) = generate_ech_keys().expect("ECH keys");
    server
        .enable_ech(88, "public.example", &sk, &pk)
        .expect("should enable server ECH");

    let mut client = Client::new("server.example", true).expect("should create client");
    client
        .enable_ech(server.ech_config())
        .expect("should enable client ECH");

    connect(&mut client, &mut server);
    assert!(client.info().unwrap().ech_accepted());
    assert!(server.info().unwrap().ech_accepted());
    assert!(client.preinfo().unwrap().ech_accepted().unwrap());
    assert!(server.preinfo().unwrap().ech_accepted().unwrap());
}

#[test]
fn ech_retry() {
    const PUBLIC_NAME: &str = "public.example";
    const PRIVATE_NAME: &str = "private.example";
    const CONFIG_ID: u8 = 7;

    fixture_init();
    let mut server = Server::new(&["key"]).unwrap();
    let (sk, pk) = generate_ech_keys().unwrap();
    server.enable_ech(CONFIG_ID, PUBLIC_NAME, &sk, &pk).unwrap();

    let mut client = Client::new(PRIVATE_NAME, true).unwrap();
    client
        .enable_ech(damage_ech_config(server.ech_config()))
        .unwrap();

    // Long version of connect() so that we can check the state.
    let records = client.handshake_raw(now(), None).unwrap(); // ClientHello
    let records = forward_records(now(), &mut server, records).unwrap(); // ServerHello...
    let records = forward_records(now(), &mut client, records).unwrap(); // (empty)
    assert!(records.is_empty());

    // The client should now be expecting authentication.
    assert_eq!(
        *client.state(),
        HandshakeState::EchFallbackAuthenticationPending(String::from(PUBLIC_NAME))
    );
    client.authenticated(AuthenticationStatus::Ok);
    let Err(Error::EchRetry(updated_config)) = client.handshake_raw(now(), None) else {
        panic!(
            "Handshake should fail with EchRetry, state is instead {:?}",
            client.state()
        );
    };
    assert_eq!(
        client
            .preinfo()
            .unwrap()
            .ech_public_name()
            .unwrap()
            .unwrap(),
        PUBLIC_NAME
    );
    // We don't forward alerts, so we can't tell the server about them.
    // An ech_required alert should be set though.
    assert_eq!(client.alert(), Some(121));

    let mut server = Server::new(&["key"]).unwrap();
    server.enable_ech(CONFIG_ID, PUBLIC_NAME, &sk, &pk).unwrap();
    let mut client = Client::new(PRIVATE_NAME, true).unwrap();
    client.enable_ech(&updated_config).unwrap();

    connect(&mut client, &mut server);

    assert!(client.info().unwrap().ech_accepted());
    assert!(server.info().unwrap().ech_accepted());
    assert!(client.preinfo().unwrap().ech_accepted().unwrap());
    assert!(server.preinfo().unwrap().ech_accepted().unwrap());
}

#[test]
fn connection_succeeds_when_server_and_client_support_cert_compr_copy() {
    struct IncDecCompression {}

    // Implementation supports both encoder and decoder
    impl CertificateCompressor for IncDecCompression {
        const ID: u16 = 0x4;
        const NAME: &CStr = c"inc-dec";
        const ENABLE_ENCODING: bool = true;

        fn decode(input: &[u8], output: &mut [u8]) -> Res<()> {
            let len = std::cmp::min(input.len(), output.len());
            for i in 0..len {
                output[i] = input[i].wrapping_sub(1);
            }
            Ok(())
        }

        fn encode(input: &[u8], output: &mut [u8]) -> Res<usize> {
            let len = std::cmp::min(input.len(), output.len());
            for i in 0..len {
                output[i] = input[i].wrapping_add(1);
            }
            Ok(len)
        }
    }

    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");

    client
        .set_certificate_compression::<IncDecCompression>()
        .unwrap();
    server
        .set_certificate_compression::<IncDecCompression>()
        .unwrap();

    connect(&mut client, &mut server);

    assert!(client.state().is_connected());
    assert!(server.state().is_connected());
}

#[test]
fn connection_succeeds_when_server_and_client_default_encoding() {
    struct DefaultEncoding {}

    // Implementation supports both encoder and decoder
    impl CertificateCompressor for DefaultEncoding {
        const ID: u16 = 0x4;
        const NAME: &CStr = c"copy";
        const ENABLE_ENCODING: bool = true;

        fn decode(input: &[u8], output: &mut [u8]) -> Res<()> {
            let len = std::cmp::min(input.len(), output.len());
            output[..len].copy_from_slice(&input[..len]);
            Ok(())
        }
    }

    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");

    client
        .set_certificate_compression::<DefaultEncoding>()
        .unwrap();
    server
        .set_certificate_compression::<DefaultEncoding>()
        .unwrap();

    connect(&mut client, &mut server);

    assert!(client.state().is_connected());
    assert!(server.state().is_connected());
}

struct CopyCompressionNoEncoder {}

impl CertificateCompressor for CopyCompressionNoEncoder {
    const ID: u16 = 0x4;
    const NAME: &CStr = c"copy";

    fn decode(input: &[u8], output: &mut [u8]) -> Res<()> {
        let len = std::cmp::min(input.len(), output.len());
        output[..len].copy_from_slice(&input[..len]);
        Ok(())
    }
}

#[test]
fn connection_succeeds_when_server_and_client_support_cert_compr_copy_without_encoder() {
    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");

    client
        .set_certificate_compression::<CopyCompressionNoEncoder>()
        .unwrap();
    server
        .set_certificate_compression::<CopyCompressionNoEncoder>()
        .unwrap();

    connect(&mut client, &mut server);

    assert!(client.state().is_connected());
    assert!(server.state().is_connected());
}

#[test]
fn connection_succeeds_when_only_server_support_cert_compr() {
    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");

    server
        .set_certificate_compression::<CopyCompressionNoEncoder>()
        .unwrap();

    connect(&mut client, &mut server);

    assert!(client.state().is_connected());
    assert!(server.state().is_connected());
}

#[test]
fn connection_succeeds_when_only_client_support_cert_compr() {
    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");

    client
        .set_certificate_compression::<CopyCompressionNoEncoder>()
        .unwrap();

    connect(&mut client, &mut server);

    assert!(client.state().is_connected());
    assert!(server.state().is_connected());
}

#[test]
fn connection_fails_when_decoding_fails() {
    struct CopyCompressionDecoderReturnsErr {}

    impl CertificateCompressor for CopyCompressionDecoderReturnsErr {
        const ID: u16 = 0x4;
        const NAME: &CStr = c"copy";

        const ENABLE_ENCODING: bool = true;

        fn decode(input: &[u8], output: &mut [u8]) -> Res<()> {
            let len = std::cmp::min(input.len(), output.len());
            output[..len].copy_from_slice(&input[..len]);
            Err(Error::CertificateDecoding)
        }
    }

    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");

    server
        .set_certificate_compression::<CopyCompressionDecoderReturnsErr>()
        .unwrap();

    client
        .set_certificate_compression::<CopyCompressionDecoderReturnsErr>()
        .unwrap();

    connect_fail(&mut client, &mut server);
}

#[test]
fn connection_fails_when_encoding_fails() {
    struct CopyCompressionEncoderReturnsErr {}

    impl CertificateCompressor for CopyCompressionEncoderReturnsErr {
        const ID: u16 = 0x4;
        const NAME: &CStr = c"copy";

        const ENABLE_ENCODING: bool = true;

        fn encode(input: &[u8], output: &mut [u8]) -> Res<usize> {
            let len = std::cmp::min(input.len(), output.len());
            for i in 0..len {
                output[i] = input[i].wrapping_add(1);
            }
            Err(Error::CertificateEncoding)
        }

        fn decode(input: &[u8], output: &mut [u8]) -> Res<()> {
            let len = std::cmp::min(input.len(), output.len());
            output[..len].copy_from_slice(&input[..len]);
            Ok(())
        }
    }

    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");

    server
        .set_certificate_compression::<CopyCompressionEncoderReturnsErr>()
        .unwrap();

    client
        .set_certificate_compression::<CopyCompressionEncoderReturnsErr>()
        .unwrap();

    connect_fail(&mut client, &mut server);
}

#[test]
fn connection_fails_encoder_returned_too_long() {
    struct CompressionEncoderReturnsTooLong {}

    impl CertificateCompressor for CompressionEncoderReturnsTooLong {
        const ID: u16 = 0x4;
        const NAME: &CStr = c"copy";

        const ENABLE_ENCODING: bool = true;
        fn encode(input: &[u8], output: &mut [u8]) -> Res<usize> {
            let len = std::cmp::min(input.len(), output.len());
            for i in 0..len {
                output[i] = input[i].wrapping_sub(1);
            }
            Ok(len + 10)
        }

        fn decode(input: &[u8], output: &mut [u8]) -> Res<()> {
            let len = std::cmp::min(input.len(), output.len());
            output[..len].copy_from_slice(&input[..len]);
            Ok(())
        }
    }

    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");

    server
        .set_certificate_compression::<CompressionEncoderReturnsTooLong>()
        .unwrap();

    client
        .set_certificate_compression::<CompressionEncoderReturnsTooLong>()
        .unwrap();

    connect_fail(&mut client, &mut server);
}
