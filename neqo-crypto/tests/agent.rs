#![deny(warnings)]

use neqo_crypto::*;

use std::mem;

const NOW: u64 = 20;

#[test]
fn make_client() {
    init_db("./db");
    let _c = Client::new("server").expect("should create client");
}

#[test]
fn make_server() {
    init_db("./db");
    let _s = Server::new(&["key"]).expect("should create server");
}

#[test]
fn basic() {
    init_db("./db");
    let mut client = Client::new("server.example").expect("should create client");
    println!("client {:p}", &client);
    let mut server = Server::new(&["key"]).expect("should create server");
    println!("server {:p}", &server);

    let (state, bytes) = client.handshake(NOW, &[]).expect("send CH");
    assert!(bytes.len() > 0);
    assert_eq!(state, HandshakeState::InProgress);

    let (state, bytes) = server.handshake(NOW, &bytes[..]).expect("read CH, send SH");
    assert!(bytes.len() > 0);
    assert_eq!(state, HandshakeState::InProgress);

    let (state, bytes) = client.handshake(NOW, &bytes[..]).expect("send CF");
    assert_eq!(bytes.len(), 0);
    assert_eq!(state, HandshakeState::AuthenticationPending);

    client.authenticated();
    assert_eq!(*client.state(), HandshakeState::Authenticated);

    // Calling handshake() again indicates that we're happy with the cert.
    let (state, bytes) = client.handshake(NOW, &[]).expect("send CF");
    assert!(bytes.len() > 0);
    assert_eq!(state, HandshakeState::Complete);

    let client_info = client.info().expect("got info");
    assert_eq!(TLS_VERSION_1_3, client_info.version());
    assert_eq!(TLS_AES_128_GCM_SHA256, client_info.cipher_suite());

    let (state, bytes) = server.handshake(NOW, &bytes[..]).expect("finish");
    assert_eq!(bytes.len(), 0);
    assert_eq!(state, HandshakeState::Complete);

    let server_info = server.info().expect("got info");
    assert_eq!(TLS_VERSION_1_3, server_info.version());
    assert_eq!(TLS_AES_128_GCM_SHA256, server_info.cipher_suite());
}

fn forward_records(agent: &mut SecretAgent, records_in: RecordList) -> Res<RecordList> {
    let mut expected_state = match agent.state() {
        HandshakeState::New => HandshakeState::New,
        _ => HandshakeState::InProgress,
    };
    let mut records_out: RecordList = Default::default();
    for record in records_in.into_iter() {
        assert_eq!(records_out.len(), 0);
        assert_eq!(*agent.state(), expected_state);

        let (_state, rec_out) = agent.handshake_raw(NOW, Some(record))?;
        records_out = rec_out;
        expected_state = HandshakeState::InProgress;
    }
    Ok(records_out)
}

#[test]
fn raw() {
    init_db("./db");
    let mut client = Client::new("server.example").expect("should create client");
    println!("client {:?}", client);
    let mut server = Server::new(&["key"]).expect("should create server");
    println!("server {:?}", server);

    let (state, client_records) = client.handshake_raw(NOW, None).expect("send CH");
    assert!(client_records.len() > 0);
    assert_eq!(state, HandshakeState::InProgress);

    let client_preinfo = client.preinfo().expect("get preinfo");
    assert_eq!(client_preinfo.version(), None);
    assert_eq!(client_preinfo.cipher_suite(), None);
    assert_eq!(client_preinfo.early_data(), false);
    assert_eq!(client_preinfo.early_data_cipher(), None);
    assert_eq!(client_preinfo.max_early_data(), 0);

    let server_records = forward_records(&mut server, client_records).expect("read CH, send SH");
    assert!(server_records.len() > 0);
    assert_eq!(*server.state(), HandshakeState::InProgress);

    let server_preinfo = server.preinfo().expect("get preinfo");
    assert_eq!(server_preinfo.version(), Some(TLS_VERSION_1_3));
    assert_eq!(server_preinfo.cipher_suite(), Some(TLS_AES_128_GCM_SHA256));
    assert_eq!(server_preinfo.early_data(), false);
    assert_eq!(server_preinfo.early_data_cipher(), None);
    assert_eq!(server_preinfo.max_early_data(), 0);

    let client_records = forward_records(&mut client, server_records).expect("send CF");
    assert_eq!(client_records.len(), 0);
    assert_eq!(*client.state(), HandshakeState::AuthenticationPending);

    client.authenticated();
    assert_eq!(*client.state(), HandshakeState::Authenticated);

    // Calling handshake() again indicates that we're happy with the cert.
    let (state, client_records) = client.handshake_raw(NOW, None).expect("send CF");
    assert!(client_records.len() > 0);
    assert_eq!(state, HandshakeState::Complete);

    let server_records = forward_records(&mut server, client_records).expect("finish");
    assert_eq!(server_records.len(), 0);
    assert_eq!(*server.state(), HandshakeState::Complete);
}

fn handshake(client: &mut SecretAgent, server: &mut SecretAgent) {
    let mut a = client;
    let mut b = server;
    let (_, mut records) = a.handshake_raw(NOW, None).unwrap();
    let is_done = |agent: &mut SecretAgent| match *agent.state() {
        HandshakeState::Complete | HandshakeState::Failed(_) => true,
        _ => false,
    };
    while !is_done(a) || !is_done(b) {
        records = match forward_records(&mut b, records) {
            Ok(r) => r,
            _ => {
                // TODO(mt) take the alert generated by the failed handshake
                // and allow it to be sent to the peer.
                return;
            }
        };

        if *b.state() == HandshakeState::AuthenticationPending {
            b.authenticated();
            let (_, rec) = b.handshake_raw(NOW, None).unwrap();
            records = rec;
        }
        b = mem::replace(&mut a, b);
    }
}

fn connect(client: &mut SecretAgent, server: &mut SecretAgent) {
    handshake(client, server);
    assert_eq!(*client.state(), HandshakeState::Complete);
    assert_eq!(*server.state(), HandshakeState::Complete);
}

fn connect_fail(client: &mut SecretAgent, server: &mut SecretAgent) {
    handshake(client, server);
    assert_ne!(*client.state(), HandshakeState::Complete);
    assert_ne!(*server.state(), HandshakeState::Complete);
}

#[test]
fn chacha_client() {
    init_db("./db");
    let mut client = Client::new("server.example").expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");
    client
        .enable_ciphers(&[TLS_CHACHA20_POLY1305_SHA256])
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
fn p256_server() {
    init_db("./db");
    let mut client = Client::new("server.example").expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");
    server
        .set_groups(&[TLS_GRP_EC_SECP256R1])
        .expect("groups set");

    connect(&mut client, &mut server);

    assert_eq!(client.info().unwrap().key_exchange(), TLS_GRP_EC_SECP256R1);
    assert_eq!(server.info().unwrap().key_exchange(), TLS_GRP_EC_SECP256R1);
}

#[test]
fn alpn() {
    init_db("./db");
    let mut client = Client::new("server.example").expect("should create client");
    client.set_alpn(&["alpn"]).expect("should set ALPN");
    let mut server = Server::new(&["key"]).expect("should create server");
    server.set_alpn(&["alpn"]).expect("should set ALPN");

    connect(&mut client, &mut server);

    let expected = Some(String::from("alpn"));
    assert_eq!(expected.as_ref(), client.info().unwrap().alpn());
    assert_eq!(expected.as_ref(), server.info().unwrap().alpn());
}

#[test]
fn alpn_multi() {
    init_db("./db");
    let mut client = Client::new("server.example").expect("should create client");
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
    init_db("./db");
    let mut client = Client::new("server.example").expect("should create client");
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
    init_db("./db");
    let mut client = Client::new("server.example").expect("should create client");
    client.set_alpn(&["a"]).expect("should set ALPN");
    let mut server = Server::new(&["key"]).expect("should create server");
    server.set_alpn(&["b"]).expect("should set ALPN");

    connect_fail(&mut client, &mut server);

    // TODO(mt) check the error code
}

#[test]
fn alpn_client_only() {
    init_db("./db");
    let mut client = Client::new("server.example").expect("should create client");
    client.set_alpn(&["alpn"]).expect("should set ALPN");
    let mut server = Server::new(&["key"]).expect("should create server");

    connect(&mut client, &mut server);

    assert_eq!(None, client.info().unwrap().alpn());
    assert_eq!(None, server.info().unwrap().alpn());
}

#[test]
fn alpn_server_only() {
    init_db("./db");
    let mut client = Client::new("server.example").expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");
    server.set_alpn(&["alpn"]).expect("should set ALPN");

    connect(&mut client, &mut server);

    assert_eq!(None, client.info().unwrap().alpn());
    assert_eq!(None, server.info().unwrap().alpn());
}
