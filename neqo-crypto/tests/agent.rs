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
fn handshake() {
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

    assert_eq!(TLS_VERSION_1_3, client.info().version());
    assert_eq!(TLS_AES_128_GCM_SHA256, client.info().cipher_suite());

    let (state, bytes) = server.handshake(NOW, &bytes[..]).expect("finish");
    assert_eq!(bytes.len(), 0);
    assert_eq!(state, HandshakeState::Complete);

    assert_eq!(TLS_VERSION_1_3, server.info().version());
    assert_eq!(TLS_AES_128_GCM_SHA256, server.info().cipher_suite());
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
fn handshake_raw() {
    init_db("./db");
    let mut client = Client::new("server.example").expect("should create client");
    println!("client {:?}", client);
    let mut server = Server::new(&["key"]).expect("should create server");
    println!("server {:?}", server);

    let (state, client_records) = client.handshake_raw(NOW, None).expect("send CH");
    assert!(client_records.len() > 0);
    assert_eq!(state, HandshakeState::InProgress);

    let server_records = forward_records(&mut server, client_records).expect("read CH, send SH");
    assert!(server_records.len() > 0);
    assert_eq!(*server.state(), HandshakeState::InProgress);

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

fn connect(client: &mut SecretAgent, server: &mut SecretAgent) {
    let mut a = client;
    let mut b = server;
    let (_, mut records) = a.handshake_raw(NOW, None).unwrap();
    while *a.state() != HandshakeState::Complete && *b.state() != HandshakeState::Complete {
        records = forward_records(&mut b, records).unwrap();
        if *b.state() == HandshakeState::AuthenticationPending {
            b.authenticated();
            let (_, rec) = b.handshake_raw(NOW, None).unwrap();
            records = rec;
        }
        b = mem::replace(&mut a, b);
    }
}

#[test]
fn chacha_client() {
    init_db("./db");
    let mut client = Client::new("server.example").expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");
    client.enable_ciphers(&[TLS_CHACHA20_POLY1305_SHA256]).expect("ciphers set");

    connect(&mut client, &mut server);

    assert_eq!(client.info().cipher_suite(), TLS_CHACHA20_POLY1305_SHA256);
}
