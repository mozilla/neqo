use nss_ssl::{init_db, Client, HandshakeState, Server};
use std::time::SystemTime;

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

    let mut c2s = [0u8; 4096];
    let mut s2c = [0u8; 4096];
    let now = SystemTime::now();

    let (state, bytes) = client
        .handshake(&now, &s2c[0..0], &mut c2s)
        .expect("send CH");
    assert_eq!(state, HandshakeState::InProgress);
    assert!(bytes > 0);

    let (state, bytes) = server
        .handshake(&now, &c2s[0..bytes], &mut s2c)
        .expect("read CH, send SH");
    assert_eq!(state, HandshakeState::InProgress);
    assert!(bytes > 0);

    let (state, bytes) = client
        .handshake(&now, &s2c[0..bytes], &mut c2s)
        .expect("send CF");
    assert_eq!(state, HandshakeState::AuthenticationPending);
    assert_eq!(bytes, 0);

    // Calling handshake() again indicates that we're happy with the cert.
    let (state, bytes) = client
        .handshake(&now, &s2c[0..0], &mut c2s)
        .expect("send CF");
    assert_eq!(state, HandshakeState::Complete);
    assert!(bytes > 0);

    let (state, bytes) = server
        .handshake(&now, &c2s[0..bytes], &mut s2c)
        .expect("finish");
    assert_eq!(state, HandshakeState::Complete);
    assert_eq!(bytes, 0);
}

#[test]
fn handshake_raw() {
    init_db("./db");
    let mut client = Client::new("server.example").expect("should create client");
    println!("client {:p}", &client);
    let mut server = Server::new(&["key"]).expect("should create server");
    println!("server {:p}", &server);

    let mut c2s = [0u8; 4096];
    let mut s2c = [0u8; 4096];
    let now = SystemTime::now();

    let (state, client_records) = client
        .handshake_raw(&now, Default::default(), &mut c2s)
        .expect("send CH");
    assert_eq!(state, HandshakeState::InProgress);
    assert!(client_records.len() > 0);

    let (state, server_records) = server
        .handshake_raw(&now, client_records, &mut s2c)
        .expect("read CH, send SH");
    assert_eq!(state, HandshakeState::InProgress);
    assert!(server_records.len() > 0);

    let (state, client_records) = client
        .handshake_raw(&now, server_records, &mut c2s)
        .expect("send CF");
    assert_eq!(state, HandshakeState::AuthenticationPending);
    assert_eq!(client_records.len(), 0);

    // Calling handshake() again indicates that we're happy with the cert.
    let (state, client_records) = client
        .handshake_raw(&now, Default::default(), &mut c2s)
        .expect("send CF");
    assert_eq!(state, HandshakeState::Complete);
    assert!(client_records.len() > 0);

    let (state, server_records) = server
        .handshake_raw(&now, client_records, &mut s2c)
        .expect("finish");
    assert_eq!(state, HandshakeState::Complete);
    assert_eq!(server_records.len(), 0);
}
