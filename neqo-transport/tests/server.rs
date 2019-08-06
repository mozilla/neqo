use neqo_transport::{server::Server, FixedConnectionIdManager, State};
use test_fixture::{self, default_client, now};

// Different than the one in the fixture, which is a single connection.
fn default_server() -> Server {
    Server::new(
        now(),
        test_fixture::DEFAULT_KEYS,
        test_fixture::DEFAULT_ALPN,
        test_fixture::anti_replay(),
        FixedConnectionIdManager::new(10),
    )
}

#[test]
fn single_client() {
    let mut server = default_server();
    let mut client = default_client();

    let dgram = client.process(None, now()).dgram();
    assert!(dgram.is_some());
    let dgram = server.process(dgram, now()).dgram();
    assert!(dgram.is_some());
    let dgram = client.process(dgram, now()).dgram();
    assert!(dgram.is_some());
    assert_eq!(*client.state(), State::Connected);
    let dgram = server.process(dgram, now()).dgram();
    assert!(dgram.is_some());
    let server_connections = server.active_connections();
    assert_eq!(server_connections.len(), 1);
    for s in server_connections {
        assert_eq!(*s.borrow().state(), State::Connected);
    }
}

#[test]
fn retry() {}
