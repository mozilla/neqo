#![deny(warnings)]

use neqo_crypto::*;

mod handshake;
use crate::handshake::*;

struct NoopExtensionHandler {}
impl ExtensionHandler for NoopExtensionHandler {}

// This test just handshakes.  It doesn't really do anything about capturing the
#[test]
fn noop_extension_handler() {
    init_db("./db");
    let mut client = Client::new("server.example").expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");

    client
        .add_extension_handler(0xffff, Box::new(NoopExtensionHandler {}))
        .expect("installed");
    server
        .add_extension_handler(0xffff, Box::new(NoopExtensionHandler {}))
        .expect("installed");

    connect(&mut client, &mut server);
}
