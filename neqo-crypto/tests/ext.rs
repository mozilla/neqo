// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{cell::RefCell, rc::Rc};

use handshake::forward_records;
use neqo_crypto::{
    constants::{HandshakeMessage, TLS_HS_CLIENT_HELLO, TLS_HS_ENCRYPTED_EXTENSIONS},
    ext::{ExtensionHandler, ExtensionHandlerResult, ExtensionWriterResult},
    generate_ech_keys, AuthenticationStatus, Client, Error, HandshakeState, Server,
};
use test_fixture::{damage_ech_config, fixture_init, now};

mod handshake;
use crate::handshake::connect;

const ECH_CONFIG_ID: u8 = 7;
const ECH_PUBLIC_NAME: &str = "public.example";

struct NoopExtensionHandler;
impl ExtensionHandler for NoopExtensionHandler {}

// This test just handshakes.  It doesn't really do anything about capturing the
#[test]
fn noop_extension_handler() {
    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");

    client
        .extension_handler(0xffff, Rc::new(RefCell::new(NoopExtensionHandler)))
        .expect("installed");
    server
        .extension_handler(0xffff, Rc::new(RefCell::new(NoopExtensionHandler)))
        .expect("installed");

    connect(&mut client, &mut server);
}

#[derive(Debug, Default)]
struct SimpleExtensionHandler {
    written: bool,
    handled: bool,
}

impl SimpleExtensionHandler {
    pub const fn negotiated(&self) -> bool {
        self.written && self.handled
    }
}

impl ExtensionHandler for SimpleExtensionHandler {
    fn write(
        &mut self,
        msg: HandshakeMessage,
        _ch_outer: bool,
        d: &mut [u8],
    ) -> ExtensionWriterResult {
        match msg {
            TLS_HS_CLIENT_HELLO | TLS_HS_ENCRYPTED_EXTENSIONS => {
                self.written = true;
                d[0] = 77;
                ExtensionWriterResult::Write(1)
            }
            _ => ExtensionWriterResult::Skip,
        }
    }

    fn handle(&mut self, msg: HandshakeMessage, d: &[u8]) -> ExtensionHandlerResult {
        match msg {
            TLS_HS_CLIENT_HELLO | TLS_HS_ENCRYPTED_EXTENSIONS => {
                self.handled = true;
                if d.len() != 1 {
                    ExtensionHandlerResult::Alert(50) // decode_error
                } else if d[0] == 77 {
                    ExtensionHandlerResult::Ok
                } else {
                    ExtensionHandlerResult::Alert(47) // illegal_parameter
                }
            }
            _ => ExtensionHandlerResult::Alert(110), // unsupported_extension
        }
    }
}

#[test]
fn simple_extension() {
    fixture_init();
    let mut client = Client::new("server.example", true).expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");

    let client_handler = Rc::new(RefCell::new(SimpleExtensionHandler::default()));
    let ch = Rc::clone(&client_handler);
    client
        .extension_handler(0xffff, ch)
        .expect("client handler installed");
    let server_handler = Rc::new(RefCell::new(SimpleExtensionHandler::default()));
    let sh = Rc::clone(&server_handler);
    server
        .extension_handler(0xffff, sh)
        .expect("server handler installed");

    connect(&mut client, &mut server);

    assert!(client_handler.borrow().negotiated());
    assert!(server_handler.borrow().negotiated());
}

#[derive(Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "These are all very different things, so it is OK"
)]
struct EchExtensionHandler {
    expect_outer: bool,
    written_inner: bool,
    written_outer: bool,
    handled: bool,
}

impl EchExtensionHandler {
    const INNER: &[u8] = b"inner is longer";
    const OUTER: &[u8] = b"outer";

    pub const fn negotiated(&self, outer_written: bool) -> bool {
        self.written_inner && self.written_outer == outer_written && self.handled
    }
}

impl ExtensionHandler for EchExtensionHandler {
    fn write(
        &mut self,
        msg: HandshakeMessage,
        ch_outer: bool,
        d: &mut [u8],
    ) -> ExtensionWriterResult {
        match msg {
            TLS_HS_CLIENT_HELLO | TLS_HS_ENCRYPTED_EXTENSIONS => {
                let v = if ch_outer {
                    self.written_outer = true;
                    Self::OUTER
                } else {
                    self.written_inner = true;
                    Self::INNER
                };
                d[..v.len()].copy_from_slice(v);
                ExtensionWriterResult::Write(v.len())
            }
            _ => ExtensionWriterResult::Skip,
        }
    }

    fn handle(&mut self, msg: HandshakeMessage, d: &[u8]) -> ExtensionHandlerResult {
        match msg {
            TLS_HS_CLIENT_HELLO | TLS_HS_ENCRYPTED_EXTENSIONS => {
                self.handled = true;
                let expected = if self.expect_outer {
                    Self::OUTER
                } else {
                    Self::INNER
                };
                if d == expected {
                    ExtensionHandlerResult::Ok
                } else {
                    ExtensionHandlerResult::Alert(47) // illegal_parameter
                }
            }
            _ => ExtensionHandlerResult::Alert(110), // unsupported_extension
        }
    }
}

#[test]
fn ech_extension() {
    fixture_init();
    let (sk, pk) = generate_ech_keys().expect("ECH keygen works");
    let mut server = Server::new(&["key"]).expect("should create server");
    server
        .enable_ech(ECH_CONFIG_ID, ECH_PUBLIC_NAME, &sk, &pk)
        .expect("ECH server setup works");

    let mut client = Client::new("server.example", true).expect("should create client");
    client
        .enable_ech(server.ech_config())
        .expect("ECH client setup works");

    let client_handler = Rc::new(RefCell::new(EchExtensionHandler::default()));
    let ch = Rc::clone(&client_handler);
    client
        .extension_handler(0xffff, ch)
        .expect("client handler installed");
    let server_handler = Rc::new(RefCell::new(EchExtensionHandler::default()));
    let sh = Rc::clone(&server_handler);
    server
        .extension_handler(0xffff, sh)
        .expect("server handler installed");

    connect(&mut client, &mut server);

    assert!(client_handler.borrow().negotiated(true));
    assert!(server_handler.borrow().negotiated(false));

    assert!(client.info().unwrap().ech_accepted());
    assert!(server.info().unwrap().ech_accepted());
    assert!(client.preinfo().unwrap().ech_accepted().unwrap());
    assert!(server.preinfo().unwrap().ech_accepted().unwrap());
}

#[test]
fn ech_retry() {
    fixture_init();
    let (sk, pk) = generate_ech_keys().expect("ECH keygen works");
    let mut server = Server::new(&["key"]).expect("should create server");
    server
        .enable_ech(ECH_CONFIG_ID, ECH_PUBLIC_NAME, &sk, &pk)
        .expect("ECH server setup works");

    let mut client = Client::new("server.example", true).expect("should create client");
    client
        .enable_ech(damage_ech_config(server.ech_config()))
        .expect("ECH client setup works");

    let client_handler = Rc::new(RefCell::new(EchExtensionHandler::default()));
    let ch = Rc::clone(&client_handler);
    client
        .extension_handler(0xffff, ch)
        .expect("client handler installed");
    let server_handler = Rc::new(RefCell::new(EchExtensionHandler {
        expect_outer: true,
        ..EchExtensionHandler::default()
    }));
    let sh = Rc::clone(&server_handler);
    server
        .extension_handler(0xffff, sh)
        .expect("server handler installed");

    let client_hello = client.handshake_raw(now(), None).expect("send ClientHello");
    let server_hello =
        forward_records(now(), &mut server, client_hello).expect("ClientHello > ServerHello");

    let client_finished =
        forward_records(now(), &mut client, server_hello).expect("ServerHello > client");
    assert!(client_finished.is_empty());
    let HandshakeState::EchFallbackAuthenticationPending(server_name) = client.state() else {
        panic!("no ECH retry configuration provided");
    };
    assert_eq!(server_name, ECH_PUBLIC_NAME);
    client.authenticated(AuthenticationStatus::Ok);
    let client_error = client
        .handshake_raw(now(), None)
        .expect_err("now the client sends a Finished and errors out");
    let Error::EchRetry(retry_cfg) = client_error else {
        panic!("no ECH retry configuration provided");
    };
    assert_eq!(server.ech_config(), retry_cfg);
    assert_eq!(client.alert(), Some(121));

    // Note that we don't have a means of signaling the error to the server in this code.
}
