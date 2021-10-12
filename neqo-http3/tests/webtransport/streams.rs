// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::webtransport::WtTest;
use neqo_http3::Error;
use neqo_transport::StreamType;
use std::mem;

#[test]
fn wt_client_stream_uni() {
    const BUF_CLIENT: &[u8] = &[0; 10];

    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let wt_stream = wt.create_wt_stream_client(wt_session.stream_id(), StreamType::UniDi);
    wt.send_data_client(wt_stream, BUF_CLIENT);
    wt.receive_data_server(wt_stream, true, BUF_CLIENT, false);
}

#[test]
fn wt_client_stream_bidi() {
    const BUF_CLIENT: &[u8] = &[0; 10];
    const BUF_SERVER: &[u8] = &[1; 20];

    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let wt_client_stream = wt.create_wt_stream_client(wt_session.stream_id(), StreamType::BiDi);
    wt.send_data_client(wt_client_stream, BUF_CLIENT);
    let mut wt_server_stream = wt.receive_data_server(wt_client_stream, true, BUF_CLIENT, false);
    wt.send_data_server(&mut wt_server_stream, BUF_SERVER);
    wt.receive_data_client(wt_client_stream, false, BUF_SERVER, false);
}

#[test]
fn wt_server_stream_uni() {
    const BUF_SERVER: &[u8] = &[2; 30];

    let mut wt = WtTest::new();
    let mut wt_session = wt.create_wt_session();
    let mut wt_server_stream = wt.create_wt_stream_server(&mut wt_session, StreamType::UniDi);
    wt.send_data_server(&mut wt_server_stream, BUF_SERVER);
    wt.receive_data_client(wt_server_stream.stream_id(), true, BUF_SERVER, false);
}

#[test]
fn wt_server_stream_bidi() {
    const BUF_CLIENT: &[u8] = &[0; 10];
    const BUF_SERVER: &[u8] = &[1; 20];

    let mut wt = WtTest::new();
    let mut wt_session = wt.create_wt_session();
    let mut wt_server_stream = wt.create_wt_stream_server(&mut wt_session, StreamType::BiDi);
    wt.send_data_server(&mut wt_server_stream, BUF_SERVER);
    wt.receive_data_client(wt_server_stream.stream_id(), true, BUF_SERVER, false);
    wt.send_data_client(wt_server_stream.stream_id(), BUF_CLIENT);
    mem::drop(wt.receive_data_server(wt_server_stream.stream_id(), false, BUF_CLIENT, false));
}

#[test]
fn wt_client_stream_uni_close() {
    const BUF_CLIENT: &[u8] = &[0; 10];

    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let wt_stream = wt.create_wt_stream_client(wt_session.stream_id(), StreamType::UniDi);
    wt.send_data_client(wt_stream, BUF_CLIENT);
    wt.close_stream_sending_client(wt_stream);
    wt.receive_data_server(wt_stream, true, BUF_CLIENT, true);
}

#[test]
fn wt_client_stream_bidi_close() {
    const BUF_CLIENT: &[u8] = &[0; 10];
    const BUF_SERVER: &[u8] = &[1; 20];

    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let wt_client_stream = wt.create_wt_stream_client(wt_session.stream_id(), StreamType::BiDi);

    wt.send_data_client(wt_client_stream, BUF_CLIENT);
    wt.close_stream_sending_client(wt_client_stream);

    let mut wt_server_stream = wt.receive_data_server(wt_client_stream, true, BUF_CLIENT, true);

    wt.send_data_server(&mut wt_server_stream, BUF_SERVER);
    wt.close_stream_sending_server(&mut wt_server_stream);
    wt.receive_data_client(wt_client_stream, false, BUF_SERVER, true);
}

#[test]
fn wt_server_stream_uni_closed() {
    const BUF_SERVER: &[u8] = &[2; 30];

    let mut wt = WtTest::new();
    let mut wt_session = wt.create_wt_session();
    let mut wt_server_stream = wt.create_wt_stream_server(&mut wt_session, StreamType::UniDi);
    wt.send_data_server(&mut wt_server_stream, BUF_SERVER);
    wt.close_stream_sending_server(&mut wt_server_stream);
    wt.receive_data_client(wt_server_stream.stream_id(), true, BUF_SERVER, true);
}

#[test]
fn wt_server_stream_bidi_close() {
    const BUF_CLIENT: &[u8] = &[0; 10];
    const BUF_SERVER: &[u8] = &[1; 20];

    let mut wt = WtTest::new();
    let mut wt_session = wt.create_wt_session();
    let mut wt_server_stream = wt.create_wt_stream_server(&mut wt_session, StreamType::BiDi);
    wt.send_data_server(&mut wt_server_stream, BUF_SERVER);
    wt.close_stream_sending_server(&mut wt_server_stream);
    wt.receive_data_client(wt_server_stream.stream_id(), true, BUF_SERVER, true);
    wt.send_data_client(wt_server_stream.stream_id(), BUF_CLIENT);
    wt.close_stream_sending_client(wt_server_stream.stream_id());
    mem::drop(wt.receive_data_server(wt_server_stream.stream_id(), false, BUF_CLIENT, true));
}

#[test]
fn wt_client_stream_uni_reset() {
    const BUF_CLIENT: &[u8] = &[0; 10];

    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let wt_stream = wt.create_wt_stream_client(wt_session.stream_id(), StreamType::UniDi);
    wt.send_data_client(wt_stream, BUF_CLIENT);
    mem::drop(wt.receive_data_server(wt_stream, true, BUF_CLIENT, false));
    wt.reset_stream_client(wt_stream);
    wt.receive_reset_server(wt_stream);
}

#[test]
fn wt_server_stream_uni_reset() {
    const BUF_SERVER: &[u8] = &[2; 30];

    let mut wt = WtTest::new();
    let mut wt_session = wt.create_wt_session();
    let mut wt_server_stream = wt.create_wt_stream_server(&mut wt_session, StreamType::UniDi);
    wt.send_data_server(&mut wt_server_stream, BUF_SERVER);
    wt.receive_data_client(wt_server_stream.stream_id(), true, BUF_SERVER, false);
    wt.reset_stream_server(&mut wt_server_stream);
    wt.receive_reset_client(wt_server_stream.stream_id());
}

#[test]
fn wt_client_stream_bidi_reset() {
    const BUF_CLIENT: &[u8] = &[0; 10];

    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let wt_client_stream = wt.create_wt_stream_client(wt_session.stream_id(), StreamType::BiDi);

    wt.send_data_client(wt_client_stream, BUF_CLIENT);
    let mut wt_server_stream = wt.receive_data_server(wt_client_stream, true, BUF_CLIENT, false);

    wt.reset_stream_client(wt_client_stream);
    wt.receive_reset_server(wt_server_stream.stream_id());

    wt.reset_stream_server(&mut wt_server_stream);
    wt.receive_reset_client(wt_client_stream);
}

#[test]
fn wt_server_stream_bidi_reset() {
    const BUF_SERVER: &[u8] = &[1; 20];

    let mut wt = WtTest::new();
    let mut wt_session = wt.create_wt_session();
    let mut wt_server_stream = wt.create_wt_stream_server(&mut wt_session, StreamType::BiDi);
    wt.send_data_server(&mut wt_server_stream, BUF_SERVER);
    wt.receive_data_client(wt_server_stream.stream_id(), true, BUF_SERVER, false);

    wt.reset_stream_client(wt_server_stream.stream_id());
    wt.receive_reset_server(wt_server_stream.stream_id());

    wt.reset_stream_server(&mut wt_server_stream);
    wt.receive_reset_client(wt_server_stream.stream_id());
}

#[test]
fn wt_client_stream_uni_stop_sending() {
    const BUF_CLIENT: &[u8] = &[0; 10];

    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    let wt_stream = wt.create_wt_stream_client(wt_session.stream_id(), StreamType::UniDi);
    wt.send_data_client(wt_stream, BUF_CLIENT);
    let mut wt_server_stream = wt.receive_data_server(wt_stream, true, BUF_CLIENT, false);
    wt.stream_stop_sending_server(&mut wt_server_stream);
    wt.receive_stop_sending_client(wt_stream);
}

#[test]
fn wt_server_stream_uni_stop_sending() {
    const BUF_SERVER: &[u8] = &[2; 30];

    let mut wt = WtTest::new();
    let mut wt_session = wt.create_wt_session();
    let mut wt_server_stream = wt.create_wt_stream_server(&mut wt_session, StreamType::UniDi);
    wt.send_data_server(&mut wt_server_stream, BUF_SERVER);
    wt.receive_data_client(wt_server_stream.stream_id(), true, BUF_SERVER, false);
    wt.stream_stop_sending_client(wt_server_stream.stream_id());
    wt.receive_stop_sending_server(wt_server_stream.stream_id());
}

#[test]
fn wt_client_stream_bidi_stop_sending() {
    const BUF_CLIENT: &[u8] = &[0; 10];

    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();

    let wt_client_stream = wt.create_wt_stream_client(wt_session.stream_id(), StreamType::BiDi);

    wt.send_data_client(wt_client_stream, BUF_CLIENT);

    let mut wt_server_stream = wt.receive_data_server(wt_client_stream, true, BUF_CLIENT, false);

    wt.stream_stop_sending_client(wt_client_stream);

    wt.receive_stop_sending_server(wt_server_stream.stream_id());
    wt.stream_stop_sending_server(&mut wt_server_stream);
    wt.receive_stop_sending_client(wt_server_stream.stream_id());
}

#[test]
fn wt_server_stream_bidi_stop_sending() {
    const BUF_SERVER: &[u8] = &[1; 20];

    let mut wt = WtTest::new();
    let mut wt_session = wt.create_wt_session();
    let mut wt_server_stream = wt.create_wt_stream_server(&mut wt_session, StreamType::BiDi);

    wt.send_data_server(&mut wt_server_stream, BUF_SERVER);
    wt.receive_data_client(wt_server_stream.stream_id(), true, BUF_SERVER, false);
    wt.stream_stop_sending_client(wt_server_stream.stream_id());
    wt.receive_stop_sending_server(wt_server_stream.stream_id());
    wt.stream_stop_sending_server(&mut wt_server_stream);
    wt.receive_stop_sending_client(wt_server_stream.stream_id());
}

#[test]
fn wt_client_session_close() {
    const BUF: &[u8] = &[0; 10];

    let mut wt = WtTest::new();
    let mut wt_session = wt.create_wt_session();

    let wt_c_bidi = wt.create_wt_stream_client(wt_session.stream_id(), StreamType::BiDi);
    wt.send_data_client(wt_c_bidi, BUF);
    let _wt_s_bidi_from_c = wt.receive_data_server(wt_c_bidi, true, BUF, false);

    let wt_c_unidi = wt.create_wt_stream_client(wt_session.stream_id(), StreamType::UniDi);
    wt.send_data_client(wt_c_unidi, BUF);
    let _wt_s_uni_from_c = wt.receive_data_server(wt_c_unidi, true, BUF, false);

    let mut wt_s_bidi = wt.create_wt_stream_server(&mut wt_session, StreamType::BiDi);
    wt.send_data_server(&mut wt_s_bidi, BUF);
    wt.receive_data_client(wt_s_bidi.stream_id(), true, BUF, false);

    let mut wt_s_unidi = wt.create_wt_stream_server(&mut wt_session, StreamType::UniDi);
    wt.send_data_server(&mut wt_s_unidi, BUF);
    wt.receive_data_client(wt_s_unidi.stream_id(), true, BUF, false);

    wt.cancel_session_client(wt_session.stream_id());

    wt.check_session_closed_event_server(&mut wt_session, Some(Error::HttpNoError.code()));

    //TODO cancel associated streams.
    //wt.receive_reset_server(wt_s_bidi_from_c.stream_id());
    //wt.receive_stop_sending_server(wt_s_uni_from_c.stream_id());
    //wt.receive_reset_server(wt_s_bidi_from_c.stream_id());

    //wt.receive_stop_sending_server(wt_s_bidi.stream_id());
    //wt.receive_reset_server(wt_s_bidi.stream_id());
    //wt.receive_stop_sending_server(wt_s_unidi.stream_id());

    //assert!(wt.client.next_event().is_none());
}

#[test]
fn wt_client_session_server_close() {
    const BUF: &[u8] = &[0; 10];

    let mut wt = WtTest::new();
    let mut wt_session = wt.create_wt_session();

    let wt_c_bidi = wt.create_wt_stream_client(wt_session.stream_id(), StreamType::BiDi);
    wt.send_data_client(wt_c_bidi, BUF);
    let _wt_s_bidi_from_c = wt.receive_data_server(wt_c_bidi, true, BUF, false);

    let wt_c_unidi = wt.create_wt_stream_client(wt_session.stream_id(), StreamType::UniDi);
    wt.send_data_client(wt_c_unidi, BUF);
    let _wt_s_uni_from_c = wt.receive_data_server(wt_c_unidi, true, BUF, false);

    let mut wt_s_bidi = wt.create_wt_stream_server(&mut wt_session, StreamType::BiDi);
    wt.send_data_server(&mut wt_s_bidi, BUF);
    wt.receive_data_client(wt_s_bidi.stream_id(), true, BUF, false);

    let mut wt_s_unidi = wt.create_wt_stream_server(&mut wt_session, StreamType::UniDi);
    wt.send_data_server(&mut wt_s_unidi, BUF);
    wt.receive_data_client(wt_s_unidi.stream_id(), true, BUF, false);

    wt.cancel_session_server(&mut wt_session);

    wt.check_session_closed_event_client(wt_session.stream_id(), Some(Error::HttpNoError.code()));

    //TODO cancel associated stream
    //wt.receive_reset_client(wt_s_bidi_from_c.stream_id());
    //wt.receive_stop_sending_client(wt_s_uni_from_c.stream_id());
    //wt.receive_reset_client(wt_s_bidi_from_c.stream_id());

    //wt.receive_stop_sending_client(wt_s_bidi.stream_id());
    //wt.receive_reset_client(wt_s_bidi.stream_id());
    //wt.receive_stop_sending_client(wt_s_unidi.stream_id());

    //assert!(wt.server.next_event().is_none());
}
