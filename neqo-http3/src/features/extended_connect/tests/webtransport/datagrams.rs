// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_common::{Encoder, event::Provider as _, to_u64};
use neqo_transport::ConnectionParameters;
use test_fixture::now;

use crate::{
    Http3ClientEvent, Http3ServerEvent,
    features::extended_connect::tests::webtransport::{
        DATAGRAM_SIZE, WtTest, wt_default_parameters,
    },
    webtransport::ServerSession,
};

const DGRAM: &[u8] = &[0, 100];

fn do_datagram_test(wt: &mut WtTest, wt_session: &ServerSession) {
    assert_eq!(
        wt_session.max_datagram_size(),
        Ok(DATAGRAM_SIZE - to_u64(Encoder::varint_len(wt_session.stream_id().as_u64())))
    );
    assert_eq!(
        wt.max_datagram_size(wt_session.stream_id()),
        Ok(DATAGRAM_SIZE - to_u64(Encoder::varint_len(wt_session.stream_id().as_u64())))
    );

    assert_eq!(wt_session.send_datagram(DGRAM, None, now()), Ok(true));
    assert_eq!(wt.send_datagram(wt_session.stream_id(), DGRAM), Ok(true));

    wt.exchange_packets();
    wt.check_datagram_received_client(wt_session.stream_id(), DGRAM);
    wt.check_datagram_received_server(wt_session, DGRAM);
}

#[test]
fn datagrams() {
    let mut wt = WtTest::new();
    let wt_session = wt.create_wt_session();
    do_datagram_test(&mut wt, &wt_session);
}

#[test]
fn datagrams_multiple_session() {
    let mut wt = WtTest::new();

    let wt_session1 = wt.create_wt_session();
    do_datagram_test(&mut wt, &wt_session1);

    let wt_session_2 = wt.create_wt_session();
    do_datagram_test(&mut wt, &wt_session_2);
}

// A peer is allowed to advertise a max_datagram_frame_size smaller than the
// per-datagram quarter-stream-id prefix. Once a session lands on a stream id
// whose quarter stream id needs a longer varint than the available datagram
// size (quarter stream id >= 64, i.e. stream id >= 256, needs two bytes), the
// prefix subtraction must clamp to zero instead of wrapping.
#[test]
fn max_datagram_size_smaller_than_session_prefix() {
    let params = || {
        wt_default_parameters()
            .connection_parameters(ConnectionParameters::default().datagram_size(1))
    };
    let mut wt = WtTest::new_with_params(params(), params());

    let mut wt_session = wt.create_wt_session();
    while wt_session.stream_id().as_u64() < 256 {
        wt_session = wt.create_wt_session();
    }
    assert_eq!(Encoder::varint_len(wt_session.stream_id().as_u64() >> 2), 2);

    assert_eq!(wt_session.max_datagram_size(), Ok(0));
    assert_eq!(wt.max_datagram_size(wt_session.stream_id()), Ok(0));
}

/// Filling the client's outgoing QUIC datagram queue and then draining it must
/// surface [`OutgoingDatagramSpaceAvailable`].
///
/// [`OutgoingDatagramSpaceAvailable`]: crate::Http3ClientEvent::OutgoingDatagramSpaceAvailable
#[test]
fn outgoing_datagram_space_available_forwarded() {
    let mut wt = WtTest::new_with_params(
        wt_default_parameters().connection_parameters(
            ConnectionParameters::default()
                .datagram_size(DATAGRAM_SIZE)
                .outgoing_datagram_queue(1),
        ),
        wt_default_parameters(),
    );
    let wt_session = wt.create_wt_session();

    assert_eq!(wt.send_datagram(wt_session.stream_id(), DGRAM), Ok(false));
    assert!(
        !wt.client
            .events()
            .any(|e| matches!(e, Http3ClientEvent::OutgoingDatagramSpaceAvailable)),
        "resume event fired before the queue drained"
    );

    wt.exchange_packets();
    assert!(
        wt.client
            .events()
            .any(|e| matches!(e, Http3ClientEvent::OutgoingDatagramSpaceAvailable)),
        "OutgoingDatagramSpaceAvailable was not forwarded to the HTTP/3 client"
    );
}

/// The server side must forward the resume signal too. Filling the server's
/// outgoing QUIC datagram queue and then draining it has to surface
/// [`OutgoingDatagramSpaceAvailable`].
///
/// [`OutgoingDatagramSpaceAvailable`]: crate::Http3ServerEvent::OutgoingDatagramSpaceAvailable
#[test]
fn outgoing_datagram_space_available_forwarded_server() {
    let mut wt = WtTest::new_with_params(
        wt_default_parameters(),
        wt_default_parameters().connection_parameters(
            ConnectionParameters::default()
                .datagram_size(DATAGRAM_SIZE)
                .outgoing_datagram_queue(1),
        ),
    );
    let wt_session = wt.create_wt_session();

    assert_eq!(wt_session.send_datagram(DGRAM, None, now()), Ok(false));
    assert!(
        !wt.server
            .events()
            .any(|e| matches!(e, Http3ServerEvent::OutgoingDatagramSpaceAvailable { .. })),
        "server resume event fired before the queue drained"
    );

    wt.exchange_packets();
    assert!(
        wt.server
            .events()
            .any(|e| matches!(e, Http3ServerEvent::OutgoingDatagramSpaceAvailable { .. })),
        "OutgoingDatagramSpaceAvailable was not forwarded to the HTTP/3 server"
    );
}
