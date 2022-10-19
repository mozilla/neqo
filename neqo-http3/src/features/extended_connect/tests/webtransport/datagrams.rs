// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::webtransport::{wt_default_parameters, WtTest, DATAGRAM_SIZE};
use neqo_common::Encoder;
use neqo_http3::{Error, Http3Parameters};
use neqo_transport::Error as TransportError;
use std::convert::TryFrom;

const DGRAM: &[u8] = &[0, 100];

#[test]
fn no_datagrams() {
    let mut wt = WtTest::new_with_params(
        Http3Parameters::default().webtransport(true),
        Http3Parameters::default().webtransport(true),
    );
    let mut wt_session = wt.create_wt_session();

    assert_eq!(
        wt_session.max_datagram_size(),
        Err(Error::TransportError(TransportError::NotAvailable))
    );
    assert_eq!(
        wt.max_datagram_size(wt_session.stream_id()),
        Err(Error::TransportError(TransportError::NotAvailable))
    );

    assert_eq!(
        wt_session.send_datagram(DGRAM, None),
        Err(Error::TransportError(TransportError::TooMuchData))
    );
    assert_eq!(
        wt.send_datagram(wt_session.stream_id(), DGRAM),
        Err(Error::TransportError(TransportError::TooMuchData))
    );

    wt.exchange_packets();
    wt.check_no_datagram_received_client();
    wt.check_no_datagram_received_server();
}

#[test]
fn datagrams() {
    let mut wt = WtTest::new();
    let mut wt_session = wt.create_wt_session();

    assert_eq!(
        wt_session.max_datagram_size(),
        Ok(DATAGRAM_SIZE
            - u64::try_from(Encoder::varint_len(wt_session.stream_id().as_u64())).unwrap())
    );
    assert_eq!(
        wt.max_datagram_size(wt_session.stream_id()),
        Ok(DATAGRAM_SIZE
            - u64::try_from(Encoder::varint_len(wt_session.stream_id().as_u64())).unwrap())
    );

    assert_eq!(wt_session.send_datagram(DGRAM, None), Ok(()));
    assert_eq!(wt.send_datagram(wt_session.stream_id(), DGRAM), Ok(()));

    wt.exchange_packets();
    wt.check_datagram_received_client(wt_session.stream_id(), DGRAM);
    wt.check_datagram_received_server(&wt_session, DGRAM);
}

#[test]
fn datagrams_server_only() {
    let mut wt = WtTest::new_with_params(
        Http3Parameters::default().webtransport(true),
        wt_default_parameters(),
    );
    let mut wt_session = wt.create_wt_session();

    assert_eq!(
        wt_session.max_datagram_size(),
        Err(Error::TransportError(TransportError::NotAvailable))
    );
    assert_eq!(
        wt.max_datagram_size(wt_session.stream_id()),
        Ok(DATAGRAM_SIZE
            - u64::try_from(Encoder::varint_len(wt_session.stream_id().as_u64())).unwrap())
    );

    assert_eq!(
        wt_session.send_datagram(DGRAM, None),
        Err(Error::TransportError(TransportError::TooMuchData))
    );
    assert_eq!(wt.send_datagram(wt_session.stream_id(), DGRAM), Ok(()));

    wt.exchange_packets();
    wt.check_datagram_received_server(&wt_session, DGRAM);
    wt.check_no_datagram_received_client();
}

#[test]
fn datagrams_client_only() {
    let mut wt = WtTest::new_with_params(
        wt_default_parameters(),
        Http3Parameters::default().webtransport(true),
    );
    let mut wt_session = wt.create_wt_session();

    assert_eq!(
        wt_session.max_datagram_size(),
        Ok(DATAGRAM_SIZE
            - u64::try_from(Encoder::varint_len(wt_session.stream_id().as_u64())).unwrap())
    );
    assert_eq!(
        wt.max_datagram_size(wt_session.stream_id()),
        Err(Error::TransportError(TransportError::NotAvailable))
    );

    assert_eq!(wt_session.send_datagram(DGRAM, None), Ok(()));
    assert_eq!(
        wt.send_datagram(wt_session.stream_id(), DGRAM),
        Err(Error::TransportError(TransportError::TooMuchData))
    );

    wt.exchange_packets();
    wt.check_datagram_received_client(wt_session.stream_id(), DGRAM);
    wt.check_no_datagram_received_server();
}
