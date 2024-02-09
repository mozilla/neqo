// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
    slice,
};

use quinn_udp::{EcnCodepoint, RecvMeta, Transmit, UdpSocketState};
use tokio::io::Interest;

use crate::{Datagram, IpTos};

/// Send the UDP datagram on the specified socket.
///
/// # Arguments
///
/// * `socket` - The UDP socket to send the datagram on.
/// * `d` - The datagram to send.
///
/// # Returns
///
/// An `io::Result` indicating whether the datagram was sent successfully.
///
/// # Errors
///
/// Returns an `io::Error` if the UDP socket fails to send the datagram.
///
/// # Panics
///
/// Panics if the datagram is too large to send.
pub fn tx(
    socket: &tokio::net::UdpSocket,
    state: &UdpSocketState,
    d: &Datagram,
) -> io::Result<usize> {
    let transmit = Transmit {
        destination: d.destination(),
        ecn: EcnCodepoint::from_bits(Into::<u8>::into(d.tos())),
        contents: d[..].to_vec().into(),
        segment_size: None,
        // TODO
        src_ip: None,
    };

    let n = (&socket).try_io(Interest::WRITABLE, || {
        state.send((&socket).into(), slice::from_ref(&transmit))
    })?;
    Ok(n)
}

/// Receive a UDP datagram on the specified socket.
///
/// # Arguments
///
/// * `socket` - The UDP socket to receive the datagram on.
/// * `buf` - The buffer to receive the datagram into.
/// * `tos` - The type-of-service (TOS) or traffic class (TC) value of the received datagram.
/// * `ttl` - The time-to-live (TTL) or hop limit (HL) value of the received datagram.
///
/// # Returns
///
/// An `io::Result` indicating the size of the received datagram and the source address.
///
/// # Errors
///
/// Returns an `io::Error` if the UDP socket fails to receive the datagram.
///
/// # Panics
///
/// Panics if the datagram is too large to receive.
pub fn rx(
    socket: &tokio::net::UdpSocket,
    state: &UdpSocketState,
    local_address: &SocketAddr,
) -> Result<Option<Datagram>, io::Error> {
    // TODO: At least we should be using a buffer pool.
    let mut buf = [0; u16::MAX as usize];

    let mut meta = RecvMeta::default();

    let (sz, remote_addr) = match (&socket).try_io(Interest::READABLE, || {
        state.recv(
            (&socket).into(),
            &mut [IoSliceMut::new(&mut buf)],
            slice::from_mut(&mut meta),
        )
    }) {
        Err(ref err)
            if err.kind() == io::ErrorKind::WouldBlock
                || err.kind() == io::ErrorKind::Interrupted =>
        {
            return Ok(None)
        }
        Err(err) => {
            eprintln!("UDP recv error: {err:?}");
            return Err(err);
        }
        Ok(n) => {
            assert_eq!(n, 1, "only passed one slice");
            (meta.len, meta.addr)
        }
    };

    if sz == buf.len() {
        eprintln!("Might have received more than {} bytes", buf.len());
    }

    if sz == 0 {
        eprintln!("zero length datagram received?");
        Ok(None)
    } else {
        Ok(Some(Datagram::new(
            remote_addr,
            *local_address,
            meta.ecn.map(|n| IpTos::from(n as u8)).unwrap_or_default(),
            Some(0xff), // TODO: get the real TTL),
            &buf[..sz],
        )))
    }
}

#[cfg(test)]
mod tests {
    use crate::{IpTos, IpTosDscp, IpTosEcn};

    use super::*;

    #[test]
    fn datagram_io() {
        // Create UDP sockets for testing.
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:8080").unwrap();

        // Create a sample datagram.
        let tos_tx = IpTos::from((IpTosDscp::Le, IpTosEcn::Ce));
        let ttl_tx = 128;
        let datagram = Datagram::new(
            sender.local_addr().unwrap(),
            receiver.local_addr().unwrap(),
            tos_tx,
            Some(ttl_tx),
            "Hello, world!".as_bytes().to_vec(),
        );

        // Call the emit_datagram function.
        let result = tx(&sender, &datagram);

        // Assert that the datagram was sent successfully.
        assert!(result.is_ok());

        // Create a buffer for receiving the datagram.
        let mut buf = [0; u16::MAX as usize];

        // Create variables for storing TOS and TTL values.
        let mut tos_rx = 0;
        let mut ttl_rx = 0;

        // Call the recv_datagram function.
        let result = rx(&receiver, &mut buf, &mut tos_rx, &mut ttl_rx);

        // Assert that the datagram was received successfully.
        println!("Received {result:?}");
        assert!(result.is_ok());

        // Assert that the ECN and TTL values are correct.
        // TODO: Also check DSCP once quinn-udp supports it.
        // assert_eq!(IpTosEcn::from(u8::from(tos_tx)), IpTosEcn::from(tos_rx));
        // assert_eq!(tos_tx, tos_rx.into());
        assert_ne!(ttl_tx, ttl_rx);
    }
}
