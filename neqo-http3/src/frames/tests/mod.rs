// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::fmt::Debug;

use neqo_common::Encoder;
use neqo_transport::StreamType;
use nss::AuthenticationStatus;
use test_fixture::{default_client, default_server, now};

use crate::{
    Error,
    frames::{
        FrameReader, HFrame, StreamReaderConnectionWrapper, WebTransportFrame, reader::FrameDecoder,
    },
};

fn add_extra_byte(st: &str) -> Encoder {
    let e_in = Encoder::from_hex(st);
    let mut dec = e_in.as_decoder();
    let frame_type = dec.decode_varint().unwrap();
    let len = dec.decode_varint().unwrap();

    let mut e_out = Encoder::with_capacity(e_in.len() + 1);
    // This might be a shorter encoding than the original, but that's OK.
    e_out.encode_varint(frame_type);
    e_out.encode_varint(len + 1);
    e_out.encode(dec.decode_remainder());
    // Add a space.  The `PRIORITY_UPDATE` frame depends on this.
    e_out.encode_byte(b' ');
    e_out
}

/// Check that the frame decoder works for `T`.
/// `st` is the encoded frame, in hex.
/// `remaining` is the bytes that the decoder won't consume.  For `DATA` frames only.
/// `greedy` is whether the frame will consume any number of bytes.
pub fn enc_dec<T: FrameDecoder<T> + Debug>(
    d: &Encoder,
    st: &str,
    remaining: usize,
    greedy: bool,
) -> T {
    // For data and headers we do not read all bytes from the buffer
    let d2 = Encoder::from_hex(st);
    assert_eq!(d.as_ref(), &d2.as_ref()[..d.as_ref().len()]);

    let mut conn_c = default_client();
    let mut conn_s = default_server();
    let out = conn_c.process_output(now());
    let out2 = conn_c.process_output(now());
    _ = conn_s.process(out.dgram(), now());
    let out = conn_s.process(out2.dgram(), now());
    let out = conn_c.process(out.dgram(), now());
    let out = conn_s.process(out.dgram(), now());
    let out = conn_c.process(out.dgram(), now());
    drop(conn_s.process(out.dgram(), now()));
    conn_c.authenticated(AuthenticationStatus::Ok, now());
    let out = conn_c.process_output(now());
    drop(conn_s.process(out.dgram(), now()));

    // create a stream
    let stream_id = conn_s.stream_create(StreamType::BiDi).unwrap();

    let mut fr = FrameReader::new();

    // convert string into u8 vector
    let buf = Encoder::from_hex(st);
    conn_s.stream_send(stream_id, buf.as_ref()).unwrap();
    let out = conn_s.process_output(now());
    drop(conn_c.process(out.dgram(), now()));

    let (frame, fin) = fr
        .receive::<T>(
            &mut StreamReaderConnectionWrapper::new(&mut conn_c, stream_id),
            now(),
        )
        .unwrap();
    assert!(!fin);
    assert!(frame.is_some());

    // Check remaining data.
    let mut buf = [0_u8; 100];
    let (amount, _) = conn_c.stream_recv(stream_id, &mut buf).unwrap();
    assert_eq!(amount, remaining);

    // Now construct a frame with an extra byte in it.
    // That should be rejected.
    // This doesn't work for `DATA`, which happily takes all extra bytes.
    let e_out = add_extra_byte(st);
    conn_s.stream_send(stream_id, e_out.as_ref()).unwrap();
    let dgram = conn_s.process_output(now()).dgram();
    drop(conn_c.process(dgram, now()));

    let res = fr.receive::<T>(
        &mut StreamReaderConnectionWrapper::new(&mut conn_c, stream_id),
        now(),
    );
    if greedy {
        assert!(res.is_ok());
    } else {
        assert!(matches!(res, Err(Error::HttpFrame)), "{res:?}");
    }

    frame.unwrap()
}

pub fn enc_dec_hframe(f: &HFrame, st: &str, remaining: usize, greedy: bool) {
    let mut d = Encoder::default();
    f.encode(&mut d);
    let frame = enc_dec::<HFrame>(&d, st, remaining, greedy);
    assert_eq!(*f, frame);
}

pub fn enc_dec_wtframe(f: &WebTransportFrame, st: &str, remaining: usize, greedy: bool) {
    let mut d = Encoder::default();
    f.encode(&mut d);
    let frame = enc_dec::<WebTransportFrame>(&d, st, remaining, greedy);
    assert_eq!(*f, frame);
}

mod hframe;
mod reader;
mod wtframe;
