// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(dead_code)]
use crate::{Error, Res};
use neqo_common::data::Data;
use neqo_common::hex;
use neqo_common::varint::get_varint_len;
use neqo_common::{qdebug, qtrace};
use neqo_crypto::ext::{ExtensionHandler, ExtensionHandlerResult, ExtensionWriterResult};
use neqo_crypto::HandshakeMessage;
use std::collections::HashMap;

struct PreferredAddress {
    // TODO(ekr@rtfm.com): Implement.
}

pub mod consts {
    pub const ORIGINAL_CONNECTION_ID: u16 = 0;
    pub const IDLE_TIMEOUT: u16 = 1;
    pub const STATELESS_RESET_TOKEN: u16 = 2;
    pub const MAX_PACKET_SIZE: u16 = 3;
    pub const INITIAL_MAX_DATA: u16 = 4;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u16 = 5;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u16 = 6;
    pub const INITIAL_MAX_STREAM_DATA_UNI: u16 = 7;
    pub const INITIAL_MAX_STREAMS_BIDI: u16 = 8;
    pub const INITIAL_MAX_STREAMS_UNI: u16 = 9;
    pub const ACK_DELAY_EXPONENT: u16 = 10;
    pub const MAX_ACK_DELAY: u16 = 11;
    pub const DISABLE_MIGRATION: u16 = 12;
    pub const PREFERRED_ADDRESS: u16 = 13;
}

use self::consts::*;

#[derive(PartialEq, Debug)]
pub enum TransportParameter {
    Bytes(Vec<u8>),
    Integer(u64),
    Empty,
}

impl TransportParameter {
    fn encode(&self, d: &mut Data, tipe: u16) -> Res<()> {
        d.encode_uint(tipe, 2);
        match self {
            TransportParameter::Bytes(a) => {
                d.encode_uint(a.len() as u64, 2);
                d.encode_vec(a);
            }
            TransportParameter::Integer(a) => {
                d.encode_uint(get_varint_len(*a), 2);
                d.encode_varint(*a);
            }
            TransportParameter::Empty => {
                d.encode_uint(0_u64, 2);
            }
        };

        Ok(())
    }

    fn decode(d: &mut Data) -> Res<(u16, TransportParameter)> {
        let tipe = d.decode_uint(2)? as u16;
        let length = d.decode_uint(2)? as usize;
        qtrace!("TP {:x} length {:x}", tipe, length);
        let remaining = d.remaining();
        // TODO(ekr@rtfm.com): Sure would be nice to have a version
        // of Data that returned another data that was a slice on
        // this one, so I could check the length more easily.
        let tp = match tipe {
            ORIGINAL_CONNECTION_ID => TransportParameter::Bytes(d.decode_data(length)?),
            STATELESS_RESET_TOKEN => {
                if length != 16 {
                    return Err(Error::TransportParameterError);
                }
                TransportParameter::Bytes(d.decode_data(length)?)
            }
            IDLE_TIMEOUT
            | INITIAL_MAX_DATA
            | INITIAL_MAX_STREAM_DATA_BIDI_LOCAL
            | INITIAL_MAX_STREAM_DATA_BIDI_REMOTE
            | INITIAL_MAX_STREAM_DATA_UNI
            | INITIAL_MAX_STREAMS_BIDI
            | INITIAL_MAX_STREAMS_UNI
            | MAX_ACK_DELAY => TransportParameter::Integer(d.decode_varint()?),

            MAX_PACKET_SIZE => {
                let tmp = d.decode_varint()?;
                if tmp < 1200 {
                    return Err(Error::TransportParameterError);
                }
                TransportParameter::Integer(tmp)
            }
            ACK_DELAY_EXPONENT => {
                let tmp = d.decode_varint()?;
                if tmp > 20 {
                    return Err(Error::TransportParameterError);
                }
                TransportParameter::Integer(tmp)
            }
            DISABLE_MIGRATION => TransportParameter::Empty,
            // Skip.
            // TODO(ekr@rtfm.com): Write a skip.
            _ => {
                d.decode_data(length as usize)?;
                return Err(Error::UnknownTransportParameter);
            }
        };

        // Check that we consumed the right amount.
        if (remaining - d.remaining()) > length {
            return Err(Error::NoMoreData);
        }
        if (remaining - d.remaining()) > length {
            return Err(Error::TooMuchData);
        }

        Ok((tipe, tp))
    }
}

#[derive(Default, PartialEq, Debug)]
pub struct TransportParameters {
    params: HashMap<u16, TransportParameter>,
}

impl TransportParameters {
    pub fn encode(&self, d: &mut Data) -> Res<()> {
        let mut d2 = Data::default();
        for (tipe, tp) in &self.params {
            tp.encode(&mut d2, *tipe)?;
        }
        d.encode_uint(d2.written() as u64, 2);
        d.encode_data(&d2);

        Ok(())
    }

    pub fn decode(d: &mut Data) -> Res<TransportParameters> {
        let mut tps = TransportParameters::default();
        qtrace!("Parsed fixed TP header");

        let l = d.decode_uint(2)?;
        qtrace!("Remaining bytes: needed {} remaining {}", l, d.remaining());
        let tmp = d.decode_data(l as usize)?;
        if d.remaining() > 0 {
            return Err(Error::UnknownTransportParameter);
        }
        let mut d2 = Data::from_slice(&tmp);
        while d2.remaining() > 0 {
            match TransportParameter::decode(&mut d2) {
                Ok((tipe, tp)) => {
                    tps.params.insert(tipe, tp);
                }
                Err(Error::UnknownTransportParameter) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(tps)
    }

    // Get an integer type or a default.
    pub fn get_integer(&self, tipe: u16) -> u64 {
        let default = match tipe {
            IDLE_TIMEOUT
            | INITIAL_MAX_DATA
            | INITIAL_MAX_STREAM_DATA_BIDI_LOCAL
            | INITIAL_MAX_STREAM_DATA_BIDI_REMOTE
            | INITIAL_MAX_STREAM_DATA_UNI
            | INITIAL_MAX_STREAMS_BIDI
            | INITIAL_MAX_STREAMS_UNI => 0,
            MAX_PACKET_SIZE => 65527,
            ACK_DELAY_EXPONENT => 3,
            MAX_ACK_DELAY => 25,
            _ => panic!("Transport parameter not known or not an Integer"),
        };
        match self.params.get(&tipe) {
            None => default,
            Some(TransportParameter::Integer(x)) => *x,
            _ => panic!("Internal error"),
        }
    }

    // Get an integer type or a default.
    pub fn set_integer(&mut self, tipe: u16, value: u64) {
        match tipe {
            IDLE_TIMEOUT
            | INITIAL_MAX_DATA
            | INITIAL_MAX_STREAM_DATA_BIDI_LOCAL
            | INITIAL_MAX_STREAM_DATA_BIDI_REMOTE
            | INITIAL_MAX_STREAM_DATA_UNI
            | INITIAL_MAX_STREAMS_BIDI
            | INITIAL_MAX_STREAMS_UNI
            | MAX_PACKET_SIZE
            | ACK_DELAY_EXPONENT
            | MAX_ACK_DELAY => {
                self.params.insert(tipe, TransportParameter::Integer(value));
            }
            _ => panic!("Transport parameter not known"),
        }
    }

    pub fn get_bytes(&self, tipe: u16) -> Option<Vec<u8>> {
        match tipe {
            ORIGINAL_CONNECTION_ID | STATELESS_RESET_TOKEN => {}
            _ => panic!("Transport parameter not known or not type bytes"),
        }

        match self.params.get(&tipe) {
            None => None,
            Some(TransportParameter::Bytes(x)) => Some(x.to_vec()),
            _ => panic!("Internal error"),
        }
    }

    pub fn set_bytes(&mut self, tipe: u16, value: Vec<u8>) {
        match tipe {
            ORIGINAL_CONNECTION_ID | STATELESS_RESET_TOKEN => {
                self.params.insert(tipe, TransportParameter::Bytes(value));
            }
            _ => panic!("Transport parameter not known or not type bytes"),
        }
    }

    pub fn set_empty(&mut self, tipe: u16) {
        match tipe {
            DISABLE_MIGRATION => {
                self.params.insert(tipe, TransportParameter::Empty);
            }
            _ => panic!("Transport parameter not known or not type empty"),
        }
    }

    fn was_sent(&self, tipe: u16) -> bool {
        self.params.contains_key(&tipe)
    }
}

#[derive(Default, Debug)]
pub struct TransportParametersHandler {
    pub local: TransportParameters,
    pub remote: Option<TransportParameters>,
}

impl ExtensionHandler for TransportParametersHandler {
    fn write(&mut self, msg: HandshakeMessage, d: &mut [u8]) -> ExtensionWriterResult {
        qdebug!("Writing transport parameters, msg={:?}", msg);

        // TODO(ekr@rtfm.com): Modify to avoid a copy.
        let mut buf = Data::default();
        self.local
            .encode(&mut buf)
            .expect("Failed to encode transport parameters");
        assert!(buf.remaining() <= d.len());
        d[..buf.remaining()].copy_from_slice(&buf.as_mut_vec());
        ExtensionWriterResult::Write(buf.remaining())
    }

    fn handle(&mut self, msg: HandshakeMessage, d: &[u8]) -> ExtensionHandlerResult {
        qdebug!(
            "Handling transport parameters, msg={:?} value={}",
            msg,
            hex(d),
        );

        // TODO(ekr@rtfm.com): Unnecessary copy.
        let mut buf = Data::from_slice(d);

        match TransportParameters::decode(&mut buf) {
            Err(_) => ExtensionHandlerResult::Alert(47), // illegal_parameter
            Ok(tp) => {
                self.remote = Some(tp);
                ExtensionHandlerResult::Ok
            }
        }
    }
}

// TODO(ekr@rtfm.com): Need to write more TP unit tests.
#[cfg(test)]
#[allow(unused_variables)]
mod tests {
    use super::*;
    #[test]
    fn test_basic_tps() {
        let mut tps = TransportParameters::default();
        tps.params.insert(
            STATELESS_RESET_TOKEN,
            TransportParameter::Bytes(vec![1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]),
        );
        tps.params
            .insert(INITIAL_MAX_STREAMS_BIDI, TransportParameter::Integer(10));

        let mut d = Data::default();
        tps.encode(&mut d).expect("Couldn't encode");

        let tps2 = TransportParameters::decode(&mut d).expect("Couldn't decode");
        assert_eq!(tps, tps2);

        println!("TPS = {:?}", tps);
        assert_eq!(tps2.get_integer(IDLE_TIMEOUT), 0); // Default
        assert_eq!(tps2.get_integer(MAX_ACK_DELAY), 25); // Default
        assert_eq!(tps2.get_integer(INITIAL_MAX_STREAMS_BIDI), 10); // Sent
        assert_eq!(
            tps2.get_bytes(STATELESS_RESET_TOKEN),
            Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8])
        );
        assert_eq!(tps2.get_bytes(ORIGINAL_CONNECTION_ID), None);
        assert_eq!(tps2.was_sent(ORIGINAL_CONNECTION_ID), false);
        assert_eq!(tps2.was_sent(STATELESS_RESET_TOKEN), true);

        let mut d = Data::default();
        tps.encode(&mut d).expect("Couldn't encode");

        let tps2 = TransportParameters::decode(&mut d).expect("Couldn't decode");
    }
}
