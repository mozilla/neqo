// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(dead_code)]
use crate::{Error, Res};
use neqo_common::{hex, matches, qdebug, qtrace, Decoder, Encoder};
use neqo_crypto::ext::{ExtensionHandler, ExtensionHandlerResult, ExtensionWriterResult};
use neqo_crypto::{HandshakeMessage, TLS_HS_CLIENT_HELLO, TLS_HS_ENCRYPTED_EXTENSIONS};
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
    fn encode(&self, enc: &mut Encoder, tipe: u16) {
        enc.encode_uint(2, tipe);
        match self {
            TransportParameter::Bytes(a) => {
                enc.encode_vec(2, a);
            }
            TransportParameter::Integer(a) => {
                enc.encode_vec_with(2, |enc_inner| {
                    enc_inner.encode_varint(*a);
                });
            }
            TransportParameter::Empty => {
                enc.encode_uint(2, 0_u64);
            }
        };
    }

    fn decode(dec: &mut Decoder) -> Res<Option<(u16, TransportParameter)>> {
        let tipe = match dec.decode_uint(2) {
            Some(v) => v as u16,
            _ => return Err(Error::NoMoreData),
        };
        let content = match dec.decode_vec(2) {
            Some(v) => v,
            _ => return Err(Error::NoMoreData),
        };
        qtrace!("TP {:x} length {:x}", tipe, content.len());
        let mut d = Decoder::from(content);
        let tp = match tipe {
            ORIGINAL_CONNECTION_ID => TransportParameter::Bytes(d.decode_remainder().to_vec()), // TODO(mt) unnecessary copy
            STATELESS_RESET_TOKEN => {
                if d.remaining() != 16 {
                    return Err(Error::TransportParameterError);
                }
                TransportParameter::Bytes(d.decode_remainder().to_vec()) // TODO(mt) unnecessary copy
            }
            IDLE_TIMEOUT
            | INITIAL_MAX_DATA
            | INITIAL_MAX_STREAM_DATA_BIDI_LOCAL
            | INITIAL_MAX_STREAM_DATA_BIDI_REMOTE
            | INITIAL_MAX_STREAM_DATA_UNI
            | INITIAL_MAX_STREAMS_BIDI
            | INITIAL_MAX_STREAMS_UNI
            | MAX_ACK_DELAY => match d.decode_varint() {
                Some(v) => TransportParameter::Integer(v),
                None => return Err(Error::TransportParameterError),
            },

            MAX_PACKET_SIZE => match d.decode_varint() {
                Some(v) if v >= 1200 => TransportParameter::Integer(v),
                _ => return Err(Error::TransportParameterError),
            },

            ACK_DELAY_EXPONENT => match d.decode_varint() {
                Some(v) if v <= 20 => TransportParameter::Integer(v),
                _ => return Err(Error::TransportParameterError),
            },

            DISABLE_MIGRATION => TransportParameter::Empty,
            // Skip.
            // TODO(ekr@rtfm.com): Write a skip.
            _ => return Ok(None),
        };
        if d.remaining() > 0 {
            return Err(Error::TooMuchData);
        }

        Ok(Some((tipe, tp)))
    }
}

#[derive(Default, PartialEq, Debug)]
pub struct TransportParameters {
    params: HashMap<u16, TransportParameter>,
}

impl TransportParameters {
    /// Decode is a static function that parses transport parameters
    /// using the provided decoder.
    pub fn decode(d: &mut Decoder) -> Res<TransportParameters> {
        let mut tps = TransportParameters::default();
        qtrace!("Parsed fixed TP header");

        let params = match d.decode_vec(2) {
            Some(v) => v,
            _ => return Err(Error::TransportParameterError),
        };
        let mut d2 = Decoder::from(params);
        while d2.remaining() > 0 {
            match TransportParameter::decode(&mut d2) {
                Ok(Some((tipe, tp))) => {
                    tps.params.insert(tipe, tp);
                }
                Ok(None) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(tps)
    }

    pub fn encode(&self, enc: &mut Encoder) {
        enc.encode_vec_with(2, |mut enc_inner| {
            for (tipe, tp) in &self.params {
                tp.encode(&mut enc_inner, *tipe);
            }
        });
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
        if !matches!(msg, TLS_HS_CLIENT_HELLO | TLS_HS_ENCRYPTED_EXTENSIONS) {
            return ExtensionWriterResult::Skip;
        }

        qdebug!("Writing transport parameters, msg={:?}", msg);

        // TODO(ekr@rtfm.com): Modify to avoid a copy.
        let mut enc = Encoder::default();
        self.local.encode(&mut enc);
        assert!(enc.len() <= d.len());
        d[..enc.len()].copy_from_slice(&enc);
        ExtensionWriterResult::Write(enc.len())
    }

    fn handle(&mut self, msg: HandshakeMessage, d: &[u8]) -> ExtensionHandlerResult {
        qdebug!(
            "Handling transport parameters, msg={:?} value={}",
            msg,
            hex(d),
        );

        if !matches!(msg, TLS_HS_CLIENT_HELLO | TLS_HS_ENCRYPTED_EXTENSIONS) {
            return ExtensionHandlerResult::Alert(110); // unsupported_extension
        }

        let mut dec = Decoder::from(d);
        match TransportParameters::decode(&mut dec) {
            Ok(tp) => {
                self.remote = Some(tp);
                ExtensionHandlerResult::Ok
            }
            _ => ExtensionHandlerResult::Alert(47), // illegal_parameter
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

        let mut enc = Encoder::default();
        tps.encode(&mut enc);

        let tps2 = TransportParameters::decode(&mut enc.as_decoder()).expect("Couldn't decode");
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

        let mut enc = Encoder::default();
        tps.encode(&mut enc);

        let tps2 = TransportParameters::decode(&mut enc.as_decoder()).expect("Couldn't decode");
    }

    #[test]
    fn test_apple_tps() {
        let enc = Encoder::from_hex("0049000100011e00020010449aeef472626f18a5bba2d51ae473be0003000244b0000400048015f9000005000480015f900006000480015f90000700048004000000080001080009000108");
        let tps2 = TransportParameters::decode(&mut enc.as_decoder()).unwrap();
    }
}
