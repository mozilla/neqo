#![allow(unused_variables,dead_code)]
use crate::{Error, Res};
use neqo_common::data::*;
use neqo_common::varint::*;
use std::collections::HashMap;
struct PreferredAddress {
    // TODO(ekr@rtfm.com): Implement.
}
const TRANSPORT_PARAMETER_ORIGINAL_CONNECTION_ID: u16 = 0;
const TRANSPORT_PARAMETER_IDLE_TIMEOUT: u16 = 1;
const TRANSPORT_PARAMETER_STATELESS_RESET_TOKEN: u16 = 2;
const TRANSPORT_PARAMETER_MAX_PACKET_SIZE: u16 = 3;
const TRANSPORT_PARAMETER_INITIAL_MAX_DATA: u16 = 4;
const TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u16 = 5;
const TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u16 = 6;
const TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_UNI: u16 = 7;
const TRANSPORT_PARAMETER_INITIAL_MAX_STREAMS_BIDI: u16 = 8;
const TRANSPORT_PARAMETER_INITIAL_MAX_STREAMS_UNI: u16 = 9;
const TRANSPORT_PARAMETER_ACK_DELAY_EXPONENT: u16 = 10;
const TRANSPORT_PARAMETER_MAX_ACK_DELAY: u16 = 11;
const TRANSPORT_PARAMETER_DISABLE_MIGRATION: u16 = 12;
const TRANSPORT_PARAMETER_PREFERRED_ADDRESS: u16 = 13;

enum TransportParameter {
    Bytes(Vec<u8>),
    Integer(u64),
    Empty,
}

impl TransportParameter {
    pub fn encode(&self, d: &mut Data, tipe: u16) -> Res<()> {
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

    pub fn decode(d: &mut Data) -> Res<(u16, TransportParameter)> {
        let tipe = d.decode_uint(2)? as u16;
        let length = d.decode_uint(2)? as usize;
        let remaining = d.remaining();
        // TODO(ekr@rtfm.com): Sure would be nice to have a version
        // of Data that returned another data that was a slice on
        // this one, so I could check the length more easily.
        let tp = match tipe {
            TRANSPORT_PARAMETER_ORIGINAL_CONNECTION_ID => {
                TransportParameter::Bytes(d.decode_data(length)?)
            }
            TRANSPORT_PARAMETER_STATELESS_RESET_TOKEN => {
                if length != 16 {
                    return Err(Error::TransportParameterError);
                }
                TransportParameter::Bytes(d.decode_data(length)?)
            },
            TRANSPORT_PARAMETER_IDLE_TIMEOUT
            | TRANSPORT_PARAMETER_INITIAL_MAX_DATA
            | TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL
            | TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE
            | TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_UNI
            | TRANSPORT_PARAMETER_INITIAL_MAX_STREAMS_BIDI
            | TRANSPORT_PARAMETER_INITIAL_MAX_STREAMS_UNI
                | TRANSPORT_PARAMETER_MAX_ACK_DELAY => TransportParameter::Integer(d.decode_varint()?),
            
            TRANSPORT_PARAMETER_MAX_PACKET_SIZE => {
                let tmp = d.decode_varint()?;
                if tmp < 1200 {
                    return Err(Error::TransportParameterError);
                }
                TransportParameter::Integer(tmp)
            },
            TRANSPORT_PARAMETER_ACK_DELAY_EXPONENT => {
                let tmp = d.decode_varint()?;
                if tmp > 20 {
                    return Err(Error::TransportParameterError);
                }
                TransportParameter::Integer(tmp)
            }
            ,
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

pub struct TransportParameters {
    params: HashMap<u16, TransportParameter>,
}
