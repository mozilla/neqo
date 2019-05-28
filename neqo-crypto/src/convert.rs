// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::err::{Error, Res};
use crate::ssl::PRTime;

use std::convert::{TryFrom, TryInto};
use std::os::raw::c_uint;

/// Integer times in this crate use a nanoseconds value.
/// This performs a conversion to PRTime from that value.
pub fn to_prtime<T: TryInto<u64>>(v: T) -> Res<PRTime> {
    match v.try_into() {
        Ok(v64) => match PRTime::try_from(v64 / 1000) {
            Ok(x) => Ok(x),
            _ => Err(Error::TimeTooFarFuture),
        },
        _ => Err(Error::TimeTooFarFuture),
    }
}

pub fn to_c_uint<T: TryInto<c_uint>>(v: T) -> Res<c_uint> {
    match v.try_into() {
        Ok(x) => Ok(x),
        _ => Err(Error::IntegerOverflow),
    }
}
