// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::err::{Error, Res};

use std::convert::TryInto;
use std::os::raw::c_uint;

pub fn to_c_uint<T: TryInto<c_uint>>(v: T) -> Res<c_uint> {
    match v.try_into() {
        Ok(x) => Ok(x),
        _ => Err(Error::IntegerOverflow),
    }
}
