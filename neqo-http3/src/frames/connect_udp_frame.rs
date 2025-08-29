// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::hframe::HFrameType;
use crate::{frames::reader::FrameDecoder, Res};

#[derive(PartialEq, Eq, Debug)]
pub(crate) enum Frame {
    // TODO: Implement HTTP Datagram <https://github.com/mozilla/neqo/issues/2843>.
}

impl FrameDecoder<Self> for Frame {
    fn decode(_frame_type: HFrameType, _frame_len: u64, _data: Option<&[u8]>) -> Res<Option<Self>> {
        // TODO: Correct?
        Ok(None)
    }

    fn is_known_type(_frame_type: HFrameType) -> bool {
        false
    }
}
