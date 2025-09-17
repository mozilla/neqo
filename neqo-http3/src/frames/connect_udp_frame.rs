// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::hframe::HFrameType;
use crate::{frames::reader::FrameDecoder, Res};

#[derive(PartialEq, Eq, Debug)]
pub enum Frame {
    // TODO: Implement HTTP Datagram <https://github.com/mozilla/neqo/issues/2843>.
}

impl FrameDecoder<Self> for Frame {
    fn decode(_frame_type: HFrameType, _frame_len: u64, _data: Option<&[u8]>) -> Res<Option<Self>> {
        Ok(None)
    }

    fn is_known_type(_frame_type: HFrameType) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frames::reader::FrameDecoder;

    const DATAGRAM: HFrameType = HFrameType(0x0);

    #[test]
    fn datagram_frame() {
        let frame_len = 1280;
        let data = vec![0u8; 1280];
        let result = <Frame as FrameDecoder<Frame>>::decode(DATAGRAM, frame_len, Some(&data));
        assert_eq!(result.unwrap(), None, "HTTP Datagram is not supported yet");
    }

    #[test]
    fn is_known_type() {
        assert!(!<Frame as FrameDecoder<Frame>>::is_known_type(DATAGRAM));
    }
}
