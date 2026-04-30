// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub(crate) mod capsule;
pub(crate) mod hframe;
pub(crate) mod reader;
pub(crate) mod wtframe;

#[allow(
    clippy::allow_attributes,
    unused_imports,
    reason = "These are exported."
)]
pub(crate) use hframe::{HFrame, HFrameType};
pub(crate) use reader::{
    FrameReader, StreamReaderConnectionWrapper, StreamReaderRecvStreamWrapper,
};
pub(crate) use wtframe::WebTransportFrame;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
