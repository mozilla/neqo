// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub mod connect_udp_frame;
pub mod hframe;
pub mod reader;
pub mod wtframe;

pub use connect_udp_frame::Frame as ConnectUdpFrame;
#[allow(
    clippy::allow_attributes,
    unused_imports,
    reason = "These are exported."
)]
pub use hframe::{HFrame, HFrameType};
pub use reader::{FrameReader, StreamReaderConnectionWrapper, StreamReaderRecvStreamWrapper};
pub use wtframe::WebTransportFrame;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
