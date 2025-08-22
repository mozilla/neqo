// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// TODO: pub(crate)?
pub mod hframe;
pub mod reader;
pub mod wtframe;
pub(crate) mod connect_udp_frame;

#[allow(
    clippy::allow_attributes,
    unused_imports,
    reason = "These are exported."
)]
pub use hframe::{HFrame, H3_FRAME_TYPE_HEADERS, H3_FRAME_TYPE_SETTINGS, H3_RESERVED_FRAME_TYPES};
pub use reader::{FrameReader, StreamReaderConnectionWrapper, StreamReaderRecvStreamWrapper};
// TODO: pub(crate)?
pub use wtframe::WebTransportFrame;
pub(crate) use connect_udp_frame::Frame as ConnectUdpFrame;

#[cfg(test)]
mod tests;
