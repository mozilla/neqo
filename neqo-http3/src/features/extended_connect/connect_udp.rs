// TODO: Rename to connect_udp_session.rs to be consistent with webtransport_session.rs?
use std::fmt::{self, Display, Formatter};

#[derive(Debug)]
pub struct ConnectUdpSession {}

impl Display for ConnectUdpSession {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "ConnectUdpSession",)
    }
}

impl ConnectUdpSession {
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }

    pub(crate) fn close_frame(&self, _error: u32, _message: &str) -> Option<Vec<u8>> {
        // TODO: WebTransport sends a message. needed here as well?
        None
    }
}
