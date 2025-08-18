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
}
