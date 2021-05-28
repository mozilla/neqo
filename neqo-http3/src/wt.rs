// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_common::qtrace;

#[derive(Debug, PartialEq)]
enum WebTransportControllerState {
    Negoiating,
    Negotiated,
    NegotiationFailed,
}

#[derive(Debug)]
pub struct WebTransportController {
    state: WebTransportControllerState,
}

impl Default for WebTransportController {
    fn default() -> Self {
        Self {
            state: WebTransportControllerState::Negoiating,
        }
    }
}

impl ::std::fmt::Display for WebTransportController {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "WebTransport")
    }
}

impl WebTransportController {
    pub fn set_negotiated(&mut self, negotiated: bool) {
        qtrace!([self], "set_negotiated {}", negotiated);
        self.state = if negotiated {
            WebTransportControllerState::Negotiated
        } else {
            WebTransportControllerState::NegotiationFailed
        };
    }

    pub fn enabled(&self) -> bool {
        self.state == WebTransportControllerState::Negotiated
    }
}
