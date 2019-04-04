// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(not(test))]
pub use neqo_crypto::agent::Agent;
#[cfg(not(test))]
pub use neqo_transport::connection::Connection;

#[cfg(test)]
pub mod test_transport;
#[cfg(test)]
pub use self::test_transport::{Agent, Connection};
#[cfg(test)]
pub mod test_stream;
