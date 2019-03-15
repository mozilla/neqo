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
