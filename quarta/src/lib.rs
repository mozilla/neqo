extern crate num_traits;
#[macro_use]
extern crate derive_more;

// Cribbed from the |matches| crate, for simplicity.
macro_rules! matches {
    ($expression:expr, $($pattern:tt)+) => {
        match $expression {
            $($pattern)+ => true,
            _ => false
        }
    }
}

pub mod connection;
pub mod data;
pub mod frame;
pub mod packet;
pub mod stream;
pub mod varint;

#[derive(PartialEq, Debug)]
pub enum Error {
    ErrNoMoreData,
    ErrUnknownFrameType,
    ErrInternal,
    ErrInvalidPacket,
    ErrDecryptError,
    ErrInvalidStreamId,
}

pub type Res<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {}
