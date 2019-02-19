extern crate num_traits;

// Cribbed from the |matches| crate, for simplicity.
macro_rules! matches {
    ($expression:expr, $($pattern:tt)+) => {
        match $expression {
            $($pattern)+ => true,
            _ => false
        }
    }
}

pub mod data;
pub mod frame;
pub mod packet;
pub mod varint;

#[derive(PartialEq, Debug)]
pub enum Error {
    ErrNoMoreData,
    ErrUnknownFrameType,
    ErrInternal,
    ErrInvalidPacket,
}

pub type Res<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {}
