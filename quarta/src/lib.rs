extern crate num_traits;
pub mod data;
pub mod frame;
pub mod varint;

#[derive(PartialEq, Debug)]
pub enum Error {
    ErrNoMoreData,
    ErrUnknownFrameType,
}

pub type Res<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {}
