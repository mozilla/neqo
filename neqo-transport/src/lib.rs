#[macro_use]
extern crate neqo_common;

pub mod connection;
pub mod data;
pub mod frame;
mod nss;
mod nss_stub;
pub mod packet;
pub mod stream;
pub mod varint;

#[derive(PartialEq, Debug)]
pub enum Error {
    ErrNoError = 0x0,
    ErrInternalError = 0x1,
    ErrServerBusy = 0x2,
    ErrFlowControlError = 0x3,
    ErrStreamLimitError = 0x4,
    ErrStreamStateError = 0x5,
    ErrFinalSizeError = 0x6,
    ErrFrameEncodingError = 0x7,
    ErrTransportParameterError = 0x8,
    ErrProtocolViolation = 0xa,
    ErrInvalidMigration = 0xc,
    ErrCryptoError = 0x100,
    ErrNoMoreData,
    ErrTooMuchData,
    ErrUnknownFrameType,
    ErrInternal,
    ErrInvalidPacket,
    ErrDecryptError,
    ErrInvalidStreamId,
    ErrDecodingFrame,
    ErrUnexpectedMessage,
    ErrHandshakeFailed,
}

pub type Res<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {}
