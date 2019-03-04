#[macro_use]
extern crate neqo_common;

pub mod connection;
pub mod data;
pub mod frame;
mod nss;
pub mod nss_stub;
pub mod packet;
pub mod stream;
pub mod varint;

#[derive(PartialEq, Debug, Copy, Clone)]
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

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum HError {
    ErrHttpNoError = 0x00,
    ErrHttpWrongSettngsDirection = 0x01,
    ErrHttpPushRefused = 0x02,
    ErrHttpInternalError = 0x03,
    ErrHttpPushAlreadyInCache = 0x04,
    ErrHttpRequestCancelled = 0x05,
    ErrHttpIncompleteRequest = 0x06,
    ErrHttpConnectError = 0x07,
    ErrHttpExcessiveLoad = 0x08,
    ErrHttpVersionFallback = 0x09,
    ErrHttpWrongStream = 0x0a,
    ErrHttpLimitExceeded = 0x0b,
    ErrHttpDuplicatePush = 0x0c,
    ErrHttpUnknownStreamType = 0x0d,
    ErrHttpWrongStreamCount = 0x0e,
    ErrHttpClosedCriticalStream = 0x0f,
    ErrHttpWrongStreamDirection = 0x10,
    ErrHttpEarlyResponse = 0x11,
    ErrHttpMissingSettings = 0x12,
    ErrHttpUnexpectedFrame = 0x13,
    ErrHttpRequestRejected = 0x14,
    ErrHttpGeneralProtocolError = 0xff,

    ErrHttpMalformatedFrameData = 0x100,
    ErrHttpMalformatedFrameHeaders = 0x101,
    ErrHttpMalformatedFramePriority = 0x102,
    ErrHttpMalformatedFrameCancelPush = 0x103,
    ErrHttpMalformatedFrameSettings = 0x104,
    ErrHttpMalformatedFramePushPromise = 0x105,
    ErrHttpMalformatedFrameGoaway = 0x107,
    ErrHttpMalformatedFrameMaxPushId = 0x10d,
    ErrHttpMalformatedFrameDuplicatePush = 0x10e,

    ErrHttpNoMoreData,
    ErrHttpDecodingFrame,
    ErrHttpNotEnoughData,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum CError {
    Error(Error),
    HError(HError),
}

impl From<Error> for CError {
    fn from(err: Error) -> Self {
        CError::Error(err)
    }
}

impl From<HError> for CError {
    fn from(err: HError) -> Self {
        CError::HError(err)
    }
}

pub type Res<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {}
