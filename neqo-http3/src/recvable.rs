use neqo_common::qinfo;
use neqo_common::readbuf::Reader;
use neqo_transport::Recvable;

// A simple wrapper that wraps a Recvable so that it can be used with ReadBuf.
#[derive(Debug)]
pub struct RecvableWrapper<'a>(&'a mut Recvable);

impl<'a> RecvableWrapper<'a> {
    pub fn wrap(r: &'a mut Recvable) -> RecvableWrapper<'a> {
        RecvableWrapper(r)
    }
}

impl<'a> Reader for RecvableWrapper<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<(usize, bool), ::neqo_common::Error> {
        match self.0.read(buf) {
            Ok((amount, end)) => Ok((amount as usize, end)),
            Err(e) => {
                qinfo!("Read error {}", e); // TODO(mt): provide context.
                Err(::neqo_common::Error::ReadError)
            }
        }
    }
}
