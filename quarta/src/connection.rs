use crate::data::Data;
use crate::frame::{decode_frame, Frame};
use crate::Res;

#[allow(unused_variables)]
#[derive(Debug)]
pub struct Connection {}

impl Connection {
    pub fn new() -> Connection {
        Connection {}
    }
    pub fn process_datagram(datagram: &[u8]) -> Res<Frame> {
        let mut data = Data::from_slice(datagram);
        let frame = decode_frame(&mut data)?;
        Ok(frame)
    }
}
