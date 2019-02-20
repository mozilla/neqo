use std::net::SocketAddr;

pub enum InterfaceError {
  NOT_IMPLEMENTED,
}

pub struct ConnState {

}

pub struct StreamInfo {
  readable_streams: Vec<u64>,
  writable_streams: Vec<u64>,
  new_streams: Vec<u64>,
  closed_streams: Vec<u64>
}
 
pub struct StateInfo {
   pub state: ConnState,
   pub stream_info: StreamInfo,
   pub datagram: Vec<u8>,
   pub path: SocketAddr
}

impl StreamInfo {
  pub fn new() -> StreamInfo {
    StreamInfo {
      readable_streams: Vec::new(),
      writable_streams: Vec::new(),
      new_streams: Vec::new(),
      closed_streams: Vec::new()
     }
  }
}

pub struct StreamStateQuery {
  readable_streams: Vec<u64>,
  writable_streams: Vec<u64>
}

pub trait QInterface<T> {
  fn incoming_datagram(&mut self, path: SocketAddr, frame: &[u8], time: u64, streamStateQuery: StreamStateQuery) -> std::result::Result<StateInfo, InterfaceError>;

  fn GetStream(&self, streamId: u64) -> Option<&T>;
}
