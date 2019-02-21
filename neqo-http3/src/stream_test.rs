use neqo_transport::Res;
use neqo_transport::connection::Role;
use neqo_transport::frame::StreamType;

pub enum StreamTypeWithRole {
  ClientBiDi,
  ServerBiDi,
  ClientUniDi,
  ServerUniDi,
}

pub fn get_stream_type(r: Role, st: StreamType) -> StreamTypeWithRole {
  if r == Role::Client {
    if st == StreamType::UniDi {
      StreamTypeWithRole::ClientUniDi
    } else {
      StreamTypeWithRole::ClientBiDi
    }
  } else {
    if st == StreamType::UniDi {
      StreamTypeWithRole::ServerUniDi
    } else {
      StreamTypeWithRole::ServerBiDi
    }
  }
}

pub struct Stream {
  send_side_fin: bool,
  receive_side_fin: bool,
  stream_type: StreamTypeWithRole,
}

impl Stream{
  pub fn new(st: StreamTypeWithRole) -> Stream {
    Stream { send_side_fin: false, receive_side_fin: false, stream_type: st }
  }
pub fn send(&mut self, buf: &[u8], close: bool) -> u64 {
  buf.len() as u64
}
pub fn get_received_data(&mut self, buf: &mut [u8]) -> Res<u64> {
  Ok(buf.len() as u64)
}
}
