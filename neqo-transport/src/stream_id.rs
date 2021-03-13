// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Stream ID and stream index handling.

use crate::fc::{ReceiverFlowControl, SenderFlowControl};
use crate::packet::PacketBuilder;
use crate::recovery::RecoveryToken;
use crate::stats::FrameStats;
use crate::{Error, Res};
use neqo_common::Role;
use std::ops::{Index, IndexMut};

#[derive(PartialEq, Debug, Copy, Clone, PartialOrd, Eq, Ord, Hash)]

/// The type of stream, either Bi-Directional or Uni-Directional.
pub enum StreamType {
    BiDi,
    UniDi,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, Ord, PartialOrd, Hash)]
pub struct StreamId(u64);

impl StreamId {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }

    pub fn is_bidi(self) -> bool {
        self.as_u64() & 0x02 == 0
    }

    pub fn is_uni(self) -> bool {
        !self.is_bidi()
    }

    pub fn stream_type(self) -> StreamType {
        if self.is_bidi() {
            StreamType::BiDi
        } else {
            StreamType::UniDi
        }
    }

    pub fn is_client_initiated(self) -> bool {
        self.as_u64() & 0x01 == 0
    }

    pub fn is_server_initiated(self) -> bool {
        !self.is_client_initiated()
    }

    pub fn role(self) -> Role {
        if self.is_client_initiated() {
            Role::Client
        } else {
            Role::Server
        }
    }

    pub fn is_self_initiated(self, my_role: Role) -> bool {
        match my_role {
            Role::Client if self.is_client_initiated() => true,
            Role::Server if self.is_server_initiated() => true,
            _ => false,
        }
    }

    pub fn is_remote_initiated(self, my_role: Role) -> bool {
        !self.is_self_initiated(my_role)
    }

    pub fn is_send_only(self, my_role: Role) -> bool {
        self.is_uni() && self.is_self_initiated(my_role)
    }

    pub fn is_recv_only(self, my_role: Role) -> bool {
        self.is_uni() && self.is_remote_initiated(my_role)
    }
}

impl From<u64> for StreamId {
    fn from(val: u64) -> Self {
        Self::new(val)
    }
}

impl PartialEq<u64> for StreamId {
    fn eq(&self, other: &u64) -> bool {
        self.as_u64() == *other
    }
}

impl ::std::fmt::Display for StreamId {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", self.as_u64())
    }
}

pub struct RemoteStreamsFlowControl {
    streams_fc: ReceiverFlowControl<StreamType>,
    next_stream: u64,
    stream_type_bits: u64,
}

impl RemoteStreamsFlowControl {
    pub fn new(stream_type: StreamType, max_streams: u64, role: Role) -> Self {
        let type_val = match stream_type {
            StreamType::BiDi => 0,
            StreamType::UniDi => 2,
        };
        // This is for a stream created by a peer, therefore the role bit is opposit.
        let role_val = match role {
            Role::Server => 0,
            Role::Client => 1,
        };

        Self {
            streams_fc: ReceiverFlowControl::new(stream_type, max_streams),
            next_stream: 0,
            stream_type_bits: type_val + role_val,
        }
    }

    pub fn write_frames(
        &mut self,
        builder: &mut PacketBuilder,
        tokens: &mut Vec<RecoveryToken>,
        stats: &mut FrameStats,
    ) -> Res<()> {
        self.streams_fc.write_frames(builder, tokens, stats)
    }

    pub fn is_new_stream(&mut self, stream_id: StreamId) -> Res<bool> {
        let stream_idx = stream_id.as_u64() >> 2;
        if !self.streams_fc.check_allowed(stream_idx) {
            return Err(Error::StreamLimitError);
        }
        Ok(stream_idx >= self.next_stream)
    }

    pub fn add_stream(&mut self) -> Option<StreamId> {
        let new_stream = self.next_stream;
        self.next_stream += 1;
        assert!(self.streams_fc.check_allowed(new_stream));
        Some(StreamId::from((new_stream << 2) + self.stream_type_bits))
    }

    pub fn send_flowc_update(&mut self) {
        self.streams_fc.send_flowc_update();
    }

    pub fn max_streams_lost(&mut self, max_streams: u64) {
        self.streams_fc.lost(max_streams);
    }

    pub fn add_retired(&mut self, removed: u64) {
        self.streams_fc.add_retired(removed);
        if removed > 0 {
            // Send a update immediately.
            self.streams_fc.send_flowc_update();
        }
    }
}

pub struct RemoteStreamsFlowControls([RemoteStreamsFlowControl; 2]);

impl RemoteStreamsFlowControls {
    pub fn new(local_max_stream_bidi: u64, local_max_stream_uni: u64, role: Role) -> Self {
        Self([
            RemoteStreamsFlowControl::new(StreamType::BiDi, local_max_stream_bidi, role),
            RemoteStreamsFlowControl::new(StreamType::UniDi, local_max_stream_uni, role),
        ])
    }
}

impl Index<StreamType> for RemoteStreamsFlowControls {
    type Output = RemoteStreamsFlowControl;

    fn index(&self, idx: StreamType) -> &Self::Output {
        match idx {
            StreamType::BiDi => &self.0[0],
            StreamType::UniDi => &self.0[1],
        }
    }
}

impl IndexMut<StreamType> for RemoteStreamsFlowControls {
    fn index_mut(&mut self, idx: StreamType) -> &mut Self::Output {
        match idx {
            StreamType::BiDi => &mut self.0[0],
            StreamType::UniDi => &mut self.0[1],
        }
    }
}

pub struct LocalStreamsFlowControls {
    fc: [SenderFlowControl<StreamType>; 2],
    role_bit: u64,
}

impl LocalStreamsFlowControls {
    pub fn new(role: Role) -> Self {
        Self {
            fc: [
                SenderFlowControl::new(StreamType::BiDi, 0),
                SenderFlowControl::new(StreamType::UniDi, 0),
            ],
            role_bit: match role {
                Role::Server => 1,
                Role::Client => 0,
            },
        }
    }

    pub fn add_stream(&mut self, stream_type: StreamType) -> Option<StreamId> {
        let fc = match stream_type {
            StreamType::BiDi => &mut self.fc[0],
            StreamType::UniDi => &mut self.fc[1],
        };
        if fc.available() > 0 {
            let new_stream = fc.used();
            fc.consume(1);
            let type_bit = match stream_type {
                StreamType::BiDi => 0,
                StreamType::UniDi => 2,
            };
            Some(StreamId::from((new_stream << 2) + type_bit + self.role_bit))
        } else {
            None
        }
    }
}

impl Index<StreamType> for LocalStreamsFlowControls {
    type Output = SenderFlowControl<StreamType>;

    fn index(&self, idx: StreamType) -> &Self::Output {
        match idx {
            StreamType::BiDi => &self.fc[0],
            StreamType::UniDi => &self.fc[1],
        }
    }
}

impl IndexMut<StreamType> for LocalStreamsFlowControls {
    fn index_mut(&mut self, idx: StreamType) -> &mut Self::Output {
        match idx {
            StreamType::BiDi => &mut self.fc[0],
            StreamType::UniDi => &mut self.fc[1],
        }
    }
}

#[cfg(test)]
mod test {
    use super::{LocalStreamsFlowControls, RemoteStreamsFlowControls, StreamId, StreamType};
    use crate::packet::PacketBuilder;
    use crate::stats::FrameStats;
    use crate::Error;
    use neqo_common::{Encoder, Role};

    #[test]
    fn bidi_stream_properties() {
        let id1 = StreamId::from(16);
        assert_eq!(id1.is_bidi(), true);
        assert_eq!(id1.is_uni(), false);
        assert_eq!(id1.is_client_initiated(), true);
        assert_eq!(id1.is_server_initiated(), false);
        assert_eq!(id1.role(), Role::Client);
        assert_eq!(id1.is_self_initiated(Role::Client), true);
        assert_eq!(id1.is_self_initiated(Role::Server), false);
        assert_eq!(id1.is_remote_initiated(Role::Client), false);
        assert_eq!(id1.is_remote_initiated(Role::Server), true);
        assert_eq!(id1.is_send_only(Role::Server), false);
        assert_eq!(id1.is_send_only(Role::Client), false);
        assert_eq!(id1.is_recv_only(Role::Server), false);
        assert_eq!(id1.is_recv_only(Role::Client), false);
        assert_eq!(id1.as_u64(), 16);
    }

    #[test]
    fn uni_stream_properties() {
        let id2 = StreamId::from(35);
        assert_eq!(id2.is_bidi(), false);
        assert_eq!(id2.is_uni(), true);
        assert_eq!(id2.is_client_initiated(), false);
        assert_eq!(id2.is_server_initiated(), true);
        assert_eq!(id2.role(), Role::Server);
        assert_eq!(id2.is_self_initiated(Role::Client), false);
        assert_eq!(id2.is_self_initiated(Role::Server), true);
        assert_eq!(id2.is_remote_initiated(Role::Client), true);
        assert_eq!(id2.is_remote_initiated(Role::Server), false);
        assert_eq!(id2.is_send_only(Role::Server), true);
        assert_eq!(id2.is_send_only(Role::Client), false);
        assert_eq!(id2.is_recv_only(Role::Server), false);
        assert_eq!(id2.is_recv_only(Role::Client), true);
        assert_eq!(id2.as_u64(), 35);
    }

    #[test]
    fn local_streams_flow_control_new_stream_client() {
        let mut fc = RemoteStreamsFlowControls::new(2, 1, Role::Client);
        assert!(fc[StreamType::BiDi]
            .is_new_stream(StreamId::from(1))
            .unwrap());
        assert!(fc[StreamType::BiDi]
            .is_new_stream(StreamId::from(5))
            .unwrap());
        assert!(fc[StreamType::UniDi]
            .is_new_stream(StreamId::from(3))
            .unwrap());

        // Exeed limits
        assert_eq!(
            fc[StreamType::BiDi].is_new_stream(StreamId::from(9)),
            Err(Error::StreamLimitError)
        );
        assert_eq!(
            fc[StreamType::UniDi].is_new_stream(StreamId::from(7)),
            Err(Error::StreamLimitError)
        );

        assert_eq!(
            fc[StreamType::BiDi].add_stream().unwrap(),
            StreamId::from(1)
        );
        assert_eq!(
            fc[StreamType::BiDi].add_stream().unwrap(),
            StreamId::from(5)
        );
        assert_eq!(
            fc[StreamType::UniDi].add_stream().unwrap(),
            StreamId::from(3)
        );

        fc[StreamType::BiDi].add_retired(1);
        // consume the frame
        let mut builder = PacketBuilder::short(Encoder::new(), false, &[]);
        let mut token = Vec::new();
        fc[StreamType::BiDi]
            .write_frames(&mut builder, &mut token, &mut FrameStats::default())
            .unwrap();
        // Now 9 can be a new StreamId.
        assert!(fc[StreamType::BiDi]
            .is_new_stream(StreamId::from(9))
            .unwrap());
        assert_eq!(
            fc[StreamType::BiDi].add_stream().unwrap(),
            StreamId::from(9)
        );
        // 13 exeeds limits
        assert_eq!(
            fc[StreamType::BiDi].is_new_stream(StreamId::from(13)),
            Err(Error::StreamLimitError)
        );

        fc[StreamType::UniDi].add_retired(1);
        // consume the frame
        fc[StreamType::UniDi]
            .write_frames(&mut builder, &mut token, &mut FrameStats::default())
            .unwrap();

        // Now 7 can be a new StreamId.
        assert!(fc[StreamType::UniDi]
            .is_new_stream(StreamId::from(7))
            .unwrap());
        assert_eq!(
            fc[StreamType::UniDi].add_stream().unwrap(),
            StreamId::from(7)
        );
        // 11 exeeds limits
        assert_eq!(
            fc[StreamType::UniDi].is_new_stream(StreamId::from(11)),
            Err(Error::StreamLimitError)
        );
    }

    #[test]
    fn local_streams_flow_control_new_stream_server() {
        let mut fc = RemoteStreamsFlowControls::new(2, 1, Role::Server);
        assert!(fc[StreamType::BiDi]
            .is_new_stream(StreamId::from(0))
            .unwrap());
        assert!(fc[StreamType::BiDi]
            .is_new_stream(StreamId::from(4))
            .unwrap());
        assert!(fc[StreamType::UniDi]
            .is_new_stream(StreamId::from(2))
            .unwrap());

        // Exeed limits
        assert_eq!(
            fc[StreamType::BiDi].is_new_stream(StreamId::from(8)),
            Err(Error::StreamLimitError)
        );
        assert_eq!(
            fc[StreamType::UniDi].is_new_stream(StreamId::from(6)),
            Err(Error::StreamLimitError)
        );

        assert_eq!(
            fc[StreamType::BiDi].add_stream().unwrap(),
            StreamId::from(0)
        );
        assert_eq!(
            fc[StreamType::BiDi].add_stream().unwrap(),
            StreamId::from(4)
        );
        assert_eq!(
            fc[StreamType::UniDi].add_stream().unwrap(),
            StreamId::from(2)
        );

        fc[StreamType::BiDi].add_retired(1);
        // consume the frame
        let mut builder = PacketBuilder::short(Encoder::new(), false, &[]);
        let mut token = Vec::new();
        fc[StreamType::BiDi]
            .write_frames(&mut builder, &mut token, &mut FrameStats::default())
            .unwrap();
        // Now 8 can be a new StreamId.
        assert!(fc[StreamType::BiDi]
            .is_new_stream(StreamId::from(8))
            .unwrap());
        assert_eq!(
            fc[StreamType::BiDi].add_stream().unwrap(),
            StreamId::from(8)
        );
        // 12 exeeds limits
        assert_eq!(
            fc[StreamType::BiDi].is_new_stream(StreamId::from(12)),
            Err(Error::StreamLimitError)
        );

        fc[StreamType::UniDi].add_retired(1);
        // consume the frame
        fc[StreamType::UniDi]
            .write_frames(&mut builder, &mut token, &mut FrameStats::default())
            .unwrap();
        // Now 6 can be a new StreamId.
        assert!(fc[StreamType::UniDi]
            .is_new_stream(StreamId::from(6))
            .unwrap());
        assert_eq!(
            fc[StreamType::UniDi].add_stream().unwrap(),
            StreamId::from(6)
        );
        // 10 exeeds limits
        assert_eq!(
            fc[StreamType::UniDi].is_new_stream(StreamId::from(10)),
            Err(Error::StreamLimitError)
        );
    }

    #[test]
    fn remote_streams_flow_control_new_stream_client() {
        let mut fc = LocalStreamsFlowControls::new(Role::Client);

        fc[StreamType::BiDi].update(2);
        fc[StreamType::UniDi].update(1);

        // Add streams
        assert_eq!(fc.add_stream(StreamType::BiDi).unwrap(), StreamId::from(0));
        assert_eq!(fc.add_stream(StreamType::BiDi).unwrap(), StreamId::from(4));
        assert_eq!(fc.add_stream(StreamType::BiDi), None);
        assert_eq!(fc.add_stream(StreamType::UniDi).unwrap(), StreamId::from(2));
        assert_eq!(fc.add_stream(StreamType::UniDi), None);

        // Increase limit
        fc[StreamType::BiDi].update(3);
        fc[StreamType::UniDi].update(2);
        assert_eq!(fc.add_stream(StreamType::BiDi).unwrap(), StreamId::from(8));
        assert_eq!(fc.add_stream(StreamType::BiDi), None);
        assert_eq!(fc.add_stream(StreamType::UniDi).unwrap(), StreamId::from(6));
        assert_eq!(fc.add_stream(StreamType::UniDi), None);
    }

    #[test]
    fn remote_streams_flow_control_new_stream_server() {
        let mut fc = LocalStreamsFlowControls::new(Role::Server);

        fc[StreamType::BiDi].update(2);
        fc[StreamType::UniDi].update(1);

        // Add streams
        assert_eq!(fc.add_stream(StreamType::BiDi).unwrap(), StreamId::from(1));
        assert_eq!(fc.add_stream(StreamType::BiDi).unwrap(), StreamId::from(5));
        assert_eq!(fc.add_stream(StreamType::BiDi), None);
        assert_eq!(fc.add_stream(StreamType::UniDi).unwrap(), StreamId::from(3));
        assert_eq!(fc.add_stream(StreamType::UniDi), None);

        // Increase limit
        fc[StreamType::BiDi].update(3);
        fc[StreamType::UniDi].update(2);
        assert_eq!(fc.add_stream(StreamType::BiDi).unwrap(), StreamId::from(9));
        assert_eq!(fc.add_stream(StreamType::BiDi), None);
        assert_eq!(fc.add_stream(StreamType::UniDi).unwrap(), StreamId::from(7));
        assert_eq!(fc.add_stream(StreamType::UniDi), None);
    }
}
