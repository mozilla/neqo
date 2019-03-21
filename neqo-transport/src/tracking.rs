#![allow(dead_code)]
use std::cmp::{max, min};
use std::collections::HashMap;

#[derive(Debug, Default)]
struct PacketMeta {
    pn: u64,
    non_acks: bool,
    t: u64,
    acked2: bool,
}

#[derive(Debug)]
pub struct RecvdPackets {
    packets: HashMap<u64, PacketMeta>,
    min_received: u64,
    max_received: u64,
    min_not_acked2: u64,
    unacked: bool, // Are there packets we haven't ACKed yet
}

impl RecvdPackets {
    pub fn new(pn: u64) -> Self {
        RecvdPackets {
            packets: HashMap::new(),
            min_received: pn,
            max_received: pn,
            min_not_acked2: pn,
            unacked: false,
        }
    }

    pub fn set_received(&mut self, now: u64, pn: u64, non_acks: bool) {
        assert!(!self.packets.contains_key(&pn));
        self.max_received = max(self.max_received, pn);
        self.min_not_acked2 = min(self.min_not_acked2, pn);
        self.packets.insert(
            pn,
            PacketMeta {
                pn: pn,
                non_acks: non_acks,
                t: now,
                acked2: false,
            },
        );
    }

    pub fn was_received(&self, pn: u64) -> bool {
        if pn < self.min_received {
            return true;
        }
        self.packets.contains_key(&pn)
    }

    pub fn set_acked2(&mut self, pn: u64) {
        if pn >= self.min_not_acked2 {}
    }
}
