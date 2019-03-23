#![allow(dead_code)]
use std::cmp::{max, min};
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct AckRange {
    pub largest: u64,
    pub length: u64,
}

#[derive(Debug, Default)]
struct PacketMeta {
    pn: u64,
    non_acks: bool,
    t: u64,
    acked2: bool,
}

#[derive(Debug)]
pub struct RecvdPackets {
    label: String,
    packets: HashMap<u64, PacketMeta>,
    min_received: u64,
    max_received: u64,
    min_not_acked2: u64,
    unacked: bool, // Are there packets we haven't ACKed yet
}

impl RecvdPackets {
    pub fn new<S: ToString>(label: S, pn: u64) -> Self {
        RecvdPackets {
            label: label.to_string() + "[Tracking]",
            packets: HashMap::new(),
            min_received: pn,
            max_received: pn,
            min_not_acked2: pn,
            unacked: false,
        }
    }

    pub fn label(&self) -> String {
        return self.label.clone();
    }

    pub fn set_received(&mut self, now: u64, pn: u64, non_acks: bool) {
        assert!(!self.packets.contains_key(&pn));
        self.max_received = max(self.max_received, pn);
        self.min_not_acked2 = min(self.min_not_acked2, pn);
        self.unacked = true;

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

    pub fn get_eligible_ack_ranges(&mut self, allow_ack_only: bool) -> Vec<AckRange> {
        qinfo!(self, "Getting eligible ack ranges {:?}", self);
        if !self.unacked {
            return vec![];
        }

        // This is not an efficient algorithm, copied from Minq, so
        // of course it's awesome.
        let mut last = 0_u64;
        let mut inrange = false;
        let mut non_acks = false;
        let mut pn = self.max_received;
        let mut new_min_not_acked2 = self.max_received;
        let mut ranges = vec![];

        loop {
            qtrace!(self, "Examining PN={}, inrange={}", pn, inrange);
            let mut needs_ack = false;

            match self.packets.get(&pn) {
                None => {}
                Some(packet) => {
                    if !packet.acked2 {
                        qtrace!(self, "Packet {} needs acking", pn);
                        needs_ack = true;
                        new_min_not_acked2 = pn;
                        if packet.non_acks {
                            non_acks = true;
                        }
                    }
                }
            }

            match (inrange, needs_ack) {
                (true, false) => {
                    // We are at the end of a range.
                    ranges.push(AckRange {
                        largest: pn,
                        length: last - pn,
                    });
                    inrange = false;
                }
                (false, true) => {
                    // We are now at the beginning of a range.
                    last = pn;
                    inrange = true;
                }
                _ => {}
            }

            if pn < self.min_not_acked2 || pn == 0 {
                break;
            }

            pn -= 1;
        }

        // If we're in a range, we need to add a final range.
        if inrange {
            ranges.push(AckRange {
                largest: last,
                length: last - pn,
            });
        }
        self.min_not_acked2 = new_min_not_acked2;

        if !allow_ack_only && !non_acks {
            return vec![];
        }

        self.unacked = false;
        return ranges;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn test_ack_range(pns: Vec<u64>) {
        let mut rp = RecvdPackets::new("[label]", pns[0]);
        let mut packets = HashSet::new();
        let mut packets2 = HashSet::new();

        for pn in pns {
            rp.set_received(0, pn, false);
            packets.insert(pn);
        }

        println!("ReceivedPackets: {:?}", rp);
        let ranges = rp.get_eligible_ack_ranges(true);

        println!("ACK ranges: {:?}", ranges);
        for range in ranges {
            for offset in 0..range.length + 1 {
                packets2.insert(range.largest - offset);
            }
        }

        assert_eq!(packets, packets2);
    }

    #[test]
    fn test_single_packet_range() {
        test_ack_range(vec![0]);
    }
}
