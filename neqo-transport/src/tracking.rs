#![allow(dead_code)]
use neqo_crypto::constants::Epoch;
use std::cmp::{max, min};
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct PacketRange {
    pub largest: u64,
    pub length: u64,
}

impl PacketRange {
    pub fn smallest(&self) -> u64 {
        self.largest - (self.length - 1)
    }
}

#[derive(Debug, Default)]
struct PacketMeta {
    pn: u64,
    //    non_acks: bool,
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
    pub fn new<S: ToString>(label: S, epoch: Epoch, pn: u64) -> Self {
        RecvdPackets {
            label: label.to_string() + &format!("[Tracking epoch={}]", epoch),
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
        self.unacked = non_acks;

        self.packets.insert(
            pn,
            PacketMeta {
                pn: pn,
                //                non_acks: non_acks,
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

    pub fn get_eligible_ack_ranges(&mut self) -> Vec<PacketRange> {
        qinfo!(self, "Getting eligible ack ranges {:?}", self);
        if !self.unacked {
            return vec![];
        }

        // TODO(ekr@rtfm.com): Need a more sophisticated algorithm
        // for bare ACKs. Right now, we just don't give you any
        // ACKs if there are no ACKs for non-ACK-eliciting packets.
        // This is not an efficient algorithm, copied from Minq, so
        // of course it's awesome.
        let mut last = 0_u64;
        let mut inrange = false;
        let mut pn = self.max_received;
        let mut new_min_not_acked2 = self.max_received;
        let mut ranges = vec![];

        loop {
            qtrace!(self, "Examining PN={}, inrange={}", pn, inrange);
            let mut needs_ack = false;

            match self.packets.get(&pn) {
                None => {
                    qtrace!(self, "Packet {} does not need acking", pn);
                }
                Some(packet) => {
                    if !packet.acked2 {
                        qtrace!(self, "Packet {} needs acking", pn);
                        needs_ack = true;
                        new_min_not_acked2 = pn;
                    }
                }
            }

            match (inrange, needs_ack) {
                (true, false) => {
                    // We are at the end of a range.
                    qtrace!(self, "End of a range");
                    ranges.push(PacketRange {
                        largest: last,
                        length: last - pn,
                    });
                    inrange = false;
                }
                (false, true) => {
                    // We are now at the beginning of a range.
                    qtrace!(self, "Beginning of a range");
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
            ranges.push(PacketRange {
                largest: last,
                length: (last - pn) + 1,
            });
        }
        self.min_not_acked2 = new_min_not_acked2;

        self.unacked = false;
        return ranges;
    }
}

impl ::std::fmt::Display for RecvdPackets {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", self.label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn test_ack_range(pns: Vec<u64>, nranges: usize) {
        let mut rp = RecvdPackets::new("[label]", 0, pns[0]);
        let mut packets = HashSet::new();
        let mut packets2 = HashSet::new();

        for pn in pns {
            rp.set_received(0, pn, true);
            packets.insert(pn);
        }

        println!("ReceivedPackets: {:?}", rp);
        let ranges = rp.get_eligible_ack_ranges();

        println!("ACK ranges: {:?}", ranges);
        assert_eq!(ranges.len(), nranges);
        for range in ranges {
            for offset in 0..range.length {
                packets2.insert(range.largest - offset);
            }
        }

        assert_eq!(packets, packets2);
    }

    #[test]
    fn test_single_packet_zero() {
        test_ack_range(vec![0], 1);
    }

    #[test]
    fn test_single_packet_one() {
        test_ack_range(vec![1], 1);
    }

    #[test]
    fn test_two_ranges() {
        test_ack_range(vec![0, 1, 2, 5, 6, 7], 2);
    }

    #[test]
    fn test_one_range_fill_in() {
        test_ack_range(vec![0, 1, 2, 5, 6, 7, 3, 4], 1);
    }

    #[test]
    fn test_two_acks() {
        let mut rp = RecvdPackets::new("[label]", 0, 0);
        rp.set_received(0, 0, true);
        let ranges = rp.get_eligible_ack_ranges();
        assert_eq!(ranges.len(), 1);
        let ranges = rp.get_eligible_ack_ranges();
        assert_eq!(ranges.len(), 0);
    }

    #[test]
    fn test_ack_only() {
        let mut rp = RecvdPackets::new("[label]", 0, 0);
        rp.set_received(0, 0, false);
        let ranges = rp.get_eligible_ack_ranges();
        assert_eq!(ranges.len(), 0);
    }

}
