#![allow(unused_variables, dead_code)]

use crate::header_read_buf::read_prefixed_encoded_int_with_recvable;
use crate::qpack_send_buf::QPData;
use crate::table::HeaderTable;
use crate::{Error, Res};
use neqo_transport::stream::{Recvable, Sendable};

enum DecoderInstructions {
    InsertCountIncrement,
    HeaderAck,
    StreamCancellation,
}

fn get_instruction(b: u8) -> DecoderInstructions {
    if (b & 0xc0) == 0 {
        DecoderInstructions::InsertCountIncrement
    } else if (b & 0x80) != 0 {
        DecoderInstructions::HeaderAck
    } else {
        DecoderInstructions::StreamCancellation
    }
}

struct QPackEncoder {
    table: HeaderTable,
    send_buf: QPData,
    max_entries: u64,
    instruction_reader_current_inst: Option<DecoderInstructions>,
    instruction_reader_value: u64, // this is instrunction dependent value.
    instruction_reader_cnt: u8, // this is helper variable for reading a prefixed integer encoded value
}

impl QPackEncoder {
    pub fn new(capacity: u64) -> QPackEncoder {
        QPackEncoder {
            table: HeaderTable::new(capacity, true),
            send_buf: QPData::default(),
            max_entries: 0,
            instruction_reader_current_inst: None,
            instruction_reader_value: 0,
            instruction_reader_cnt: 0,
        }
    }

    pub fn set_max_capacity(&mut self, cap: u64) {
        self.max_entries = (cap as f64 / 32.0).floor() as u64;
    }

    pub fn read_instructions(&mut self, s: &mut Recvable) -> Res<()> {
        loop {
            match self.instruction_reader_current_inst {
                None => {
                    // get new instruction
                    let mut b = [0];
                    match s.read(&mut b) {
                        Err(_) => break Err(Error::EncoderStreamError),
                        Ok((amount, fin)) => {
                            if fin {
                                break Err(Error::ClosedCriticalStream);
                            }
                            if amount != 1 {
                                // wait for more data.
                                break Ok(());
                            }
                        }
                    }
                    self.instruction_reader_current_inst = Some(get_instruction(b[0]));

                    // try to read data
                    let prefix_len = if (b[0] & 0x80) != 0 { 1 } else { 2 };
                    match read_prefixed_encoded_int_with_recvable(
                        s,
                        &mut self.instruction_reader_value,
                        &mut self.instruction_reader_cnt,
                        prefix_len,
                        b[0],
                        true,
                    ) {
                     Ok(done) => {
                        if done {
                            self.call_instruction();
                        } else {
                            // wait for more data.
                            break Ok(());
                        }
                     },
                     Err(Error::ClosedCriticalStream) => break Err(Error::ClosedCriticalStream),
                     Err(_) => break Err(Error::EncoderStreamError),
                    }
                }
                Some(_) => {
                    match read_prefixed_encoded_int_with_recvable(
                        s,
                        &mut self.instruction_reader_value,
                        &mut self.instruction_reader_cnt,
                        0,
                        0x0,
                        false,
                    ) {
                     Ok(done) => {
                        if done {
                            self.call_instruction();
                        } else {
                            // wait for more data.
                            break Ok(());
                        }
                    },
                    Err(Error::ClosedCriticalStream) =>  break Err(Error::ClosedCriticalStream),
                    Err(_) => break Err(Error::EncoderStreamError),
                    }
                }
            }
        }
    }

    fn call_instruction(&mut self) {
        if let Some(inst) = &self.instruction_reader_current_inst {
            match inst {
                DecoderInstructions::InsertCountIncrement => {
                    self.table.increment_acked(self.instruction_reader_value)
                }
                DecoderInstructions::HeaderAck => {
                    self.table.header_ack(self.instruction_reader_value)
                }
                DecoderInstructions::StreamCancellation => {
                    self.table.header_ack(self.instruction_reader_value)
                }
            }
            self.instruction_reader_current_inst = None;
            self.instruction_reader_value = 0;
            self.instruction_reader_cnt = 0;
        } else {
            panic!("We must have a instruction decoded beforewe call call_instruction");
        }
    }

    pub fn insert_with_name_ref(
        &mut self,
        name_static_table: bool,
        name_index: u64,
        value_is_huffman: bool,
        value: Vec<u8>,
    ) -> Res<()> {
        self.table
            .insert_with_name_ref(name_static_table, name_index, value_is_huffman, value)?;

        // write instruction
        let entry = self.table.get_last_added_entry().unwrap();
        let instr = 0x80 | (if name_static_table { 0x40 } else { 0x00 });
        self.send_buf
            .encode_prefixed_encoded_int(instr, 2, name_index);
        self.send_buf.encode_prefixed_encoded_int(
            if value_is_huffman { 0x80 } else { 0x00 },
            1,
            entry.value().len() as u64,
        );
        self.send_buf.write_bytes(&entry.value());
        Ok(())
    }

    pub fn insert_with_name_literal(
        &mut self,
        name_is_huffman: bool,
        name: Vec<u8>,
        value_is_huffman: bool,
        value: Vec<u8>,
    ) -> Res<()> {
        // try to inser a new entry
        self.table.insert(name, value)?;

        let entry = self.table.get_last_added_entry().unwrap();
        // encode instruction.
        self.send_buf.encode_prefixed_encoded_int(
            if name_is_huffman { 0x60 } else { 0x40 },
            3,
            entry.name().len() as u64,
        );
        self.send_buf.write_bytes(entry.name());
        self.send_buf.encode_prefixed_encoded_int(
            if value_is_huffman { 0x80 } else { 0x00 },
            1,
            entry.value().len() as u64,
        );
        self.send_buf.write_bytes(entry.value());
        Ok(())
    }

    pub fn duplicate(&mut self, index: u64) -> Res<()> {
        self.table.duplicate(index)?;
        self.send_buf.encode_prefixed_encoded_int(0x00, 3, index);
        Ok(())
    }

    pub fn change_capacity(&mut self, cap: u64) {
        self.table.set_capacity(cap);
        self.send_buf.encode_prefixed_encoded_int(0x20, 3, cap);
    }

    pub fn write(&mut self, s: &mut Sendable) -> Res<()> {
        match s.send(self.send_buf.as_mut_vec()) {
            Err(_) => Err(Error::EncoderStreamError),
            Ok(r) => {
                self.send_buf.read(r as usize);
                Ok(())
            }
        }
    }

    pub fn encode_header_block(&mut self, h: &Vec<(String, String)>, stream_id: u64) -> QPData {
        let mut encoded_h = QPData::default();
        let base = self.table.base();
        let mut req_insert_cnt = 0;
        self.encode_header_block_prefix(&mut encoded_h, false, 0, base, true);
        for iter in h.iter() {
            let name = iter.0.clone().into_bytes();
            let value = iter.1.clone().into_bytes();

            let mut can_use = false;
            let mut index: u64 = 0;
            let mut value_as_well = false;
            let mut is_dynamic = false;
            {
                // this is done in this way because otherwise it is complaining about mut borrow. TODO: look if we can do this better
                let (e_s, e_d, found_value) = self.table.lookup(&name, &value);
                if let Some(entry) = e_s {
                    can_use = true; //can_use(index); TODO
                    if can_use {
                        index = entry.index();
                        value_as_well = found_value;
                    }
                }
                if !can_use {
                    if let Some(entry) = e_d {
                        can_use = true; //can_use(index); TODO
                        if can_use {
                            index = entry.index();
                            value_as_well = found_value;
                            is_dynamic = true;
                            entry.add_ref(stream_id, 1);
                        }
                    }
                }
            }
            if can_use {
                if value_as_well {
                    if !is_dynamic {
                        self.encode_indexed(&mut encoded_h, index, false);
                    } else if index < base {
                        self.encode_indexed(&mut encoded_h, base - index - 1, true);
                    } else {
                        self.encode_post_base_index(&mut encoded_h, index - base);
                    }
                    if is_dynamic && req_insert_cnt < (index + 1) {
                        req_insert_cnt = index + 1;
                    }
                    continue;
                } else {
                    if !is_dynamic {
                        self.encode_literal_with_name_ref(&mut encoded_h, index, false, &value);
                    } else if index < base {
                        self.encode_literal_with_name_ref(
                            &mut encoded_h,
                            base - index - 1,
                            true,
                            &value,
                        );
                    } else {
                        self.encode_literal_with_post_based_name_ref(
                            &mut encoded_h,
                            index - base,
                            &value,
                        );
                    }

                    if is_dynamic && req_insert_cnt < (index + 1) {
                        req_insert_cnt = index + 1;
                    }
                    continue;
                }
            }

            let name2 = name.clone();
            let value2 = value.clone();
            match self.insert_with_name_literal(false, name2, false, value2) {
                Err(_) => {
                    self.encode_literal_with_name_literal(&mut encoded_h, &name, &value);
                }
                Ok(()) => {
                    let index: u64;
                    {
                        let entry = self.table.get_last_added_entry().unwrap();
                        entry.add_ref(stream_id, 1);
                        index = entry.index();
                    }
                    self.encode_post_base_index(&mut encoded_h, index - base);

                    req_insert_cnt = index + 1;
                }
            }
        }
        if req_insert_cnt > 0 {
            self.fix_header_block_prefix(&mut encoded_h, base, req_insert_cnt);
        }
        encoded_h
    }

    fn encode_header_block_prefix(
        &self,
        buf: &mut QPData,
        fix: bool,
        req_insert_cnt: u64,
        delta: u64,
        positive: bool,
    ) {
        let mut enc_insert_cnt = 0;
        if req_insert_cnt != 0 {
            enc_insert_cnt = (req_insert_cnt % (2 * self.max_entries)) + 1;
        }

        let mut offset = 0; // this is for fixing header_block only.
        if !fix {
            buf.encode_prefixed_encoded_int(0x0, 0, enc_insert_cnt);
        } else {
            // TODO fix for case when there is no enough space!!!
            offset = buf.encode_prefixed_encoded_int_fix(0, 0x0, 0, enc_insert_cnt);
        }
        let prefix = if positive { 0x00 } else { 0x80 };
        if !fix {
            buf.encode_prefixed_encoded_int(prefix, 1, delta);
        } else {
            let _ = buf.encode_prefixed_encoded_int_fix(offset, prefix, 1, delta);
        }
    }

    fn fix_header_block_prefix(&self, buf: &mut QPData, base: u64, req_insert_cnt: u64) {
        if req_insert_cnt > 0 {
            if req_insert_cnt <= base {
                self.encode_header_block_prefix(
                    buf,
                    true,
                    req_insert_cnt,
                    base - req_insert_cnt,
                    true,
                );
            } else {
                self.encode_header_block_prefix(
                    buf,
                    true,
                    req_insert_cnt,
                    req_insert_cnt - base - 1,
                    false,
                );
            }
        }
    }

    fn encode_indexed(&self, buf: &mut QPData, index: u64, is_dynamic: bool) {
        let prefix = if is_dynamic { 0x80 } else { 0xc0 };
        buf.encode_prefixed_encoded_int(prefix, 2, index);
    }

    fn encode_literal_with_name_ref(
        &self,
        buf: &mut QPData,
        index: u64,
        is_dynamic: bool,
        value: &[u8],
    ) {
        let prefix = if is_dynamic { 0x40 } else { 0x50 };
        buf.encode_prefixed_encoded_int(prefix, 4, index);
        buf.encode_prefixed_encoded_int(0x00, 1, value.len() as u64);
        buf.write_bytes(value);
    }

    fn encode_post_base_index(&self, buf: &mut QPData, index: u64) {
        buf.encode_prefixed_encoded_int(0x10, 4, index);
    }

    fn encode_literal_with_post_based_name_ref(&self, buf: &mut QPData, index: u64, value: &[u8]) {
        buf.encode_prefixed_encoded_int(0x00, 5, index);
        buf.encode_prefixed_encoded_int(0x00, 1, value.len() as u64);
        buf.write_bytes(value);
    }

    fn encode_literal_with_name_literal(&self, buf: &mut QPData, name: &[u8], value: &[u8]) {
        buf.encode_prefixed_encoded_int(0x00, 1, name.len() as u64);
        buf.write_bytes(name);
        buf.encode_prefixed_encoded_int(0x00, 1, value.len() as u64);
        buf.write_bytes(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neqo_transport::connection::TxMode;
    use neqo_transport::{AppError, Res};

    #[derive(Debug)]
    struct SenderForTests {
        pub send_buf: Vec<u8>,
    }
    impl Sendable for SenderForTests {
        /// Enqueue some bytes to send
        fn send(&mut self, buf: &[u8]) -> Res<usize> {
            self.send_buf.extend(buf);
            Ok(buf.len())
        }

        fn send_data_ready(&self) -> bool {
            self.send_buf.len() > 0
        }

        fn reset(&mut self, err: AppError) -> Res<()> {
            Ok(())
        }

        fn close(&mut self) {
            false;
        }

        fn next_bytes(&mut self, _mode: TxMode) -> Option<(u64, &[u8])> {
            let len = self.send_buf.len() as u64;
            if len > 0 {
                Some((len, &self.send_buf))
            } else {
                None
            }
        }

        fn mark_as_sent(&mut self, offset: u64, len: usize) {}

        fn final_size(&self) -> Option<u64> {
            None
        }

        fn reset_acked(&mut self) {}
    }

    #[derive(Debug)]
    struct ReceiverForTests {
        pub recv_buf: Vec<u8>,
    }

    impl Recvable for ReceiverForTests {
        fn recv_data_ready(&self) -> bool {
            self.recv_buf.len() > 0
        }

        /// caller has been told data is available on a stream, and they want to
        /// retrieve it.
        fn read_with_amount(&mut self, buf: &mut [u8], amount: u64) -> Res<(u64, bool)> {
            assert!(buf.len() >= amount as usize);
            let ret_bytes = std::cmp::min(self.recv_buf.len(), amount as usize);
            let remaining = self.recv_buf.split_off(ret_bytes);
            buf[..ret_bytes].copy_from_slice(&*self.recv_buf);
            self.recv_buf = remaining;
            Ok((ret_bytes as u64, false))
        }

        fn read(&mut self, buf: &mut [u8]) -> Res<(u64, bool)> {
            self.read_with_amount(buf, buf.len() as u64)
        }

        fn inbound_stream_frame(&mut self, _fin: bool, _offset: u64, _data: Vec<u8>) -> Res<()> {
            Ok(())
        }
        fn needs_flowc_update(&mut self) -> Option<u64> {
            None
        }

        fn stop_sending(&mut self, _err: AppError) {}

        fn final_size(&self) -> Option<u64> {
            None
        }

        fn close(&mut self) {}
    }

    fn test_sent_instructions(encoder: &mut QPackEncoder, res: &[u8]) {
        let mut sender = SenderForTests {
            send_buf: Vec::new(),
        };
        if let Err(_) = encoder.write(&mut sender) {
            assert!(false);
        } else {
            assert!(true);
        }
        assert_eq!(sender.send_buf, res)
    }

    // test insert_with_name_ref which fails because there is not enough space in the table
    #[test]
    fn test_insert_with_name_ref_1() {
        let mut encoder = QPackEncoder::new(0);
        if let Err(e) = encoder.insert_with_name_ref(true, 4, false, vec![0x31, 0x32, 0x33, 0x34]) {
            assert_eq!(Error::EncoderStreamError, e);
        } else {
            assert!(false);
        }
        test_sent_instructions(&mut encoder, &vec![]);
    }

    // test insert_name_ref that succeeds
    #[test]
    fn test_insert_with_name_ref_2() {
        let mut encoder = QPackEncoder::new(200);
        if let Err(_) = encoder.insert_with_name_ref(true, 4, false, vec![0x31, 0x32, 0x33, 0x34]) {
            assert!(false);
        } else {
            assert!(true);
        }
        test_sent_instructions(&mut encoder, &vec![0xc4, 0x04, 0x31, 0x32, 0x33, 0x34]);
    }

    // test insert_with_name_literal which fails because there is not enough space in the table
    #[test]
    fn test_insert_with_name_literal_1() {
        let mut encoder = QPackEncoder::new(0);
        // insert "content-length: 1234
        if let Err(e) = encoder.insert_with_name_literal(
            false,
            vec![
                0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68,
            ],
            false,
            vec![0x31, 0x32, 0x33, 0x34],
        ) {
            assert_eq!(Error::EncoderStreamError, e);
        } else {
            assert!(false);
        }
        test_sent_instructions(&mut encoder, &vec![]);
    }

    // test insert_with_name_literal - succeeds
    #[test]
    fn test_insert_with_name_literal_2() {
        let mut encoder = QPackEncoder::new(200);
        // insert "content-length: 1234
        if let Err(_) = encoder.insert_with_name_literal(
            false,
            vec![
                0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68,
            ],
            false,
            vec![0x31, 0x32, 0x33, 0x34],
        ) {
            assert!(false);
        } else {
            assert!(true);
        }
        test_sent_instructions(
            &mut encoder,
            &vec![
                0x4e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, 0x74,
                0x68, 0x04, 0x31, 0x32, 0x33, 0x34,
            ],
        );
    }

    #[test]
    fn test_change_capacity() {
        let mut encoder = QPackEncoder::new(0);
        encoder.change_capacity(200);
        test_sent_instructions(&mut encoder, &vec![0x3f, 0xa9, 0x01]);
    }

    #[test]
    fn test_duplicate() {
        let mut encoder = QPackEncoder::new(200);
        // insert "content-length: 1234
        if let Err(_) = encoder.insert_with_name_literal(
            false,
            vec![
                0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68,
            ],
            false,
            vec![0x31, 0x32, 0x33, 0x34],
        ) {
            assert!(false);
        } else {
            assert!(true);
        }
        test_sent_instructions(
            &mut encoder,
            &vec![
                0x4e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, 0x74,
                0x68, 0x04, 0x31, 0x32, 0x33, 0x34,
            ],
        );

        if let Err(_) = encoder.duplicate(0) {
            assert!(false);
        } else {
            assert!(true);
        }
        test_sent_instructions(&mut encoder, &vec![0x00]);
    }

    struct TestElement {
        pub headers: Vec<(String, String)>,
        pub header_block: &'static [u8],
        pub encoder_inst: &'static [u8],
    }

    #[test]
    fn test_header_block_encoder() {
        let test_cases: [TestElement; 6] = [
            // test a header with ref to static - encode_indexed
            TestElement {
                headers: vec![(String::from(":method"), String::from("GET"))],
                header_block: &[0x00, 0x00, 0xd1],
                encoder_inst: &[],
            },
            // test encode_literal_with_name_ref
            TestElement {
                headers: vec![(String::from(":path"), String::from("/somewhere"))],
                header_block: &[
                    0x00, 0x00, 0x51, 0x0a, 0x2f, 0x73, 0x6f, 0x6d, 0x65, 0x77, 0x68, 0x65, 0x72,
                    0x65,
                ],
                encoder_inst: &[],
            },
            // test adding a new header and encode_post_base_index, also test fix_header_block_prefix
            TestElement {
                headers: vec![(String::from("my-header"), String::from("my-value"))],
                header_block: &[0x02, 0x80, 0x10],
                encoder_inst: &[
                    0x49, 0x6d, 0x79, 0x2d, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x08, 0x6d, 0x79,
                    0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65,
                ],
            },
            // test encode_indexed with a ref to dynamic table.
            TestElement {
                headers: vec![(String::from("my-header"), String::from("my-value"))],
                header_block: &[0x02, 0x00, 0x80],
                encoder_inst: &[],
            },
            // test encode_literal_with_name_ref.
            TestElement {
                headers: vec![(String::from("my-header"), String::from("my-value2"))],
                header_block: &[
                    0x02, 0x00, 0x40, 0x09, 0x6d, 0x79, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x32,
                ],
                encoder_inst: &[],
            },
            // test multiple headers
            TestElement {
                headers: vec![
                    (String::from(":method"), String::from("GET")),
                    (String::from(":path"), String::from("/somewhere")),
                    (String::from(":authority"), String::from("example.com")),
                    (String::from(":scheme"), String::from("https")),
                ],
                header_block: &[
                    0x00, 0x01, 0xd1, 0x51, 0x0a, 0x2f, 0x73, 0x6f, 0x6d, 0x65, 0x77, 0x68, 0x65,
                    0x72, 0x65, 0x50, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63,
                    0x6f, 0x6d, 0xd7,
                ],
                encoder_inst: &[],
            },
        ];

        let mut encoder = QPackEncoder::new(200);
        encoder.set_max_capacity(200);
        for t in &test_cases {
            let mut buf = encoder.encode_header_block(&t.headers, 1);
            assert_eq!(buf.as_mut_vec(), t.header_block);
            test_sent_instructions(&mut encoder, t.encoder_inst);
        }
    }

    // Test inserts block on waiting for an insert count increment.
    #[test]
    fn test_insertion_blocked_on_insert_count_feedback() {
        let mut encoder = QPackEncoder::new(60);
        // insert "content-length: 1234
        if let Err(_) = encoder.insert_with_name_literal(
            false,
            vec![
                0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68,
            ],
            false,
            vec![0x31, 0x32, 0x33, 0x34],
        ) {
            assert!(false);
        } else {
            assert!(true);
        }
        test_sent_instructions(
            &mut encoder,
            &vec![
                0x4e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, 0x74,
                0x68, 0x04, 0x31, 0x32, 0x33, 0x34,
            ],
        );

        // insert "content-length: 12345 which will fail because the ntry in the table cannot be evicted.
        if let Err(_) = encoder.insert_with_name_literal(
            false,
            vec![
                0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68,
            ],
            false,
            vec![0x31, 0x32, 0x33, 0x34, 0x35],
        ) {
            assert!(true);
        } else {
            assert!(false);
        }
        test_sent_instructions(&mut encoder, &vec![]);

        // receive an insert count increment.
        let mut receiver = ReceiverForTests {
            recv_buf: Vec::new(),
        };

        receiver.recv_buf.extend(vec![0x01]);
        if let Err(_) = encoder.read_instructions(&mut receiver) {
            assert!(false);
        } else {
            assert!(true);
        }

        // insert "content-length: 12345 again it will succeed.
        if let Err(_) = encoder.insert_with_name_literal(
            false,
            vec![
                0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68,
            ],
            false,
            vec![0x31, 0x32, 0x33, 0x34, 0x35],
        ) {
            assert!(false);
        } else {
            assert!(true);
        }
        test_sent_instructions(
            &mut encoder,
            &vec![
                0x4e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, 0x74,
                0x68, 0x05, 0x31, 0x32, 0x33, 0x34, 0x35,
            ],
        );
    }

    // Test inserts block on waiting for acks
    // test the table inseriong blocking:
    // 0 - waithing for a header ack
    // 2 - waithing for a stream cancel.
    fn test_insertion_blocked_on_waiting_forheader_ack_or_stream_cancel(wait: u8) {
        let mut encoder = QPackEncoder::new(60);
        encoder.set_max_capacity(200);
        // insert "content-length: 1234
        if let Err(_) = encoder.insert_with_name_literal(
            false,
            vec![
                0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68,
            ],
            false,
            vec![0x31, 0x32, 0x33, 0x34],
        ) {
            assert!(false);
        } else {
            assert!(true);
        }
        test_sent_instructions(
            &mut encoder,
            &vec![
                0x4e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, 0x74,
                0x68, 0x04, 0x31, 0x32, 0x33, 0x34,
            ],
        );

        // receive an insert count increment.
        let mut receiver = ReceiverForTests {
            recv_buf: Vec::new(),
        };

        receiver.recv_buf.extend(vec![0x01]);
        if let Err(_) = encoder.read_instructions(&mut receiver) {
            assert!(false);
        } else {
            assert!(true);
        }

        // send a header block
        let mut buf = encoder.encode_header_block(
            &vec![(String::from("content-length"), String::from("1234"))],
            1,
        );
        assert_eq!(buf.as_mut_vec(), &[0x02, 0x00, 0x80]);
        test_sent_instructions(&mut encoder, &[]);

        // insert "content-length: 12345 which will fail because the ntry in the table cannot be evicted.
        if let Err(_) = encoder.insert_with_name_literal(
            false,
            vec![
                0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68,
            ],
            false,
            vec![0x31, 0x32, 0x33, 0x34, 0x35],
        ) {
            assert!(true);
        } else {
            assert!(false);
        }
        test_sent_instructions(&mut encoder, &vec![]);

        let mut receiver = ReceiverForTests {
            recv_buf: Vec::new(),
        };
        if wait == 0 {
            // receive a header_ack.
            receiver.recv_buf.extend(vec![0x81]);
        } else {
            // reveice a stream canceled
            receiver.recv_buf.extend(vec![0x41]);
        }
        if let Err(_) = encoder.read_instructions(&mut receiver) {
            assert!(false);
        } else {
            assert!(true);
        }

        // insert "content-length: 12345 again it will succeed.
        if let Err(_) = encoder.insert_with_name_literal(
            false,
            vec![
                0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68,
            ],
            false,
            vec![0x31, 0x32, 0x33, 0x34, 0x35],
        ) {
            assert!(false);
        } else {
            assert!(true);
        }
        test_sent_instructions(
            &mut encoder,
            &vec![
                0x4e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, 0x74,
                0x68, 0x05, 0x31, 0x32, 0x33, 0x34, 0x35,
            ],
        );
    }

    #[test]
    fn test_header_ack() {
        test_insertion_blocked_on_waiting_forheader_ack_or_stream_cancel(0);
    }

    #[test]
    fn test_stream_canceled() {
        test_insertion_blocked_on_waiting_forheader_ack_or_stream_cancel(1);
    }
}
