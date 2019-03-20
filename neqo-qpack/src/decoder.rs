#![allow(unused_variables, dead_code)]

use crate::header_read_buf::{
    read_prefixed_encoded_int_header_read_buf, read_prefixed_encoded_int_with_recvable,
    HeaderReadBuf,
};
use crate::qpack_send_buf::QPData;
use crate::table::HeaderTable;
use crate::{Error, Res};
use neqo_transport::stream::{Recvable, Sendable};
use std::{mem, str};

fn to_string(v: &[u8]) -> Res<String> {
    match str::from_utf8(v) {
        Ok(s) => Ok(s.to_string()),
        Err(_) => Err(Error::DecompressionFailed),
    }
}

enum QPackWithRefState {
    GetName { cnt: u8 },
    GetValueLength { len: u64, cnt: u8 },
    GetValue { offset: usize },
}

enum QPackWithoutRefState {
    GetNameLength { len: u64, cnt: u8 },
    GetName { offset: usize },
    GetValueLength { len: u64, cnt: u8 },
    GetValue { offset: usize },
}

enum QPackDecoderState {
    ReadInstruction,
    InsertWithNameRef {
        name_index: u64,
        name_static_table: bool,
        value: Vec<u8>,
        value_is_huffman: bool,
        state: QPackWithRefState,
    },
    InsertWithoutNameRef {
        name: Vec<u8>,
        name_is_huffman: bool,
        value: Vec<u8>,
        value_is_huffman: bool,
        state: QPackWithoutRefState,
    },
    Duplicate {
        index: u64,
        cnt: u8,
    },
    Capacity {
        capacity: u64,
        cnt: u8,
    },
}

struct QPackDecoder {
    state: QPackDecoderState,
    table: HeaderTable,
    increment: u64,
    total_num_of_inserts: u64,
    max_entries: u64,
    send_buf: QPData,
}

impl QPackDecoder {
    pub fn new(capacity: u64) -> QPackDecoder {
        QPackDecoder {
            state: QPackDecoderState::ReadInstruction,
            table: HeaderTable::new(capacity, false),
            increment: 0,
            total_num_of_inserts: 0,
            max_entries: 0,
            send_buf: QPData::default(),
        }
    }

    pub fn set_max_capacity(&mut self, cap: u64) {
        self.max_entries = (cap as f64 / 32.0).floor() as u64;
    }

    pub fn capacity(&self) -> u64 {
        self.table.capacity()
    }

    pub fn read_instructions(&mut self, s: &mut Recvable) -> Res<()> {
        loop {
            match self.state {
                QPackDecoderState::ReadInstruction => {
                    let mut b = [0; 1];
                    match s.read(&mut b) {
                        Err(_) => break Err(Error::DecoderStreamError),
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

                    if (b[0] & 0x80) != 0 {
                        // Insert With Name Reference
                        let static_t = (b[0] & 0x40) != 0;
                        let mut v: u64 = 0;
                        let mut cnt: u8 = 0;
                        let name_done = read_prefixed_encoded_int_with_recvable_wrap(
                            s, &mut v, &mut cnt, 2, b[0], true,
                        )?;
                        self.state = QPackDecoderState::InsertWithNameRef {
                            name_index: v,
                            name_static_table: static_t,
                            value: Vec::new(),
                            value_is_huffman: false,
                            state: if name_done {
                                QPackWithRefState::GetValueLength { len: 0, cnt: 0 }
                            } else {
                                QPackWithRefState::GetName { cnt: cnt }
                            },
                        };
                        if !name_done {
                            // wait for more data
                            break Ok(());
                        }
                    } else if (b[0] & 0x40) != 0 {
                        // Insert Without Name Reference
                        let huffman = (b[0] & 0x20) != 0;
                        let mut v: u64 = 0;
                        let mut cnt: u8 = 0;
                        let name_done = read_prefixed_encoded_int_with_recvable_wrap(
                            s, &mut v, &mut cnt, 3, b[0], true,
                        )?;
                        self.state = QPackDecoderState::InsertWithoutNameRef {
                            name: if name_done {
                                vec![0; v as usize]
                            } else {
                                Vec::new()
                            },
                            name_is_huffman: huffman,
                            value: Vec::new(),
                            value_is_huffman: false,
                            state: if name_done {
                                QPackWithoutRefState::GetName { offset: 0 }
                            } else {
                                QPackWithoutRefState::GetNameLength { len: v, cnt: cnt }
                            },
                        };
                        if !name_done {
                            // wait for more data
                            break Ok(());
                        }
                    } else if (b[0] & 0x20) == 0 {
                        // Duplicate
                        let mut v: u64 = 0;
                        let mut cnt: u8 = 0;
                        let done = read_prefixed_encoded_int_with_recvable_wrap(
                            s, &mut v, &mut cnt, 3, b[0], true,
                        )?;
                        if done {
                            self.table.duplicate(v)?;
                            self.total_num_of_inserts += 1;
                            self.increment += 1;
                            self.state = QPackDecoderState::ReadInstruction;
                        } else {
                            self.state = QPackDecoderState::Duplicate { index: v, cnt: cnt };
                            // wait for more data
                            break Ok(());
                        }
                    } else {
                        // Set Dynamic Table Capacity
                        let mut v: u64 = 0;
                        let mut cnt: u8 = 0;
                        let done = read_prefixed_encoded_int_with_recvable_wrap(
                            s, &mut v, &mut cnt, 3, b[0], true,
                        )?;
                        if done {
                            self.table.set_capacity(v);
                            self.state = QPackDecoderState::ReadInstruction;
                        } else {
                            self.state = QPackDecoderState::Capacity {
                                capacity: v,
                                cnt: cnt,
                            };
                            // wait for more data
                            break Ok(());
                        }
                    }
                }
                QPackDecoderState::InsertWithNameRef {
                    ref mut name_static_table,
                    ref mut name_index,
                    ref mut value_is_huffman,
                    ref mut value,
                    ref mut state,
                } => {
                    match state {
                        QPackWithRefState::GetName { ref mut cnt } => {
                            let done = read_prefixed_encoded_int_with_recvable_wrap(
                                s, name_index, cnt, 0, 0x0, false,
                            )?;
                            if !done {
                                // waiting for more data
                                break Ok(());
                            }
                            *state = QPackWithRefState::GetValueLength { len: 0, cnt: 0 };
                        }
                        QPackWithRefState::GetValueLength {
                            ref mut len,
                            ref mut cnt,
                        } => {
                            let done = read_prefixed_encoded_int_with_recvable_wrap(
                                s, len, cnt, 0, 0x0, false,
                            )?;
                            if !done {
                                // waiting for more data
                                break Ok(());
                            }
                            *value = vec![0; *len as usize];
                            *state = QPackWithRefState::GetValue { offset: 0 };
                        }
                        QPackWithRefState::GetValue { ref mut offset } => {
                            match s.read(&mut value[*offset..]) {
                                Err(_) => break Err(Error::DecoderStreamError),
                                Ok((amount, fin)) => {
                                    if fin {
                                        break Err(Error::ClosedCriticalStream);
                                    }
                                    *offset += amount as usize;
                                }
                            }
                            if value.len() == *offset {
                                // We are done reading instruction, insert the new entry.
                                let mut value_to_insert: Vec<u8> = Vec::new();
                                mem::swap(&mut value_to_insert, value);
                                self.table.insert_with_name_ref(
                                    *name_static_table,
                                    *name_index,
                                    *value_is_huffman,
                                    value_to_insert,
                                )?;
                                self.total_num_of_inserts += 1;
                                self.increment += 1;
                                self.state = QPackDecoderState::ReadInstruction;
                            } else {
                                // waiting for more data
                                break Ok(());
                            }
                        }
                    }
                }

                QPackDecoderState::InsertWithoutNameRef {
                    ref mut name,
                    ref mut name_is_huffman,
                    ref mut value,
                    ref mut value_is_huffman,
                    ref mut state,
                } => {
                    match state {
                        QPackWithoutRefState::GetNameLength {
                            ref mut len,
                            ref mut cnt,
                        } => {
                            let done = read_prefixed_encoded_int_with_recvable_wrap(
                                s, len, cnt, 0, 0x0, false,
                            )?;
                            if !done {
                                // waiting for more data
                                break Ok(());
                            }
                            *name = vec![0; *len as usize];
                            *state = QPackWithoutRefState::GetName { offset: 0 };
                        }
                        QPackWithoutRefState::GetName { offset } => {
                            match s.read(&mut name[*offset..]) {
                                Err(_) => break Err(Error::DecoderStreamError),
                                Ok((amount, fin)) => {
                                    if fin {
                                        break Err(Error::ClosedCriticalStream);
                                    }
                                    *offset += amount as usize;
                                }
                            }

                            if name.len() == *offset {
                                *state = QPackWithoutRefState::GetValueLength { len: 0, cnt: 0 };
                            } else {
                                // waiting for more data
                                break Ok(());
                            }
                        }
                        QPackWithoutRefState::GetValueLength {
                            ref mut len,
                            ref mut cnt,
                        } => {
                            let done = read_prefixed_encoded_int_with_recvable_wrap(
                                s, len, cnt, 0, 0x0, false,
                            )?;
                            if !done {
                                // waiting for more data
                                break Ok(());
                            }
                            *value = vec![0; *len as usize];
                            *state = QPackWithoutRefState::GetValue { offset: 0 };
                        }
                        QPackWithoutRefState::GetValue { ref mut offset } => {
                            match s.read(&mut value[*offset..]) {
                                Err(_) => break Err(Error::DecoderStreamError),
                                Ok((amount, fin)) => {
                                    if fin {
                                        break Err(Error::ClosedCriticalStream);
                                    }
                                    *offset += amount as usize;
                                }
                            }

                            if value.len() == *offset {
                                // We are done reading instruction, insert the new entry.
                                let mut name_to_insert: Vec<u8> = Vec::new();
                                mem::swap(&mut name_to_insert, name);
                                let mut value_to_insert: Vec<u8> = Vec::new();
                                mem::swap(&mut value_to_insert, value);
                                // TODO decode huffman
                                self.table.insert(name_to_insert, value_to_insert)?;
                                self.total_num_of_inserts += 1;
                                self.increment += 1;
                                self.state = QPackDecoderState::ReadInstruction;
                            } else {
                                // waiting for more data
                                break Ok(());
                            }
                        }
                    }
                }
                QPackDecoderState::Duplicate {
                    ref mut index,
                    ref mut cnt,
                } => {
                    let done =
                        read_prefixed_encoded_int_with_recvable_wrap(s, index, cnt, 0, 0x0, false)?;
                    if done {
                        self.table.duplicate(*index)?;
                        self.total_num_of_inserts += 1;
                        self.increment += 1;
                        self.state = QPackDecoderState::ReadInstruction;
                    } else {
                        // waiting for more data
                        break Ok(());
                    }
                }
                QPackDecoderState::Capacity {
                    ref mut capacity,
                    ref mut cnt,
                } => {
                    let done = read_prefixed_encoded_int_with_recvable_wrap(
                        s, capacity, cnt, 0, 0x0, false,
                    )?;
                    if done {
                        self.table.set_capacity(*capacity);
                        self.state = QPackDecoderState::ReadInstruction;
                    } else {
                        // waiting for more data
                        break Ok(());
                    }
                }
            }
        }
    }

    fn header_ack(&mut self, stream_id: u64) {
        self.send_buf
            .encode_prefixed_encoded_int(0x80, 1, stream_id);
    }

    pub fn cancel_stream(&mut self, stream_id: u64) {
        self.send_buf
            .encode_prefixed_encoded_int(0x40, 1, stream_id);
    }

    pub fn write(&mut self, s: &mut Sendable) -> Res<()> {
        // Encode increment istruction if neede.
        if self.increment > 0 {
            self.send_buf
                .encode_prefixed_encoded_int(0x00, 2, self.increment);
            self.increment = 0;
        }
        match s.send(self.send_buf.as_mut_vec()) {
            Err(_) => Err(Error::DecoderStreamError),
            Ok(r) => {
                self.send_buf.read(r as usize);
                Ok(())
            }
        }
    }

    pub fn decode_header_block(
        &mut self,
        buf: &mut HeaderReadBuf,
        stream_id: u64,
    ) -> Res<Vec<(String, String)>> {
        let (largest_ref, base) = self.read_base(buf)?;
        if self.table.base() < largest_ref {
            //TODO
        }
        let mut h: Vec<(String, String)> = Vec::new();

        let mut b: u8;
        loop {
            if buf.remaining() == 0 {
                // Send header_ack
                self.header_ack(stream_id);
                break Ok(h);
            }

            b = buf.read_bits2(1)?;
            if b == 1 {
                h.push(self.read_indexed(buf, base)?);
                continue;
            }

            b = buf.read_bits2(1)?;
            if b == 1 {
                h.push(self.read_literal_with_name_ref(buf, base)?);
                continue;
            }

            b = buf.read_bits2(1)?;
            if b == 1 {
                h.push(self.read_literal_with_name_literal(buf)?);
                continue;
            }

            b = buf.read_bits2(1)?;
            if b == 1 {
                h.push(self.read_post_base_index(buf, base)?);
                continue;
            } else {
                h.push(self.read_literal_with_post_base_name_ref(buf, base)?);
            }
        }
    }

    fn read_base(&self, buf: &mut HeaderReadBuf) -> Res<(u64, u64)> {
        let req_insert_cnt =
            self.calc_req_insert_cnt(read_prefixed_encoded_int_header_read_buf(buf, 0)?)?;

        let b = buf.read_bits2(1)?;
        let base_delta = read_prefixed_encoded_int_header_read_buf(buf, 1)?;

        let base: u64;
        if b == 0 {
            base = req_insert_cnt + base_delta;
        } else {
            base = req_insert_cnt - base_delta - 1;
        }
        Ok((req_insert_cnt, base))
    }

    fn read_indexed(&self, buf: &mut HeaderReadBuf, base: u64) -> Res<(String, String)> {
        let static_table = buf.read_bits2(1)?;
        let index = read_prefixed_encoded_int_header_read_buf(buf, 2)?;
        if static_table == 1 {
            if let Ok(entry) = self.table.get_static(index) {
                Ok((to_string(entry.name())?, to_string(entry.value())?))
            } else {
                Err(Error::DecompressionFailed)
            }
        } else {
            if let Ok(entry) = self.table.get_dynamic(index, base, false) {
                Ok((to_string(entry.name())?, to_string(entry.value())?))
            } else {
                Err(Error::DecompressionFailed)
            }
        }
    }

    fn read_post_base_index(&self, buf: &mut HeaderReadBuf, base: u64) -> Res<(String, String)> {
        let index = read_prefixed_encoded_int_header_read_buf(buf, 4)?;
        // TODO(dragana) huffman
        if let Ok(entry) = self.table.get_dynamic(index, base, true) {
            Ok((to_string(entry.name())?, to_string(entry.value())?))
        } else {
            Err(Error::DecompressionFailed)
        }
    }

    fn read_literal_with_name_ref(
        &self,
        buf: &mut HeaderReadBuf,
        base: u64,
    ) -> Res<(String, String)> {
        let _n = buf.read_bits2(1)?;
        let static_table = buf.read_bits2(1)?;
        let index = read_prefixed_encoded_int_header_read_buf(buf, 4)?;
        let mut name: Vec<u8>;
        if static_table == 1 {
            if let Ok(entry) = self.table.get_static(index) {
                name = entry.name().to_vec();
            } else {
                return Err(Error::DecompressionFailed);
            }
        } else {
            if let Ok(entry) = self.table.get_dynamic(index, base, false) {
                name = entry.name().to_vec();
            } else {
                return Err(Error::DecompressionFailed);
            }
        }
        let _value_is_huffman = buf.read_bits2(1)?;
        let value_len = read_prefixed_encoded_int_header_read_buf(buf, 1)?;
        let mut value: Vec<u8> = Vec::new();
        buf.read_bytes(&mut value, value_len)?;
        Ok((to_string(&name)?, to_string(&value)?))
    }

    fn read_literal_with_post_base_name_ref(
        &self,
        buf: &mut HeaderReadBuf,
        base: u64,
    ) -> Res<(String, String)> {
        let _n = buf.read_bits2(1)?;
        let index = read_prefixed_encoded_int_header_read_buf(buf, 5)?;
        let mut name: Vec<u8>;
        if let Ok(entry) = self.table.get_dynamic(index, base, true) {
            name = entry.name().to_vec();
        } else {
            return Err(Error::DecompressionFailed);
        }

        let _value_is_huffman = buf.read_bits2(1)?;
        let value_len = read_prefixed_encoded_int_header_read_buf(buf, 1)?;
        let mut value: Vec<u8> = Vec::new();
        buf.read_bytes(&mut value, value_len)?;
        Ok((to_string(&name)?, to_string(&value)?))
    }

    fn read_literal_with_name_literal(&self, buf: &mut HeaderReadBuf) -> Res<(String, String)> {
        let _n = buf.read_bits2(1)?;

        let _name_is_huffman = buf.read_bits2(1)?;
        let name_len = read_prefixed_encoded_int_header_read_buf(buf, 5)?;
        let mut name: Vec<u8> = Vec::new();
        buf.read_bytes(&mut name, name_len)?;

        let _value_is_huffman = buf.read_bits2(1)?;
        let value_len = read_prefixed_encoded_int_header_read_buf(buf, 1)?;
        let mut value: Vec<u8> = Vec::new();
        buf.read_bytes(&mut value, value_len)?;

        Ok((to_string(&name)?, to_string(&value)?))
    }

    fn calc_req_insert_cnt(&self, encoded: u64) -> Res<u64> {
        if encoded == 0 {
            Ok(0)
        } else if self.max_entries == 0 {
            Err(Error::DecompressionFailed)
        } else {
            let full_range = 2 * self.max_entries;
            if encoded > full_range {
                return Err(Error::DecompressionFailed);
            }
            let max_value = self.total_num_of_inserts + self.max_entries;
            let max_wrapped = (max_value as f64 / full_range as f64).floor() as u64 * full_range;
            let mut req_insert_cnt = max_wrapped + encoded - 1;
            if req_insert_cnt > max_value {
                if req_insert_cnt < full_range {
                    return Err(Error::DecompressionFailed);
                } else {
                    req_insert_cnt -= full_range;
                }
            }
            Ok(req_insert_cnt)
        }
    }
}

// this wraps read_prefixed_encoded_int_with_recvable to return proper error.
fn read_prefixed_encoded_int_with_recvable_wrap(
    s: &mut Recvable,
    val: &mut u64,
    cnt: &mut u8,
    prefix_len: u8,
    first_byte: u8,
    have_first_byte: bool,
) -> Res<bool> {
    match read_prefixed_encoded_int_with_recvable(
        s,
        val,
        cnt,
        prefix_len,
        first_byte,
        have_first_byte,
    ) {
        Err(Error::ClosedCriticalStream) => Err(Error::ClosedCriticalStream),
        Err(_) => Err(Error::DecoderStreamError),
        Ok(done) => Ok(done),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neqo_transport::connection::TxMode;
    use neqo_transport::{AppError, Res};

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

    fn test_sent_instructions(decoder: &mut QPackDecoder, res: &[u8]) {
        let mut sender = SenderForTests {
            send_buf: Vec::new(),
        };
        if let Err(_) = decoder.write(&mut sender) {
            assert!(false);
        } else {
            assert!(true);
        }
        assert_eq!(sender.send_buf, res)
    }

    // test insert_with_name_ref which fails because there is not enough space in the table
    #[test]
    fn test_recv_insert_with_name_ref_1() {
        let mut decoder = QPackDecoder::new(0);
        let mut receiver = ReceiverForTests {
            recv_buf: Vec::new(),
        };

        receiver
            .recv_buf
            .extend(vec![0xc4, 0x04, 0x31, 0x32, 0x33, 0x34]);
        if let Err(e) = decoder.read_instructions(&mut receiver) {
            assert_eq!(Error::DecoderStreamError, e);
        } else {
            assert!(false);
        }
        // test the insert count increment command.
        test_sent_instructions(&mut decoder, &vec![]);
    }

    // test insert_name_ref that succeeds
    #[test]
    fn test_recv_insert_with_name_ref_2() {
        let mut decoder = QPackDecoder::new(200);
        let mut receiver = ReceiverForTests {
            recv_buf: Vec::new(),
        };

        receiver
            .recv_buf
            .extend(vec![0xc4, 0x04, 0x31, 0x32, 0x33, 0x34]);
        if let Err(_) = decoder.read_instructions(&mut receiver) {
            assert!(false);
        } else {
            assert!(true);
        }
        // test the insert count increment command.
        test_sent_instructions(&mut decoder, &vec![0x01]);
    }

     // test insert_with_name_literal which fails because there is not enough space in the table
    #[test]
    fn test_recv_insert_with_name_litarel_1() {
        let mut decoder = QPackDecoder::new(0);
        let mut receiver = ReceiverForTests {
            recv_buf: Vec::new(),
        };

        receiver.recv_buf.extend(vec![
            0x4e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, 0x74,
            0x68, 0x04, 0x31, 0x32, 0x33, 0x34,
        ]);
        if let Err(e) = decoder.read_instructions(&mut receiver) {
            assert_eq!(Error::DecoderStreamError, e);
        } else {
            assert!(false);
        }
        // test the insert count increment command.
        test_sent_instructions(&mut decoder, &vec![]);
    }

   // test insert with name literal - succeeds
    #[test]
    fn test_recv_insert_with_name_litarel_2() {
        let mut decoder = QPackDecoder::new(200);
        let mut receiver = ReceiverForTests {
            recv_buf: Vec::new(),
        };

        receiver.recv_buf.extend(vec![
            0x4e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, 0x74,
            0x68, 0x04, 0x31, 0x32, 0x33, 0x34,
        ]);
        if let Err(_) = decoder.read_instructions(&mut receiver) {
            assert!(false);
        } else {
            assert!(true);
        }
        // test the insert count increment command.
        test_sent_instructions(&mut decoder, &vec![0x01]);
    }

    #[test]
    fn test_recv_change_capacity() {
        let mut decoder = QPackDecoder::new(0);
        let mut receiver = ReceiverForTests {
            recv_buf: Vec::new(),
        };
        receiver.recv_buf.extend(vec![0x3f, 0xa9, 0x01]);

        if let Err(_) = decoder.read_instructions(&mut receiver) {
            assert!(false);
        } else {
            assert!(true);
        }
        assert_eq!(decoder.capacity(), 200);
    }

    // this test tests heade decoding, the header acks command and the insert count increment command.
    #[test]
    fn test_duplicate() {
        let mut decoder = QPackDecoder::new(60);
        let mut receiver = ReceiverForTests {
            recv_buf: Vec::new(),
        };

        receiver.recv_buf.extend(vec![
            0x4e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, 0x74,
            0x68, 0x04, 0x31, 0x32, 0x33, 0x34,
        ]);
        if let Err(_) = decoder.read_instructions(&mut receiver) {
            assert!(false);
        } else {
            assert!(true);
        }

        receiver.recv_buf.extend(vec![0x00]);
        if let Err(_) = decoder.read_instructions(&mut receiver) {
            assert!(false);
        } else {
            assert!(true);
        }

        // test the insert count increment command.
        test_sent_instructions(&mut decoder, &vec![0x02]);
    }

    struct TestElement {
        pub headers: Vec<(String, String)>,
        pub header_block: &'static [u8],
        pub encoder_inst: &'static [u8],
    }

    #[test]
    fn test_header_block_decoder() {
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

        let mut decoder = QPackDecoder::new(200);
        decoder.set_max_capacity(200);
        let mut receiver = ReceiverForTests {
            recv_buf: Vec::new(),
        };
        let mut i = 0;
        for t in &test_cases {
            receiver.recv_buf.extend(t.encoder_inst);

            if let Err(_) = decoder.read_instructions(&mut receiver) {
                assert!(false);
            } else {
                assert!(true);
            }

            let headers = decoder.decode_header_block(&mut HeaderReadBuf::from(t.header_block), i);
            if let Ok(h) = headers {
                assert_eq!(h, t.headers);
            } else {
                assert!(false);
            }
            i += 1;
        }

        // test header acks and insert count increment command.
        test_sent_instructions(&mut decoder, &vec![0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x1]);
    }
}
