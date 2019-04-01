#![allow(unused_variables, dead_code)]
use crate::huffman::Huffman;
use crate::qpack_helper::{
    read_prefixed_encoded_int_slice, read_prefixed_encoded_int_with_recvable, BufWrapper,
};
use crate::qpack_send_buf::QPData;
use crate::table::HeaderTable;
use crate::{Error, Res};
use log::Level;
use neqo_transport::{Recvable, Sendable};
use std::{mem, str};

pub const QPACK_UNI_STREAM_TYPE_DECODER: u64 = 0x3;

fn to_string(v: &[u8]) -> Res<String> {
    match str::from_utf8(v) {
        Ok(s) => Ok(s.to_string()),
        Err(_) => Err(Error::DecompressionFailed),
    }
}

#[derive(Debug)]
enum QPackWithRefState {
    GetName { cnt: u8 },
    GetValueLength { len: u64, cnt: u8 },
    GetValue { offset: usize },
}

#[derive(Debug)]
enum QPackWithoutRefState {
    GetNameLength { len: u64, cnt: u8 },
    GetName { offset: usize },
    GetValueLength { len: u64, cnt: u8 },
    GetValue { offset: usize },
}

#[derive(Debug)]
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

#[derive(Debug)]
pub struct QPackDecoder {
    state: QPackDecoderState,
    table: HeaderTable,
    increment: u64,
    total_num_of_inserts: u64,
    max_entries: u64,
    send_buf: QPData,
    local_stream_id: Option<u64>,
    remote_stream_id: Option<u64>,
    max_table_size: u32,
    max_blocked_streams: u16,
    blocked_streams: Vec<(u64, u64)>, //stream_id and requested inserts count.
}

impl QPackDecoder {
    pub fn new(max_table_size: u32, max_blocked_streams: u16) -> QPackDecoder {
        log!(Level::Debug, "Decoder: creating a new qpack decoder.");
        QPackDecoder {
            state: QPackDecoderState::ReadInstruction,
            table: HeaderTable::new(false),
            increment: 0,
            total_num_of_inserts: 0,
            max_entries: (max_table_size as f64 / 32.0).floor() as u64,
            send_buf: QPData::default(),
            local_stream_id: None,
            remote_stream_id: None,
            max_table_size: max_table_size,
            max_blocked_streams: max_blocked_streams,
            blocked_streams: Vec::new(),
        }
    }

    pub fn capacity(&self) -> u64 {
        self.table.capacity()
    }

    pub fn get_max_table_size(&self) -> u32 {
        self.max_table_size
    }

    pub fn get_blocked_streams(&self) -> u16 {
        self.max_blocked_streams
    }

    // returns a list of unblocked streams
    pub fn receive(&mut self, s: &mut Recvable) -> Res<Vec<u64>> {
        self.read_instructions(s)?;
        let base = self.table.base();
        let r = self
            .blocked_streams
            .iter()
            .filter(|(_, req)| req <= &base)
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        self.blocked_streams.retain(|(_, req)| req <= &base);
        Ok(r)
    }

    fn read_instructions(&mut self, s: &mut Recvable) -> Res<()> {
        log!(Level::Debug, "Decoder: reading instructions");
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
                            log!(
                                Level::Debug,
                                "Decoder: receiced instruction - duplicate index={}",
                                v
                            );
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
                            self.set_capacity(v)?;
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
                                log!(Level::Debug, "Decoder: received instruction - insert with name ref index={} static={} value={:x?}", name_index, name_static_table, value_to_insert);
                                self.table.insert_with_name_ref(
                                    *name_static_table,
                                    *name_index,
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
                                if *name_is_huffman {
                                    name_to_insert = Huffman::default().decode(name)?;
                                } else {
                                    mem::swap(&mut name_to_insert, name);
                                }
                                let mut value_to_insert: Vec<u8> = Vec::new();
                                if *value_is_huffman {
                                    value_to_insert = Huffman::default().decode(value)?;
                                } else {
                                    mem::swap(&mut value_to_insert, value);
                                }
                                log!(Level::Debug, "Decoder: received instruction - insert with name literal name={:x?} value={:x?}", name_to_insert, value_to_insert);
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
                        log!(
                            Level::Debug,
                            "Decoder: received instruction - duplicate index={}",
                            index
                        );
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
                        let v = *capacity;
                        self.set_capacity(v)?;
                        self.state = QPackDecoderState::ReadInstruction;
                    } else {
                        // waiting for more data
                        break Ok(());
                    }
                }
            }
        }
    }

    fn set_capacity(&mut self, cap: u64) -> Res<()> {
        log!(
            Level::Debug,
            "Decoder: received instruction capacity cap={}",
            cap
        );
        if cap > self.max_table_size as u64 {
            return Err(Error::EncoderStreamError);
        }
        self.table.set_capacity(cap);
        Ok(())
    }

    fn header_ack(&mut self, stream_id: u64) {
        self.send_buf
            .encode_prefixed_encoded_int(0x80, 1, stream_id);
    }

    pub fn cancel_stream(&mut self, stream_id: u64) {
        self.send_buf
            .encode_prefixed_encoded_int(0x40, 1, stream_id);
    }

    pub fn send(&mut self, s: &mut Sendable) -> Res<()> {
        // Encode increment istruction if needed.
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

    // this function returns None if the stream is blocked waiting for table insertions.
    pub fn decode_header_block(
        &mut self,
        buf: &[u8],
        stream_id: u64,
    ) -> Res<Option<Vec<(String, String)>>> {
        log!(Level::Debug, "Decoder: decode header block.");
        let mut reader = BufWrapper {
            buf: buf,
            offset: 0,
        };

        let (req_inserts, base) = self.read_base(&mut reader)?;
        log!(
            Level::Debug,
            "Decoder: requested inserts count is {} and base is {}",
            req_inserts,
            base
        );
        if self.table.base() < req_inserts {
            log!(
                Level::Debug,
                "Decoder: stream is blocked stream_id={} requested inserts count={}",
                stream_id,
                req_inserts
            );
            self.blocked_streams.push((stream_id, req_inserts));
            if self.blocked_streams.len() > self.max_blocked_streams as usize {
                return Err(Error::DecompressionFailed);
            }
            return Ok(None);
        }
        let mut h: Vec<(String, String)> = Vec::new();

        loop {
            if reader.done() {
                // Send header_ack
                if req_inserts != 0 {
                    self.header_ack(stream_id);
                }
                log!(Level::Debug, "Decoder: done decoding header block.");
                break Ok(Some(h));
            }

            let b = reader.peek()?;
            if b & 0x80 != 0 {
                h.push(self.read_indexed(&mut reader, base)?);
            } else if b & 0x40 != 0 {
                h.push(self.read_literal_with_name_ref(&mut reader, base)?);
            } else if b & 0x20 != 0 {
                h.push(self.read_literal_with_name_literal(&mut reader)?);
                continue;
            } else if b & 0x10 != 0 {
                h.push(self.read_post_base_index(&mut reader, base)?);
            } else {
                h.push(self.read_literal_with_post_base_name_ref(&mut reader, base)?);
            }
        }
    }

    fn read_base(&self, buf: &mut BufWrapper) -> Res<(u64, u64)> {
        let req_insert_cnt = self.calc_req_insert_cnt(read_prefixed_encoded_int_slice(buf, 0)?)?;

        let s = buf.peek()? & 0x80 != 0;
        let base_delta = read_prefixed_encoded_int_slice(buf, 1)?;
        let base: u64;
        if !s {
            base = req_insert_cnt + base_delta;
        } else {
            if req_insert_cnt <= base_delta {
                return Err(Error::DecompressionFailed);
            }
            base = req_insert_cnt - base_delta - 1;
        }
        Ok((req_insert_cnt, base))
    }

    fn read_indexed(&self, buf: &mut BufWrapper, base: u64) -> Res<(String, String)> {
        let static_table = buf.peek()? & 0x40 != 0;
        let index = read_prefixed_encoded_int_slice(buf, 2)?;
        log!(
            Level::Debug,
            "Decoder: decoder indexed {} static={}.",
            index,
            static_table
        );
        if static_table {
            match self.table.get_static(index) {
                Ok(entry) => Ok((to_string(entry.name())?, to_string(entry.value())?)),
                Err(_) => Err(Error::DecompressionFailed),
            }
        } else {
            if let Ok(entry) = self.table.get_dynamic(index, base, false) {
                Ok((to_string(entry.name())?, to_string(entry.value())?))
            } else {
                Err(Error::DecompressionFailed)
            }
        }
    }

    fn read_post_base_index(&self, buf: &mut BufWrapper, base: u64) -> Res<(String, String)> {
        let index = read_prefixed_encoded_int_slice(buf, 4)?;
        log!(Level::Debug, "Decoder: decode post-based {}.", index);
        if let Ok(entry) = self.table.get_dynamic(index, base, true) {
            Ok((to_string(entry.name())?, to_string(entry.value())?))
        } else {
            Err(Error::DecompressionFailed)
        }
    }

    fn read_literal_with_name_ref(&self, buf: &mut BufWrapper, base: u64) -> Res<(String, String)> {
        log!(Level::Debug, "Decoder: insert with name reference.");
        // ignore n bit.
        let static_table = buf.peek()? & 0x10 != 0;
        let index = read_prefixed_encoded_int_slice(buf, 4)?;

        let mut name: Vec<u8>;
        if static_table {
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

        let value_is_huffman = buf.peek()? & 0x80 != 0;
        let value_len = read_prefixed_encoded_int_slice(buf, 1)? as usize;

        let mut value: Vec<u8> = Vec::new();
        if value_is_huffman {
            value = Huffman::default().decode(buf.slice(value_len)?)?;
        } else {
            value.extend_from_slice(buf.slice(value_len)?);
        }
        log!(
            Level::Debug,
            "Decoder: name index={} static={} value={:x?}.",
            index,
            static_table,
            value
        );
        Ok((to_string(&name)?, to_string(&value)?))
    }

    fn read_literal_with_post_base_name_ref(
        &self,
        buf: &mut BufWrapper,
        base: u64,
    ) -> Res<(String, String)> {
        log!(
            Level::Debug,
            "Decoder: decoder literal with post-based index."
        );
        // ignore n bit.
        let index = read_prefixed_encoded_int_slice(buf, 5)?;
        let mut name: Vec<u8>;
        if let Ok(entry) = self.table.get_dynamic(index, base, true) {
            name = entry.name().to_vec();
        } else {
            return Err(Error::DecompressionFailed);
        }

        let value_is_huffman = buf.peek()? & 0x80 != 0;
        let value_len = read_prefixed_encoded_int_slice(buf, 1)? as usize;

        let mut value: Vec<u8> = Vec::new();
        if value_is_huffman {
            value = Huffman::default().decode(buf.slice(value_len)?)?;
        } else {
            value.extend_from_slice(buf.slice(value_len)?);
        }

        log!(
            Level::Debug,
            "Decoder: name={:x?} value={:x?}.",
            name,
            value
        );
        Ok((to_string(&name)?, to_string(&value)?))
    }

    fn read_literal_with_name_literal(&self, buf: &mut BufWrapper) -> Res<(String, String)> {
        log!(Level::Debug, "Decoder: decode literal with name literal.");
        // ignore n bit.

        let name_is_huffman = buf.peek()? & 0x08 != 0;
        let name_len = read_prefixed_encoded_int_slice(buf, 5)? as usize;

        let mut name: Vec<u8> = Vec::new();
        if name_is_huffman {
            name = Huffman::default().decode(buf.slice(name_len)?)?;
        } else {
            name.extend_from_slice(buf.slice(name_len)?);
        }

        let value_is_huffman = buf.peek()? & 0x80 != 0;
        let value_len = read_prefixed_encoded_int_slice(buf, 1)? as usize;

        let mut value: Vec<u8> = Vec::new();
        if value_is_huffman {
            value = Huffman::default().decode(buf.slice(value_len)?)?;
        } else {
            value.extend_from_slice(buf.slice(value_len)?);
        }

        log!(
            Level::Debug,
            "Decoder: name={:x?} value={:x?}.",
            name,
            value
        );
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

    pub fn is_send_stream(&self, stream_id: u64) -> bool {
        match self.local_stream_id {
            Some(id) => id == stream_id,
            None => false,
        }
    }

    pub fn is_recv_stream(&self, stream_id: u64) -> bool {
        match self.remote_stream_id {
            Some(id) => id == stream_id,
            None => false,
        }
    }

    pub fn add_send_stream(&mut self, stream_id: u64) {
        if let Some(_) = self.local_stream_id {
            panic!("Adding multiple local streams");
        }
        self.local_stream_id = Some(stream_id);
        self.send_buf
            .write_byte(QPACK_UNI_STREAM_TYPE_DECODER as u8);
    }

    pub fn add_recv_stream(&mut self, stream_id: u64) {
        if let Some(_) = self.remote_stream_id {
            panic!("Adding multiple remote streams");
        }
        self.remote_stream_id = Some(stream_id);
    }

    pub fn has_recv_stream(&self) -> bool {
        match self.remote_stream_id {
            Some(_) => true,
            None => false,
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
    use neqo_transport::{AppError, Res};

    #[derive(Debug)]
    struct ReceiverForTests {
        pub recv_buf: Vec<u8>,
    }

    impl Recvable for ReceiverForTests {
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

        fn data_ready(&self) -> bool {
            self.recv_buf.len() > 0
        }

        fn stop_sending(&mut self, _err: AppError) {}

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

        fn reset(&mut self, err: AppError) {}

        fn close(&mut self) {
            false;
        }
    }

    fn test_sent_instructions(decoder: &mut QPackDecoder, res: &[u8]) {
        let mut sender = SenderForTests {
            send_buf: Vec::new(),
        };
        if let Err(_) = decoder.send(&mut sender) {
            assert!(false);
        } else {
            assert!(true);
        }
        assert_eq!(sender.send_buf, res)
    }

    // test insert_with_name_ref which fails because there is not enough space in the table
    #[test]
    fn test_recv_insert_with_name_ref_1() {
        let mut decoder = QPackDecoder::new(100, 100);
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
        let mut decoder = QPackDecoder::new(100, 100);
        if let Err(_) = decoder.set_capacity(100) {
            assert!(false);
        }
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
        let mut decoder = QPackDecoder::new(100, 100);
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
        let mut decoder = QPackDecoder::new(200, 100);
        if let Err(_) = decoder.set_capacity(200) {
            assert!(false);
        }
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
        let mut decoder = QPackDecoder::new(300, 100);
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

    #[test]
    fn test_recv_change_capacity_too_big() {
        let mut decoder = QPackDecoder::new(100, 100);
        let mut receiver = ReceiverForTests {
            recv_buf: Vec::new(),
        };
        receiver.recv_buf.extend(vec![0x3f, 0xa9, 0x01]);

        if let Err(e) = decoder.read_instructions(&mut receiver) {
            assert_eq!(Error::EncoderStreamError, e);
        } else {
            assert!(false);
        }
    }

    // this test tests heade decoding, the header acks command and the insert count increment command.
    #[test]
    fn test_duplicate() {
        let mut decoder = QPackDecoder::new(200, 100);
        if let Err(_) = decoder.set_capacity(60) {
            assert!(false);
        }
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

        let mut decoder = QPackDecoder::new(200, 100);
        if let Err(_) = decoder.set_capacity(200) {
            assert!(false);
        }
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

            if let Ok(headers) = decoder.decode_header_block(t.header_block, i) {
                if let Some(h) = headers {
                    assert_eq!(h, t.headers);
                } else {
                    assert!(false);
                }
            } else {
                assert!(false);
            }
            i += 1;
        }

        // test header acks and insert count increment command.
        test_sent_instructions(&mut decoder, &vec![0x82, 0x83, 0x84, 0x1]);
    }
}
