// TOTO(dragana) remove this
#![allow(unused_variables, dead_code)]

pub struct HuffmanDecodeEntry {
    pub val: u16,
    pub prefix_len: u16,
}

pub struct HuffmanDecodeTable<'a> {
    entry: &'a [HuffmanDecodeEntry],
    next_table: &'a [&'a HuffmanDecodeTable<'a>],
    index_of_first_next_table: u16,
    prefix_len: u8,
}

impl<'a> HuffmanDecodeTable<'a> {
    pub fn index_has_a_next_table(&self, inx: u8) -> bool {
        (inx as u16) >= self.index_of_first_next_table
    }

    pub fn entry(&self, inx: u8) -> &'a HuffmanDecodeEntry {
        assert!((inx as u16) < self.index_of_first_next_table);
        return &self.entry[inx as usize];
    }

    pub fn next_table(&self, inx: u8) -> &'a HuffmanDecodeTable {
        assert!((inx as u16) >= self.index_of_first_next_table);
        return self.next_table[(inx as usize) - (self.index_of_first_next_table as usize)];
    }
}

pub const HUFFMAN_DECODE_ROOT: &'static HuffmanDecodeTable = &HuffmanDecodeTable {
    entry: HUFFMAN_DECODE_ENTRIES_ROOT,
    next_table: HUFFMAN_DECODE_NEXT_TABLE_ROOT,
    index_of_first_next_table: 254,
    prefix_len: 8,
};

const HUFFMAN_DECODE_NEXT_TABLE_ROOT: &'static [&HuffmanDecodeTable] =
    &[HUFFMAN_DECODE_254, HUFFMAN_DECODE_255];

const HUFFMAN_DECODE_ENTRIES_ROOT: &'static [HuffmanDecodeEntry] = &[
    HuffmanDecodeEntry {
        val: 48,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 48,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 48,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 48,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 48,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 48,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 48,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 48,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 49,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 49,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 49,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 49,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 49,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 49,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 49,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 49,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 50,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 50,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 50,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 50,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 50,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 50,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 50,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 50,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 97,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 97,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 97,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 97,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 97,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 97,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 97,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 97,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 99,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 99,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 99,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 99,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 99,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 99,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 99,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 99,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 101,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 101,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 101,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 101,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 101,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 101,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 101,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 101,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 105,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 105,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 105,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 105,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 105,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 105,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 105,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 105,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 111,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 111,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 111,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 111,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 111,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 111,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 111,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 111,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 115,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 115,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 115,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 115,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 115,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 115,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 115,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 115,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 116,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 116,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 116,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 116,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 116,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 116,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 116,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 116,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 32,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 32,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 32,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 32,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 37,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 37,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 37,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 37,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 45,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 45,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 45,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 45,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 46,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 46,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 46,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 46,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 47,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 47,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 47,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 47,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 51,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 51,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 51,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 51,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 52,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 52,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 52,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 52,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 53,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 53,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 53,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 53,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 54,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 54,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 54,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 54,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 55,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 55,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 55,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 55,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 56,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 56,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 56,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 56,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 57,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 57,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 57,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 57,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 61,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 61,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 61,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 61,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 65,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 65,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 65,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 65,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 95,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 95,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 95,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 95,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 98,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 98,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 98,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 98,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 100,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 100,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 100,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 100,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 102,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 102,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 102,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 102,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 103,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 103,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 103,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 103,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 104,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 104,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 104,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 104,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 108,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 108,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 108,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 108,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 109,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 109,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 109,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 109,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 110,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 110,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 110,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 110,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 112,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 112,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 112,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 112,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 114,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 114,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 114,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 114,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 117,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 117,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 117,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 117,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 58,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 58,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 66,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 66,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 67,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 67,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 68,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 68,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 69,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 69,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 70,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 70,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 71,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 71,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 72,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 72,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 73,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 73,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 74,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 74,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 75,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 75,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 76,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 76,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 77,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 77,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 78,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 78,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 79,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 79,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 80,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 80,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 81,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 81,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 82,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 82,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 83,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 83,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 84,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 84,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 85,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 85,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 86,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 86,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 87,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 87,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 89,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 89,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 106,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 106,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 107,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 107,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 113,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 113,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 118,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 118,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 119,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 119,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 120,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 120,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 121,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 121,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 122,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 122,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 38,
        prefix_len: 8,
    },
    HuffmanDecodeEntry {
        val: 42,
        prefix_len: 8,
    },
    HuffmanDecodeEntry {
        val: 44,
        prefix_len: 8,
    },
    HuffmanDecodeEntry {
        val: 59,
        prefix_len: 8,
    },
    HuffmanDecodeEntry {
        val: 88,
        prefix_len: 8,
    },
    HuffmanDecodeEntry {
        val: 90,
        prefix_len: 8,
    },
];

const HUFFMAN_DECODE_255: &'static HuffmanDecodeTable = &HuffmanDecodeTable {
    entry: HUFFMAN_DECODE_ENTRIES_255,
    next_table: HUFFMAN_DECODE_NEXT_TABLE_255,
    index_of_first_next_table: 254,
    prefix_len: 7,
};

const HUFFMAN_DECODE_NEXT_TABLE_255: &'static [&HuffmanDecodeTable] =
    &[HUFFMAN_DECODE_255_254, HUFFMAN_DECODE_255_255];

const HUFFMAN_DECODE_ENTRIES_255: &'static [HuffmanDecodeEntry] = &[
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 63,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 39,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 43,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 124,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 35,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 35,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 35,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 35,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 35,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 35,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 35,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 35,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 35,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 35,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 35,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 35,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 35,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 35,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 35,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 35,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 62,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 62,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 62,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 62,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 62,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 62,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 62,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 62,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 62,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 62,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 62,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 62,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 62,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 62,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 62,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 62,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 0,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 0,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 0,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 0,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 0,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 0,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 0,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 0,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 36,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 36,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 36,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 36,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 36,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 36,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 36,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 36,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 64,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 64,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 64,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 64,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 64,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 64,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 64,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 64,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 91,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 91,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 91,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 91,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 91,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 91,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 91,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 91,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 93,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 93,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 93,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 93,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 93,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 93,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 93,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 93,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 126,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 126,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 126,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 126,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 126,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 126,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 126,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 126,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 94,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 94,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 94,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 94,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 125,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 125,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 125,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 125,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 60,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 60,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 96,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 96,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 123,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 123,
        prefix_len: 7,
    },
];

const HUFFMAN_DECODE_255_255: &'static HuffmanDecodeTable = &HuffmanDecodeTable {
    entry: HUFFMAN_DECODE_ENTRIES_255_255,
    next_table: HUFFMAN_DECODE_NEXT_TABLE_255_255,
    index_of_first_next_table: 246,
    prefix_len: 8,
};

const HUFFMAN_DECODE_NEXT_TABLE_255_255: &'static [&HuffmanDecodeTable] = &[
    &HUFFMAN_DECODE_255_255_246,
    &HUFFMAN_DECODE_255_255_247,
    &HUFFMAN_DECODE_255_255_248,
    &HUFFMAN_DECODE_255_255_249,
    &HUFFMAN_DECODE_255_255_250,
    &HUFFMAN_DECODE_255_255_251,
    &HUFFMAN_DECODE_255_255_252,
    &HUFFMAN_DECODE_255_255_253,
    &HUFFMAN_DECODE_255_255_254,
    &HUFFMAN_DECODE_255_255_255,
];

const HUFFMAN_DECODE_ENTRIES_255_255: &'static [HuffmanDecodeEntry] = &[
    HuffmanDecodeEntry {
        val: 176,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 176,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 176,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 176,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 176,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 176,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 176,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 176,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 177,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 177,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 177,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 177,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 177,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 177,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 177,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 177,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 179,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 179,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 179,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 179,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 179,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 179,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 179,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 179,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 209,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 209,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 209,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 209,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 209,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 209,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 209,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 209,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 216,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 216,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 216,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 216,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 216,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 216,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 216,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 216,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 217,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 217,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 217,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 217,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 217,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 217,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 217,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 217,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 227,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 227,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 227,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 227,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 227,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 227,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 227,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 227,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 229,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 229,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 229,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 229,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 229,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 229,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 229,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 229,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 230,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 230,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 230,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 230,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 230,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 230,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 230,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 230,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 129,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 129,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 129,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 129,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 132,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 132,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 132,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 132,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 133,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 133,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 133,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 133,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 134,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 134,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 134,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 134,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 136,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 136,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 136,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 136,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 146,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 146,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 146,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 146,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 154,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 154,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 154,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 154,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 156,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 156,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 156,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 156,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 160,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 160,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 160,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 160,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 163,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 163,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 163,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 163,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 164,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 164,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 164,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 164,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 169,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 169,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 169,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 169,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 170,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 170,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 170,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 170,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 173,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 173,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 173,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 173,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 178,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 178,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 178,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 178,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 181,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 181,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 181,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 181,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 185,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 185,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 185,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 185,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 186,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 186,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 186,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 186,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 187,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 187,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 187,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 187,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 189,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 189,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 189,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 189,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 190,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 190,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 190,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 190,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 196,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 196,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 196,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 196,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 198,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 198,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 198,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 198,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 228,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 228,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 228,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 228,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 232,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 232,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 232,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 232,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 233,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 233,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 233,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 233,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 1,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 1,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 135,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 135,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 137,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 137,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 138,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 138,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 139,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 139,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 140,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 140,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 141,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 141,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 143,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 143,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 147,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 147,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 149,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 149,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 150,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 150,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 151,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 151,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 152,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 152,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 155,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 155,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 157,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 157,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 158,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 158,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 165,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 165,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 166,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 166,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 168,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 168,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 174,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 174,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 175,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 175,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 180,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 180,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 182,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 182,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 183,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 183,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 188,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 188,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 191,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 191,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 197,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 197,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 231,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 231,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 239,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 239,
        prefix_len: 7,
    },
    HuffmanDecodeEntry {
        val: 9,
        prefix_len: 8,
    },
    HuffmanDecodeEntry {
        val: 142,
        prefix_len: 8,
    },
    HuffmanDecodeEntry {
        val: 144,
        prefix_len: 8,
    },
    HuffmanDecodeEntry {
        val: 145,
        prefix_len: 8,
    },
    HuffmanDecodeEntry {
        val: 148,
        prefix_len: 8,
    },
    HuffmanDecodeEntry {
        val: 159,
        prefix_len: 8,
    },
    HuffmanDecodeEntry {
        val: 171,
        prefix_len: 8,
    },
    HuffmanDecodeEntry {
        val: 206,
        prefix_len: 8,
    },
    HuffmanDecodeEntry {
        val: 215,
        prefix_len: 8,
    },
    HuffmanDecodeEntry {
        val: 225,
        prefix_len: 8,
    },
    HuffmanDecodeEntry {
        val: 236,
        prefix_len: 8,
    },
    HuffmanDecodeEntry {
        val: 237,
        prefix_len: 8,
    },
];

const HUFFMAN_DECODE_255_255_255: &'static HuffmanDecodeTable = &HuffmanDecodeTable {
    entry: HUFFMAN_DECODE_ENTRIES_255_255_255,
    next_table: &[],
    index_of_first_next_table: 256,
    prefix_len: 6,
};

const HUFFMAN_DECODE_ENTRIES_255_255_255: &'static [HuffmanDecodeEntry] = &[
    HuffmanDecodeEntry {
        val: 19,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 19,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 19,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 19,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 19,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 19,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 19,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 19,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 19,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 19,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 19,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 19,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 19,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 19,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 19,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 19,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 20,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 20,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 20,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 20,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 20,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 20,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 20,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 20,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 20,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 20,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 20,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 20,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 20,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 20,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 20,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 20,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 21,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 21,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 21,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 21,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 21,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 21,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 21,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 21,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 21,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 21,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 21,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 21,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 21,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 21,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 21,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 21,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 23,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 23,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 23,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 23,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 23,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 23,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 23,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 23,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 23,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 23,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 23,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 23,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 23,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 23,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 23,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 23,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 24,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 24,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 24,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 24,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 24,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 24,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 24,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 24,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 24,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 24,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 24,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 24,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 24,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 24,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 24,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 24,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 25,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 25,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 25,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 25,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 25,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 25,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 25,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 25,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 25,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 25,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 25,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 25,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 25,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 25,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 25,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 25,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 26,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 26,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 26,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 26,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 26,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 26,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 26,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 26,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 26,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 26,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 26,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 26,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 26,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 26,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 26,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 26,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 27,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 27,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 27,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 27,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 27,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 27,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 27,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 27,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 27,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 27,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 27,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 27,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 27,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 27,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 27,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 27,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 28,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 28,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 28,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 28,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 28,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 28,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 28,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 28,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 28,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 28,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 28,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 28,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 28,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 28,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 28,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 28,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 29,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 29,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 29,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 29,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 29,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 29,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 29,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 29,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 29,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 29,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 29,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 29,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 29,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 29,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 29,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 29,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 30,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 30,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 30,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 30,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 30,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 30,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 30,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 30,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 30,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 30,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 30,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 30,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 30,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 30,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 30,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 30,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 31,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 31,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 31,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 31,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 31,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 31,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 31,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 31,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 31,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 31,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 31,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 31,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 31,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 31,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 31,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 31,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 127,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 127,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 127,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 127,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 127,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 127,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 127,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 127,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 127,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 127,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 127,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 127,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 127,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 127,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 127,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 127,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 220,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 220,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 220,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 220,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 220,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 220,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 220,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 220,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 220,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 220,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 220,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 220,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 220,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 220,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 220,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 220,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 249,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 249,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 249,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 249,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 249,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 249,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 249,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 249,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 249,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 249,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 249,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 249,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 249,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 249,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 249,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 249,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 10,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 10,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 10,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 10,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 13,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 13,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 13,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 13,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 22,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 22,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 22,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 22,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 256,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 256,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 256,
        prefix_len: 6,
    },
    HuffmanDecodeEntry {
        val: 256,
        prefix_len: 6,
    },
];

const HUFFMAN_DECODE_255_255_254: &'static HuffmanDecodeTable = &HuffmanDecodeTable {
    entry: HUFFMAN_DECODE_ENTRIES_255_255_254,
    next_table: &[],
    index_of_first_next_table: 256,
    prefix_len: 4,
};

const HUFFMAN_DECODE_ENTRIES_255_255_254: &'static [HuffmanDecodeEntry] = &[
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 254,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 2,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 2,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 2,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 2,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 2,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 2,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 2,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 2,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 2,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 2,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 2,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 2,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 2,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 2,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 2,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 2,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 3,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 3,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 3,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 3,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 3,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 3,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 3,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 3,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 3,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 3,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 3,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 3,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 3,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 3,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 3,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 3,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 4,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 4,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 4,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 4,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 4,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 4,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 4,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 4,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 4,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 4,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 4,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 4,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 4,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 4,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 4,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 4,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 5,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 5,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 5,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 5,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 5,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 5,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 5,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 5,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 5,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 5,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 5,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 5,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 5,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 5,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 5,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 5,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 6,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 6,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 6,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 6,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 6,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 6,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 6,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 6,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 6,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 6,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 6,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 6,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 6,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 6,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 6,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 6,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 7,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 7,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 7,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 7,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 7,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 7,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 7,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 7,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 7,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 7,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 7,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 7,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 7,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 7,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 7,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 7,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 8,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 8,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 8,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 8,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 8,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 8,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 8,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 8,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 8,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 8,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 8,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 8,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 8,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 8,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 8,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 8,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 11,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 11,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 11,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 11,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 11,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 11,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 11,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 11,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 11,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 11,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 11,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 11,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 11,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 11,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 11,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 11,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 12,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 12,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 12,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 12,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 12,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 12,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 12,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 12,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 12,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 12,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 12,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 12,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 12,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 12,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 12,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 12,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 14,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 14,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 14,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 14,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 14,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 14,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 14,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 14,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 14,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 14,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 14,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 14,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 14,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 14,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 14,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 14,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 15,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 15,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 15,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 15,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 15,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 15,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 15,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 15,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 15,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 15,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 15,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 15,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 15,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 15,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 15,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 15,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 16,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 16,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 16,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 16,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 16,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 16,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 16,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 16,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 16,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 16,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 16,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 16,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 16,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 16,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 16,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 16,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 17,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 17,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 17,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 17,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 17,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 17,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 17,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 17,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 17,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 17,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 17,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 17,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 17,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 17,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 17,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 17,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 18,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 18,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 18,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 18,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 18,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 18,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 18,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 18,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 18,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 18,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 18,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 18,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 18,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 18,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 18,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 18,
        prefix_len: 4,
    },
];

const HUFFMAN_DECODE_255_255_253: &'static HuffmanDecodeTable = &HuffmanDecodeTable {
    entry: HUFFMAN_DECODE_ENTRIES_255_255_253,
    next_table: &[],
    index_of_first_next_table: 256,
    prefix_len: 3,
};

const HUFFMAN_DECODE_ENTRIES_255_255_253: &'static [HuffmanDecodeEntry] = &[
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 245,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 246,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 247,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 248,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 250,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 251,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 252,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 253,
        prefix_len: 3,
    },
];

const HUFFMAN_DECODE_255_255_252: &'static HuffmanDecodeTable = &HuffmanDecodeTable {
    entry: HUFFMAN_DECODE_ENTRIES_255_255_252,
    next_table: &[],
    index_of_first_next_table: 256,
    prefix_len: 3,
};

const HUFFMAN_DECODE_ENTRIES_255_255_252: &'static [HuffmanDecodeEntry] = &[
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 211,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 212,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 214,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 221,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 222,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 223,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 241,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 244,
        prefix_len: 3,
    },
];

const HUFFMAN_DECODE_255_255_251: &'static HuffmanDecodeTable = &HuffmanDecodeTable {
    entry: HUFFMAN_DECODE_ENTRIES_255_255_251,
    next_table: &[],
    index_of_first_next_table: 256,
    prefix_len: 3,
};

const HUFFMAN_DECODE_ENTRIES_255_255_251: &'static [HuffmanDecodeEntry] = &[
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 242,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 243,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 255,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 203,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 204,
        prefix_len: 3,
    },
];

const HUFFMAN_DECODE_255_255_250: &'static HuffmanDecodeTable = &HuffmanDecodeTable {
    entry: HUFFMAN_DECODE_ENTRIES_255_255_250,
    next_table: &[],
    index_of_first_next_table: 256,
    prefix_len: 2,
};

const HUFFMAN_DECODE_ENTRIES_255_255_250: &'static [HuffmanDecodeEntry] = &[
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 218,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 219,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 238,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 240,
        prefix_len: 2,
    },
];

const HUFFMAN_DECODE_255_255_249: &'static HuffmanDecodeTable = &HuffmanDecodeTable {
    entry: HUFFMAN_DECODE_ENTRIES_255_255_249,
    next_table: &[],
    index_of_first_next_table: 256,
    prefix_len: 2,
};

const HUFFMAN_DECODE_ENTRIES_255_255_249: &'static [HuffmanDecodeEntry] = &[
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 202,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 205,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 210,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 213,
        prefix_len: 2,
    },
];

const HUFFMAN_DECODE_255_255_248: &'static HuffmanDecodeTable = &HuffmanDecodeTable {
    entry: HUFFMAN_DECODE_ENTRIES_255_255_248,
    next_table: &[],
    index_of_first_next_table: 256,
    prefix_len: 2,
};

const HUFFMAN_DECODE_ENTRIES_255_255_248: &'static [HuffmanDecodeEntry] = &[
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 192,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 193,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 200,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 201,
        prefix_len: 2,
    },
];

const HUFFMAN_DECODE_255_255_247: &'static HuffmanDecodeTable = &HuffmanDecodeTable {
    entry: HUFFMAN_DECODE_ENTRIES_255_255_247,
    next_table: &[],
    index_of_first_next_table: 256,
    prefix_len: 1,
};

const HUFFMAN_DECODE_ENTRIES_255_255_247: &'static [HuffmanDecodeEntry] = &[
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 234,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 235,
        prefix_len: 1,
    },
];

const HUFFMAN_DECODE_255_255_246: &'static HuffmanDecodeTable = &HuffmanDecodeTable {
    entry: HUFFMAN_DECODE_ENTRIES_255_255_246,
    next_table: &[],
    index_of_first_next_table: 256,
    prefix_len: 1,
};

const HUFFMAN_DECODE_ENTRIES_255_255_246: &'static [HuffmanDecodeEntry] = &[
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 199,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
    HuffmanDecodeEntry {
        val: 207,
        prefix_len: 1,
    },
];

const HUFFMAN_DECODE_255_254: &'static HuffmanDecodeTable = &HuffmanDecodeTable {
    entry: HUFFMAN_DECODE_ENTRIES_255_254,
    next_table: &[],
    index_of_first_next_table: 256,
    prefix_len: 5,
};

const HUFFMAN_DECODE_ENTRIES_255_254: &'static [HuffmanDecodeEntry] = &[
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 92,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 195,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 208,
        prefix_len: 3,
    },
    HuffmanDecodeEntry {
        val: 128,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 128,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 128,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 128,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 128,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 128,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 128,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 128,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 128,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 128,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 128,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 128,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 128,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 128,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 128,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 128,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 130,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 130,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 130,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 130,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 130,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 130,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 130,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 130,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 130,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 130,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 130,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 130,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 130,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 130,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 130,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 130,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 131,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 131,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 131,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 131,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 131,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 131,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 131,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 131,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 131,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 131,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 131,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 131,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 131,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 131,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 131,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 131,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 162,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 162,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 162,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 162,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 162,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 162,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 162,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 162,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 162,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 162,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 162,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 162,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 162,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 162,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 162,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 162,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 184,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 184,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 184,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 184,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 184,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 184,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 184,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 184,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 184,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 184,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 184,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 184,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 184,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 184,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 184,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 184,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 194,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 194,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 194,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 194,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 194,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 194,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 194,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 194,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 194,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 194,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 194,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 194,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 194,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 194,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 194,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 194,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 224,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 224,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 224,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 224,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 224,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 224,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 224,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 224,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 224,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 224,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 224,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 224,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 224,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 224,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 224,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 224,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 226,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 226,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 226,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 226,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 226,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 226,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 226,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 226,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 226,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 226,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 226,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 226,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 226,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 226,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 226,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 226,
        prefix_len: 4,
    },
    HuffmanDecodeEntry {
        val: 153,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 153,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 153,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 153,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 153,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 153,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 153,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 153,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 161,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 161,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 161,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 161,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 161,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 161,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 161,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 161,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 167,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 167,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 167,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 167,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 167,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 167,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 167,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 167,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 172,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 172,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 172,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 172,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 172,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 172,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 172,
        prefix_len: 5,
    },
    HuffmanDecodeEntry {
        val: 172,
        prefix_len: 5,
    },
];

const HUFFMAN_DECODE_254: &'static HuffmanDecodeTable = &HuffmanDecodeTable {
    entry: HUFFMAN_DECODE_ENTRIES_254,
    next_table: &[],
    index_of_first_next_table: 256,
    prefix_len: 2,
};

const HUFFMAN_DECODE_ENTRIES_254: &'static [HuffmanDecodeEntry] = &[
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 33,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 34,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 40,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
    HuffmanDecodeEntry {
        val: 41,
        prefix_len: 2,
    },
];
