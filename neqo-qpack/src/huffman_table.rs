#[derive(Debug, Copy, Clone)]
pub struct HuffmanTableEntry {
    pub len: u8,
    pub val: u32,
}

// Table contains the raw HPACK Huffman table
pub const HUFFMAN_TABLE: &'static [HuffmanTableEntry] = &[
    HuffmanTableEntry {
        len: 13,
        val: 0x1ff8,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7fffd8,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xfffffe2,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xfffffe3,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xfffffe4,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xfffffe5,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xfffffe6,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xfffffe7,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xfffffe8,
    },
    HuffmanTableEntry {
        len: 24,
        val: 0xffffea,
    },
    HuffmanTableEntry {
        len: 30,
        val: 0x3ffffffc,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xfffffe9,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xfffffea,
    },
    HuffmanTableEntry {
        len: 30,
        val: 0x3ffffffd,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xfffffeb,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xfffffec,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xfffffed,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xfffffee,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xfffffef,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xffffff0,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xffffff1,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xffffff2,
    },
    HuffmanTableEntry {
        len: 30,
        val: 0x3ffffffe,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xffffff3,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xffffff4,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xffffff5,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xffffff6,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xffffff7,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xffffff8,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xffffff9,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xffffffa,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xffffffb,
    },
    HuffmanTableEntry { len: 6, val: 0x14 }, // ' '
    HuffmanTableEntry {
        len: 10,
        val: 0x3f8,
    }, // !
    HuffmanTableEntry {
        len: 10,
        val: 0x3f9,
    }, // '"'
    HuffmanTableEntry {
        len: 12,
        val: 0xffa,
    }, // '#'
    HuffmanTableEntry {
        len: 13,
        val: 0x1ff9,
    }, // '$'
    HuffmanTableEntry { len: 6, val: 0x15 }, // '%'
    HuffmanTableEntry { len: 8, val: 0xf8 }, // '&'
    HuffmanTableEntry {
        len: 11,
        val: 0x7fa,
    }, // '''
    HuffmanTableEntry {
        len: 10,
        val: 0x3fa,
    }, // '('
    HuffmanTableEntry {
        len: 10,
        val: 0x3fb,
    }, // ')'
    HuffmanTableEntry { len: 8, val: 0xf9 }, // '*'
    HuffmanTableEntry {
        len: 11,
        val: 0x7fb,
    }, // '+'
    HuffmanTableEntry { len: 8, val: 0xfa }, // ','
    HuffmanTableEntry { len: 6, val: 0x16 }, // '-'
    HuffmanTableEntry { len: 6, val: 0x17 }, // '.'
    HuffmanTableEntry { len: 6, val: 0x18 }, // '/'
    HuffmanTableEntry { len: 5, val: 0x0 },  // '0'
    HuffmanTableEntry { len: 5, val: 0x1 },  // '1'
    HuffmanTableEntry { len: 5, val: 0x2 },  // '2'
    HuffmanTableEntry { len: 6, val: 0x19 }, // '3'
    HuffmanTableEntry { len: 6, val: 0x1a }, // '4'
    HuffmanTableEntry { len: 6, val: 0x1b }, // '5'
    HuffmanTableEntry { len: 6, val: 0x1c }, // '6'
    HuffmanTableEntry { len: 6, val: 0x1d }, // '7'
    HuffmanTableEntry { len: 6, val: 0x1e }, // '8'
    HuffmanTableEntry { len: 6, val: 0x1f }, // '9'
    HuffmanTableEntry { len: 7, val: 0x5c }, // ':'
    HuffmanTableEntry { len: 8, val: 0xfb }, // ';'
    HuffmanTableEntry {
        len: 15,
        val: 0x7ffc,
    }, // '<'
    HuffmanTableEntry { len: 6, val: 0x20 }, // '='
    HuffmanTableEntry {
        len: 12,
        val: 0xffb,
    }, // '>'
    HuffmanTableEntry {
        len: 10,
        val: 0x3fc,
    }, // '?'
    HuffmanTableEntry {
        len: 13,
        val: 0x1ffa,
    }, // '@'
    HuffmanTableEntry { len: 6, val: 0x21 }, // 'A'
    HuffmanTableEntry { len: 7, val: 0x5d }, // 'B'
    HuffmanTableEntry { len: 7, val: 0x5e }, // 'C'
    HuffmanTableEntry { len: 7, val: 0x5f }, // 'D'
    HuffmanTableEntry { len: 7, val: 0x60 }, // 'E'
    HuffmanTableEntry { len: 7, val: 0x61 }, // 'F'
    HuffmanTableEntry { len: 7, val: 0x62 }, // 'G'
    HuffmanTableEntry { len: 7, val: 0x63 }, // 'H'
    HuffmanTableEntry { len: 7, val: 0x64 }, // 'I'
    HuffmanTableEntry { len: 7, val: 0x65 }, // 'J'
    HuffmanTableEntry { len: 7, val: 0x66 }, // 'K'
    HuffmanTableEntry { len: 7, val: 0x67 }, // 'L'
    HuffmanTableEntry { len: 7, val: 0x68 }, // 'M'
    HuffmanTableEntry { len: 7, val: 0x69 }, // 'N'
    HuffmanTableEntry { len: 7, val: 0x6a }, // 'O'
    HuffmanTableEntry { len: 7, val: 0x6b }, // 'P'
    HuffmanTableEntry { len: 7, val: 0x6c }, // 'Q'
    HuffmanTableEntry { len: 7, val: 0x6d }, // 'R'
    HuffmanTableEntry { len: 7, val: 0x6e }, // 'S'
    HuffmanTableEntry { len: 7, val: 0x6f }, // 'T'
    HuffmanTableEntry { len: 7, val: 0x70 }, // 'U'
    HuffmanTableEntry { len: 7, val: 0x71 }, // 'V'
    HuffmanTableEntry { len: 7, val: 0x72 }, // 'W'
    HuffmanTableEntry { len: 8, val: 0xfc }, // 'X'
    HuffmanTableEntry { len: 7, val: 0x73 }, // 'Y'
    HuffmanTableEntry { len: 8, val: 0xfd }, // 'Z'
    HuffmanTableEntry {
        len: 13,
        val: 0x1ffb,
    }, // '['
    HuffmanTableEntry {
        len: 19,
        val: 0x7fff0,
    }, // '\'
    HuffmanTableEntry {
        len: 13,
        val: 0x1ffc,
    }, // ']'
    HuffmanTableEntry {
        len: 14,
        val: 0x3ffc,
    }, // '^'
    HuffmanTableEntry { len: 6, val: 0x22 }, // '_'
    HuffmanTableEntry {
        len: 15,
        val: 0x7ffd,
    }, // '`'
    HuffmanTableEntry { len: 5, val: 0x3 },  // 'a'
    HuffmanTableEntry { len: 6, val: 0x23 }, // 'b'
    HuffmanTableEntry { len: 5, val: 0x4 },  // 'c'
    HuffmanTableEntry { len: 6, val: 0x24 }, // 'd'
    HuffmanTableEntry { len: 5, val: 0x5 },  // 'e'
    HuffmanTableEntry { len: 6, val: 0x25 }, // 'f'
    HuffmanTableEntry { len: 6, val: 0x26 }, // 'g'
    HuffmanTableEntry { len: 6, val: 0x27 }, // 'h'
    HuffmanTableEntry { len: 5, val: 0x6 },  // 'i'
    HuffmanTableEntry { len: 7, val: 0x74 }, // 'j'
    HuffmanTableEntry { len: 7, val: 0x75 }, // 'k'
    HuffmanTableEntry { len: 6, val: 0x28 }, // 'l'
    HuffmanTableEntry { len: 6, val: 0x29 }, // 'm'
    HuffmanTableEntry { len: 6, val: 0x2a }, // 'n'
    HuffmanTableEntry { len: 5, val: 0x7 },  // 'o'
    HuffmanTableEntry { len: 6, val: 0x2b }, // 'p'
    HuffmanTableEntry { len: 7, val: 0x76 }, // 'q'
    HuffmanTableEntry { len: 6, val: 0x2c }, // 'r'
    HuffmanTableEntry { len: 5, val: 0x8 },  // 's'
    HuffmanTableEntry { len: 5, val: 0x9 },  // 't'
    HuffmanTableEntry { len: 6, val: 0x2d }, // 'u'
    HuffmanTableEntry { len: 7, val: 0x77 }, // 'v'
    HuffmanTableEntry { len: 7, val: 0x78 }, // 'w'
    HuffmanTableEntry { len: 7, val: 0x79 }, // 'x'
    HuffmanTableEntry { len: 7, val: 0x7a }, // 'y'
    HuffmanTableEntry { len: 7, val: 0x7b }, // 'z'
    HuffmanTableEntry {
        len: 15,
        val: 0x7ffe,
    }, // '{'
    HuffmanTableEntry {
        len: 11,
        val: 0x7fc,
    }, // '|'
    HuffmanTableEntry {
        len: 14,
        val: 0x3ffd,
    }, // '}'
    HuffmanTableEntry {
        len: 13,
        val: 0x1ffd,
    }, // ~
    HuffmanTableEntry {
        len: 28,
        val: 0xffffffc,
    },
    HuffmanTableEntry {
        len: 20,
        val: 0xfffe6,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffd2,
    },
    HuffmanTableEntry {
        len: 20,
        val: 0xfffe7,
    },
    HuffmanTableEntry {
        len: 20,
        val: 0xfffe8,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffd3,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffd4,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffd5,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7fffd9,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffd6,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7fffda,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7fffdb,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7fffdc,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7fffdd,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7fffde,
    },
    HuffmanTableEntry {
        len: 24,
        val: 0xffffeb,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7fffdf,
    },
    HuffmanTableEntry {
        len: 24,
        val: 0xffffec,
    },
    HuffmanTableEntry {
        len: 24,
        val: 0xffffed,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffd7,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7fffe0,
    },
    HuffmanTableEntry {
        len: 24,
        val: 0xffffee,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7fffe1,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7fffe2,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7fffe3,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7fffe4,
    },
    HuffmanTableEntry {
        len: 21,
        val: 0x1fffdc,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffd8,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7fffe5,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffd9,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7fffe6,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7fffe7,
    },
    HuffmanTableEntry {
        len: 24,
        val: 0xffffef,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffda,
    },
    HuffmanTableEntry {
        len: 21,
        val: 0x1fffdd,
    },
    HuffmanTableEntry {
        len: 20,
        val: 0xfffe9,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffdb,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffdc,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7fffe8,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7fffe9,
    },
    HuffmanTableEntry {
        len: 21,
        val: 0x1fffde,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7fffea,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffdd,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffde,
    },
    HuffmanTableEntry {
        len: 24,
        val: 0xfffff0,
    },
    HuffmanTableEntry {
        len: 21,
        val: 0x1fffdf,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffdf,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7fffeb,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7fffec,
    },
    HuffmanTableEntry {
        len: 21,
        val: 0x1fffe0,
    },
    HuffmanTableEntry {
        len: 21,
        val: 0x1fffe1,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffe0,
    },
    HuffmanTableEntry {
        len: 21,
        val: 0x1fffe2,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7fffed,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffe1,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7fffee,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7fffef,
    },
    HuffmanTableEntry {
        len: 20,
        val: 0xfffea,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffe2,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffe3,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffe4,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7ffff0,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffe5,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffe6,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7ffff1,
    },
    HuffmanTableEntry {
        len: 26,
        val: 0x3ffffe0,
    },
    HuffmanTableEntry {
        len: 26,
        val: 0x3ffffe1,
    },
    HuffmanTableEntry {
        len: 20,
        val: 0xfffeb,
    },
    HuffmanTableEntry {
        len: 19,
        val: 0x7fff1,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffe7,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7ffff2,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffe8,
    },
    HuffmanTableEntry {
        len: 25,
        val: 0x1ffffec,
    },
    HuffmanTableEntry {
        len: 26,
        val: 0x3ffffe2,
    },
    HuffmanTableEntry {
        len: 26,
        val: 0x3ffffe3,
    },
    HuffmanTableEntry {
        len: 26,
        val: 0x3ffffe4,
    },
    HuffmanTableEntry {
        len: 27,
        val: 0x7ffffde,
    },
    HuffmanTableEntry {
        len: 27,
        val: 0x7ffffdf,
    },
    HuffmanTableEntry {
        len: 26,
        val: 0x3ffffe5,
    },
    HuffmanTableEntry {
        len: 24,
        val: 0xfffff1,
    },
    HuffmanTableEntry {
        len: 25,
        val: 0x1ffffed,
    },
    HuffmanTableEntry {
        len: 19,
        val: 0x7fff2,
    },
    HuffmanTableEntry {
        len: 21,
        val: 0x1fffe3,
    },
    HuffmanTableEntry {
        len: 26,
        val: 0x3ffffe6,
    },
    HuffmanTableEntry {
        len: 27,
        val: 0x7ffffe0,
    },
    HuffmanTableEntry {
        len: 27,
        val: 0x7ffffe1,
    },
    HuffmanTableEntry {
        len: 26,
        val: 0x3ffffe7,
    },
    HuffmanTableEntry {
        len: 27,
        val: 0x7ffffe2,
    },
    HuffmanTableEntry {
        len: 24,
        val: 0xfffff2,
    },
    HuffmanTableEntry {
        len: 21,
        val: 0x1fffe4,
    },
    HuffmanTableEntry {
        len: 21,
        val: 0x1fffe5,
    },
    HuffmanTableEntry {
        len: 26,
        val: 0x3ffffe8,
    },
    HuffmanTableEntry {
        len: 26,
        val: 0x3ffffe9,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xffffffd,
    },
    HuffmanTableEntry {
        len: 27,
        val: 0x7ffffe3,
    },
    HuffmanTableEntry {
        len: 27,
        val: 0x7ffffe4,
    },
    HuffmanTableEntry {
        len: 27,
        val: 0x7ffffe5,
    },
    HuffmanTableEntry {
        len: 20,
        val: 0xfffec,
    },
    HuffmanTableEntry {
        len: 24,
        val: 0xfffff3,
    },
    HuffmanTableEntry {
        len: 20,
        val: 0xfffed,
    },
    HuffmanTableEntry {
        len: 21,
        val: 0x1fffe6,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffe9,
    },
    HuffmanTableEntry {
        len: 21,
        val: 0x1fffe7,
    },
    HuffmanTableEntry {
        len: 21,
        val: 0x1fffe8,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7ffff3,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffea,
    },
    HuffmanTableEntry {
        len: 22,
        val: 0x3fffeb,
    },
    HuffmanTableEntry {
        len: 25,
        val: 0x1ffffee,
    },
    HuffmanTableEntry {
        len: 25,
        val: 0x1ffffef,
    },
    HuffmanTableEntry {
        len: 24,
        val: 0xfffff4,
    },
    HuffmanTableEntry {
        len: 24,
        val: 0xfffff5,
    },
    HuffmanTableEntry {
        len: 26,
        val: 0x3ffffea,
    },
    HuffmanTableEntry {
        len: 23,
        val: 0x7ffff4,
    },
    HuffmanTableEntry {
        len: 26,
        val: 0x3ffffeb,
    },
    HuffmanTableEntry {
        len: 27,
        val: 0x7ffffe6,
    },
    HuffmanTableEntry {
        len: 26,
        val: 0x3ffffec,
    },
    HuffmanTableEntry {
        len: 26,
        val: 0x3ffffed,
    },
    HuffmanTableEntry {
        len: 27,
        val: 0x7ffffe7,
    },
    HuffmanTableEntry {
        len: 27,
        val: 0x7ffffe8,
    },
    HuffmanTableEntry {
        len: 27,
        val: 0x7ffffe9,
    },
    HuffmanTableEntry {
        len: 27,
        val: 0x7ffffea,
    },
    HuffmanTableEntry {
        len: 27,
        val: 0x7ffffeb,
    },
    HuffmanTableEntry {
        len: 28,
        val: 0xffffffe,
    },
    HuffmanTableEntry {
        len: 27,
        val: 0x7ffffec,
    },
    HuffmanTableEntry {
        len: 27,
        val: 0x7ffffed,
    },
    HuffmanTableEntry {
        len: 27,
        val: 0x7ffffee,
    },
    HuffmanTableEntry {
        len: 27,
        val: 0x7ffffef,
    },
    HuffmanTableEntry {
        len: 27,
        val: 0x7fffff0,
    },
    HuffmanTableEntry {
        len: 26,
        val: 0x3ffffee,
    },
    //        HuffmanTableEntry { len: 30, val: 0x3fffffff},
];
