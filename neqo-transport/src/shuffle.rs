// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::ops::Range;

use neqo_common::qtrace;

/// Finds the range where the SNI extension lives.
///
/// If this isn't a `ClientHello` or the range cannot be found, return the whole message.
fn find_sni(buf: &[u8]) -> Range<usize> {
    // Read a big-endian integer from `buf`.
    fn read_len(buf: &[u8]) -> usize {
        let mut len = 0;
        for v in buf {
            len = (len << 8) + usize::from(*v);
        }
        len
    }

    // Advance `i` by the value read from the `N` bytes at `i`, and return the new index.
    // If the buffer is too short, return `None`.
    fn skip_vec<const N: usize>(i: usize, buf: &[u8]) -> Option<usize> {
        if i + N > buf.len() {
            return None;
        }
        let i = i + N + read_len(&buf[i..i + N]);
        if i > buf.len() {
            None
        } else {
            Some(i)
        }
    }

    let mut i = 1 + 3 + 2 + 32; // msg_type, length, version, random

    // Return if buf is too short or does not contain a ClientHello (first byte== 1)
    if buf.len() < i || buf[0] != 1 {
        return 0..buf.len();
    }

    // Skip session_id
    i = if let Some(i) = skip_vec::<1>(i, buf) {
        i
    } else {
        return 0..buf.len();
    };

    // Skip cipher_suites
    i = if let Some(i) = skip_vec::<2>(i, buf) {
        i
    } else {
        return 0..buf.len();
    };

    // Skip compression_methods
    i = if let Some(i) = skip_vec::<1>(i, buf) {
        i
    } else {
        return 0..buf.len();
    };

    i += 2; // Skip extensions length

    while i + 4 < buf.len() {
        if buf[i] == 0 && buf[i + 1] == 0 {
            // SNI!
            i += 2;
            let len = read_len(&buf[i..i + 2]);
            if len < 2 || i + len > buf.len() {
                break;
            }
            return i + 2..i + len;
        }
        // Skip extension
        i = if let Some(i) = skip_vec::<2>(i, buf) {
            i
        } else {
            break;
        };
    }
    0..buf.len()
}

/// Find the index range of the SNI extension in `data`, split `data` in half at the midpoint of
/// the SNI extension, and return the two halves and their respective starting indexes in reverse
/// order.
///
/// # Panics
///
/// When `u64` values cannot be converted to `usize`.
#[must_use]
pub fn reorder_chunks(data: &[u8]) -> [(u64, &[u8]); 2] {
    let Range { start, end } = find_sni(data);
    qtrace!("Extracted SNI: {:?}", String::from_utf8_lossy(&data[start..end]));
    let mid = start + (end - start) / 2;
    let (left, right) = data.split_at(mid);
    [(mid.try_into().unwrap(), right), (0, left)]
}

#[cfg(test)]
mod tests {

    const BUF_WITH_SNI: &[u8] = &[
        0x01, // msg_type == 1 (ClientHello)
        0x00, 0x00, 0x3a, // length (arbitrary)
        0x03, 0x03, // version (TLS 1.2)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, // random
        0x00, // session_id length
        0x00, 0x02, // cipher_suites length
        0x13, 0x01, // cipher_suites
        0x00, // compression_methods length
        0x00, 0x16, // extensions length
        // SNI extension
        0x00, 0x00, // Extension type (SNI)
        0x00, 0x12, // Extension length
        0x00, 0x10, // Server Name Indication length
        0x00, // Name type (host_name)
        0x00, 0x0d, // Host name length
        b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', // example.com
    ];

    #[test]
    fn find_sni() {
        // Construct a buffer representing a ClientHello with SNI extension
        let range = super::find_sni(BUF_WITH_SNI);
        let expected_range = BUF_WITH_SNI.len() - 16..BUF_WITH_SNI.len();
        assert_eq!(range, expected_range);
        assert_eq!(&BUF_WITH_SNI[range], b"\x00\x10\x00\x00\x0dexample.com");
    }

    #[test]
    fn find_sni_no_sni() {
        // Construct a buffer representing a ClientHello without SNI extension
        let mut buf = Vec::from(&BUF_WITH_SNI[..BUF_WITH_SNI.len() - 20]);
        let len = buf.len();
        buf[len - 1] = 0x00; // Change the last byte of extensions length to 0
        let range = super::find_sni(&buf);
        assert_eq!(range, 0..buf.len());
    }

    #[test]
    fn find_sni_invalid_sni() {
        // Construct a buffer representing a ClientHello with an invalid SNI extension
        let truncated = &BUF_WITH_SNI[..BUF_WITH_SNI.len() - 13];
        let range = super::find_sni(truncated);
        assert_eq!(range, 0..truncated.len());
    }

    #[test]
    fn find_sni_no_client_hello() {
        // Buffer that does not represent a ClientHello (msg_type != 1)
        let buf = vec![2; 50];
        let range = super::find_sni(&buf);
        assert_eq!(range, 0..buf.len());
    }

    #[test]
    fn find_sni_malformed() {
        // Buffers that are too short to contain a ClientHello
        for len in 0..1024 {
            let buf = vec![1; len];
            let range = super::find_sni(&buf);
            assert_eq!(range, 0..buf.len());
        }
    }

    #[test]
    fn reorder_chunks() {
        let chunks = super::reorder_chunks(BUF_WITH_SNI);

        // Test that the chunk lengths sum to the total length
        let total_length: usize = chunks.iter().map(|(_, chunk)| chunk.len()).sum();
        assert_eq!(total_length, BUF_WITH_SNI.len());

        // Test that the combined chunks cover the entire data
        let mut reconstructed = vec![0; BUF_WITH_SNI.len()];
        for (index, data) in chunks {
            let idx: usize = index.try_into().unwrap();
            reconstructed.splice(idx..idx + data.len(), data.iter().copied());
        }
        assert_eq!(BUF_WITH_SNI, reconstructed.as_slice());
    }
}
