// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{cmp::min, ops::Range};

use neqo_crypto::randomize;

/// [Fisher–Yates shuffle](https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle#Modern_method)
/// Modified to make sure no element stays in place if `a` has more than one element.
///
/// We could use <https://docs.rs/rand/latest/rand/seq/trait.SliceRandom.html#tymethod.shuffle>
/// instead, but we're currently not depending on the `rand` crate and this is a simple enough
/// so we don't need to.
fn shuffle<T>(a: &mut [T]) {
    // To shuffle an array a of n elements (indices 0..n-1)
    let n: usize = a.len();
    if n < 2 {
        return;
    }
    let mut randomness = [0; 32];
    let count = min(randomness.len(), n - 1);
    randomize(&mut randomness[..count]);
    for (i, r) in randomness.iter().enumerate().take(count) {
        let j = usize::from(*r) % (n - i - 1) + i + 1;
        a.swap(i, j);
    }
}

/// Find the ranges of all sequences of `len` or more ASCII "LDHD" (letters, digits,
/// hyphens, dots) bytes in `data`.
fn ascii_sequences(data: &[u8], len: usize) -> Vec<Range<usize>> {
    const fn is_ascii_ldhd(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'-' || b == b'.'
    }

    let mut sequences = vec![];
    let mut start = None;
    for (i, &b) in data.iter().enumerate() {
        if is_ascii_ldhd(b) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start {
            if i - s >= len {
                sequences.push(s..i);
            }
            start = None;
        }
    }
    if let Some(s) = start {
        if data.len() - s >= len {
            sequences.push(s..data.len());
        }
    }
    sequences
}

/// Reorder `data` into chunks delimited by ASCII "LDHD" (letters, digits, hyphens, dots) sequences.
///
/// Look for ranges of `N` or more bytes of graphical ASCII "LDHD" data in `data`. Create at least
/// one split point at `N/2` into the range for each range, multiple ones each `N` bytes afterwards
/// if the range is long enough. Create data chunks based on those split points. Shuffle the chunks
/// and return them.
#[must_use]
pub fn reorder_chunks(data: &[u8]) -> Vec<(u64, &[u8])> {
    const N: usize = 3;
    // FIXME: Suggestion from @martinthomson; fails tests:
    // let mut data = data;
    // let mut used = 0;
    // let ranges = ascii_sequences(data, N);
    // let mut chunks = Vec::with_capacity(ranges.len() + 1);
    // for Range { start, end: _ } in ranges {
    //     debug_assert!(start > used);
    //     let (left, right) = data.split_at(start + N / 2 - used);
    //     chunks.push((u64::try_from(used).unwrap(), left));
    //     used += left.len();
    //     data = right;
    // }
    // shuffle(&mut chunks);
    // chunks
    let mut splits = vec![];
    // For each sequence, split it into chunks of `N` bytes.
    for Range { mut start, end } in ascii_sequences(data, N) {
        while start + N <= end {
            splits.push(start + N / 2);
            start += N;
        }
    }
    let mut chunks = vec![];
    let mut start = 0;
    for split in splits {
        let chunk = &data[start..split];
        chunks.push((start as u64, chunk));
        start = split;
    }
    chunks.push((start as u64, &data[start..]));
    shuffle(&mut chunks);
    chunks
}

#[cfg(test)]
mod tests {
    use test_fixture::fixture_init;

    #[test]
    fn shuffle() {
        fixture_init();

        // Empty arrays should remain empty.
        let mut a: [i32; 0] = [];
        let b = a;
        super::shuffle(&mut a);
        assert_eq!(a, b);

        // For a one-element array, the only possible shuffle is the identity.
        let mut a = [1];
        let b = a;
        super::shuffle(&mut a);
        assert_eq!(a, b);

        // For a two-element array, the only possible shuffle is the reverse, since `shuffle`
        // doesn't leave any element in place.
        let mut a = [1, 2];
        let mut b = a;
        super::shuffle(&mut a);
        b.reverse();
        assert_eq!(a, b);

        // For three-element and longer arrays, the shuffle is always different from the original.
        let mut a = [1, 2, 3];
        let b = a;
        super::shuffle(&mut a);
        assert_ne!(a, b);
    }

    #[test]
    fn ascii_sequences() {
        const N: usize = 3;

        // Empty input
        let data = b"";
        let sequences = super::ascii_sequences(data, N);
        assert!(sequences.is_empty());

        // No LDHD ASCII
        let data = b"\x00\x01\x02";
        let sequences = super::ascii_sequences(data, N);
        assert!(sequences.is_empty());

        // Sequences shorter than required length
        let data = b"ab\x00cd";
        let sequences = super::ascii_sequences(data, N);
        assert!(sequences.is_empty());

        // One valid sequence of the required length
        let data = b"abc";
        let sequences = super::ascii_sequences(data, N);
        assert_eq!(sequences, vec![0..3]);

        // Multiple valid sequences
        let data = b"abc\x00defgh\x00ijklmno";
        let sequences = super::ascii_sequences(data, N);
        assert_eq!(sequences, vec![0..3, 4..9, 10..17]);

        // One sequence at the end of data
        let data = b"\x00\x00abcde";
        let sequences = super::ascii_sequences(data, N);
        assert_eq!(sequences, vec![2..7]);

        // One sequence at the beginning of data
        let data = b"abcde\x00\x00";
        let sequences = super::ascii_sequences(data, N);
        assert_eq!(sequences, vec![0..5]);
    }

    #[test]
    fn reorder_chunks() {
        fn assert_complete(data: &[u8], chunks: &[(u64, &[u8])]) {
            // Footgun prevention
            const EMPTY: u8 = 0xff;
            assert!(!data.contains(&EMPTY));

            // Test that the chunk lengths sum to the total length
            let total_length: usize = chunks.iter().map(|(_, chunk)| chunk.len()).sum();
            assert_eq!(total_length, data.len());

            // Test that the combined chunks cover the entire data
            let mut reconstructed = vec![EMPTY; data.len()];
            for &(index, data) in chunks {
                let idx: usize = index.try_into().unwrap();
                reconstructed.splice(idx..idx + data.len(), data.iter().copied());
            }
            assert_eq!(data, reconstructed.as_slice());
        }

        fixture_init();

        // Empty input -> empty output
        let data = b"";
        let chunks = super::reorder_chunks(data);
        assert_eq!(chunks, vec![(0, data.as_ref())]);
        assert_complete(data, &chunks);

        // Data without graphic ASCII sequences -> output == input
        let data = b"\x00\x01\x02";
        let chunks = super::reorder_chunks(data);
        assert_eq!(chunks, vec![(0, data.as_ref())]);
        assert_complete(data, &chunks);

        // Data containing one graphic ASCII sequence -> one predictable reordering
        let data = b"abc";
        let chunks = super::reorder_chunks(data);
        assert_eq!(chunks, vec![(1, &data[1..3]), (0, &data[0..1])]);
        assert_complete(data, &chunks);

        // Data containing two graphic ASCII sequences -> one of two predictable reorderings
        let data = b"abc\x00def";
        let chunks = super::reorder_chunks(data);
        assert_eq!(chunks.len(), 3); // 2 splits create 3 chunks
        let order1 = [(1, &data[1..5]), (5, &data[5..7]), (0, &data[0..1])];
        let order2 = [(5, &data[5..7]), (0, &data[0..1]), (1, &data[1..5])];
        assert!(chunks == order1 || chunks == order2);
        assert_complete(data, &chunks);

        // Data containing three graphic ASCII sequences
        let data = b"abc\x00defg\x00hijkl";
        let chunks = super::reorder_chunks(data);
        // Too many possibilities to check, just check that the output is valid
        assert_eq!(chunks.len(), 4); // 3 splits create 4 chunks
        assert_complete(data, &chunks);
    }
}
