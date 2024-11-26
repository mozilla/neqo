// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{array, collections::BinaryHeap, mem, ops::Range};

use neqo_crypto::random;

/// [Fisher–Yates shuffle](https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle#Modern_method)
/// Modified to make sure no element stays in place if `a` has more than one element.
///
/// We could use <https://docs.rs/rand/latest/rand/seq/trait.SliceRandom.html#tymethod.shuffle>
/// instead, but we're currently not depending on the `rand` crate and this is a simple enough
/// so we don't need to.
fn shuffle<T>(a: &mut [T]) {
    // To shuffle an array a of n elements (indices 0..n-1)
    const USIZE: usize = mem::size_of::<usize>();
    let n: usize = a.len();
    if n < 2 {
        return;
    }
    for i in 0..(n - 1) {
        // j ← random integer such that i ≤ j < n
        let j = usize::from_ne_bytes(random::<USIZE>()) % (n - i - 1) + i + 1;
        // Exchange a[i] and a[j]
        debug_assert!(i != j);
        a.swap(i, j);
    }
}

/// Find the ranges of all sequences of two or more ASCII "LDHD" (letters, digits, hyphens, dots)
/// bytes in `data`, and return the `N` longest ones in ascending order by start index.
fn ascii_sequences<const N: usize>(data: &[u8]) -> impl Iterator<Item = Range<usize>> {
    #[derive(Eq, PartialEq, Debug)]
    struct Sequence(Range<usize>);

    impl PartialOrd for Sequence {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for Sequence {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.0.len().cmp(&other.0.len())
        }
    }

    const fn is_ascii_ldhd(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'-' || b == b'.'
    }

    let mut sequences = BinaryHeap::new();
    let mut start = None;
    for (i, &b) in data.iter().enumerate() {
        if is_ascii_ldhd(b) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start {
            if i - s >= 2 {
                sequences.push(Sequence(s..i));
            }
            start = None;
        }
    }
    if let Some(s) = start {
        if data.len() - s >= 2 {
            sequences.push(Sequence(s..data.len()));
        }
    }
    let mut sequences: [_; N] = array::from_fn(|_| sequences.pop().unwrap());
    sequences.sort_by(|a, b| a.0.start.cmp(&b.0.start));
    sequences.into_iter().map(|Sequence(r)| r)
}

/// Reorder `data` into chunks roughly delimited by the midpoints of ASCII "LDHD" (letters, digits,
/// hyphens, dots) sequences.
///
/// Look for the `N` longest ranges of ASCII "LDHD" characters in `data`. Create split points
/// halfway into each range. Chunks the data based on those split points, shuffle the chunks and
/// return them.
///
/// # Panics
///
/// When `u64` values cannot be converted to `usize`.
#[must_use]
pub fn reorder_chunks<const N: usize>(mut data: &[u8]) -> Vec<(u64, &[u8])> {
    let mut chunks = vec![];
    let mut last = 0;
    for Range { start, end } in ascii_sequences::<N>(data) {
        let mid = start + (end - start) / 2 - last;
        let (left, right) = data.split_at(mid);
        chunks.push((u64::try_from(last).unwrap(), left));
        last += mid;
        data = right;
    }
    chunks.push((u64::try_from(last).unwrap(), data));
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
        // Empty input
        let data = b"";
        let mut sequences = super::ascii_sequences::<1>(data);
        assert!(sequences.next().is_none());

        // No LDHD ASCII
        let data = b"\x00\x01\x02";
        let mut sequences = super::ascii_sequences::<2>(data);
        assert!(sequences.next().is_none());

        // Sequences shorter than two
        let data = b"a\x00b";
        let mut sequences = super::ascii_sequences::<3>(data);
        assert!(sequences.next().is_none());

        // One valid sequence of the required length
        let data = b"ab";
        let sequences = super::ascii_sequences::<1>(data);
        assert_eq!(sequences.collect::<Vec<_>>(), vec![0..2]);

        // Multiple valid sequences
        let data = b"abc\x00defg\x00hi";
        let sequences = super::ascii_sequences::<3>(data);
        assert_eq!(sequences.collect::<Vec<_>>(), vec![0..3, 4..8, 9..11]);
        // Multiple valid sequences, pick one
        let sequences = super::ascii_sequences::<1>(data);
        assert_eq!(sequences.collect::<Vec<_>>(), vec![4..8]);

        // One sequence at the end of data
        let data = b"\x00\x00abcde";
        let sequences = super::ascii_sequences::<2>(data);
        assert_eq!(sequences.collect::<Vec<_>>(), vec![2..7]);

        // One sequence at the beginning of data
        let data = b"abcde\x00\x00";
        let sequences = super::ascii_sequences::<2>(data);
        assert_eq!(sequences.collect::<Vec<_>>(), vec![0..5]);
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
        let chunks = super::reorder_chunks::<1>(data);
        assert_eq!(chunks, vec![(0, data.as_ref())]);
        assert_complete(data, &chunks);

        // Data without ASCII sequences -> output == input
        let data = b"\x00\x01\x02";
        let chunks = super::reorder_chunks::<1>(data);
        assert_eq!(chunks, vec![(0, data.as_ref())]);
        assert_complete(data, &chunks);

        // Data containing one ASCII sequence -> one predictable reordering
        let data = b"ab";
        let chunks = super::reorder_chunks::<1>(data);
        assert_eq!(chunks, vec![(1, &data[1..2]), (0, &data[0..1])]);
        assert_complete(data, &chunks);
        let chunks = super::reorder_chunks::<2>(data);
        assert_eq!(chunks, vec![(1, &data[1..2]), (0, &data[0..1])]);
        assert_complete(data, &chunks);

        // Data containing two ASCII sequences -> one of two predictable reorderings
        let data = b"abc\x00def";
        let chunks = super::reorder_chunks::<2>(data);
        assert_eq!(chunks.len(), 3); // 2 splits create 3 chunks
        let order1 = [(1, &data[1..5]), (5, &data[5..7]), (0, &data[0..1])];
        let order2 = [(5, &data[5..7]), (0, &data[0..1]), (1, &data[1..5])];
        assert!(chunks == order1 || chunks == order2);
        assert_complete(data, &chunks);

        // Data containing two ASCII sequences, pick one -> one predictable reordering
        let data = b"abcd\x00ef";
        let chunks = super::reorder_chunks::<1>(data);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks, vec![(2, &data[2..7]), (0, &data[0..2])]);
        assert_complete(data, &chunks);

        // Data containing three ASCII sequences
        let data = b"abc\x00defg\x00hijkl";
        let chunks = super::reorder_chunks::<3>(data);
        // Too many possibilities to check, just check that the output is valid
        assert_eq!(chunks.len(), 4); // 3 splits create 4 chunks
        assert_complete(data, &chunks);
    }
}
