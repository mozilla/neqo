#![cfg_attr(all(fuzzing, not(windows)), no_main)]

#[cfg(all(fuzzing, not(windows)))]
use libfuzzer_sys::fuzz_target;

#[cfg(all(fuzzing, not(windows)))]
fuzz_target!(|data: &[u8]| {
    use std::time::Instant;

    use neqo_http3::frames::{
        hframe::HFrame,
        reader::{FrameReader, StreamReader},
    };
    use test_fixture::now;

    struct FuzzStreamReader<'a> {
        data: &'a [u8],
        offset: usize,
    }

    impl StreamReader for FuzzStreamReader<'_> {
        fn read_data(
            &mut self,
            buf: &mut [u8],
            _now: Instant,
        ) -> Result<(usize, bool), neqo_http3::Error> {
            let remaining = self.data.len() - self.offset;
            let to_read = std::cmp::min(buf.len(), remaining);

            if to_read > 0 {
                buf[..to_read].copy_from_slice(&self.data[self.offset..self.offset + to_read]);
                self.offset += to_read;
            }

            let fin = self.offset >= self.data.len();
            Ok((to_read, fin))
        }
    }

    let mut frame_reader = FrameReader::new();
    let mut stream = FuzzStreamReader { data, offset: 0 };

    // Attempt to decode an HFrame from the fuzzed input
    _ = frame_reader.receive::<HFrame>(&mut stream, now());
});

#[cfg(any(not(fuzzing), windows))]
fn main() {}
