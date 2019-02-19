#[derive(Debug, Default, PartialEq, Eq, Hash)]
pub struct Stream {
    offset: u64,
}

impl Stream {
    pub fn new() -> Stream {
        Stream::default()
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn add_to_offset(&mut self, add_to_offset: u64) {
        self.offset += add_to_offset
    }
}
