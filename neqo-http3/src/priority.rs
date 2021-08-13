use crate::Header;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Priority {
    urgency: u8,
    incremental: bool,
}

impl Default for Priority {
    fn default() -> Self {
        Priority {
            urgency: 3,
            incremental: false,
        }
    }
}

impl Priority {
    /// # Panics
    /// If an invalid urgency (>7 is given)
    pub fn new(urgency: u8, incremental: bool) -> Priority {
        assert!(urgency < 8);
        Priority {
            urgency,
            incremental,
        }
    }

    /// Returns a header if required to send
    pub fn header(self) -> Option<Header> {
        match self {
            Priority {
                urgency: 3,
                incremental: false,
            } => None,
            Priority {
                urgency: 3,
                incremental: true,
            } => Some(Header::new("priority", "i")),
            Priority {
                urgency,
                incremental: false,
            } => Some(Header::new("priority", format!("u={}", urgency))),
            Priority {
                urgency,
                incremental: true,
            } => Some(Header::new("priority", format!("u={},i", urgency))),
        }
    }
}
