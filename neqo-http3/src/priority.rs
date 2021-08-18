use crate::{HFrame, Header};
use std::fmt;

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
            other => Some(Header::new("priority", format!("{}", other))),
        }
    }
}

impl fmt::Display for Priority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Priority {
                urgency: 3,
                incremental: false,
            } => Ok(()),
            Priority {
                urgency: 3,
                incremental: true,
            } => write!(f, "i"),
            Priority {
                urgency,
                incremental: false,
            } => write!(f, "u={}", urgency),
            Priority {
                urgency,
                incremental: true,
            } => write!(f, "u={},i", urgency),
        }
    }
}

#[derive(Debug)]
pub struct PriorityHandler {
    priority: Priority,
    last_send_priority: Priority,
}

impl PriorityHandler {
    pub fn new(priority: Priority) -> PriorityHandler {
        PriorityHandler {
            priority,
            last_send_priority: priority,
        }
    }

    pub fn priority(&self) -> Priority {
        self.priority
    }

    pub fn priority_update(&mut self, priority: Priority) {
        self.priority = priority;
    }

    pub fn priority_update_outstanding(&self) -> bool {
        self.priority != self.last_send_priority
    }

    pub fn priority_update_sent(&mut self) {
        self.last_send_priority = self.priority
    }

    pub fn encode_request_frame(&self, stream_id: u64) -> HFrame {
        HFrame::PriorityUpdateRequest {
            element_id: stream_id,
            priority: self.priority,
        }
    }

    pub fn encode_push_frame(&self, stream_id: u64) -> HFrame {
        HFrame::PriorityUpdatePush {
            element_id: stream_id,
            priority: self.priority,
        }
    }
}
