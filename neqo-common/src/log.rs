// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cell::RefCell;
use std::fmt;
use std::io::Write;
use std::rc::Rc;
use std::sync::Once;
use std::time::Instant;

use env_logger::Builder;
use qlog::Trace;

pub struct NeqoQlog {
    pub trace: Trace,
    pub zero_time: Instant,
}

impl NeqoQlog {
    #[must_use]
    pub fn new(now: Instant, trace: Trace) -> Self {
        Self {
            trace,
            zero_time: now,
        }
    }
}

impl fmt::Debug for NeqoQlog {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "NeqoQlog with zero time of {:?}", self.zero_time)
    }
}

pub type NeqoQlogRef = Rc<RefCell<NeqoQlog>>;

static INIT_ONCE: Once = Once::new();

lazy_static! {
    static ref START_TIME: Instant = Instant::now();
}

pub fn init() {
    INIT_ONCE.call_once(|| {
        let mut builder = Builder::from_env("RUST_LOG");
        builder.format(|buf, record| {
            let elapsed = START_TIME.elapsed();
            writeln!(
                buf,
                "{}s{:3}ms {} {}",
                elapsed.as_secs(),
                elapsed.as_millis() % 1000,
                buf.default_styled_level(record.level()),
                record.args()
            )
        });
        if let Err(e) = builder.try_init() {
            ::log::log!(::log::Level::Info, "Logging initialization error {:?}", e);
        } else {
            ::log::log!(::log::Level::Info, "Logging initialized");
        }
    });
}

#[macro_export]
macro_rules! log_invoke {
    ($lvl:expr, $ctx:expr, $($arg:tt)*) => ( {
        ::neqo_common::log::init();
        ::log::log!($lvl, "[{}] {}", $ctx, format!($($arg)*));
    } )
}
#[macro_export]
macro_rules! qerror {
    ([$ctx:expr], $($arg:tt)*) => (::neqo_common::log_invoke!(::log::Level::Error, $ctx, $($arg)*););
    ($($arg:tt)*) => ( { ::neqo_common::log::init(); ::log::log!(::log::Level::Error, $($arg)*); } );
}
#[macro_export]
macro_rules! qwarn {
    ([$ctx:expr], $($arg:tt)*) => (::neqo_common::log_invoke!(::log::Level::Warn, $ctx, $($arg)*););
    ($($arg:tt)*) => ( { ::neqo_common::log::init(); ::log::log!(::log::Level::Warn, $($arg)*); } );
}
#[macro_export]
macro_rules! qinfo {
    ([$ctx:expr], $($arg:tt)*) => (::neqo_common::log_invoke!(::log::Level::Info, $ctx, $($arg)*););
    ($($arg:tt)*) => ( { ::neqo_common::log::init(); ::log::log!(::log::Level::Info, $($arg)*); } );
}
#[macro_export]
macro_rules! qdebug {
    ([$ctx:expr], $($arg:tt)*) => (::neqo_common::log_invoke!(::log::Level::Debug, $ctx, $($arg)*););
    ($($arg:tt)*) => ( { ::neqo_common::log::init(); ::log::log!(::log::Level::Debug, $($arg)*); } );
}
#[macro_export]
macro_rules! qtrace {
    ([$ctx:expr], $($arg:tt)*) => (::neqo_common::log_invoke!(::log::Level::Trace, $ctx, $($arg)*););
    ($($arg:tt)*) => ( { ::neqo_common::log::init(); ::log::log!(::log::Level::Trace, $($arg)*); } );
}
