// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use env_logger::{Builder, Target};

pub fn init() {
    let _x = Builder::new().target(Target::Stdout).try_init();
}

#[macro_export]
macro_rules! qlog {
    ($lvl:expr, $ctx:expr, $($arg:tt)*) => ( {
        ::neqo_common::log::init();
        ::log::log!($lvl, "[{}] {}", $ctx, format!($($arg)*));
    } )
}
#[macro_export]
macro_rules! qerror {
    ($ctx:ident, $($arg:tt)*) => ( ::neqo_common::qlog!(::log::Level::Error, $ctx, $($arg)*); );
    ($($arg:tt)*) => ( { ::neqo_common::log::init(); ::log::log!(::log::Level::Error, $($arg)*); } );
}
#[macro_export]
macro_rules! qwarn {
    ($ctx:ident, $($arg:tt)*) => ( ::neqo_common::qlog!(::log::Level::Warn, $ctx, $($arg)*););
    ($($arg:tt)*) => ( { ::neqo_common::log::init(); ::log::log!(::log::Level::Warn, $($arg)*); } );
}
#[macro_export]
macro_rules! qinfo {
    ($ctx:ident, $($arg:tt)*) => ( ::neqo_common::qlog!(::log::Level::Info, $ctx, $($arg)*););
    ($($arg:tt)*) => ( { ::neqo_common::log::init(); ::log::log!(::log::Level::Info, $($arg)*); } );
}
#[macro_export]
macro_rules! qdebug {
    ($ctx:ident, $($arg:tt)*) => ( ::neqo_common::qlog!(::log::Level::Debug, $ctx, $($arg)*););
    ($($arg:tt)*) => ( { ::neqo_common::log::init(); ::log::log!(::log::Level::Debug, $($arg)*); } );
}
#[macro_export]
macro_rules! qtrace {
    ($ctx:ident, $($arg:tt)*) => ( ::neqo_common::qlog!(::log::Level::Trace, $ctx, $($arg)*););
    ($($arg:tt)*) => ( { ::neqo_common::log::init(); ::log::log!(::log::Level::Trace, $($arg)*); } );
}
