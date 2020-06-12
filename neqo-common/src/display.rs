// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// Implement `std::fmt::Display` for a type.
/// A single argument form displays the name of the type.
/// A two argument form takes a fixed string as an argument.
/// Adding identifiers for members of the type after the format string
/// allows for those to be added to the format string.
/// If more complex formatting is needed, then pass an identifier *before*
/// the format string and then the trailing arguments can be expressions using
/// that identifier, which will contain an immutable reference.
#[macro_export]
macro_rules! display {
    ($name:ident $(< $($lt:tt),+ >)? $(,)?) => {
        display!($name $(< $( $lt ),* >)?, stringify!($name),);
    };

    ($name:ident $(< $($lt:tt),+ >)?, $s:expr) => {
        display!($name $(< $( $lt ),* >)?, $s,);
    };

    ($name:ident $(< $($lt:tt),+ >)?, $format:expr, $($member:ident),* $(,)?) => {
        display!($name $(< $( $lt ),* >)?, _v, $format, $(_v.$member),*);
    };

    ($name:ident $(< $($lt:tt),+ >)?, $v:ident, $format:expr, $($arg:expr),* $(,)?) => {
        impl $(< $( $lt ),* >)? ::std::fmt::Display for $name $(< $( $lt ),* >)? {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                let $v = self;
                write!(f, $format, $($arg),*)
            }
        }
    };
}

/// `display_debug` implements `Display` for a type that already implements `Debug`.
/// The `Display` implementation forwards to the `Debug` implementation.
/// This version with a second argument adds that as a prefix,
/// followed by ": " and the debug string.
#[macro_export]
macro_rules! display_debug {
    ($name:ident $(< $($lt:tt),+ >)?) => {
        impl $(< $( $lt ),* >)? ::std::fmt::Display for $name $(< $( $lt ),* >)? {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                ::std::fmt::Debug::fmt(self, f)
            }
        }
    };

    ($name:ident $(< $($lt:tt),+ >)?, $prefix:expr) => {
        impl $(< $( $lt ),* >)? ::std::fmt::Display for $name $(< $( $lt ),* >)? {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                f.write_str($prefix)?;
                f.write_str(": ")?;
                ::std::fmt::Debug::fmt(self, f)
            }
        }
    };
}

#[cfg(test)]
#[allow(dead_code)] // Lots of unused fields in the structs we define.
mod test {

    #[test]
    fn display_nofield() {
        struct Point {
            x: i32,
            y: i32,
        }

        display!(Point, "point");
        let origin = Point { x: 1, y: 2 };
        assert_eq!(format!("The origin is: {}", origin), "The origin is: point");
    }

    #[test]
    fn display_onefield() {
        struct Point {
            x: i32,
            y: i32,
        }

        display!(Point, "({})", x);
        let origin = Point { x: 1, y: 2 };
        assert_eq!(format!("origin: {}", origin), "origin: (1)");
    }

    #[test]
    fn display_twofield() {
        struct Point {
            x: i32,
            y: i32,
        }

        display!(Point, "({}, {})", x, y);
        let origin = Point { x: 1, y: 2 };
        assert_eq!(format!("origin: {}", origin), "origin: (1, 2)");
    }

    #[test]
    fn display_trailingcomma() {
        struct Point {
            x: i32,
            y: i32,
        }

        display!(Point, "({}, {})", x, y,);
        let origin = Point { x: 1, y: 2 };
        assert_eq!(format!("origin: {}", origin), "origin: (1, 2)");
    }

    #[test]
    fn display_accessor() {
        struct Point {
            x: i32,
            y: i32,
        }
        impl Point {
            fn x(&self) -> i32 {
                self.x
            }
            fn y(&self) -> i32 {
                self.y
            }
        }

        display!(Point, v, "({}, {})", v.x(), v.y());
        let origin = Point { x: 1, y: 2 };
        assert_eq!(format!("origin: {}", origin), "origin: (1, 2)");
    }

    #[test]
    fn display_complex() {
        struct Point {
            x: i32,
            y: i32,
        }
        display!(Point, v, "{}", v.x + v.y);
        let origin = Point { x: 1, y: 2 };
        assert_eq!(format!("{}", origin), "3");
    }

    #[test]
    fn display_lifetime() {
        struct S<'a> {
            s: &'a str,
        }
        display!(S<'a>);
        let v = S { s: "testing" };
        assert_eq!(format!("{}", v), "S");
    }

    #[test]
    fn display_lifetime_params() {
        struct S<'a> {
            s: &'a str,
        }
        display!(S<'a>, "S<'a> = {}", s);
        let v = S { s: "testing" };
        assert_eq!(format!("{}", v), "S<'a> = testing");
    }

    #[test]
    fn display_debug() {
        #[derive(Debug)]
        struct Point {
            x: i32,
            y: i32,
        }

        display_debug!(Point);
        let origin = Point { x: 1, y: 2 };
        assert_eq!(format!("{}", origin), format!("{:?}", origin));
    }

    #[test]
    fn display_debug_fmt() {
        #[derive(Debug)]
        struct Point {
            x: i32,
            y: i32,
        }

        display_debug!(Point, "Pt");
        let origin = Point { x: 1, y: 2 };
        assert_eq!(format!("{}", origin), format!("Pt: {:?}", origin));
    }

    #[test]
    fn display_debug_lifetime() {
        #[derive(Debug)]
        struct S<'a> {
            s: &'a str,
        }
        display_debug!(S<'a>);
        let v = S { s: "testing" };
        assert_eq!(format!("{}", v), format!("{:?}", v));
    }
}
