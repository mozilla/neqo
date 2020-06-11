#[macro_export]
macro_rules! display {

    ($name: ident, $formatter: expr) => {
        display!($name, self, $formatter,)
    };

    ($name: ident, $formatter: expr, $($arg: ident,)*) => {
        display!($name, self, $formatter, $($arg),*)
    };

    ($name: ident, $formatter: expr, $($arg: ident),*) => {
        display!($name, self, $formatter, $($arg),*)
    };

    ($name: ident, $self_: ident, $formatter: expr, $($arg: ident),*) => {
        impl ::std::fmt::Display for $name {
            fn fmt(&$self_, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(f, $formatter, $($self_.$arg),*)
            }
        }
    };

}

#[cfg(test)]
#[allow(dead_code)]
mod test {

    #[test]
    fn display_nofield() {
        struct Point {
            x: i32,
            y: i32,
        }

        display!(Point, "point");
        let origin = Point { x: 0, y: 0 };
        assert_eq!(format!("The origin is: {}", origin), "The origin is: point");
    }

    #[test]
    fn display_onefield() {
        struct Point {
            x: i32,
            y: i32,
        }

        display!(Point, "({})", x);
        let origin = Point { x: 0, y: 0 };
        assert_eq!(format!("The origin is: {}", origin), "The origin is: (0)");
    }

    #[test]
    fn display_twofield() {
        struct Point {
            x: i32,
            y: i32,
        }

        display!(Point, "({}, {})", x, y);
        let origin = Point { x: 0, y: 0 };
        assert_eq!(
            format!("The origin is: {}", origin),
            "The origin is: (0, 0)"
        );
    }

    #[test]
    fn display_trailingcomma() {
        struct Point {
            x: i32,
            y: i32,
        }

        display!(Point, "({}, {})", x, y,);
        let origin = Point { x: 0, y: 0 };
        assert_eq!(
            format!("The origin is: {}", origin),
            "The origin is: (0, 0)"
        );
    }
}
