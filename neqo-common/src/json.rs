// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! JSON formatting shared by callers that print structured stats.

use std::fmt::Write as _;

use serde::Serialize;
use serde_json::Value;

struct Options {
    max_line_length: usize,
    indent: usize,
}

const DEFAULT_OPTIONS: Options = Options {
    max_line_length: 100,
    indent: 2,
};

/// Serialize `value` as JSON, trading vertical space for horizontal space.
///
/// Arrays and objects that fit within [`DEFAULT_OPTIONS`]'s line length are printed on a single
/// line; larger ones fall back to one-entry-per-line formatting. Object keys are sorted
/// alphabetically .
///
/// # Panics
///
/// If `value`'s `Serialize` impl fails.
pub fn compact<T: Serialize>(value: &T) -> String {
    render_root(value, &DEFAULT_OPTIONS)
}

fn render_root<T: Serialize>(value: &T, opts: &Options) -> String {
    let mut value = serde_json::to_value(value).expect("serializes");
    value.sort_all_objects();
    let mut out = String::new();
    render(&value, 0, opts, &mut out);
    out
}

fn write_key(out: &mut String, key: &str) {
    write!(out, "{key:?}: ").expect("write! to a String cannot fail");
}

/// Render `value`, choosing between [`render_inline`] and [`render_block`]
/// depending on whether the inline form fits within `opts.max_line_length`
/// once `depth` levels of indentation are accounted for.
fn render(value: &Value, depth: usize, opts: &Options, out: &mut String) {
    let mut inline = String::new();
    render_inline(value, &mut inline);
    if depth * opts.indent + inline.len() <= opts.max_line_length
        || !matches!(value, Value::Array(_) | Value::Object(_))
    {
        out.push_str(&inline);
        return;
    }
    match value {
        Value::Array(items) => {
            let entries = items.iter().map(|v| (None, v));
            render_block(entries, '[', ']', depth, opts, out);
        }
        Value::Object(map) => {
            let entries = map.iter().map(|(k, v)| (Some(k.as_str()), v));
            render_block(entries, '{', '}', depth, opts, out);
        }
        _ => unreachable!("scalars always fit inline"),
    }
}

/// Render `value` fully on one line, with a space after every `:` and `,`.
fn render_inline(value: &Value, out: &mut String) {
    match value {
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                render_inline(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (key, val)) in map.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_key(out, key);
                render_inline(val, out);
            }
            out.push('}');
        }
        _ => write!(out, "{value}").expect("write! to a String cannot fail"),
    }
}

/// Render an array or object that didn't fit on one line: one entry per
/// line, indented one level (i.e. `opts.indent` spaces) deeper than `depth`.
fn render_block<'a>(
    entries: impl ExactSizeIterator<Item = (Option<&'a str>, &'a Value)>,
    open: char,
    close: char,
    depth: usize,
    opts: &Options,
    out: &mut String,
) {
    let n = entries.len();
    if n == 0 {
        out.push(open);
        out.push(close);
        return;
    }
    out.push(open);
    out.push('\n');
    for (i, (key, val)) in entries.enumerate() {
        out.push_str(&" ".repeat((depth + 1) * opts.indent));
        if let Some(k) = key {
            write_key(out, k);
        }
        render(val, depth + 1, opts, out);
        if i + 1 < n {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str(&" ".repeat(depth * opts.indent));
    out.push(close);
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{Options, compact, render_root};

    const SMALL: Options = Options {
        max_line_length: 10,
        indent: 2,
    };

    #[test]
    fn compact_form_is_one_line_sorted_and_spaced() {
        let json = compact(&json!({"zebra": [1, 2], "apple": "x"}));
        assert_eq!(json, r#"{"apple": "x", "zebra": [1, 2]}"#);
    }

    #[test]
    fn empty_array_and_object_have_no_inner_whitespace() {
        assert_eq!(compact(&json!([])), "[]");
        assert_eq!(compact(&json!({})), "{}");
    }

    #[test]
    fn value_exceeding_max_line_length_expands_to_a_block() {
        let json = render_root(&json!({"numbers": [1, 2, 3, 4], "name": "x"}), &SMALL);
        assert!(json.lines().count() > 1, "got: {json}");
    }
}
