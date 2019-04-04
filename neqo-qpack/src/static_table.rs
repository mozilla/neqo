// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(unused_variables, dead_code)]

#[derive(Debug)]
pub struct StaticTableEntry {
    index: u64,
    name: &'static [u8],
    value: &'static [u8],
}

impl StaticTableEntry {
    pub fn name(&self) -> &[u8] {
        self.name
    }

    pub fn value(&self) -> &[u8] {
        self.value
    }

    pub fn index(&self) -> u64 {
        self.index
    }
}

pub const HEADER_STATIC_TABLE: &[StaticTableEntry] = &[
    StaticTableEntry {
        index: 0,
        name: b":authority",
        value: b"",
    },
    StaticTableEntry {
        index: 1,
        name: b":path",
        value: b"/",
    },
    StaticTableEntry {
        index: 2,
        name: b"age",
        value: b"0",
    },
    StaticTableEntry {
        index: 3,
        name: b"content-disposition",
        value: b"",
    },
    StaticTableEntry {
        index: 4,
        name: b"content-length",
        value: b"0",
    },
    StaticTableEntry {
        index: 5,
        name: b"cookie",
        value: b"",
    },
    StaticTableEntry {
        index: 6,
        name: b"date",
        value: b"",
    },
    StaticTableEntry {
        index: 7,
        name: b"etag",
        value: b"",
    },
    StaticTableEntry {
        index: 8,
        name: b"if-modified-since",
        value: b"",
    },
    StaticTableEntry {
        index: 9,
        name: b"if-none-match",
        value: b"",
    },
    StaticTableEntry {
        index: 10,
        name: b"last-modified",
        value: b"",
    },
    StaticTableEntry {
        index: 11,
        name: b"link",
        value: b"",
    },
    StaticTableEntry {
        index: 12,
        name: b"location",
        value: b"",
    },
    StaticTableEntry {
        index: 13,
        name: b"referer",
        value: b"",
    },
    StaticTableEntry {
        index: 14,
        name: b"set-cookie",
        value: b"",
    },
    StaticTableEntry {
        index: 15,
        name: b":method",
        value: b"CONNECT",
    },
    StaticTableEntry {
        index: 16,
        name: b":method",
        value: b"DELETE",
    },
    StaticTableEntry {
        index: 17,
        name: b":method",
        value: b"GET",
    },
    StaticTableEntry {
        index: 18,
        name: b":method",
        value: b"HEAD",
    },
    StaticTableEntry {
        index: 19,
        name: b":method",
        value: b"OPTIONS",
    },
    StaticTableEntry {
        index: 20,
        name: b":method",
        value: b"POST",
    },
    StaticTableEntry {
        index: 21,
        name: b":method",
        value: b"PUT",
    },
    StaticTableEntry {
        index: 22,
        name: b":scheme",
        value: b"http",
    },
    StaticTableEntry {
        index: 23,
        name: b":scheme",
        value: b"https",
    },
    StaticTableEntry {
        index: 24,
        name: b":status",
        value: b"103",
    },
    StaticTableEntry {
        index: 25,
        name: b":status",
        value: b"200",
    },
    StaticTableEntry {
        index: 26,
        name: b":status",
        value: b"304",
    },
    StaticTableEntry {
        index: 27,
        name: b":status",
        value: b"404",
    },
    StaticTableEntry {
        index: 28,
        name: b":status",
        value: b"503",
    },
    StaticTableEntry {
        index: 29,
        name: b"accept",
        value: b"*/*",
    },
    StaticTableEntry {
        index: 30,
        name: b"accept",
        value: b"application/dns-message",
    },
    StaticTableEntry {
        index: 31,
        name: b"accept-encoding",
        value: b"gzip, deflate, br",
    },
    StaticTableEntry {
        index: 32,
        name: b"accept-ranges",
        value: b"bytes",
    },
    StaticTableEntry {
        index: 33,
        name: b"access-control-allow-headers",
        value: b"cache-control",
    },
    StaticTableEntry {
        index: 34,
        name: b"access-control-allow-headers",
        value: b"content-type",
    },
    StaticTableEntry {
        index: 35,
        name: b"access-control-allow-origin",
        value: b"*",
    },
    StaticTableEntry {
        index: 36,
        name: b"cache-control",
        value: b"max-age=0",
    },
    StaticTableEntry {
        index: 37,
        name: b"cache-control",
        value: b"max-age=2592000",
    },
    StaticTableEntry {
        index: 38,
        name: b"cache-control",
        value: b"max-age=604800",
    },
    StaticTableEntry {
        index: 39,
        name: b"cache-control",
        value: b"no-cache",
    },
    StaticTableEntry {
        index: 40,
        name: b"cache-control",
        value: b"no-store",
    },
    StaticTableEntry {
        index: 41,
        name: b"cache-control",
        value: b"public, max-age=31536000",
    },
    StaticTableEntry {
        index: 42,
        name: b"content-encoding",
        value: b"br",
    },
    StaticTableEntry {
        index: 43,
        name: b"content-encoding",
        value: b"gzip",
    },
    StaticTableEntry {
        index: 44,
        name: b"content-type",
        value: b"application/dns-message",
    },
    StaticTableEntry {
        index: 45,
        name: b"content-type",
        value: b"application/javascript",
    },
    StaticTableEntry {
        index: 46,
        name: b"content-type",
        value: b"application/json",
    },
    StaticTableEntry {
        index: 47,
        name: b"content-type",
        value: b"application/x-www-form-urlencoded",
    },
    StaticTableEntry {
        index: 48,
        name: b"content-type",
        value: b"image/gif",
    },
    StaticTableEntry {
        index: 49,
        name: b"content-type",
        value: b"image/jpeg",
    },
    StaticTableEntry {
        index: 50,
        name: b"content-type",
        value: b"image/png",
    },
    StaticTableEntry {
        index: 51,
        name: b"content-type",
        value: b"text/css",
    },
    StaticTableEntry {
        index: 52,
        name: b"content-type",
        value: b"text/html; charset=utf-8",
    },
    StaticTableEntry {
        index: 53,
        name: b"content-type",
        value: b"text/plain",
    },
    StaticTableEntry {
        index: 54,
        name: b"content-type",
        value: b"text/plain;charset=utf-8",
    },
    StaticTableEntry {
        index: 55,
        name: b"range",
        value: b"bytes=0-",
    },
    StaticTableEntry {
        index: 56,
        name: b"strict-transport-security",
        value: b"max-age=31536000",
    },
    StaticTableEntry {
        index: 57,
        name: b"strict-transport-security",
        value: b"max-age=31536000; includesubdomains",
    },
    StaticTableEntry {
        index: 58,
        name: b"strict-transport-security",
        value: b"max-age=31536000; includesubdomains; preload",
    },
    StaticTableEntry {
        index: 59,
        name: b"vary",
        value: b"accept-encoding",
    },
    StaticTableEntry {
        index: 60,
        name: b"vary",
        value: b"origin",
    },
    StaticTableEntry {
        index: 61,
        name: b"x-content-type-options",
        value: b"nosniff",
    },
    StaticTableEntry {
        index: 62,
        name: b"x-xss-protection",
        value: b"1; mode=block",
    },
    StaticTableEntry {
        index: 63,
        name: b":status",
        value: b"100",
    },
    StaticTableEntry {
        index: 64,
        name: b":status",
        value: b"204",
    },
    StaticTableEntry {
        index: 65,
        name: b":status",
        value: b"206",
    },
    StaticTableEntry {
        index: 66,
        name: b":status",
        value: b"302",
    },
    StaticTableEntry {
        index: 67,
        name: b":status",
        value: b"400",
    },
    StaticTableEntry {
        index: 68,
        name: b":status",
        value: b"403",
    },
    StaticTableEntry {
        index: 69,
        name: b":status",
        value: b"421",
    },
    StaticTableEntry {
        index: 70,
        name: b":status",
        value: b"425",
    },
    StaticTableEntry {
        index: 71,
        name: b":status",
        value: b"500",
    },
    StaticTableEntry {
        index: 72,
        name: b"accept-language",
        value: b"",
    },
    StaticTableEntry {
        index: 73,
        name: b"access-control-allow-credentials",
        value: b"FALSE",
    },
    StaticTableEntry {
        index: 74,
        name: b"access-control-allow-credentials",
        value: b"TRUE",
    },
    StaticTableEntry {
        index: 75,
        name: b"access-control-allow-headers",
        value: b"*",
    },
    StaticTableEntry {
        index: 76,
        name: b"access-control-allow-methods",
        value: b"get",
    },
    StaticTableEntry {
        index: 77,
        name: b"access-control-allow-methods",
        value: b"get, post, options",
    },
    StaticTableEntry {
        index: 78,
        name: b"access-control-allow-methods",
        value: b"options",
    },
    StaticTableEntry {
        index: 79,
        name: b"access-control-expose-headers",
        value: b"content-length",
    },
    StaticTableEntry {
        index: 80,
        name: b"access-control-request-headers",
        value: b"content-type",
    },
    StaticTableEntry {
        index: 81,
        name: b"access-control-request-method",
        value: b"get",
    },
    StaticTableEntry {
        index: 82,
        name: b"access-control-request-method",
        value: b"post",
    },
    StaticTableEntry {
        index: 83,
        name: b"alt-svc",
        value: b"clear",
    },
    StaticTableEntry {
        index: 84,
        name: b"authorization",
        value: b"",
    },
    StaticTableEntry {
        index: 85,
        name: b"content-security-policy",
        value: b"script-src 'none'; object-src 'none'; base-uri 'none'",
    },
    StaticTableEntry {
        index: 86,
        name: b"early-data",
        value: b"1",
    },
    StaticTableEntry {
        index: 87,
        name: b"expect-ct",
        value: b"",
    },
    StaticTableEntry {
        index: 88,
        name: b"forwarded",
        value: b"",
    },
    StaticTableEntry {
        index: 89,
        name: b"if-range",
        value: b"",
    },
    StaticTableEntry {
        index: 90,
        name: b"origin",
        value: b"",
    },
    StaticTableEntry {
        index: 91,
        name: b"purpose",
        value: b"prefetch",
    },
    StaticTableEntry {
        index: 92,
        name: b"server",
        value: b"",
    },
    StaticTableEntry {
        index: 93,
        name: b"timing-allow-origin",
        value: b"*",
    },
    StaticTableEntry {
        index: 94,
        name: b"upgrade-insecure-requests",
        value: b"1",
    },
    StaticTableEntry {
        index: 95,
        name: b"user-agent",
        value: b"",
    },
    StaticTableEntry {
        index: 96,
        name: b"x-forwarded-for",
        value: b"",
    },
    StaticTableEntry {
        index: 97,
        name: b"x-frame-options",
        value: b"deny",
    },
    StaticTableEntry {
        index: 98,
        name: b"x-frame-options",
        value: b"sameorigin",
    },
];
