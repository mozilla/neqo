// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    PartialOrd,
    Default,
    derive_more::Display,
    derive_more::From,
    derive_more::Into,
    derive_more::Sub,
)]
#[display("{_0}")]
pub struct PushId(u64);

impl PushId {
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub const fn next(&mut self) {
        self.0 += 1;
    }
}

// TODO: Derive this with derive_more once generic RHS parameters are supported.
// See: https://github.com/JelteF/derive_more/issues/118
impl std::ops::Add<u64> for PushId {
    type Output = Self;

    fn add(self, rhs: u64) -> Self {
        Self(self.0 + rhs)
    }
}

#[test]
fn push_id_display() {
    assert_eq!(PushId::new(42).to_string(), "42");
}
