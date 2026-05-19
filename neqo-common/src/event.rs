// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// An event provider is able to generate a stream of events.
pub trait Provider {
    type Event;

    /// Get the next event.
    #[must_use]
    fn next_event(&mut self) -> Option<Self::Event>;

    /// Determine whether there are pending events.
    #[must_use]
    fn has_events(&self) -> bool;

    /// Construct an iterator that produces all events.
    fn events(&'_ mut self) -> Iter<'_, Self> {
        Iter { p: self }
    }
}

pub struct Iter<'a, P: ?Sized> {
    p: &'a mut P,
}

impl<P: Provider + ?Sized> Iterator for Iter<'_, P> {
    type Item = P::Event;
    fn next(&mut self) -> Option<Self::Item> {
        self.p.next_event()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::Provider;

    struct MockProvider(std::collections::VecDeque<u32>);

    impl Provider for MockProvider {
        type Event = u32;
        fn next_event(&mut self) -> Option<u32> {
            self.0.pop_front()
        }
        fn has_events(&self) -> bool {
            !self.0.is_empty()
        }
    }

    #[test]
    fn iter_yields_events() {
        let mut p = MockProvider(std::collections::VecDeque::from([1, 2, 3]));
        assert!(p.has_events());
        let events: Vec<u32> = p.events().collect();
        assert_eq!(events, [1, 2, 3]);
        assert!(!p.has_events());
    }

    #[test]
    fn iter_empty() {
        let mut p = MockProvider(std::collections::VecDeque::new());
        assert!(!p.has_events());
        assert_eq!(p.events().next(), None);
    }
}
