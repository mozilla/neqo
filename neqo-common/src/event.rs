// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{cell::RefCell, collections::VecDeque, rc::Rc};

/// A shared FIFO of events. Clones share the same underlying queue.
#[derive(Debug)]
pub struct Queue<T> {
    events: Rc<RefCell<VecDeque<T>>>,
}

impl<T> Default for Queue<T> {
    fn default() -> Self {
        Self {
            events: Rc::default(),
        }
    }
}

impl<T> Clone for Queue<T> {
    fn clone(&self) -> Self {
        Self {
            events: Rc::clone(&self.events),
        }
    }
}

impl<T> Queue<T> {
    /// Append `event`, regardless of what is already queued.
    pub fn push(&self, event: T) {
        self.events.borrow_mut().push_back(event);
    }

    /// Append `event` unless an equal event is already queued.
    /// An existing equal event keeps its place in the queue.
    pub fn push_unique(&self, event: T)
    where
        T: PartialEq,
    {
        let mut q = self.events.borrow_mut();
        if !q.contains(&event) {
            q.push_back(event);
        }
    }

    /// Append `event` unless a queued event matches `is_duplicate`.
    /// An existing match keeps its place in the queue.
    pub fn push_unique_by<F>(&self, event: T, is_duplicate: F)
    where
        F: Fn(&T) -> bool,
    {
        let mut q = self.events.borrow_mut();
        if !q.iter().any(is_duplicate) {
            q.push_back(event);
        }
    }

    /// Remove all queued events matching `f`.
    pub fn remove_matching<F>(&self, f: F)
    where
        F: Fn(&T) -> bool,
    {
        self.events.borrow_mut().retain(|event| !f(event));
    }

    /// Remove all queued events.
    pub fn clear(&self) {
        self.events.borrow_mut().clear();
    }

    /// Determine whether the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.borrow().is_empty()
    }

    /// Take the first event.
    #[must_use]
    pub fn next_event(&self) -> Option<T> {
        self.events.borrow_mut().pop_front()
    }

    /// Take all events.
    #[must_use]
    pub fn take_all(&self) -> VecDeque<T> {
        self.events.take()
    }
}

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

    #[test]
    fn queue_push_allows_duplicates() {
        let q = super::Queue::default();
        q.push(1);
        q.push(1);
        assert_eq!(q.take_all(), [1, 1]);
    }

    #[test]
    fn queue_push_unique_keeps_first() {
        let q = super::Queue::default();
        q.push_unique(1);
        q.push_unique(2);
        q.push_unique(1);
        assert_eq!(q.take_all(), [1, 2]);
    }

    #[test]
    fn queue_push_unique_by_matches_key() {
        let q = super::Queue::default();
        q.push_unique_by((1, 'a'), |(k, _)| *k == 1);
        q.push_unique_by((1, 'b'), |(k, _)| *k == 1);
        q.push_unique_by((2, 'c'), |(k, _)| *k == 2);
        assert_eq!(q.take_all(), [(1, 'a'), (2, 'c')]);
    }

    #[test]
    fn queue_remove_clear_next() {
        let q = super::Queue::default();
        q.push(1);
        q.push(2);
        q.push(3);
        q.remove_matching(|e| *e == 2);
        assert!(!q.is_empty());
        assert_eq!(q.next_event(), Some(1));
        assert_eq!(q.next_event(), Some(3));
        assert_eq!(q.next_event(), None);
        q.push(4);
        q.clear();
        assert!(q.is_empty());
    }

    #[test]
    fn queue_clones_share() {
        let q = super::Queue::default();
        let clone = q.clone();
        clone.push(1);
        assert_eq!(q.next_event(), Some(1));
        clone.push(2);
        assert_eq!(q.next_event(), Some(2));
    }
}
