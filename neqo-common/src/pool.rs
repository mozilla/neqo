// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A simple object pool for reusing heap allocations.
//!
//! Objects are stored in a LIFO stack, so recently released objects are
//! acquired first. This improves CPU cache utilization since recently
//! used memory is more likely to still be in cache.

use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
    mem,
    ops::{Deref, DerefMut},
    rc::Rc,
};

/// A trait for objects that can be pooled and reused.
///
/// Implementations must reset the object to a clean, reusable state
/// while preserving allocated capacity where possible.
pub trait Poolable: Default {
    /// Reset the object to a reusable state.
    ///
    /// This should clear any data while retaining allocated capacity
    /// to avoid reallocations when the object is reused.
    fn reset(&mut self);
}

impl<T> Poolable for Vec<T> {
    fn reset(&mut self) {
        self.clear();
    }
}

impl<T> Poolable for VecDeque<T> {
    fn reset(&mut self) {
        self.clear();
    }
}

impl<K: Ord, V> Poolable for BTreeMap<K, V> {
    fn reset(&mut self) {
        self.clear();
    }
}

impl Poolable for String {
    fn reset(&mut self) {
        self.clear();
    }
}

/// A simple object pool that reuses heap allocations.
///
/// The pool uses LIFO (stack) semantics: the most recently released
/// object is the first to be acquired. This improves cache locality
/// since recently used memory is more likely to be in CPU cache.
#[derive(Debug, Default)]
pub struct Pool<T> {
    items: Vec<T>,
}

impl<T: Poolable> Pool<T> {
    /// Create an empty pool.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a pool wrapped in `Rc<RefCell<...>>` for shared ownership.
    ///
    /// This is the common pattern needed when sharing a pool across structures.
    #[must_use]
    pub fn shared() -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self::new()))
    }

    /// Create a pool with pre-allocated capacity.
    ///
    /// This avoids reallocations as the pool grows during initial use.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            items: Vec::with_capacity(capacity),
        }
    }

    /// Acquire an object from the pool, or create a new one if empty.
    ///
    /// If the pool contains objects, the most recently released one
    /// is returned. Otherwise, a new default instance is created.
    #[must_use]
    pub fn acquire(&mut self) -> T {
        self.items.pop().unwrap_or_default()
    }

    /// Release an object back to the pool for reuse.
    ///
    /// The object is reset before being stored.
    pub fn release(&mut self, mut item: T) {
        item.reset();
        self.items.push(item);
    }

    /// Return the number of objects currently in the pool.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.items.len()
    }

    /// Return whether the pool is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Clear all objects from the pool, releasing their memory.
    pub fn clear(&mut self) {
        self.items.clear();
    }

    /// Shrink the pool's capacity to match its current length.
    pub fn shrink_to_fit(&mut self) {
        self.items.shrink_to_fit();
    }
}

/// A `Vec<T>` that automatically returns to a pool when dropped.
///
/// This enables efficient reuse of vectors that are created frequently
/// and passed across function boundaries. When the `PooledVec` is dropped,
/// the underlying vector is cleared and returned to the pool for reuse.
///
/// Use [`Deref`] and [`DerefMut`] to access the underlying `Vec<T>`.
#[derive(Debug)]
pub struct PooledVec<T> {
    vec: Vec<T>,
    pool: Rc<RefCell<Pool<Vec<T>>>>,
}

impl<T> PooledVec<T> {
    /// Acquire a vector from the pool.
    #[must_use]
    pub fn new(pool: Rc<RefCell<Pool<Vec<T>>>>) -> Self {
        let vec = pool.borrow_mut().acquire();
        Self { vec, pool }
    }

    /// Consume the `PooledVec` and return the underlying `Vec<T>`.
    ///
    /// The vector will NOT be returned to the pool. Use this when you need
    /// to transfer ownership of the data without returning it to the pool.
    #[must_use]
    pub fn into_vec(mut self) -> Vec<T> {
        mem::take(&mut self.vec)
    }
}

impl<T> Deref for PooledVec<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.vec
    }
}

impl<T> DerefMut for PooledVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.vec
    }
}

impl<T> Drop for PooledVec<T> {
    fn drop(&mut self) {
        if self.vec.capacity() != 0 {
            // Only return to pool if we have allocated capacity worth preserving.
            // An empty, default vec has no capacity to preserve.
            let vec = mem::take(&mut self.vec);
            self.pool.borrow_mut().release(vec);
        }
    }
}

/// A draining iterator over `PooledVec<T>`.
///
/// When this iterator is dropped (whether fully consumed or not),
/// the underlying vector is cleared and returned to the pool.
#[derive(Debug)]
pub struct PooledVecIntoIter<T> {
    inner: PooledVec<T>,
}

impl<T> Iterator for PooledVecIntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.vec.pop()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.inner.vec.len();
        (len, Some(len))
    }
}

impl<T> ExactSizeIterator for PooledVecIntoIter<T> {}

impl<T> DoubleEndedIterator for PooledVecIntoIter<T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.inner.vec.is_empty() {
            None
        } else {
            Some(self.inner.vec.remove(0))
        }
    }
}

impl<T> IntoIterator for PooledVec<T> {
    type Item = T;
    type IntoIter = PooledVecIntoIter<T>;

    fn into_iter(mut self) -> Self::IntoIter {
        // Reverse so that pop() yields elements in original order.
        self.vec.reverse();
        PooledVecIntoIter { inner: self }
    }
}

impl<'a, T> IntoIterator for &'a PooledVec<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.vec.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut PooledVec<T> {
    type Item = &'a mut T;
    type IntoIter = std::slice::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.vec.iter_mut()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    macro_rules! capacity_tests {
        ($($name:ident: $ty:ty => $reserve:expr),+ $(,)?) => {
            $(
                #[test]
                fn $name() {
                    let mut pool: Pool<$ty> = Pool::new();
                    let mut item = pool.acquire();
                    let capacity = ($reserve)(&mut item);
                    pool.release(item);
                    assert_eq!(pool.len(), 1);

                    let mut reused = pool.acquire();
                    assert_eq!(($reserve)(&mut reused), capacity);
                    assert!(pool.is_empty());
                }
            )+
        };
    }

    capacity_tests! {
        vec_preserves_capacity: Vec<u8> => |v: &mut Vec<u8>| { v.reserve(100); v.capacity() },
        vecdeque_preserves_capacity: VecDeque<u8> => |v: &mut VecDeque<u8>| { v.reserve(100); v.capacity() },
        string_preserves_capacity: String => |s: &mut String| { s.reserve(100); s.capacity() },
    }

    #[test]
    fn acquire_from_empty_creates_default() {
        let mut pool: Pool<Vec<u8>> = Pool::new();
        let v = pool.acquire();
        assert!(v.is_empty());
        assert_eq!(v.capacity(), 0);
    }

    #[test]
    fn lifo_ordering() {
        let mut pool: Pool<Vec<u8>> = Pool::new();
        let capacities = [10, 20, 30];

        for &cap in &capacities {
            let v = Vec::with_capacity(cap);
            pool.release(v);
        }

        for &cap in capacities.iter().rev() {
            assert!(pool.acquire().capacity() >= cap);
        }
    }

    #[test]
    fn btreemap_clears_entries() {
        let mut pool: Pool<BTreeMap<u64, u64>> = Pool::new();
        let mut map = pool.acquire();
        map.insert(1, 100);
        pool.release(map);
        assert!(pool.acquire().is_empty());
    }

    #[derive(Default)]
    struct CustomType {
        data: Vec<u8>,
        counter: u32,
    }

    impl Poolable for CustomType {
        fn reset(&mut self) {
            self.data.clear();
            self.counter = 0;
        }
    }

    #[test]
    fn custom_poolable_resets_fields() {
        let mut pool: Pool<CustomType> = Pool::new();
        let mut obj = pool.acquire();
        obj.data.reserve(100);
        obj.counter = 42;
        let capacity = obj.data.capacity();

        pool.release(obj);

        let obj = pool.acquire();
        assert!(obj.data.is_empty());
        assert_eq!(obj.counter, 0);
        assert_eq!(obj.data.capacity(), capacity);
    }

    #[test]
    fn pooled_vec_drop_returns_to_pool() {
        let pool = Pool::<Vec<u8>>::shared();
        let mut pv = PooledVec::new(Rc::clone(&pool));
        pv.reserve(100);
        drop(pv);
        assert!(pool.borrow_mut().acquire().capacity() >= 100);
    }

    #[test]
    fn pooled_vec_deref() {
        let mut pv = PooledVec::new(Pool::<Vec<u8>>::shared());
        pv.extend([1, 2, 3]);
        assert_eq!(&*pv, &[1, 2, 3]);
        pv[1] = 42;
        assert_eq!(pv[1], 42);
    }

    #[test]
    fn pooled_vec_into_vec_skips_pool() {
        let pool = Pool::<Vec<u8>>::shared();
        let mut pv = PooledVec::new(Rc::clone(&pool));
        pv.extend([1, 2]);
        assert_eq!(pv.into_vec(), vec![1, 2]);
        assert!(pool.borrow().is_empty());
    }

    #[test]
    fn pooled_vec_into_iter_returns_to_pool() {
        let pool = Pool::<Vec<u8>>::shared();
        let mut pv = PooledVec::new(Rc::clone(&pool));
        pv.extend([1, 2, 3]);
        assert_eq!(pv.into_iter().sum::<u8>(), 6);
        // Draining iterator returns vec to pool after consumption
        assert_eq!(pool.borrow().len(), 1);
    }

    #[test]
    fn pooled_vec_zero_capacity_skips_pool() {
        let pool = Pool::<Vec<u8>>::shared();
        drop(PooledVec::new(Rc::clone(&pool)));
        assert!(pool.borrow().is_empty());
    }
}
