//! Bounded least-recently-used containers (port of `src/lru.ts`).
//!
//! The recency order is a strictly increasing tick, so behaviour is
//! deterministic and independent of hashing. Capacity is always honoured:
//! `len() <= capacity()` after every operation.
use std::collections::BTreeMap;

/// Hard upper bound for any capacity accepted by this crate.
pub const MAX_CAPACITY: usize = 4_000_000;

pub struct LruMap<V> {
    max: usize,
    tick: u64,
    map: BTreeMap<String, (u64, V)>,
    order: BTreeMap<u64, String>,
}

impl<V> LruMap<V> {
    /// `max` is clamped to `1..=MAX_CAPACITY` (legacy: `Math.max(1, max)`; a NaN
    /// capacity made the legacy set unbounded, see README).
    pub fn new(max: usize) -> Self {
        Self {
            max: max.clamp(1, MAX_CAPACITY),
            tick: 0,
            map: BTreeMap::new(),
            order: BTreeMap::new(),
        }
    }

    pub fn capacity(&self) -> usize {
        self.max
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Membership without refreshing recency (legacy `LruSet.has`).
    pub fn contains(&self, key: &str) -> bool {
        self.map.contains_key(key)
    }

    pub fn peek(&self, key: &str) -> Option<&V> {
        self.map.get(key).map(|(_, v)| v)
    }

    fn next_tick(&mut self) -> u64 {
        if self.tick == u64::MAX {
            // Renumber instead of wrapping so relative order is preserved.
            let keys: Vec<String> = self.order.values().cloned().collect();
            self.order.clear();
            for (i, key) in keys.into_iter().enumerate() {
                let t = i as u64;
                if let Some(slot) = self.map.get_mut(&key) {
                    slot.0 = t;
                }
                self.order.insert(t, key);
            }
            self.tick = self.order.len() as u64;
        }
        let t = self.tick;
        self.tick += 1;
        t
    }

    /// Lookup that refreshes recency (legacy `LruMap.get`).
    pub fn get(&mut self, key: &str) -> Option<&V> {
        if !self.map.contains_key(key) {
            return None;
        }
        let t = self.next_tick();
        let slot = self.map.get_mut(key)?;
        self.order.remove(&slot.0);
        slot.0 = t;
        self.order.insert(t, key.to_owned());
        Some(&slot.1)
    }

    /// Insert or replace, refreshing recency. Returns the evicted entry, if any.
    /// The oldest entry is evicted by tick, so the empty string is an ordinary
    /// key (the legacy `if (oldest)` guard skipped eviction of `""`).
    pub fn insert(&mut self, key: &str, value: V) -> Option<(String, V)> {
        if let Some((old_tick, _)) = self.map.remove(key) {
            self.order.remove(&old_tick);
        }
        let t = self.next_tick();
        self.map.insert(key.to_owned(), (t, value));
        self.order.insert(t, key.to_owned());
        if self.map.len() > self.max {
            let (&oldest_tick, _) = self.order.iter().next()?;
            let oldest = self.order.remove(&oldest_tick)?;
            let (_, v) = self.map.remove(&oldest)?;
            return Some((oldest, v));
        }
        None
    }

    pub fn remove(&mut self, key: &str) -> Option<V> {
        let (t, v) = self.map.remove(key)?;
        self.order.remove(&t);
        Some(v)
    }

    /// Keys from oldest to newest.
    pub fn keys_oldest_first(&self) -> Vec<String> {
        self.order.values().cloned().collect()
    }
}

/// Bounded set (legacy `LruSet`).
pub struct LruSet {
    inner: LruMap<()>,
}

impl LruSet {
    pub fn new(max: usize) -> Self {
        Self {
            inner: LruMap::new(max),
        }
    }
    pub fn has(&self, key: &str) -> bool {
        self.inner.contains(key)
    }
    pub fn add(&mut self, key: &str) {
        let _ = self.inner.insert(key, ());
    }
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }
}
