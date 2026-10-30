//! Token bucket with an injected millisecond clock (port of `src/ratelimit.ts`).
//!
//! Tokens are kept in integer milli-tokens (`rate` tokens per second is exactly
//! `rate` milli-tokens per millisecond), so there is no floating point and the
//! bucket can never exceed `capacity * 1000`. A clock that moves backwards
//! refills nothing and does not move the reference time.
use crate::lru::LruMap;

pub const MAX_BUCKET_CAPACITY: u32 = 1_000_000;
pub const MAX_BUCKET_RATE: u32 = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenBucket {
    capacity: u32,
    rate_per_sec: u32,
    milli: u64,
    last_ms: u64,
}

impl TokenBucket {
    /// `capacity` is clamped to `1..=MAX_BUCKET_CAPACITY` (legacy `Math.max(1, ..)`),
    /// `rate_per_sec` to `0..=MAX_BUCKET_RATE`. The bucket starts full.
    pub fn new(capacity: u32, rate_per_sec: u32, now_ms: u64) -> Self {
        let capacity = capacity.clamp(1, MAX_BUCKET_CAPACITY);
        Self {
            capacity,
            rate_per_sec: rate_per_sec.min(MAX_BUCKET_RATE),
            milli: u64::from(capacity) * 1000,
            last_ms: now_ms,
        }
    }

    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Whole tokens currently available.
    pub fn available(&self) -> u64 {
        self.milli / 1000
    }

    fn refill(&mut self, now_ms: u64) {
        if now_ms <= self.last_ms {
            return;
        }
        let dt = u128::from(now_ms - self.last_ms);
        let add = dt * u128::from(self.rate_per_sec);
        let cap = u128::from(self.capacity) * 1000;
        let next = (u128::from(self.milli) + add).min(cap);
        // `next <= cap <= 1e9`, so the conversion cannot fail.
        self.milli = u64::try_from(next).unwrap_or(u64::from(self.capacity) * 1000);
        self.last_ms = now_ms;
    }

    /// Spend `cost` whole tokens if available. A cost above capacity never succeeds.
    pub fn allow(&mut self, cost: u32, now_ms: u64) -> bool {
        self.refill(now_ms);
        let need = u64::from(cost) * 1000;
        if self.milli >= need {
            self.milli -= need;
            true
        } else {
            false
        }
    }
}

/// Per-key buckets with bounded memory, so a reconnecting peer cannot obtain
/// a fresh bucket by dropping its session (legacy: bucket lived in `PeerSession`).
/// An evicted key starts over with a full bucket; the bound is what keeps memory finite.
pub struct KeyedLimiter {
    capacity: u32,
    rate_per_sec: u32,
    buckets: LruMap<TokenBucket>,
}

impl KeyedLimiter {
    pub fn new(max_keys: usize, capacity: u32, rate_per_sec: u32) -> Self {
        Self {
            capacity,
            rate_per_sec,
            buckets: LruMap::new(max_keys),
        }
    }

    pub fn allow(&mut self, key: &str, cost: u32, now_ms: u64) -> bool {
        let mut bucket = self
            .buckets
            .remove(key)
            .unwrap_or_else(|| TokenBucket::new(self.capacity, self.rate_per_sec, now_ms));
        let ok = bucket.allow(cost, now_ms);
        let _ = self.buckets.insert(key, bucket);
        ok
    }

    pub fn tracked(&self) -> usize {
        self.buckets.len()
    }
}
