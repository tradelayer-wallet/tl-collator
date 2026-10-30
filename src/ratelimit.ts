import { LruMap } from './lru.js';

export class TokenBucket {
  private capacity: number;
  private refillPerSec: number;
  private tokens: number;
  private lastRefillMs: number;

  constructor(opts: { capacity: number; refillPerSec: number; startMs?: number }) {
    this.capacity = Math.max(1, opts.capacity);
    this.refillPerSec = Math.max(0, opts.refillPerSec);
    this.tokens = this.capacity;
    this.lastRefillMs = opts.startMs ?? Date.now();
  }

  allow(cost: number = 1, nowMs: number = Date.now()): boolean {
    const dt = Math.max(0, nowMs - this.lastRefillMs);
    const add = (dt / 1000) * this.refillPerSec;
    if (add > 0) {
      this.tokens = Math.min(this.capacity, this.tokens + add);
      this.lastRefillMs = nowMs;
    }
    if (this.tokens >= cost) {
      this.tokens -= cost;
      return true;
    }
    return false;
  }

  /** True when the bucket would be full at `nowMs` (idle for at least a full refill). Does not mutate. */
  isRefilled(nowMs: number = Date.now()): boolean {
    const dt = Math.max(0, nowMs - this.lastRefillMs);
    return this.tokens + (dt / 1000) * this.refillPerSec >= this.capacity;
  }
}

export interface KeyedTokenBucketsOpts {
  capacity: number;
  refillPerSec: number;
  /** Hard bound on the number of tracked keys. */
  maxKeys: number;
  /** Least-recently-used keys one insert may examine for an evictable bucket. */
  scanLimit?: number;
}

export interface KeyedTakeResult {
  allowed: boolean;
  /** True when the key had no bucket and the table was full: the request was charged to the shared overflow bucket. */
  overflow: boolean;
}

/**
 * One token bucket per key, in a bounded table.
 *
 * Eviction is lossless: a key is dropped only when its bucket has fully
 * refilled, so a later re-creation starts from exactly the state it had.
 * When the table is full and no bucket qualifies, the request is charged to a
 * single shared overflow bucket instead of creating a fresh full bucket. Under
 * churn through many keys the limiter therefore fails closed: no client's
 * budget is reset by someone else's traffic.
 */
export class KeyedTokenBuckets {
  private readonly buckets = new Map<string, TokenBucket>(); // insertion order = recency order
  // Created on first use, so its clock starts when the table first overflowed.
  private overflow: TokenBucket | null = null;
  private readonly scanLimit: number;

  constructor(private readonly opts: KeyedTokenBucketsOpts) {
    if (!Number.isInteger(opts.maxKeys) || opts.maxKeys < 1) {
      throw new Error('KeyedTokenBuckets: maxKeys must be a positive integer');
    }
    this.scanLimit = Math.max(1, opts.scanLimit ?? 64);
  }

  get size(): number {
    return this.buckets.size;
  }

  take(key: string, nowMs: number = Date.now()): KeyedTakeResult {
    const existing = this.buckets.get(key);
    if (existing) {
      // refresh recency
      this.buckets.delete(key);
      this.buckets.set(key, existing);
      return { allowed: existing.allow(1, nowMs), overflow: false };
    }
    if (this.buckets.size >= this.opts.maxKeys && !this.evictOneRefilled(nowMs)) {
      this.overflow ??= this.newBucket(nowMs);
      return { allowed: this.overflow.allow(1, nowMs), overflow: true };
    }
    const fresh = this.newBucket(nowMs);
    this.buckets.set(key, fresh);
    return { allowed: fresh.allow(1, nowMs), overflow: false };
  }

  private newBucket(nowMs: number): TokenBucket {
    return new TokenBucket({ capacity: this.opts.capacity, refillPerSec: this.opts.refillPerSec, startMs: nowMs });
  }

  private evictOneRefilled(nowMs: number): boolean {
    let scanned = 0;
    for (const [key, bucket] of this.buckets) {
      if (scanned++ >= this.scanLimit) break;
      if (bucket.isRefilled(nowMs)) {
        this.buckets.delete(key);
        return true;
      }
    }
    return false;
  }
}

// Allows at most one event per `key` every `intervalMs`. Keys are bounded (LRU),
// so a flood of distinct keys cannot grow memory without limit.
export class MinIntervalGate {
  private last: LruMap<number>;

  constructor(private intervalMs: number, maxKeys: number) {
    this.last = new LruMap<number>(maxKeys);
  }

  allow(key: string, nowMs: number = Date.now()): boolean {
    const prev = this.last.get(key);
    if (prev !== undefined && nowMs - prev < this.intervalMs) return false;
    this.last.set(key, nowMs);
    return true;
  }
}

// Per-key count of outstanding (admitted, not yet released) operations, used for
// routed-RPC admission. Keys with no outstanding work are dropped, so the map
// only holds clients that currently have work in flight.
export class ConcurrencyCounter {
  private counts = new Map<string, number>();

  get(key: string): number {
    return this.counts.get(key) || 0;
  }

  acquire(key: string): void {
    this.counts.set(key, this.get(key) + 1);
  }

  release(key: string): void {
    const remaining = this.get(key) - 1;
    if (remaining > 0) this.counts.set(key, remaining);
    else this.counts.delete(key);
  }
}
