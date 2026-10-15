import test from 'node:test';
import assert from 'node:assert/strict';

import { ConcurrencyCounter, KeyedTokenBuckets, MinIntervalGate, TokenBucket } from '../dist/ratelimit.js';

test('ConcurrencyCounter tracks outstanding work per key and drops idle keys', () => {
  const c = new ConcurrencyCounter();
  c.acquire('ip:a');
  c.acquire('ip:a');
  c.acquire('sess:1');
  assert.equal(c.get('ip:a'), 2);
  assert.equal(c.get('sess:1'), 1);
  c.release('ip:a');
  c.release('ip:a');
  c.release('ip:a'); // extra release never goes negative
  assert.equal(c.get('ip:a'), 0);
  assert.equal(c.get('sess:1'), 1);
});

test('TokenBucket admits a burst then refuses', () => {
  const b = new TokenBucket({ capacity: 3, refillPerSec: 0 });
  assert.equal(b.allow(1), true);
  assert.equal(b.allow(1), true);
  assert.equal(b.allow(1), true);
  assert.equal(b.allow(1), false);
});

test('MinIntervalGate admits one event per key per interval; keys are independent', () => {
  const g = new MinIntervalGate(1000, 10);
  assert.equal(g.allow('ip:a', 0), true);
  assert.equal(g.allow('ip:a', 999), false);
  assert.equal(g.allow('ip:b', 999), true, 'a second client is not held back by the first');
  assert.equal(g.allow('ip:a', 1000), true);
});

test('MinIntervalGate is bounded: old keys are evicted rather than growing without limit', () => {
  const g = new MinIntervalGate(1000, 2);
  assert.equal(g.allow('ip:a', 0), true);
  assert.equal(g.allow('ip:b', 0), true);
  assert.equal(g.allow('ip:c', 0), true); // evicts ip:a
  assert.equal(g.allow('ip:a', 1), true, 'the oldest key is forgotten once the bound is reached');
});

// KeyedTokenBuckets: bounded table, lossless eviction, shared overflow.
// Times are passed explicitly, so these tests do not depend on the wall clock.
test('KeyedTokenBuckets: a churn of more keys than the table holds cannot reset an exhausted client', () => {
  const t = new KeyedTokenBuckets({ capacity: 2, refillPerSec: 1, maxKeys: 4 });
  assert.equal(t.take('victim', 0).allowed, true);
  assert.equal(t.take('victim', 0).allowed, true);
  assert.equal(t.take('victim', 0).allowed, false, 'victim is exhausted');
  // 200 distinct attacker keys, none refilled (same instant): the table never grows past 4.
  let overflowSeen = false;
  for (let i = 0; i < 200; i++) {
    const r = t.take(`attacker-${i}`, 0);
    overflowSeen ||= r.overflow;
    assert.ok(t.size <= 4);
  }
  assert.equal(overflowSeen, true, 'once full, new keys are charged to the overflow bucket');
  assert.equal(t.take('victim', 0).allowed, false, 'churn did not reset the victim budget');
});

test('KeyedTokenBuckets: an idle (fully refilled) bucket is evicted losslessly', () => {
  const t = new KeyedTokenBuckets({ capacity: 2, refillPerSec: 1, maxKeys: 2 });
  assert.equal(t.take('a', 0).allowed, true); // a: 1 token left, not yet refilled
  assert.equal(t.take('b', 0).allowed, true);
  // Table full, nothing refilled at t=0 -> newcomer uses overflow, nothing evicted.
  assert.deepEqual(t.take('c', 0), { allowed: true, overflow: true });
  assert.equal(t.size, 2);
  // At t=10s both a and b have refilled to capacity: one is evicted and c gets its own bucket.
  const r = t.take('c', 10_000);
  assert.deepEqual(r, { allowed: true, overflow: false });
  assert.equal(t.size, 2);
});

test('KeyedTokenBuckets: an evicted refilled bucket behaves exactly like one that was kept', () => {
  // Eviction is only lossless if a re-created key looks identical to the kept bucket.
  const kept = new KeyedTokenBuckets({ capacity: 3, refillPerSec: 1, maxKeys: 100 });
  const churned = new KeyedTokenBuckets({ capacity: 3, refillPerSec: 1, maxKeys: 1 });
  for (const t of [kept, churned]) t.take('x', 0);
  churned.take('y', 60_000); // evicts refilled 'x'
  for (const now of [60_000, 60_000, 60_000, 60_000, 61_000]) {
    assert.equal(kept.take('x', now).allowed, churned.take('x', now).allowed);
  }
});

test('KeyedTokenBuckets: overflow is one shared budget, so new clients cannot multiply it', () => {
  const t = new KeyedTokenBuckets({ capacity: 2, refillPerSec: 0, maxKeys: 1 });
  assert.equal(t.take('hold', 0).allowed, true); // table: 1 key, not refilled (tokens 1/2)
  assert.deepEqual(t.take('n1', 0), { allowed: true, overflow: true });
  assert.deepEqual(t.take('n2', 0), { allowed: true, overflow: true });
  assert.deepEqual(t.take('n3', 0), { allowed: false, overflow: true }, 'overflow budget of 2 is shared by all newcomers');
});

test('KeyedTokenBuckets: keys are isolated while the table has room', () => {
  const t = new KeyedTokenBuckets({ capacity: 1, refillPerSec: 0, maxKeys: 10 });
  assert.equal(t.take('ip:a', 0).allowed, true);
  assert.equal(t.take('ip:a', 0).allowed, false);
  assert.deepEqual(t.take('ip:b', 0), { allowed: true, overflow: false });
});

test('TokenBucket.isRefilled reports a bucket that has had a full refill period, without mutating it', () => {
  const b = new TokenBucket({ capacity: 2, refillPerSec: 1, startMs: 0 });
  b.allow(1, 0);
  assert.equal(b.isRefilled(0), false);
  assert.equal(b.isRefilled(999), false);
  assert.equal(b.isRefilled(1000), true);
  assert.equal(b.allow(1, 1000), true);
  assert.equal(b.allow(1, 1000), true);
  assert.equal(b.allow(1, 1000), false, 'isRefilled had no side effect on the budget');
});
