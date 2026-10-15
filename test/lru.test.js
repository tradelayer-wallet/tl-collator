import test from 'node:test';
import assert from 'node:assert/strict';

import { LruMap } from '../dist/lru.js';

test('LruMap evicts the least recently used key', () => {
  const m = new LruMap(2);
  m.set('a', 1);
  m.set('b', 2);
  assert.equal(m.get('a'), 1); // refresh 'a'
  m.set('c', 3); // evicts 'b'
  assert.equal(m.get('b'), undefined);
  assert.equal(m.get('a'), 1);
  assert.equal(m.get('c'), 3);
});
