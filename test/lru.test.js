import test from 'node:test';
import assert from 'node:assert/strict';

import { LruSet } from '../dist/lru.js';

test('LruSet evicts oldest', () => {
  const s = new LruSet(2);
  s.add('a');
  s.add('b');
  assert.equal(s.has('a'), true);
  s.add('c');
  assert.equal(s.has('a'), false);
  assert.equal(s.has('b'), true);
  assert.equal(s.has('c'), true);
});

