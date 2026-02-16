import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

import { TapeStore } from '../dist/tape.js';
import { sha256Hex } from '../dist/crypto.js';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'tl-collator-'));
}

test('TapeStore builds index and replays entries >= fromSeq', async () => {
  const dir = tmpDir();
  const tapePath = path.join(dir, 'tape.log');
  const idxPath = path.join(dir, 'tape.idx');

  for (let i = 1; i <= 5; i++) {
    fs.appendFileSync(
      tapePath,
      JSON.stringify({
        v: 1,
        collatorId: 'c',
        seq: i,
        prevHash: '',
        entryHash: sha256Hex(String(i)),
        receivedTs: 1,
        order: {},
        sigCollator: '',
      }) + '\n'
    );
  }

  const t = new TapeStore({
    tapePath,
    idxPath,
    idxStride: 2,
    replayBatch: 2,
    collatorId: 'c',
    collatorPrivKeyHex: '11'.repeat(32),
  });

  const got = [];
  const last = await t.replayFromSeq(3, (e) => got.push(e.seq));
  assert.deepEqual(got, [3, 4, 5]);
  assert.ok(last >= 5);
  assert.equal(fs.existsSync(idxPath), true);
});

