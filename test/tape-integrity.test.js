import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { TapeStore } from '../dist/tape.js';
import { sha256Hex } from '../dist/crypto.js';

const PRIV = '22'.repeat(32);

function order(i) {
  return {
    v: 1,
    kind: 'NEW',
    body: { v: 1, market: 'SPOT:LTC/USDT', side: 'BUY', px: '1', qty: '1', visibility: { kind: 'PUBLIC' }, clientTs: i },
    traderPubKey: '02' + 'aa'.repeat(32),
    clientNonce: sha256Hex(`nonce-${i}`).slice(0, 32),
    orderId: sha256Hex(`order-${i}`),
    sigTrader: '11'.repeat(64),
  };
}

function openTape(dir, opts = {}) {
  return new TapeStore({
    tapePath: path.join(dir, 'tape.log'),
    idxPath: path.join(dir, 'tape.idx'),
    idxStride: 4,
    replayBatch: 8,
    maxReplayEntries: opts.maxReplayEntries ?? 1000,
    collatorId: 'collator-test',
    collatorPrivKeyHex: PRIV,
  });
}

function lineCount(dir) {
  return fs.readFileSync(path.join(dir, 'tape.log'), 'utf8').split('\n').filter(Boolean).length;
}

test('N2: a repeated orderId is refused by append and writes nothing', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-dedupe-'));
  const t = openTape(dir);
  assert.ok(t.append(order(1)));
  assert.equal(t.append(order(1)), null);
  assert.equal(t.hasOrder(order(1).orderId), true);
  assert.equal(lineCount(dir), 1);
});

test('N2: a harvested orderId is still refused after a restart (tape reloaded from disk)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-dedupe-restart-'));
  const first = openTape(dir);
  assert.ok(first.append(order(7)));
  const restarted = openTape(dir);
  assert.equal(restarted.hasOrder(order(7).orderId), true);
  assert.equal(restarted.append(order(7)), null);
  assert.equal(lineCount(dir), 1);
  // Distinct orders still append after the restart, with a continuous seq.
  assert.equal(restarted.append(order(8)).seq, 2);
});

test('N7: a resync is clamped to the newest maxReplayEntries and reports the effective fromSeq', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-resync-'));
  const t = openTape(dir, { maxReplayEntries: 10 });
  for (let i = 1; i <= 50; i++) t.append(order(i));

  const seqs = [];
  const clamped = await t.replayFromSeq(1, (e) => seqs.push(e.seq));
  assert.deepEqual(seqs, [41, 42, 43, 44, 45, 46, 47, 48, 49, 50]);
  assert.deepEqual(clamped, { fromSeq: 41, lastSeq: 50 });
});

test('N7: a resync inside the bound is not clamped', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-resync-ok-'));
  const t = openTape(dir, { maxReplayEntries: 10 });
  for (let i = 1; i <= 50; i++) t.append(order(i));

  const seqs = [];
  const res = await t.replayFromSeq(45, (e) => seqs.push(e.seq));
  assert.deepEqual(seqs, [45, 46, 47, 48, 49, 50]);
  assert.deepEqual(res, { fromSeq: 45, lastSeq: 50 });
});

test('N7: the seek index stays correct across appends made after it was built', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-resync-idx-'));
  const t = openTape(dir, { maxReplayEntries: 1000 });
  for (let i = 1; i <= 10; i++) t.append(order(i));
  await t.replayFromSeq(1, () => {}); // builds the index (stride 4)
  for (let i = 11; i <= 22; i++) t.append(order(i)); // extends it in place

  for (const from of [1, 4, 5, 9, 13, 17, 21, 22]) {
    const seqs = [];
    await t.replayFromSeq(from, (e) => seqs.push(e.seq));
    const want = [];
    for (let s = from; s <= 22; s++) want.push(s);
    assert.deepEqual(seqs, want, `replay from ${from}`);
  }
  // A restart reads the tape and index back and still lines up.
  const restarted = openTape(dir, { maxReplayEntries: 1000 });
  const seqs = [];
  await restarted.replayFromSeq(15, (e) => seqs.push(e.seq));
  assert.deepEqual(seqs, [15, 16, 17, 18, 19, 20, 21, 22]);
});

// Simulates a disk-full failure in the middle of a write: half the line reaches
// the file, then the write throws.
function failMidWrite(t) {
  const realAppend = fs.appendFileSync;
  fs.appendFileSync = (p, data, enc) => {
    const s = String(data);
    realAppend(p, s.slice(0, Math.floor(s.length / 2)), enc);
    throw Object.assign(new Error('ENOSPC: no space left on device'), { code: 'ENOSPC' });
  };
  return () => { fs.appendFileSync = realAppend; };
}

test('N5: a failed append leaves no partial line; the next append continues the chain and survives restart', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-partial-'));
  const t = openTape(dir);
  assert.ok(t.append(order(1)));
  const restore = failMidWrite(t);
  try {
    assert.throws(() => t.append(order(2)), /ENOSPC/);
  } finally {
    restore();
  }
  assert.equal(t.getLastSeq(), 1, 'a failed append does not advance the chain');
  assert.equal(t.hasOrder(order(2).orderId), false);
  assert.equal(fs.readFileSync(path.join(dir, 'tape.log'), 'utf8').endsWith('\n'), true, 'file ends on a line boundary');

  const acked = t.append(order(3));
  assert.equal(acked.seq, 2);
  const restarted = openTape(dir);
  assert.equal(restarted.getLastSeq(), 2);
  assert.equal(restarted.hasOrder(order(3).orderId), true, 'an acknowledged order is still on the tape after restart');
  assert.equal(restarted.append(order(3)), null, 'and is not accepted a second time');
});

test('N5: if the partial write cannot be cut back, appends are refused until the cut-back succeeds', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-partial-stuck-'));
  const t = openTape(dir);
  assert.ok(t.append(order(1)));
  const restore = failMidWrite(t);
  const realTruncate = fs.truncateSync;
  fs.truncateSync = () => { throw new Error('EIO'); };
  try {
    assert.throws(() => t.append(order(2)), /ENOSPC/);
    assert.throws(() => t.append(order(3)), /refusing appends until a failed write is cut back/);
  } finally {
    restore();
    fs.truncateSync = realTruncate;
  }
  // The disk recovered: the next append cuts the partial line off first, so the chain continues at seq 2.
  assert.equal(t.append(order(3)).seq, 2);
  const reopened = openTape(dir);
  assert.equal(reopened.getLastSeq(), 2);
  assert.equal(reopened.hasOrder(order(2).orderId), false);
  assert.equal(reopened.hasOrder(order(3).orderId), true);
});

test('N5: a torn last line from a crash is cut off on load, not glued onto by the next append', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-torn-'));
  const t = openTape(dir);
  assert.ok(t.append(order(1)));
  fs.appendFileSync(path.join(dir, 'tape.log'), '{"v":1,"collatorId":"collator-test","seq":2,"prevHash"');
  const reopened = openTape(dir);
  assert.equal(reopened.getLastSeq(), 1);
  assert.equal(reopened.append(order(2)).seq, 2);
  const again = openTape(dir);
  assert.equal(again.getLastSeq(), 2);
  assert.equal(again.hasOrder(order(2).orderId), true);
});

test('N5: a damaged interior tape line refuses startup instead of silently dropping its orderId', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-damaged-'));
  const t = openTape(dir);
  assert.ok(t.append(order(1)));
  assert.ok(t.append(order(2)));
  const file = path.join(dir, 'tape.log');
  const [first, second] = fs.readFileSync(file, 'utf8').split('\n');
  fs.writeFileSync(file, `${first}\n{damaged\n${second}\n`);
  assert.throws(() => openTape(dir), /not valid JSON/);
});

test('N5: a resync past the tip reads nothing (no full-file scan per request)', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-beyond-'));
  const t = openTape(dir, { maxReplayEntries: 10 });
  for (let i = 1; i <= 50; i++) t.append(order(i));
  const realRead = fs.readSync;
  let bytesRead = 0;
  fs.readSync = (...args) => {
    const n = realRead(...args);
    if (n > 0) bytesRead += n;
    return n;
  };
  const sent = [];
  let result;
  try {
    result = await t.replayFromSeq(1000000, (e) => sent.push(e.seq));
  } finally {
    fs.readSync = realRead;
  }
  assert.deepEqual(sent, []);
  assert.equal(bytesRead, 0, 'the tape is not read when the requested range is empty');
  assert.equal(result.lastSeq, 50);
});
