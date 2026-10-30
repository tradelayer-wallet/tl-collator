// Round 13: one ordered stream per subscriber. A property test drives a real PeerSession and
// TapeStore with random interleavings of live appends, subscribes (including supersedes on the
// same channel), slow and drained channels, and channel replacements. Runs against dist/.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { DC_REPLAY_HIGH_WATER_BYTES, PeerSession, broadcastTapeEntry } from '../dist/peerSession.js';
import { TapeStore } from '../dist/tape.js';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// A channel the test controls. `parkAfter` sets a full queue once that many messages were sent,
// so a replay parks until the test drains it. A send on a closed channel throws, as a real
// RTCDataChannel does, and is counted as a violation.
const makeChannel = ({ parkAfter = Infinity, onSend } = {}) => ({
  readyState: 'open',
  bufferedAmount: 0,
  msgs: [],
  ends: [],
  closed: 0,
  sentAfterClose: 0,
  subscribed: false,
  entriesBeforeSubscribe: 0,
  requested: 0,
  tailAtSubscribe: 0,
  send(data) {
    if (this.readyState !== 'open') {
      this.sentAfterClose += 1;
      throw new Error('channel is not open');
    }
    const msg = JSON.parse(data);
    if (msg.t === 'TAPE_ENTRY' && !this.subscribed) this.entriesBeforeSubscribe += 1;
    this.msgs.push(msg);
    if (msg.t === 'TAPE_END') this.ends.push({ index: this.msgs.length - 1, requested: this.requested, tail: this.tailAtSubscribe });
    if (onSend) onSend(this, msg);
    if (this.msgs.length === parkAfter) this.bufferedAmount = 2 * DC_REPLAY_HIGH_WATER_BYTES;
  },
  close() {
    this.readyState = 'closed';
    this.closed += 1;
  },
});

const orderFor = (i, pad = 'x'.repeat(200)) => ({
  v: 1,
  kind: 'PLACE',
  orderId: i.toString(16).padStart(64, '0'),
  traderPubKey: 'ab'.repeat(33),
  clientNonce: `n${i}`,
  sigTrader: 'cd'.repeat(64),
  body: { pad, i },
});

const openStore = (dir) => new TapeStore({
  tapePath: path.join(dir, 'tape.jsonl'), idxPath: path.join(dir, 'tape.idx.json'), idxStride: 50,
  replayBatch: 7, maxReplayEntries: 1e6, collatorId: 'collator', collatorPrivKeyHex: '11'.repeat(32),
});

const tapeSeqs = (msgs) => msgs.filter((m) => m.t === 'TAPE_ENTRY').map((m) => m.entry.seq);
const errCodes = (ch) => ch.msgs.filter((m) => m.t === 'ERR').map((m) => m.code);
const range = (a, b) => Array.from({ length: Math.max(0, b - a + 1) }, (_, k) => a + k);
const mulberry32 = (seed) => () => {
  seed |= 0;
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};

// Every channel is one ordered stream: seqs strictly increase between TAPE_END markers, and each
// TAPE_END covers exactly [fromSeq, lastSeq]. fromSeq is max(requested, next seq after what this
// channel already carried), so it names any seq that was skipped rather than hiding it.
function assertOrderedStreams(ch, label) {
  assert.equal(ch.sentAfterClose, 0, `${label}: a send was attempted on a closed channel`);
  // A channel carries nothing until its own TAPE_SUB: a wallet that never subscribed on it would
  // otherwise see a live feed that starts after a gap it does not know about.
  assert.equal(ch.entriesBeforeSubscribe, 0, `${label}: entries reached a channel before its own TAPE_SUB`);
  const strictly = (seqs) => {
    for (let k = 1; k < seqs.length; k += 1) {
      assert.ok(seqs[k] > seqs[k - 1], `${label}: seq ${seqs[k]} follows ${seqs[k - 1]} on one channel`);
    }
  };
  let segStart = 0;
  ch.msgs.forEach((msg, i) => {
    if (msg.t !== 'TAPE_END') return;
    const seqs = tapeSeqs(ch.msgs.slice(segStart, i));
    strictly(seqs);
    const info = ch.ends.find((x) => x.index === i);
    const { fromSeq: f, lastSeq: last } = msg;
    assert.equal(f, Math.max(info.requested, info.tail + 1, 1), `${label}: TAPE_END fromSeq`);
    // A stream may start after the requested seq only over seqs this channel already carried.
    const carried = new Set(tapeSeqs(ch.msgs.slice(0, i)));
    for (let s = info.requested; s < f; s += 1) {
      assert.ok(carried.has(s), `${label}: TAPE_END skips ${s}, which this channel never carried`);
    }
    assert.deepEqual(seqs.filter((s) => s >= f), range(f, last), `${label}: stream [${f}, ${last}] is not exactly once each`);
    segStart = i + 1;
  });
  strictly(tapeSeqs(ch.msgs.slice(segStart)));
}

// The live-reach rule: an entry committed while a subscriber's channel is open reaches that
// channel, or the channel is closed so the wallet knows to resync.
function assertLiveReach(commits, label) {
  for (const c of commits) {
    if (!c.channel) continue;
    const delivered = tapeSeqs(c.channel.msgs).includes(c.seq);
    assert.ok(delivered || c.channel.readyState === 'closed', `${label}: seq ${c.seq} committed on an open channel never reached it`);
  }
}

async function runSchedule(seed) {
  const rand = mulberry32(seed);
  const pick = (n) => Math.floor(rand() * n);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-stream-prop-'));
  const label = `seed ${seed}`;
  try {
    const store = openStore(dir);
    const session = new PeerSession({ id: `prop-${seed}`, ws: { readyState: 1 }, burst: 1000, ratePerSec: 1000, openBurst: 4, openRatePerSec: 3 });
    const channels = [];
    const commits = [];
    const serves = [];
    let current = null;
    let nextOrder = 1;
    const refused = [];
    const attach = () => {
      const ch = makeChannel();
      channels.push(ch);
      if (session.attachDataChannel(ch)) current = ch;
      else refused.push(ch);
    };
    // The wallet's position: the highest seq n such that it has received 1..n on any channel.
    const position = () => {
      const seen = new Set(channels.flatMap((ch) => tapeSeqs(ch.msgs)));
      let n = 0;
      while (seen.has(n + 1)) n += 1;
      return n;
    };
    const subscribe = (from) => {
      if (!current || current.readyState !== 'open') attach();
      const ch = current;
      const sent = ch.msgs.slice(ch.msgs.findLastIndex((m) => m.t === 'TAPE_END') + 1);
      ch.subscribed = true;
      ch.requested = from;
      ch.tailAtSubscribe = tapeSeqs(sent).at(-1) ?? 0;
      serves.push(session.serveTapeSub(ch, store, from, { stallMs: 60_000, deadlineMs: 60_000 }));
    };

    attach();
    for (let step = 0; step < 60; step += 1) {
      const r = rand();
      if (r < 0.3) {
        const entry = store.append(orderFor(nextOrder));
        nextOrder += 1;
        const target = session.wantsTape && session.dc && session.dc.readyState === 'open' ? session.dc : null;
        commits.push({ seq: entry.seq, channel: target });
        broadcastTapeEntry([session], entry);
      } else if (r < 0.5) {
        const tip = store.getLastSeq();
        const choice = pick(3);
        subscribe(choice === 0 ? 1 : choice === 1 ? position() + 1 : 1 + pick(tip + 1));
      } else if (r < 0.58) {
        if (current) current.bufferedAmount = 2 * DC_REPLAY_HIGH_WATER_BYTES;
      } else if (r < 0.66) {
        if (current) current.bufferedAmount = 0;
      } else if (r < 0.72) {
        attach();
      } else {
        await sleep(pick(6));
      }
    }

    // Quiesce: drain every channel and let the streams finish. Then the wallet reconnects on a fresh
    // channel and resyncs from its own position. That resync must reach the tip with nothing missing.
    for (const ch of channels) ch.bufferedAmount = 0;
    await Promise.all(serves);
    attach();
    subscribe(position() + 1);
    await Promise.all(serves);

    for (const ch of channels) assertOrderedStreams(ch, label);
    for (const ch of refused) {
      assert.equal(ch.closed, 1, `${label}: a refused channel stayed open`);
      assert.deepEqual(errCodes(ch), ['busy_retry'], `${label}: a refused channel was not told to retry`);
      assert.deepEqual(tapeSeqs(ch.msgs), [], `${label}: a refused channel carried entries`);
    }
    assertLiveReach(commits, label);
    assert.equal(position(), store.getLastSeq(), `${label}: the wallet cannot resync to the tip`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('R13 property: random subscribe, supersede, append, slow and replace interleavings keep one ordered stream per channel', { timeout: 300000 }, async () => {
  for (let seed = 1; seed <= 30; seed += 1) {
    await runSchedule(seed);
  }
});

test('R13-1 a superseding TAPE_SUB continues the channel after the seqs it already carried', { timeout: 20000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-r13-supersede-'));
  try {
    const store = openStore(dir);
    for (let i = 1; i <= 300; i += 1) store.append(orderFor(i));
    const ch = makeChannel({ parkAfter: 50 });
    const session = new PeerSession({ id: 'r13-1', ws: { readyState: 1 }, burst: 10, ratePerSec: 1, openBurst: 4, openRatePerSec: 3 });
    session.dc = ch;
    const first = session.serveTapeSub(ch, store, 1);
    while (tapeSeqs(ch.msgs).length < 50) await sleep(2);
    ch.requested = 1;
    ch.tailAtSubscribe = 50;
    const second = session.serveTapeSub(ch, store, 1);
    ch.bufferedAmount = 0;
    await Promise.all([first, second]);
    assert.deepEqual(tapeSeqs(ch.msgs), range(1, 300), 'the channel carried a seq twice or skipped one');
    assert.equal(ch.msgs.filter((m) => m.t === 'TAPE_END').length, 1, 'the superseded replay sent a TAPE_END');
    assert.equal(ch.msgs.at(-1).fromSeq, 51, 'TAPE_END does not name the first seq the successor sent');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('R13-2 a channel attached while a replay is in flight is refused with ERR busy_retry; the replay finishes on its channel', { timeout: 20000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-r13-replace-'));
  try {
    const store = openStore(dir);
    for (let i = 1; i <= 20; i += 1) store.append(orderFor(i));
    const a = makeChannel();
    a.bufferedAmount = 2 * DC_REPLAY_HIGH_WATER_BYTES;
    const session = new PeerSession({ id: 'r13-2', ws: { readyState: 1 }, burst: 10, ratePerSec: 1, openBurst: 4, openRatePerSec: 3 });
    session.attachDataChannel(a);
    const served = session.serveTapeSub(a, store, 1);
    await sleep(20);
    const held = [21, 22, 23].map((i) => store.append(orderFor(i)));
    for (const e of held) broadcastTapeEntry([session], e);
    const b = makeChannel();
    assert.equal(session.attachDataChannel(b), false, 'a channel attached during a replay was adopted');
    broadcastTapeEntry([session], store.append(orderFor(24)));
    a.bufferedAmount = 0;
    await served;
    assert.equal(b.closed, 1, 'the refused channel stayed open');
    assert.deepEqual(errCodes(b), ['busy_retry'], 'the refused channel was not told to retry');
    assert.deepEqual(tapeSeqs(b.msgs), [], 'the refused channel carried entries');
    assert.equal(a.closed, 0, 'the refusal closed the channel whose replay was in flight');
    assert.deepEqual(tapeSeqs(a.msgs), range(1, 24), 'the replay in flight did not finish in order');
    assert.equal(a.msgs.at(-1).t, 'TAPE_END', 'the replay in flight did not end');
    assert.equal(session.dc, a, 'the session moved off the channel whose replay was in flight');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('R17-F3 the busy_retry answer tells the peer to wait 1 s before its TAPE_SUB, the interval the TAPE_SUB gate charges', { timeout: 20000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-r17-busy-'));
  try {
    const store = openStore(dir);
    for (let i = 1; i <= 20; i += 1) store.append(orderFor(i));
    const a = makeChannel();
    a.bufferedAmount = 2 * DC_REPLAY_HIGH_WATER_BYTES;
    const session = new PeerSession({ id: 'r17-3', ws: { readyState: 1 }, burst: 10, ratePerSec: 1, openBurst: 4, openRatePerSec: 3 });
    session.attachDataChannel(a);
    const served = session.serveTapeSub(a, store, 1);
    await sleep(20);
    const b = makeChannel();
    assert.equal(session.attachDataChannel(b), false);
    a.bufferedAmount = 0;
    await served;
    const refusals = b.msgs.filter((m) => m.t === 'ERR');
    assert.deepEqual(refusals.map((m) => m.code), ['busy_retry']);
    assert.match(refusals[0].msg, /TAPE_SUB at least 1 s after this message/, 'the busy_retry answer does not say how long to wait');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('R13-4 a replay past its deadline ends with the channel closed and no TAPE_END', { timeout: 20000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-r13-deadline-'));
  try {
    const store = openStore(dir);
    for (let i = 1; i <= 30; i += 1) store.append(orderFor(i));
    // Each entry adds 1 KB to the queue and the queue drains 50 bytes per millisecond: the stall
    // window never fires, yet the replay takes about 20 ms per entry.
    const ch = makeChannel({ onSend: (c) => { c.bufferedAmount += 1000; } });
    ch.bufferedAmount = DC_REPLAY_HIGH_WATER_BYTES + 1;
    const drain = setInterval(() => {
      ch.bufferedAmount = Math.max(0, ch.bufferedAmount - 50);
    }, 1);
    const session = new PeerSession({ id: 'r13-4', ws: { readyState: 1 }, burst: 10, ratePerSec: 1, openBurst: 4, openRatePerSec: 3 });
    session.dc = ch;
    const started = Date.now();
    await session.serveTapeSub(ch, store, 1, { stallMs: 60_000, deadlineMs: 300 });
    clearInterval(drain);
    assert.ok(Date.now() - started < 5000, 'the replay was not bounded by its deadline');
    assert.equal(ch.closed, 1, 'a replay past its deadline kept its channel');
    assert.equal(ch.msgs.filter((m) => m.t === 'TAPE_END').length, 0, 'an expired replay sent TAPE_END');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// R15-3: every close the collator starts on a tape channel says why first, so the peer can tell a
// resync request from a dead channel. The ERR is the last message the channel carries.
test('R15-3 a TAPE_SUB below the channel run closes the channel after an ERR resync_required', { timeout: 20000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-r15-below-'));
  try {
    const store = openStore(dir);
    for (let i = 1; i <= 30; i += 1) store.append(orderFor(i));
    // A replay from 10 is parked after three entries: the run this channel carries is 10..12.
    const ch = makeChannel({ parkAfter: 3 });
    const session = new PeerSession({ id: 'r15-3-below', ws: { readyState: 1 }, burst: 10, ratePerSec: 1, openBurst: 4, openRatePerSec: 3 });
    session.attachDataChannel(ch);
    const first = session.serveTapeSub(ch, store, 10, { stallMs: 60_000, deadlineMs: 60_000 });
    while (tapeSeqs(ch.msgs).length < 3) await sleep(2);
    await session.serveTapeSub(ch, store, 5);
    await first;
    assert.deepEqual(tapeSeqs(ch.msgs), range(10, 12));
    assert.equal(ch.closed, 1, 'a request below the run kept its channel');
    assert.deepEqual(errCodes(ch), ['resync_required'], 'the close carried no reason');
    assert.equal(ch.msgs.at(-1).t, 'ERR', 'the ERR is not the last message before the close');
    assert.equal(ch.sentAfterClose, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('R15-3 a replay whose peer stops draining closes the channel after an ERR stalled', { timeout: 20000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-r15-stall-'));
  try {
    const store = openStore(dir);
    for (let i = 1; i <= 30; i += 1) store.append(orderFor(i));
    const ch = makeChannel({ parkAfter: 3 });
    const session = new PeerSession({ id: 'r15-3-stall', ws: { readyState: 1 }, burst: 10, ratePerSec: 1, openBurst: 4, openRatePerSec: 3 });
    session.attachDataChannel(ch);
    await session.serveTapeSub(ch, store, 1, { stallMs: 50, deadlineMs: 60000 });
    assert.equal(ch.closed, 1, 'a stalled replay kept its channel');
    assert.deepEqual(errCodes(ch), ['stalled'], 'the stall close carried no reason');
    assert.equal(ch.msgs.at(-1).t, 'ERR', 'the ERR is not the last message before the close');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('R15-3 a replay past its deadline closes the channel after an ERR deadline_exceeded', { timeout: 20000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-r15-deadline-'));
  try {
    const store = openStore(dir);
    for (let i = 1; i <= 30; i += 1) store.append(orderFor(i));
    const ch = makeChannel({ onSend: (c) => { c.bufferedAmount += 1000; } });
    ch.bufferedAmount = DC_REPLAY_HIGH_WATER_BYTES + 1;
    const drain = setInterval(() => {
      ch.bufferedAmount = Math.max(0, ch.bufferedAmount - 50);
    }, 1);
    const session = new PeerSession({ id: 'r15-3-deadline', ws: { readyState: 1 }, burst: 10, ratePerSec: 1, openBurst: 4, openRatePerSec: 3 });
    session.attachDataChannel(ch);
    await session.serveTapeSub(ch, store, 1, { stallMs: 60_000, deadlineMs: 300 });
    clearInterval(drain);
    assert.equal(ch.closed, 1, 'a replay past its deadline kept its channel');
    assert.deepEqual(errCodes(ch), ['deadline_exceeded'], 'the deadline close carried no reason');
    assert.equal(ch.msgs.at(-1).t, 'ERR', 'the ERR is not the last message before the close');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
