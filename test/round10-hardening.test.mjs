// Regression probes for the round-10 findings on the round-8 hardening. Each case is written to
// fail on the round-8 behaviour it guards against. Runs against dist/ (npm run build first).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

import { attachRequestDeadlines } from '../dist/httpDeadlines.js';
import { DC_MAX_BUFFERED_BYTES, PeerSession } from '../dist/peerSession.js';
import { TapeStore } from '../dist/tape.js';
// Namespace imports: on a build without an export, only that case fails.
import { IpIntelClient } from '../dist/ipIntel.js';
import * as ipIntel from '../dist/ipIntel.js';

const listen = (server) => new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
const closeServer = (server) => new Promise((resolve) => server.close(() => resolve()));
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const connect = (port) =>
  new Promise((resolve) => {
    const sock = net.connect(port, '127.0.0.1');
    sock.on('error', () => {});
    sock.on('connect', () => resolve(sock));
  });

// Resolves true when the server closes the socket within `ms`. A paused socket never emits 'end',
// so the response bytes are drained first.
const closedWithin = (sock, ms) =>
  new Promise((resolve) => {
    sock.resume();
    const timer = setTimeout(() => resolve(false), ms);
    sock.once('close', () => { clearTimeout(timer); resolve(true); });
    sock.once('end', () => { clearTimeout(timer); resolve(true); });
  });

// --------------------------------------------------------------- HTTP watchdog

test('R10-WD a GET whose handler takes 31 s is still answered (no body deadline on a bodyless request)', { timeout: 60000 }, async () => {
  const server = http.createServer(async (req, res) => {
    await sleep(31000);
    res.end('done');
  });
  attachRequestDeadlines(server);
  const port = await listen(server);
  const sock = await connect(port);
  let body = '';
  sock.on('data', (chunk) => { body += chunk.toString(); });
  sock.write('GET /slow HTTP/1.1\r\nHost: x\r\n\r\n');
  await sleep(32000);
  sock.destroy();
  await closeServer(server);
  assert.match(body, /HTTP\/1\.1 200/, 'a slow but honest GET was closed by the body deadline');
});

test('R10-WD an idle keep-alive socket is closed at the idle deadline', { timeout: 20000 }, async () => {
  const server = http.createServer((req, res) => res.end('ok'));
  server.keepAliveTimeout = 60000;
  attachRequestDeadlines(server, { headersMs: 5000, bodyMs: 5000, idleMs: 300 });
  const port = await listen(server);
  const sock = await connect(port);
  sock.write('GET / HTTP/1.1\r\nHost: x\r\n\r\n');
  const closed = await closedWithin(sock, 2000);
  sock.destroy();
  await closeServer(server);
  assert.equal(closed, true, 'idle keep-alive socket outlived its idle deadline');
});

test('R10-WD a POST whose body stalls is closed at the body deadline', { timeout: 20000 }, async () => {
  const server = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => res.end('ok'));
  });
  attachRequestDeadlines(server, { headersMs: 5000, bodyMs: 300, idleMs: 5000 });
  const port = await listen(server);
  const sock = await connect(port);
  sock.write('POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n{"a":');
  const closed = await closedWithin(sock, 2000);
  sock.destroy();
  await closeServer(server);
  assert.equal(closed, true, 'stalled POST body was not closed at the body deadline');
});

// ---------------------------------------------------------- paced TAPE_SUB replay

const fakeChannel = ({ drainPerTick = 8 * 1024, tickMs = 1, bufferedAmount = 0 } = {}) => {
  const ch = {
    readyState: 'open',
    bufferedAmount,
    sent: [],
    closed: 0,
    send(data) {
      this.sent.push(data);
      this.bufferedAmount += Buffer.byteLength(data);
    },
    close() {
      this.readyState = 'closed';
      this.closed += 1;
    },
  };
  // Steady link: the queue drains a fixed amount per tick, while the replay produces at CPU speed.
  const timer = setInterval(() => {
    if (ch.readyState === 'open') ch.bufferedAmount = Math.max(0, ch.bufferedAmount - drainPerTick);
  }, tickMs);
  // unref: a failing case must not keep the test process alive.
  timer.unref();
  ch.stop = () => clearInterval(timer);
  return ch;
};

const writeTape = (dir, count, noteBytes) => {
  const tapePath = path.join(dir, 'tape.jsonl');
  const lines = [];
  const note = 'x'.repeat(noteBytes);
  for (let seq = 1; seq <= count; seq += 1) {
    lines.push(JSON.stringify({ v: 1, seq, entryHash: `h${seq}`, order: { orderId: `o${seq}`, note } }));
  }
  fs.writeFileSync(tapePath, `${lines.join('\n')}\n`, 'utf8');
  return tapePath;
};

const openStore = (dir, tapePath, maxReplayEntries) =>
  new TapeStore({
    tapePath, idxPath: path.join(dir, 'tape.idx.json'), idxStride: 1000, replayBatch: 500,
    maxReplayEntries, collatorId: 'collator', collatorPrivKeyHex: '11'.repeat(32),
  });

test('R10-REPLAY a large TAPE_SUB resync through a responsive channel is delivered whole', { timeout: 60000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-r10-replay-'));
  try {
    const count = 7000;
    const tapePath = writeTape(dir, count, 600);
    const store = openStore(dir, tapePath, 10000);
    const ch = fakeChannel();
    const session = new PeerSession({ id: 'p1', ws: { readyState: 1 }, burst: 10, ratePerSec: 1 });
    session.dc = ch;
    const replay = await store.replayFromSeq(1, (e) => session.sendReplayEntry(ch, e));
    ch.stop();
    // The whole replay is far beyond the live-feed cap, so a burst without pacing could not pass.
    const total = ch.sent.reduce((n, s) => n + Buffer.byteLength(s), 0);
    assert.ok(total > DC_MAX_BUFFERED_BYTES, `fixture too small (${total} bytes) to exercise the cap`);
    assert.equal(replay.lastSeq, count, 'replay stopped before the end');
    assert.equal(ch.closed, 0, 'a responsive channel was closed during resync');
    assert.equal(ch.sent.length, count, `delivered ${ch.sent.length} of ${count} entries`);
    assert.equal(session.dc, ch, 'session lost its channel during resync');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('R10-REPLAY the unpaced burst (round 8 path) closes the same channel: the mechanism this guards', { timeout: 60000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-r10-burst-'));
  try {
    const tapePath = writeTape(dir, 7000, 600);
    const store = openStore(dir, tapePath, 10000);
    const ch = fakeChannel();
    const session = new PeerSession({ id: 'p0', ws: { readyState: 1 }, burst: 10, ratePerSec: 1 });
    session.dc = ch;
    await store.replayFromSeq(1, (e) => session.sendTapeEntry(e));
    ch.stop();
    assert.equal(ch.closed, 1, 'an unpaced burst no longer exceeds the live-feed cap; re-check the fixture');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('R10-REPLAY a stalled channel ends the replay and is closed (no hang)', { timeout: 20000 }, async () => {
  const ch = { readyState: 'open', bufferedAmount: 2 * 1024 * 1024, sent: [], closed: 0, send() {}, close() { this.readyState = 'closed'; this.closed += 1; } };
  const session = new PeerSession({ id: 'p2', ws: { readyState: 1 }, burst: 10, ratePerSec: 1 });
  session.dc = ch;
  const entry = { v: 1, seq: 1, order: {} };
  const delivered = await session.sendReplayEntry(ch, entry, 200);
  assert.equal(delivered, false);
  assert.equal(ch.closed, 1, 'stalled channel was not closed');
  assert.equal(session.dc, null);
});

test('R10-REPLAY a replay stops when its channel is replaced by a newer one', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-r10-swap-'));
  try {
    const tapePath = writeTape(dir, 300, 100);
    const store = openStore(dir, tapePath, 10000);
    const old = fakeChannel();
    const fresh = fakeChannel();
    const session = new PeerSession({ id: 'p3', ws: { readyState: 1 }, burst: 10, ratePerSec: 1 });
    session.dc = old;
    let n = 0;
    let stopped = false;
    await store.replayFromSeq(1, async (e) => {
      n += 1;
      if (n === 50) session.attachDataChannel(fresh);
      const sent = await session.sendReplayEntry(old, e);
      if (!sent) stopped = true;
      return sent;
    });
    old.stop();
    fresh.stop();
    assert.equal(stopped, true, 'replay ran on after its channel was replaced');
    assert.equal(fresh.sent.length, 0, 'replaced channel delivered entries to the successor');
    assert.equal(old.sent.length, 49);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ------------------------------------------------------- fail-closed intel policy

test('R10-INTEL a reject mode needs an intel verdict; log modes and an empty ASN list do not', () => {
  const base = { vpnFilterMode: 'off', asnBlockMode: 'off', asnBlocklist: [] };
  assert.equal(ipIntel.intelAdmits(base, null), true);
  assert.equal(ipIntel.intelAdmits({ ...base, vpnFilterMode: 'log' }, null), true);
  assert.equal(ipIntel.intelAdmits({ ...base, vpnFilterMode: 'reject' }, null), false);
  assert.equal(ipIntel.intelAdmits({ ...base, asnBlockMode: 'log', asnBlocklist: [64500] }, null), true);
  assert.equal(ipIntel.intelAdmits({ ...base, asnBlockMode: 'reject' }, null), true);
  assert.equal(ipIntel.intelAdmits({ ...base, asnBlockMode: 'reject', asnBlocklist: [64500] }, null), false);
});

test('R10-INTEL a hung intel answer is an error for the caller (the policy path refuses on it)', { timeout: 20000 }, async () => {
  const server = http.createServer(() => {});
  const port = await listen(server);
  const client = new IpIntelClient({ url: `http://127.0.0.1:${port}/intel`, ttlSec: 0, max: 10 });
  const started = Date.now();
  let failed = false;
  try {
    await client.lookup('198.51.100.7');
  } catch {
    failed = true;
  }
  server.closeAllConnections?.();
  await closeServer(server);
  assert.equal(failed, true, 'hung intel lookup returned a verdict');
  assert.ok(Date.now() - started < 6000, 'hung intel lookup was not abandoned at its deadline');
});
