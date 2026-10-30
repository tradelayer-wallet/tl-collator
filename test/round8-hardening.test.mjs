// Regression probes for the round-8 findings. Each case is written to fail on the round-7
// behaviour it guards against. Unit cases load dist/ (run `npm run build` first). The e2e
// cases spawn dist/index.js with the wrtc stub, as server.e2e.test.mjs does.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import WebSocket from 'ws';

import { PeerSession } from '../dist/peerSession.js';
// Namespace import: on a build without these exports, each case fails on its own.
import * as peerSession from '../dist/peerSession.js';
import { IpIntelClient } from '../dist/ipIntel.js';
import { ClearlistClient } from '../dist/clearlist.js';
import { TapeStore } from '../dist/tape.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const loader = path.join(root, 'scripts', 'e2e', 'wrtc-loader.mjs');

// --------------------------------------------------------------------- helpers

const fakeDc = ({ bufferedAmount = 0, throwOnSend = false } = {}) => {
  const sent = [];
  let closed = 0;
  return {
    readyState: 'open',
    bufferedAmount,
    send(data) {
      if (throwOnSend) throw new Error('send failed');
      sent.push(data);
    },
    close() {
      closed += 1;
    },
    get sent() {
      return sent;
    },
    get closed() {
      return closed;
    },
  };
};

const fakeWs = { readyState: 1, OPEN: 1, close() {} };

const sessionWith = (dc) => {
  const s = new PeerSession({ id: `p-${Math.random()}`, ws: fakeWs, burst: 10, ratePerSec: 1, openBurst: 4, openRatePerSec: 3 });
  s.dc = dc;
  return s;
};

// Resolves to { value } / { error } / 'timeout' so a hung call fails the case instead of the run.
const settle = (promise, ms) =>
  Promise.race([
    promise.then((value) => ({ value }), (error) => ({ error })),
    new Promise((resolve) => setTimeout(() => resolve('timeout'), ms)),
  ]);

const listen = (handler) =>
  new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });

const closeServer = (server) =>
  new Promise((resolve) => {
    server.closeAllConnections?.();
    server.close(() => resolve());
  });

const freePort = () =>
  new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });

// ------------------------------------------------------------------ unit cases

test('R8-DC a channel holding more unsent data than the cap is closed, not queued', () => {
  const dc = fakeDc({ bufferedAmount: 4 * 1024 * 1024 + 1 });
  const s = sessionWith(dc);
  const delivered = s.sendDc({ t: 'PONG', v: 1, ts: 1 });
  assert.equal(delivered, false, 'message was queued on a channel past its buffer cap');
  assert.equal(dc.sent.length, 0);
  assert.equal(dc.closed, 1, 'slow channel was not closed');
  assert.equal(s.dc, null);
});

test('R8-DC a send that throws closes the channel and does not propagate', () => {
  const dc = fakeDc({ throwOnSend: true });
  const s = sessionWith(dc);
  assert.doesNotThrow(() => s.sendDc({ t: 'PONG', v: 1, ts: 1 }));
  assert.equal(dc.closed, 1);
  assert.equal(s.dc, null);
});

test('R8-DC attaching a second channel closes the first and keeps the second', () => {
  const first = fakeDc();
  const second = fakeDc();
  const s = sessionWith(first);
  s.attachDataChannel(second);
  assert.equal(s.dc, second);
  assert.equal(first.closed, 1, 'replaced channel was left open');
  assert.equal(second.closed, 0);
});

test('R8-DC a tape broadcast reaches every subscriber even when one send throws', () => {
  const bad = sessionWith(fakeDc({ throwOnSend: true }));
  bad.wantsTape = true;
  const goodDc = fakeDc();
  const good = sessionWith(goodDc);
  good.wantsTape = true;
  const entry = { v: 1, seq: 1, entryHash: 'h', order: {} };
  assert.equal(typeof peerSession.broadcastTapeEntry, 'function', 'broadcastTapeEntry is not exported');
  assert.doesNotThrow(() => peerSession.broadcastTapeEntry([bad, good], entry));
  assert.equal(goodDc.sent.length, 1, 'subscriber after the failing one missed the entry');
});

test('R8-OUT IP intel answers that never finish are abandoned at the deadline', async () => {
  let open = 0;
  const server = await listen(() => {
    open += 1; // never answers
  });
  try {
    const client = new IpIntelClient({ url: `http://127.0.0.1:${server.address().port}/intel`, ttlSec: 60, max: 10 });
    const outcome = await settle(client.lookup('203.0.113.9'), 6000);
    assert.notEqual(outcome, 'timeout', 'IP intel lookup hung past any deadline');
    assert.ok(outcome.error, 'stalled lookup did not fail');
    assert.equal(open, 1);
  } finally {
    await closeServer(server);
  }
});

test('R8-OUT an oversized IP intel body is refused, not buffered', async () => {
  const server = await listen((req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ asn: 64500, pad: 'x'.repeat(5 * 1024 * 1024) }));
  });
  try {
    const client = new IpIntelClient({ url: `http://127.0.0.1:${server.address().port}/intel`, ttlSec: 60, max: 10 });
    const outcome = await settle(client.lookup('203.0.113.10'), 8000);
    assert.notEqual(outcome, 'timeout');
    assert.ok(outcome.error, '5 MiB intel body was accepted');
  } finally {
    await closeServer(server);
  }
});

test('R8-OUT an outbound redirect is refused (no second host is contacted)', async () => {
  let hops = 0;
  const target = await listen((req, res) => {
    hops += 1;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ asn: 64500 }));
  });
  const first = await listen((req, res) => {
    res.statusCode = 302;
    res.setHeader('location', `http://127.0.0.1:${target.address().port}/elsewhere`);
    res.end();
  });
  try {
    const client = new IpIntelClient({ url: `http://127.0.0.1:${first.address().port}/intel`, ttlSec: 60, max: 10 });
    const outcome = await settle(client.lookup('203.0.113.11'), 6000);
    assert.ok(outcome !== 'timeout' && outcome.error, 'redirect was followed and answered');
    assert.equal(hops, 0, 'redirect target was contacted');
  } finally {
    await closeServer(first);
    await closeServer(target);
  }
});

test('R8-OUT a clearlist check that never finishes is abandoned at the deadline', async () => {
  const server = await listen(() => {});
  try {
    const client = new ClearlistClient({ baseUrl: `http://127.0.0.1:${server.address().port}` });
    const outcome = await settle(client.check('group-1', 'ab'.repeat(33)), 6000);
    assert.notEqual(outcome, 'timeout', 'clearlist check hung past any deadline');
    assert.ok(outcome.error);
  } finally {
    await closeServer(server);
  }
});

test('R8-TAPE a multi-byte character split across replay reads is replayed intact', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-r8-tape-'));
  try {
    const tapePath = path.join(dir, 'tape.jsonl');
    const idxPath = path.join(dir, 'tape.idx.json');
    // A 3-byte character run that is cut by the 64 KiB read boundary of the replay scan.
    let note = '';
    for (let pad = 0; pad < 4; pad += 1) {
      note = 'a'.repeat(pad) + '€'.repeat(30000);
      const probe = Buffer.from(JSON.stringify({ seq: 1, entryHash: 'h1', order: { orderId: 'o1', traderPubKey: 'p1', note } }) + '\n');
      if ((probe[65536] & 0xc0) === 0x80) break;
    }
    const probe = Buffer.from(JSON.stringify({ seq: 1, entryHash: 'h1', order: { orderId: 'o1', traderPubKey: 'p1', note } }) + '\n');
    assert.equal(probe[65536] & 0xc0, 0x80, 'fixture does not cut a character at the read boundary');
    const first = JSON.stringify({ seq: 1, entryHash: 'h1', order: { orderId: 'o1', traderPubKey: 'p1', note } });
    const second = JSON.stringify({ seq: 2, entryHash: 'h2', order: { orderId: 'o2', traderPubKey: 'p2', note: 'plain' } });
    fs.writeFileSync(tapePath, `${first}\n${second}\n`, 'utf8');
    const store = new TapeStore({
      tapePath, idxPath, idxStride: 1000, replayBatch: 100, maxReplayEntries: 10000,
      collatorId: 'collator', collatorPrivKeyHex: '11'.repeat(32),
    });
    const seen = [];
    await store.replayFromSeq(1, (e) => seen.push(e));
    assert.equal(seen.length, 2);
    assert.equal(seen[0].order.note, note, 'replayed entry differs from the stored one');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ------------------------------------------------------------------ e2e cases

const startCollator = async () => {
  const port = await freePort();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-r8-e2e-'));
  const env = { PATH: process.env.PATH, HOME: process.env.HOME || os.homedir(), DATA_DIR: dataDir, PORT: String(port) };
  const child = spawn(process.execPath, ['--import', loader, 'dist/index.js'], { cwd: root, env, stdio: ['ignore', 'pipe', 'pipe'] });
  let exited = null;
  child.stdout.on('data', () => {});
  child.stderr.on('data', () => {});
  child.on('exit', (code) => { exited = code; });
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    if (exited !== null) throw new Error(`collator exited early (${exited})`);
    try {
      const res = await fetch(`http://127.0.0.1:${port}/health`);
      if (res.ok) break;
    } catch {}
    await new Promise((r) => setTimeout(r, 150));
  }
  const stop = () => new Promise((resolve) => {
    if (exited !== null) return resolve();
    child.once('exit', () => resolve());
    child.kill('SIGTERM');
  });
  return { port, child, stop, alive: () => exited === null, dataDir };
};

// Resolves true when the server closes the socket within `ms`.
const closedWithin = (sock, ms) =>
  new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), ms);
    sock.on('close', () => { clearTimeout(timer); resolve(true); });
    sock.on('end', () => { clearTimeout(timer); resolve(true); });
  });

test('R8-HTTP deadlines: stalled headers, stalled bodies and an idle WebSocket', { timeout: 120000 }, async () => {
  const c = await startCollator();
  try {
    const stalledHeaders = (async () => {
      const sock = net.connect(c.port, '127.0.0.1');
      sock.on('error', () => {});
      await new Promise((resolve) => sock.on('connect', resolve));
      sock.write('GET /health HTTP/1.1\r\nHost: x\r\n');
      const closed = await closedWithin(sock, 15000);
      sock.destroy();
      return closed;
    })();

    const stalledBody = (async () => {
      const sock = net.connect(c.port, '127.0.0.1');
      sock.on('error', () => {});
      await new Promise((resolve) => sock.on('connect', resolve));
      sock.write('POST /rpc/tl_getinfo HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{');
      const closed = await closedWithin(sock, 40000);
      sock.destroy();
      return closed;
    })();

    const idleWs = (async () => {
      const ws = await new Promise((resolve, reject) => {
        const socket = new WebSocket(`ws://127.0.0.1:${c.port}/ws`);
        socket.once('open', () => resolve(socket));
        socket.once('error', reject);
      });
      await new Promise((resolve) => setTimeout(resolve, 35000));
      const open = ws.readyState === WebSocket.OPEN;
      ws.close();
      return open;
    })();

    const [headersClosed, bodyClosed, wsOpen] = await Promise.all([stalledHeaders, stalledBody, idleWs]);
    assert.equal(headersClosed, true, 'stalled request headers were not closed within 15 s');
    assert.equal(bodyClosed, true, 'stalled request body was not closed within 40 s');
    assert.equal(wsOpen, true, 'an idle, authorised WebSocket was closed by the HTTP deadlines');
    assert.equal(c.alive(), true, 'collator exited during the deadline probes');
  } finally {
    await c.stop();
  }
});

test('R8-DC the inbound size is measured in bytes, the unit MAX_MSG_BYTES and the WebSocket cap use', () => {
  // 'é' is two bytes in UTF-8 but one UTF-16 unit: a string cap counted in units admits twice the bytes.
  assert.equal(peerSession.dcMessageBytes('é'.repeat(10)), 20);
  assert.equal(peerSession.dcMessageBytes(new Uint8Array(7)), 7);
  assert.equal(peerSession.dcMessageBytes(new ArrayBuffer(5)), 5);
});
