// Regression probes for the round-12 findings. Each case is written to fail on the behaviour it
// guards against. Runs against dist/ (npm run build first).
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { DC_REPLAY_HIGH_WATER_BYTES, PeerSession, broadcastTapeEntry } from '../dist/peerSession.js';
import { loadConfig } from '../dist/config.js';
import { TapeStore } from '../dist/tape.js';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// A channel whose queue stays where the test puts it, so the replay parks on a full queue until
// the test drains it. Messages are recorded as the peer would parse them.
const fakeChannel = () => ({
  readyState: 'open',
  bufferedAmount: 0,
  msgs: [],
  closed: 0,
  send(data) {
    this.msgs.push(JSON.parse(data));
  },
  close() {
    this.readyState = 'closed';
    this.closed += 1;
  },
});

const orderFor = (i) => ({
  v: 1,
  kind: 'PLACE',
  orderId: i.toString(16).padStart(64, '0'),
  traderPubKey: 'ab'.repeat(33),
  clientNonce: `n${i}`,
  sigTrader: 'cd'.repeat(64),
  body: { pad: 'x'.repeat(200), i },
});

const openStore = (dir, count) => {
  const store = new TapeStore({
    tapePath: path.join(dir, 'tape.jsonl'), idxPath: path.join(dir, 'tape.idx.json'), idxStride: 50,
    replayBatch: 500, maxReplayEntries: 10000, collatorId: 'collator', collatorPrivKeyHex: '11'.repeat(32),
  });
  for (let i = 1; i <= count; i += 1) store.append(orderFor(i));
  return store;
};

const tapeSeqs = (ch) => ch.msgs.filter((m) => m.t === 'TAPE_ENTRY').map((m) => m.entry.seq);

test('R12-F1 live entries committed during a paused replay follow the replay in seq order, before TAPE_END', { timeout: 20000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-r12-order-'));
  try {
    const store = openStore(dir, 300);
    const ch = fakeChannel();
    ch.bufferedAmount = 2 * DC_REPLAY_HIGH_WATER_BYTES;
    const session = new PeerSession({ id: 'f1-order', ws: { readyState: 1 }, burst: 10, ratePerSec: 1, openBurst: 4, openRatePerSec: 3 });
    session.dc = ch;
    const served = session.serveTapeSub(ch, store, 1);
    // The replay is now parked on the full queue at seq 1.
    await sleep(30);
    for (const i of [301, 302]) broadcastTapeEntry([session], store.append(orderFor(i)));
    ch.bufferedAmount = 0;
    await served;
    const expected = Array.from({ length: 302 }, (_, k) => k + 1);
    assert.deepEqual(tapeSeqs(ch), expected, 'channel seqs are not one ascending stream');
    const end = ch.msgs[ch.msgs.length - 1];
    assert.equal(end.t, 'TAPE_END');
    assert.equal(end.lastSeq, 302, 'TAPE_END reports a tip the channel had not carried yet');
    assert.equal(ch.closed, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('R12-F1 a newer TAPE_SUB on the same session supersedes the replay still parked on that channel', { timeout: 20000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-r12-supersede-'));
  try {
    const store = openStore(dir, 300);
    const ch = fakeChannel();
    ch.bufferedAmount = 2 * DC_REPLAY_HIGH_WATER_BYTES;
    const session = new PeerSession({ id: 'f1-supersede', ws: { readyState: 1 }, burst: 10, ratePerSec: 1, openBurst: 4, openRatePerSec: 3 });
    session.dc = ch;
    const first = session.serveTapeSub(ch, store, 1);
    await sleep(30);
    const second = session.serveTapeSub(ch, store, 1);
    ch.bufferedAmount = 0;
    await Promise.all([first, second]);
    const seqs = tapeSeqs(ch);
    assert.equal(seqs.length, 300, `delivered ${seqs.length} entries; two replays ran on one channel`);
    assert.deepEqual(seqs, Array.from({ length: 300 }, (_, k) => k + 1));
    assert.equal(ch.msgs.filter((m) => m.t === 'TAPE_END').length, 1, 'superseded replay sent a TAPE_END');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('R12-F1 live entries held past the bound close the channel and end the replay without TAPE_END', { timeout: 20000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-r12-held-'));
  try {
    const store = openStore(dir, 20);
    const ch = fakeChannel();
    ch.bufferedAmount = 2 * DC_REPLAY_HIGH_WATER_BYTES;
    const session = new PeerSession({ id: 'f1-held', ws: { readyState: 1 }, burst: 10, ratePerSec: 1, openBurst: 4, openRatePerSec: 3 });
    session.dc = ch;
    const served = session.serveTapeSub(ch, store, 1);
    await sleep(30);
    // Held entries are bounded by bytes (R13-3): about 400 KB each, so a few of them pass the bound.
    const pad = 'x'.repeat(400 * 1024);
    for (let i = 0; i < 16; i += 1) {
      broadcastTapeEntry([session], store.append({ ...orderFor(1000 + i), body: { pad, i } }));
    }
    ch.bufferedAmount = 0;
    await served;
    assert.equal(ch.closed, 1, 'a replay holding unbounded live entries kept its channel');
    assert.equal(ch.msgs.filter((m) => m.t === 'TAPE_END').length, 0, 'an interrupted replay sent TAPE_END');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('R12-F1 a replay delivers only the lines that existed when it began', { timeout: 20000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-r12-snapshot-'));
  try {
    const store = openStore(dir, 300);
    const seen = [];
    let appended = false;
    await store.replayFromSeq(1, (e) => {
      seen.push(e.seq);
      if (!appended) {
        appended = true;
        for (let i = 301; i <= 305; i += 1) store.append(orderFor(i));
      }
    });
    assert.deepEqual(seen, Array.from({ length: 300 }, (_, k) => k + 1), 'replay read lines appended after it began');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ------------------------------------------------------- collator as a process (F2)

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const loader = path.join(root, 'scripts', 'e2e', 'wrtc-loader.mjs');

const freePort = () =>
  new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });

// Starts dist/index.js with a clean environment, as server.e2e.test.mjs does.
async function startCollator(extraEnv = {}) {
  const port = await freePort();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-r12-e2e-'));
  const env = { PATH: process.env.PATH, HOME: process.env.HOME || os.homedir(), DATA_DIR: dataDir, PORT: String(port), ...extraEnv };
  const child = spawn(process.execPath, ['--import', loader, 'dist/index.js'], { cwd: root, env, stdio: ['ignore', 'pipe', 'pipe'] });
  let exited = null;
  child.stdout.on('data', () => {});
  child.stderr.on('data', () => {});
  child.on('exit', (code) => { exited = code; });
  const base = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline && exited === null) {
    try {
      if ((await fetch(`${base}/health`)).ok) break;
    } catch {}
    await sleep(150);
  }
  const stop = () => new Promise((resolve) => {
    if (exited !== null) return resolve();
    child.once('exit', () => resolve());
    child.kill('SIGTERM');
  });
  return { base, stop, exited: () => exited };
}

// A loopback intel provider that answers every lookup with the same verdict.
async function startIntelStub(verdict) {
  const server = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(verdict));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${server.address().port}/`, close: () => new Promise((resolve) => server.close(resolve)) };
}

test('R12-F2 /attestation/ip with no reputation source fails closed instead of reporting a clean IP', { timeout: 120000 }, async () => {
  const c = await startCollator();
  try {
    const res = await fetch(`${c.base}/attestation/ip`);
    const body = await res.json();
    assert.equal(body.success, false, `reported success with no reputation source: "${body.message}"`);
    assert.equal(body.isBlocked, false);
    assert.doesNotMatch(String(body.message), /clean/i);
  } finally {
    await c.stop();
  }
});

test('R12-F2 /attestation/ip with a configured intel provider still reports its verdict', { timeout: 120000 }, async () => {
  const intel = await startIntelStub({ vpn: false, asn: 64500 });
  const c = await startCollator({ IP_INTEL_URL: intel.url });
  try {
    const res = await fetch(`${c.base}/attestation/ip`);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.isBlocked, false);
    assert.equal(body.message, 'IP is clean and trusted.');
  } finally {
    await c.stop();
    await intel.close();
  }
});

// ------------------------------------------------------- clearlist answers (F3)

// A loopback clearlist oracle that answers every check with `body`.
async function startClearlistStub(body) {
  const server = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((resolve) => server.close(resolve)) };
}

test('R12-F3 a clearlist answer admits only a boolean true', { timeout: 60000 }, async () => {
  const { ClearlistClient } = await import('../dist/clearlist.js');
  const cases = [
    [{ allowed: true }, true],
    [{ allowed: false }, false],
    [{ allowed: 'false' }, 'refused'],
    [{ allowed: 'true' }, 'refused'],
    [{ allowed: 0 }, 'refused'],
    [{ allowed: 1 }, 'refused'],
    [{}, 'refused'],
  ];
  for (const [body, want] of cases) {
    const stub = await startClearlistStub(body);
    try {
      const client = new ClearlistClient({ baseUrl: stub.url });
      const got = await client.check('group-1', 'ab'.repeat(33)).then((r) => r.allowed, () => 'refused');
      assert.equal(got, want, `clearlist answer ${JSON.stringify(body)} was read as ${JSON.stringify(got)}`);
    } finally {
      await stub.close();
    }
  }
});

// ------------------------------------------------------- broad trusted hops (F4)

test('R12-F4 a trusted hop broader than /8 (IPv4) or /16 (IPv6) is refused unless explicitly allowed', async () => {
  const { parseTrustedProxyConfig, createClientIpResolver } = await import('../dist/clientIp.js');
  const trust = (cidrs, extra = {}) => parseTrustedProxyConfig({ TRUST_PROXY: '1', TRUST_PROXY_CIDRS: cidrs, ...extra });
  for (const broad of ['0.0.0.0/0', '::/0', '0.0.0.0/1', '128.0.0.0/1', '10.0.0.0/7', '2000::/3', '2001::/15']) {
    assert.throws(() => trust(broad), /too broad/, `${broad} was accepted as a trusted hop`);
  }
  for (const narrow of ['10.0.0.0/8', '192.168.0.0/16', '2001:db8::/32', '10.0.0.1']) {
    assert.doesNotThrow(() => trust(narrow), `${narrow} was refused`);
  }
  // The explicit opt-in admits a broad entry, and the resolver then trusts exactly what it names.
  const optIn = trust('0.0.0.0/1', { TRUST_PROXY_ALLOW_BROAD_CIDRS: '1' });
  const resolver = createClientIpResolver(optIn);
  const req = { headers: { 'x-forwarded-for': '200.0.0.1' }, socket: { remoteAddress: '1.2.3.4' } };
  assert.equal(resolver.resolve(req), '200.0.0.1');
  assert.throws(() => trust('0.0.0.0/1', { TRUST_PROXY_ALLOW_BROAD_CIDRS: 'yes' }), /TRUST_PROXY_ALLOW_BROAD_CIDRS/);
});

// ------------------------------------------------------- client IP rule (F5)

// Shared with tl-relayer (scripts/fixtures/client-ip-vectors.json): both repos read the same bytes.
const CLIENT_IP_VECTORS_SHA256 = '38120ac55cdd3d7938fd09e680d1567a5a78fd95d433dc7ec511a528cda90020';

test('R12-F5 the X-Forwarded-For client IP rule matches the shared vectors', async () => {
  const bytes = fs.readFileSync(path.join(root, 'test', 'fixtures', 'client-ip-vectors.json'));
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), CLIENT_IP_VECTORS_SHA256, 'vector file differs from the shared copy');
  const { cases } = JSON.parse(bytes.toString('utf8'));
  const { createClientIpResolver } = await import('../dist/clientIp.js');
  const failures = [];
  for (const c of cases) {
    const resolver = createClientIpResolver({ enabled: true, cidrs: c.trusted });
    const headers = c.xff === null ? {} : { 'x-forwarded-for': c.xff };
    const got = resolver.resolve({ headers, socket: { remoteAddress: c.peer } });
    if (got !== c.expect) failures.push(`${c.name}: got ${JSON.stringify(got)}, want ${JSON.stringify(c.expect)}`);
  }
  assert.deepEqual(failures, [], 'client IP rule disagrees with the shared vectors');
});

// ------------------------------------------------------- ICE server config (F8)

// Same shape as test/config.test.js: loadConfig reads process.env at call time.
const withConfigEnv = (overrides, fn) => {
  const saved = { ...process.env };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-r12-config-'));
  try {
    Object.assign(process.env, { DATA_DIR: dir, TRUST_PROXY: '', TRUST_PROXY_CIDRS: '' }, overrides);
    return fn();
  } finally {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    Object.assign(process.env, saved);
    fs.rmSync(dir, { recursive: true, force: true });
  }
};

test('R12-F8 an ICE_SERVERS_JSON that is not a JSON array aborts startup instead of silently using Google STUN', () => {
  for (const bad of ['[{"urls":', '{"urls":"stun:stun.example.org:3478"}', '"stun:stun.example.org"']) {
    withConfigEnv({ ICE_SERVERS_JSON: bad }, () => {
      assert.throws(() => loadConfig(), /ICE_SERVERS_JSON/, `accepted ICE_SERVERS_JSON=${bad}`);
    });
  }
  withConfigEnv({ ICE_SERVERS_JSON: '[{"urls":["stun:stun.example.org:3478"]}]' }, () => {
    assert.deepEqual(loadConfig().iceServers, [{ urls: ['stun:stun.example.org:3478'] }]);
  });
});
