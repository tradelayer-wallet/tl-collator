// Characterization of the SUBMIT admission checks (src/orderAdmission.ts). The WebRTC path that
// carries SUBMIT is not reachable under the e2e wrtc stub, so these cases call admitOrder directly
// against a real TapeStore.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

import { admitOrder } from '../dist/orderAdmission.js';
import { IpIntelClient, intelAdmits } from '../dist/ipIntel.js';
import { ClearlistClient } from '../dist/clearlist.js';
import { computeEnvelopeHash } from '../dist/canonical.js';
import { pubKeyFromPrivKeyHex, signWithPrivKeyHex } from '../dist/crypto.js';
import { TapeStore } from '../dist/tape.js';
import { PeerSession } from '../dist/peerSession.js';
import { KeyedTokenBuckets } from '../dist/ratelimit.js';

const TRADER_A = '11'.repeat(32);
const TRADER_B = '22'.repeat(32);
const COLLATOR = '33'.repeat(32);
const NO_POLICY = { vpnFilterMode: 'off', asnBlockMode: 'off', asnBlocklist: [], clearlistEnforce: false, clearlistFailMode: 'closed' };

// A correctly signed envelope; `fields` are part of the signed envelope, `signer` signs it.
function signed(fields = {}, signer = TRADER_A) {
  const env = {
    v: 1,
    kind: 'NEW',
    body: { v: 1, market: 'SPOT:LTC/TL', side: 'BUY', px: '1', qty: '1', visibility: { kind: 'PUBLIC' }, clientTs: 1 },
    traderPubKey: pubKeyFromPrivKeyHex(TRADER_A),
    clientNonce: '01',
    ...fields,
  };
  if (signer !== TRADER_A) env.traderPubKey = pubKeyFromPrivKeyHex(signer);
  const orderId = computeEnvelopeHash(env);
  return { ...env, orderId, sigTrader: signWithPrivKeyHex(orderId, signer) };
}

function openTape() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-admission-'));
  const tape = new TapeStore({
    tapePath: path.join(dir, 'tape.log'),
    idxPath: path.join(dir, 'tape.idx'),
    idxStride: 4,
    replayBatch: 8,
    maxReplayEntries: 1000,
    collatorId: 'collator-test',
    collatorPrivKeyHex: COLLATOR,
  });
  return { tape, dir };
}

const meta = (remoteIp = '198.51.100.7') => ({ ...(remoteIp ? { remoteIp } : {}), firstSeenTs: 0, lastSeenTs: 0 });

// Intel stub: records lookups; `answer` is a verdict object or an Error to throw.
function intelStub(answer) {
  const calls = [];
  return {
    calls,
    lookup: async (ip) => {
      calls.push(ip);
      if (answer instanceof Error) throw answer;
      return answer;
    },
  };
}

function clearlistStub(answer) {
  const calls = [];
  return {
    calls,
    check: async (groupId, pubkeyHex) => {
      calls.push([groupId, pubkeyHex]);
      if (answer instanceof Error) throw answer;
      return answer;
    },
  };
}

async function refusalOf(policy, sources, m, order) {
  const r = await admitOrder(policy, sources, m, order);
  return r === null ? null : r.code;
}

test('admission: a well-formed NEW is admitted with no policy configured', async () => {
  const { tape, dir } = openTape();
  try {
    assert.equal(await refusalOf(NO_POLICY, { tape, intel: null, clearlist: null }, meta(), signed()), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('admission: an orderId already on the tape is a DUPLICATE, checked before the signature', async () => {
  const { tape, dir } = openTape();
  try {
    const order = signed();
    assert.ok(tape.append(order));
    const tampered = { ...order, sigTrader: '00'.repeat(64) };
    const r = await admitOrder(NO_POLICY, { tape, intel: null, clearlist: null }, meta(), tampered);
    assert.deepEqual(r, { code: 'DUPLICATE', msg: 'orderId already seen' });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('admission: a signature by another key is bad_sig', async () => {
  const { tape, dir } = openTape();
  try {
    const order = signed({}, TRADER_B);
    const forged = { ...order, traderPubKey: pubKeyFromPrivKeyHex(TRADER_A) };
    assert.equal(await refusalOf(NO_POLICY, { tape, intel: null, clearlist: null }, meta(), forged), 'bad_sig');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('admission: an orderId that is not the envelope derivation is bad_order_id', async () => {
  const { tape, dir } = openTape();
  try {
    const order = signed();
    const edited = { ...order, body: { ...order.body, qty: '2' } };
    assert.equal(await refusalOf(NO_POLICY, { tape, intel: null, clearlist: null }, meta(), edited), 'bad_order_id');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('admission: a CANCEL needs a target, a known target, and the target owner', async () => {
  const { tape, dir } = openTape();
  try {
    const sources = { tape, intel: null, clearlist: null };
    const owned = signed();
    assert.ok(tape.append(owned));
    const noTarget = signed({ kind: 'CANCEL' });
    assert.deepEqual(await admitOrder(NO_POLICY, sources, meta(), noTarget), {
      code: 'SCHEMA_INVALID',
      msg: 'missing cancelsOrderId',
    });
    const unknown = signed({ kind: 'CANCEL', cancelsOrderId: 'ab'.repeat(32) });
    assert.deepEqual(await admitOrder(NO_POLICY, sources, meta(), unknown), {
      code: 'UNKNOWN_ORDER',
      msg: 'cancelsOrderId not found',
    });
    const byOther = signed({ kind: 'CANCEL', cancelsOrderId: owned.orderId }, TRADER_B);
    assert.deepEqual(await admitOrder(NO_POLICY, sources, meta(), byOther), {
      code: 'NOT_OWNER',
      msg: 'cannot cancel other trader order',
    });
    const byOwner = signed({ kind: 'CANCEL', cancelsOrderId: owned.orderId });
    assert.equal(await admitOrder(NO_POLICY, sources, meta(), byOwner), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('admission: a REPLACE needs a target, a known target, and the target owner', async () => {
  const { tape, dir } = openTape();
  try {
    const sources = { tape, intel: null, clearlist: null };
    const owned = signed();
    assert.ok(tape.append(owned));
    assert.deepEqual(await admitOrder(NO_POLICY, sources, meta(), signed({ kind: 'REPLACE' })), {
      code: 'SCHEMA_INVALID',
      msg: 'missing replacesOrderId',
    });
    assert.deepEqual(await admitOrder(NO_POLICY, sources, meta(), signed({ kind: 'REPLACE', replacesOrderId: 'cd'.repeat(32) })), {
      code: 'UNKNOWN_ORDER',
      msg: 'replacesOrderId not found',
    });
    assert.deepEqual(await admitOrder(NO_POLICY, sources, meta(), signed({ kind: 'REPLACE', replacesOrderId: owned.orderId }, TRADER_B)), {
      code: 'NOT_OWNER',
      msg: 'cannot replace other trader order',
    });
    assert.equal(await admitOrder(NO_POLICY, sources, meta(), signed({ kind: 'REPLACE', replacesOrderId: owned.orderId })), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('admission: a VPN verdict refuses only in reject mode, and records the verdict on the session', async () => {
  const { tape, dir } = openTape();
  try {
    const reject = { ...NO_POLICY, vpnFilterMode: 'reject' };
    const m = meta();
    const intel = intelStub({ vpn: true });
    assert.deepEqual(await admitOrder(reject, { tape, intel, clearlist: null }, m, signed()), {
      code: 'VPN_BLOCKED',
      msg: 'vpn traffic rejected',
    });
    assert.equal(m.vpn, true);
    assert.deepEqual(intel.calls, ['198.51.100.7']);
    const logOnly = { ...NO_POLICY, vpnFilterMode: 'log' };
    assert.equal(await admitOrder(logOnly, { tape, intel: intelStub({ vpn: true }), clearlist: null }, meta(), signed()), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('admission: an ASN on the blocklist refuses only in reject mode', async () => {
  const { tape, dir } = openTape();
  try {
    const blockReject = { ...NO_POLICY, asnBlockMode: 'reject', asnBlocklist: [64500] };
    assert.deepEqual(await admitOrder(blockReject, { tape, intel: intelStub({ asn: 64500 }), clearlist: null }, meta(), signed()), {
      code: 'ASN_BLOCKED',
      msg: 'asn blocked',
    });
    assert.equal(await admitOrder(blockReject, { tape, intel: intelStub({ asn: 64501 }), clearlist: null }, meta(), signed()), null);
    const blockLog = { ...blockReject, asnBlockMode: 'log' };
    assert.equal(await admitOrder(blockLog, { tape, intel: intelStub({ asn: 64500 }), clearlist: null }, meta(), signed()), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('admission: in a reject mode a failed intel lookup or a missing client IP refuses; log modes admit', async () => {
  const { tape, dir } = openTape();
  try {
    const reject = { ...NO_POLICY, vpnFilterMode: 'reject' };
    const failing = intelStub(new Error('upstream down'));
    assert.equal(
      await refusalOf(reject, { tape, intel: failing, clearlist: null }, meta(), signed()),
      'INTEL_UNAVAILABLE',
    );
    const noIp = intelStub({ vpn: false });
    assert.equal(await refusalOf(reject, { tape, intel: noIp, clearlist: null }, meta(''), signed()), 'INTEL_UNAVAILABLE');
    assert.equal(noIp.calls.length, 0);
    const logOnly = { ...NO_POLICY, vpnFilterMode: 'log' };
    assert.equal(await refusalOf(logOnly, { tape, intel: intelStub(new Error('down')), clearlist: null }, meta(), signed()), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('admission: a clearlist-gated order is checked with its group and trader key; closed fails closed, open admits', async () => {
  const { tape, dir } = openTape();
  try {
    const gated = { ...NO_POLICY, clearlistEnforce: true };
    const dark = signed({ body: { v: 1, market: 'SPOT:LTC/TL', side: 'BUY', px: '1', qty: '1', visibility: { kind: 'DARK', groupId: 'g1' }, clientTs: 1 } });
    const notListed = clearlistStub({ allowed: false });
    assert.deepEqual(await admitOrder(gated, { tape, intel: null, clearlist: notListed }, meta(), dark), {
      code: 'NOT_CLEARLISTED',
      msg: 'not clearlisted',
    });
    assert.deepEqual(notListed.calls, [['g1', dark.traderPubKey]]);
    assert.equal(await admitOrder(gated, { tape, intel: null, clearlist: clearlistStub({ allowed: true }) }, meta(), dark), null);
    assert.equal(
      await refusalOf(gated, { tape, intel: null, clearlist: clearlistStub(new Error('down')) }, meta(), dark),
      'CLEARLIST_DOWN',
    );
    const open = { ...gated, clearlistFailMode: 'open' };
    assert.equal(await admitOrder(open, { tape, intel: null, clearlist: clearlistStub(new Error('down')) }, meta(), dark), null);
    const probe = clearlistStub({ allowed: false });
    assert.equal(await admitOrder(gated, { tape, intel: null, clearlist: probe }, meta(), signed()), null);
    assert.equal(probe.calls.length, 0, 'a PUBLIC order is not checked against the clearlist');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- intel verdicts

const VPN_REJECT = { ...NO_POLICY, vpnFilterMode: 'reject' };
const ASN_REJECT = { ...NO_POLICY, asnBlockMode: 'reject', asnBlocklist: [64500] };

test('intel: an admitting verdict carries every field a reject mode reads', () => {
  assert.equal(intelAdmits(VPN_REJECT, { vpn: false }), true);
  assert.equal(intelAdmits(VPN_REJECT, { asn: 64500 }), false, 'a vpn reject admitted a verdict with no vpn field');
  assert.equal(intelAdmits(ASN_REJECT, { vpn: false }), false, 'an asn reject admitted a verdict with no asn field');
  assert.equal(intelAdmits(ASN_REJECT, { asn: 64501 }), true);
  assert.equal(intelAdmits(VPN_REJECT, null), false);
  assert.equal(intelAdmits({ ...NO_POLICY, asnBlockMode: 'reject' }, null), true, 'an empty ASN list needs no verdict');
  assert.equal(intelAdmits({ ...NO_POLICY, vpnFilterMode: 'log', asnBlockMode: 'log', asnBlocklist: [64500] }, null), true);
});

test('intel: the client keeps asn and vpn only when they have the documented types', async () => {
  let body = null;
  const server = http.createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(body));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const client = new IpIntelClient({ url: `http://127.0.0.1:${server.address().port}/intel`, ttlSec: 0, max: 10 });
  try {
    body = { asn: null, vpn: 'yes' };
    assert.deepEqual(await client.lookup('198.51.100.1'), { asn: undefined, vpn: undefined });
    body = { asn: '64500', vpn: 1 };
    assert.deepEqual(await client.lookup('198.51.100.2'), { asn: undefined, vpn: undefined });
    body = { asn: 0, vpn: false };
    assert.deepEqual(await client.lookup('198.51.100.3'), { asn: undefined, vpn: false });
    body = { asn: 64500, vpn: true };
    assert.deepEqual(await client.lookup('198.51.100.4'), { asn: 64500, vpn: true });
  } finally {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
  }
});

test('intel: an incomplete verdict refuses in a reject mode, through the admission path', async () => {
  const { tape, dir } = openTape();
  try {
    assert.equal(await refusalOf(VPN_REJECT, { tape, intel: intelStub({}), clearlist: null }, meta(), signed()), 'INTEL_UNAVAILABLE');
    assert.equal(await refusalOf(ASN_REJECT, { tape, intel: intelStub({ vpn: false }), clearlist: null }, meta(), signed()), 'INTEL_UNAVAILABLE');
    assert.equal(await refusalOf(ASN_REJECT, { tape, intel: intelStub({ asn: null }), clearlist: null }, meta(), signed()), 'INTEL_UNAVAILABLE');
    const logOnly = { ...NO_POLICY, asnBlockMode: 'log', asnBlocklist: [64500] };
    assert.equal(await refusalOf(logOnly, { tape, intel: intelStub({ vpn: false }), clearlist: null }, meta(), signed()), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('intel: a reject mode with no intel source refuses rather than admitting unchecked', async () => {
  const { tape, dir } = openTape();
  try {
    assert.equal(await refusalOf(VPN_REJECT, { tape, intel: null, clearlist: null }, meta(), signed()), 'INTEL_UNAVAILABLE');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- clearlist cache

test('clearlist: the verdict cache is bounded; the least recently used key is re-asked', async () => {
  let hits = 0;
  const server = http.createServer((req, res) => {
    hits += 1;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ allowed: true }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const client = new ClearlistClient({ baseUrl: `http://127.0.0.1:${server.address().port}`, max: 2 });
  try {
    await client.check('g', 'aa');
    await client.check('g', 'bb');
    await client.check('g', 'cc');
    assert.equal(hits, 3);
    await client.check('g', 'cc');
    assert.equal(hits, 3, 'a recent key was served from the cache');
    await client.check('g', 'aa');
    assert.equal(hits, 4, 'the evicted key was not re-asked: the cache grew past its bound');
  } finally {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
  }
});

test('admission: a trader key or order reference in upper-case hex names the same trader and order', async () => {
  const { tape, dir } = openTape();
  try {
    const sources = { tape, intel: null, clearlist: clearlistStub({ allowed: true }) };
    const upperKey = pubKeyFromPrivKeyHex(TRADER_A).toUpperCase();
    const owned = signed({ traderPubKey: upperKey });
    assert.ok(tape.append(owned));
    const cancel = signed({ kind: 'CANCEL', cancelsOrderId: owned.orderId.toUpperCase() });
    assert.equal(await admitOrder(NO_POLICY, sources, meta(), cancel), null, 'an honest cancel was refused');
    const gated = { ...NO_POLICY, clearlistEnforce: true };
    const groupOrder = signed({ traderPubKey: upperKey, body: { v: 1, market: 'SPOT:LTC/TL', side: 'BUY', px: '1', qty: '1', visibility: { kind: 'CLEARLIST', groupId: 'g1' }, clientTs: 2 } });
    await admitOrder(gated, sources, meta(), groupOrder);
    assert.deepEqual(sources.clearlist.calls, [['g1', upperKey.toLowerCase()]], 'the clearlist was asked about a differently spelled key');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- TAPE_SUB replay cost

test('tape: sessions behind one client share one replay budget; another client is not affected', () => {
  // Generous open budgets, so only the replay bucket can refuse. Each session asks once.
  const opens = new KeyedTokenBuckets({ capacity: 1000, refillPerSec: 1000, maxKeys: 100 });
  const tape = new KeyedTokenBuckets({ capacity: 4, refillPerSec: 0.001, maxKeys: 100 });
  const session = (id) => new PeerSession({ id, ws: {}, burst: 100, ratePerSec: 100, openBurst: 100, openRatePerSec: 100, remoteIp: '198.51.100.7' });
  const key = 'ip:198.51.100.7';
  let admitted = 0;
  for (let i = 0; i < 16; i++) if (session(`s${i}`).admitTapeSub(opens, tape, key)) admitted++;
  assert.equal(admitted, 4, `16 sessions of one client started ${admitted} replays; the client bucket allows 4`);
  assert.equal(session('other').admitTapeSub(opens, tape, 'ip:203.0.113.9'), true, 'another client was refused');
});

// ---------------------------------------------------------------- SUBMIT rate

test('submit: sessions of one client share one SUBMIT budget; another client is not affected', () => {
  const clients = new KeyedTokenBuckets({ capacity: 2, refillPerSec: 0.001, maxKeys: 100 });
  const session = (id) => new PeerSession({ id, ws: {}, burst: 100, ratePerSec: 100, openBurst: 4, openRatePerSec: 3, remoteIp: '198.51.100.7' });
  const a = session('a');
  const b = session('b');
  assert.equal(a.admitSubmit(clients, 'ip:198.51.100.7'), true);
  assert.equal(a.admitSubmit(clients, 'ip:198.51.100.7'), true);
  assert.equal(b.admitSubmit(clients, 'ip:198.51.100.7'), false, 'a second session multiplied the client budget');
  assert.equal(b.admitSubmit(clients, 'ip:203.0.113.9'), true);
});
