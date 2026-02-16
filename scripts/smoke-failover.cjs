#!/usr/bin/env node
/* eslint-disable no-console */
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const ecc = require('tiny-secp256k1');
const wrtc = require('wrtc');
const WS = require('ws');

global.RTCPeerConnection = wrtc.RTCPeerConnection;

function parseArgs(argv) {
  const out = {};
  for (let i = 2; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const k = a.slice(2);
    const v = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : true;
    out[k] = v;
    if (v !== true) i += 1;
  }
  return out;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

function canonicalize(v) {
  if (Array.isArray(v)) return v.map(canonicalize);
  if (v && typeof v === 'object' && Object.getPrototypeOf(v) === Object.prototype) {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = canonicalize(v[k]);
    return out;
  }
  return v;
}

function stableStringify(v) {
  return JSON.stringify(canonicalize(v));
}

function startCollator(port, dataDir) {
  const env = { ...process.env, PORT: String(port), DATA_DIR: dataDir };
  const proc = spawn(process.execPath, ['--enable-source-maps', 'dist/index.js'], {
    cwd: process.cwd(),
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let logs = '';
  proc.stdout.on('data', (d) => {
    logs += d.toString();
  });
  proc.stderr.on('data', (d) => {
    logs += d.toString();
  });
  // Ignore kill races (e.g., ESRCH after process already exited).
  proc.on('error', () => {});
  return { proc, getLogs: () => logs };
}

async function waitHealth(port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/health`);
      if (r.ok) return true;
    } catch {}
    await sleep(250);
  }
  return false;
}

async function connect(url, clientId, openTimeoutMs) {
  const ws = new WS(url);
  await new Promise((resolve, reject) => {
    const to = setTimeout(() => reject(new Error(`ws open timeout ${url}`)), openTimeoutMs);
    ws.on('open', () => {
      clearTimeout(to);
      resolve();
    });
    ws.on('error', (e) => {
      clearTimeout(to);
      reject(e);
    });
  });

  const pc = new RTCPeerConnection({
    iceServers: [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] }],
  });
  const dc = pc.createDataChannel('tl-bb', { ordered: true });
  const tapeEntries = [];
  const errs = [];

  ws.on('message', async (buf) => {
    try {
      const m = JSON.parse(String(buf));
      if (m.t === 'SIGNAL_ANSWER') {
        await pc.setRemoteDescription({ type: 'answer', sdp: m.sdp });
      } else if (m.t === 'SIGNAL_ICE') {
        try {
          await pc.addIceCandidate(m.candidate);
        } catch {}
      } else if (m.t === 'SIGNAL_ERR') {
        errs.push(`SIGNAL_ERR:${m.code}:${m.msg}`);
      }
    } catch {}
  });

  pc.onicecandidate = (ev) => {
    if (!ev.candidate) return;
    const c = typeof ev.candidate.toJSON === 'function'
      ? ev.candidate.toJSON()
      : {
          candidate: ev.candidate.candidate,
          sdpMid: ev.candidate.sdpMid,
          sdpMLineIndex: ev.candidate.sdpMLineIndex,
          usernameFragment: ev.candidate.usernameFragment,
        };
    ws.send(JSON.stringify({ t: 'SIGNAL_ICE', v: 1, candidate: c }));
  };

  dc.onmessage = (ev) => {
    try {
      const m = JSON.parse(typeof ev.data === 'string' ? ev.data : Buffer.from(ev.data).toString('utf8'));
      if (m.t === 'TAPE_ENTRY') tapeEntries.push(m.entry);
      else if (m.t === 'ERR') errs.push(`ERR:${m.code}:${m.msg}`);
    } catch {}
  };

  ws.send(JSON.stringify({ t: 'SIGNAL_HELLO', v: 1, clientId }));
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  ws.send(JSON.stringify({ t: 'SIGNAL_OFFER', v: 1, kind: 'offer', sdp: offer.sdp || '' }));

  await new Promise((resolve, reject) => {
    const to = setTimeout(() => reject(new Error(`dc open timeout ${url}`)), openTimeoutMs);
    dc.onopen = () => {
      clearTimeout(to);
      resolve();
    };
    dc.onerror = () => {
      clearTimeout(to);
      reject(new Error(`dc error ${url}`));
    };
  });

  dc.send(JSON.stringify({ t: 'HELLO', v: 1, clientId, want: ['TAPE', 'SUBMIT'] }));
  dc.send(JSON.stringify({ t: 'TAPE_SUB', v: 1 }));
  return { ws, pc, dc, tapeEntries, errs };
}

function buildOrder(seq) {
  const priv = Buffer.from('22'.repeat(32), 'hex');
  const pub = ecc.pointFromScalar(priv, true);
  if (!pub) throw new Error('invalid test private key');
  const traderPubKey = Buffer.from(pub).toString('hex');
  const body = {
    v: 1,
    market: 'SPOT:LTC/USDT',
    side: 'BUY',
    px: String(100 + seq),
    qty: '0.01',
    visibility: { kind: 'PUBLIC' },
    clientTs: Date.now(),
  };
  const clientNonce = crypto.randomBytes(16).toString('hex');
  const orderId = sha256Hex(stableStringify(body) + traderPubKey + clientNonce);
  const sig = ecc.sign(Buffer.from(orderId, 'hex'), priv);
  return {
    v: 1,
    kind: 'NEW',
    body,
    traderPubKey,
    clientNonce,
    orderId,
    sigTrader: Buffer.from(sig).toString('hex'),
  };
}

function closePeer(p) {
  try {
    p.dc.close();
  } catch {}
  try {
    p.pc.close();
  } catch {}
  try {
    p.ws.close();
  } catch {}
}

async function runOnce(cfg) {
  const a = startCollator(cfg.portA, cfg.dataDirA);
  const b = startCollator(cfg.portB, cfg.dataDirB);
  let pA = null;
  let pB = null;

  try {
    const upA = await waitHealth(cfg.portA, cfg.healthTimeoutMs);
    const upB = await waitHealth(cfg.portB, cfg.healthTimeoutMs);
    if (!upA || !upB) {
      throw new Error(
        `health check failed upA=${upA} upB=${upB} logsA=${a.getLogs().slice(-500)} logsB=${b.getLogs().slice(-500)}`
      );
    }

    pA = await connect(`ws://127.0.0.1:${cfg.portA}/ws`, `smoke-a-${Date.now()}`, cfg.openTimeoutMs);
    pB = await connect(`ws://127.0.0.1:${cfg.portB}/ws`, `smoke-b-${Date.now()}`, cfg.openTimeoutMs);

    await sleep(700);
    pA.dc.send(JSON.stringify({ t: 'SUBMIT', v: 1, order: buildOrder(1) }));
    await sleep(cfg.submitSettleMs);
    if (pA.tapeEntries.length < 1) {
      throw new Error(`primary submit no tape entries; errs=${pA.errs.join('|')}`);
    }

    a.proc.kill('SIGTERM');
    await sleep(cfg.failoverWaitMs);

    pB.dc.send(JSON.stringify({ t: 'SUBMIT', v: 1, order: buildOrder(2) }));
    await sleep(cfg.submitSettleMs);
    if (pB.tapeEntries.length < 1) {
      throw new Error(`backup submit no tape entries; errs=${pB.errs.join('|')}`);
    }

    console.log(
      JSON.stringify(
        {
          ok: true,
          primaryTape: pA.tapeEntries.length,
          backupTape: pB.tapeEntries.length,
          primaryErrors: pA.errs,
          backupErrors: pB.errs,
          ports: { primary: cfg.portA, backup: cfg.portB },
        },
        null,
        2
      )
    );
  } finally {
    if (pA) closePeer(pA);
    if (pB) closePeer(pB);
    try {
      a.proc.kill('SIGKILL');
    } catch {}
    try {
      b.proc.kill('SIGKILL');
    } catch {}
  }
}

async function main() {
  const args = parseArgs(process.argv);
  const cfg = {
    portA: Number(args['port-a'] || 8787),
    portB: Number(args['port-b'] || 8788),
    dataDirA: String(args['data-dir-a'] || '.\\data-8787-smoke'),
    dataDirB: String(args['data-dir-b'] || '.\\data-8788-smoke'),
    retries: Math.max(1, Number(args.retries || 3)),
    healthTimeoutMs: Math.max(1000, Number(args['health-timeout-ms'] || 15000)),
    openTimeoutMs: Math.max(1000, Number(args['open-timeout-ms'] || 20000)),
    submitSettleMs: Math.max(500, Number(args['submit-settle-ms'] || 2200)),
    failoverWaitMs: Math.max(500, Number(args['failover-wait-ms'] || 1800)),
  };

  let lastErr = null;
  for (let i = 1; i <= cfg.retries; i += 1) {
    try {
      if (i > 1) {
        console.log(`retry ${i}/${cfg.retries}`);
      }
      await runOnce(cfg);
      return;
    } catch (e) {
      lastErr = e;
      console.error(`attempt ${i} failed: ${e && e.message ? e.message : String(e)}`);
      await sleep(500);
    }
  }

  throw lastErr || new Error('smoke failover failed');
}

main().catch((e) => {
  console.error(`smoke_failover_fail: ${e && e.message ? e.message : String(e)}`);
  process.exit(1);
});
