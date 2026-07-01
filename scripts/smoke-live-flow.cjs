#!/usr/bin/env node
/* eslint-disable no-console */
const crypto = require('node:crypto');
const http = require('node:http');
const https = require('node:https');
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
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function requestJson(method, url, body, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const transport = parsed.protocol === 'https:' ? https : http;
    const raw = body == null ? undefined : Buffer.from(JSON.stringify(body));
    const req = transport.request(parsed, {
      method,
      headers: {
        accept: 'application/json',
        ...(raw ? { 'content-type': 'application/json', 'content-length': String(raw.length) } : {}),
      },
      timeout: timeoutMs,
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try {
          json = text ? JSON.parse(text) : null;
        } catch {
          json = text;
        }
        if (res.statusCode < 200 || res.statusCode >= 300) {
          const error = new Error(`${method} ${url} returned HTTP ${res.statusCode}: ${text}`);
          error.statusCode = res.statusCode;
          error.body = json;
          reject(error);
          return;
        }
        resolve(json);
      });
    });
    req.on('timeout', () => {
      req.destroy(new Error(`${method} ${url} timed out after ${timeoutMs}ms`));
    });
    req.on('error', reject);
    if (raw) req.write(raw);
    req.end();
  });
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

async function waitForProvider(baseUrl, service, network, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < deadline) {
    try {
      const out = await requestJson('GET', `${baseUrl}/rpc/providers`, null, 10000);
      last = out;
      const provider = (out.providers || []).find((p) =>
        (p.services || []).some((s) => s.service === service && (!network || s.network === network))
      );
      if (provider) return { provider, providers: out.providers || [] };
    } catch (e) {
      last = { error: e.message };
    }
    await sleep(1000);
  }
  throw new Error(`provider timeout for ${service} ${network}; last=${JSON.stringify(last)}`);
}

async function routeRpc(baseUrl, service, network, method, params, timeoutMs) {
  return requestJson('POST', `${baseUrl}/rpc/route`, {
    service,
    network,
    method,
    params,
    timeoutMs,
    sourceEndpoint: 'smoke-live-flow',
  }, timeoutMs + 5000);
}

async function connectTape(wsUrl, clientId, timeoutMs) {
  const ws = new WS(wsUrl);
  await new Promise((resolve, reject) => {
    const to = setTimeout(() => reject(new Error(`ws open timeout ${wsUrl}`)), timeoutMs);
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
  const errors = [];

  ws.on('message', async (buf) => {
    try {
      const msg = JSON.parse(String(buf));
      if (msg.t === 'SIGNAL_ANSWER') {
        await pc.setRemoteDescription({ type: 'answer', sdp: msg.sdp });
      } else if (msg.t === 'SIGNAL_ICE') {
        try { await pc.addIceCandidate(msg.candidate); } catch {}
      } else if (msg.t === 'SIGNAL_ERR') {
        errors.push(`SIGNAL_ERR:${msg.code}:${msg.msg}`);
      }
    } catch (e) {
      errors.push(`SIGNAL_PARSE:${e.message}`);
    }
  });

  pc.onicecandidate = (ev) => {
    if (!ev.candidate) return;
    const candidate = typeof ev.candidate.toJSON === 'function'
      ? ev.candidate.toJSON()
      : {
          candidate: ev.candidate.candidate,
          sdpMid: ev.candidate.sdpMid,
          sdpMLineIndex: ev.candidate.sdpMLineIndex,
          usernameFragment: ev.candidate.usernameFragment,
        };
    ws.send(JSON.stringify({ t: 'SIGNAL_ICE', v: 1, candidate }));
  };

  dc.onmessage = (ev) => {
    try {
      const msg = JSON.parse(typeof ev.data === 'string' ? ev.data : Buffer.from(ev.data).toString('utf8'));
      if (msg.t === 'TAPE_ENTRY') tapeEntries.push(msg.entry);
      if (msg.t === 'ERR') errors.push(`ERR:${msg.code}:${msg.msg}`);
    } catch (e) {
      errors.push(`DC_PARSE:${e.message}`);
    }
  };

  ws.send(JSON.stringify({ t: 'SIGNAL_HELLO', v: 1, clientId }));
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  ws.send(JSON.stringify({ t: 'SIGNAL_OFFER', v: 1, kind: 'offer', sdp: offer.sdp || '' }));

  await new Promise((resolve, reject) => {
    const to = setTimeout(() => reject(new Error('data channel open timeout')), timeoutMs);
    dc.onopen = () => {
      clearTimeout(to);
      resolve();
    };
    dc.onerror = () => {
      clearTimeout(to);
      reject(new Error('data channel error'));
    };
  });

  dc.send(JSON.stringify({ t: 'HELLO', v: 1, clientId, want: ['TAPE', 'SUBMIT'] }));
  dc.send(JSON.stringify({ t: 'TAPE_SUB', v: 1, fromSeq: 1 }));
  return { ws, pc, dc, tapeEntries, errors };
}

function closePeer(peer) {
  try { peer.dc.close(); } catch {}
  try { peer.pc.close(); } catch {}
  try { peer.ws.close(); } catch {}
}

function buildOrder(market, side, px, qty) {
  const priv = Buffer.from('22'.repeat(32), 'hex');
  const pub = ecc.pointFromScalar(priv, true);
  if (!pub) throw new Error('invalid smoke private key');
  const traderPubKey = Buffer.from(pub).toString('hex');
  const body = {
    v: 1,
    market,
    side,
    px,
    qty,
    tif: 'GTC',
    visibility: { kind: 'PUBLIC' },
    clientTs: Date.now(),
  };
  const clientNonce = crypto.randomBytes(16).toString('hex');
  const orderId = sha256Hex(stableStringify(body) + traderPubKey + clientNonce);
  const sigTrader = Buffer.from(ecc.sign(Buffer.from(orderId, 'hex'), priv)).toString('hex');
  return { v: 1, kind: 'NEW', body, traderPubKey, clientNonce, orderId, sigTrader };
}

async function waitForOrderEcho(peer, orderId, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const entry = peer.tapeEntries.find((e) => e?.order?.orderId === orderId);
    if (entry) return entry;
    if (peer.errors.length) throw new Error(`order submit error: ${peer.errors.join('|')}`);
    await sleep(250);
  }
  throw new Error(`order ${orderId} was not echoed on tape within ${timeoutMs}ms`);
}

async function main() {
  const args = parseArgs(process.argv);
  const collatorHttp = String(args['collator-http'] || process.env.COLLATOR_HTTP || 'https://testnet-api.layerwallet.com').replace(/\/+$/, '');
  const collatorWs = String(args['collator-ws'] || process.env.COLLATOR_WS || 'wss://testnet-api.layerwallet.com/ws');
  const service = String(args.service || process.env.RPC_SERVICE || 'tradelayer.rpc');
  const network = String(args.network || process.env.RPC_NETWORK || 'litecoin.testnet');
  const address = String(args.address || process.env.TL_SMOKE_ADDRESS || 'tltc1qjqaxx2nsmdc26pvjkyn6mrs0dvcqy9kaschwcl');
  const timeoutMs = Math.max(5000, Number(args.timeoutMs || args.timeout || 30000));
  const market = String(args.market || 'SPOT:5/0');
  const orderbookOnly = args['orderbook-only'] === true || String(args['orderbook-only'] || '').toLowerCase() === 'true';
  const provider = orderbookOnly
    ? { provider: { nodeId: null }, providers: [] }
    : await waitForProvider(collatorHttp, service, network, timeoutMs);

  let attestation = null;
  let commitPayload = null;

  if (!orderbookOnly) {
    attestation = await routeRpc(collatorHttp, service, network, 'tl_getattestations', [address, 0], timeoutMs);
    if (!attestation.ok) throw new Error(`attestation route failed: ${JSON.stringify(attestation)}`);

    commitPayload = await routeRpc(collatorHttp, service, network, 'tl_createpayload_commit_tochannel', [{
      propertyId: 5,
      amount: 0.000001,
      channelAddress: address,
      payEnabled: false,
      clearLists: [],
      isColoredOutput: false,
    }], timeoutMs);
    if (!commitPayload.ok) throw new Error(`commit payload route failed: ${JSON.stringify(commitPayload)}`);
  }

  const orderPeer = await connectTape(collatorWs, `smoke-live-order-${Date.now()}`, timeoutMs);
  let orderEntry;
  try {
    const order = buildOrder(market, 'BUY', '1.00000000', '0.00000100');
    orderPeer.dc.send(JSON.stringify({ t: 'SUBMIT', v: 1, order }));
    orderEntry = await waitForOrderEcho(orderPeer, order.orderId, timeoutMs);
  } finally {
    closePeer(orderPeer);
  }

  console.log(JSON.stringify({
    ok: true,
    collatorHttp,
    collatorWs,
    service,
    network,
    providerNodeId: provider.provider.nodeId,
    advertisedProviders: provider.providers.length,
    attestation: attestation ? {
      ok: attestation.ok,
      providerNodeId: attestation.providerNodeId || null,
      resultType: Array.isArray(attestation.result) ? 'array' : typeof attestation.result,
      resultCount: Array.isArray(attestation.result) ? attestation.result.length : undefined,
    } : null,
    commitPayload: commitPayload ? {
      ok: commitPayload.ok,
      providerNodeId: commitPayload.providerNodeId || null,
      resultType: typeof commitPayload.result,
      resultPreview: typeof commitPayload.result === 'string'
        ? commitPayload.result.slice(0, 80)
        : commitPayload.result,
    } : null,
    orderbook: {
      submittedOrderId: orderEntry.order.orderId,
      echoedSeq: orderEntry.seq,
      market: orderEntry.order.body.market,
      side: orderEntry.order.body.side,
    },
  }, null, 2));
  process.exitCode = 0;
  setTimeout(() => process.exit(0), 50);
}

main().catch((e) => {
  console.error(`smoke_live_flow_fail: ${e && e.stack ? e.stack : e}`);
  process.exit(1);
});
