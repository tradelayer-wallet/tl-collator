#!/usr/bin/env node
/* eslint-disable no-console */
const crypto = require('node:crypto');
const wrtc = require('wrtc');
const WS = require('ws');

global.RTCPeerConnection = wrtc.RTCPeerConnection;

function env(name, fallback) {
  return process.env[name] || fallback;
}

function parseJson(value, fallback) {
  if (!value) return fallback;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function normalizeWsUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) return raw;
  try {
    const url = new URL(raw);
    if (!url.pathname || url.pathname === '/') {
      url.pathname = '/ws';
    }
    return url.toString().replace(/\/+$/, '').replace(/\/ws$/, '/ws');
  } catch {
    return raw.endsWith('/ws') ? raw : `${raw.replace(/\/+$/, '')}/ws`;
  }
}

function nodeId() {
  return env('RPC_NODE_ID', `fullnode-${crypto.randomBytes(8).toString('hex')}`);
}

async function postJson(url, body, headers = {}) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  const json = text ? JSON.parse(text) : null;
  if (!res.ok) {
    throw new Error(`${url} returned HTTP ${res.status}: ${text}`);
  }
  return json;
}

async function callUpstream(req) {
  const target = env('RPC_TARGET', 'http://127.0.0.1:3000').replace(/\/+$/, '');
  const style = env('RPC_STYLE', 'path').toLowerCase();
  const user = process.env.RPC_USER;
  const pass = process.env.RPC_PASSWORD;
  const headers = {};

  if (user || pass) {
    headers.authorization = `Basic ${Buffer.from(`${user || ''}:${pass || ''}`).toString('base64')}`;
  }

  if (style === 'jsonrpc') {
    const body = {
      jsonrpc: '2.0',
      id: req.id,
      method: req.method,
      params: Array.isArray(req.params) ? req.params : req.params == null ? [] : [req.params],
    };
    const out = await postJson(target, body, headers);
    if (out && out.error) {
      throw new Error(out.error.message || JSON.stringify(out.error));
    }
    return out ? out.result : null;
  }

  const body = { params: req.params == null ? [] : req.params };
  return postJson(`${target}/${String(req.method).replace(/^\/+/, '')}`, body, headers);
}

async function main() {
  const wsUrl = normalizeWsUrl(env('COLLATOR_WS', 'ws://127.0.0.1:8787/ws'));
  const clientId = env('RPC_CLIENT_ID', `rpc-peer-${Date.now()}`);
  const service = env('RPC_SERVICE', 'tradelayer.rpc');
  const network = env('RPC_NETWORK', 'bitcoin.testnet4');
  const methods = parseJson(process.env.RPC_METHODS_JSON, []);
  const label = env('RPC_LABEL', 'local full-node RPC');
  const id = nodeId();

  const ws = new WS(wsUrl);
  await new Promise((resolve, reject) => {
    const to = setTimeout(() => reject(new Error(`ws open timeout ${wsUrl}`)), 15000);
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
    iceServers: parseJson(
      process.env.ICE_SERVERS_JSON,
      [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] }]
    ),
  });
  const dc = pc.createDataChannel('tl-bb', { ordered: true });

  ws.on('message', async (buf) => {
    const msg = JSON.parse(String(buf));
    if (msg.t === 'SIGNAL_ANSWER') {
      await pc.setRemoteDescription({ type: 'answer', sdp: msg.sdp });
    } else if (msg.t === 'SIGNAL_ICE') {
      try {
        await pc.addIceCandidate(msg.candidate);
      } catch {}
    } else if (msg.t === 'SIGNAL_ERR') {
      console.error(`SIGNAL_ERR ${msg.code}: ${msg.msg}`);
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

  dc.onmessage = async (ev) => {
    const msg = JSON.parse(typeof ev.data === 'string' ? ev.data : Buffer.from(ev.data).toString('utf8'));
    if (msg.t !== 'RPC_REQ') return;

    try {
      const result = await callUpstream(msg.req);
      dc.send(JSON.stringify({ t: 'RPC_RES', v: 1, res: { id: msg.req.id, ok: true, result } }));
    } catch (e) {
      dc.send(JSON.stringify({
        t: 'RPC_RES',
        v: 1,
        res: {
          id: msg.req.id,
          ok: false,
          error: { code: 'UPSTREAM_RPC_ERROR', message: e && e.message ? e.message : String(e) },
        },
      }));
    }
  };

  ws.send(JSON.stringify({ t: 'SIGNAL_HELLO', v: 1, clientId }));
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  ws.send(JSON.stringify({ t: 'SIGNAL_OFFER', v: 1, kind: 'offer', sdp: offer.sdp || '' }));

  await new Promise((resolve, reject) => {
    const to = setTimeout(() => reject(new Error('data channel open timeout')), 20000);
    dc.onopen = () => {
      clearTimeout(to);
      resolve();
    };
    dc.onerror = () => {
      clearTimeout(to);
      reject(new Error('data channel error'));
    };
  });

  dc.send(JSON.stringify({ t: 'HELLO', v: 1, clientId, want: ['RPC'] }));
  dc.send(JSON.stringify({
    t: 'RPC_ADVERTISE',
    v: 1,
    nodeId: id,
    services: [{ service, network, methods, label }],
  }));

  console.log(JSON.stringify({ ok: true, ws: wsUrl, nodeId: id, service, network, target: env('RPC_TARGET', 'http://127.0.0.1:3000') }, null, 2));
}

main().catch((e) => {
  console.error(e && e.stack ? e.stack : e);
  process.exit(1);
});
