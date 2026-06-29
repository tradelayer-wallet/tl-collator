#!/usr/bin/env node
/* eslint-disable no-console */
const crypto = require('node:crypto');
const http = require('node:http');
const https = require('node:https');
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

function fetchCompat(url, options = {}) {
  if (typeof fetch === 'function') {
    return fetch(url, options);
  }

  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const transport = parsed.protocol === 'https:' ? https : http;
    const body = options.body == null ? undefined : Buffer.from(String(options.body));
    const headers = { ...(options.headers || {}) };
    if (body && !headers['content-length'] && !headers['Content-Length']) {
      headers['content-length'] = String(body.length);
    }

    const req = transport.request(parsed, {
      method: options.method || 'GET',
      headers,
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve({
          ok: res.statusCode >= 200 && res.statusCode < 300,
          status: res.statusCode,
          text: async () => text,
        });
      });
    });

    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function postJson(url, body, headers = {}) {
  const res = await fetchCompat(url, {
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

async function requestJson(method, url, body, headers = {}) {
  const res = await fetchCompat(url, {
    method,
    headers: { 'content-type': 'application/json', ...headers },
    body: method === 'GET' || method === 'HEAD' ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  const json = text ? JSON.parse(text) : null;
  if (!res.ok) {
    throw new Error(`${url} returned HTTP ${res.status}: ${text}`);
  }
  return json;
}

function asArray(value) {
  return Array.isArray(value) ? value : value == null ? [] : [value];
}

function firstObjectOrValue(params) {
  const values = asArray(params);
  const first = values[0];
  return first && typeof first === 'object' && !Array.isArray(first) ? first : { value: first, values };
}

function listenerRequestFor(req, target, walletTarget = target) {
  const method = String(req.method || '').trim();
  const normalized = method.toLowerCase();
  const params = asArray(req.params);
  const first = params[0];
  const shaped = firstObjectOrValue(params);

  const post = (path, body) => ({ method: 'POST', url: `${target}/${path}`, body });
  const walletRpc = (rpcMethod) => ({
    method: 'POST',
    url: `${walletTarget}/rpc/${rpcMethod}`,
    body: { params: req.params == null ? [] : req.params },
    internalRelay: true,
  });
  const get = (path, query) => {
    const url = new URL(`${target}/${path}`);
    for (const [key, value] of Object.entries(query || {})) {
      if (value !== undefined && value !== null && value !== '') url.searchParams.set(key, String(value));
    }
    return { method: 'GET', url: url.toString(), body: undefined };
  };

  const postMap = {
    getaddressinfo: () => walletRpc('getaddressinfo'),
    importpubkey: () => walletRpc('importpubkey'),
    listunspent: () => walletRpc('listunspent'),
    getblockchaininfo: () => walletRpc('getblockchaininfo'),
    validateaddress: () => walletRpc('validateaddress'),
    tl_getstatesnapshot: () => post('tl_getStateSnapshot', { label: shaped.label || shaped.value || undefined }),
    tl_getallbalancesforaddress: () => post('tl_getAllBalancesForAddress', { params: shaped.address || shaped.value }),
    tl_listproperties: () => post('tl_listProperties', {}),
    tl_getproperty: () => post('tl_getProperty', { params: shaped.propertyId || shaped.propid || shaped.id || shaped.value }),
    tl_getchannel: () => post('tl_getChannel', { params: shaped.channelAddress || shaped.address || shaped.value }),
    tl_getattestations: () => post('tl_getAttestations', {
      address: shaped.address || params[0],
      id: shaped.id ?? params[1],
    }),
    tl_getchannelcolumn: () => post('tl_getChannelColumn', {
      channelAddress: shaped.channelAddress || params[0],
      newCommitAddress: shaped.newCommitAddress || params[1],
      cpAddress: shaped.cpAddress || params[2],
    }),
    tl_gettransaction: () => post('tl_getTransaction', { txid: shaped.txid || shaped.value || params[0] }),
    tl_getclearlistbyid: () => post('tl_getClearlistById', { id: shaped.id ?? shaped.value ?? params[0] }),
    tl_getsyncstatus: () => post('tl_getSyncStatus', {}),
    tl_getinfo: () => post('tl_getSyncStatus', {}),
    tl_getbalance: () => post('tl_getAllBalancesForAddress', { params: shaped.address || shaped.value || params[0] }),
    tl_listcontractseries: () => post('tl_listContractSeries', { contractId: shaped.contractId ?? shaped.id ?? shaped.value }),
  };

  const getMap = {
    tl_getcontractinfo: () => get('tl_getContractInfo', { contractId: shaped.contractId ?? shaped.id ?? shaped.value }),
    tl_channelbalanceforcommiter: () => get('tl_channelBalanceForCommiter', {
      address: shaped.address || params[0],
      propertyId: shaped.propertyId ?? params[1],
    }),
    tl_getinitmargin: () => get('tl_getInitMargin', {
      contractId: shaped.contractId ?? params[0],
      price: shaped.price ?? params[1],
    }),
    tl_tokentradehistoryforaddress: () => get('tl_tokenTradeHistoryForAddress', {
      propertyId1: shaped.propertyId1 ?? params[0],
      propertyId2: shaped.propertyId2 ?? params[1],
      address: shaped.address || params[2],
    }),
    tl_contracttradehistoryforaddress: () => get('tl_contractTradeHistoryForAddress', {
      contractId: shaped.contractId ?? params[0],
      address: shaped.address || params[1] || params[2],
    }),
    tl_totaltradehistoryforaddress: () => get('tl_totalTradeHistoryForAddress', {
      address: shaped.address || shaped.value || params[0],
    }),
    tl_contractposition: () => get('tl_contractPosition', {
      address: shaped.address || params[0],
      contractId: shaped.contractId ?? params[1],
    }),
    tl_getmaxsynth: () => get('tl_getMaxSynth', {
      address: shaped.address || params[0],
      propId: shaped.propId ?? shaped.propertyId ?? params[1],
    }),
  };

  const factory = postMap[normalized] || getMap[normalized];
  if (factory) return factory();

  return post(String(method).replace(/^\/+/, ''), { params: req.params == null ? [] : req.params });
}

async function callUpstream(req) {
  const target = env('RPC_TARGET', 'http://127.0.0.1:3000').replace(/\/+$/, '');
  const walletTarget = env('RPC_WALLET_TARGET', 'http://127.0.0.1:1986').replace(/\/+$/, '');
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

  const routed = listenerRequestFor(req, target, walletTarget);
  const routedHeaders = routed.internalRelay
    ? { ...headers, 'x-tradelayer-internal-relay': '1' }
    : headers;
  const out = await requestJson(routed.method, routed.url, routed.body, routedHeaders);
  if (
    routed.internalRelay
    && out
    && typeof out === 'object'
    && Object.prototype.hasOwnProperty.call(out, 'data')
  ) {
    return out.data;
  }
  return out;
}

async function main() {
  const wsUrl = normalizeWsUrl(env('COLLATOR_WS', 'ws://127.0.0.1:8787/ws'));
  const clientId = env('RPC_CLIENT_ID', `rpc-peer-${Date.now()}`);
  const service = env('RPC_SERVICE', 'tradelayer.rpc');
  const network = env('RPC_NETWORK', 'bitcoin.testnet4');
  const methods = parseJson(process.env.RPC_METHODS_JSON, [
    'tl_getStateSnapshot',
  ]);
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

    const startedAt = Date.now();
    const rpcMethod = msg.req && msg.req.method ? String(msg.req.method) : '(unknown)';
    console.log(JSON.stringify({
      event: 'rpc-request',
      id: msg.req && msg.req.id,
      method: rpcMethod,
      network,
      nodeId: id,
    }));

    try {
      const result = await callUpstream(msg.req);
      console.log(JSON.stringify({
        event: 'rpc-reply',
        id: msg.req && msg.req.id,
        method: rpcMethod,
        ok: true,
        elapsedMs: Date.now() - startedAt,
        resultType: Array.isArray(result) ? 'array' : typeof result,
        resultCount: Array.isArray(result) ? result.length : undefined,
      }));
      dc.send(JSON.stringify({ t: 'RPC_RES', v: 1, res: { id: msg.req.id, ok: true, result } }));
    } catch (e) {
      console.log(JSON.stringify({
        event: 'rpc-reply',
        id: msg.req && msg.req.id,
        method: rpcMethod,
        ok: false,
        elapsedMs: Date.now() - startedAt,
        error: e && e.message ? e.message : String(e),
      }));
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
