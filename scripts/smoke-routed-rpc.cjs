#!/usr/bin/env node
/* eslint-disable no-console */
const { spawn } = require('node:child_process');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseArgs(argv) {
  const out = {};
  for (let i = 2; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2);
    const value = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : true;
    out[key] = value;
    if (value !== true) i += 1;
  }
  return out;
}

function listen(server, port = 0) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      server.off('error', reject);
      resolve(server.address().port);
    });
  });
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.setEncoding('utf8');
    req.on('data', (chunk) => {
      raw += chunk;
    });
    req.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : null);
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}

function writeJson(res, statusCode, body) {
  res.statusCode = statusCode;
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify(body));
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  const json = text ? JSON.parse(text) : null;
  if (!res.ok) {
    throw new Error(`${url} returned HTTP ${res.status}: ${text}`);
  }
  return json;
}

async function getJson(url) {
  const res = await fetch(url);
  const text = await res.text();
  const json = text ? JSON.parse(text) : null;
  if (!res.ok) {
    throw new Error(`${url} returned HTTP ${res.status}: ${text}`);
  }
  return json;
}

function startMockRpc() {
  const calls = [];
  const server = http.createServer((req, res) => {
    void (async () => {
      const body = req.method === 'POST' ? await readJson(req) : null;
      calls.push({ method: req.method, path: req.url, body });

      if (req.method !== 'POST') {
        writeJson(res, 405, { error: 'method not allowed' });
        return;
      }

      const rpcMethod = String(req.url || '/').replace(/^\/+/, '').split('?')[0];
      writeJson(res, 200, {
        source: 'mock-local-node',
        method: rpcMethod,
        params: body?.params ?? null,
        tip: { chain: 'LTCTEST', blocks: 123456 },
      });
    })().catch((e) => writeJson(res, 500, { error: e?.message || String(e) }));
  });
  return { server, calls };
}

function startChild(label, command, args, env) {
  const proc = spawn(command, args, {
    cwd: process.cwd(),
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let logs = '';
  proc.stdout.on('data', (d) => {
    const s = d.toString();
    logs += s;
    if (process.env.SMOKE_VERBOSE) process.stdout.write(`[${label}] ${s}`);
  });
  proc.stderr.on('data', (d) => {
    const s = d.toString();
    logs += s;
    if (process.env.SMOKE_VERBOSE) process.stderr.write(`[${label}] ${s}`);
  });
  proc.on('error', () => {});
  return { proc, logs: () => logs };
}

async function waitForHealth(port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const health = await getJson(`http://127.0.0.1:${port}/health`);
      if (health?.ok) return health;
    } catch {}
    await sleep(200);
  }
  throw new Error(`collator health timeout on ${port}`);
}

async function waitForProvider(port, service, network, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const out = await getJson(`http://127.0.0.1:${port}/rpc/providers`);
      const provider = (out.providers || []).find((p) =>
        (p.services || []).some((s) => s.service === service && (!network || s.network === network))
      );
      if (provider) return { out, provider };
    } catch {}
    await sleep(250);
  }
  throw new Error(`provider advertise timeout for ${service} ${network}`);
}

function killChild(child) {
  try {
    child?.proc?.kill('SIGTERM');
  } catch {}
}

async function main() {
  const args = parseArgs(process.argv);
  const service = String(args.service || 'tradelayer.rpc');
  const network = String(args.network || 'LTCTEST');
  const collatorPort = Number(args.port || 0);
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-collator-rpc-smoke-'));
  const mock = startMockRpc();
  let collator;
  let peer;

  try {
    const mockPort = await listen(mock.server, 0);
    const portServer = http.createServer((_, res) => writeJson(res, 404, { error: 'reserved' }));
    const port = collatorPort || await listen(portServer, 0);
    if (!collatorPort) {
      await new Promise((resolve) => portServer.close(resolve));
    }

    collator = startChild('collator', process.execPath, ['--enable-source-maps', 'dist/index.js'], {
      PORT: String(port),
      DATA_DIR: dataDir,
      ICE_SERVERS_JSON: '[]',
      TL_COLLATOR_RPC_SERVICE: service,
      TL_COLLATOR_RPC_NETWORK: network,
    });

    await waitForHealth(port, 15000);

    peer = startChild('rpc-peer', process.execPath, ['scripts/fullnode-rpc-peer.cjs'], {
      COLLATOR_WS: `ws://127.0.0.1:${port}/ws`,
      RPC_TARGET: `http://127.0.0.1:${mockPort}`,
      RPC_SERVICE: service,
      RPC_NETWORK: network,
      RPC_STYLE: 'path',
      RPC_METHODS_JSON: JSON.stringify(['tl_getinfo', 'getblockchaininfo', 'tl_getallbalancesforaddress']),
      ICE_SERVERS_JSON: '[]',
    });

    const advertised = await waitForProvider(port, service, network, 20000);

    const direct = await postJson(`http://127.0.0.1:${port}/rpc/route`, {
      service,
      network,
      method: 'tl_getinfo',
      params: [{ probe: 'direct-route' }],
      timeoutMs: 10000,
    });
    if (!direct.ok || direct.result?.source !== 'mock-local-node' || direct.result?.method !== 'tl_getinfo') {
      throw new Error(`direct /rpc/route did not return mock result: ${JSON.stringify(direct)}`);
    }

    const compat = await postJson(`http://127.0.0.1:${port}/relayer/rpc/tl_getallbalancesforaddress`, {
      params: ['tltc1qsmokeaddress'],
    });
    if (compat?.data?.source !== 'mock-local-node' || compat?.data?.method !== 'tl_getallbalancesforaddress') {
      throw new Error(`compat /relayer/rpc route did not return mock result: ${JSON.stringify(compat)}`);
    }

    console.log(JSON.stringify({
      ok: true,
      collator: `http://127.0.0.1:${port}`,
      websocket: `ws://127.0.0.1:${port}/ws`,
      mockLocalNode: `http://127.0.0.1:${mockPort}`,
      providerNodeId: advertised.provider.nodeId,
      directRoute: {
        ok: direct.ok,
        method: direct.result.method,
        providerNodeId: direct.providerNodeId,
      },
      compatRoute: {
        method: compat.data.method,
        params: compat.data.params,
      },
      mockCalls: mock.calls,
    }, null, 2));
  } catch (e) {
    console.error('smoke_routed_rpc_fail:', e?.stack || e?.message || String(e));
    if (collator) console.error(`collator_logs:\n${collator.logs().slice(-2000)}`);
    if (peer) console.error(`rpc_peer_logs:\n${peer.logs().slice(-2000)}`);
    process.exitCode = 1;
  } finally {
    killChild(peer);
    killChild(collator);
    await new Promise((resolve) => mock.server.close(resolve));
    try {
      fs.rmSync(dataDir, { recursive: true, force: true });
    } catch {}
  }
}

main();
