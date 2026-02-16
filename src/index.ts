import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { WebSocketServer } from 'ws';
import wrtc from 'wrtc';

import { loadConfig } from './config.js';
import type { SignalMsg, WireMsg } from './types.js';
import { verifyTraderSig, ensurePrivKeyHex, pubKeyFromPrivKeyHex, sha256Hex } from './crypto.js';
import { TapeStore } from './tape.js';
import { PeerSession } from './peerSession.js';
import { isWireMsg } from './validate.js';
import { LruSet } from './lru.js';
import { ClearlistClient } from './clearlist.js';
import { loadValidators } from './schema.js';
import { buildManifest } from './manifest.js';
import { IpIntelClient } from './ipIntel.js';
import { AuditLog } from './auditLog.js';

function randId(): string {
  return Math.random().toString(16).slice(2) + Math.random().toString(16).slice(2);
}

function safeJsonParse(s: string): any | null {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}

async function main() {
  const cfg = loadConfig();
  const schemas = loadValidators();
  const startedAt = Date.now();

  // Load/generate collator key.
  let privHex: string;
  if (fs.existsSync(cfg.collatorKeyPath)) privHex = ensurePrivKeyHex(fs.readFileSync(cfg.collatorKeyPath, 'utf8'));
  else {
    privHex = ensurePrivKeyHex(null);
    fs.mkdirSync(path.dirname(cfg.collatorKeyPath), { recursive: true });
    fs.writeFileSync(cfg.collatorKeyPath, privHex, 'utf8');
  }
  const pubHex = pubKeyFromPrivKeyHex(privHex);
  const collatorId = sha256Hex(pubHex);

  const manifest = buildManifest(cfg, { collatorId, collatorPubKey: pubHex, collatorPrivKeyHex: privHex });

  const tape = new TapeStore({
    tapePath: cfg.tapePath,
    idxPath: cfg.idxPath,
    idxStride: cfg.idxStride,
    replayBatch: cfg.replayBatch,
    collatorId,
    collatorPrivKeyHex: privHex,
  });
  const seen = new LruSet(Number(process.env.SEEN_ORDERIDS_MAX || 100000));
  const clearlist = cfg.clearlistEnforce && cfg.clearlistUrl ? new ClearlistClient({ baseUrl: cfg.clearlistUrl }) : null;
  const ipIntel = cfg.ipIntelUrl ? new IpIntelClient({ url: cfg.ipIntelUrl, ttlSec: cfg.ipIntelTtlSec, max: 5000 }) : null;
  const audit = new AuditLog(cfg.ipLogging === 'on' ? path.join(cfg.dataDir, 'audit.log') : null);

  const server = cfg.tlsKeyPath && cfg.tlsCertPath
    ? https.createServer({
        key: fs.readFileSync(cfg.tlsKeyPath),
        cert: fs.readFileSync(cfg.tlsCertPath),
      })
    : http.createServer();

  server.on('request', (req, res) => {
    try {
      const u = new URL(req.url || '/', `http://${req.headers.host || '127.0.0.1'}`);

      // Basic CORS for web clients.
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'content-type');
      if (req.method === 'OPTIONS') {
        res.statusCode = 204;
        res.end();
        return;
      }

      if (req.method === 'GET' && u.pathname === '/health') {
        res.setHeader('content-type', 'application/json');
        res.statusCode = 200;
        res.end(JSON.stringify({ ok: true, collatorId, uptimeSec: Math.floor((Date.now() - startedAt) / 1000) }));
        return;
      }

      if (req.method === 'GET' && u.pathname === '/manifest') {
        res.setHeader('content-type', 'application/json');
        res.statusCode = 200;
        res.end(JSON.stringify(manifest));
        return;
      }

      res.statusCode = 404;
      res.end('not found');
    } catch {
      res.statusCode = 500;
      res.end('internal error');
    }
  });

  const wss = new WebSocketServer({ server, path: cfg.wsPath, maxPayload: cfg.maxMsgBytes });
  const sessions = new Map<string, PeerSession>();
  const peers = new Set<PeerSession>();

  wss.on('connection', (ws, req) => {
    if (typeof cfg.connMax === 'number' && cfg.connMax >= 0 && peers.size >= cfg.connMax) {
      try {
        ws.close(1013, 'server busy');
      } catch {}
      return;
    }

    const id = `peer-${randId()}`;
    const remoteIp = (req as any)?.socket?.remoteAddress ? String((req as any).socket.remoteAddress) : undefined;
    const userAgent = req?.headers?.['user-agent'] ? String(req.headers['user-agent']) : undefined;
    const sess = new PeerSession({ id, ws, burst: cfg.submitBurst, ratePerSec: cfg.submitRatePerSec, remoteIp, userAgent });
    sessions.set(id, sess);
    peers.add(sess);

    let pc: any = null;

    const sendSignal = (m: SignalMsg) => {
      if (ws.readyState !== ws.OPEN) return;
      ws.send(JSON.stringify(m));
    };

    const cleanup = async () => {
      try {
        sess.dc?.close();
      } catch {}
      sess.dc = null;
      try {
        pc?.close?.();
      } catch {}
      pc = null;
      sessions.delete(id);
      peers.delete(sess);
    };

    ws.on('close', () => void cleanup());
    ws.on('error', () => void cleanup());

    ws.on('message', async (buf) => {
      if (typeof buf !== 'string' && !(buf instanceof Buffer)) return;
      const raw = typeof buf === 'string' ? buf : buf.toString('utf8');
      const msg = safeJsonParse(raw) as SignalMsg | null;
      if (!msg || typeof msg.t !== 'string') return;
      sess.meta.lastSeenTs = Date.now();
      if (!schemas.validateSignalMsg(msg)) return;

      try {
        if (msg.t === 'SIGNAL_HELLO') {
          // Wallet sends this before offer. No response required for current wallet client.
          return;
        }

        if (msg.t === 'SIGNAL_OFFER') {
          // Collator is the answerer.
          pc = new (wrtc as any).RTCPeerConnection({ iceServers: cfg.iceServers });

          pc.onicecandidate = (ev: any) => {
            if (!ev.candidate) return;
            sendSignal({ t: 'SIGNAL_ICE', v: 1, candidate: ev.candidate.toJSON() });
          };

          pc.ondatachannel = (ev: any) => {
            const dc: RTCDataChannel = ev.channel;
            sess.dc = dc;

            dc.onmessage = async (ev2: any) => {
              const txt = typeof ev2.data === 'string' ? ev2.data : Buffer.from(ev2.data).toString('utf8');
              if (txt.length > cfg.maxMsgBytes) {
                sess.sendDc({ t: 'ERR', v: 1, code: 'msg_too_large', msg: 'message too large' });
                try { dc.close(); } catch {}
                return;
              }
              const wm = safeJsonParse(txt) as WireMsg | null;
              if (!wm || !isWireMsg(wm)) return;
              sess.meta.lastSeenTs = Date.now();
              if (!schemas.validateWireMsg(wm)) {
                sess.sendDc({ t: 'ERR', v: 1, code: 'SCHEMA_INVALID', msg: 'invalid WireMsg schema' });
                return;
              }

              if (wm.t === 'PING') {
                sess.sendDc({ t: 'PONG', v: 1, ts: wm.ts });
                return;
              }

              if (wm.t === 'HELLO') {
                // Treat as ready.
                return;
              }

              if (wm.t === 'TAPE_SUB') {
                sess.wantsTape = true;
                const fromSeq = typeof wm.fromSeq === 'number' ? wm.fromSeq : 1;
                const lastSeq = await tape.replayFromSeq(Math.max(1, fromSeq), (e) => sess.sendTapeEntry(e));
                // Optional end marker; wallets that don't understand it should ignore.
                sess.sendDc({ t: 'TAPE_END', v: 1, lastSeq });
                return;
              }

              if (wm.t === 'SUBMIT') {
                if (!sess.submitBucket.allow(1)) {
                  sess.sendDc({ t: 'ERR', v: 1, code: 'rate_limited', msg: 'too many SUBMIT' });
                  return;
                }
                const order = (wm as any).order;
                if (!schemas.validateOrderEnvelope(order)) {
                  sess.sendDc({ t: 'ERR', v: 1, code: 'SCHEMA_INVALID', msg: 'invalid OrderEnvelopeV1 schema' });
                  return;
                }
                if (seen.has(order.orderId)) {
                  sess.sendDc({ t: 'ERR', v: 1, code: 'DUPLICATE', msg: 'orderId already seen' });
                  return;
                }
                if (!verifyTraderSig(order.orderId, order.sigTrader, order.traderPubKey)) {
                  sess.sendDc({ t: 'ERR', v: 1, code: 'bad_sig', msg: 'sigTrader verify failed' });
                  return;
                }

                // Basic referential integrity: prevent third-party cancels/replaces.
                if (order.kind === 'CANCEL') {
                  const target = String(order.cancelsOrderId || '').trim();
                  if (!target) {
                    sess.sendDc({ t: 'ERR', v: 1, code: 'SCHEMA_INVALID', msg: 'missing cancelsOrderId' });
                    return;
                  }
                  const owner = tape.getTraderForOrderId(target);
                  if (!owner) {
                    sess.sendDc({ t: 'ERR', v: 1, code: 'UNKNOWN_ORDER', msg: 'cancelsOrderId not found' });
                    return;
                  }
                  if (owner !== order.traderPubKey) {
                    sess.sendDc({ t: 'ERR', v: 1, code: 'NOT_OWNER', msg: 'cannot cancel other trader order' });
                    return;
                  }
                } else if (order.kind === 'REPLACE') {
                  const target = String(order.replacesOrderId || '').trim();
                  if (!target) {
                    sess.sendDc({ t: 'ERR', v: 1, code: 'SCHEMA_INVALID', msg: 'missing replacesOrderId' });
                    return;
                  }
                  const owner = tape.getTraderForOrderId(target);
                  if (!owner) {
                    sess.sendDc({ t: 'ERR', v: 1, code: 'UNKNOWN_ORDER', msg: 'replacesOrderId not found' });
                    return;
                  }
                  if (owner !== order.traderPubKey) {
                    sess.sendDc({ t: 'ERR', v: 1, code: 'NOT_OWNER', msg: 'cannot replace other trader order' });
                    return;
                  }
                }

                // Optional IP intel policy enforcement.
                if (ipIntel && (cfg.vpnFilterMode !== 'off' || cfg.asnBlockMode !== 'off')) {
                  const ip = sess.meta.remoteIp;
                  if (ip) {
                    try {
                      const intel = await ipIntel.lookup(ip);
                      if (typeof intel.asn === 'number') sess.meta.asn = intel.asn;
                      if (typeof intel.vpn === 'boolean') sess.meta.vpn = intel.vpn;
                    } catch {
                      // ignore intel errors for now; manifest already disables enforcement if IP_INTEL_URL missing.
                    }
                  }
                }

                if (cfg.vpnFilterMode !== 'off' && sess.meta.vpn === true) {
                  if (cfg.vpnFilterMode === 'reject') {
                    sess.sendDc({ t: 'ERR', v: 1, code: 'VPN_BLOCKED', msg: 'vpn traffic rejected' });
                    return;
                  }
                }
                if (cfg.asnBlockMode !== 'off' && typeof sess.meta.asn === 'number' && cfg.asnBlocklist.includes(sess.meta.asn)) {
                  if (cfg.asnBlockMode === 'reject') {
                    sess.sendDc({ t: 'ERR', v: 1, code: 'ASN_BLOCKED', msg: 'asn blocked' });
                    return;
                  }
                }

                // Optional clearlist enforcement.
                if (cfg.clearlistEnforce) {
                  const vis: any = order?.body?.visibility;
                  const kind = vis?.kind;
                  const groupId = vis?.groupId;
                  if ((kind === 'CLEARLIST' || kind === 'DARK') && typeof groupId === 'string' && groupId) {
                    if (!clearlist) {
                      sess.sendDc({ t: 'ERR', v: 1, code: 'CLEARLIST_CONFIG', msg: 'CLEARLIST_URL not configured' });
                      if (cfg.clearlistFailMode === 'closed') return;
                    } else {
                      try {
                        const res = await clearlist.check(groupId, order.traderPubKey);
                        if (!res.allowed) {
                          sess.sendDc({ t: 'ERR', v: 1, code: 'NOT_CLEARLISTED', msg: 'not clearlisted' });
                          return;
                        }
                      } catch (e: any) {
                        if (cfg.clearlistFailMode === 'closed') {
                          sess.sendDc({ t: 'ERR', v: 1, code: 'CLEARLIST_DOWN', msg: e?.message || String(e) });
                          return;
                        }
                      }
                    }
                  }
                }

                const entry = tape.append(order);
                seen.add(order.orderId);
                audit.write({
                  ts: Date.now(),
                  collatorId,
                  peerId: sess.id,
                  ip: sess.meta.remoteIp,
                  asn: sess.meta.asn,
                  vpn: sess.meta.vpn,
                  orderId: order.orderId,
                  traderPubKey: order.traderPubKey,
                  seq: entry.seq,
                });

                // Broadcast to all tape subscribers (MVP: if no explicit subscribers, still broadcast).
                for (const p of peers) {
                  if (!p.dc || p.dc.readyState !== 'open') continue;
                  if (!p.wantsTape) continue;
                  p.sendTapeEntry(entry);
                }
                return;
              }
            };

            dc.onopen = () => {
              // No-op. Wait for client HELLO/TAPE_SUB.
            };
            dc.onclose = () => {
              sess.dc = null;
            };
          };

          await pc.setRemoteDescription({ type: 'offer', sdp: msg.sdp });
          const answer = await pc.createAnswer();
          await pc.setLocalDescription(answer);
          sendSignal({ t: 'SIGNAL_ANSWER', v: 1, kind: 'answer', sdp: answer.sdp || '' });
          return;
        }

        if (msg.t === 'SIGNAL_ICE') {
          if (!pc) return;
          try {
            await pc.addIceCandidate(msg.candidate);
          } catch {}
          return;
        }
      } catch (e: any) {
        sendSignal({ t: 'SIGNAL_ERR', v: 1, code: 'internal', msg: e?.message || String(e) });
      }
    });
  });

  server.listen(cfg.port, '0.0.0.0', () => {
    // eslint-disable-next-line no-console
    console.log(
      JSON.stringify(
        {
          service: 'tl-collator',
          port: cfg.port,
          ws_path: cfg.wsPath,
          collator_id: collatorId,
          tape_path: cfg.tapePath,
          last_seq: tape.getLastSeq(),
        },
        null,
        2
      )
    );
  });
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error(e);
  process.exit(1);
});
