import type { WebSocket } from 'ws';
import type { TapeEntryV1, WireMsg } from './types.js';
import { TokenBucket } from './ratelimit.js';

export interface SessionMetaV1 {
  remoteIp?: string;
  userAgent?: string;
  asn?: number;
  vpn?: boolean;
  firstSeenTs: number;
  lastSeenTs: number;
}

export class PeerSession {
  readonly id: string;
  readonly ws: WebSocket;
  dc: RTCDataChannel | null = null;

  // If true, peer has requested tape feed (or we treat all as subscribers).
  wantsTape: boolean = false;

  // SUBMIT rate limit (per-peer).
  submitBucket: TokenBucket;

  meta: SessionMetaV1;

  constructor(opts: { id: string; ws: WebSocket; burst: number; ratePerSec: number; remoteIp?: string; userAgent?: string }) {
    this.id = opts.id;
    this.ws = opts.ws;
    this.submitBucket = new TokenBucket({ capacity: opts.burst, refillPerSec: opts.ratePerSec });
    const now = Date.now();
    this.meta = {
      remoteIp: opts.remoteIp,
      userAgent: opts.userAgent,
      firstSeenTs: now,
      lastSeenTs: now,
    };
  }

  sendDc(msg: WireMsg) {
    if (!this.dc || this.dc.readyState !== 'open') return;
    this.dc.send(JSON.stringify(msg));
  }

  sendTapeEntry(entry: TapeEntryV1) {
    this.sendDc({ t: 'TAPE_ENTRY', v: 1, entry });
  }
}
