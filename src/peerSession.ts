import type { WebSocket } from 'ws';
import type { TapeEntryV1, WireMsg } from './types.js';
import { TokenBucket, type KeyedTokenBuckets } from './ratelimit.js';

export interface SessionMetaV1 {
  remoteIp?: string;
  userAgent?: string;
  asn?: number;
  vpn?: boolean;
  firstSeenTs: number;
  lastSeenTs: number;
}

/**
 * Largest amount of outgoing data a DataChannel may hold unsent (round 8). A peer that stops
 * reading keeps its channel open, so without this bound every tape broadcast queued for it stays
 * in native memory until the process dies. Past the bound the channel is closed; the wallet
 * resyncs with TAPE_SUB on reconnect.
 */
export const DC_MAX_BUFFERED_BYTES = 4 * 1024 * 1024;

/**
 * Queue level a TAPE_SUB replay waits for before it sends the next entry (round 10). A replay
 * of up to TAPE_RESYNC_MAX_ENTRIES entries is produced at CPU speed, so without pacing it fills
 * the channel past DC_MAX_BUFFERED_BYTES in one burst and the live-feed cap closes a healthy
 * wallet mid-resync. The wait keeps a responsive peer's queue well below that cap.
 */
export const DC_REPLAY_HIGH_WATER_BYTES = 1024 * 1024;

/**
 * Size in bytes of one inbound DataChannel message. MAX_MSG_BYTES is a byte limit (the WebSocket
 * side is enforced in bytes by ws), so the DataChannel side must count bytes too, not string units.
 */
export function dcMessageBytes(data: string | ArrayBuffer | ArrayBufferView): number {
  return typeof data === 'string' ? Buffer.byteLength(data, 'utf8') : data.byteLength;
}

/** A replay gives up on a channel whose queue has not shrunk for this long (a stalled peer). */
export const DC_REPLAY_STALL_MS = 10_000;

const DC_REPLAY_POLL_MS = 5;

export class PeerSession {
  readonly id: string;
  readonly ws: WebSocket;
  dc: RTCDataChannel | null = null;

  // If true, peer has requested tape feed (or we treat all as subscribers).
  wantsTape: boolean = false;

  // SUBMIT rate limit (per-peer).
  submitBucket: TokenBucket;

  // SIGNAL_OFFER pacing. Each accepted offer builds a native peer connection, and one connection
  // needs one offer, so a small burst covers reconnects and the rest is refused.
  offerBucket: TokenBucket = new TokenBucket({ capacity: 3, refillPerSec: 1 });

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

  /**
   * Charges one SUBMIT to this session and to its client key. The session bucket alone would let one
   * client multiply its rate by the number of sessions it can open (CONN_MAX_PER_IP).
   */
  admitSubmit(clients: KeyedTokenBuckets, clientKey: string): boolean {
    return this.submitBucket.allow(1) && clients.take(clientKey).allowed;
  }

  /**
   * Adopts the channel the peer just opened. A peer may open several channels on one connection;
   * the previous one is closed here, so only one channel per session can hold state or memory.
   */
  attachDataChannel(dc: RTCDataChannel): void {
    const previous = this.dc;
    this.dc = dc;
    if (previous && previous !== dc) {
      try {
        previous.close();
      } catch {}
    }
  }

  /**
   * Sends one message on the session's channel. It never throws: a failed or stalled send closes
   * the channel, which removes the session from the live feed and the idle reaper takes it from there.
   * Returns true when the message was handed to the channel.
   */
  sendDc(msg: WireMsg): boolean {
    const dc = this.dc;
    if (!dc || dc.readyState !== 'open') return false;
    if (dc.bufferedAmount > DC_MAX_BUFFERED_BYTES) {
      this.dropChannel();
      return false;
    }
    try {
      dc.send(JSON.stringify(msg));
      return true;
    } catch {
      this.dropChannel();
      return false;
    }
  }

  sendTapeEntry(entry: TapeEntryV1): boolean {
    return this.sendDc({ t: 'TAPE_ENTRY', v: 1, entry });
  }

  /**
   * Sends one replayed entry on `channel`, waiting for the queue to drain first. Returns false,
   * and sends nothing more, once `channel` is no longer this session's channel or is closed. A
   * queue that does not shrink for `stallMs` closes the channel, so a stalled peer still ends the
   * replay.
   */
  async sendReplayEntry(channel: RTCDataChannel, entry: TapeEntryV1, stallMs: number = DC_REPLAY_STALL_MS): Promise<boolean> {
    let queued = channel.bufferedAmount;
    let progressAt = Date.now();
    while (channel.bufferedAmount > DC_REPLAY_HIGH_WATER_BYTES) {
      if (this.dc !== channel || channel.readyState !== 'open') return false;
      await new Promise<void>((resolve) => setTimeout(resolve, DC_REPLAY_POLL_MS));
      if (channel.bufferedAmount < queued) {
        queued = channel.bufferedAmount;
        progressAt = Date.now();
      } else if (Date.now() - progressAt > stallMs) {
        this.dropChannel();
        return false;
      }
    }
    if (this.dc !== channel || channel.readyState !== 'open') return false;
    return this.sendTapeEntry(entry);
  }

  private dropChannel(): void {
    const dc = this.dc;
    this.dc = null;
    try {
      dc?.close();
    } catch {}
  }
}

/**
 * Live tape broadcast. Each subscriber is isolated: one peer whose send fails or stalls can not
 * stop the others from receiving the entry, and the caller (a SUBMIT that is already committed
 * to the tape) never sees an error from this step.
 */
export function broadcastTapeEntry(peers: Iterable<PeerSession>, entry: TapeEntryV1): void {
  for (const peer of peers) {
    if (!peer.dc || peer.dc.readyState !== 'open') continue;
    if (!peer.wantsTape) continue;
    peer.sendTapeEntry(entry);
  }
}
