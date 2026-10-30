import type { WebSocket } from 'ws';
import type { TapeEntryV1, WireMsg } from './types.js';
import type { TapeStore } from './tape.js';
import { TokenBucket, type KeyedTokenBuckets } from './ratelimit.js';

// Minimum interval between two TAPE_SUB replays admitted on one session (H3c, now per session).
const TAPE_SUB_MIN_INTERVAL_MS = 1000;

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

/** A replay gives up on its channel once it has run this long, however steadily the peer drains it. */
export const DC_REPLAY_MAX_MS = 120_000;

/**
 * Bytes of live entries a stream holds while its replay runs (round 13). A replay can be slow and
 * every SUBMIT commits meanwhile, so past this bound the channel is closed and the wallet resyncs.
 * Bytes, not entries: one entry can be close to MAX_MSG_BYTES.
 */
export const DC_REPLAY_MAX_HELD_BYTES = DC_MAX_BUFFERED_BYTES;

const DC_REPLAY_POLL_MS = 5;

interface TapeSubOpts {
  stallMs?: number;
  deadlineMs?: number;
}

/**
 * The TAPE_SUB stream a session is serving. Idle is no stream. A stream is replaying while it
 * reads the tape, then flushing its held run; live entries wait behind both, in commit order.
 */
interface TapeStream {
  channel: RTCDataChannel;
  deadline: number;
  held: Array<{ entry: TapeEntryV1; bytes: number }>;
  heldBytes: number;
}

/** Bytes a TAPE_ENTRY takes on the wire, counted the way the held run is bounded. */
const entryBytes = (entry: TapeEntryV1): number => dcMessageBytes(JSON.stringify(entry));

/** Why the collator closes a tape channel. The code is stable: the peer reads it to tell a resync from a dead channel. */
export interface CloseReason {
  code: 'resync_required' | 'stalled' | 'deadline_exceeded' | 'busy_retry' | 'rate_limited';
  msg: string;
}

/**
 * Sends an ERR on a channel that is about to close. Best effort: a channel that cannot take the
 * message (for example one whose queue is full) is closed all the same.
 */
function sendErrOn(channel: RTCDataChannel, reason: CloseReason): void {
  if (channel.readyState !== 'open') return;
  try {
    channel.send(JSON.stringify({ t: 'ERR', v: 1, code: reason.code, msg: reason.msg }));
  } catch {}
}

/** Refuses a channel the collator will not adopt: the stated ERR, then the close. */
export function refuseChannel(channel: RTCDataChannel, reason: CloseReason): void {
  sendErrOn(channel, reason);
  try {
    channel.close();
  } catch {}
}

export class PeerSession {
  readonly id: string;
  readonly ws: WebSocket;
  dc: RTCDataChannel | null = null;

  // True once a TAPE_SUB on the current channel has been served. Live entries go only to a subscribed
  // channel, so a channel's stream always starts at its own served TAPE_SUB, never with live entries
  // it cannot backfill.
  wantsTape: boolean = false;

  // The stream this session is serving, if any (see TapeStream).
  private stream: TapeStream | null = null;

  // The run of seqs this session sent on a channel since that channel's last TAPE_END: its first seq
  // and its last. A TAPE_SUB on the channel continues after the run, so no seq goes out twice.
  private tail: { channel: RTCDataChannel; first: number; seq: number } | null = null;

  // SUBMIT rate limit (per-peer).
  submitBucket: TokenBucket;

  // The session's share of the open budget (see admitOpen).
  private openBucket: TokenBucket;

  // When this session's last served TAPE_SUB was admitted (see admitTapeSub).
  private lastTapeSubMs = -Infinity;

  meta: SessionMetaV1;

  constructor(opts: {
    id: string;
    ws: WebSocket;
    burst: number;
    ratePerSec: number;
    openBurst: number;
    openRatePerSec: number;
    remoteIp?: string;
    userAgent?: string;
  }) {
    this.id = opts.id;
    this.ws = opts.ws;
    this.submitBucket = new TokenBucket({ capacity: opts.burst, refillPerSec: opts.ratePerSec });
    this.openBucket = new TokenBucket({ capacity: opts.openBurst, refillPerSec: opts.openRatePerSec });
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
   * Charges one open to this session and to its client key. An open is a SIGNAL_OFFER (a peer connection
   * built), a channel open (adopted or refused) or a TAPE_SUB. The session bucket bounds one session; the
   * client bucket bounds the sum over every session of that client, so opening sessions does not multiply
   * the budget.
   */
  admitOpen(clients: KeyedTokenBuckets, clientKey: string): boolean {
    return this.openBucket.allow(1) && clients.take(clientKey).allowed;
  }

  /**
   * Admits a TAPE_SUB as an open, and also refuses one that comes less than TAPE_SUB_MIN_INTERVAL_MS after
   * this session's last served TAPE_SUB, whatever the budget holds: a token bucket alone would admit a
   * second TAPE_SUB on a session that has tokens left. A request refused by the spacing charges nothing. The
   * client's TAPE_SUBs also draw on tapeClients, so sessions behind one IP cannot start replays faster than that bucket.
   */
  admitTapeSub(clients: KeyedTokenBuckets, tapeClients: KeyedTokenBuckets, clientKey: string): boolean {
    const now = Date.now();
    if (now - this.lastTapeSubMs < TAPE_SUB_MIN_INTERVAL_MS) return false;
    if (!this.admitOpen(clients, clientKey)) return false;
    // A replay costs more than an open, so the client's replays are bounded by their own bucket.
    if (!tapeClients.take(clientKey).allowed) return false;
    this.lastTapeSubMs = now;
    return true;
  }

  /**
   * Adopts the channel the peer just opened. A peer may open several channels on one connection;
   * the previous one is closed here, so only one channel per session can hold state or memory. The
   * new channel is unsubscribed until its own TAPE_SUB. A channel opened while a stream is in flight
   * is refused with ERR busy_retry and closed, and returns false. The stream keeps its channel and
   * ends on its own (it completes, stalls or passes its deadline), and the peer opens a channel again
   * once it has ended.
   */
  attachDataChannel(dc: RTCDataChannel): boolean {
    if (this.stream !== null) {
      refuseChannel(dc, { code: 'busy_retry', msg: 'a replay is in flight on this connection; open the channel again when it ends, and send its TAPE_SUB at least 1 s after this message' });
      return false;
    }
    const previous = this.dc;
    this.dc = dc;
    this.wantsTape = false;
    if (previous && previous !== dc) {
      try {
        previous.close();
      } catch {}
    }
    return true;
  }

  /**
   * Closes the session's channel and ends the stream on it. A close the collator starts for a stated
   * reason sends that ERR first. The peer resubscribes on its next channel, from its own position.
   */
  dropChannel(reason?: CloseReason): void {
    const dc = this.dc;
    this.dc = null;
    this.stream = null;
    this.wantsTape = false;
    if (dc && reason) sendErrOn(dc, reason);
    try {
      dc?.close();
    } catch {}
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

  /** Sends a TAPE_ENTRY. The channel's run continues if the entry follows its last seq, else starts over. */
  sendTapeEntry(entry: TapeEntryV1): boolean {
    const dc = this.dc;
    if (!dc || !this.sendDc({ t: 'TAPE_ENTRY', v: 1, entry })) return false;
    const run = this.tail?.channel === dc && this.tail.seq + 1 === entry.seq ? this.tail : null;
    this.tail = { channel: dc, first: run ? run.first : entry.seq, seq: entry.seq };
    return true;
  }

  /**
   * Serves a TAPE_SUB on `channel` as one ordered stream: the replay, then the live entries
   * committed while it ran, then TAPE_END. The replay starts at `fromSeq`, or after the run this
   * channel already carried if that is later, and TAPE_END reports the seq it started at.
   *
   * A TAPE_SUB on the same channel supersedes the stream in flight: that stream stops with no
   * TAPE_END. Its held entries are not carried over. They are all on the tape already, so the new
   * replay (which reads up to the tip at its start) sends each of them once. A stream that cannot
   * finish closes the channel with no TAPE_END; the peer resubscribes from its own position. So does
   * a request for seqs below the run: the channel cannot send them without going back.
   */
  async serveTapeSub(channel: RTCDataChannel, tape: TapeStore, fromSeq: number, opts: TapeSubOpts = {}): Promise<void> {
    if (this.dc !== channel || channel.readyState !== 'open') return;
    const run = this.tail?.channel === channel ? this.tail : null;
    if (run && fromSeq < run.first) {
      this.dropChannel({ code: 'resync_required', msg: 'TAPE_SUB starts before this channel\'s run; resubscribe on a new channel' });
      return;
    }
    const start = run ? Math.max(fromSeq, run.seq + 1) : fromSeq;
    const stream: TapeStream = { channel, deadline: Date.now() + (opts.deadlineMs ?? DC_REPLAY_MAX_MS), held: [], heldBytes: 0 };
    this.stream = stream;
    this.wantsTape = true;
    try {
      const range = await tape.replayFromSeq(start, (e) => this.sendStreamEntry(stream, e, opts.stallMs));
      while (this.streamIsCurrent(stream) && stream.held.length > 0) {
        const { entry, bytes } = stream.held.shift()!;
        stream.heldBytes -= bytes;
        await this.sendStreamEntry(stream, entry, opts.stallMs);
      }
      if (!this.streamIsCurrent(stream)) return;
      // Cleared and TAPE_END sent with no await in between: no live entry can slip in before the end marker.
      // TAPE_END is optional for the wallet, which ignores it if it does not understand it.
      this.stream = null;
      this.tail = null;
      // `fromSeq` is the first seq actually sent in this stream. It is greater than the requested one
      // when the resync was clamped to TAPE_RESYNC_MAX_ENTRIES or continued after the channel's tail.
      this.sendDc({ t: 'TAPE_END', v: 1, lastSeq: tape.getLastSeq(), fromSeq: range.fromSeq });
    } finally {
      if (this.stream === stream) this.stream = null;
    }
  }

  /**
   * Hands a live entry to this session. Idle, it is sent now. Replaying or flushing, it is held
   * behind the entries already in the stream. The held run is bounded in bytes: past the bound the
   * channel is closed with an ERR, and the peer resubscribes.
   */
  deliverTapeEntry(entry: TapeEntryV1): void {
    const stream = this.stream;
    if (!stream) {
      this.sendTapeEntry(entry);
      return;
    }
    const bytes = entryBytes(entry);
    if (stream.heldBytes + bytes > DC_REPLAY_MAX_HELD_BYTES) {
      this.dropChannel({ code: 'resync_required', msg: 'live entries outran the replay; resubscribe from your last seq' });
      return;
    }
    stream.held.push({ entry, bytes });
    stream.heldBytes += bytes;
  }

  /**
   * Sends one entry of a stream, waiting for the queue to drain first. Returns false, and sends
   * nothing more, once the stream is superseded or its channel is gone. A queue that does not shrink
   * for `stallMs`, or a stream past its deadline, closes the channel.
   */
  private async sendStreamEntry(stream: TapeStream, entry: TapeEntryV1, stallMs: number = DC_REPLAY_STALL_MS): Promise<boolean> {
    const channel = stream.channel;
    let queued = channel.bufferedAmount;
    let progressAt = Date.now();
    for (;;) {
      if (!this.streamIsCurrent(stream)) return false;
      if (Date.now() > stream.deadline) {
        this.dropChannel({ code: 'deadline_exceeded', msg: 'replay ran past its deadline; resubscribe from your last seq' });
        return false;
      }
      if (channel.bufferedAmount <= DC_REPLAY_HIGH_WATER_BYTES) return this.sendTapeEntry(entry);
      await new Promise<void>((resolve) => setTimeout(resolve, DC_REPLAY_POLL_MS));
      if (channel.bufferedAmount < queued) {
        queued = channel.bufferedAmount;
        progressAt = Date.now();
      } else if (Date.now() - progressAt > stallMs) {
        this.dropChannel({ code: 'stalled', msg: 'replay queue stopped draining; resubscribe from your last seq' });
        return false;
      }
    }
  }

  private streamIsCurrent(stream: TapeStream): boolean {
    return this.stream === stream && this.dc === stream.channel && stream.channel.readyState === 'open';
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
    peer.deliverTapeEntry(entry);
  }
}
