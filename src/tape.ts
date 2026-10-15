import fs from 'node:fs';
import path from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import { stableStringify } from './canonical.js';
import { sha256Hex, signWithPrivKeyHex } from './crypto.js';
import { buildIndex, findStartOffset, isIndexFresh, loadIndex, saveIndex, type TapeIndex } from './tapeIndex.js';
import type { OrderEnvelopeV1, TapeEntryV1 } from './types.js';

function sleep0(): Promise<void> {
  return new Promise((r) => setImmediate(r));
}

export class TapeStore {
  private tapePath: string;
  private idxPath: string;
  private idxStride: number;
  private replayBatch: number;
  private maxReplayEntries: number;

  private lastSeq: number = 0;
  private lastHash: string = '';

  // Minimal index for referential integrity checks (CANCEL/REPLACE).
  private traderByOrderId = new Map<string, string>();

  private collatorId: string;
  private collatorPrivKeyHex: string;

  private idx: TapeIndex | null = null;
  // Byte length of the tape file, tracked across appends so the index can be
  // extended in place instead of being rebuilt (a full re-scan) after each one.
  private tapeBytes: number = 0;
  // Set when a failed append could not be cut back: the file may end mid-line.
  private writeFailed: boolean = false;

  constructor(opts: {
    tapePath: string;
    idxPath: string;
    idxStride: number;
    replayBatch: number;
    maxReplayEntries: number;
    collatorId: string;
    collatorPrivKeyHex: string;
  }) {
    this.tapePath = opts.tapePath;
    this.idxPath = opts.idxPath;
    this.idxStride = Math.max(1, opts.idxStride);
    this.replayBatch = Math.max(1, opts.replayBatch);
    // A non-finite bound would make the resync clamp vacuous; refuse it loudly.
    if (!Number.isFinite(opts.maxReplayEntries)) throw new Error('TapeStore: maxReplayEntries must be a finite number');
    this.maxReplayEntries = Math.max(1, Math.floor(opts.maxReplayEntries));
    this.collatorId = opts.collatorId;
    this.collatorPrivKeyHex = opts.collatorPrivKeyHex;
    fs.mkdirSync(path.dirname(this.tapePath), { recursive: true });
    this.loadFromDisk();
    this.tapeBytes = fs.existsSync(this.tapePath) ? fs.statSync(this.tapePath).size : 0;
    this.loadOrBuildIndex();
  }

  private loadFromDisk() {
    if (!fs.existsSync(this.tapePath)) return;
    const buf = fs.readFileSync(this.tapePath);
    // A crash mid-append can leave an unterminated last line. Its write never
    // completed, so it was never acknowledged; cut it off so the next append
    // does not glue onto it.
    const keep = buf.lastIndexOf(0x0a) + 1;
    if (keep < buf.length) {
      fs.truncateSync(this.tapePath, keep);
      console.warn(JSON.stringify({ service: 'tl-collator', event: 'tape-torn-tail-truncated', bytes: buf.length - keep }));
    }
    const lines = buf.subarray(0, keep).toString('utf8').split(/\r?\n/).filter(Boolean);
    lines.forEach((ln, i) => {
      // Every entry feeds the duplicate check. A damaged interior line would
      // silently leave its orderId out of it, so refuse to start instead.
      let e: TapeEntryV1;
      try {
        e = JSON.parse(ln) as TapeEntryV1;
      } catch {
        throw new Error(`TapeStore: tape line ${i + 1} is not valid JSON; refusing to start with an incomplete duplicate check`);
      }
      if (typeof e?.seq === 'number' && typeof e.entryHash === 'string') {
        if (e.seq >= this.lastSeq) {
          this.lastSeq = e.seq;
          this.lastHash = e.entryHash;
        }
      }
      const oid = (e as any)?.order?.orderId;
      const pk = (e as any)?.order?.traderPubKey;
      if (typeof oid === 'string' && typeof pk === 'string') {
        this.traderByOrderId.set(oid.toLowerCase(), pk.toLowerCase());
      }
    });
  }

  private loadOrBuildIndex() {
    const idx = loadIndex(this.idxPath);
    if (idx && fs.existsSync(this.tapePath) && isIndexFresh(idx, this.tapePath) && idx.stride === this.idxStride) {
      this.idx = idx;
      return;
    }
    this.rebuildIndex();
  }

  rebuildIndex() {
    const idx = buildIndex(this.tapePath, this.idxStride);
    saveIndex(this.idxPath, idx);
    this.idx = idx;
  }

  getLastSeq(): number {
    return this.lastSeq;
  }

  getLastHash(): string {
    return this.lastHash;
  }

  // Ids and trader keys are hex. Their case is not part of their identity, so every key is stored
  // and looked up in lower case.
  getTraderForOrderId(orderId: string): string | null {
    return this.traderByOrderId.get(orderId.toLowerCase()) || null;
  }

  // Covers every entry on disk (loaded at startup) and every append since, so
  // an orderId can never be recorded twice — including after a restart, when
  // a harvested SUBMIT would otherwise be re-accepted.
  hasOrder(orderId: string): boolean {
    return this.traderByOrderId.has(orderId.toLowerCase());
  }

  computeEntryHash(base: Omit<TapeEntryV1, 'entryHash' | 'sigCollator'>): string {
    // Must match wallet TapeVerifier.computeEntryHash material shape.
    const material = stableStringify({
      v: base.v,
      collatorId: base.collatorId,
      seq: base.seq,
      prevHash: base.prevHash,
      receivedTs: base.receivedTs,
      order: base.order,
    });
    return sha256Hex(material);
  }

  // Atomic check-and-append: nothing is awaited between the duplicate check and
  // the write, so two identical SUBMITs cannot both land. Returns null (and
  // writes nothing) when the orderId is already on the tape.
  // A failed write is cut back to the pre-append length, so the file always
  // ends on a line boundary and in-memory state (seq, hash, index) matches disk.
  // If that cut fails too, every append retries it first and is refused while it fails.
  append(order: OrderEnvelopeV1): TapeEntryV1 | null {
    if (this.writeFailed) this.repairAfterWriteFailure();
    if (this.hasOrder(order.orderId)) return null;
    const seq = this.lastSeq + 1;
    const prevHash = this.lastHash;
    const receivedTs = Date.now();
    const base = {
      v: 1 as const,
      collatorId: this.collatorId,
      seq,
      prevHash,
      receivedTs,
      order,
    };
    const entryHash = this.computeEntryHash(base);

    // Collator signature: sign sha256(seq|prevHash|orderId|entryHash).
    const sigMsg = sha256Hex(`${seq}|${prevHash}|${order.orderId}|${entryHash}`);
    const sigCollator = signWithPrivKeyHex(sigMsg, this.collatorPrivKeyHex);

    const entry: TapeEntryV1 = { ...base, entryHash, sigCollator };
    const line = JSON.stringify(entry) + '\n';
    const lineOffset = this.tapeBytes;
    try {
      fs.appendFileSync(this.tapePath, line, 'utf8');
    } catch (err) {
      this.cutBackTo(lineOffset);
      throw err;
    }
    this.tapeBytes += Buffer.byteLength(line, 'utf8');

    this.lastSeq = seq;
    this.lastHash = entryHash;
    this.traderByOrderId.set(order.orderId.toLowerCase(), order.traderPubKey.toLowerCase());

    // Keep the seek index current: offsets[i] is the line for seq i*stride+1.
    if (this.idx) {
      if ((seq - 1) % this.idx.stride === 0) this.idx.offsets.push(lineOffset);
      this.idx.tapeSize = this.tapeBytes;
    }
    return entry;
  }

  private repairAfterWriteFailure(): void {
    try {
      fs.truncateSync(this.tapePath, this.tapeBytes);
    } catch {
      throw new Error('tape: refusing appends until a failed write is cut back');
    }
    this.writeFailed = false;
  }

  private cutBackTo(offset: number): void {
    try {
      fs.truncateSync(this.tapePath, offset);
    } catch {
      this.writeFailed = true;
    }
  }

  // Stream replay for backpressure. Calls onEntry for each entry. A resync is
  // bounded to the newest `maxReplayEntries` entries so one TAPE_SUB cannot
  // force a full-file read; the returned `fromSeq` is the first seq actually
  // replayed, which callers must report so a clamped resync is visible.
  // `onEntry` may wait (for example, for a channel to drain). Returning false stops the replay
  // early; `lastSeq` is then the last entry actually delivered.
  async replayFromSeq(
    requestedFromSeq: number,
    onEntry: (e: TapeEntryV1) => boolean | void | Promise<boolean | void>,
  ): Promise<{ fromSeq: number; lastSeq: number }> {
    const fromSeq = Math.max(requestedFromSeq, this.lastSeq - this.maxReplayEntries + 1, 1);
    // Nothing to send past the tip. Returning here matters: the seek index has no
    // offset for such a seq, so the scan below would read the whole file.
    if (fromSeq > this.lastSeq || !fs.existsSync(this.tapePath)) return { fromSeq, lastSeq: this.lastSeq };
    const idx = this.idx || (this.loadOrBuildIndex(), this.idx);
    const startOffset = idx ? findStartOffset(idx, fromSeq) : 0;

    const fd = fs.openSync(this.tapePath, 'r');
    try {
      const st = fs.fstatSync(fd);
      const buf = Buffer.allocUnsafe(64 * 1024);
      let filePos = startOffset;
      let carry = '';
      let sent = 0;
      let lastSentSeq = 0;
      // Round 8: a multi-byte UTF-8 character can straddle two reads. Decoding each read on its
      // own turned the split character into U+FFFD inside a valid-looking entry, which replay then
      // sent to wallets. A StringDecoder keeps the partial bytes until the next read completes them.
      const decoder = new StringDecoder('utf8');

      while (filePos < st.size) {
        const n = fs.readSync(fd, buf, 0, buf.length, filePos);
        if (n <= 0) break;
        filePos += n;
        const chunk = carry + decoder.write(buf.subarray(0, n));
        const parts = chunk.split(/\r?\n/);
        carry = parts.pop() || '';
        for (const line of parts) {
          const raw = line.trim();
          if (!raw) continue;
          let e: TapeEntryV1 | null = null;
          try {
            e = JSON.parse(raw) as TapeEntryV1;
          } catch {
            continue;
          }
          if (!e || typeof e.seq !== 'number') continue;
          if (e.seq < fromSeq) continue;
          if ((await onEntry(e)) === false) {
            return { fromSeq, lastSeq: lastSentSeq };
          }
          lastSentSeq = e.seq;
          sent++;
          if (sent >= this.replayBatch) {
            sent = 0;
            await sleep0();
          }
        }
      }

      return { fromSeq, lastSeq: Math.max(lastSentSeq, this.lastSeq) };
    } finally {
      try {
        fs.closeSync(fd);
      } catch {}
    }
  }
}
