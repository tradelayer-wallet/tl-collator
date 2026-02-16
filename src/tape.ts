import fs from 'node:fs';
import path from 'node:path';
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

  private lastSeq: number = 0;
  private lastHash: string = '';

  // Minimal index for referential integrity checks (CANCEL/REPLACE).
  private traderByOrderId = new Map<string, string>();

  private collatorId: string;
  private collatorPrivKeyHex: string;

  private idx: TapeIndex | null = null;

  constructor(opts: {
    tapePath: string;
    idxPath: string;
    idxStride: number;
    replayBatch: number;
    collatorId: string;
    collatorPrivKeyHex: string;
  }) {
    this.tapePath = opts.tapePath;
    this.idxPath = opts.idxPath;
    this.idxStride = Math.max(1, opts.idxStride);
    this.replayBatch = Math.max(1, opts.replayBatch);
    this.collatorId = opts.collatorId;
    this.collatorPrivKeyHex = opts.collatorPrivKeyHex;
    fs.mkdirSync(path.dirname(this.tapePath), { recursive: true });
    this.loadFromDisk();
    this.loadOrBuildIndex();
  }

  private loadFromDisk() {
    if (!fs.existsSync(this.tapePath)) return;
    const data = fs.readFileSync(this.tapePath, 'utf8');
    const lines = data.split(/\r?\n/).filter(Boolean);
    for (const ln of lines) {
      try {
        const e = JSON.parse(ln) as TapeEntryV1;
        if (typeof e.seq === 'number' && typeof e.entryHash === 'string') {
          if (e.seq >= this.lastSeq) {
            this.lastSeq = e.seq;
            this.lastHash = e.entryHash;
          }
        }
        const oid = (e as any)?.order?.orderId;
        const pk = (e as any)?.order?.traderPubKey;
        if (typeof oid === 'string' && typeof pk === 'string') {
          this.traderByOrderId.set(oid, pk);
        }
      } catch {}
    }
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

  getTraderForOrderId(orderId: string): string | null {
    return this.traderByOrderId.get(orderId) || null;
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

  append(order: OrderEnvelopeV1): TapeEntryV1 {
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
    fs.appendFileSync(this.tapePath, JSON.stringify(entry) + '\n', 'utf8');

    this.lastSeq = seq;
    this.lastHash = entryHash;
    this.traderByOrderId.set(order.orderId, order.traderPubKey);

    // Index is based on file size; easiest is to mark stale and rebuild lazily.
    this.idx = null;
    return entry;
  }

  // Stream replay for backpressure. Calls onEntry for each entry.
  async replayFromSeq(fromSeq: number, onEntry: (e: TapeEntryV1) => void): Promise<number> {
    if (!fs.existsSync(this.tapePath)) return this.lastSeq;
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

      while (filePos < st.size) {
        const n = fs.readSync(fd, buf, 0, buf.length, filePos);
        if (n <= 0) break;
        filePos += n;
        const chunk = carry + buf.slice(0, n).toString('utf8');
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
          onEntry(e);
          lastSentSeq = e.seq;
          sent++;
          if (sent >= this.replayBatch) {
            sent = 0;
            await sleep0();
          }
        }
      }

      return Math.max(lastSentSeq, this.lastSeq);
    } finally {
      try {
        fs.closeSync(fd);
      } catch {}
    }
  }
}
