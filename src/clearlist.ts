import { fetchBoundedJson } from './boundedFetch.js';
import { LruMap } from './lru.js';

// Round 8: a stalled or oversized clearlist answer must not hold a SUBMIT open or buffer without limit.
const CLEARLIST_TIMEOUT_MS = 3000;
const CLEARLIST_MAX_BYTES = 64 * 1024;
// Keys are (group, trader key) pairs a SUBMIT chooses, so the cache is bounded like the intel cache.
const CLEARLIST_CACHE_MAX = 5000;

export interface ClearlistResult {
  allowed: boolean;
  snapshotId?: string;
  expTs?: number;
}

export class ClearlistClient {
  private baseUrl: string;
  private ttlMs: number;
  private cache: LruMap<{ exp: number; v: ClearlistResult }>;

  constructor(opts: { baseUrl: string; ttlMs?: number; max?: number }) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, '');
    this.ttlMs = Math.max(1000, opts.ttlMs || 60000);
    this.cache = new LruMap(opts.max ?? CLEARLIST_CACHE_MAX);
  }

  async check(groupId: string, pubkeyHex: string): Promise<ClearlistResult> {
    // pubkeyHex is hex, so no '|' can occur in it and the key is unambiguous.
    const k = `${groupId}|${pubkeyHex}`;
    const now = Date.now();
    const hit = this.cache.get(k);
    if (hit && hit.exp > now) return hit.v;

    const url = `${this.baseUrl}/clearlist/check`;
    const r = await fetchBoundedJson(
      url,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'X-TL-Clearlist-OptIn': '1' },
        body: JSON.stringify({ groupId, pubkeyHex, optIn: true }),
      },
      { timeoutMs: CLEARLIST_TIMEOUT_MS, maxBytes: CLEARLIST_MAX_BYTES },
    );
    if (!r.ok) throw new Error(`clearlist http ${r.status}`);
    const j: any = r.body;
    // Only a boolean admits or refuses. Any other answer is an error, so CLEARLIST_FAIL_MODE decides (round 12 / F3).
    if (typeof j?.allowed !== 'boolean') throw new Error('clearlist answer has no boolean "allowed"');
    const v: ClearlistResult = {
      allowed: j.allowed,
      snapshotId: j.snapshotId ? String(j.snapshotId) : undefined,
      expTs: typeof j.expTs === 'number' ? j.expTs : undefined,
    };
    this.cache.set(k, { exp: now + this.ttlMs, v });
    return v;
  }
}
