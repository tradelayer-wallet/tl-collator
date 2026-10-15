import { LruMap } from './lru.js';
import { fetchBoundedJson } from './boundedFetch.js';

// Round 8: a stalled or oversized IP intel answer must not hold a SUBMIT open or buffer without limit.
const IP_INTEL_TIMEOUT_MS = 3000;
const IP_INTEL_MAX_BYTES = 64 * 1024;

export interface IpIntel {
  asn?: number;
  vpn?: boolean;
}

/**
 * Whether an intel answer lets an order through under the policy; `null` is no answer at all. A
 * reject mode admits only when the answer carries the field that mode reads: a verdict without a
 * `vpn` boolean or an `asn` number is as unusable as no verdict. `log` modes, and an empty ASN list,
 * never need a field.
 */
export function intelAdmits(
  policy: { vpnFilterMode: 'off' | 'log' | 'reject'; asnBlockMode: 'off' | 'log' | 'reject'; asnBlocklist: number[] },
  intel: IpIntel | null,
): boolean {
  const needsVpn = policy.vpnFilterMode === 'reject';
  const needsAsn = policy.asnBlockMode === 'reject' && policy.asnBlocklist.length > 0;
  if (!needsVpn && !needsAsn) return true;
  return intel !== null && (!needsVpn || typeof intel.vpn === 'boolean') && (!needsAsn || typeof intel.asn === 'number');
}

export class IpIntelClient {
  private url: string;
  private ttlMs: number;
  private cache: LruMap<{ exp: number; v: IpIntel }>;

  constructor(opts: { url: string; ttlSec: number; max: number }) {
    this.url = opts.url;
    this.ttlMs = Math.max(0, opts.ttlSec) * 1000;
    this.cache = new LruMap(opts.max);
  }

  async lookup(ip: string): Promise<IpIntel> {
    const now = Date.now();
    const hit = this.cache.get(ip);
    if (hit && hit.exp > now) return hit.v;

    const res = await fetchBoundedJson(
      this.url,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ ip }),
      },
      { timeoutMs: IP_INTEL_TIMEOUT_MS, maxBytes: IP_INTEL_MAX_BYTES },
    );
    if (!res.ok) throw new Error(`ipIntel http ${res.status}`);
    // A field is kept only in its documented type. Coercion (`Number(null)` is 0) would turn a missing
    // or malformed answer into a verdict.
    const j: any = res.body;
    const v: IpIntel = {
      asn: Number.isInteger(j?.asn) && j.asn >= 1 && j.asn <= 4294967295 ? j.asn : undefined,
      vpn: typeof j?.vpn === 'boolean' ? j.vpn : undefined,
    };
    this.cache.set(ip, { exp: now + this.ttlMs, v });
    return v;
  }
}
