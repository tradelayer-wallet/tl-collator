import { LruMap } from './lru.js';

export interface IpIntel {
  asn?: number;
  vpn?: boolean;
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

    const res = await fetch(this.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ip }),
    });
    if (!res.ok) throw new Error(`ipIntel http ${res.status}`);
    const j: any = await res.json();
    const v: IpIntel = {
      asn: Number.isFinite(Number(j?.asn)) ? Number(j.asn) : undefined,
      vpn: typeof j?.vpn === 'boolean' ? j.vpn : undefined,
    };
    this.cache.set(ip, { exp: now + this.ttlMs, v });
    return v;
  }
}
