import net from 'node:net';
import type http from 'node:http';

// Single trusted-client-IP resolver. Every per-IP decision in the collator (WS
// connection caps, routed-RPC admission, HTTP rate limits, TAPE_SUB resync
// gating, IP intel, logs) goes through `resolve()`, so header trust is decided
// in exactly one place.

export interface TrustedProxyConfig {
  /** TRUST_PROXY=1: client-IP headers may be honored, but only from a peer in `cidrs`. */
  enabled: boolean;
  /** TRUST_PROXY_CIDRS: the reverse-proxy / CDN hop addresses (IPv4 or IPv6, optional /prefix). */
  cidrs: string[];
}

export interface ClientIpResolver {
  /** Client IP for a request: the socket peer, or an X-Forwarded-For-derived address when the peer is a trusted hop. */
  resolve(req: Pick<http.IncomingMessage, 'headers' | 'socket'>): string;
  /** True when client-IP headers on this request may be believed (peer is a configured proxy hop). */
  headersTrusted(req: Pick<http.IncomingMessage, 'socket'>): boolean;
}

interface ParsedCidr {
  addr: string;
  prefix: number;
  family: 'ipv4' | 'ipv6';
}

// Canonical textual form of an address. IPv4-mapped IPv6 in either spelling
// (`::ffff:a.b.c.d`, what dual-stack sockets report, or `::ffff:0a00:0001`)
// becomes `a.b.c.d`; other IPv6 is returned in RFC 5952 form. Returns '' when
// the input is not an IP address.
export function normalizeIp(raw: string): string {
  const s = String(raw || '').trim();
  const family = net.isIP(s);
  if (family === 4) return s;
  if (family !== 6) return '';
  let host: string;
  try {
    // WHATWG URL parsing produces the canonical compressed IPv6 spelling.
    host = new URL(`http://[${s}]/`).hostname.slice(1, -1);
  } catch {
    return ''; // e.g. zone-scoped (`fe80::1%eth0`) addresses
  }
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
  if (!mapped) return host;
  const hi = parseInt(mapped[1], 16);
  const lo = parseInt(mapped[2], 16);
  return [hi >> 8, hi & 0xff, lo >> 8, lo & 0xff].join('.');
}

// IPv6 limiter-key prefix length (CLIENT_IPV6_PREFIX_LEN). A residential or VPS
// customer normally holds a whole /64, so keying on the full address would give
// one customer 2^64 buckets. Bounds: shorter than /32 would merge whole ISP
// allocations into one budget; longer than /128 is meaningless.
export const CLIENT_IPV6_PREFIX_MIN = 32;
export const CLIENT_IPV6_PREFIX_MAX = 128;
export const CLIENT_IPV6_PREFIX_DEFAULT = 64;

// Expands canonical IPv6 text (as produced by normalizeIp) into eight 16-bit words.
function ipv6Words(canonical: string): number[] {
  const halves = canonical.split('::');
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
  const zeros = new Array<string>(8 - head.length - tail.length).fill('0');
  return [...head, ...zeros, ...tail].map((g) => parseInt(g, 16));
}

/**
 * Admission / rate-limit identity for a client IP. Every per-client budget, cap
 * and per-client aggregation keys on this, never on the raw address:
 *  - IPv4 → the address;
 *  - IPv4-mapped IPv6 (`::ffff:a.b.c.d`) → the embedded IPv4, so both spellings are one client;
 *  - other IPv6 → its `ipv6PrefixLen` prefix (default /64), so one allocation is one client.
 * The raw resolved IP is still used for logging and for forwarding.
 */
export function clientKeyForIp(ip: string, ipv6PrefixLen: number): string {
  if (!Number.isInteger(ipv6PrefixLen) || ipv6PrefixLen < CLIENT_IPV6_PREFIX_MIN || ipv6PrefixLen > CLIENT_IPV6_PREFIX_MAX) {
    throw new Error(`CLIENT_IPV6_PREFIX_LEN must be an integer from ${CLIENT_IPV6_PREFIX_MIN} to ${CLIENT_IPV6_PREFIX_MAX}`);
  }
  const addr = normalizeIp(ip);
  if (!addr) return 'ip:unknown';
  if (net.isIP(addr) === 4) return `ip:${addr}`;
  const masked = ipv6Words(addr).map((word, i) => {
    const bits = Math.min(16, Math.max(0, ipv6PrefixLen - 16 * i));
    const mask = bits === 0 ? 0 : (0xffff << (16 - bits)) & 0xffff;
    return word & mask;
  });
  return `ip:${normalizeIp(masked.map((w) => w.toString(16)).join(':'))}/${ipv6PrefixLen}`;
}

function parseCidr(entry: string): ParsedCidr {
  const m = /^(.+)\/(\d{1,3})$/.exec(entry);
  const addr = m ? m[1] : entry;
  const family = net.isIP(addr);
  if (family === 0) throw new Error(`TRUST_PROXY_CIDRS: "${entry}" is not an IP address or CIDR`);
  if (family === 6 && /^::ffff:/i.test(addr)) {
    throw new Error(`TRUST_PROXY_CIDRS: "${entry}" — write IPv4 proxy hops as IPv4 (a.b.c.d), not IPv4-mapped IPv6`);
  }
  const maxPrefix = family === 4 ? 32 : 128;
  const prefix = m ? Number(m[2]) : maxPrefix;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix) {
    throw new Error(`TRUST_PROXY_CIDRS: "${entry}" has an invalid prefix length`);
  }
  // A /0 hop would make every TCP peer a trusted proxy, i.e. any client could
  // choose its own IP. Refuse it: hops must be listed explicitly.
  if (prefix === 0) {
    throw new Error(`TRUST_PROXY_CIDRS: "${entry}" matches every address; list the proxy hops explicitly`);
  }
  return { addr, prefix, family: family === 4 ? 'ipv4' : 'ipv6' };
}

/**
 * Reads TRUST_PROXY / TRUST_PROXY_CIDRS. Throws on anything ambiguous so the
 * collator refuses to start instead of silently trusting or ignoring headers.
 */
export function parseTrustedProxyConfig(env: NodeJS.ProcessEnv): TrustedProxyConfig {
  const raw = String(env.TRUST_PROXY ?? '').trim();
  if (raw !== '' && raw !== '0' && raw !== '1') {
    throw new Error(`TRUST_PROXY must be 0 or 1 (got "${raw}")`);
  }
  const enabled = raw === '1';
  const cidrs = String(env.TRUST_PROXY_CIDRS ?? '').split(/[\s,]+/).filter(Boolean);
  for (const entry of cidrs) parseCidr(entry);
  if (!enabled && cidrs.length > 0) {
    throw new Error('TRUST_PROXY_CIDRS is set but TRUST_PROXY is not 1; set TRUST_PROXY=1 or unset TRUST_PROXY_CIDRS');
  }
  if (enabled && cidrs.length === 0) {
    throw new Error('TRUST_PROXY=1 requires TRUST_PROXY_CIDRS (the reverse proxy / CDN hop addresses)');
  }
  return { enabled, cidrs };
}

export function createClientIpResolver(cfg: TrustedProxyConfig): ClientIpResolver {
  const hops = new net.BlockList();
  for (const entry of cfg.cidrs) {
    const { addr, prefix, family } = parseCidr(entry);
    hops.addSubnet(addr, prefix, family);
  }

  const isTrustedHop = (ip: string): boolean => {
    if (!cfg.enabled || !ip) return false;
    return hops.check(ip, net.isIP(ip) === 6 ? 'ipv6' : 'ipv4');
  };

  const header = (req: Pick<http.IncomingMessage, 'headers'>, name: string): string => {
    const v = req.headers[name];
    return typeof v === 'string' ? v : '';
  };

  const peerOf = (req: Pick<http.IncomingMessage, 'socket'>): string => normalizeIp(req.socket?.remoteAddress || '');

  return {
    headersTrusted(req) {
      return isTrustedHop(peerOf(req));
    },
    resolve(req) {
      const peer = peerOf(req);
      // Headers are only believed when the TCP peer is one of our proxy hops.
      if (!isTrustedHop(peer)) return peer;

      // The only client-IP header believed is X-Forwarded-For. Each hop appends
      // the address it received the request from, so walking right to left past
      // our own hops reaches the first address no trusted hop vouches for. The
      // leftmost entries are client-controlled and are never consulted.
      // Single-valued headers (cf-connecting-ip, x-real-ip) are deliberately
      // ignored: a proxy that does not overwrite them passes a client-chosen
      // value straight through. Malformed entries fail closed to the peer.
      const xff = header(req, 'x-forwarded-for').split(',').map((s) => s.trim()).filter(Boolean);
      for (let i = xff.length - 1; i >= 0; i--) {
        const ip = normalizeIp(xff[i]);
        if (!ip) return peer;
        if (!isTrustedHop(ip)) return ip;
      }
      return peer;
    },
  };
}
