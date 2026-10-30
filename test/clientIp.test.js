import test from 'node:test';
import assert from 'node:assert/strict';

import { clientKeyForIp, createClientIpResolver, normalizeIp, parseTrustedProxyConfig } from '../dist/clientIp.js';

const req = (remoteAddress, headers = {}) => ({ socket: { remoteAddress }, headers });

test('config: TRUST_PROXY unset means headers are never believed', () => {
  assert.deepEqual(parseTrustedProxyConfig({}), { enabled: false, cidrs: [] });
});

test('config: TRUST_PROXY=1 without TRUST_PROXY_CIDRS refuses to start', () => {
  assert.throws(() => parseTrustedProxyConfig({ TRUST_PROXY: '1' }), /requires TRUST_PROXY_CIDRS/);
});

test('config: unrecognised TRUST_PROXY values are refused, not treated as off', () => {
  assert.throws(() => parseTrustedProxyConfig({ TRUST_PROXY: 'true', TRUST_PROXY_CIDRS: '10.0.0.1' }), /must be 0 or 1/);
});

test('config: TRUST_PROXY_CIDRS without TRUST_PROXY=1 is an ambiguous setup and is refused', () => {
  assert.throws(() => parseTrustedProxyConfig({ TRUST_PROXY_CIDRS: '10.0.0.1' }), /TRUST_PROXY is not 1/);
});

test('config: malformed CIDR entries are refused', () => {
  for (const bad of ['not-an-ip', '10.0.0.0/33', '2001:db8::/129', '::ffff:10.0.0.1', '10.0.0.0/']) {
    assert.throws(() => parseTrustedProxyConfig({ TRUST_PROXY: '1', TRUST_PROXY_CIDRS: bad }), /TRUST_PROXY_CIDRS/, bad);
  }
});

test('config: valid explicit configuration parses', () => {
  assert.deepEqual(
    parseTrustedProxyConfig({ TRUST_PROXY: '1', TRUST_PROXY_CIDRS: '10.0.0.1, 192.168.0.0/16 2001:db8::/32' }),
    { enabled: true, cidrs: ['10.0.0.1', '192.168.0.0/16', '2001:db8::/32'] },
  );
});

test('N3: a direct client cannot spoof its IP with proxy headers', () => {
  const r = createClientIpResolver({ enabled: true, cidrs: ['10.0.0.0/8'] });
  const spoofed = req('198.51.100.7', {
    'cf-connecting-ip': '203.0.113.1',
    'x-real-ip': '203.0.113.2',
    'x-forwarded-for': '203.0.113.3',
  });
  assert.equal(r.resolve(spoofed), '198.51.100.7');
  assert.equal(r.headersTrusted(spoofed), false);
});

test('N3: with no trusted hops configured, headers are ignored entirely', () => {
  const r = createClientIpResolver({ enabled: false, cidrs: [] });
  assert.equal(r.resolve(req('198.51.100.7', { 'x-forwarded-for': '203.0.113.3' })), '198.51.100.7');
});

test('N3: single-valued client-IP headers are never believed, even from a trusted hop', () => {
  // A proxy that only appends X-Forwarded-For passes a client-chosen
  // X-Real-IP / CF-Connecting-IP straight through; trusting it would let every
  // request pick a fresh IP and escape all per-IP limits.
  const r = createClientIpResolver({ enabled: true, cidrs: ['10.0.0.1/32'] });
  assert.equal(r.resolve(req('10.0.0.1', { 'cf-connecting-ip': '203.0.113.9' })), '10.0.0.1');
  assert.equal(r.resolve(req('10.0.0.1', { 'x-real-ip': '203.0.113.8' })), '10.0.0.1');
  assert.equal(r.resolve(req('10.0.0.1', { 'x-real-ip': '203.0.113.8', 'x-forwarded-for': '198.51.100.7' })), '198.51.100.7');
  assert.equal(r.headersTrusted(req('10.0.0.1')), true);
});

test('config: a /0 trusted hop (matches every peer) is refused', () => {
  assert.throws(() => parseTrustedProxyConfig({ TRUST_PROXY: '1', TRUST_PROXY_CIDRS: '0.0.0.0/0' }), /too broad/);
  assert.throws(() => parseTrustedProxyConfig({ TRUST_PROXY: '1', TRUST_PROXY_CIDRS: '::/0' }), /too broad/);
});

test('N3: X-Forwarded-For is walked right to left past trusted hops; a client-prepended entry is ignored', () => {
  const r = createClientIpResolver({ enabled: true, cidrs: ['10.0.0.0/24'] });
  // Client 203.0.113.9 went through a second trusted hop 10.0.0.5.
  assert.equal(r.resolve(req('10.0.0.1', { 'x-forwarded-for': '203.0.113.9, 10.0.0.5' })), '203.0.113.9');
  // The leftmost entry is client-controlled; only the entry appended by our hop counts.
  assert.equal(r.resolve(req('10.0.0.1', { 'x-forwarded-for': '6.6.6.6, 203.0.113.9' })), '203.0.113.9');
});

test('N3: a malformed XFF entry fails closed to the peer address', () => {
  const r = createClientIpResolver({ enabled: true, cidrs: ['10.0.0.1/32'] });
  assert.equal(r.resolve(req('10.0.0.1', { 'x-forwarded-for': '203.0.113.9, not-an-ip' })), '10.0.0.1');
});

test('N4 input: IPv4-mapped socket addresses resolve to the same client key as plain IPv4', () => {
  const r = createClientIpResolver({ enabled: true, cidrs: ['10.0.0.0/24'] });
  assert.equal(normalizeIp('::ffff:198.51.100.7'), '198.51.100.7');
  assert.equal(r.resolve(req('::ffff:198.51.100.7')), '198.51.100.7');
  assert.equal(r.resolve(req('::ffff:10.0.0.1', { 'x-forwarded-for': '203.0.113.9' })), '203.0.113.9');
});

test('N4 input: hex-spelled IPv4-mapped IPv6 canonicalizes to the dotted IPv4 key', () => {
  // Without this, `::ffff:0a00:0001` in a header would be keyed separately from
  // 10.0.0.1 and be treated as a different client.
  assert.equal(normalizeIp('::ffff:a00:1'), '10.0.0.1');
  assert.equal(normalizeIp('::FFFF:0A00:0001'), '10.0.0.1');
  assert.equal(normalizeIp('2001:DB8::1'), '2001:db8::1');
  assert.equal(normalizeIp('fe80::1%eth0'), '', 'zone-scoped addresses are not client IPs');
});

test('IPv6 trusted hop', () => {
  const r = createClientIpResolver({ enabled: true, cidrs: ['2001:db8::/32'] });
  assert.equal(r.resolve(req('2001:db8::1', { 'x-forwarded-for': '203.0.113.9' })), '203.0.113.9');
  assert.equal(r.resolve(req('2001:db9::1', { 'x-forwarded-for': '203.0.113.9' })), '2001:db9::1');
});

test('N3: spoofed X-Real-IP with an appended X-Forwarded-For resolves to the appended client', () => {
  const r = createClientIpResolver({ enabled: true, cidrs: ['127.0.0.1/32'] });
  const attack = req('127.0.0.1', { 'x-forwarded-for': '198.51.100.7', 'x-real-ip': '203.0.113.1' });
  assert.equal(r.resolve(attack), '198.51.100.7');
});

// Limiter identity. Every per-client budget keys on clientKeyForIp(ip, prefixLen).
test('client key: two IPv6 addresses in the same /64 are one client', () => {
  assert.equal(
    clientKeyForIp('2001:db8:1:2::1', 64),
    clientKeyForIp('2001:db8:1:2:ffff:ffff:ffff:fffe', 64),
  );
  // Same /64, different spellings of the same address still agree.
  assert.equal(clientKeyForIp('2001:0db8:0001:0002:0000:0000:0000:0001', 64), clientKeyForIp('2001:db8:1:2::1', 64));
});

test('client key: different /64 prefixes are different clients', () => {
  assert.notEqual(clientKeyForIp('2001:db8:1:2::1', 64), clientKeyForIp('2001:db8:1:3::1', 64));
});

test('client key: IPv4-mapped IPv6 is the embedded IPv4 in either spelling', () => {
  assert.equal(clientKeyForIp('::ffff:203.0.113.5', 64), clientKeyForIp('203.0.113.5', 64));
  assert.equal(clientKeyForIp('::ffff:cb00:7105', 64), clientKeyForIp('203.0.113.5', 64));
  assert.equal(clientKeyForIp('203.0.113.5', 64), 'ip:203.0.113.5');
});

test('client key: IPv4 addresses are never collapsed', () => {
  assert.notEqual(clientKeyForIp('203.0.113.5', 64), clientKeyForIp('203.0.113.6', 64));
});

test('client key: the prefix length is the configured one', () => {
  assert.equal(clientKeyForIp('2001:db8:1:2:aaaa::1', 48), clientKeyForIp('2001:db8:1:ffff::9', 48));
  assert.equal(clientKeyForIp('2001:db8:1:2:aaaa::1', 64), clientKeyForIp('2001:db8:1:2:bbbb::1', 64));
  assert.notEqual(clientKeyForIp('2001:db8:1:2::1', 128), clientKeyForIp('2001:db8:1:2::2', 128));
});

test('client key: an unparseable or empty address keys to one shared unknown bucket', () => {
  assert.equal(clientKeyForIp('', 64), 'ip:unknown');
  assert.equal(clientKeyForIp('not-an-ip', 64), 'ip:unknown');
});

test('client key: prefix length outside 32..128 is refused', () => {
  for (const bad of [31, 129, 64.5, Number.NaN]) {
    assert.throws(() => clientKeyForIp('2001:db8::1', bad), /CLIENT_IPV6_PREFIX_LEN/, String(bad));
  }
});
