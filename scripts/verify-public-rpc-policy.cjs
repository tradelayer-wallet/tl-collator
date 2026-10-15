#!/usr/bin/env node
/* eslint-disable no-console */
const fs = require('node:fs');
const path = require('node:path');

// Needles are matched against code only. Comments are blanked (offsets and
// newlines kept) with the repo's own TypeScript scanner, so a policy line that
// survives only inside a comment does not satisfy the check.
const ts = require('typescript');
function codeOnly(source) {
  const scanner = ts.createScanner(ts.ScriptTarget.Latest, false, ts.LanguageVariant.Standard, source);
  const out = source.split('');
  const braces = []; // 'T' = open template literal substitution, '{' = plain brace
  for (let kind = scanner.scan(); kind !== ts.SyntaxKind.EndOfFileToken; kind = scanner.scan()) {
    if (kind === ts.SyntaxKind.SingleLineCommentTrivia || kind === ts.SyntaxKind.MultiLineCommentTrivia) {
      for (let i = scanner.getTokenPos(); i < scanner.getTextPos(); i++) if (out[i] !== '\n') out[i] = ' ';
    } else if (kind === ts.SyntaxKind.TemplateHead) {
      braces.push('T');
    } else if (kind === ts.SyntaxKind.OpenBraceToken) {
      braces.push('{');
    } else if (kind === ts.SyntaxKind.CloseBraceToken && braces.pop() === 'T') {
      if (scanner.reScanTemplateToken(false) === ts.SyntaxKind.TemplateMiddle) braces.push('T');
    }
  }
  return out.join('');
}

const collatorPath = path.resolve(__dirname, '..', 'src', 'index.ts');
const canonicalPath = path.resolve(__dirname, '..', 'src', 'canonical.ts');
const clientIpPath = path.resolve(__dirname, '..', 'src', 'clientIp.ts');
const schemaPath = path.resolve(__dirname, '..', 'src', 'schema.ts');
const orderSchemaPath = path.resolve(__dirname, '..', 'spec', 'schemas', 'order-envelope.v1.schema.json');
// The relayer checkout is a sibling of this repo (contrib/tl-relayer when both
// are cloned side by side); TL_RELAYER_RPC_ROUTE_SOURCE overrides the location.
const relayerPath = process.env.TL_RELAYER_RPC_ROUTE_SOURCE
  || path.resolve(__dirname, '..', '..', 'tl-relayer', 'src', 'routes', 'rpc.route.ts');
const collator = codeOnly(fs.readFileSync(collatorPath, 'utf8'));
const canonical = codeOnly(fs.readFileSync(canonicalPath, 'utf8'));
const clientIpSrc = codeOnly(fs.readFileSync(clientIpPath, 'utf8'));
const admissionSrc = codeOnly(fs.readFileSync(path.resolve(__dirname, '..', 'src', 'orderAdmission.ts'), 'utf8'));
const configSrc = codeOnly(fs.readFileSync(path.resolve(__dirname, '..', 'src', 'config.ts'), 'utf8'));
const schemaSrc = codeOnly(fs.readFileSync(schemaPath, 'utf8'));
const orderSchema = fs.readFileSync(orderSchemaPath, 'utf8');
if (!fs.existsSync(relayerPath)) {
  throw new Error(`relayer RPC route source not found: ${relayerPath} (set TL_RELAYER_RPC_ROUTE_SOURCE)`);
}
const relayer = codeOnly(fs.readFileSync(relayerPath, 'utf8'));

function methodsFrom(source, name) {
  const block = source.match(new RegExp(`const ${name} = new Set\\(\\[([\\s\\S]*?)\\]\\);`));
  if (!block) throw new Error(`Missing ${name}`);
  return [...block[1].matchAll(/'([^']+)'/g)].map(([, method]) => method);
}

const collatorMethods = methodsFrom(collator, 'PUBLIC_RPC_METHODS');
const relayerMethods = methodsFrom(relayer, 'PUBLIC_RPC_METHODS');
const required = [
  'tl_getstatesnapshot',
  'tl_getsyncstatus',
  'tl_getallbalancesforaddress',
  'tl_listproperties',
  'tl_watchonly_register',
  'tl_watchonly_utxos',
  'tl_createpayload_attestation',
  'tl_createpayload_commit_tochannel',
];
const prohibited = /(?:sign|privatekey|dumpprivkey|importprivkey|walletpassphrase|loadwallet|unloadwallet|finalizepsbt|sendrawtransaction|broadcast|sendtoaddress|addmultisig)/i;

// Read-only bitcoin-family RPCs backing the documented HTTP compat routes
// (/chain/info, /address/validate/*, /address/utxo/*, /tx/decode). These MUST
// stay on the collator allowlist: with the legacy proxy disabled (H2) they
// fall through to the WebRTC-routed path, and the README documents that.
const readOnlyCompat = ['getblockchaininfo', 'validateaddress', 'listunspent', 'decoderawtransaction'];

for (const method of [...collatorMethods, ...relayerMethods]) {
  if (prohibited.test(method)) throw new Error(`Prohibited public RPC method: ${method}`);
}
for (const method of required) {
  if (!collatorMethods.includes(method) || !relayerMethods.includes(method)) {
    throw new Error(`Required public method missing: ${method}`);
  }
}
for (const method of readOnlyCompat) {
  if (!collatorMethods.includes(method)) {
    throw new Error(`Required read-only compat RPC method missing from collator: ${method}`);
  }
}

for (const needle of [
  'if (!Array.isArray(service.methods) || service.methods.length === 0) continue;',
  "code: 'RPC_ADVERTISEMENT_REJECTED'",
  'TL_COLLATOR_CORS_ORIGINS',
  'TL_COLLATOR_ENABLE_LEGACY_TL_PROXY',
  "code: 'LEGACY_TL_PROXY_DISABLED'",
  "code: 'RPC_SERVICE_FORBIDDEN'",
  "code: 'RPC_METHOD_FORBIDDEN'",
  "'tl_watchonly_register'",
  "'tl_watchonly_utxos'",
  "'/tx/buildUnsigned'",
  "'/tx/buildunsigned'",
  "'/tx/build-unsigned'",
  "proxyLegacyJson('POST', u.pathname, body)",
  // Security batch 1 (issue #1): legacy proxy master switch + faucet opt-in (H2),
  // trusted-proxy gating for client IP headers (H1), orderId binding (C1),
  // RPC_RES provider binding and pending-RPC caps (C2).
  'LEGACY_PROXY_ENABLED',
  "code: 'LEGACY_PROXY_DISABLED'",
  'LEGACY_PROXY_FAUCET',
  "code: 'LEGACY_PROXY_FAUCET_DISABLED'",
  'clientIpResolver.resolve(req)',
  'clientIpResolver.headersTrusted(req)',
  'net.isIP(ip) === 0',
  // Adversarial review fixes (batch 2): envelope-bound orderId (C1 complete),
  // endpoint allowlist regression (H2), connection fairness (H3b), TAPE_SUB
  // subscription survival, XFF rightmost hop, per-session pending RPC cap.
  'admitOrder(cfg, { tape, intel: ipIntel, clearlist }, sess.meta, order)',
  "'getblockchaininfo'",
  "'validateaddress'",
  "'listunspent'",
  "'decoderawtransaction'",
  'sess.wantsTape = true;',
  "code: 'rate_limited', msg: 'TAPE_SUB resync too frequent; live feed stays subscribed'",
  'for (const key of admissionKeys) rpcAdmission.acquire(key);',
  "const tapeResyncGate = new MinIntervalGate(",
  // Limiter identity (one key for every per-client budget): IPv6 collapses to its
  // prefix, and the HTTP table is bounded and never resets a client on eviction.
  "const clientKey = (ip: string): string => clientKeyForIp(ip, cfg.clientIpv6PrefixLen);",
  "const ipKey = clientKey(remoteIp);",
  "const ipKey = clientKey(caller.ip);",
  "const httpRpcBuckets = new KeyedTokenBuckets({",
  "event: 'http-bucket-table-full'",
  "const admissionKeys = sessionKey ? [sessionKey, ipKey] : [ipKey];",
  "!HTTP_UNLIMITED_PATHS.has(u.pathname) && !httpRpcAllowed(clientIp)",
  "code: 'RPC_RATE_LIMITED'",
  "message: 'internal error'",
  'pendingRpcMaxPerSession',
  'if (!entry) {',
  "'RPC_SESSION_OVERLOADED'",
  'releasePending(pendingKey)',
  'settleRpcResponse(wm.res, sess)',
  'pending.provider !== sender',
  'pendingRpc.size >= pendingRpcMax',
]) {
  if (!collator.includes(needle)) throw new Error(`Collator policy missing: ${needle}`);
}

// Single HTTP admission point: httpRpcAllowed has exactly one call site. That
// call is the whole gate statement (charge, 429, return, no extra condition),
// it sits at the top level of the request handler's async body (not nested in a
// route branch), and nothing that reads the body or contacts an upstream runs
// before it.
{
  const calls = [...collator.matchAll(/httpRpcAllowed\(/g)].map((m) => m.index);
  if (calls.length !== 1) throw new Error(`Expected one HTTP admission call site, found ${calls.length}`);
  const handler = collator.indexOf("server.on('request'");
  const gateAt = calls[0];
  if (handler < 0 || gateAt < handler) throw new Error('HTTP admission gate must sit inside the request handler');
  const gateStmt = /if \(!HTTP_UNLIMITED_PATHS\.has\(u\.pathname\) && !httpRpcAllowed\(clientIp\)\) \{\s*writeJson\(res, 429, httpRateLimitedBody\(u\.pathname\)\);\s*return;\s*\}/g;
  const gates = [...collator.matchAll(gateStmt)];
  if (gates.length !== 1) throw new Error(`HTTP admission gate statement must appear exactly once, found ${gates.length}`);
  const gateStart = gates[0].index;
  if (!(gateAt >= gateStart && gateAt < gateStart + gates[0][0].length)) throw new Error('httpRpcAllowed is not the gate statement');
  // Brace depth at the gate: the request listener body plus the async IIFE body
  // (two open blocks). Any deeper means the gate sits inside a route or condition.
  const scanner = ts.createScanner(ts.ScriptTarget.Latest, false, ts.LanguageVariant.Standard, collator.slice(handler, gateStart));
  const stack = [];
  for (let kind = scanner.scan(); kind !== ts.SyntaxKind.EndOfFileToken; kind = scanner.scan()) {
    if (kind === ts.SyntaxKind.TemplateHead) stack.push('T');
    else if (kind === ts.SyntaxKind.OpenBraceToken) stack.push('{');
    else if (kind === ts.SyntaxKind.CloseBraceToken && stack.pop() === 'T') {
      if (scanner.reScanTemplateToken(false) === ts.SyntaxKind.TemplateMiddle) stack.push('T');
    }
  }
  if (stack.length !== 2) throw new Error(`HTTP admission gate must be a top-level statement of the request handler (brace depth ${stack.length}, expected 2)`);
  const beforeGate = [
    ['readHttpJson(req', 'an HTTP body read'],
    ['proxyLegacyJson(', 'a legacy relayer call'],
    ['routeCompatRpcRequest(', 'a compat RPC call'],
    ['routeRpcRequest(', 'a routed RPC call'],
    ['ipIntel.lookup(', 'an IP intel lookup'],
    ['fetch(', 'an outbound fetch'],
  ];
  for (const [needle, what] of beforeGate) {
    const at = collator.indexOf(needle, handler);
    if (at >= 0 && at < gateStart) throw new Error(`${what} precedes the HTTP admission gate`);
  }
  // Exempt paths: exactly the three local status routes, no more.
  const unlimited = collator.match(/const HTTP_UNLIMITED_PATHS = new Set\(\[([^\]]*)\]\);/);
  if (!unlimited || unlimited[1].replace(/\s/g, '') !== "'/health','/manifest','/rpc/providers'") {
    throw new Error('HTTP_UNLIMITED_PATHS must be exactly /health, /manifest and /rpc/providers');
  }
}

// 413 path: the oversize body is refused with Connection: close, and the
// read-side error is the only thing that maps to 413.
for (const needle of [
  "res.setHeader('Connection', 'close');",
  "e instanceof RequestBodyTooLarge",
  "writeJson(res, 413, { ok: false, error: { code: 'BODY_TOO_LARGE', message: 'request body too large' } });",
]) {
  if (!collator.includes(needle)) throw new Error(`Collator policy missing: ${needle}`);
}

// Integer env vars: one bounded parser. No Math.max/min clamp around a parsed
// value, and every intEnv call declares its bounds (no two-argument form).
for (const [name, text] of [['config', configSrc], ['bitvmStatus', codeOnly(fs.readFileSync(path.resolve(__dirname, '..', 'src', 'bitvmStatus.ts'), 'utf8'))]]) {
  if (/Math\.(?:max|min)\(\s*-?\d+\s*,\s*intEnv\(/.test(text)) throw new Error(`${name}: integer env value is clamped instead of bounded`);
  if (/intEnv\('[A-Z_]+',\s*[^,()]+\)/.test(text)) throw new Error(`${name}: intEnv call without bounds`);
}

// Peer-facing errors carry fixed text; caught exception text is logged only.
for (const [name, text] of [['collator', collator], ['canonical', canonical], ['clientIp', clientIpSrc], ['config', configSrc], ['schema', schemaSrc]]) {
  // A key (not a property access such as `e.message`) bound to the caught value.
  if (/(?<![.\w])(?:message|msg|error)\s*:\s*(?:e|err)\??\.message|(?<![.\w])(?:message|msg|error)\s*:\s*String\((?:e|err)\)/.test(text)) {
    throw new Error(`${name}: caught error text is returned to a peer`);
  }
}

// Integer env vars go through the single strict parser (config.ts intEnv).
for (const [name, text] of [['collator', collator], ['config', configSrc]]) {
  if (/Number\(\s*process\.env|parseInt\(\s*process\.env/.test(text)) throw new Error(`${name}: integer env read bypasses intEnv`);
}
if (/Number\(\s*process\.env/.test(fs.readFileSync(path.resolve(__dirname, '..', 'src', 'bitvmStatus.ts'), 'utf8'))) {
  throw new Error('bitvmStatus: integer env read bypasses intEnv');
}

// canonical.ts: own-key-safe canonicalization + envelope-hash derivation.
// SUBMIT admission: one module decides every refusal, in order (orderAdmission.ts).
for (const needle of [
  'src.tape.hasOrder(order.orderId)',
  'computeEnvelopeHash(order)',
  "'bad_order_id'",
  "'INTEL_UNAVAILABLE'",
  "'CLEARLIST_DOWN'",
]) {
  if (!admissionSrc.includes(needle)) throw new Error(`Admission policy missing: ${needle}`);
}

for (const needle of [
  "new Set(['__proto__', 'constructor', 'prototype'])",
  'Object.create(null)',
  'Object.defineProperty',
  'const out: Record<string, unknown> = Object.create(null);',
  "if (k === 'orderId' || k === 'sigTrader') continue;",
  'envelopeSignedFields',
  'computeEnvelopeHash',
]) {
  if (!canonical.includes(needle)) throw new Error(`Canonical policy missing: ${needle}`);
}

// clientIp.ts: the single trusted-client-IP resolver; headers believed only from
// configured proxy hops, and proxy configuration refused at startup when ambiguous.
for (const needle of [
  'TRUST_PROXY_CIDRS',
  'TRUST_PROXY=1 requires TRUST_PROXY_CIDRS',
  'if (!isTrustedHop(peer)) return peer;',
  'export function clientKeyForIp(ip: string, ipv6PrefixLen: number): string {',
  'export const CLIENT_IPV6_PREFIX_DEFAULT = 64;',
]) {
  if (!clientIpSrc.includes(needle)) throw new Error(`Client IP policy missing: ${needle}`);
}
// Single-valued client-IP headers are never read, in any spelling.
if (/header\(\s*req\s*,\s*'(?:cf-connecting-ip|x-real-ip)'\s*\)/.test(clientIpSrc)) {
  throw new Error('Client IP policy: cf-connecting-ip / x-real-ip must not be believed');
}

// config.ts: admission caps are parsed strictly (startup aborts on garbage).
for (const needle of [
  "intEnv('CONN_MAX_PER_IP'",
  "intEnv('CLIENT_IPV6_PREFIX_LEN'",
  "intEnv('PENDING_RPC_MAX_PER_SESSION'",
  "intEnv('PENDING_RPC_MAX'",
  "intEnv('CONN_IDLE_TIMEOUT_MS'",
  "intEnv('CONN_HANDSHAKE_GRACE_MS'",
  'throw new Error(`${k} must be an integer',
]) {
  if (!configSrc.includes(needle)) throw new Error(`Config policy missing: ${needle}`);
}

// schema.ts: unsafe-key rejection before schema validation.
for (const needle of ['findCanonicalViolation', 'validateOrderEnvelope']) {
  if (!schemaSrc.includes(needle)) throw new Error(`Schema policy missing: ${needle}`);
}

// order-envelope schema: unsafe keys rejected at the JSON-Schema layer too.
for (const needle of ['"propertyNames"', '"__proto__"', '"constructor"', '"prototype"']) {
  if (!orderSchema.includes(needle)) throw new Error(`Order schema policy missing: ${needle}`);
}

for (const needle of [
  'async function handleAllocatedRpc',
  'PUBLIC_RPC_METHODS.has(normalizedMethod)',
  "'PAYLOAD_TYPE_FORBIDDEN'",
  "'RPC_METHOD_FORBIDDEN'",
  "'tl_watchonly_register'",
  "'tl_watchonly_utxos'",
]) {
  if (!relayer.includes(needle)) throw new Error(`Relayer policy missing: ${needle}`);
}

console.log(JSON.stringify({
  ok: true,
  collatorMethodCount: collatorMethods.length,
  relayerMethodCount: relayerMethods.length,
  collatorOnlyMethods: collatorMethods.filter((method) => !relayerMethods.includes(method)),
  required,
  readOnlyCompat,
}, null, 2));
