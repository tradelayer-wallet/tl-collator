# tl-collator (MVP)

One-process TradeLayer collator node:

- WebSocket signaling server (ws or wss)
- WebRTC RTCPeerConnection per wallet, DataChannel transport
- Append-only tape (NDJSON) with hash-chain + collator signature
- Broadcast `TAPE_ENTRY` to subscribers

This implementation matches the desktop wallet protocol in:

- `SIGNAL_*` messages: `SIGNAL_HELLO`, `SIGNAL_OFFER`, `SIGNAL_ANSWER`, `SIGNAL_ICE`, `SIGNAL_ERR`
- DataChannel `WireMsg`: `HELLO`, `SUBMIT`, `TAPE_SUB`, `TAPE_ENTRY`, `PING`, `PONG`, `ERR`

## Run

```powershell
cd C:\projects\tl-collator
npm i
npm run dev
```

Default listens on `ws://0.0.0.0:8787/ws`.
Wallet and peer handshakes must use the full websocket URL, including the `/ws`
path. If you pass only a host or `host:port` to `COLLATOR_WS`, the peer helper
now normalizes it to `/ws` automatically.

HTTP endpoints on the same port:

- `GET /health`
- `GET /manifest` (TL-CSv1 manifest, signed by collator key)
- `GET /rpc/providers` (currently advertised WebRTC RPC providers)
- `POST /rpc/route` (HTTP gateway into WebRTC-routed full-node RPC)

Relayer compatibility endpoints are also exposed so older TL-Web wiring can
keep working without changing its base URL:

- `POST /relayer/rpc/:method`
- `POST /rpc/:method`
- `POST /tl_*` legacy listener endpoints
- `GET /address/validate/:address`
- `GET /address/balance/:address`
- `GET /address/faucet/:address`
- `POST /address/utxo/:address`
- `GET /chain/info`
- `GET /tx/:txid`
- `POST /tx/decode`
- `POST /tx/sendTx`
- `POST /tx/buildTx`
- `POST /tx/multisig`
- `POST /tx/buildTradeTx`
- `POST /tx/buildLTCTradeTx`
- `POST /tx/finalizePsbt`
- `GET /token/list`
- `GET /token/:propid`

Note: all legacy relayer proxy routes are **disabled by default** and require
`LEGACY_PROXY_ENABLED=1` (see Configure). Routes that have a WebRTC-routed RPC
fallback transparently use the allowlisted routed path while the proxy is off —
`GET /chain/info` → `getblockchaininfo`, `GET /address/validate/:address` →
`validateaddress`, `POST /address/utxo/:address` → `listunspent`, and
`POST /tx/decode` → `decoderawtransaction` are all on the public RPC allowlist
for exactly this reason.

## Order submission and `orderId` derivation

`SUBMIT` envelopes must follow the TL-Canon v1 derivation rule (see
`spec/schemas/tl-canon-v1.md`):

```
orderId   = sha256(stableStringify(envelope minus orderId/sigTrader))   (lowercase hex)
sigTrader = secp256k1 compact signature (64 bytes hex) over the 32 raw bytes of orderId
```

That is, `orderId` is derived over **every envelope field except `orderId` and
`sigTrader`** — `v`, `kind`, `body`, `traderPubKey`, `clientNonce`, and
`cancelsOrderId` / `replacesOrderId` when present. The collator verifies
`sigTrader` over `orderId` **and** rejects any envelope whose `orderId` does
not match the canonical derivation (`ERR` code `bad_order_id`). This binds the
trader signature to the complete order intent: a harvested
`(orderId, sigTrader, traderPubKey)` triple can never be replayed with a
different `body`, and a tape-harvested `NEW` order can never be re-submitted as
a forged `CANCEL`/`REPLACE` of another trader's order.

⚠️ **BREAKING:** an earlier revision of this PR derived `orderId` from `body`
alone (`sha256(stableStringify(body) + traderPubKey + clientNonce)`), leaving
`kind`/`cancelsOrderId`/`replacesOrderId` outside the signature. Clients must
adopt the envelope-hash convention above (identical to
`scripts/smoke-live-flow.cjs`). Envelopes derived the old way are rejected with
`bad_order_id`. Worked test vectors: `spec/test-vectors.json` (checked by
`npm test`).

Envelopes carrying `__proto__`, `constructor` or `prototype` keys anywhere
(including inside `body`/`visibility`) are rejected as schema-invalid; the
canonicalizer hashes such keys as ordinary own keys and never treats them as
prototypes.

## Configure

Environment variables:

Integer variables must be plain decimal integers (optional sign and surrounding whitespace only; no `0x`, exponents, separators or units) inside their documented range. Anything else, including a negative cap or a zero where a value of at least 1 is required, aborts startup instead of being clamped, dropped or silently disabling a check.


- `PORT` (default: `8787`, `SERVER_PORT` is accepted as a legacy alias)
- `WS_PATH` (default: `/ws`)
- `DATA_DIR` (default: `./data`)
- `TAPE_PATH` (default: `./data/tape.log`)
- `TAPE_INDEX_PATH` (default: `./data/tape.idx`)
- `TAPE_INDEX_STRIDE` (default: `1000`)
- `TAPE_REPLAY_BATCH` (default: `500`)
- `COLLATOR_KEY_PATH` (default: `./data/collator.key`)
- `MAX_MSG_BYTES` (default: `1048576`)
- `SUBMIT_BURST` (default: `10`) and `SUBMIT_RPS` (default: `2`) (also accepts legacy `SUBMIT_RATE_PER_SEC`)
- `SUBMIT_CLIENT_BURST` (default: `40`) and `SUBMIT_CLIENT_RPS` (default: `8`): the SUBMIT budget of one client (limiter key, see below), shared by all of that client's sessions. Each SUBMIT is charged to its session and to its client, so opening more sessions does not raise a client's rate.
- `TAPE_RESYNC_MAX_ENTRIES` (default: `10000`): a `TAPE_SUB` resync replays at most this many of the newest tape entries. The `TAPE_END` reply carries `fromSeq`, the first seq actually replayed; when it is greater than the requested `fromSeq` the earlier history was not sent and must be fetched another way.
- `NAME`, `OPERATOR`, `REGION` (optional manifest fields)
- `CONN_MAX` (hard cap on concurrent WS connections, default `256`; set `0` to disable the cap)
- `CONN_MAX_PER_IP` (default `16`; per-client sub-cap on concurrent WS connections, where a client is defined by the limiter key below; `0` disables) — one source cannot hold a large share of the pool
- `CONN_IDLE_TIMEOUT_MS` (default `60000`): sessions with no open DataChannel and no traffic for this long are closed (WS `1013`)
- `CONN_SWEEP_INTERVAL_MS` (default `15000`): idle-reaper sweep interval
- `CONN_HANDSHAKE_GRACE_MS` (default `5000`): fresh connections younger than this are never displaced by the handshake reserve; when `CONN_MAX` is reached, new handshakes displace the oldest silent (no-DataChannel) session instead of being refused — only a pool of fully-established sessions returns `1013`
- `CLEARLIST_ENFORCE` (`0|1`, default `0`)
- `CLEARLIST_URL` (required if `CLEARLIST_ENFORCE=1`; expects `POST /clearlist/check`)
- `CLEARLIST_FAIL_MODE` (`closed|open`, default `closed`)
- `IP_LOGGING` (`off|on` or `0|1`, default `off`) writes submit audit NDJSON to `./data/audit.log`
- `IP_INTEL_URL` (optional; enables vpn/asn policy hooks; expects `POST {ip}` returning `{asn?:number,vpn?:boolean}`)
- `IP_INTEL_TTL_SEC` (default `300`)
- `VPN_FILTER_MODE` (`off|log|reject`, default `off`; effective only if `IP_INTEL_URL` is set)
- `ASN_BLOCK_MODE` (`off|log|reject`, default `off`; effective only if `IP_INTEL_URL` is set)
- `ASN_BLOCKLIST` (comma-separated ints; used when `ASN_BLOCK_MODE` != `off`)
- `ICE_SERVERS_JSON` (default: a couple public STUN servers)
- `TL_RELAY_COMPAT_UPSTREAM_URL` (legacy relayer upstream, defaults to `http://127.0.0.1:3000`)
- `TL_WALLET_LISTENER_URL` is also honored as the upstream fallback for legacy listener routes
- `LEGACY_PROXY_ENABLED` (`0|1`, default `0`): master switch for all legacy relayer proxy routes (`/address/*`, `/tx/*`, `/token/*`, `/chain/info`, `/rpc/:method` fallback, `/attestation/ip` forwarding, `/tl_*`). Off by default because these paths bypass the public RPC allowlist. Enable only for a trusted local relayer.
- `LEGACY_PROXY_FAUCET` (`0|1`, default `0`): additionally required to proxy `GET /address/faucet/:address`. This is a fund-moving endpoint — never enable it on an untrusted network.
- `TRUST_PROXY` (`0|1`, default `0`): whether client-IP headers may be believed at all. Any other value aborts startup. **Behind a reverse proxy or CDN, set `TRUST_PROXY=1` together with `TRUST_PROXY_CIDRS`**; `TRUST_PROXY=1` without `TRUST_PROXY_CIDRS` aborts startup (before this change it was accepted and trusted any peer).
- `TRUST_PROXY_CIDRS` (comma- or space-separated IPv4/IPv6 addresses or CIDRs, required with `TRUST_PROXY=1`, refused without it; IPv4-mapped IPv6 entries are refused, write IPv4 hops as IPv4): the proxy/CDN hop addresses. Headers are believed **only** when the TCP peer is inside this list. Then `x-forwarded-for` is walked right to left past trusted hops and the first untrusted entry is the client; `cf-connecting-ip` and `x-real-ip` are ignored, since a proxy that does not overwrite them passes a client-chosen value through. Malformed entries fail closed to the socket address. Client IPs are used for WS per-IP caps, HTTP rate limits, routed-RPC admission, IP intel and `/attestation/ip`.
- `PENDING_RPC_MAX` (default `1000`): cap on concurrent in-flight routed RPC requests.
- `PENDING_RPC_MAX_PER_IP` (default `256`, `0` disables): cap on outstanding routed RPC requests per client (limiter key below), across all of that client's sessions and HTTP calls.
- `PENDING_RPC_MAX_PER_SESSION` (default `32`, `0` disables): cap on outstanding routed RPC requests per requester, so one requester (or a colluding pair with a pinned provider) cannot fill the global pool and starve other callers. A WebSocket requester is counted per session (`RPC_SESSION_OVERLOADED`); an HTTP caller is counted per resolved client IP (`RPC_IP_OVERLOADED`, HTTP 429).
- **Client limiter key.** Every per-client budget, cap and aggregation (WS per-client cap, HTTP token bucket, routed-RPC admission, `TAPE_SUB` resync gate) is keyed on one derived value, not on the raw address: IPv4 → the address; IPv4-mapped IPv6 (`::ffff:a.b.c.d`) → the embedded IPv4; any other IPv6 → its prefix, `/64` by default. A residential or VPS customer holds a whole `/64`, so keying on the full address would give one customer 2^64 buckets. Logs and `/attestation/ip` still use the raw resolved address.
- `CLIENT_IPV6_PREFIX_LEN` (default `64`, integer `32`–`128`; anything else aborts startup): the IPv6 prefix length that defines one client. Lower values group more addresses into one budget (a `/48` makes a whole site share a budget); a value under `32` would merge whole ISP allocations and is refused.
- `HTTP_RPC_PER_IP_RPS` (default `20`) and `HTTP_RPC_PER_IP_BURST` (default `40`): one token bucket per client limiter key, charged once per request at the HTTP entry point for every route that reaches the mesh or the legacy relayer (`POST /rpc/route`, `POST /rpc/:method`, `POST /tl_bitvmStatus`, the compat GET/POST routes, `/attestation/ip`). Only `GET /health`, `GET /manifest` and `GET /rpc/providers` are local and uncharged. Exceeding it returns HTTP 429 `RPC_RATE_LIMITED`. Behind a proxy, set `TRUST_PROXY_CIDRS`, or every caller shares the proxy's bucket.
  - The bucket table holds at most 5000 clients. An entry is evicted only once it has fully refilled, so eviction never grants more than a fresh bucket would. When the table is full and no entry has refilled, a new client is charged to one shared overflow bucket (fail closed; logged at most once a minute as `http-bucket-table-full`). Churning through many addresses therefore cannot reset an exhausted client's budget.
  - `HTTP_RPC_GLOBAL_RPS` (default `0`, disabled) and `HTTP_RPC_GLOBAL_BURST` (default `200`): optional backstop over all clients together, charged only after a client's own bucket admits the request. It bounds total unauthenticated HTTP throughput when traffic comes from many prefixes; enabling it also throttles legitimate traffic beyond that rate.
- `TL_COLLATOR_RPC_SERVICE` / `TL_COLLATOR_RPC_NETWORK` tune routed RPC matching

### Security defaults

- Legacy relayer proxy is **disabled** unless `LEGACY_PROXY_ENABLED=1`; the faucet path additionally requires `LEGACY_PROXY_FAUCET=1`.
- Client IP is taken from the socket unless the peer is a configured `TRUST_PROXY_CIDRS` hop (see `TRUST_PROXY`); determined IPs are validated with `net.isIP` before use in `/attestation/ip`.
- Concurrent WS connections are capped by `CONN_MAX` (default `256`) and `CONN_MAX_PER_IP` (default `16`); silent (no-DataChannel) sessions idle for `CONN_IDLE_TIMEOUT_MS` (default 60 s) are reaped, and when the pool is full a fresh handshake displaces the oldest silent session (handshake reserve) instead of locking everyone out with `1013`.
- Each `SIGNAL_OFFER` closes/replaces the session's previous `RTCPeerConnection`; `TAPE_SUB` full re-reads are rate-limited to one per second per session — a rate-limited `TAPE_SUB` keeps the live subscription active and only skips the replay.
- Each `SIGNAL_OFFER` and each DataChannel open (adopted or refused) draws on one per-session budget (burst 3, one per second). An open past it gets `ERR` `rate_limited` and is closed. A channel refused with `ERR` `busy_retry` (a replay in flight on the connection) asks for its `TAPE_SUB` at least 1 s after that answer, the interval the `TAPE_SUB` gate charges per client IP.
- A channel carries one ordered tape stream: the replay, then the live entries, then `TAPE_END`. Live entries reach a channel only after its own `TAPE_SUB`, so a subscriber resubscribes on each new channel from its last received seq. A `TAPE_SUB` on the same channel supersedes the stream in flight and continues after the last seq that channel carried, so no seq is sent twice; `TAPE_END.fromSeq` is where the stream started. A request below what the channel already carried, a stream that stalls, a stream past `DC_REPLAY_MAX_MS` (120 s), or live entries held past `DC_REPLAY_MAX_HELD_BYTES` (4 MiB) closes the channel with no `TAPE_END`; a held-bytes overflow sends `ERR` `resync_required` first. The subscriber then resubscribes on a new channel.
- `RPC_RES` is only accepted from the session the request was routed to; pending routed RPCs are namespaced per provider session, capped globally by `PENDING_RPC_MAX` and per requester (session, or client IP for HTTP) by `PENDING_RPC_MAX_PER_SESSION`.
- A `SUBMIT` whose `orderId` is already on the tape (including orders recorded before a restart) is refused with `DUPLICATE`; the check is made atomically at append time.
- The generated collator key file is written with mode `0600`.

Infra attestations (optional; used by wallets for curated-mode acceptability):

- `INFRA_ATTESTATIONS_PATH` (default: `./data/infra-attestations.json`, loaded if the file exists)
- `INFRA_ATTESTATIONS_JSON` (inline JSON array; if set, overrides file loading)

Generate/sign attestation entries:

```powershell
$env:ADMIN_KEY_FILE = "./data/admin.key"   # file with the 32-byte hex admin private key
npm run infra:sign -- `
  --ws ws://127.0.0.1:8787/ws `
  --clearlist-id 42 `
  --admin-pubkey 02... `
  --collator-key ./data/collator.key `
  --expires-in-days 30 `
  --out ./data/infra-attestations.json
```

The admin private key is read from `ADMIN_KEY_FILE` (path to a hex-key file) or
`ADMIN_KEY` (raw hex). The legacy `--admin-privkey` CLI argument still works but
is deprecated (exposed via `ps`/shell history) and prints a warning.

The command writes/updates an `InfraAttestationV1` array and upserts by
`(ws, clearlistId, infraId)` to avoid duplicates.

Run local failover smoke test:

```powershell
npm run smoke:failover
```

Optional overrides:

```powershell
npm run smoke:failover -- --port-a 8787 --port-b 8788 --retries 3
```

Note: on some Windows + `wrtc` builds, the child test process can crash during
native teardown *after* printing a successful JSON result. The wrapper script
handles this and still returns success when `{ "ok": true }` was emitted.

### WebRTC-routed full-node RPC

Wallets can call `POST /rpc/route` and let the collator forward the request to
a WebRTC peer that advertised a matching full-node RPC service over the
DataChannel. This keeps wallet RPC transport stable while the full-node peer can
be NATed and reachable only through the gossip/signaling fabric.

Start a local TradeLayer RPC provider peer:

```powershell
$env:COLLATOR_WS="ws://127.0.0.1:8787/ws"
$env:RPC_TARGET="http://127.0.0.1:3000"
$env:RPC_SERVICE="tradelayer.rpc"
$env:RPC_NETWORK="bitcoin.testnet4"
$env:RPC_STYLE="path"
npm run rpc:peer
```

For Bitcoin Core JSON-RPC, use `RPC_STYLE=jsonrpc`, point `RPC_TARGET` at the
Core RPC URL, and set `RPC_USER` / `RPC_PASSWORD` if needed.

If another local service already owns `8787`, run the collator with
`$env:PORT="18878"` and point both `COLLATOR_WS` and wallet route URLs at that
port. The full handshake URL would then be `ws://127.0.0.1:18878/ws`.

Example routed call:

```powershell
Invoke-RestMethod http://127.0.0.1:8787/rpc/route -Method Post -ContentType 'application/json' -Body (@{
  service = 'tradelayer.rpc'
  network = 'bitcoin.testnet4'
  method = 'tl_getAllBalancesForAddress'
  params = 'tb1...'
} | ConvertTo-Json)
```

The file/JSON is an array of objects:

```json
[
  {
    "body": {
      "v": 1,
      "kind": "COLLATOR_APPROVAL",
      "clearlistId": 42,
      "infraPubKey": "02...",
      "infraId": "sha256(infraPubKeyHex)",
      "ws": "wss://example/ws",
      "issuedAt": 1760000000,
      "expiresAt": 1762592000,
      "nonce": "deadbeef...",
      "adminPubKey": "02..."
    },
    "sigAdmin": "64-byte-compact-hex"
  }
]
```

TLS (optional):

- `TLS_KEY_PATH` and `TLS_CERT_PATH` (enables `wss://`)

### WebRTC NAT traversal (STUN/TURN)

WebRTC needs ICE servers for NAT traversal.

- STUN helps discover public-facing candidates
- TURN is required on many restrictive networks (CGNAT/corporate)

This collator can be configured with a TURN server via `ICE_SERVERS_JSON` (but does not implement TURN itself).

Example:

```json
[
  {"urls":["stun:stun.l.google.com:19302"]},
  {"urls":["turn:turn.example.com:3478"],"username":"u","credential":"p"}
]
```

## Fixed limits (not env-configurable)

These bounds are enforced in code. A request or session that exceeds one is refused at its own boundary.

| Limit | Value | Where |
| --- | --- | --- |
| HTTP request headers | 10 s from connection start (and from the end of each response) | `src/httpDeadlines.ts` |
| HTTP request body | 30 s from headers complete until the body ends | `src/httpDeadlines.ts` |
| Idle keep-alive socket | 60 s after a response finishes | `src/httpDeadlines.ts` |
| TLS handshake | 10 s (HTTPS mode only) | `src/index.ts` (`handshakeTimeout`) |
| DataChannel unsent data | 4 MiB; past it the channel is closed | `src/peerSession.ts` (`DC_MAX_BUFFERED_BYTES`) |
| IP intel and clearlist answer | 3 s deadline, 64 KiB body, redirects refused | `src/boundedFetch.ts` callers |
| Legacy relayer answer | 20 s deadline, 8 MiB body, redirects refused | `src/index.ts` (`LEGACY_PROXY_*`) |

The WebSocket frame and DataChannel message size is `MAX_MSG_BYTES` (default 1 MiB). The connection cap is `CONN_MAX` and `CONN_MAX_PER_IP`. Those are unchanged in round 8.
