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

## Configure

Environment variables:

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
- `SEEN_ORDERIDS_MAX` (default: `100000`)
- `NAME`, `OPERATOR`, `REGION` (optional manifest fields)
- `CONN_MAX` (optional hard cap on concurrent WS connections)
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
- `TL_COLLATOR_RPC_SERVICE` / `TL_COLLATOR_RPC_NETWORK` tune routed RPC matching

Infra attestations (optional; used by wallets for curated-mode acceptability):

- `INFRA_ATTESTATIONS_PATH` (default: `./data/infra-attestations.json`, loaded if the file exists)
- `INFRA_ATTESTATIONS_JSON` (inline JSON array; if set, overrides file loading)

Generate/sign attestation entries:

```powershell
npm run infra:sign -- `
  --ws ws://127.0.0.1:8787/ws `
  --clearlist-id 42 `
  --admin-pubkey 02... `
  --admin-privkey <admin-privkey-hex> `
  --collator-key ./data/collator.key `
  --expires-in-days 30 `
  --out ./data/infra-attestations.json
```

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
