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

HTTP endpoints on the same port:

- `GET /health`
- `GET /manifest` (TL-CSv1 manifest, signed by collator key)

## Configure

Environment variables:

- `PORT` (default: `8787`)
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

Infra attestations (optional; used by wallets for curated-mode acceptability):

- `INFRA_ATTESTATIONS_PATH` (default: `./data/infra-attestations.json`, loaded if the file exists)
- `INFRA_ATTESTATIONS_JSON` (inline JSON array; if set, overrides file loading)

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
