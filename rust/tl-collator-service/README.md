# tl-collator-service: offline pure-reducer port of the collator service layer

Baseline: `tradelayer-wallet/tl-collator` branch `master`, local head
`6543908` (merge base with `origin/master` `a184247`); Rust work committed on `master` as requested,
nothing pushed. Inspected TypeScript (blob SHAs at the baseline):
`src/index.ts` 43a5f2ec, `config.ts` 9a6af69d, `ratelimit.ts` f9f166f3, `lru.ts` b7fe32a7,
`clearlist.ts` 3d3f2b4f, `manifest.ts` 6e9ffb01, `bitvmStatus.ts` fd1a5eab, `ipIntel.ts` 87b4c2ee,
`peerSession.ts` 26868f90, `auditLog.ts` 52abd4dc, `schema.ts` 1e42f149, `validate.ts` 1e34cd7e,
`types.ts` 81435d85, `tape.ts` 35a29559, plus `spec/schemas/*.json`.

The crate owns no socket, timer, file, key or clock. The host feeds it session ids, text frames,
parsed HTTP requests and `now_ms` (unix milliseconds, never decreasing: `tl-rpc-router` latches a
permanent failure on a backwards clock) and performs the `Out` values it returns. Cryptography and
the ledger rules stay in `tl-collator-wire`; provider routing stays in `tl-rpc-router`.

## What is ported

| TypeScript | Rust | Notes |
|---|---|---|
| `config.ts` + env reads in `index.ts` | `config::Config::from_env(&Env)` | fail-closed validation, no env/file access |
| `ratelimit.ts` | `ratelimit::TokenBucket`, `KeyedLimiter` | integer milli-tokens, injected clock |
| `lru.ts` | `lru::LruMap`, `LruSet` | tick-ordered, deterministic, always `len <= capacity` |
| `clearlist.ts` + `index.ts` 1183-1207 | `clearlist` (`ClearlistOracle` trait, `ClearlistClient`, `decide`) | no network; TTL cache bounded |
| `ipIntel.ts` + `index.ts` 1156-1181 | `ipintel` (`IpIntelSource` trait, `IpIntelClient`, `evaluate`) | no network |
| `auditLog.ts` + record at `index.ts` 1211 | `audit::AuditRecord::to_line`, `AuditSink` | legacy key order |
| `manifest.ts` | `manifest::{manifest_body, sign_manifest, load_infra_attestations}` | signing via `DigestSigner` |
| `bitvmStatus.ts` | `bitvm::build_status` (+ `jsval` JS coercions), `ArtifactSource` trait | host supplies parsed artifacts |
| `peerSession.ts` | `peer::PeerSession` | transport objects stay in the host |
| `types.ts`, `validate.ts`, `schema.ts` (WireMsg) | `wire::{parse_wire, WireIn}` + outbound constructors | strict parser from `tl-collator-wire` |
| `schema.ts` (OrderEnvelope) | `order::validate_shape`, `verify_binding` | stricter than Ajv, see table |
| `tape.ts` (append/replay) | `tape::{TapeStore, MemoryTape, DurableSignedTape}` | commits through `tl-collator-wire` |
| `index.ts` WS message handlers | `Service::on_message`, `pump_replay`, `channel_*`, `close_session`, `expire` | HELLO, SUBMIT, TAPE_SUB, TAPE_ENTRY, TAPE_END, RPC_ADVERTISE, RPC_REQ, RPC_RES, PING/PONG, ERR |
| `index.ts` HTTP handler | `Service::handle_http`, `proxy_done`, `http_abort` | `/health`, `/manifest`, `/attestation/ip`, `/rpc/providers`, `/rpc/<m>`, `/rpc/route`, `/tl_*`, legacy proxy routes, CORS |

`wire` and `order` do not duplicate what `tl-collator-wire` enforces. At append time the wire crate
re-verifies order id, trader and collator signatures, hash chain, duplicate ids, CANCEL/REPLACE
ownership and capacity, so nothing the wire crate would refuse to replay reaches the tape. The
service adds the checks that must happen before the collator signs anything.

## Reducer contract

```
Service::new(cfg, ServiceParts, now)                  -> Service
open_session(host, ip, ua, now) / channel_opened      -> admission (connection caps), router identity
on_message(host, text, now)                           -> Vec<Out>
pump_replay(host)                                     -> Vec<Out>   (while is_replaying(host))
handle_http(&HttpRequest, now)                        -> (HttpTicket, Vec<Out>)
proxy_done(ticket, Option<(status, body)>, now)       -> Vec<Out>   (once per Out::Proxy)
expire(now), channel_closed(host, now), close_session -> Vec<Out>
Out = Send{to,msg} | CloseChannel | HttpReply{ticket,response} | Proxy{ticket,request}
```

SUBMIT admission order (`Service::submit`): session and per-address rate limit, shape, order-id
recomputation, duplicate check against the tape, trader signature, tape `precheck` (CANCEL/REPLACE
owner), IP policy, clearlist policy, then `TapeStore::append_order`. TAPE_SUB replays the contiguous
range from the cursor in batches of `replay_batch`; live broadcast reaches a session only after its
replay finished.

## Compatibility table

Legacy line numbers refer to the baseline blobs above.

| Behavior | Legacy | Rust | Class |
|---|---|---|---|
| Wire message shapes (HELLO, SUBMIT, TAPE_*, RPC_*, PING/PONG, ERR) and ERR codes `rate_limited`, `SCHEMA_INVALID`, `DUPLICATE`, `bad_sig`, `UNKNOWN_ORDER`, `NOT_OWNER`, `VPN_BLOCKED`, `ASN_BLOCKED`, `NOT_CLEARLISTED`, `CLEARLIST_DOWN`, `CLEARLIST_CONFIG`, `msg_too_large` | `index.ts` 1000-1230 | same codes and texts | preserved contract |
| No ack to SUBMIT; submitter sees its entry only if subscribed | 1209-1228 | same | preserved contract |
| Silent drop of non-JSON / non-object / missing `t`,`v` frames; `ERR SCHEMA_INVALID` for schema failures | 1004-1010 | same | preserved contract |
| `/health`, `/manifest`, `/rpc/providers` bodies; compat `/rpc/<m>` `{data}` / `{error,code}`; `/rpc/route` RpcResponseV1 and 200/503/502 mapping; legacy relayer fallback and 404 fall-through; 403 for non-public methods | 469-902 | same | preserved contract |
| Public method allowlist, timeout clamp `[1000,120000]` default 12000, `Math.max` capacity clamps | 22-49, 315 | same | preserved contract |
| Manifest field set and `sha256(canonical(body))` signature | `manifest.ts` 120-174 | same fields; `cacheTtlSec` is configurable (default 60) | preserved contract |
| BitVM status fields, error strings and context hash payload | `bitvmStatus.ts` 310-466 | same (JS `??`/`\|\|`/`Number` semantics reproduced, incl. `Number(null) = 0` for a trailing null `vout`) | preserved contract |
| `orderId` accepted if the client signed any 32 bytes; order body unauthenticated | 1118 `verifyTraderSig(order.orderId, ...)`, no recomputation | id recomputed with `tl_collator_wire::order_id`, mismatch -> `BAD_ORDER_ID` | repaired defect |
| Duplicate detection by a bounded LRU (`SEEN_ORDERIDS_MAX`, NaN = unbounded); `TapeStore.append` never checks, so an evicted id could be appended again | 215, 1114, 1210; `tape.ts` 110 | tape is authoritative (`contains_order` + wire `Duplicate`); LRU is only a fast path; capacity validated | repaired defect |
| Uppercase `orderId`/target hex passes the schema (`/^[0-9a-fA-F]{64}$/`) and defeats the string-keyed duplicate and owner maps | schema; 1114, 1135 | lowercase 64-hex required; owners compared lowercased | repaired defect |
| `RPC_RES` accepted by `res.id` from any session; `pendingRpc` keyed by caller-chosen id (collision overwrites another caller's entry); provider echoes `providerNodeId` | 351, 429, 1090 | `Router::settle` on the sender session + server token; caller id restored; pinned node id overwrites | repaired defect |
| `RPC_ADVERTISE` unauthenticated: any peer registers any `nodeId` and receives routed requests | 1022-1053 | challenge/proof against operator pins (`tl-rpc-router`); proof-less advertise gets `RPC_CHALLENGE` | versioned protocol change (inactive until providers implement it) |
| Unbounded `pendingRpc`, `rpcAdvertisements`, `peers` growth | 230-238, 911 | router caps (pending 1000, per requester 32, per provider 64), `CONN_MAX` default 1024, per-address cap 16 | repaired defect |
| Rate limiting only on SUBMIT, bucket lives in the session so a reconnect resets it; TAPE_SUB, RPC_REQ, PING unlimited | `peerSession.ts` 30; 1095, 1055 | per-session message and heavy buckets, per-address SUBMIT/HTTP bucket in a bounded keyed limiter | repaired defect |
| Message limit measured in UTF-16 units (`txt.length`) | 999 | bytes | repaired defect |
| TAPE_SUB streams while live broadcast is already enabled: duplicates/out-of-order entries mid-replay; whole tape sent in one `await` loop | 1096-1101, 1224-1228 | cursor per session, batches, live only after replay completes | repaired defect |
| CORS: `*` whenever `NODE_ENV` is not `production` (unset = permissive); unapproved origins still reach POST handlers | 186, 448-467 | production by default, wildcard only for `NODE_ENV=development` with an empty list, unapproved cross-origin POST -> 403 | repaired defect |
| `/tl_*` proxy enabled by `!isProduction`; raw pathname forwarded upstream | 187, 550-565 | needs `NODE_ENV=development` and the flag; path charset restricted, no `.`/`..` segments | repaired defect |
| Client IP from `cf-connecting-ip`/`x-real-ip`/`x-forwarded-for` always trusted and forwarded upstream | 377-385, 488 | socket address unless `TL_COLLATOR_TRUST_PROXY_HEADERS=1` | repaired defect |
| IP-intel lookup errors ignored, so `reject` modes silently stop enforcing; `log` modes do nothing | 1164, 1170-1181 | `IP_INTEL_FAIL_MODE` (default closed) -> `IP_INTEL_DOWN`; log matches counted in `Stats::intel_logged` | repaired defect |
| Clearlist: cache key `group\|pubkey` collides; `!!j.allowed` accepts `"false"`; unbounded cache; upstream error text sent to the client; `open` mode sent an ERR and then appended | `clearlist.ts` 20, 38, 12; 1190-1204 | length-prefixed lowercase key; strict boolean; bounded LRU; fixed text; open mode just admits | repaired defect |
| LRU never evicts the key `""` (`if (oldest)`) | `lru.ts` 23, 50 | eviction by tick | repaired defect |
| Config: `parseInt` prefixes and NaN fallbacks; unknown modes -> `off`; VPN/ASN modes silently `off` without an intel URL; invalid ICE JSON replaced by Google STUN; half a TLS pair serves plaintext; `CLEARLIST_ENFORCE` any value but `1` = off; unlimited `CONN_MAX` by default | `config.ts` 36-40, 55, 62, 78-91, 123; `index.ts` 220 | strict `Config::from_env`, every violation is an error | repaired defect |
| HTTP: invalid JSON body treated as empty; internal errors leak `e.message` as 500; sendTx fallback wraps error bodies as `txid` | 82-96, 906, 818 | 400 `BAD_JSON`, fixed internal text, wrap only on success | repaired defect |
| `/attestation/ip` answers `success:true`, "clean" when no intel provider is configured; lookup failure is `isBlocked:false` | 503-529 | no verdict -> `success:false, isBlocked:false` (failure shape kept) | repaired defect |
| BitVM: public response includes the server's `artifactDir` and echoes the whole request body; 5 synchronous file reads per unauthenticated request | `bitvmStatus.ts` 237, 283, 137-141 | no path, only bounded `propertyId`/`dlcRef` echoed, host-side cached `ArtifactSource`, per-address HTTP bucket | repaired defect |
| Infra attestations: any-length hex, `Number("")` accepted, expired entries published, unknown fields passed through | `manifest.ts` 96-111 | 33-byte hex keys, integer times, `expiresAt > issuedAt` and unexpired, 128-hex `sigAdmin`, fields rebuilt | repaired defect |
| Session and RPC ids from `Math.random` | 70-72, 919 | counters and router tokens (SHA-256 over a boot secret) | repaired defect |
| Absent RPC `network` matches any provider network | 262-267 | defaults to the configured network; other networks are `BAD_RPC_REQUEST` | versioned protocol change |
| `preferredProviderNodeId` is dropped by `normalizeRpcRequest` | 124-138 | still dropped | unresolved question (router supports it) |
| `params` omitted in `RPC_REQ` | forwarded without key | forwarded as `null` | unresolved question |
| Public `tl_bitvmstatus` over WebSocket RPC_REQ is routed to a provider | 22-49, 1055 | unchanged (HTTP answers it locally as before) | preserved contract |
| `expTs` from the clearlist oracle | read, ignored | read, ignored | unresolved question |
| `px`/`qty` content (decimal syntax, ranges) | unchecked | unchecked (same as `tl-collator-wire`) | unresolved question |
| `sigAdmin` of infra attestations | passed through for the wallet to verify | same | unresolved question |
| Faucet/`sendTx`/`buildTx` routes proxy to the relayer for anyone | 703-878 | same, behind the per-address limit and parameter validation | unresolved question |

## Dependencies

`tl-collator-wire` and `tl-rpc-router` (path); `serde_json =1.0.145` (message values; the
same pin as both crates); `secp256k1 =0.29.1` (parse the trader public key for
`tl_collator_wire::verify::verify_compact`, and the sample `SecretKeySigner`). `Cargo.lock` started
as a copy of `tl-rpc-router`'s and only gained this crate's entry; no new third-party crate.
SHA-256 comes from `tl_collator_wire::sha256_hex`.

## Verification

Rust 1.90.0 (`rust-toolchain.toml`), from `rust/tl-collator-service`:

    cargo test --locked --offline         # 81 tests: 31 reducer, 18 HTTP, 30 unit, 2 durable
    cargo clippy --locked --offline --all-targets -- -D warnings
    cargo fmt --all -- --check

The tests cover success paths, malformed and oversized frames, boundary values (rate limits,
LRU capacity, cursor start values), failure and recovery paths (oracle/intel down, provider
disconnect, timeouts, durable reopen) and a regression for each repaired defect above. The
broadcast TAPE_ENTRY bytes are re-verified by an independent `VerifiedReplay`; the durable tests
run the reducer on `DurableTape` under a temp directory (unix only).

Lean 4 v4.34.1, core only, no `sorry`/`admit`/new axioms (`lean/`):

    cd lean && lake build && lake env lean AxiomCheck.lean

| Theorem | Models | Statement |
|---|---|---|
| `allow_capacity` | `TokenBucket::allow` | tokens never exceed capacity, for any clock |
| `refill_no_gain`, `allow_true_spends`, `allow_false_keeps` | `refill`, `allow` | a backwards clock adds nothing; a grant spends exactly its cost; a refusal spends nothing |
| `step_inv`, `exec_inv`, `grants_bounded` | repeated `allow` | after any request sequence, granted tokens `<= burst + rate * elapsed / 1000` and the bucket is at most full |
| `touch_length_le`, `touch_mem`, `touch_subset` | `LruMap::insert` | size bound, the new key is present, no invented keys (holds for every key including the empty-string model `0`) |
| `touch_evicts_oldest`, `touch_no_eviction` | `LruMap::insert` | a full container drops exactly the oldest key and keeps the order; below capacity nothing is dropped |
| `not_enforcing_allows`, `public_allows`, `restricted_allowed_iff`, `negative_never_overridden`, `closed_requires_yes` | `clearlist::decide` | membership/authorization predicate: restricted orders pass only on a yes (or fail-open with oracle missing/down); a no is never overridden |
| `cacheKey_injective` | `clearlist::cache_key` | the length-prefixed key is injective; the legacy `\|` key is shown ambiguous by an `example` |
| `appended_only_if`, `appended_of_gates` | `Service::submit` | an order is appended iff every gate passed: rate-allowed (session and address), shape, id bound, signature verified, not already on the tape, reference, policies, commit |
| `rejected_leaves_state`, `rate_limited_ip_leaves_state`, `duplicate_never_appended` | `submit` | refused or duplicate submissions change nothing |
| `nodup_preserved`, `runAll_nodup`, `seq_step` | `submit` | tape ids stay unique over any SUBMIT sequence; each SUBMIT adds zero or one entry |
| `batch_length_le`, `batch_mem` | `pump_replay` | a pump sends at most `replay_batch` entries, all inside `cursor..last` |
| `replay_complete`, `replay_nodup`, `replay_bounds`, `replay_beyond_end` | repeated `pump_replay` | the replay is exactly the contiguous range `cursor..last`: no gap, no repeat, in order; a start beyond the tape sends nothing |

`decide` examples in the Lean files replay the vectors of `bucket_burst_refill_and_cap`,
`bucket_cost_zero_and_over_capacity_and_backwards_clock`, `lru_set_evicts_oldest_and_refreshes_on_add`,
`lru_map_get_refreshes_and_the_empty_key_is_evictable`, `clearlist_decision_table`,
`duplicate_is_refused_even_after_the_recent_id_cache_forgot_it` and
`replay_is_contiguous_batched_and_does_not_double_deliver_live_entries`. The model abstracts keys
and ids to `Nat`, strings to lists, `u32`/`u64` overflow (the Rust code clamps inputs and widens
the refill arithmetic) and every cryptographic check to a Boolean gate; it does not model
`HashMap` ordering, the router, HTTP or JSON.

## Not done

- The WebSocket/WebRTC signaling handlers (`SIGNAL_HELLO/OFFER/ANSWER/ICE`, `index.ts` 911-1259),
  the HTTP/HTTPS/WebSocket servers, TLS, collator key file loading, timers and the sparse tape index
  (`tapeIndex.ts`; the durable adapter scans the NDJSON file) are host work. `ICE_SERVERS_JSON` is
  validated and kept in `Config` for the host.
- No legacy-parity harness. `lru.ts`, `ratelimit.ts` and the other helpers are TypeScript and Node 18
  in WSL cannot run them without a compile step; behaviour was derived from the source and checked
  by tests written from it. `bitvmStatus` was ported from source and the `test/bitvm-status.test.mjs`
  assertions (field names, context id shape, non-ready message) are mirrored on synthetic artifacts;
  the real referee artifacts were not used.
- `WitnessedTape` (independent witness) is not wrapped in a `TapeStore` adapter yet.
- Provider authentication (`RPC_CHALLENGE`/proof in `RPC_ADVERTISE`) has had no independent protocol
  review and no provider implements it.
- IP-intel and clearlist traits are synchronous: a real adapter must bound its own latency, since a
  slow oracle blocks the reducer thread.
- Not wired into the running TypeScript collator; open collator PR #2 is untouched.
- CI workflow `.github/workflows/rust-collator-service.yml` has not run (nothing is pushed).
