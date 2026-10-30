# tl-collator-service: offline pure-reducer port of the collator service layer

Baseline: `tradelayer-wallet/tl-collator` branch `master`, local head
`6543908` (merge base with `origin/master` `a184247`); Rust work committed on `master` as requested,
nothing pushed. Inspected TypeScript (blob SHAs at the baseline):
`src/index.ts` 43a5f2ec, `config.ts` 9a6af69d, `ratelimit.ts` f9f166f3, `lru.ts` b7fe32a7,
`clearlist.ts` 3d3f2b4f, `manifest.ts` 6e9ffb01, `bitvmStatus.ts` fd1a5eab, `ipIntel.ts` 87b4c2ee,
`peerSession.ts` 26868f90, `auditLog.ts` 52abd4dc, `schema.ts` 1e42f149, `validate.ts` 1e34cd7e,
`types.ts` 81435d85, `tape.ts` 35a29559, `tapeIndex.ts` d12b1c53, `wrtc.d.ts` c0201637, plus
`spec/schemas/*.json`. The second slice (signaling, sparse tape index, `WitnessedTape` adapter,
`ServerConfig`) was written against the same TypeScript blobs, on top of `tl-collator-wire`
and `tl-witness-service` as committed on `master`.

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
| `index.ts` 911-1259 `SIGNAL_*` handlers, `wrtc.d.ts`, `peerSession.ts` (`dc`, `sendDc`) | `signaling::SignalSession` (`on_frame`, `on_event`, `expire`), `SignalLimits`, `Action`, `HostEvent` | pure reducer, the host owns the socket and the WebRTC stack |
| `tapeIndex.ts` + `tape.ts` 70-83, 136-143 (`loadOrBuildIndex`, `replayFromSeq`) | `tapeindex::{TapeIndex, read_range_at}`, `DurableSignedTape::with_index` | same stride rule and lookup; legacy `tape.idx` JSON readable and writable |
| (`tl-collator-wire` `WitnessedTape`; no TS counterpart: the TS has no witness) | `witnessed::WitnessedSignedTape` (`TapeStore`), `Judgement`, `WitnessPin`, `recheck` | serves only while the witness judgement is `Ok` |
| `index.ts` 220-227, 1261-1281, `config.ts` TLS fields | `server::ServerConfig::from_config` | validation only; sockets and TLS are host-owned |

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

## Signaling, tape index, witnessed tape, server options

```
SignalSession::new(SignalLimits, now)                     states Idle -> Greeted -> Offering -> Answered -> Established -> Closed
  on_frame(text, now)  -> Vec<Action>   Send | ApplyOffer{sdp} | AddRemoteCandidate | ClosePeer | CloseSocket{code, reason}
  on_event(HostEvent)  -> Vec<Action>   AnswerReady | LocalCandidate | PeerFailed | DataChannelOpen | SocketClosed
  expire(now)          -> Vec<Action>   idle 30 s, answer 15 s, channel-open 60 s (deadline_ms() says when to call)
TapeIndex::build / build_from_reader / record_append / find_start / to_legacy_json / from_legacy_json
read_range_at(reader, Option<&TapeIndex>, from_seq, max)  -> RangeRead { entries, used_index, index_rejected }
DurableSignedTape::new(..).with_index(stride, max_entries)       WitnessedSignedTape::open(&WitnessedOpen, signer, transport)
  recheck(receipt_json, challenge) -> Judgement                  checkpoint(), judgement(), state(), with_index(..)
ServerConfig::from_config(&Config, &Env) -> bind, port, ws_path, max_msg_bytes, tls, scheme(), ws_url()
```

Close codes: 1009 frame too big, 1008 policy (violation or message budget), 1011 internal, 4408
timeout. `SignalLimits::validate` rejects inconsistent bounds (SDP and candidate sizes must fit the
frame limit). Signaling errors reach the peer as `SIGNAL_ERR` with fixed texts; the reason for the
last refused frame is kept in `last_reject()` for the host's log. The TAPE_SUB replay of
`Service::pump_replay` calls `TapeStore::read_range`, which the two durable adapters serve through
the index when one was configured.

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
| `SIGNAL_HELLO` ignored; `SIGNAL_OFFER` accepted from any state with or without a HELLO | 971-976 | OFFER accepted from `Idle` or `Greeted` (HELLO stays optional); HELLO only once | preserved contract (HELLO optional) |
| Each `SIGNAL_OFFER` replaces `pc`; the previous `RTCPeerConnection` is never closed (unbounded peer connections per socket) | 976-978 | one offer per session; a second OFFER gets `SIGNAL_ERR unexpected` and changes nothing, so at most one offer is pending | repaired defect |
| Schema-invalid and unhandled frames (`SIGNAL_ANSWER` from a client, `SIGNAL_ICE` before an offer) dropped silently, unlimited | 962-968, 1248 | `SIGNAL_ERR bad_message`/`unexpected`, counted against a violation budget, then close 1008 | repaired defect |
| `SIGNAL_ICE` candidate (any JSON object) passed to `addIceCandidate` unchecked, unbounded count | 1248-1253 | rebuilt from `candidate`/`sdpMid`/`sdpMLineIndex`/`usernameFragment`, candidate line shape and size checked, budgets for buffered and total candidates | repaired defect |
| SDP of any size and content handed to `setRemoteDescription` | 1241 | size bound, `v=0`, line syntax, no control bytes, data-channel (`m=application`) media only | repaired defect |
| Local ICE sent from `onicecandidate`, i.e. possibly before `SIGNAL_ANSWER` | 980-991, 1241-1244 | local candidates buffered until the ANSWER is out, then relayed in order | repaired defect |
| Internal failure sent to the peer as `e.message` | 1255-1256 | fixed text `internal error`, then close 1011 (peer connection closed) | repaired defect |
| No time limit: a socket that never offers, a host that never answers, a channel that never opens live forever | whole handler | idle 30 s, answer 15 s, channel-open 60 s (`SignalLimits`), injected clock, close 4408 | repaired defect |
| `cleanup` on `close`/`error` | 933-958 | `HostEvent::SocketClosed` -> `ClosePeer` (idempotent), buffers cleared; the host then calls `Service::close_session` | preserved contract |
| Index lookup `offsets[floor((fromSeq-1)/stride)]`, `0` for `fromSeq <= 1`, same selection in `findStartOffset` | `tapeIndex.ts` 80-85 | `TapeIndex::find_start` returns the greatest indexed `seq <= fromSeq` (identical for every `fromSeq` within the tape) | preserved contract |
| `fromSeq` beyond the last indexed block falls back to offset `0` (full scan) | `tapeIndex.ts` 80-84 | starts at the last indexed entry; the result is the same (no entry reaches `fromSeq`) | preserved contract (cheaper) |
| A valid-JSON line without numeric `seq` re-uses the previous `seq` and pushes a second offset at a stride boundary, shifting every later block | `tapeIndex.ts` 49, 72 | `IndexError::BadLine`; gaps, repeats and regressions are `NotContiguous` | repaired defect |
| Index is trusted when `tapeSize` equals the file size (same-size swap or edit passes); `Number(n) \|\| 0` turns garbage offsets into 0; stride 0 or non-integer accepted from the file | `tapeIndex.ts` 16, 26-29, `tape.ts` 70-75 | strict loader (integer stride `1..=2^32`, offsets strictly increasing from 0), and every lookup checks that the line at the offset carries the expected `seq`, else scans from the start (`index_rejected`) | repaired defect |
| Index dropped after every append (`this.idx = null`) and rebuilt by a full scan on the next TAPE_SUB; unbounded `offsets` array | `tape.ts` 136, `tapeIndex.ts` 36-87 | `record_append` extends it in place; at `max_entries` the stride doubles and every other entry goes (still a plain stride-`s` index), so memory is bounded | repaired defect |
| Non-JSON or `seq`-less lines skipped silently in `replayFromSeq`; a torn tail line parsed if it happened to be valid JSON | `tape.ts` 160-171 | contiguity enforced (`TapeError::Invalid` on a gap), an unterminated final line is never served | repaired defect |
| Plaintext server whenever only one of `TLS_KEY_PATH`/`TLS_CERT_PATH` is set; always `0.0.0.0` | `index.ts` 220-225, 1261 | both-or-neither (also when the `Config` was built by hand), key and certificate must differ; default bind `127.0.0.1`; a non-loopback plaintext listener needs `TL_COLLATOR_ALLOW_PLAINTEXT=1` | repaired defect |
| `WS_PATH` unrestricted (can shadow `/health`, `/rpc/...`, `/tl_*`); `MAX_MSG_BYTES` only a `ws` option | `index.ts` 227 | plain path charset, no `//`/dot segments, not a dispatcher route; `1024..=1 MiB` rechecked | repaired defect |
| TS has no witness: the tape file alone decides the head, a restored older tape is served | `tape.ts` 48-69 | `WitnessedSignedTape`: refuses to open on rollback/fork/ahead/wrong scope/outage and latches `Refused` after any non-`Ok` `recheck` | versioned protocol change (opt-in adapter) |
| `ServerConfig` has no TLS minimum version or cipher policy | n/a | none: the host's TLS stack sets it | unresolved question |

## Dependencies

`tl-collator-wire` and `tl-rpc-router` (path); `serde_json =1.0.145` (message values; the
same pin as both crates); `secp256k1 =0.29.1` (parse the trader public key for
`tl_collator_wire::verify::verify_compact`, and the sample `SecretKeySigner`). `Cargo.lock` started
as a copy of `tl-rpc-router`'s and only gained this crate's entry; no new third-party crate.
SHA-256 comes from `tl_collator_wire::sha256_hex`. `tl-witness-service` (path) is a **dev-dependency**
only: the `WitnessedSignedTape` tests run against a real, separately keyed `WitnessService`; the
library itself depends only on `tl-collator-wire`'s `WitnessTransport`. The lock file gained that
entry and nothing else.

## Verification

Rust 1.90.0 (`rust-toolchain.toml`), from `rust/tl-collator-service`:

    cargo test --locked --offline         # 136 tests: 31 reducer, 18 HTTP, 30 unit, 3 durable,
                                          #   25 signaling, 12 tape index, 6 server config, 11 witnessed
    cargo clippy --locked --offline --all-targets -- -D warnings
    cargo fmt --all -- --check

The tests cover success paths, malformed and oversized frames, boundary values (rate limits,
LRU capacity, cursor start values), failure and recovery paths (oracle/intel down, provider
disconnect, timeouts, durable reopen) and a regression for each repaired defect above. The
broadcast TAPE_ENTRY bytes are re-verified by an independent `VerifiedReplay`; the durable tests
run the reducer on `DurableTape` under a temp directory (unix only). The witnessed tests (unix
only: the wire crate's witness path needs `/dev/urandom`) open a real `WitnessService` and cover
rollback by restoring an older tape and anchor, an alternative fully signed fork, a local head ahead
of the witness, wrong epoch/network/key pins, an unreachable witness, a lost acknowledgment, and
`recheck` with forked, ahead, replayed-challenge, bad-signature, junk and wrong-scope receipts.
The signaling tests include a 400-session random walk that asserts every transition is an allowed
edge and that pending offers, offers accepted and buffered candidates stay within bounds.

**Legacy parity (tape index only).** `scripts/compare-legacy-tapeindex.mjs` imports the pinned
legacy `src/tapeIndex.ts` (blob `d12b1c53`) unchanged on Node 24 (type stripping) and prints
`buildIndex`/`findStartOffset`/`isIndexFresh` results for six strides over a 53-line tape;
`tests/fixtures/tapeindex_legacy.json` is that output and `matches_the_output_of_the_pinned_legacy_module`
asserts offsets, tape size and 366 lookups against it. The signaling handlers sit inside `index.ts`
(needs `ws`, `wrtc`, Ajv) and the service layer has no parity harness, so those are tested from the
source only.

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
| `Signaling.init_inv`, `step_inv`, `run_inv`, `at_most_one_pending`, `peer_needs_one_offer` | `SignalSession::on_frame/on_event/expire` | from `init`, over any input sequence: `pending <= 1` (and `= 1` exactly while `offering`), `offers <= 1`, and a peer exists only after exactly one accepted offer |
| `Signaling.step_edge`, `closed_absorbing` | same | every transition follows an allowed edge (`edge_allowed`); `closed` is never left |
| `Signaling.second_offer_ignored`, `answered_only_from_offering`, `established_only_from_answered` | same | an OFFER outside `idle`/`greeted` changes nothing; the answer comes only from `offering` on `answerReady`, the open channel only from `answered` |
| `TapeIndex.find_sound`, `find_le`, `find_mem` | `TapeIndex::find_start` | the lookup returns an indexed sequence number and never one beyond the target |
| `TapeIndex.find_max`, `find_none` | same | it is the greatest indexed entry at or before the target; `none` (start of file) only when every entry is beyond it |
| `TapeIndex.find_matches_legacy` | `find_start` vs `findStartOffset` | on a stride-`s` index the lookup equals the TS formula `floor((t-1)/s)*s+1` (`seqs_sorted`, `mem_seqs`, `find_isSome` support it) |
| `TapeIndex.pushLen_le_cap` | `TapeIndex::push_line` | appending to a full index (capacity `>= 2`) halves instead of growing: `len <= cap` always |
| `Witnessed.serves_iff`, `read_requires_serving`, `recheck_latched`, `recheck_serves_iff`, `recheckAll_serves` | `ServeState`, `recheck` | the adapter serves iff its latched judgement is `Ok`; a refusal is never lifted; after any sequence of rechecks it serves only if every receipt judged `Ok` |
| `Witnessed.judge_ok_exact` | `recheck` | `Ok` means a valid receipt (scope, challenge, signature) and a tape of exactly the witnessed length with the witnessed head |
| `Witnessed.rollback_not_served`, `fork_not_served`, `ahead_not_served`, `invalid_receipt_not_served` | `recheck` | a witness ahead of the tape, a different head, a local head ahead of the witness, or a receipt invalid for the pinned scope/challenge/key is never served |
| `Witnessed.append_refused_unchanged`, `tape_changes_only_when_committed`, `uncommitted_append_latches`, `committed_append_extends`, `append_grows_by_at_most_one` | `append_order` | nothing is appended while refused; the tape changes only after the witness CAS and local commit both succeeded; a failed attempt latches `Uncertain` and leaves the tape as it was |

`decide` examples in the Lean files replay the vectors of `bucket_burst_refill_and_cap`,
`bucket_cost_zero_and_over_capacity_and_backwards_clock`, `lru_set_evicts_oldest_and_refreshes_on_add`,
`lru_map_get_refreshes_and_the_empty_key_is_evictable`, `clearlist_decision_table`,
`duplicate_is_refused_even_after_the_recent_id_cache_forgot_it` and
`replay_is_contiguous_batched_and_does_not_double_deliver_live_entries`. The model abstracts keys
and ids to `Nat`, strings to lists, `u32`/`u64` overflow (the Rust code clamps inputs and widens
the refill arithmetic) and every cryptographic check to a Boolean gate; it does not model
`HashMap` ordering, the router, HTTP or JSON.

The new modules (`Signaling.lean`, `TapeIndex.lean`, `Witnessed.lean`, each in its own namespace)
replay the vectors of `full_handshake_hello_offer_answer_ice_open`,
`at_most_one_pending_offer_and_one_offer_per_session`, `unanswered_offer_times_out_and_closes_the_peer`,
`data_channel_must_open_in_time_and_established_has_no_deadline`,
`host_failure_sends_fixed_text_closes_peer_and_ignores_the_rest`, `edge_table_matches_the_documented_diagram`,
`lookup_is_the_greatest_indexed_seq_at_or_before_and_never_beyond` (stride 7), the rollback/fork/ahead
tests of `witnessed.rs` and `nothing_is_committed_or_visible_when_the_witness_is_down`. They abstract
SDP and candidate content, counters, buffers and the clock (signaling), byte offsets and file IO
(index; the Rust tests tie each indexed `seq` to its offset), and entry hashes, signatures and the
witness CAS (witnessed tape: hashes are `Nat`, receipt validity is an input fact checked by
`tl-collator-wire`).

## Not done

- Sockets, TLS, the WebSocket upgrade, the WebRTC stack (`wrtc`, SDP, ICE, data channels), timers
  (calling `SignalSession::expire` at `deadline_ms`), the collator key file and the consumers of
  `ServerConfig` are **host-owned**; this crate never opens a socket and reads no certificate or key.
  The signaling reducer returns `Action`s for the host to perform, `ServerConfig` only validates the
  options. The host maps a signaling socket to a `HostSession`, calls `Service::open_session` on
  connect (the legacy `connMax` check) and `Service::close_session` after `CloseSocket`.
  `ICE_SERVERS_JSON` is validated and kept in `Config` and `ServerConfig::ice_servers`.
- TLS minimum version and cipher policy are not expressed (host TLS stack); `ServerConfig` does
  not check that the key matches the certificate.
- The signaling SDP and candidate checks are bounds and shape checks, not an RFC 4566/8839 parser;
  the host's SDP engine stays the authority. Only data-channel (`m=application`) offers are accepted.
- `WitnessedSignedTape` needs a unix filesystem (the wire crate's witness path reads
  `/dev/urandom` and `DurableTape` syncs directories). It rebuilds a verified mirror of the tape at
  open (linear), `recheck` re-verifies the whole tape (linear), a latched refusal needs a restart, and
  the witness transport (SSH, TLS, key custody, restoring history after an ambiguous commit) is
  still the wire crate's open gate. A witness-ahead state after a lost acknowledgment refuses to open;
  recovery is an operator action.
- The tape index is built by one scan at open (`with_index`) and never persisted by the adapters
  (`to_legacy_json`/`from_legacy_json` exist for hosts that want the file); a loaded legacy index
  cannot be extended in place (its file does not record the last `seq`).
- No service-layer legacy-parity harness: `lru.ts`, `ratelimit.ts` and the other helpers are TypeScript and Node 18
  in WSL cannot run them without a compile step; behaviour was derived from the source and checked
  by tests written from it. `bitvmStatus` was ported from source and the `test/bitvm-status.test.mjs`
  assertions (field names, context id shape, non-ready message) are mirrored on synthetic artifacts;
  the real referee artifacts were not used.
- Provider authentication (`RPC_CHALLENGE`/proof in `RPC_ADVERTISE`) has had no independent protocol
  review and no provider implements it.
- IP-intel and clearlist traits are synchronous: a real adapter must bound its own latency, since a
  slow oracle blocks the reducer thread.
- Not wired into the running TypeScript collator; open collator PR #2 is untouched.
- CI workflow `.github/workflows/rust-collator-service.yml` has not run (nothing is pushed).
