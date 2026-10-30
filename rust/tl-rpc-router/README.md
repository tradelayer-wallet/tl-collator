# tl-rpc-router: offline collator RPC routing contract (RUST-17, router slice)

Baseline: `tradelayer-wallet/tl-collator` master `a1842473124453cbbd2d697c067129342deb00ab`
plus the local witness commits through `20b81dd8e5c6f33b7deb947191d335a3c5e9ba60`.
Inspected TypeScript: `src/index.ts` (`findRpcProvider`, `routeRpcRequest`,
`settleRpcResponse`, `normalizeRpcMethod`, `pruneRpcAdvertisements`, the
`RPC_ADVERTISE`/`RPC_REQ`/`RPC_RES` wire handlers) and `src/types.ts`
(`RpcRequestV1`, `RpcResponseV1`, `WireMsg`).

This crate is an in-memory state machine. It opens no socket, owns no timer,
loads no key and is not wired into the running collator. The host supplies the
authenticated transport session for every call, a monotonic clock and a fresh
32-byte boot secret per process start.

## What it does

- **Provider authentication (proposed v1, not active).** A provider session asks
  for a challenge, then returns a canonical TL-Canon JSON proof
  `{domain, v, collatorId, service, network, nodeId, challenge, methods, sigProvider}`
  signed (compact ECDSA over SHA-256 of the canonical payload) by the key the
  operator pinned for that `nodeId`. Accepted methods must be a subset of the pin.
  Every attempt consumes the challenge; any failure revokes the session's
  advertisement; one live session per node; a session cannot switch node identity.
- **Routing.** Requests are normalized like the legacy collator (`trim`,
  lowercase), validated (id, service, network, method charset, JSON params
  <= 64 KiB, timeout <= configured maximum, preferred-provider label) and
  admitted only under global, per-requester and per-provider caps. Eligible
  providers are live, advertised the method, are not the requester and honour a
  preference. Selection is round robin over node ids.
- **Response ownership.** The provider receives a server token, never the
  caller id. `settle` accepts a response only from the session the request was
  dispatched to, only while its advertisement is live, and only in the
  RpcResponseV1 shape bound to the token. The caller id and the pinned
  `providerNodeId` are restored; a provider-supplied `providerNodeId` is
  overwritten.
- **Completion.** `expire` and `close_session` complete pending work with the
  legacy error codes `RPC_TIMEOUT` and `RPC_PEER_CLOSED`; `refusal` maps router
  errors to RpcResponseV1 errors (`NO_RPC_PROVIDER`, `BAD_RPC_REQUEST`, ...).
- **Clock.** A backwards or out-of-range clock latches a permanent failure.

## Compatibility table

| Behavior | Legacy TypeScript | Rust | Class |
|---|---|---|---|
| Method normalization | `String(m).trim().toLowerCase()` | same, then ASCII charset check | preserved contract |
| RpcResponseV1 fields to requester | `id, ok, result/error, providerNodeId` | same; failures carry legacy codes | preserved contract |
| Response accepted by id from any session | `settleRpcResponse(wm.res)` keyed only by `res.id` | only the dispatched provider session; token, not caller id | repaired defect |
| Provider claims `providerNodeId` | trusted from advertisement | pinned node id from authenticated proof, overwrites response field | repaired defect |
| `RPC_ADVERTISE` | unauthenticated `nodeId` + services | challenge/proof against operator pin | versioned protocol change (unreviewed, inactive) |
| Pending work | unbounded `pendingRpc` map | global, per-requester, per-provider caps | repaired defect |
| Provider choice | first matching advertisement in map order | round robin over sorted node ids | preserved contract (order unspecified) |
| Params duplicate keys | forwarded | forwarded byte-for-byte (serde_json syntax check only) | unresolved question |
| Public method allowlist (`PUBLIC_RPC_METHODS`) | in collator | operator pins per node; host keeps the allowlist | unresolved question |

## Dependencies

`tl-collator-wire` (path; canonical JSON, compact signature verification),
`secp256k1 =0.29.1`, `serde_json =1.0.145`, `sha2 =0.10.9`: the same pinned versions
as `tl-collator-wire`, locked in `Cargo.lock`. No new third-party crate.

## Verification

Rust 1.90.0 (`rust-toolchain.toml`):

    cargo test --locked --offline        # 20 contract tests
    cargo clippy --locked --offline --all-targets -- -D warnings
    cargo fmt --all -- --check

Lean 4 v4.34.1, core only (`lean/`):

    cd lean && lake build && lake env lean AxiomCheck.lean

`lean/` models the clock latch, provider selection, the pending table and the
response-shape check. Theorems (all without `sorry`; axioms limited to `propext`,
`Quot.sound`, `Classical.choice`):

| Theorem | Models | Statement |
|---|---|---|
| `failed_is_absorbing`, `admitted_monotone`, `admitted_deadline_safe` | `Router::clock` | a failed clock never admits; admitted time is non-decreasing; `now + duration` stays below 2^53 |
| `choose_sound` | `route` candidate filter + pick | the chosen provider is listed, is not the requester, is live, advertised the method, honours the preference, is under its cap |
| `choose_some_of_eligible` | same | if any advertisement is eligible, routing picks one |
| `pick_advances` | round robin | the choice moves strictly past the previous node when possible |
| `admit_global_cap`, `admit_requester_cap` | admission | caps hold after every admitted request |
| `admit_fresh` | token minting | each token is new; freshness invariant is preserved |
| `settle_requires_provider`, `settle_wrong_sender` | `settle` | completion requires the dispatched provider; a wrong sender gets an error and the table is unchanged |
| `settle_removes_only_token` | `settle`/`finish` | exactly the settled token is removed |
| `expire_exact` | `expire` | a request survives iff its deadline is in the future |
| `close_clears_session`, `close_keeps_others` | `close_session` | nothing referencing the closed session remains; others stay |
| `shape_sound`, `shape_requires_token` | `response_shape` | accepted responses name the token and are exactly success-with-result or failure-with-message |

`decide` examples in the Lean files replay the vectors of
`round_robin_between_providers_and_preference`,
`per_requester_per_provider_and_global_caps`,
`response_from_non_provider_session_is_refused_and_kept_pending`,
`settle_at_deadline_is_a_timeout` and `malformed_responses_do_not_settle`.
The model abstracts node ids, sessions, methods and tokens to `Nat`, JSON to the
observations the Rust code makes, and assumes SHA-256 collision resistance and
ECDSA unforgeability; signature checking itself is not modelled.

## Not done

- Not wired into the TypeScript collator or a native WebRTC transport; open
  collator PR #2 (response-session ownership, bounded pending work) is untouched.
- The authentication wire format has had no independent protocol review and is
  not activated. Providers do not implement it yet.
- No timer loop, rate limiting of challenges per session, or persistence.
- CI workflow `.github/workflows/rust-rpc-router.yml` has not run (not pushed).
