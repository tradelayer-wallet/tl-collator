/-!
Model of the authorization decision at the start of `recovery::export_history`
(rust/tl-witness-service/src/recovery.rs, `export_history` up to the anchor check, plus
`RecoveryPolicy`).

Abstraction: the schema, domain, version, scope (collator id, network, stream, epoch),
operator id and challenge-format checks are folded into `envelopeOk`; the three-way key
distinctness (witness, collator, operator) into `keysDistinct`; the secp256k1 verification of
`sigOperator` over the canonical request into `sigOk`. Those are decided by `verify_compact` and
string equality in Rust and are not re-derived here. What is modelled is the order of the
decisions, the range arithmetic and the exact-checkpoint binding. The checkpoint hash is
`none` for the empty genesis hash.

Not modelled (documented non-goal in RECOVERY.md): there is no one-use ledger, so a request
that was authorized once is authorized again for as long as the committed checkpoint is
unchanged, and refused afterwards (`stale_checkpoint_refused`).
-/
namespace TlWitnessService

structure Cp where
  seq : Nat
  hash : Option Nat
  orders : Nat
deriving DecidableEq, Repr

/-- `recovery::checkpoint`: `orders = seq`, and the hash is empty exactly at genesis. -/
def Cp.valid (c : Cp) : Prop :=
  c.orders = c.seq ∧ (c.seq = 0 → c.hash = none) ∧ (0 < c.seq → c.hash.isSome = true)

instance (c : Cp) : Decidable c.valid := by unfold Cp.valid; infer_instance

structure Request where
  envelopeOk : Bool
  keysDistinct : Bool
  sigOk : Bool
  cp : Cp
  start : Nat
  count : Nat

/-- Operator policy (`RecoveryLimits.max_records`) and trusted `Config.max_entries`. -/
structure Policy where
  maxRecords : Nat
  maxEntries : Nat

inductive Err where
  | unauthorized
  | checkpoint
  | limit
deriving DecidableEq, Repr

inductive Verdict where
  | ok
  | refuse (e : Err)
deriving DecidableEq, Repr

/-- Last sequence number of the range; `count ≥ 1` is checked before it is used in `authorize`
(Rust uses checked_add/checked_sub; over `Nat` no overflow is possible). -/
def Request.finish (r : Request) : Nat := r.start + r.count - 1

/-- `cur` is the witness's committed checkpoint (`witness.checkpoint` anchor, equal to the full
replay result in Rust). Same order of checks as Rust. -/
def authorize (pol : Policy) (r : Request) (cur : Cp) : Verdict :=
  if r.envelopeOk = false then .refuse .unauthorized
  else if r.keysDistinct = false then .refuse .unauthorized
  else if r.sigOk = false then .refuse .unauthorized
  else if ¬ r.cp.valid then .refuse .checkpoint
  else if r.start = 0 ∨ r.count = 0 ∨ pol.maxRecords < r.count ∨ r.cp.seq < r.finish
      ∨ pol.maxEntries < r.cp.seq then .refuse .limit
  else if r.cp ≠ cur then .refuse .checkpoint
  else .ok

/-- Everything `export_history` requires before it produces any bytes. -/
theorem authorize_sound (pol : Policy) (r : Request) (cur : Cp)
    (h : authorize pol r cur = .ok) :
    r.envelopeOk = true ∧ r.keysDistinct = true ∧ r.sigOk = true ∧ r.cp.valid ∧
    1 ≤ r.start ∧ 1 ≤ r.count ∧ r.count ≤ pol.maxRecords ∧
    r.start + r.count - 1 ≤ r.cp.seq ∧ r.cp.seq ≤ pol.maxEntries ∧ r.cp = cur := by
  unfold authorize Request.finish at h
  split at h
  · simp at h
  split at h
  · simp at h
  split at h
  · simp at h
  split at h
  · simp at h
  split at h
  · simp at h
  split at h
  · simp at h
  rename_i e1 e2 e3 e4 e5 e6
  simp only [Bool.not_eq_false] at e1 e2 e3
  simp only [not_or] at e5
  have e4' : r.cp.valid := by simpa using e4
  have e6' : r.cp = cur := by simpa using e6
  refine ⟨e1, e2, e3, e4', ?_, ?_, ?_, ?_, ?_, e6'⟩ <;> omega

/-- A request bound to an older checkpoint is refused whatever else it contains. -/
theorem stale_checkpoint_refused (pol : Policy) (r : Request) (cur : Cp) (h : r.cp ≠ cur) :
    authorize pol r cur ≠ .ok := by
  intro hok
  exact h (authorize_sound pol r cur hok).2.2.2.2.2.2.2.2.2

/-- An unsigned request (or one with a failing envelope or key-separation check) is never
authorized. -/
theorem unsigned_refused (pol : Policy) (r : Request) (cur : Cp)
    (h : r.sigOk = false ∨ r.keysDistinct = false ∨ r.envelopeOk = false) :
    authorize pol r cur ≠ .ok := by
  intro hok
  obtain ⟨h1, h2, h3, -⟩ := authorize_sound pol r cur hok
  rcases h with h | h | h <;> simp_all

/-- The range lies inside the committed history and is no larger than the operator cap. -/
theorem range_bounded (pol : Policy) (r : Request) (cur : Cp)
    (h : authorize pol r cur = .ok) :
    1 ≤ r.start ∧ r.start ≤ r.finish ∧ r.finish ≤ cur.seq ∧ r.count ≤ pol.maxRecords := by
  obtain ⟨-, -, -, -, h5, h6, h7, h8, -, h10⟩ := authorize_sound pol r cur h
  subst h10
  unfold Request.finish
  omega

/-- Replay: the decision reads no history, so a request authorized against `cur` is
authorized again against any state with the same checkpoint (documented absence of a one-use
ledger; freshness comes from the challenge-bound response and the checkpoint binding). -/
theorem replay_same_checkpoint (pol : Policy) (r : Request) (cur cur' : Cp)
    (h : authorize pol r cur = .ok) (he : cur' = cur) : authorize pol r cur' = .ok := by
  subst he; exact h

/-! Vectors mirroring `tests/recovery.rs`. -/

def pol : Policy := ⟨3, 10⟩
def cp3 : Cp := ⟨3, some 77, 3⟩
def req (start count : Nat) : Request :=
  ⟨true, true, true, cp3, start, count⟩

example : authorize pol (req 1 3) cp3 = .ok := by decide
example : authorize pol (req 2 2) cp3 = .ok := by decide
-- start 0, count 0, count over cap, range past head
example : authorize pol (req 0 1) cp3 = .refuse .limit := by decide
example : authorize pol (req 1 0) cp3 = .refuse .limit := by decide
example : authorize pol (req 1 4) cp3 = .refuse .limit := by decide
example : authorize pol (req 3 2) cp3 = .refuse .limit := by decide
-- stale expected checkpoint after CAS advanced
example : authorize pol (req 1 3) ⟨4, some 88, 4⟩ = .refuse .checkpoint := by decide
-- unsigned / wrong operator, latest-only capability, key collision
example : authorize pol { req 1 3 with sigOk := false } cp3 = .refuse .unauthorized := by decide
example : authorize pol { req 1 3 with keysDistinct := false } cp3 = .refuse .unauthorized := by
  decide
example : authorize pol { req 1 3 with envelopeOk := false } cp3 = .refuse .unauthorized := by
  decide
-- inconsistent checkpoint (orders <> seq)
example : authorize pol { req 1 3 with cp := ⟨3, some 77, 2⟩ } cp3 = .refuse .checkpoint := by
  decide

end TlWitnessService
