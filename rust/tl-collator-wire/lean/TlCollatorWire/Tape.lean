/-!
Model of the chain rules in `VerifiedReplay::prepare_entry` / `commit_prepared`
(src/verify.rs). Hashes, order ids and owners are abstracted to `Nat`; schema checks
and signature verification (trader and collator) are abstracted to one boolean
`sigOk`, and the canonical entry hash to the value carried in the entry.

Rust order of checks: `seq == last_seq + 1`, `prevHash == last_hash`, entry hash shape,
order schema, order id, duplicate id, capacity, trader signature, CANCEL/REPLACE target
owned by the same trader, entry hash, collator signature; then commit.
-/
namespace TlCollatorWire

inductive Kind where
  | new
  | cancel (target : Nat)
  | replace (target : Nat)
deriving DecidableEq, Repr

structure Entry where
  seq : Nat
  prev : Nat
  hash : Nat
  orderId : Nat
  owner : Nat
  kind : Kind
  sigOk : Bool
deriving DecidableEq, Repr

structure Replay where
  lastSeq : Nat
  lastHash : Nat
  /-- `(orderId, owner)`, newest first. -/
  owners : List (Nat × Nat)
  maxEntries : Nat
deriving DecidableEq, Repr

inductive VErr where
  | brokenChain
  | duplicate
  | capacity
  | badSig
  | unknownOrder
  | notOwner
deriving DecidableEq, Repr

def ownerOf (owners : List (Nat × Nat)) (id : Nat) : Option Nat :=
  (owners.find? (fun p => p.1 == id)).map (·.2)

def targetOk (owners : List (Nat × Nat)) (who : Nat) : Kind → Except VErr Unit
  | .new => .ok ()
  | .cancel t | .replace t =>
    match ownerOf owners t with
    | none => .error .unknownOrder
    | some o => if o = who then .ok () else .error .notOwner

def apply (r : Replay) (e : Entry) : Except VErr Replay :=
  if e.seq ≠ r.lastSeq + 1 then .error .brokenChain
  else if e.prev ≠ r.lastHash then .error .brokenChain
  else if (ownerOf r.owners e.orderId).isSome then .error .duplicate
  else if r.owners.length ≥ r.maxEntries then .error .capacity
  else if !e.sigOk then .error .badSig
  else match targetOk r.owners e.owner e.kind with
    | .error err => .error err
    | .ok () => .ok { r with lastSeq := e.seq, lastHash := e.hash,
                              owners := (e.orderId, e.owner) :: r.owners }

/-- Replay a tape from an initial state; stops at the first refused entry. -/
def replay (r : Replay) : List Entry → Except VErr Replay
  | [] => .ok r
  | e :: es => match apply r e with
    | .error err => .error err
    | .ok r' => replay r' es

def genesis (cap : Nat) : Replay := ⟨0, 0, [], cap⟩

theorem apply_spec (r r' : Replay) (e : Entry) (h : apply r e = .ok r') :
    e.seq = r.lastSeq + 1 ∧ e.prev = r.lastHash ∧ ownerOf r.owners e.orderId = none ∧
      r.owners.length < r.maxEntries ∧ e.sigOk = true ∧
      r' = { r with lastSeq := e.seq, lastHash := e.hash,
                    owners := (e.orderId, e.owner) :: r.owners } := by
  unfold apply at h
  split at h; · simp at h
  split at h; · simp at h
  split at h; · simp at h
  split at h; · simp at h
  split at h; · simp at h
  rename_i h1 h2 h3 h4 h5
  split at h
  · simp at h
  · simp only [Except.ok.injEq] at h
    refine ⟨by omega, by omega, ?_, by omega, by simpa using h5, h.symm⟩
    simpa using h3

/-- Each accepted entry advances the sequence by exactly one and records one order, so
`seen_orders == last_seq` (the equality the witness receipt checks) is invariant. -/
theorem apply_counts (r r' : Replay) (e : Entry) (hinv : r.owners.length = r.lastSeq)
    (h : apply r e = .ok r') : r'.lastSeq = r.lastSeq + 1 ∧ r'.owners.length = r'.lastSeq := by
  obtain ⟨hs, -, -, -, -, rfl⟩ := apply_spec r r' e h
  simp only [List.length_cons]
  omega

theorem replay_counts (r r' : Replay) (es : List Entry) (hinv : r.owners.length = r.lastSeq)
    (h : replay r es = .ok r') : r'.lastSeq = r.lastSeq + es.length ∧
      r'.owners.length = r'.lastSeq := by
  induction es generalizing r with
  | nil => simp only [replay, Except.ok.injEq] at h; subst h; simp [hinv]
  | cons e es ih =>
    simp only [replay] at h
    split at h
    · simp at h
    · rename_i r1 h1
      have ⟨a, b⟩ := apply_counts r r1 e hinv h1
      have ⟨c, d⟩ := ih r1 b h
      refine ⟨?_, d⟩
      simp only [List.length_cons]
      omega

/-- The owner index never exceeds the configured bound. -/
theorem apply_capacity (r r' : Replay) (e : Entry) (h : apply r e = .ok r') :
    r'.owners.length ≤ r'.maxEntries := by
  obtain ⟨-, -, -, hc, -, rfl⟩ := apply_spec r r' e h
  simp only [List.length_cons]
  omega

/-- Order ids are never reused: the new id was absent before the append. -/
theorem apply_fresh_id (r r' : Replay) (e : Entry) (h : apply r e = .ok r') :
    ownerOf r.owners e.orderId = none ∧ ownerOf r'.owners e.orderId = some e.owner := by
  obtain ⟨-, -, hn, -, -, rfl⟩ := apply_spec r r' e h
  refine ⟨hn, ?_⟩
  simp [ownerOf]

/-- CANCEL and REPLACE are accepted only from the trader that owns the target. -/
theorem apply_cancel_owner (r r' : Replay) (e : Entry) (t : Nat)
    (hk : e.kind = .cancel t ∨ e.kind = .replace t) (h : apply r e = .ok r') :
    ownerOf r.owners t = some e.owner := by
  unfold apply at h
  split at h; · simp at h
  split at h; · simp at h
  split at h; · simp at h
  split at h; · simp at h
  split at h; · simp at h
  split at h
  · simp at h
  · rename_i hok
    rcases hk with hk | hk <;> rw [hk] at hok <;> simp only [targetOk] at hok <;>
      (split at hok
       · simp at hok
       · rename_i o ho
         split at hok
         · rename_i heq; rw [ho, heq]
         · simp at hok)

/-- Hash linkage: in an accepted tape every entry names its predecessor's hash. -/
def linked : Nat → List Entry → Prop
  | _, [] => True
  | h, e :: es => e.prev = h ∧ linked e.hash es

theorem replay_linked (r r' : Replay) (es : List Entry) (h : replay r es = .ok r') :
    linked r.lastHash es := by
  induction es generalizing r with
  | nil => trivial
  | cons e es ih =>
    simp only [replay] at h
    split at h
    · simp at h
    · rename_i r1 h1
      obtain ⟨-, hp, -, -, -, rfl⟩ := apply_spec r r1 e h1
      exact ⟨hp, ih _ h⟩

-- Vectors in the spirit of src/durable_tests.rs: new, cancel by owner, cancel by
-- another trader, duplicate id, skipped sequence.
def e1 : Entry := ⟨1, 0, 11, 100, 7, .new, true⟩
def e2 : Entry := ⟨2, 11, 12, 101, 7, .cancel 100, true⟩
def e2bad : Entry := ⟨2, 11, 12, 101, 8, .cancel 100, true⟩
def e2dup : Entry := ⟨2, 11, 12, 100, 7, .new, true⟩
def e3skip : Entry := ⟨3, 11, 12, 101, 7, .new, true⟩

def errOf {α : Type} : Except VErr α → Option VErr
  | .error e => some e
  | .ok _ => none

example : (replay (genesis 10) [e1, e2]).toOption.map (·.lastSeq) = some 2 := by decide
example : errOf (replay (genesis 10) [e1, e2bad]) = some .notOwner := by decide
example : errOf (replay (genesis 10) [e1, e2dup]) = some .duplicate := by decide
example : errOf (replay (genesis 10) [e1, e3skip]) = some .brokenChain := by decide
example : errOf (replay (genesis 1) [e1, ⟨2, 11, 12, 101, 7, .new, true⟩]) = some .capacity := by
  decide
example : errOf (replay (genesis 10) [{ e1 with sigOk := false }]) = some .badSig := by decide

end TlCollatorWire
