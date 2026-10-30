import TlCollatorWire.Tape
/-!
Model of `WitnessService::compare_and_swap` (rust/tl-witness-service/src/lib.rs):
the append happens only if the caller's expected checkpoint equals the current one,
and then through the same verified `apply` as replay. Durability, the OS lock and the
SSH capability split are outside this model.
-/
namespace TlCollatorWire

structure Checkpoint where
  seq : Nat
  hash : Nat
  seen : Nat
deriving DecidableEq, Repr

def Replay.checkpoint (r : Replay) : Checkpoint := ⟨r.lastSeq, r.lastHash, r.owners.length⟩

inductive CasErr where
  | conflict
  | verify (e : VErr)
deriving DecidableEq, Repr

def cas (r : Replay) (expected : Checkpoint) (e : Entry) : Except CasErr Replay :=
  if r.checkpoint ≠ expected then .error .conflict
  else match apply r e with
    | .error err => .error (.verify err)
    | .ok r' => .ok r'

/-- A successful CAS started from exactly the expected checkpoint and moved the
sequence forward by one. -/
theorem cas_spec (r r' : Replay) (exp : Checkpoint) (e : Entry) (h : cas r exp e = .ok r') :
    r.checkpoint = exp ∧ r'.lastSeq = exp.seq + 1 := by
  unfold cas at h
  split at h
  · simp at h
  · rename_i hc
    have hc' : r.checkpoint = exp := by simpa using hc
    split at h
    · simp at h
    · rename_i r1 h1
      simp only [Except.ok.injEq] at h
      subst h
      obtain ⟨hs, -, -, -, -, rfl⟩ := apply_spec r r1 e h1
      refine ⟨hc', ?_⟩
      rw [← hc']; simp [Replay.checkpoint, hs]

/-- Two writers racing from the same observed checkpoint: once one succeeds, the
other's expectation is stale and it gets `conflict` (no lost update, no fork). -/
theorem cas_race (r r1 : Replay) (exp : Checkpoint) (e1 e2 : Entry)
    (h1 : cas r exp e1 = .ok r1) : cas r1 exp e2 = .error .conflict := by
  obtain ⟨hc, hs⟩ := cas_spec r r1 exp e1 h1
  have hne : r1.checkpoint ≠ exp := by
    intro heq
    have : r1.lastSeq = exp.seq := by rw [← heq]; rfl
    omega
  simp [cas, hne]

/-- The witnessed sequence is monotone across any successful CAS history. -/
theorem cas_monotone (r r' : Replay) (exp : Checkpoint) (e : Entry)
    (h : cas r exp e = .ok r') : r.lastSeq < r'.lastSeq := by
  obtain ⟨hc, hs⟩ := cas_spec r r' exp e h
  have : r.lastSeq = exp.seq := by rw [← hc]; rfl
  omega

def casErrOf {α : Type} : Except CasErr α → Option CasErr
  | .error e => some e
  | .ok _ => none

example : (cas (genesis 10) ⟨0, 0, 0⟩ e1).toOption.map (·.lastSeq) = some 1 := by decide
example : casErrOf (cas (genesis 10) ⟨1, 11, 1⟩ e1) = some .conflict := by decide

end TlCollatorWire
