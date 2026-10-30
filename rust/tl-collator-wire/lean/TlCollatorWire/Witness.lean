import TlCollatorWire.Tape
/-!
Model of `WitnessScope::verify_tape` (src/witness.rs): replay the signed tape and
compare every intermediate checkpoint at the receipt's sequence. A different head at
that sequence is a fork; never reaching it is a rollback (the local tape was truncated
below what the independent witness saw). Receipt signature checks are abstracted.
-/
namespace TlCollatorWire

structure Receipt where
  seq : Nat
  head : Nat
deriving DecidableEq, Repr

/-- The `(seq, hash)` checkpoints visited while replaying, in order. -/
def checkpoints (r : Replay) : List Entry → List (Nat × Nat)
  | [] => []
  | e :: es => match apply r e with
    | .error _ => []
    | .ok r' => (r'.lastSeq, r'.lastHash) :: checkpoints r' es

inductive WErr where
  | fork
  | rollback
deriving DecidableEq, Repr

/-- `seen` starts true only for a genesis receipt; a checkpoint at the receipt's
sequence either matches (seen) or not (fork). Fork takes precedence. -/
def judge (rc : Receipt) (cps : List (Nat × Nat)) : Option WErr :=
  if cps.any (fun c => c.1 == rc.seq && c.2 != rc.head) then some .fork
  else if rc.seq == 0 || cps.any (fun c => c.1 == rc.seq && c.2 == rc.head) then none
  else some .rollback

/-- Acceptance means the witnessed head is on the replayed history. -/
theorem judge_ok (rc : Receipt) (cps : List (Nat × Nat)) (h : judge rc cps = none)
    (hpos : rc.seq ≠ 0) : (rc.seq, rc.head) ∈ cps := by
  unfold judge at h
  split at h
  · simp at h
  · split at h
    · rename_i _ hseen
      simp only [Bool.or_eq_true, beq_iff_eq, List.any_eq_true, Bool.and_eq_true] at hseen
      rcases hseen with h0 | ⟨c, hc, h1, h2⟩
      · exact absurd h0 hpos
      · have : c = (rc.seq, rc.head) := by
          cases c; simp_all
        exact this ▸ hc
    · simp at h

/-- A checkpoint list in which the witnessed sequence carries another head is a fork,
whatever else happens. -/
theorem judge_fork (rc : Receipt) (cps : List (Nat × Nat)) (h0 : Nat)
    (hin : (rc.seq, h0) ∈ cps) (hne : h0 ≠ rc.head) : judge rc cps = some .fork := by
  unfold judge
  have : cps.any (fun c => c.1 == rc.seq && c.2 != rc.head) = true := by
    simp only [List.any_eq_true, Bool.and_eq_true, beq_iff_eq, bne_iff_ne, ne_eq]
    exact ⟨_, hin, rfl, hne⟩
  simp [this]

/-- Checkpoint sequences visited by a replay are exactly `last+1, last+2, ...`, so a
tape shorter than the receipt can never reach it: truncation is reported as rollback. -/
theorem checkpoints_seq_bound (r : Replay) (es : List Entry) :
    ∀ c ∈ checkpoints r es, r.lastSeq < c.1 ∧ c.1 ≤ r.lastSeq + es.length := by
  induction es generalizing r with
  | nil => simp [checkpoints]
  | cons e es ih =>
    intro c hc
    simp only [checkpoints] at hc
    split at hc
    · simp at hc
    · rename_i r1 h1
      obtain ⟨hs, -, -, -, -, rfl⟩ := apply_spec r _ e h1
      simp only [List.mem_cons] at hc
      rcases hc with rfl | hc
      · simp only [List.length_cons]; omega
      · have := ih _ c hc
        simp only [List.length_cons] at *
        omega

theorem truncated_is_rollback (r : Replay) (es : List Entry) (rc : Receipt)
    (hpos : rc.seq ≠ 0) (hshort : r.lastSeq + es.length < rc.seq) :
    judge rc (checkpoints r es) = some .rollback := by
  have none_at : ∀ c ∈ checkpoints r es, c.1 ≠ rc.seq := by
    intro c hc heq
    have := checkpoints_seq_bound r es c hc
    omega
  unfold judge
  have hf : (checkpoints r es).any (fun c => c.1 == rc.seq && c.2 != rc.head) = false := by
    rw [List.any_eq_false]; intro c hc; simp [none_at c hc]
  have hs : (checkpoints r es).any (fun c => c.1 == rc.seq && c.2 == rc.head) = false := by
    rw [List.any_eq_false]; intro c hc; simp [none_at c hc]
  simp [hf, hs, hpos]

-- Vectors: honest receipt at seq 1, forked head at seq 1, receipt beyond the tape.
example : judge ⟨1, 11⟩ (checkpoints (genesis 10) [e1, e2]) = none := by decide
example : judge ⟨1, 99⟩ (checkpoints (genesis 10) [e1, e2]) = some .fork := by decide
example : judge ⟨3, 13⟩ (checkpoints (genesis 10) [e1, e2]) = some .rollback := by decide
example : judge ⟨0, 0⟩ [] = none := by decide

end TlCollatorWire
