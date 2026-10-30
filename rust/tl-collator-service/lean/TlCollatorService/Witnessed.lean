/-!
Model of the witnessed-tape serve gate (src/witnessed.rs).

`Judgement` is the adapter's verdict; the adapter serves (`read_range`, `append_order`,
`precheck`) iff its latched judgement is `ok` (`ServeState::Serving`). `judge` models
`WitnessedSignedTape::recheck`: the receipt checks of `WitnessScope::verify_receipt` in the Rust
order (scope, challenge, signature), then `verify_tape` (witness ahead of the tape -> rollback,
a different head at the witnessed sequence -> fork) and the ahead-of-witness test. The tape is
the list of entry hashes (entry `i` has sequence `i + 1`); hash verification and signatures are
assumed (`tl-collator-wire` does them), the receipt's validity is an input.
-/
namespace TlCollatorService.Witnessed

inductive Judgement where
  | ok | rollback | fork | ahead | wrongScope | stale | badSig | invalid | uncertain | inconsistent
deriving DecidableEq, Repr

structure Receipt where
  scopeOk : Bool
  challengeOk : Bool
  sigOk : Bool
  seq : Nat
  head : Nat
deriving DecidableEq, Repr

/-- `ServeState::Serving` is `Judgement.ok`. -/
def serves (j : Judgement) : Bool := decide (j = .ok)

/-- Head recorded for sequence `seq` (`1`-based), `none` past the end. -/
def headAt (tape : List Nat) (seq : Nat) : Option Nat := tape[seq - 1]?

def judge (tape : List Nat) (r : Receipt) : Judgement :=
  if r.scopeOk = false then .wrongScope
  else if r.challengeOk = false then .stale
  else if r.sigOk = false then .badSig
  else if tape.length < r.seq then .rollback
  else if r.seq ≠ 0 ∧ headAt tape r.seq ≠ some r.head then .fork
  else if r.seq < tape.length then .ahead
  else .ok

/-- `WitnessedSignedTape::refuse` / `recheck`: a failed judgement latches; success never lifts it. -/
def recheck (st : Judgement) (j : Judgement) : Judgement :=
  if st = .ok then j else st

theorem serves_iff (j : Judgement) : serves j = true ↔ j = .ok := by
  simp [serves]

/-- A latched refusal stays, whatever the next receipt says. -/
theorem recheck_latched (st j : Judgement) (h : st ≠ .ok) : recheck st j = st := by
  simp [recheck, h]

theorem recheck_serves_iff (j : Judgement) : serves (recheck .ok j) = true ↔ j = .ok := by
  simp [recheck, serves]

/-- Over any sequence of rechecks, serving afterwards implies every judgement was `ok`. -/
def recheckAll : Judgement → List Judgement → Judgement
  | st, [] => st
  | st, j :: js => recheckAll (recheck st j) js

theorem recheckAll_serves (js : List Judgement) (st : Judgement)
    (h : serves (recheckAll st js) = true) : st = .ok ∧ ∀ j ∈ js, j = .ok := by
  induction js generalizing st with
  | nil => exact ⟨(serves_iff st).mp h, by simp⟩
  | cons j js ih =>
    have h' : serves (recheckAll (recheck st j) js) = true := h
    obtain ⟨h1, h2⟩ := ih _ h'
    by_cases hs : st = .ok
    · subst hs
      have e : recheck .ok j = j := by simp [recheck]
      rw [e] at h1
      refine ⟨rfl, fun x hx => ?_⟩
      rcases List.mem_cons.mp hx with hx | hx
      · subst hx; exact h1
      · exact h2 x hx
    · rw [recheck_latched st j hs] at h1
      exact absurd h1 hs

/-- The receipt judgement is `ok` only for a valid receipt that matches the whole local tape:
same length, and the witnessed head at that sequence. -/
theorem judge_ok_exact (tape : List Nat) (r : Receipt) (h : judge tape r = .ok) :
    r.scopeOk = true ∧ r.challengeOk = true ∧ r.sigOk = true ∧ tape.length = r.seq ∧
      (r.seq = 0 ∨ headAt tape r.seq = some r.head) := by
  unfold judge at h
  by_cases h1 : r.scopeOk = false
  · simp [h1] at h
  by_cases h2 : r.challengeOk = false
  · simp [h1, h2] at h
  by_cases h3 : r.sigOk = false
  · simp [h1, h2, h3] at h
  by_cases h4 : tape.length < r.seq
  · simp [h1, h2, h3, h4] at h
  by_cases h5 : r.seq ≠ 0 ∧ headAt tape r.seq ≠ some r.head
  · simp [h1, h2, h3, h4, h5] at h
  by_cases h6 : r.seq < tape.length
  · simp [h1, h2, h3, h4, h5, h6] at h
  refine ⟨by simpa using h1, by simpa using h2, by simpa using h3, by omega, ?_⟩
  by_cases hz : r.seq = 0
  · exact Or.inl hz
  · right
    by_cases hh : headAt tape r.seq = some r.head
    · exact hh
    · exact absurd ⟨hz, hh⟩ h5

/-- A witness ahead of the tape (truncation or restore) is never served. -/
theorem rollback_not_served (tape : List Nat) (r : Receipt) (hs : r.scopeOk = true)
    (hc : r.challengeOk = true) (hg : r.sigOk = true) (h : tape.length < r.seq) :
    serves (judge tape r) = false := by
  simp [judge, hs, hc, hg, h, serves]

/-- A different head at the witnessed sequence (a fork) is never served. -/
theorem fork_not_served (tape : List Nat) (r : Receipt) (hs : r.scopeOk = true)
    (hc : r.challengeOk = true) (hg : r.sigOk = true) (hl : r.seq ≤ tape.length)
    (hz : r.seq ≠ 0) (hh : headAt tape r.seq ≠ some r.head) :
    serves (judge tape r) = false := by
  have : ¬ tape.length < r.seq := by omega
  simp [judge, hs, hc, hg, this, hz, hh, serves]

/-- A local head ahead of the witness is never served. -/
theorem ahead_not_served (tape : List Nat) (r : Receipt) (hs : r.scopeOk = true)
    (hc : r.challengeOk = true) (hg : r.sigOk = true) (hl : r.seq < tape.length)
    (hh : r.seq = 0 ∨ headAt tape r.seq = some r.head) :
    serves (judge tape r) = false := by
  have h1 : ¬ tape.length < r.seq := by omega
  have h2 : ¬ (r.seq ≠ 0 ∧ headAt tape r.seq ≠ some r.head) := by
    intro ⟨a, b⟩; rcases hh with h | h
    · exact a h
    · exact b h
  simp [judge, hs, hc, hg, h1, h2, hl, serves]

/-- A receipt that is invalid for the pinned scope, challenge or key is never served. -/
theorem invalid_receipt_not_served (tape : List Nat) (r : Receipt)
    (h : r.scopeOk = false ∨ r.challengeOk = false ∨ r.sigOk = false) :
    serves (judge tape r) = false := by
  unfold judge serves
  rcases h with h | h | h
  · simp [h]
  · by_cases h0 : r.scopeOk = false <;> simp [h, h0]
  · by_cases h0 : r.scopeOk = false <;> by_cases h1 : r.challengeOk = false <;> simp [h, h0, h1]

/-! ### The adapter: appends change the tape only after the commit and only while serving -/

structure WT where
  st : Judgement
  tape : List Nat

/-- `append_order`: nothing happens unless serving; the entry joins the tape only when the
witness CAS and the local durable commit both succeeded (`committed`); a failed attempt
latches `uncertain` and leaves the tape unchanged. -/
def append (w : WT) (h : Nat) (committed : Bool) : WT :=
  if w.st = .ok then
    (if committed then { w with tape := w.tape ++ [h] } else { w with st := .uncertain })
  else w

def readRange (w : WT) : Option (List Nat) :=
  if serves w.st then some w.tape else none

theorem read_requires_serving (w : WT) (l : List Nat) (h : readRange w = some l) : w.st = .ok := by
  unfold readRange at h
  by_cases hs : serves w.st = true
  · exact (serves_iff _).mp hs
  · simp [hs] at h

theorem append_refused_unchanged (w : WT) (h : Nat) (c : Bool) (hs : w.st ≠ .ok) :
    append w h c = w := by
  simp [append, hs]

theorem tape_changes_only_when_committed (w : WT) (h : Nat) (c : Bool)
    (hne : (append w h c).tape ≠ w.tape) : c = true ∧ w.st = .ok := by
  unfold append at hne
  by_cases hs : w.st = .ok
  · by_cases hc : c = true
    · exact ⟨hc, hs⟩
    · simp [hs, hc] at hne
  · simp [hs] at hne

theorem uncommitted_append_latches (w : WT) (h : Nat) (hs : w.st = .ok) :
    (append w h false).tape = w.tape ∧ serves (append w h false).st = false := by
  simp [append, hs, serves]

theorem committed_append_extends (w : WT) (h : Nat) (hs : w.st = .ok) :
    (append w h true).tape = w.tape ++ [h] ∧ (append w h true).st = .ok := by
  simp [append, hs]

theorem append_grows_by_at_most_one (w : WT) (h : Nat) (c : Bool) :
    (append w h c).tape.length ≤ w.tape.length + 1 := by
  unfold append
  split
  · split <;> simp
  · omega

/-! ### Vectors shared with tests/witnessed.rs -/

private def good (seq head : Nat) : Receipt :=
  { scopeOk := true, challengeOk := true, sigOk := true, seq := seq, head := head }

/-- `appends_reads_checkpoint_and_restart`: a receipt for the head of a 4-entry tape. -/
example : judge [11, 12, 13, 14] (good 4 14) = .ok := by decide
/-- `a_restored_older_tape_is_a_rollback...` / `recheck..._rollback`: witness at 4, tape has 2. -/
example : judge [11, 12] (good 4 14) = .rollback := by decide
/-- `an_alternative_signed_history_is_a_fork...`: same length, different head. -/
example : judge [11, 12, 13, 99] (good 4 14) = .fork := by decide
/-- `an_unwitnessed_local_head_is_refused`: tape has 3, witness is at 2. -/
example : judge [11, 12, 13] (good 2 12) = .ahead := by decide
/-- Wrong scope / stale challenge / bad signature win over the tape comparison, in that order. -/
example : judge [11] { good 1 11 with scopeOk := false, challengeOk := false } = .wrongScope := by decide
example : judge [11] { good 1 11 with challengeOk := false } = .stale := by decide
example : judge [11] { good 1 11 with sigOk := false } = .badSig := by decide
/-- Empty witness and empty tape. -/
example : judge [] (good 0 0) = .ok := by decide

/-- `nothing_is_committed_or_visible_when_the_witness_is_down`. -/
example : (append { st := .ok, tape := [1, 2] } 3 false).tape = [1, 2] := by decide
example : (append { st := .ok, tape := [1, 2] } 3 false).st = .uncertain := by decide
example : (append (append { st := .ok, tape := [1, 2] } 3 false) 4 true).tape = [1, 2] := by decide
example : readRange (append { st := .ok, tape := [1, 2] } 3 false) = none := by decide
example : readRange { st := .ok, tape := [1, 2] } = some [1, 2] := by decide

end TlCollatorService.Witnessed
