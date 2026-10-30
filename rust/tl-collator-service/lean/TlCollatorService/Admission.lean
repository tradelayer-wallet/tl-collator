/-!
Model of the SUBMIT admission order in `Service::submit` (src/service.rs). The gates are taken
in the Rust order; each gate's verdict is an input fact, because the cryptographic content of
the gates (ECDSA, SHA-256 of the canonical envelope) is checked by `tl-collator-wire` and is
assumed here.

`Facts.shape` is `validate_shape`, `idBound` is `verify_binding`'s order-id recomputation and
`sigOk` its trader signature check, `refOk` is `TapeStore::precheck`, `intelOk`/`clearOk` the
IP and clearlist policies and `commit` the wire crate's re-verification inside
`TapeStore::append_order`. Duplicates are not an input: they are decided from the tape itself.
-/
namespace TlCollatorService

structure Facts where
  sessionRate : Bool
  ipRate : Bool
  shape : Bool
  idBound : Bool
  sigOk : Bool
  refOk : Bool
  intelOk : Bool
  clearOk : Bool
  commit : Bool
deriving DecidableEq, Repr

/-- Order ids on the tape, newest first (`TapeStore` as seen by the reducer). -/
structure St where
  tape : List Nat
deriving DecidableEq, Repr

/-- One SUBMIT of order id `id`; mirrors the `if`-chain in `Service::submit`. -/
def submit (s : St) (id : Nat) (f : Facts) : St :=
  if f.sessionRate && f.ipRate && f.shape && f.idBound && decide (id ∉ s.tape) && f.sigOk
      && f.refOk && f.intelOk && f.clearOk && f.commit then
    { tape := id :: s.tape }
  else s

theorem submit_cases (s : St) (id : Nat) (f : Facts) :
    submit s id f = s ∨ submit s id f = { tape := id :: s.tape } := by
  unfold submit
  split
  · exact Or.inr rfl
  · exact Or.inl rfl

/-- An order is appended only if every gate passed, in particular: rate-allowed, verified (id
bound to the contents and signature valid) and not already on the tape. -/
theorem appended_only_if (s : St) (id : Nat) (f : Facts) (h : (submit s id f).tape ≠ s.tape) :
    f.sessionRate = true ∧ f.ipRate = true ∧ f.idBound = true ∧ f.sigOk = true ∧
      f.shape = true ∧ id ∉ s.tape := by
  unfold submit at h
  split at h
  · rename_i hg
    simp only [Bool.and_eq_true, decide_eq_true_eq] at hg
    obtain ⟨⟨⟨⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩, h6⟩, _⟩, _⟩, _⟩, _⟩ := hg
    exact ⟨h1, h2, h4, h6, h3, h5⟩
  · exact absurd rfl h

/-- Completeness: when every gate passes the order is appended at the head. -/
theorem appended_of_gates (s : St) (id : Nat) (f : Facts) (h1 : f.sessionRate = true)
    (h2 : f.ipRate = true) (h3 : f.shape = true) (h4 : f.idBound = true) (h5 : id ∉ s.tape)
    (h6 : f.sigOk = true) (h7 : f.refOk = true) (h8 : f.intelOk = true) (h9 : f.clearOk = true)
    (h10 : f.commit = true) : submit s id f = { tape := id :: s.tape } := by
  unfold submit
  simp [h1, h2, h3, h4, h5, h6, h7, h8, h9, h10]

/-- A refused SUBMIT leaves the tape untouched (and a rate-limited one cannot reach any later gate). -/
theorem rejected_leaves_state (s : St) (id : Nat) (f : Facts) (h : f.sessionRate = false) :
    submit s id f = s := by
  unfold submit
  simp [h]

theorem rate_limited_ip_leaves_state (s : St) (id : Nat) (f : Facts) (h : f.ipRate = false) :
    submit s id f = s := by
  unfold submit
  simp [h]

/-- Duplicate order ids are never appended, whatever the other gates say. -/
theorem duplicate_never_appended (s : St) (id : Nat) (f : Facts) (h : id ∈ s.tape) :
    submit s id f = s := by
  unfold submit
  simp [h]

/-- Tape order ids stay unique forever: no sequence of SUBMITs creates a duplicate. -/
theorem nodup_preserved (s : St) (id : Nat) (f : Facts) (h : s.tape.Nodup) :
    (submit s id f).tape.Nodup := by
  unfold submit
  split
  · rename_i hg
    simp only [Bool.and_eq_true, decide_eq_true_eq] at hg
    obtain ⟨⟨⟨⟨⟨⟨⟨⟨⟨_, _⟩, _⟩, _⟩, hn⟩, _⟩, _⟩, _⟩, _⟩, _⟩ := hg
    exact List.nodup_cons.mpr ⟨hn, h⟩
  · exact h

/-- Sequence numbers are the tape length: a SUBMIT adds exactly one entry or none. -/
theorem seq_step (s : St) (id : Nat) (f : Facts) :
    (submit s id f).tape.length = s.tape.length ∨ (submit s id f).tape.length = s.tape.length + 1 := by
  rcases submit_cases s id f with h | h
  · exact Or.inl (by rw [h])
  · exact Or.inr (by rw [h]; simp)

def runAll : St → List (Nat × Facts) → St
  | s, [] => s
  | s, (id, f) :: rest => runAll (submit s id f) rest

theorem runAll_nodup (s : St) (ops : List (Nat × Facts)) (h : s.tape.Nodup) :
    (runAll s ops).tape.Nodup := by
  induction ops generalizing s with
  | nil => exact h
  | cons op rest ih => exact ih _ (nodup_preserved s op.1 op.2 h)

def allOk : Facts :=
  { sessionRate := true, ipRate := true, shape := true, idBound := true, sigOk := true,
    refOk := true, intelOk := true, clearOk := true, commit := true }

/-- Replaying the same order (tests/reducer.rs `duplicate_is_refused_...`): the second SUBMIT of
id 7 changes nothing even though every other gate passes. -/
example : runAll ⟨[]⟩ [(7, allOk), (8, allOk), (7, allOk)] = ⟨[8, 7]⟩ := by decide

/-- A forged id (`idBound = false`) never reaches the tape. -/
example : submit ⟨[]⟩ 9 { allOk with idBound := false } = ⟨[]⟩ := by decide

/-- Rate limiting wins over everything after it. -/
example : submit ⟨[]⟩ 9 { allOk with sessionRate := false } = ⟨[]⟩ := by decide

end TlCollatorService
