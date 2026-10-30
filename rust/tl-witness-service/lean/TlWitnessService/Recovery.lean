/-!
Model of the offline acceptance predicate: `PagedRecovery::{new, accept_page, finish}` and
`verify_full_recovery` (rust/tl-witness-service/src/recovery/paged.rs and recovery.rs).

Abstraction: per-page signature, digest, byte-count, record-replay and `prevHash`/`finalHash`
chain checks are folded away (Rust accepts a page only after every record verified; chain
continuity is the sequence contiguity modelled here plus the hash chain `VerifiedReplay`
enforces). What is modelled is which sequence ranges are accepted, challenge uniqueness,
aggregate limits, the sticky failure, and the finishing conditions with the fresh receipt.
`Fresh.headMatches` stands for "signature valid under the pinned witness key AND receipt head,
orders and sequence equal the target"; `ageOk` for `validate_freshness`.
-/
namespace TlWitnessService

structure Page where
  start : Nat
  count : Nat
  challenge : Nat
deriving DecidableEq, Repr

structure Limits where
  maxRecords : Nat
  maxPages : Nat

structure State where
  last : Nat
  target : Nat
  challenges : List Nat
  pages : Nat
deriving DecidableEq, Repr

def State.init (target : Nat) : State := ⟨0, target, [], 0⟩

/-- `accept_inner`. A challenge must be valid (nonzero) and unused, the page must start right
after the verified prefix, hold between 1 and `maxRecords` records and stay inside the target. -/
def accept (L : Limits) (s : State) (p : Page) : Option State :=
  if p.challenge = 0 ∨ p.challenge ∈ s.challenges then none
  else if L.maxPages ≤ s.pages then none
  else if p.count = 0 ∨ L.maxRecords < p.count ∨ p.start ≠ s.last + 1
      ∨ s.target < p.start + p.count - 1 then none
  else some ⟨p.start + p.count - 1, s.target, p.challenge :: s.challenges, s.pages + 1⟩

/-- Pages are fed in order; the first failure ends the run (the Rust verifier is blocked for
good after any failed page). -/
def run (L : Limits) : State → List Page → Option State
  | s, [] => some s
  | s, p :: ps => (accept L s p).bind fun s' => run L s' ps

structure Fresh where
  challenge : Nat
  headMatches : Bool
  ageOk : Bool

/-- `PagedRecovery::finish`. -/
def finish (s : State) (f : Fresh) : Bool :=
  decide (1 ≤ s.pages ∧ 0 < s.target ∧ s.last = s.target ∧ f.challenge ≠ 0 ∧
    f.challenge ∉ s.challenges) && f.headMatches && f.ageOk

/-- Whole offline predicate: `PagedRecovery::new` with `target`, the pages, then `finish`. -/
def verify (L : Limits) (target : Nat) (pages : List Page) (f : Fresh) : Bool :=
  match run L (State.init target) pages with
  | none => false
  | some s => finish s f

/-- Pages tile `n+1, n+2, ...` with no gap and no overlap. -/
def Contig : Nat → List Page → Prop
  | _, [] => True
  | n, p :: ps => p.start = n + 1 ∧ 1 ≤ p.count ∧ Contig (n + p.count) ps

def total (ps : List Page) : Nat := (ps.map Page.count).sum

theorem accept_spec (L : Limits) (s s' : State) (p : Page) (h : accept L s p = some s') :
    p.start = s.last + 1 ∧ 1 ≤ p.count ∧ p.count ≤ L.maxRecords ∧
    s'.last = s.last + p.count ∧ s'.target = s.target ∧ s'.last ≤ s.target ∧
    s'.challenges = p.challenge :: s.challenges ∧ p.challenge ∉ s.challenges ∧
    p.challenge ≠ 0 ∧ s.pages < L.maxPages ∧ s'.pages = s.pages + 1 := by
  unfold accept at h
  split at h
  · simp at h
  split at h
  · simp at h
  split at h
  · simp at h
  rename_i h1 h2 h3
  simp only [not_or] at h1 h3
  simp only [Option.some.injEq] at h
  subst h
  obtain ⟨a, b⟩ := h1
  obtain ⟨c, d, e, f⟩ := h3
  refine ⟨by omega, by omega, by omega, by simp only; omega, rfl, by simp only; omega, rfl, b, a,
    by omega, rfl⟩

theorem run_contig (L : Limits) (s s' : State) (ps : List Page) (h : run L s ps = some s') :
    Contig s.last ps ∧ s'.last = s.last + total ps := by
  induction ps generalizing s with
  | nil => simp only [run, Option.some.injEq] at h; subst h; simp [Contig, total]
  | cons p ps ih =>
    simp only [run, Option.bind_eq_some_iff] at h
    obtain ⟨s1, h1, h2⟩ := h
    obtain ⟨a, b, -, d, -, -, -, -, -, -, -⟩ := accept_spec L s s1 p h1
    obtain ⟨c1, c2⟩ := ih s1 h2
    refine ⟨⟨a, b, ?_⟩, ?_⟩
    · rw [← d]; exact c1
    · simp only [total, List.map_cons, List.sum_cons] at *
      omega

theorem run_target (L : Limits) (s s' : State) (ps : List Page) (h : run L s ps = some s') :
    s'.target = s.target := by
  induction ps generalizing s with
  | nil => simp only [run, Option.some.injEq] at h; subst h; rfl
  | cons p ps ih =>
    simp only [run, Option.bind_eq_some_iff] at h
    obtain ⟨s1, h1, h2⟩ := h
    obtain ⟨-, -, -, -, e, -⟩ := accept_spec L s s1 p h1
    rw [ih s1 h2, e]

theorem run_challenges (L : Limits) (s s' : State) (ps : List Page) (h : run L s ps = some s') :
    s'.challenges = (ps.map Page.challenge).reverse ++ s.challenges ∧
    (s.challenges.Nodup → s'.challenges.Nodup) ∧
    (∀ p ∈ ps, p.challenge ≠ 0 ∧ p.count ≤ L.maxRecords) ∧
    s'.pages = s.pages + ps.length ∧ (s.pages ≤ L.maxPages → s'.pages ≤ L.maxPages) := by
  induction ps generalizing s with
  | nil => simp only [run, Option.some.injEq] at h; subst h; simp
  | cons p ps ih =>
    simp only [run, Option.bind_eq_some_iff] at h
    obtain ⟨s1, h1, h2⟩ := h
    obtain ⟨-, -, hm, -, -, -, hc, hn, hz, hp, hq⟩ := accept_spec L s s1 p h1
    obtain ⟨i1, i2, i3, i4, i5⟩ := ih s1 h2
    refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · rw [i1, hc]; simp
    · intro hs
      apply i2
      rw [hc]
      exact List.nodup_cons.mpr ⟨hn, hs⟩
    · intro q hq'
      rcases List.mem_cons.mp hq' with rfl | hq''
      · exact ⟨hz, hm⟩
      · exact i3 q hq''
    · rw [i4, hq]; simp only [List.length_cons]; omega
    · intro _; apply i5; omega

/-- Acceptance forces a complete, ordered, gap-free and overlap-free tiling of
`1 .. target` by at most `maxPages` pages, each within the per-page record cap, with pairwise
distinct export challenges and a fresh receipt whose challenge is none of them. -/
theorem verify_complete (L : Limits) (target : Nat) (pages : List Page) (f : Fresh)
    (h : verify L target pages f = true) :
    Contig 0 pages ∧ total pages = target ∧ 0 < target ∧ pages ≠ [] ∧
    (∀ p ∈ pages, p.count ≤ L.maxRecords) ∧ pages.length ≤ L.maxPages ∧
    (pages.map Page.challenge).Nodup ∧ (∀ p ∈ pages, p.challenge ≠ f.challenge) ∧
    f.headMatches = true ∧ f.ageOk = true := by
  unfold verify at h
  split at h
  · simp at h
  · rename_i s hs
    unfold finish at h
    simp only [Bool.and_eq_true, decide_eq_true_eq] at h
    obtain ⟨⟨⟨hp, ht, hl, hf, hnot⟩, hm⟩, ha⟩ := h
    obtain ⟨c1, c2⟩ := run_contig L _ _ _ hs
    obtain ⟨d1, d2, d3, d4, d5⟩ := run_challenges L _ _ _ hs
    have ht' : s.target = target := run_target L _ _ _ hs
    have hinit : (State.init target).last = 0 := rfl
    have hpg : (State.init target).pages = 0 := rfl
    have hch : (State.init target).challenges = [] := rfl
    rw [hinit] at c1 c2
    rw [hpg] at d4 d5
    rw [hch] at d1 d2
    refine ⟨c1, ?_, ?_, ?_, fun p hp' => (d3 p hp').2, ?_, ?_, ?_, hm, ha⟩
    · omega
    · omega
    · intro hnil; subst hnil; simp at d4; omega
    · have := d5 (by omega); omega
    · have := d2 List.nodup_nil
      rw [d1] at this
      have h3 : (List.map Page.challenge pages).reverse.Nodup := by simpa using this
      exact (List.pairwise_reverse.mp h3).imp (fun h => Ne.symm h)
    · intro p hp' heq
      apply hnot
      rw [d1]
      simp only [List.append_nil, List.mem_reverse, List.mem_map]
      exact ⟨p, hp', heq⟩

/-- A failed page ends the run: nothing after it can rescue acceptance. -/
theorem failure_sticky (L : Limits) (s : State) (p : Page) (ps : List Page)
    (h : accept L s p = none) : run L s (p :: ps) = none := by
  simp [run, h]

/-- The fresh receipt may not reuse the challenge of any export page. -/
theorem fresh_distinct (L : Limits) (target : Nat) (pages : List Page) (f : Fresh)
    (h : verify L target pages f = true) (p : Page) (hp : p ∈ pages) :
    p.challenge ≠ f.challenge := (verify_complete L target pages f h).2.2.2.2.2.2.2.1 p hp

/-! Vectors mirroring `tests/recovery.rs` (paged recovery tests). -/

def L : Limits := ⟨3, 4⟩
def fr (c : Nat) : Fresh := ⟨c, true, true⟩
-- two pages 1..3, 4..6 for target 6, fresh challenge distinct
example : verify L 6 [⟨1, 3, 11⟩, ⟨4, 3, 12⟩] (fr 99) = true := by decide
-- missing first page (gap)
example : verify L 6 [⟨4, 3, 12⟩] (fr 99) = false := by decide
-- missing middle page
example : verify L 9 [⟨1, 3, 11⟩, ⟨7, 3, 13⟩] (fr 99) = false := by decide
-- overlap
example : verify L 6 [⟨1, 3, 11⟩, ⟨3, 3, 12⟩] (fr 99) = false := by decide
-- reordered
example : verify L 6 [⟨4, 3, 12⟩, ⟨1, 3, 11⟩] (fr 99) = false := by decide
-- replayed page challenge
example : verify L 6 [⟨1, 3, 11⟩, ⟨4, 3, 11⟩] (fr 99) = false := by decide
-- incomplete: last page missing
example : verify L 6 [⟨1, 3, 11⟩] (fr 99) = false := by decide
-- page past the target
example : verify L 5 [⟨1, 3, 11⟩, ⟨4, 3, 12⟩] (fr 99) = false := by decide
-- fresh receipt reuses an export challenge
example : verify L 6 [⟨1, 3, 11⟩, ⟨4, 3, 12⟩] (fr 12) = false := by decide
-- stale / non-matching / zero-challenge receipt
example : verify L 6 [⟨1, 3, 11⟩, ⟨4, 3, 12⟩] ⟨99, true, false⟩ = false := by decide
example : verify L 6 [⟨1, 3, 11⟩, ⟨4, 3, 12⟩] ⟨99, false, true⟩ = false := by decide
example : verify L 6 [⟨1, 3, 11⟩, ⟨4, 3, 12⟩] (fr 0) = false := by decide
-- per-page record cap (maxRecords 3) and aggregate page cap (maxPages 4)
example : verify L 8 [⟨1, 4, 11⟩, ⟨5, 4, 12⟩] (fr 99) = false := by decide
example : verify L 5 [⟨1, 1, 11⟩, ⟨2, 1, 12⟩, ⟨3, 1, 13⟩, ⟨4, 1, 14⟩, ⟨5, 1, 15⟩] (fr 99)
    = false := by decide
-- no pages at all / genesis target
example : verify L 0 [] (fr 99) = false := by decide
example : verify L 6 [] (fr 99) = false := by decide
-- single complete page (verify_full_recovery shape)
example : verify L 3 [⟨1, 3, 11⟩] (fr 99) = true := by decide

end TlWitnessService
