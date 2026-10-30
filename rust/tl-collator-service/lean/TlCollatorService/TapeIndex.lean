/-!
Model of the sparse tape index (src/tapeindex.rs, from `src/tapeIndex.ts`).

The index of a contiguous tape `1 .. last` with stride `s` holds the sequence numbers
`k * s + 1` (`seqs`; Rust: entries with `seq == 1 || (seq - 1) % s == 0`). A lookup
(`TapeIndex::find_start`, TS `findStartOffset`) returns the greatest indexed sequence number at
or before the target; `find` models it over the ascending list of indexed sequence numbers and
`none` stands for the start of the file. Offsets are abstracted away: the Rust tests tie each
indexed `seq` to its byte offset.
-/
namespace TlCollatorService.TapeIndex

/-- Greatest element `<= t` of an ascending list, `none` when the head is already beyond `t`. -/
def find : List Nat → Nat → Option Nat
  | [], _ => none
  | e :: es, t =>
    if e ≤ t then
      (match find es t with
        | none => some e
        | some r => some r)
    else none

/-- The indexed sequence numbers of a tape with `n` blocks: `1, 1 + s, 1 + 2 s, ...`. -/
def seqs (stride n : Nat) : List Nat := List.range' 1 n stride

theorem find_le (es : List Nat) (t r : Nat) (h : find es t = some r) : r ≤ t := by
  induction es generalizing r with
  | nil => simp [find] at h
  | cons e es ih =>
    unfold find at h
    by_cases he : e ≤ t
    · rw [if_pos he] at h
      cases hf : find es t with
      | none => rw [hf] at h; simp at h; omega
      | some r' => rw [hf] at h; simp at h; subst h; exact ih r' hf
    · rw [if_neg he] at h; simp at h

theorem find_mem (es : List Nat) (t r : Nat) (h : find es t = some r) : r ∈ es := by
  induction es generalizing r with
  | nil => simp [find] at h
  | cons e es ih =>
    unfold find at h
    by_cases he : e ≤ t
    · rw [if_pos he] at h
      cases hf : find es t with
      | none => rw [hf] at h; simp at h; subst h; simp
      | some r' => rw [hf] at h; simp at h; subst h; exact List.mem_cons_of_mem _ (ih r' hf)
    · rw [if_neg he] at h; simp at h

/-- On an ascending list, an element at or before `t` guarantees an answer. -/
theorem find_isSome (es : List Nat) (hs : es.Pairwise (· < ·)) (t x : Nat) (hx : x ∈ es)
    (hxt : x ≤ t) : ∃ r, find es t = some r := by
  induction es with
  | nil => simp at hx
  | cons e es ih =>
    obtain ⟨hlt, hrest⟩ := List.pairwise_cons.mp hs
    unfold find
    have het : e ≤ t := by
      rcases List.mem_cons.mp hx with h | h
      · subst h; exact hxt
      · have := hlt x h; omega
    rw [if_pos het]
    cases hf : find es t with
    | none => exact ⟨e, rfl⟩
    | some r => exact ⟨r, rfl⟩

/-- Maximality: no indexed sequence number at or before `t` exceeds the result. -/
theorem find_max (es : List Nat) (hs : es.Pairwise (· < ·)) (t r : Nat) (h : find es t = some r)
    (x : Nat) (hx : x ∈ es) (hxt : x ≤ t) : x ≤ r := by
  induction es generalizing r with
  | nil => simp at hx
  | cons e es ih =>
    obtain ⟨hlt, hrest⟩ := List.pairwise_cons.mp hs
    unfold find at h
    by_cases he : e ≤ t
    · rw [if_pos he] at h
      cases hf : find es t with
      | none =>
        rw [hf] at h; simp at h; subst h
        rcases List.mem_cons.mp hx with h | h
        · omega
        · obtain ⟨r', hr'⟩ := find_isSome es hrest t x h hxt
          rw [hf] at hr'; simp at hr'
      | some r' =>
        rw [hf] at h; simp at h; subst h
        rcases List.mem_cons.mp hx with h | h
        · have := hlt r' (find_mem es t r' hf); omega
        · exact ih hrest r' hf h
    · rw [if_neg he] at h; simp at h

/-- The lookup never returns an entry beyond the target, and returns an indexed entry. -/
theorem find_sound (es : List Nat) (t r : Nat) (h : find es t = some r) : r ≤ t ∧ r ∈ es :=
  ⟨find_le es t r h, find_mem es t r h⟩

/-- `none` (start of file) only when every indexed entry is beyond the target. -/
theorem find_none (es : List Nat) (hs : es.Pairwise (· < ·)) (t : Nat) (h : find es t = none)
    (x : Nat) (hx : x ∈ es) : t < x := by
  by_cases hxt : x ≤ t
  · obtain ⟨r, hr⟩ := find_isSome es hs t x hx hxt
    rw [h] at hr; simp at hr
  · omega

theorem seqs_sorted (stride n : Nat) (h : 0 < stride) : (seqs stride n).Pairwise (· < ·) :=
  List.pairwise_lt_range' stride h

theorem mem_seqs (stride n x : Nat) : x ∈ seqs stride n ↔ ∃ k, k < n ∧ x = 1 + stride * k := by
  unfold seqs
  exact List.mem_range'

/-- The TypeScript formula `offsets[floor((fromSeq - 1) / stride)]` selects exactly this entry:
for `1 <= t`, and a tape with at least `b + 1` blocks where `b = (t - 1) / stride`, the lookup
returns `b * stride + 1`. -/
theorem find_matches_legacy (stride n t : Nat) (hs : 0 < stride) (ht : 1 ≤ t)
    (hb : (t - 1) / stride < n) :
    find (seqs stride n) t = some ((t - 1) / stride * stride + 1) := by
  have hsorted := seqs_sorted stride n hs
  have hmem : (t - 1) / stride * stride + 1 ∈ seqs stride n := by
    rw [mem_seqs]
    exact ⟨(t - 1) / stride, hb, by rw [Nat.mul_comm]; omega⟩
  have hle : (t - 1) / stride * stride + 1 ≤ t := by
    have := Nat.div_mul_le_self (t - 1) stride
    omega
  obtain ⟨r, hr⟩ := find_isSome _ hsorted t _ hmem hle
  obtain ⟨hrt, hrmem⟩ := find_sound _ t r hr
  have h1 : (t - 1) / stride * stride + 1 ≤ r := find_max _ hsorted t r hr _ hmem hle
  obtain ⟨k, hk, hkx⟩ := (mem_seqs stride n r).mp hrmem
  have h2 : k ≤ (t - 1) / stride := by
    rw [Nat.le_div_iff_mul_le hs]
    rw [Nat.mul_comm]
    omega
  have h3 : r ≤ (t - 1) / stride * stride + 1 := by
    have := Nat.mul_le_mul_right stride h2
    rw [Nat.mul_comm stride k] at hkx
    omega
  rw [hr]; congr 1; omega

/-- Bounded memory (`TapeIndex::push_line`): appending an eligible entry to an index of `len`
entries with capacity `cap >= 2` keeps `len <= cap`, by halving (keeping every other entry,
which doubles the stride) when full. -/
def pushLen (len cap : Nat) : Nat :=
  if len ≥ cap then (len + 1) / 2 + 1 else len + 1

theorem pushLen_le_cap (len cap : Nat) (hc : 2 ≤ cap) (hl : len ≤ cap) : pushLen len cap ≤ cap := by
  unfold pushLen
  split <;> omega

/-! ### Vectors shared with tests/tapeindex.rs -/

/-- Stride 7: indexed entries are 1, 8, 15, 22 (`lookup_is_the_greatest_indexed_seq...`). -/
example : seqs 7 4 = [1, 8, 15, 22] := by decide

example : find (seqs 7 15) 14 = some 8 := by decide
example : find (seqs 7 15) 15 = some 15 := by decide
example : find (seqs 7 15) 1 = some 1 := by decide
example : find (seqs 7 15) 0 = none := by decide

/-- The target is beyond the last indexed entry: the last one is returned (the TS returns offset 0
here; both then read no entry at or after the target). -/
example : find (seqs 7 4) 1000 = some 22 := by decide

/-- Stride 1 indexes everything; the TS formula gives `t`. -/
example : find (seqs 1 10) 6 = some 6 := by decide

/-- A full index of capacity 4 halves instead of growing: 4 entries, one more eligible entry. -/
example : pushLen 4 4 = 3 := by decide
example : pushLen 3 4 = 4 := by decide

end TlCollatorService.TapeIndex
