/-!
Model of `lru::LruMap::insert` / `LruSet::add` (src/lru.rs). The container is a list of keys,
oldest first (`keys_oldest_first`). Keys are `Nat`: any key, including `0` (the model of the empty
string), takes part in eviction, unlike the legacy `if (oldest)` guard.

Rust `insert`: remove the key if present, append it as newest, and if `len > max` remove the oldest.
The Rust version tracks recency with a tick counter; the list order is what the ticks encode.
-/
namespace TlCollatorService

def touch (cap : Nat) (l : List Nat) (k : Nat) : List Nat :=
  let l' := l.filter (fun x => x ≠ k) ++ [k]
  if cap < l'.length then l'.drop 1 else l'

/-- The bound holds after every insertion, for every key. -/
theorem touch_length_le (cap : Nat) (l : List Nat) (k : Nat) (h : l.length ≤ cap) :
    (touch cap l k).length ≤ cap := by
  unfold touch
  have := List.length_filter_le (fun x => x ≠ k) l
  dsimp only
  split
  · simp only [List.length_drop, List.length_append, List.length_singleton]
    omega
  · rename_i hn
    omega

/-- The key just inserted is present (capacity at least 1). -/
theorem touch_mem (cap : Nat) (l : List Nat) (k : Nat) (hc : 1 ≤ cap) : k ∈ touch cap l k := by
  unfold touch
  dsimp only
  split
  · rename_i hn
    -- the list is `filter ++ [k]`; dropping one element removes a non-last element
    generalize hf : l.filter (fun x => x ≠ k) = f
    rw [hf] at hn
    cases f with
    | nil => simp at hn; omega
    | cons x xs => simp
  · simp

/-- Insertion never invents keys. -/
theorem touch_subset (cap : Nat) (l : List Nat) (k j : Nat) (h : j ∈ touch cap l k) :
    j = k ∨ j ∈ l := by
  unfold touch at h
  dsimp only at h
  have hd : ∀ (m : List Nat), j ∈ m.drop 1 → j ∈ m := fun m hm => List.mem_of_mem_drop hm
  have key : j ∈ l.filter (fun x => x ≠ k) ++ [k] → j = k ∨ j ∈ l := by
    intro hj
    rcases List.mem_append.mp hj with h1 | h1
    · exact Or.inr (List.mem_filter.mp h1).1
    · exact Or.inl (by simpa using h1)
  split at h
  · exact key (hd _ h)
  · exact key h

/-- When a new key arrives at a full container the oldest key is evicted and the order of the
remaining keys is unchanged. -/
theorem touch_evicts_oldest (cap : Nat) (x : Nat) (xs : List Nat) (k : Nat) (hc : 1 ≤ cap)
    (hlen : (x :: xs).length = cap) (hk : k ∉ x :: xs) :
    touch cap (x :: xs) k = xs ++ [k] := by
  unfold touch
  have hf : (x :: xs).filter (fun y => y ≠ k) = x :: xs := by
    apply List.filter_eq_self.mpr
    intro a ha
    simp only [decide_eq_true_eq]
    intro hak
    exact hk (hak ▸ ha)
  rw [hf]
  have hlt : cap < (x :: xs ++ [k]).length := by simp at hlen ⊢; omega
  dsimp only
  split
  · simp
  · rename_i hn; exact absurd hlt hn

/-- Below capacity nothing is evicted. -/
theorem touch_no_eviction (cap : Nat) (l : List Nat) (k : Nat) (hk : k ∉ l) (h : l.length < cap) :
    touch cap l k = l ++ [k] := by
  unfold touch
  have hf : l.filter (fun y => y ≠ k) = l := by
    apply List.filter_eq_self.mpr
    intro a ha
    simp only [decide_eq_true_eq]
    intro hak
    exact hk (hak ▸ ha)
  rw [hf]
  have hlt : ¬ cap < (l ++ [k]).length := by simp; omega
  dsimp only
  split
  · rename_i hn; exact absurd hn hlt
  · rfl

/-- Re-adding the oldest key makes it the newest (refresh), shown on a concrete container
that matches `lru_set_evicts_oldest_and_refreshes_on_add` in tests/units.rs (a=1,b=2,c=3,d=4). -/
example : touch 2 (touch 2 (touch 2 (touch 2 (touch 2 [] 1) 2) 3) 2) 4 = [2, 4] := by decide

/-- After `a, b, c` into capacity 2 the survivors are `b, c` in order. -/
example : touch 2 (touch 2 (touch 2 [] 1) 2) 3 = [2, 3] := by decide

/-- The empty-string regression (`lru_map_get_refreshes_and_the_empty_key_is_evictable`): key `0` is
inserted first with capacity 2 and is evicted by the third insertion. -/
example : touch 2 (touch 2 (touch 2 [] 0) 7) 8 = [7, 8] := by decide

end TlCollatorService
