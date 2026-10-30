/-!
Model of `Service::pump_replay` (src/service.rs). The tape holds sequence numbers `1 .. last`.
A TAPE_SUB session has a cursor `c` (next sequence to send). One pump sends the contiguous
range `c .. c + k - 1` with `k = min n (last + 1 - c)` (`n` is `replay_batch`), advances the
cursor by `k`, and the replay is finished when the cursor passes `last` (then TAPE_END follows).
-/
namespace TlCollatorService

/-- Sequence numbers sent by one pump (`read_range(cursor, batch)` over a contiguous tape). -/
def batch (c last n : Nat) : List Nat := List.range' c (min n (last + 1 - c))

theorem batch_length_le (c last n : Nat) : (batch c last n).length ≤ n := by
  unfold batch; simp; omega

theorem batch_mem (c last n m : Nat) (h : m ∈ batch c last n) : c ≤ m ∧ m ≤ last := by
  unfold batch at h
  rw [List.mem_range'_1] at h
  omega

/-- Sequence numbers delivered by up to `fuel` pumps starting at cursor `c`. -/
def replay (last n : Nat) : Nat → Nat → List Nat
  | 0, _ => []
  | fuel + 1, c =>
    if last < c then [] else batch c last n ++ replay last n fuel (c + (batch c last n).length)

/-- The whole replay is exactly the contiguous range `c .. last`: nothing skipped, nothing
repeated, in order, provided there are enough pumps (the host pumps while `is_replaying`). -/
theorem replay_complete (last n : Nat) (hn : 1 ≤ n) :
    ∀ (fuel c : Nat), last + 1 - c ≤ fuel → replay last n fuel c = List.range' c (last + 1 - c) := by
  intro fuel
  induction fuel with
  | zero =>
    intro c h
    have : last + 1 - c = 0 := by omega
    simp [replay, this]
  | succ fuel ih =>
    intro c h
    unfold replay
    by_cases hl : last < c
    · rw [if_pos hl]
      have : last + 1 - c = 0 := by omega
      simp [this]
    · rw [if_neg hl]
      have hk : (batch c last n).length = min n (last + 1 - c) := by
        unfold batch; simp
      have hpos : 1 ≤ min n (last + 1 - c) := by omega
      have hrest := ih (c + (batch c last n).length) (by omega)
      rw [hrest, hk]
      unfold batch
      have e : last + 1 - (c + min n (last + 1 - c)) = last + 1 - c - min n (last + 1 - c) := by omega
      rw [e]
      rw [List.range'_append_1]
      congr 1
      omega

theorem replay_nodup (last n : Nat) (hn : 1 ≤ n) (fuel c : Nat) (h : last + 1 - c ≤ fuel) :
    (replay last n fuel c).Nodup := by
  rw [replay_complete last n hn fuel c h]
  exact List.nodup_range'

/-- Every delivered sequence number is a real tape entry at or after the requested start. -/
theorem replay_bounds (last n : Nat) (hn : 1 ≤ n) (fuel c m : Nat) (h : last + 1 - c ≤ fuel)
    (hm : m ∈ replay last n fuel c) : c ≤ m ∧ m ≤ last := by
  rw [replay_complete last n hn fuel c h, List.mem_range'_1] at hm
  omega

/-- A start beyond the end of the tape yields no entries (only TAPE_END). -/
theorem replay_beyond_end (last n fuel c : Nat) (h : last < c) : replay last n fuel c = [] := by
  cases fuel with
  | zero => rfl
  | succ f => simp [replay, h]

/-! ### Vectors shared with tests/reducer.rs `replay_is_contiguous_batched_...` -/

/-- Batch size 2, entries 1..5, `fromSeq = 2`: the first pump sends 2 and 3. -/
example : batch 2 5 2 = [2, 3] := by decide

/-- Second pump from cursor 4 sends 4 and 5. -/
example : batch 4 5 2 = [4, 5] := by decide

/-- The tape grew to 6 during the replay: the replay reaches the new entry and ends there. -/
example : replay 6 2 10 2 = [2, 3, 4, 5, 6] := by decide

/-- `fromSeq` beyond the tape: nothing but TAPE_END (`replay_start_is_clamped_...`). -/
example : replay 3 500 10 99 = [] := by decide

/-- Default batch of 500 over a short tape sends everything in one pump. -/
example : batch 1 3 500 = [1, 2, 3] := by decide

end TlCollatorService
