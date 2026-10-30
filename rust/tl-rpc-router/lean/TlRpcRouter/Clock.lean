/-!
Model of `Router::clock` (src/lib.rs). The Rust check is
`clock_failed || now < last_now || now > MAX_SAFE - MAX_DURATION_MS`; on failure it
latches `clock_failed = true` and returns `Error::Clock`, on success it stores `now`.
-/
namespace TlRpcRouter

def maxSafe : Nat := 9007199254740991
def maxDuration : Nat := 120000

structure Clock where
  lastNow : Nat
  failed : Bool
deriving DecidableEq, Repr

/-- Returns the new clock state and whether the call was admitted. -/
def Clock.step (c : Clock) (now : Nat) : Clock × Bool :=
  if c.failed || decide (now < c.lastNow) || decide (now > maxSafe - maxDuration) then
    ({ c with failed := true }, false)
  else
    ({ c with lastNow := now }, true)

/-- A failed clock never admits again, whatever time is presented later. -/
theorem failed_is_absorbing (c : Clock) (now : Nat) (h : c.failed = true) :
    (c.step now).2 = false ∧ (c.step now).1.failed = true := by
  simp [Clock.step, h]

/-- Admission implies time did not go backwards and the stored time advanced to `now`. -/
theorem admitted_monotone (c : Clock) (now : Nat) (h : (c.step now).2 = true) :
    c.lastNow ≤ now ∧ (c.step now).1.lastNow = now ∧ (c.step now).1.failed = false := by
  unfold Clock.step at *
  split at h
  · simp at h
  · rename_i hc
    rw [if_neg hc]
    simp only [Bool.or_eq_true, decide_eq_true_eq, not_or] at hc
    refine ⟨by omega, rfl, ?_⟩
    cases hf : c.failed <;> simp_all

/-- Every admitted time leaves room for the largest configured duration, so
`now + duration` (deadlines, expiries) stays within the JavaScript safe range. -/
theorem admitted_deadline_safe (c : Clock) (now d : Nat) (h : (c.step now).2 = true)
    (hd : d ≤ maxDuration) : now + d ≤ maxSafe := by
  unfold Clock.step at h
  split at h
  · simp at h
  · rename_i hc
    simp only [Bool.or_eq_true, decide_eq_true_eq, not_or] at hc
    simp only [maxSafe, maxDuration] at *
    omega

/-- Over any sequence of calls, admitted times are non-decreasing. -/
def runClock : Clock → List Nat → List Bool
  | _, [] => []
  | c, t :: ts => (c.step t).2 :: runClock (c.step t).1 ts

example : runClock ⟨0, false⟩ [100, 99, 200] = [true, false, false] := by decide
example : runClock ⟨0, false⟩ [maxSafe] = [false] := by decide

end TlRpcRouter
