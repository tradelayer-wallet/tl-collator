/-!
Model of `ratelimit::TokenBucket` (src/ratelimit.rs). Tokens are integer milli-tokens;
`rate` tokens per second is `rate` milli-tokens per millisecond, exactly as in the Rust code.

Rust `refill`: if `now <= last` nothing happens; otherwise
`milli := min (cap*1000) (milli + (now-last)*rate)` and `last := now`.
Rust `allow cost now`: refill, then spend `cost*1000` milli-tokens iff available.
The model abstracts `u32`/`u64` overflow: the Rust code clamps `cap`/`rate` to 1e6 and computes
the refill in `u128`, so no intermediate value wraps.
-/
namespace TlCollatorService

set_option maxRecDepth 8000

structure Bucket where
  cap : Nat
  rate : Nat
  milli : Nat
  last : Nat
deriving DecidableEq, Repr

/-- `TokenBucket::new`: starts full at time `t0`. -/
def Bucket.init (cap rate t0 : Nat) : Bucket := ⟨cap, rate, cap * 1000, t0⟩

/-- `TokenBucket::refill`. -/
def Bucket.refill (b : Bucket) (now : Nat) : Bucket :=
  if b.last < now then
    { b with milli := min (b.cap * 1000) (b.milli + (now - b.last) * b.rate), last := now }
  else b

/-- `TokenBucket::allow`. -/
def Bucket.allow (b : Bucket) (cost now : Nat) : Bucket × Bool :=
  let r := b.refill now
  if cost * 1000 ≤ r.milli then ({ r with milli := r.milli - cost * 1000 }, true) else (r, false)

theorem refill_cap (b : Bucket) (now : Nat) : (b.refill now).cap = b.cap := by
  unfold Bucket.refill; split <;> rfl

theorem refill_rate (b : Bucket) (now : Nat) : (b.refill now).rate = b.rate := by
  unfold Bucket.refill; split <;> rfl

theorem allow_cap (b : Bucket) (cost now : Nat) : (b.allow cost now).1.cap = b.cap := by
  unfold Bucket.allow; dsimp only; split <;> exact refill_cap b now

theorem allow_rate (b : Bucket) (cost now : Nat) : (b.allow cost now).1.rate = b.rate := by
  unfold Bucket.allow; dsimp only; split <;> exact refill_rate b now

/-- The bucket never holds more than its capacity, whatever the clock does. -/
theorem allow_capacity (b : Bucket) (cost now : Nat) (h : b.milli ≤ b.cap * 1000) :
    (b.allow cost now).1.milli ≤ b.cap * 1000 := by
  unfold Bucket.allow Bucket.refill
  dsimp only
  by_cases hl : b.last < now
  · rw [if_pos hl]
    dsimp only
    by_cases hc : cost * 1000 ≤ min (b.cap * 1000) (b.milli + (now - b.last) * b.rate)
    · rw [if_pos hc]; dsimp only; omega
    · rw [if_neg hc]; dsimp only; omega
  · rw [if_neg hl]
    by_cases hc : cost * 1000 ≤ b.milli
    · rw [if_pos hc]; dsimp only; omega
    · rw [if_neg hc]; omega

/-- A backwards or repeated clock reading adds nothing. -/
theorem refill_no_gain (b : Bucket) (now : Nat) (h : now ≤ b.last) : b.refill now = b := by
  unfold Bucket.refill
  rw [if_neg (by omega)]

/-- A grant spends exactly `cost` tokens; a refusal spends nothing. -/
theorem allow_true_spends (b : Bucket) (cost now : Nat) (h : (b.allow cost now).2 = true) :
    (b.allow cost now).1.milli + cost * 1000 = (b.refill now).milli := by
  unfold Bucket.allow at *
  dsimp only at *
  split at h
  · rename_i hc
    simp only [if_pos hc]
    omega
  · simp at h

theorem allow_false_keeps (b : Bucket) (cost now : Nat) (h : (b.allow cost now).2 = false) :
    (b.allow cost now).1 = b.refill now := by
  unfold Bucket.allow at *
  dsimp only at *
  split at h
  · simp at h
  · rename_i hc
    simp only [if_neg hc]

/-! ### Burst plus rate bound -/

/-- Ghost run state: the bucket, the total whole tokens granted so far, and the start time. -/
structure Run where
  b : Bucket
  spent : Nat
  t0 : Nat

def Run.start (cap rate t0 : Nat) : Run := ⟨Bucket.init cap rate t0, 0, t0⟩

def Run.step (r : Run) (cost now : Nat) : Run :=
  let p := r.b.allow cost now
  { r with b := p.1, spent := match p.2 with | true => r.spent + cost | false => r.spent }

/-- Invariant: capacity bound, time never before the start, and
`milli + 1000*spent <= 1000*cap + rate*(last - t0)` (tokens granted never exceed what the bucket
was given: the initial burst plus the refill earned since the start). -/
def Run.Inv (r : Run) : Prop :=
  r.b.milli ≤ r.b.cap * 1000 ∧ r.t0 ≤ r.b.last ∧
    r.b.milli + r.spent * 1000 ≤ r.b.cap * 1000 + (r.b.last - r.t0) * r.b.rate

theorem start_inv (cap rate t0 : Nat) : (Run.start cap rate t0).Inv := by
  unfold Run.start Run.Inv Bucket.init
  simp

theorem mul_split (t0 l n r : Nat) (h1 : t0 ≤ l) (h2 : l ≤ n) :
    (n - t0) * r = (l - t0) * r + (n - l) * r := by
  have : n - t0 = (l - t0) + (n - l) := by omega
  rw [this, Nat.add_mul]

theorem step_cap (r : Run) (c n : Nat) : (r.step c n).b.cap = r.b.cap := allow_cap r.b c n

theorem step_rate (r : Run) (c n : Nat) : (r.step c n).b.rate = r.b.rate := allow_rate r.b c n

theorem step_t0 (r : Run) (c n : Nat) : (r.step c n).t0 = r.t0 := rfl

theorem step_inv (r : Run) (cost now : Nat) (h : r.Inv) : (r.step cost now).Inv := by
  obtain ⟨b, spent, t0⟩ := r
  obtain ⟨cap, rate, milli, last⟩ := b
  obtain ⟨h1, h2, h3⟩ := h
  simp only at h1 h2 h3
  unfold Run.step Bucket.allow Bucket.refill Run.Inv
  dsimp only
  by_cases hl : last < now
  · have hm := mul_split t0 last now rate h2 (by omega)
    rw [if_pos hl]
    dsimp only
    by_cases hc : cost * 1000 ≤ min (cap * 1000) (milli + (now - last) * rate)
    · rw [if_pos hc]
      dsimp only
      refine ⟨by omega, by omega, ?_⟩
      omega
    · rw [if_neg hc]
      dsimp only
      refine ⟨by omega, by omega, ?_⟩
      omega
  · rw [if_neg hl]
    dsimp only
    by_cases hc : cost * 1000 ≤ milli
    · rw [if_pos hc]
      dsimp only
      refine ⟨by omega, by omega, ?_⟩
      omega
    · rw [if_neg hc]
      dsimp only
      exact ⟨h1, h2, h3⟩

/-- Running any sequence of `(cost, now)` requests. -/
def Run.exec (r : Run) : List (Nat × Nat) → Run
  | [] => r
  | (c, n) :: rest => (r.step c n).exec rest

theorem exec_inv (r : Run) (ops : List (Nat × Nat)) (h : r.Inv) : (r.exec ops).Inv := by
  induction ops generalizing r with
  | nil => exact h
  | cons op rest ih => exact ih _ (step_inv r op.1 op.2 h)

/-- Main safety statement: after any sequence of requests the whole tokens granted are at most
the burst plus `rate * elapsed / 1000`, and the bucket is never above capacity. -/
theorem grants_bounded (cap rate t0 : Nat) (ops : List (Nat × Nat)) :
    let r := (Run.start cap rate t0).exec ops
    r.spent * 1000 ≤ cap * 1000 + (r.b.last - t0) * rate ∧ r.b.milli ≤ cap * 1000 := by
  have h := exec_inv _ ops (start_inv cap rate t0)
  obtain ⟨h1, _, h3⟩ := h
  -- cap and rate and t0 are preserved by every step
  have hcap : ∀ (r : Run) (ops : List (Nat × Nat)), (r.exec ops).b.cap = r.b.cap ∧
      (r.exec ops).b.rate = r.b.rate ∧ (r.exec ops).t0 = r.t0 := by
    intro r ops
    induction ops generalizing r with
    | nil => exact ⟨rfl, rfl, rfl⟩
    | cons op rest ih =>
      obtain ⟨cc, nn⟩ := op
      obtain ⟨a, b, c⟩ := ih (r.step cc nn)
      show ((r.step cc nn).exec rest).b.cap = r.b.cap ∧ ((r.step cc nn).exec rest).b.rate = r.b.rate ∧
        ((r.step cc nn).exec rest).t0 = r.t0
      exact ⟨a.trans (step_cap r cc nn), b.trans (step_rate r cc nn), c.trans (step_t0 r cc nn)⟩
  obtain ⟨c1, c2, c3⟩ := hcap (Run.start cap rate t0) ops
  have c1' : ((Run.start cap rate t0).exec ops).b.cap = cap := c1
  have c2' : ((Run.start cap rate t0).exec ops).b.rate = rate := c2
  have c3' : ((Run.start cap rate t0).exec ops).t0 = t0 := c3
  simp only
  rw [c1'] at h1
  rw [c1', c2', c3'] at h3
  constructor
  · omega
  · exact h1

/-! ### Vectors shared with tests/units.rs -/

/-- `bucket_burst_refill_and_cap`: capacity 3, 2 tokens per second, start at 1000 ms. -/
example : (Bucket.init 3 2 1000).allow 1 1000 =
    ({ cap := 3, rate := 2, milli := 2000, last := 1000 }, true) := by decide

example : ((Bucket.init 3 2 1000).allow 3 1000).1.allow 1 1499 =
    ({ cap := 3, rate := 2, milli := 998, last := 1499 }, false) := by decide

example : (((Bucket.init 3 2 1000).allow 3 1000).1.allow 1 1500).2 = true := by decide

/-- A cost above capacity can never be granted. -/
example : ((Bucket.init 2 1 5000).allow 3 5000).2 = false := by decide

/-- A backwards clock neither refills nor panics (`bucket_cost_zero_and_over_capacity_and_backwards_clock`). -/
example : (((Bucket.init 2 1 5000).allow 2 5000).1.allow 1 1000).2 = false := by decide

end TlCollatorService
