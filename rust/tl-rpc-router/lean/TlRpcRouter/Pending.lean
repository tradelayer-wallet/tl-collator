/-!
Model of the pending-request table in `Router::{route, settle, expire, close_session}`.
Tokens are abstracted to the counter value that minted them (the Rust token is
SHA-256 over the boot secret and that counter; hash collision resistance is assumed,
not proved). The Rust table is a `BTreeMap<token, Pending>`; here a list whose
tokens are kept distinct by the freshness invariant.
-/
namespace TlRpcRouter

structure Pend where
  token : Nat
  requester : Nat
  provider : Nat
  deadline : Nat
deriving DecidableEq, Repr

structure St where
  pending : List Pend
  counter : Nat
deriving DecidableEq, Repr

def countReq (ps : List Pend) (r : Nat) : Nat := (ps.filter (fun p => p.requester == r)).length

/-- Admission in `route` after a provider was chosen: global cap, per-requester cap,
then a fresh token from the incremented counter. -/
def admit (cap perReq : Nat) (s : St) (requester provider now timeout : Nat) :
    Option (St × Nat) :=
  if s.pending.length < cap ∧ countReq s.pending requester < perReq then
    let t := s.counter + 1
    some ({ pending := s.pending ++ [⟨t, requester, provider, now + timeout⟩], counter := t }, t)
  else none

def Fresh (s : St) : Prop := ∀ p ∈ s.pending, p.token ≤ s.counter

theorem admit_global_cap (cap perReq : Nat) (s s' : St) (r q now to t : Nat)
    (h : admit cap perReq s r q now to = some (s', t)) : s'.pending.length ≤ cap := by
  unfold admit at h
  split at h
  · rename_i hc
    simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    simp only [List.length_append, List.length_cons, List.length_nil]
    omega
  · simp at h

theorem admit_requester_cap (cap perReq : Nat) (s s' : St) (r q now to t : Nat)
    (h : admit cap perReq s r q now to = some (s', t)) : countReq s'.pending r ≤ perReq := by
  unfold admit at h
  split at h
  · rename_i hc
    simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    simp only [countReq, List.filter_append, List.length_append] at *
    simp only [List.filter_cons, beq_self_eq_true, ite_true, List.filter_nil,
      List.length_cons, List.length_nil]
    omega
  · simp at h

/-- The minted token is new and the freshness invariant is preserved, so tokens in the
table stay pairwise distinct and a caller can never address another request by guessing
an old counter value. -/
theorem admit_fresh (cap perReq : Nat) (s s' : St) (r q now to t : Nat) (hf : Fresh s)
    (h : admit cap perReq s r q now to = some (s', t)) :
    Fresh s' ∧ (∀ p ∈ s.pending, p.token ≠ t) ∧ s'.counter = t := by
  unfold admit at h
  split at h
  · simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    refine ⟨?_, ?_, rfl⟩
    · intro p hp
      simp only [List.mem_append, List.mem_cons, List.not_mem_nil, or_false] at hp
      rcases hp with hp | rfl
      · have := hf p hp; simp only; omega
      · simp
    · intro p hp heq
      have := hf p hp
      omega
  · simp at h

inductive Outcome where
  | answered
  | timedOut
deriving DecidableEq, Repr

inductive Err where
  | unknownRequest
  | wrongProvider
deriving DecidableEq, Repr

/-- `settle`: unknown token, then sender ownership, then deadline. Shape/advert checks
that can only refuse (never remove) are outside this model. -/
def settle (s : St) (sender token now : Nat) : Except Err (Outcome × St) :=
  match s.pending.find? (fun p => p.token == token) with
  | none => .error .unknownRequest
  | some p =>
    if p.provider != sender then .error .wrongProvider
    else
      let rest := { s with pending := s.pending.filter (fun x => x.token != token) }
      if now ≥ p.deadline then .ok (.timedOut, rest) else .ok (.answered, rest)

/-- Only the session the request was dispatched to can complete it (repairs the legacy
collator, which accepted an RPC_RES with a matching id from any session). -/
theorem settle_requires_provider (s : St) (sender token now : Nat) (o : Outcome) (s' : St)
    (h : settle s sender token now = .ok (o, s')) :
    ∃ p ∈ s.pending, p.token = token ∧ p.provider = sender := by
  unfold settle at h
  split at h
  · simp at h
  · rename_i p hp
    split at h
    · simp at h
    · rename_i hne
      refine ⟨p, List.mem_of_find?_eq_some hp, ?_, ?_⟩
      · have := List.find?_some hp; simpa using this
      · simpa using hne

/-- A completion removes exactly the settled token and nothing else. -/
theorem settle_removes_only_token (s : St) (sender token now : Nat) (o : Outcome) (s' : St)
    (h : settle s sender token now = .ok (o, s')) :
    s'.pending = s.pending.filter (fun x => x.token != token) ∧ s'.counter = s.counter := by
  unfold settle at h
  split at h
  · simp at h
  · split at h
    · simp at h
    · split at h
      · simp only [Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨-, rfl⟩ := h
        exact ⟨rfl, rfl⟩
      · simp only [Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨-, rfl⟩ := h
        exact ⟨rfl, rfl⟩

/-- A wrong sender gets an error, so the table is untouched even past the deadline. -/
theorem settle_wrong_sender (s : St) (sender token now : Nat) (p : Pend)
    (hp : s.pending.find? (fun x => x.token == token) = some p) (hs : p.provider ≠ sender) :
    settle s sender token now = .error .wrongProvider := by
  simp [settle, hp, hs]

def expire (s : St) (now : Nat) : St :=
  { s with pending := s.pending.filter (fun p => decide (now < p.deadline)) }

theorem expire_exact (s : St) (now : Nat) (p : Pend) (hp : p ∈ s.pending) :
    p ∈ (expire s now).pending ↔ now < p.deadline := by
  simp [expire, List.mem_filter, hp]

def closeSession (s : St) (sess : Nat) : St :=
  { s with pending := s.pending.filter (fun p => p.provider != sess && p.requester != sess) }

theorem close_clears_session (s : St) (sess : Nat) (p : Pend)
    (hp : p ∈ (closeSession s sess).pending) : p.provider ≠ sess ∧ p.requester ≠ sess := by
  simp only [closeSession, List.mem_filter, Bool.and_eq_true, bne_iff_ne, ne_eq] at hp
  exact hp.2

theorem close_keeps_others (s : St) (sess : Nat) (p : Pend) (hp : p ∈ s.pending)
    (h1 : p.provider ≠ sess) (h2 : p.requester ≠ sess) : p ∈ (closeSession s sess).pending := by
  simp [closeSession, List.mem_filter, hp, h1, h2]

-- Vectors mirroring tests/router.rs `per_requester_per_provider_and_global_caps`
-- (pending = 3, per_requester = 2): requester 1 twice, third refused; requester 2 once,
-- then the global cap refuses.
def s0 : St := ⟨[], 0⟩
example : (admit 3 2 s0 1 9 11 5000).isSome = true := by decide
example :
    (do let (a, _) ← admit 3 2 s0 1 9 11 5000
        let (b, _) ← admit 3 2 a 1 9 11 5000
        admit 3 2 b 1 9 11 5000).isNone = true := by decide
example :
    (do let (a, _) ← admit 3 2 s0 1 9 11 5000
        let (b, _) ← admit 3 2 a 1 9 11 5000
        let (c, _) ← admit 3 2 b 2 9 11 5000
        admit 3 2 c 2 9 11 5000).isNone = true := by decide
-- `response_from_non_provider_session_is_refused_and_kept_pending`.
def errOf {α : Type} : Except Err α → Option Err
  | .error e => some e
  | .ok _ => none

def s1 : St := ⟨[⟨1, 5, 9, 5011⟩], 1⟩
example : errOf (settle s1 6 1 12) = some .wrongProvider := by decide
example : errOf (settle s1 6 1 1000000) = some .wrongProvider := by decide
example : (settle s1 9 1 1000000).toOption.map (·.1) = some .timedOut := by decide
example : (settle s1 9 1 12).toOption.map (·.1) = some .answered := by decide
example : errOf (settle s1 9 2 12) = some .unknownRequest := by decide
-- `settle_at_deadline_is_a_timeout`: deadline 5010 reached exactly.
example : (settle ⟨[⟨1, 5, 9, 5010⟩], 1⟩ 9 1 5010).toOption.map (·.1) = some .timedOut := by
  decide

end TlRpcRouter
