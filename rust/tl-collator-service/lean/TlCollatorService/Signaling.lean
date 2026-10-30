/-!
Model of the signaling reducer `SignalSession` (src/signaling.rs).

`SState` is `SignalState`. `Input` is the abstract event the reducer reacts to: the five valid
inbound frame kinds, `invalid` (a frame that failed parsing/shape/bounds: Rust answers with an
error or drops it, the state is unchanged), the host events `answerReady`, `channelOpen`,
`peerFailed`, `socketClosed`, the clock event `timeout` (`expire` at or after `deadline_ms`;
the state `established` has no deadline) and `budget` (violation or message budget exhausted).
`pending` is `pending_offers()` and `offers` is `offers_accepted()`.

The model abstracts SDP/candidate content, buffers, counters and the clock; it keeps the branch
structure of `on_frame`, `on_event` and `expire` that decides the state.
-/
namespace TlCollatorService.Signaling

inductive SState where
  | idle | greeted | offering | answered | established | closed
deriving DecidableEq, Repr

inductive Input where
  | hello | offer | answer | ice | peerErr | invalid
  | answerReady | channelOpen | peerFailed | socketClosed | timeout | budget
deriving DecidableEq, Repr

structure SS where
  state : SState
  pending : Nat
  offers : Nat
deriving DecidableEq, Repr

def init : SS := { state := .idle, pending := 0, offers := 0 }

/-- `signaling::edge_allowed` (self loops included). -/
def edge : SState → SState → Bool
  | .idle, .greeted => true
  | .idle, .offering => true
  | .greeted, .offering => true
  | .offering, .answered => true
  | .answered, .established => true
  | .idle, .closed => true
  | .greeted, .closed => true
  | .offering, .closed => true
  | .answered, .closed => true
  | .established, .closed => true
  | a, b => decide (a = b)

def step (s : SS) (i : Input) : SS :=
  match s.state, i with
  | .closed, _ => s
  | .idle, .hello => { s with state := .greeted }
  | .idle, .offer => { state := .offering, pending := 1, offers := s.offers + 1 }
  | .greeted, .offer => { state := .offering, pending := 1, offers := s.offers + 1 }
  | .offering, .answerReady => { s with state := .answered, pending := 0 }
  | .answered, .channelOpen => { s with state := .established }
  | .offering, .peerFailed => { s with state := .closed, pending := 0 }
  | .answered, .peerFailed => { s with state := .closed, pending := 0 }
  | .established, .peerFailed => { s with state := .closed, pending := 0 }
  | _, .socketClosed => { s with state := .closed, pending := 0 }
  | _, .budget => { s with state := .closed, pending := 0 }
  | .idle, .timeout => { s with state := .closed, pending := 0 }
  | .greeted, .timeout => { s with state := .closed, pending := 0 }
  | .offering, .timeout => { s with state := .closed, pending := 0 }
  | .answered, .timeout => { s with state := .closed, pending := 0 }
  | _, _ => s

def run (s : SS) : List Input → SS
  | [] => s
  | i :: is => run (step s i) is

/-- The state invariant: one pending offer at most, exactly while `offering`; one accepted
offer at most; an unanswered/answered/open peer exists only after exactly one offer. -/
def Inv (s : SS) : Prop :=
  s.pending ≤ 1 ∧ (s.pending = 1 ↔ s.state = .offering) ∧ s.offers ≤ 1 ∧
    ((s.state = .idle ∨ s.state = .greeted) → s.offers = 0) ∧
    ((s.state = .offering ∨ s.state = .answered ∨ s.state = .established) → s.offers = 1)

theorem init_inv : Inv init := by
  simp [Inv, init]

/-- Every transition follows an allowed edge. -/
theorem step_edge (s : SS) (i : Input) : edge s.state (step s i).state = true := by
  obtain ⟨st, p, o⟩ := s
  cases st <;> cases i <;> simp [step, edge]

theorem step_inv (s : SS) (i : Input) (h : Inv s) : Inv (step s i) := by
  obtain ⟨st, p, o⟩ := s
  obtain ⟨h1, h2, h3, h4, h5⟩ := h
  cases st <;> cases i <;> simp_all [step, Inv]

theorem run_inv (s : SS) (is : List Input) (h : Inv s) : Inv (run s is) := by
  induction is generalizing s with
  | nil => exact h
  | cons i is ih => exact ih _ (step_inv s i h)

/-- At most one offer is ever pending and at most one is ever accepted, for any input sequence. -/
theorem at_most_one_pending (is : List Input) :
    (run init is).pending ≤ 1 ∧ (run init is).offers ≤ 1 := by
  have h := run_inv init is init_inv
  exact ⟨h.1, h.2.2.1⟩

/-- A second offer (or an offer in any state but idle/greeted) changes nothing. -/
theorem second_offer_ignored (s : SS)
    (h : s.state = .offering ∨ s.state = .answered ∨ s.state = .established ∨ s.state = .closed) :
    step s .offer = s := by
  obtain ⟨st, p, o⟩ := s
  rcases h with h | h | h | h <;> simp at h <;> subst h <;> simp [step]

/-- `closed` is absorbing. -/
theorem closed_absorbing (s : SS) (h : s.state = .closed) (is : List Input) :
    (run s is).state = .closed := by
  induction is generalizing s with
  | nil => exact h
  | cons i is ih =>
    apply ih
    obtain ⟨st, p, o⟩ := s
    simp at h; subst h; simp [step]

/-- The answer is produced only from `offering`, on the host's `answerReady`. -/
theorem answered_only_from_offering (s : SS) (i : Input)
    (h : (step s i).state = .answered) (hn : s.state ≠ .answered) :
    s.state = .offering ∧ i = .answerReady := by
  obtain ⟨st, p, o⟩ := s
  cases st <;> cases i <;> simp_all [step]

/-- The channel opens only after the answer. -/
theorem established_only_from_answered (s : SS) (i : Input)
    (h : (step s i).state = .established) (hn : s.state ≠ .established) :
    s.state = .answered ∧ i = .channelOpen := by
  obtain ⟨st, p, o⟩ := s
  cases st <;> cases i <;> simp_all [step]

/-- Any state reached from `init` is reached along allowed edges only, and a peer exists only
after exactly one accepted offer. -/
theorem peer_needs_one_offer (is : List Input)
    (h : (run init is).state = .offering ∨ (run init is).state = .answered ∨
      (run init is).state = .established) : (run init is).offers = 1 :=
  (run_inv init is init_inv).2.2.2.2 h

/-! ### Vectors shared with tests/signaling.rs -/

/-- `full_handshake_hello_offer_answer_ice_open`. -/
example : (run init [.hello, .offer, .ice, .answerReady, .ice, .channelOpen]).state = .established := by
  decide

/-- `at_most_one_pending_offer_and_one_offer_per_session`. -/
example : run init [.offer, .offer, .offer] = { state := .offering, pending := 1, offers := 1 } := by
  decide

example : run init [.offer, .answerReady, .offer] =
    { state := .answered, pending := 0, offers := 1 } := by decide

/-- `ice_before_the_offer_is_refused` and client answers: no state change. -/
example : run init [.ice, .answer, .invalid, .peerErr] = init := by decide

/-- `unanswered_offer_times_out_and_closes_the_peer`, then a late host answer is ignored. -/
example : (run init [.offer, .timeout, .answerReady]).state = .closed := by decide

/-- `data_channel_must_open_in_time_and_established_has_no_deadline`. -/
example : (run init [.offer, .answerReady, .channelOpen, .timeout]).state = .established := by decide

example : (run init [.offer, .answerReady, .timeout]).state = .closed := by decide

/-- `host_failure_sends_fixed_text_closes_peer_and_ignores_the_rest`. -/
example : run init [.offer, .peerFailed, .offer, .answerReady] =
    { state := .closed, pending := 0, offers := 1 } := by decide

/-- `edge_table_matches_the_documented_diagram`. -/
example : edge .closed .idle = false := by decide
example : edge .established .offering = false := by decide
example : edge .answered .offering = false := by decide
example : edge .offering .answered = true := by decide

end TlCollatorService.Signaling
