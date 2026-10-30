/-!
Model of provider selection in `Router::route` (src/lib.rs). Node ids and sessions
are abstracted to `Nat`, method names to `Nat`; candidates are assumed to be in the
`(node, session)` order produced by the Rust `candidates.sort()`.

Rust:
```
eligible = id != requester && now < a.expires && a.methods contains method
        && preferred.is_none_or(|n| n == a.node) && pending_for_provider(id) < per_provider
selected = candidates.find(|(node,_)| last.is_none_or(|l| node > l)).or(candidates.first())
```
-/
namespace TlRpcRouter

structure Advert where
  session : Nat
  node : Nat
  expires : Nat
  methods : List Nat
  /-- `pending_for_provider(session)` at routing time. -/
  load : Nat
deriving DecidableEq, Repr

def eligible (requester now m : Nat) (pref : Option Nat) (perProvider : Nat) (a : Advert) :
    Bool :=
  a.session != requester && decide (now < a.expires) && a.methods.contains m &&
    pref.all (· == a.node) && decide (a.load < perProvider)

def pick (last : Option Nat) (cs : List Advert) : Option Advert :=
  (cs.find? (fun a => last.all (· < a.node))).orElse (fun _ => cs.head?)

def choose (requester now m : Nat) (pref : Option Nat) (perProvider : Nat)
    (last : Option Nat) (ads : List Advert) : Option Advert :=
  pick last (ads.filter (eligible requester now m pref perProvider))

theorem pick_mem (last : Option Nat) (cs : List Advert) (a : Advert)
    (h : pick last cs = some a) : a ∈ cs := by
  unfold pick at h
  cases hf : cs.find? (fun b => last.all (· < b.node)) with
  | some b =>
    simp only [hf, Option.orElse] at h
    cases h
    exact List.mem_of_find?_eq_some hf
  | none =>
    simp only [hf, Option.orElse] at h
    cases cs with
    | nil => simp at h
    | cons x xs =>
      simp only [List.head?_cons, Option.some.injEq] at h
      subst h
      exact List.mem_cons_self

theorem pick_some_of_nonempty (last : Option Nat) (cs : List Advert) (h : cs ≠ []) :
    (pick last cs).isSome = true := by
  unfold pick
  cases hf : cs.find? (fun b => last.all (· < b.node)) with
  | some b => simp [Option.orElse]
  | none =>
    cases cs with
    | nil => exact absurd rfl h
    | cons x xs => simp [Option.orElse]

/-- The chosen provider is an advertisement that satisfies every eligibility check:
it is not the requester, its advertisement is live, it advertised the method, it honours
the caller's preference and it is below its per-provider pending cap. -/
theorem choose_sound (requester now m : Nat) (pref : Option Nat) (perProvider : Nat)
    (last : Option Nat) (ads : List Advert) (a : Advert)
    (h : choose requester now m pref perProvider last ads = some a) :
    a ∈ ads ∧ a.session ≠ requester ∧ now < a.expires ∧ m ∈ a.methods ∧
      pref.all (· == a.node) = true ∧ a.load < perProvider := by
  have hm := pick_mem _ _ _ h
  rw [List.mem_filter] at hm
  obtain ⟨hin, he⟩ := hm
  simp only [eligible, Bool.and_eq_true, bne_iff_ne, ne_eq, decide_eq_true_eq,
    List.contains_iff_mem] at he
  obtain ⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩ := he
  exact ⟨hin, h1, h2, h3, h4, h5⟩

/-- Liveness: if any advertisement is eligible, routing selects someone. -/
theorem choose_some_of_eligible (requester now m : Nat) (pref : Option Nat)
    (perProvider : Nat) (last : Option Nat) (ads : List Advert) (a : Advert)
    (hin : a ∈ ads) (he : eligible requester now m pref perProvider a = true) :
    (choose requester now m pref perProvider last ads).isSome = true := by
  apply pick_some_of_nonempty
  intro hnil
  have : a ∈ ads.filter (eligible requester now m pref perProvider) :=
    List.mem_filter.mpr ⟨hin, he⟩
  rw [hnil] at this
  simp at this

/-- Round robin: when some candidate node is above the previous choice, the choice moves
strictly forward; otherwise it wraps to the first candidate. -/
theorem pick_advances (l : Nat) (cs : List Advert) (a : Advert)
    (h : cs.find? (fun b => (some l).all (· < b.node)) = some a) :
    pick (some l) cs = some a ∧ l < a.node := by
  have h' : cs.find? (fun b => decide (l < b.node)) = some a := by simpa [Option.all] using h
  refine ⟨by simp [pick, Option.orElse, h'], ?_⟩
  have := List.find?_some h'
  simpa using this

-- Vectors shared with tests/router.rs `round_robin_between_providers_and_preference`:
-- node-a = 1, node-b = 2, both live with method 0.
def adA : Advert := ⟨10, 1, 45010, [0], 0⟩
def adB : Advert := ⟨11, 2, 45010, [0], 0⟩

example : (choose 99 11 0 none 64 none [adA, adB]).map (·.node) = some 1 := by decide
example : (choose 99 11 0 none 64 (some 1) [adA, adB]).map (·.node) = some 2 := by decide
example : (choose 99 11 0 none 64 (some 2) [adA, adB]).map (·.node) = some 1 := by decide
example : (choose 99 11 0 (some 2) 64 (some 2) [adA, adB]).map (·.node) = some 2 := by decide
-- The requester never serves itself (`requester_never_serves_itself...`).
example : choose 10 11 0 none 64 none [adA] = none := by decide
-- Expired advertisement (`now = 10 + advertisement_ms`).
example : choose 99 45010 0 none 64 none [adA] = none := by decide
-- Per-provider cap reached.
example : choose 99 11 0 none 1 none [{ adA with load := 1 }] = none := by decide

end TlRpcRouter
