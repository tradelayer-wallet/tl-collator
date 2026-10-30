/-!
Model of `clearlist::decide` and `clearlist::cache_key` (src/clearlist.rs). The decision is a
pure function of: whether enforcement is on, the fail mode, the order's visibility and what the
oracle said (`OracleView`).
-/
namespace TlCollatorService

inductive Vis where
  | pub
  | restricted (group : Nat)
deriving DecidableEq, Repr

inductive Oracle where
  | notConfigured
  | answer (allowed : Bool)
  | down
deriving DecidableEq, Repr

inductive Dec where
  | allow
  | deny
deriving DecidableEq, Repr

/-- `clearlist::decide`; `failOpen = true` is `FailMode::Open`. -/
def clearDecide (enforce failOpen : Bool) (v : Vis) (o : Oracle) : Dec :=
  if enforce = false then .allow
  else match v with
    | .pub => .allow
    | .restricted _ =>
      match o with
      | .answer true => .allow
      | .answer false => .deny
      | .notConfigured => if failOpen then .allow else .deny
      | .down => if failOpen then .allow else .deny

theorem not_enforcing_allows (f : Bool) (v : Vis) (o : Oracle) :
    clearDecide false f v o = .allow := by
  simp [clearDecide]

theorem public_allows (f : Bool) (o : Oracle) : clearDecide true f .pub o = .allow := by
  simp [clearDecide]

/-- Authorization predicate: an enforced, restricted order is admitted exactly when the oracle
said yes, or the operator chose fail-open and the oracle was missing or down. -/
theorem restricted_allowed_iff (f : Bool) (g : Nat) (o : Oracle) :
    clearDecide true f (.restricted g) o = .allow ↔
      o = .answer true ∨ (f = true ∧ (o = .notConfigured ∨ o = .down)) := by
  cases o with
  | notConfigured => cases f <;> simp [clearDecide]
  | down => cases f <;> simp [clearDecide]
  | answer a => cases a <;> cases f <;> simp [clearDecide]

/-- A negative answer is never overridden, in either fail mode. -/
theorem negative_never_overridden (f : Bool) (g : Nat) :
    clearDecide true f (.restricted g) (.answer false) = .deny := by
  simp [clearDecide]

/-- Fail-closed (`f = false`) admits only on an affirmative answer. -/
theorem closed_requires_yes (g : Nat) (o : Oracle)
    (h : clearDecide true false (.restricted g) o = .allow) : o = .answer true := by
  rcases (restricted_allowed_iff false g o).mp h with h1 | ⟨h2, _⟩
  · exact h1
  · exact absurd h2 (by decide)

/-! ### Cache key injectivity (strings modelled as lists of code points) -/

/-- `cache_key`: length prefix, group, public key. -/
def cacheKey (g pk : List Nat) : List Nat := g.length :: (g ++ pk)

/-- Legacy key `groupId + "|" + pubkey`, with `0` standing for the separator character. -/
def legacyKey (g pk : List Nat) : List Nat := g ++ [0] ++ pk

theorem cacheKey_injective (g pk g' pk' : List Nat) (h : cacheKey g pk = cacheKey g' pk') :
    g = g' ∧ pk = pk' := by
  unfold cacheKey at h
  obtain ⟨h1, h2⟩ := List.cons.inj h
  exact List.append_inj h2 h1

/-- The legacy key was ambiguous: two different (group, key) pairs shared a cache entry. -/
example : legacyKey [1, 0, 2] [3] = legacyKey [1] [2, 0, 3] := by decide

example : [1, 0, 2] ≠ [1] := by decide

/-- ... while the length-prefixed key tells them apart. -/
example : cacheKey [1, 0, 2] [3] ≠ cacheKey [1] [2, 0, 3] := by decide

/-! ### Vectors shared with tests/units.rs `clearlist_decision_table` -/

example : clearDecide true false (.restricted 1) .down = .deny := by decide
example : clearDecide true true (.restricted 1) .down = .allow := by decide
example : clearDecide true true (.restricted 1) .notConfigured = .allow := by decide
example : clearDecide true false (.restricted 1) .notConfigured = .deny := by decide
example : clearDecide true true (.restricted 1) (.answer false) = .deny := by decide
example : clearDecide true false (.restricted 1) (.answer true) = .allow := by decide

end TlCollatorService
