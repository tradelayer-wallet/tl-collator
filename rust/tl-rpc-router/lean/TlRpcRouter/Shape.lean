/-!
Model of `response_shape` (src/lib.rs): the provider's RpcResponseV1 must name the
server token, carry a boolean `ok`, contain only known keys, and have a result exactly
when it succeeded and an `error.message` exactly when it failed.
JSON is abstracted to the observations the Rust function makes.
-/
namespace TlRpcRouter

structure Resp where
  /-- `map.get("id").and_then(as_str) == Some(token)` -/
  idIsToken : Bool
  /-- `map.get("ok").and_then(as_bool)`; `none` covers missing and non-boolean. -/
  ok : Option Bool
  unknownKey : Bool
  hasResult : Bool
  hasError : Bool
  /-- `error.message` exists and is a string. -/
  hasErrorMessage : Bool
deriving DecidableEq, Repr

def shape (r : Resp) : Bool :=
  match r.ok with
  | none => false
  | some success =>
    if r.unknownKey then false
    else if !r.idIsToken then false
    else if success then r.hasResult && !r.hasError
    else !r.hasResult && r.hasErrorMessage

theorem shape_sound (r : Resp) (h : shape r = true) :
    r.idIsToken = true ∧ r.unknownKey = false ∧
      ((r.ok = some true ∧ r.hasResult = true ∧ r.hasError = false) ∨
        (r.ok = some false ∧ r.hasResult = false ∧ r.hasErrorMessage = true)) := by
  rcases r with ⟨i, ok, u, hr, he, hm⟩
  rcases ok with _ | s
  · simp [shape] at h
  · revert h
    cases s <;> cases i <;> cases u <;> cases hr <;> cases he <;> cases hm <;> decide

/-- A response naming any id other than the server token never settles. -/
theorem shape_requires_token (r : Resp) (h : r.idIsToken = false) : shape r = false := by
  rcases r with ⟨i, ok, u, hr, he, hm⟩
  simp only at h
  subst h
  rcases ok with _ | s
  · rfl
  · cases s <;> cases u <;> cases hr <;> cases he <;> cases hm <;> decide

-- Vectors from tests/router.rs `malformed_responses_do_not_settle`.
def good : Resp := ⟨true, some true, false, true, false, false⟩
example : shape good = true := by decide
example : shape { good with idIsToken := false } = false := by decide       -- caller id
example : shape { good with hasResult := false } = false := by decide       -- no result
example : shape { good with hasError := true } = false := by decide         -- both
example : shape ⟨true, some false, false, false, true, false⟩ = false := by decide -- no message
example : shape ⟨true, some false, false, true, true, true⟩ = false := by decide   -- result+error
example : shape { good with ok := none } = false := by decide               -- "true" string
example : shape { good with unknownKey := true } = false := by decide       -- extra key
example : shape ⟨true, some false, false, false, true, true⟩ = true := by decide  -- failure ok

end TlRpcRouter
