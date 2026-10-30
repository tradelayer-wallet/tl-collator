/-!
Model of `forced_command::parse` and the role-to-program choice in
`bin/witness-ssh-gate.rs` (rust/tl-witness-service).

Abstraction: the Rust code first rejects raw text over 1024 bytes or containing non-ASCII or
control bytes, then splits on ' '. Each resulting word is classified here into `Word`
(`num n` = at most 16 ASCII digits with value `n`; `hash h` = 64 lowercase hex digits with value
`h`, `h = 0` being the all-zero string; `emptyTok` = the two-character token `''`). Byte-level
string classification is not modelled; the dispatch structure, the capability split and the
argument constraints are.
-/
namespace TlWitnessService

/-- `MAX_SAFE_INTEGER` of tl-collator-wire. -/
def maxSafe : Nat := 9007199254740991

inductive Cap where
  | witness
  | recovery
deriving DecidableEq, Repr

inductive Word where
  | witnessctl
  | latest
  | cas
  | exportKw
  | emptyTok
  | num (n : Nat)
  | hash (h : Nat)
  | other
deriving DecidableEq, Repr

inductive Cmd where
  | latest (nonce : Nat)
  | cas (seq : Nat) (hash : Option Nat) (orders : Nat) (nonce : Nat)
  | export
deriving DecidableEq, Repr

/-- Mirrors `forced_command::parse`. `none` is `Err(Refused)`. -/
def parse : Cap → List Word → Option Cmd
  | .recovery, [.exportKw] => some .export
  | .witness, [.witnessctl, .latest, .hash n] =>
      if n ≠ 0 then some (.latest n) else none
  | .witness, [.witnessctl, .cas, .num seq, h, .num orders, .hash nonce] =>
      if nonce = 0 then none
      else if seq > maxSafe ∨ orders > maxSafe then none
      else if seq ≠ orders then none
      else match h with
        | .emptyTok => if seq = 0 then some (.cas seq none orders nonce) else none
        | .hash hv => if seq > 0 then some (.cas seq (some hv) orders nonce) else none
        | _ => none
  | _, _ => none

inductive Prog where
  | witnessctl
  | exporter
deriving DecidableEq, Repr

/-- The gate chooses the executable from its fixed role argument only. -/
def programFor : Cap → Prog
  | .witness => .witnessctl
  | .recovery => .exporter

/-- Parse then select the program, as `witness-ssh-gate` does. -/
def gate (c : Cap) (ws : List Word) : Option (Prog × Cmd) :=
  (parse c ws).map fun cmd => (programFor c, cmd)

/-- Complete characterization of the accepted commands. -/
theorem parse_cases (c : Cap) (ws : List Word) (cmd : Cmd) (h : parse c ws = some cmd) :
    (c = .recovery ∧ ws = [.exportKw] ∧ cmd = .export) ∨
    (c = .witness ∧ ∃ n, ws = [.witnessctl, .latest, .hash n] ∧ n ≠ 0 ∧ cmd = .latest n) ∨
    (c = .witness ∧ ∃ seq hh orders nonce,
      ws = [.witnessctl, .cas, .num seq, hh, .num orders, .hash nonce] ∧
      nonce ≠ 0 ∧ seq ≤ maxSafe ∧ seq = orders ∧
      ((hh = .emptyTok ∧ seq = 0 ∧ cmd = .cas seq none orders nonce) ∨
       (∃ hv, hh = .hash hv ∧ 0 < seq ∧ cmd = .cas seq (some hv) orders nonce))) := by
  unfold parse at h
  split at h
  · simp at h; subst h; exact Or.inl ⟨rfl, rfl, rfl⟩
  · rename_i n
    split at h
    · rename_i hn; simp at h; subst h; exact Or.inr (Or.inl ⟨rfl, n, rfl, hn, rfl⟩)
    · simp at h
  · rename_i seq hh orders nonce
    split at h
    · simp at h
    · rename_i h0
      split at h
      · simp at h
      · rename_i h1
        split at h
        · simp at h
        · rename_i h2
          have h1' : seq ≤ maxSafe := by omega
          split at h
          · split at h
            · rename_i hs
              simp at h
              refine Or.inr (Or.inr ⟨rfl, seq, .emptyTok, orders, nonce, rfl, h0, h1', by omega, ?_⟩)
              exact Or.inl ⟨rfl, hs, h.symm⟩
            · simp at h
          · rename_i hv
            split at h
            · rename_i hs
              simp at h
              refine Or.inr (Or.inr ⟨rfl, seq, .hash hv, orders, nonce, rfl, h0, h1', by omega, ?_⟩)
              exact Or.inr ⟨hv, rfl, hs, h.symm⟩
            · simp at h
          · simp at h
  · simp at h

/-- Only the exact one-word `witness-export` command parses to `export`, and only under the
recovery capability. -/
theorem parse_export (c : Cap) (ws : List Word) (h : parse c ws = some .export) :
    c = .recovery ∧ ws = [.exportKw] := by
  rcases parse_cases c ws _ h with ⟨a, b, -⟩ | ⟨-, n, -, -, e⟩ | ⟨-, s, hh, o, n, -, -, -, -, e⟩
  · exact ⟨a, b⟩
  · cases e
  · rcases e with ⟨-, -, e⟩ | ⟨hv, -, -, e⟩ <;> cases e

/-- The witness (latest/CAS) capability can never obtain `export`. -/
theorem witness_never_exports (ws : List Word) : parse .witness ws ≠ some .export := by
  intro h
  have := (parse_export .witness ws h).1
  cases this

/-- The recovery capability can obtain nothing except `export`. -/
theorem recovery_only_export (ws : List Word) (c : Cmd) (h : parse .recovery ws = some c) :
    c = .export := by
  rcases parse_cases .recovery ws c h with ⟨-, -, e⟩ | ⟨e, -⟩ | ⟨e, -⟩ <;> first | exact e | cases e

/-- The exporter program is selected only by the recovery role with the exact export word. -/
theorem exporter_requires_recovery (c : Cap) (ws : List Word) (cmd : Cmd)
    (h : gate c ws = some (.exporter, cmd)) :
    c = .recovery ∧ cmd = .export ∧ ws = [.exportKw] := by
  unfold gate at h
  cases hp : parse c ws with
  | none => simp [hp] at h
  | some cm =>
    simp only [hp, Option.map_some, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨h1, h2⟩ := h
    subst h2
    cases c with
    | witness => simp [programFor] at h1
    | recovery =>
      have he := recovery_only_export ws cm hp
      subst he
      exact ⟨rfl, rfl, (parse_export .recovery ws hp).2⟩

/-- The program and the parsed command always agree: `witnessctl` never receives `export`,
and the exporter never receives latest/CAS. -/
theorem gate_consistent (c : Cap) (ws : List Word) (p : Prog) (cmd : Cmd)
    (h : gate c ws = some (p, cmd)) : (p = .exporter ↔ cmd = .export) := by
  unfold gate at h
  cases hp : parse c ws with
  | none => simp [hp] at h
  | some cm =>
    simp only [hp, Option.map_some, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨h1, h2⟩ := h
    subst h1; subst h2
    cases c with
    | witness =>
      have hne : cm ≠ .export := fun e => witness_never_exports ws (by rw [hp, e])
      simp [programFor, hne]
    | recovery =>
      simp [programFor, recovery_only_export ws cm hp]

/-- A parsed CAS command satisfies the argument constraints enforced by the Rust parser:
safe integers, `seq = orders`, nonzero nonce, and the empty genesis hash exactly at sequence 0. -/
theorem cas_args (ws : List Word) (seq : Nat) (hash : Option Nat) (orders nonce : Nat)
    (h : parse .witness ws = some (.cas seq hash orders nonce)) :
    seq = orders ∧ seq ≤ maxSafe ∧ nonce ≠ 0 ∧ (seq = 0 ↔ hash = none) := by
  rcases parse_cases .witness ws _ h with ⟨e, -⟩ | ⟨-, n, -, -, e⟩ | ⟨-, s, hh, o, n, -, h0, h1, h2, h3⟩
  · cases e
  · cases e
  · rcases h3 with ⟨-, hs, e⟩ | ⟨hv, -, hs, e⟩
    · simp only [Cmd.cas.injEq] at e
      obtain ⟨e1, e2, e3, e4⟩ := e
      subst e1 e2 e3 e4
      exact ⟨h2, h1, h0, by simp [hs]⟩
    · simp only [Cmd.cas.injEq] at e
      obtain ⟨e1, e2, e3, e4⟩ := e
      subst e1 e2 e3 e4
      exact ⟨h2, h1, h0, by simp; omega⟩

/-- A latest command carries a nonzero challenge. -/
theorem latest_nonce (ws : List Word) (n : Nat) (h : parse .witness ws = some (.latest n)) :
    n ≠ 0 := by
  rcases parse_cases .witness ws _ h with ⟨e, -⟩ | ⟨-, m, -, hm, e⟩ | ⟨-, s, hh, o, m, -, -, -, -, h3⟩
  · cases e
  · simp only [Cmd.latest.injEq] at e; subst e; exact hm
  · rcases h3 with ⟨-, -, e⟩ | ⟨hv, -, -, e⟩ <;> cases e

/-! Vectors mirroring the Rust tests in `src/forced_command.rs`. -/

example : parse .recovery [.exportKw] = some .export := by decide
example : parse .witness [.exportKw] = none := by decide
example : parse .recovery [.witnessctl, .latest, .hash 171] = none := by decide
example : parse .witness [.witnessctl, .cas, .num 0, .emptyTok, .num 0, .hash 171]
    = some (.cas 0 none 0 171) := by decide
-- `cas 0  0 nonce` (empty hash dropped by the shell): a word is missing
example : parse .witness [.witnessctl, .cas, .num 0, .num 0, .hash 171] = none := by decide
example : parse .witness [.witnessctl, .cas, .num 1, .hash 170, .num 1, .hash 171]
    = some (.cas 1 (some 170) 1 171) := by decide
-- `witness-export extra`, `sh`, `sftp`
example : parse .recovery [.exportKw, .other] = none := by decide
example : parse .recovery [.other] = none := by decide
example : parse .witness [.other] = none := by decide
-- all-zero challenge
example : parse .witness [.witnessctl, .latest, .hash 0] = none := by decide
-- `cas 0 '' 1 nonce` and `cas 1 '' 1 nonce`
example : parse .witness [.witnessctl, .cas, .num 0, .emptyTok, .num 1, .hash 171] = none := by
  decide
example : parse .witness [.witnessctl, .cas, .num 1, .emptyTok, .num 1, .hash 171] = none := by
  decide
-- seq beyond MAX_SAFE_INTEGER (9007199254740992)
example : parse .witness [.witnessctl, .cas, .num 9007199254740992, .hash 170,
    .num 9007199254740992, .hash 171] = none := by decide
-- genesis with a real hash is refused
example : parse .witness [.witnessctl, .cas, .num 0, .hash 170, .num 0, .hash 171] = none := by
  decide
-- the gate maps the recovery role to the exporter and the witness role to witnessctl
example : gate .recovery [.exportKw] = some (.exporter, .export) := by decide
example : gate .witness [.witnessctl, .latest, .hash 171] = some (.witnessctl, .latest 171) := by
  decide

end TlWitnessService
