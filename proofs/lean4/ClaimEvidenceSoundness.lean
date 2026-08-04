/-
# Claim ⇄ Evidence Soundness — machine-checked monotonicity/soundness lemma

CEI track H.4 (`bd-sde5e.8.4`). This is the one property the whole
claim-evidence *honesty* thesis rests on, stated as a checked Lean 4 theorem:

  the asserted claim state never exceeds the evidence ceiling, and that
  soundness is *preserved by the gate's corrective transition* and can only be
  *strengthened* (never weakened) by committing more evidence.

It mirrors, line for line, the finite lattices implemented in
`crates/franken-engine/src/claim_evidence_lattice.rs`
(`ClaimAssertionState`, `EvidenceTier`, `ceiling`, `tier`, `EvidenceFacts::dominates`)
and the Biba-dual integrity reading in
`crates/franken-engine/src/claim_integrity_flow.rs` (`flow_legal`,
`evidence_integrity`, `required_integrity`). The Rust side already exhaustively
property-tests these (lattice laws, `tier`/`ceiling` monotonicity over all
dominating pairs, `flow_legal ⟺ state ≤ ceiling(tier)` over all 15 pairs); this
file makes the central soundness lemma *machine-checked* rather than merely
exhaustively tested.

## Why pure Lean 4 core (no `Mathlib`)

The claim/evidence lattices are *small finite chains* (3 claim states, 5 evidence
tiers, 2^6 fact vectors). Every theorem below is `decide`-checkable after a finite
case split, so the proof needs nothing from `Mathlib`. Keeping it `Mathlib`-free
makes the soundness lemma (a) fast to re-check in the gate, and (b) immune to the
library-version drift that the heavier isomorphism proofs are sensitive to — the
one property the honesty thesis depends on should not be hostage to an upstream
`Mathlib` bump.

Referenced by `FE-CLAIM-025` (reflexive soundness). Re-checked by
`scripts/run_cei_soundness_lean_proof.sh ci`.

Related: `bd-sde5e.1.1` (A.1 lattice), `bd-sde5e.8.3` (H.3 IFC dual),
`FORMAL_RUNTIME_SECURITY_MODEL_V1`.
-/

namespace FrankenEngine.ClaimEvidence

-- ===========================================================================
-- Claim assertion state  (mirrors `ClaimAssertionState`, ranks 0/1/2)
-- ===========================================================================

/-- How strongly a README/matrix row *asserts* a capability. Ascending order is
    the lattice order, exactly as the Rust `#[derive(Ord)]` declaration order. -/
inductive ClaimState where
  | hypothesis
  | target
  | observed
deriving DecidableEq, Repr

/-- Numeric rank within the chain (0 = weakest). Mirrors `ClaimAssertionState::rank`. -/
def ClaimState.rank : ClaimState → Nat
  | .hypothesis => 0
  | .target     => 1
  | .observed   => 2

/-- Lattice meet (greatest lower bound) — the *weaker* of two states. Mirrors
    `ClaimAssertionState::meet`. -/
def ClaimState.meet (a b : ClaimState) : ClaimState :=
  if a.rank ≤ b.rank then a else b

-- ===========================================================================
-- Evidence tier  (mirrors `EvidenceTier`, ranks 0..4)
-- ===========================================================================

/-- The strength of evidence a row can actually stand on, derived purely from
    machine-checkable facts. Ascending. Mirrors `EvidenceTier`. -/
inductive EvidenceTier where
  | unbacked
  | asserted
  | exercised
  | reproduced
  | adversariallyVerified
deriving DecidableEq, Repr

/-- Numeric rank within the chain (0 = weakest). Mirrors `EvidenceTier::rank`. -/
def EvidenceTier.rank : EvidenceTier → Nat
  | .unbacked              => 0
  | .asserted              => 1
  | .exercised             => 2
  | .reproduced            => 3
  | .adversariallyVerified => 4

/-- Total, monotone map from an evidence tier to the **maximum** claim state it
    can honestly license. Mirrors `ceiling` exactly:

      Unbacked              → Hypothesis
      Asserted | Exercised  → Target
      Reproduced | Adv.Ver. → Observed

    The `Reproduced → Observed` boundary encodes the reproducibility contract
    (`bd-cixqu.4.3`): an `observed` row needs a committed, fresh `repro.lock`. -/
def ceiling : EvidenceTier → ClaimState
  | .unbacked              => .hypothesis
  | .asserted              => .target
  | .exercised             => .target
  | .reproduced            => .observed
  | .adversariallyVerified => .observed

-- ===========================================================================
-- The soundness predicate and the gate's corrective transition
-- ===========================================================================

/-- A row is **sound** iff its asserted state is within its evidence ceiling.
    This is the A.1 predicate `state ≤ ceiling(tier)`. -/
def sound (state : ClaimState) (tier : EvidenceTier) : Prop :=
  state.rank ≤ (ceiling tier).rank

/-- `sound` is decidable (a `Nat ≤ Nat` test), so the soundness theorems below
    close by `decide` over the finite (state × tier) grid. -/
instance (state : ClaimState) (tier : EvidenceTier) : Decidable (sound state tier) :=
  Nat.decLe state.rank (ceiling tier).rank

/-- The gate's corrective transition: it downgrades an over-promoted assertion to
    the evidence ceiling, and leaves a sound assertion untouched. This is exactly
    `meet(state, ceiling(tier))` — the weaker of the asserted state and what the
    evidence licenses. It is the function the integrity gate applies when it emits
    its `downgrade_text`. -/
def gateState (state : ClaimState) (tier : EvidenceTier) : ClaimState :=
  ClaimState.meet state (ceiling tier)

-- ===========================================================================
-- Evidence facts → tier ladder  (mirrors `EvidenceFacts` + `tier`)
-- ===========================================================================

/-- The six positive evidence facts the `tier` ladder consumes (`true` = stronger
    evidence). Mirrors the monotone fields of `EvidenceFacts`. -/
structure Facts where
  gitTracked            : Bool
  verificationPassed    : Bool
  receiptExitZero       : Bool
  reproLockPresent      : Bool
  fresh                 : Bool
  adversariallyVerified : Bool
deriving DecidableEq, Repr

/-- Monotone facts→tier ladder of cumulative conjunctive gates. Mirrors `tier`
    exactly: strengthening any single fact can only move a row *up* the ladder. -/
def tier (f : Facts) : EvidenceTier :=
  let committed  := f.gitTracked
  let exercised  := committed && f.verificationPassed && f.receiptExitZero
  let reproduced := exercised && f.reproLockPresent && f.fresh
  let adversarial := reproduced && f.adversariallyVerified
  if adversarial then .adversariallyVerified
  else if reproduced then .reproduced
  else if exercised then .exercised
  else if committed then .asserted
  else .unbacked

/-- Componentwise dominance: `s` is at least as strong as `w` in every fact.
    Mirrors `EvidenceFacts::dominates` (Bool-valued for clean decidability). -/
def dominates (s w : Facts) : Bool :=
  (s.gitTracked            || !w.gitTracked)            &&
  (s.verificationPassed    || !w.verificationPassed)    &&
  (s.receiptExitZero       || !w.receiptExitZero)       &&
  (s.reproLockPresent      || !w.reproLockPresent)      &&
  (s.fresh                 || !w.fresh)                 &&
  (s.adversariallyVerified || !w.adversariallyVerified)

/-- `Bool` → `Nat` (1 / 0). -/
def b2n (b : Bool) : Nat := if b then 1 else 0

/-- The tier rank re-expressed as the count of cumulative ladder gates passed.
    Because the ladder is strictly nested (adversarial ⊆ reproduced ⊆ exercised ⊆
    committed), this sum is exactly `(tier f).rank` — proven by `tier_rank_eq`. -/
def tierLadder (f : Facts) : Nat :=
  b2n f.gitTracked
    + b2n (f.gitTracked && f.verificationPassed && f.receiptExitZero)
    + b2n (f.gitTracked && f.verificationPassed && f.receiptExitZero
            && f.reproLockPresent && f.fresh)
    + b2n (f.gitTracked && f.verificationPassed && f.receiptExitZero
            && f.reproLockPresent && f.fresh && f.adversariallyVerified)

-- ===========================================================================
-- Biba-dual integrity reading  (mirrors `claim_integrity_flow.rs`, H.3)
-- ===========================================================================

/-- Integrity level (0..4) of committed evidence in the runtime's five-element
    `LabelClass` chain (Public<Internal<Confidential<Secret<TopSecret). Mirrors
    `evidence_integrity` — an order-isomorphism `EvidenceTier ≅ LabelClass`. -/
def evidenceIntegrity : EvidenceTier → Nat
  | .unbacked              => 0  -- Public
  | .asserted              => 1  -- Internal
  | .exercised             => 2  -- Confidential
  | .reproduced            => 3  -- Secret
  | .adversariallyVerified => 4  -- TopSecret

/-- Minimum evidence integrity an asserted state may legally flow from. Mirrors
    `required_integrity`: Hypothesis→Public(0), Target→Internal(1), Observed→Secret(3). -/
def requiredIntegrity : ClaimState → Nat
  | .hypothesis => 0  -- Public
  | .target     => 1  -- Internal
  | .observed   => 3  -- Secret

/-- Biba integrity rule: evidence integrity ≥ required integrity. Mirrors
    `flow_legal`. -/
def flowLegal (state : ClaimState) (tier : EvidenceTier) : Bool :=
  decide (requiredIntegrity state ≤ evidenceIntegrity tier)

-- ===========================================================================
-- Theorems
-- ===========================================================================

/-- **ceiling is monotone in the evidence tier.** Strengthening the committed
    evidence can never *lower* the assertable ceiling. (25 ground cases.) -/
theorem ceiling_monotone (t1 t2 : EvidenceTier) :
    t1.rank ≤ t2.rank → (ceiling t1).rank ≤ (ceiling t2).rank := by
  cases t1 <;> cases t2 <;> decide

/-- **The gate's transition always lands within the ceiling (KEYSTONE).**
    After the gate's corrective transition, the asserted state never exceeds the
    evidence ceiling — i.e. the gate's output is always sound, for every input
    state and tier. This is the single soundness property the honesty thesis
    rests on. (15 ground cases.) -/
theorem gate_transition_sound (state : ClaimState) (tier : EvidenceTier) :
    sound (gateState state tier) tier := by
  cases state <;> cases tier <;> decide

/-- The gate is **conservative**: a row that is already sound is left untouched
    (no gratuitous downgrade). -/
theorem gate_fixes_sound (state : ClaimState) (tier : EvidenceTier) :
    sound state tier → gateState state tier = state := by
  cases state <;> cases tier <;> decide

/-- The gate's transition is **idempotent**: applying it twice equals applying it
    once. Re-running the integrity gate never changes an already-corrected row. -/
theorem gate_transition_idempotent (state : ClaimState) (tier : EvidenceTier) :
    gateState (gateState state tier) tier = gateState state tier := by
  cases state <;> cases tier <;> decide

/-- **Soundness can only rise with committed evidence.** If a state is sound
    against a weaker tier, it stays sound against any stronger-or-equal tier.
    "Honesty can only rise; committing more evidence never invalidates an
    already-honest claim." -/
theorem sound_monotone_in_tier
    (state : ClaimState) (t1 t2 : EvidenceTier) :
    t1.rank ≤ t2.rank → sound state t1 → sound state t2 := by
  intro hle hsound
  exact Nat.le_trans hsound (ceiling_monotone t1 t2 hle)

/-- The tier rank equals the cumulative-ladder count. (64 ground cases.) -/
theorem tier_rank_eq (f : Facts) : (tier f).rank = tierLadder f := by
  obtain ⟨a, b, c, d, e, g⟩ := f
  cases a <;> cases b <;> cases c <;> cases d <;> cases e <;> cases g <;> rfl

/-- One componentwise-dominance disjunct `(sx ∨ ¬wx)` is the implication `wx → sx`. -/
theorem imp_of_or_not {sx wx : Bool} (h : (sx || !wx) = true) :
    wx = true → sx = true := by
  cases sx <;> cases wx <;> simp_all

/-- `b2n` is monotone along a Bool implication. -/
theorem b2n_le_of_imp {p q : Bool} (h : p = true → q = true) : b2n p ≤ b2n q := by
  cases p <;> cases q <;> simp_all [b2n]

/-- **The facts→tier ladder is monotone under componentwise dominance.** If the
    committed facts `s` dominate `w`, then `tier w ≤ tier s`: strengthening any
    single fact can only move the row up the evidence ladder — "honesty can only
    rise with committed evidence." Proven via the cumulative-ladder decomposition:
    each nested ladder predicate is a monotone conjunction of dominated fields, so
    every term of the rank sum is monotone. (Same property the Rust `tier`
    monotonicity test checks, here kernel-checked.) -/
theorem tier_monotone (s w : Facts) (hdom : dominates s w = true) :
    (tier w).rank ≤ (tier s).rank := by
  simp only [tier_rank_eq]
  simp only [dominates, Bool.and_eq_true] at hdom
  obtain ⟨⟨⟨⟨⟨hg, hv⟩, hr⟩, hl⟩, hf⟩, ha⟩ := hdom
  have ig := imp_of_or_not hg
  have iv := imp_of_or_not hv
  have ir := imp_of_or_not hr
  have il := imp_of_or_not hl
  have ifr := imp_of_or_not hf
  have ia := imp_of_or_not ha
  unfold tierLadder
  have m1 : b2n w.gitTracked ≤ b2n s.gitTracked := b2n_le_of_imp ig
  have m2 : b2n (w.gitTracked && w.verificationPassed && w.receiptExitZero)
              ≤ b2n (s.gitTracked && s.verificationPassed && s.receiptExitZero) := by
    refine b2n_le_of_imp (fun hw => ?_)
    simp only [Bool.and_eq_true] at hw ⊢
    exact ⟨⟨ig hw.1.1, iv hw.1.2⟩, ir hw.2⟩
  have m3 : b2n (w.gitTracked && w.verificationPassed && w.receiptExitZero
                  && w.reproLockPresent && w.fresh)
              ≤ b2n (s.gitTracked && s.verificationPassed && s.receiptExitZero
                  && s.reproLockPresent && s.fresh) := by
    refine b2n_le_of_imp (fun hw => ?_)
    simp only [Bool.and_eq_true] at hw ⊢
    exact ⟨⟨⟨⟨ig hw.1.1.1.1, iv hw.1.1.1.2⟩, ir hw.1.1.2⟩, il hw.1.2⟩, ifr hw.2⟩
  have m4 : b2n (w.gitTracked && w.verificationPassed && w.receiptExitZero
                  && w.reproLockPresent && w.fresh && w.adversariallyVerified)
              ≤ b2n (s.gitTracked && s.verificationPassed && s.receiptExitZero
                  && s.reproLockPresent && s.fresh && s.adversariallyVerified) := by
    refine b2n_le_of_imp (fun hw => ?_)
    simp only [Bool.and_eq_true] at hw ⊢
    exact ⟨⟨⟨⟨⟨ig hw.1.1.1.1.1, iv hw.1.1.1.1.2⟩, ir hw.1.1.1.2⟩, il hw.1.1.2⟩,
           ifr hw.1.2⟩, ia hw.2⟩
  omega

/-- **The Biba integrity verdict is equivalent to A.1 soundness (ties Track F/H.3).**
    The IFC dual `flow_legal` agrees with `state ≤ ceiling(tier)` on every one of
    the 15 (state, tier) pairs — so the runtime's own information-flow vocabulary
    and the claim-evidence lattice are the *same* soundness condition. -/
theorem flow_legal_iff_sound (state : ClaimState) (tier : EvidenceTier) :
    flowLegal state tier = true ↔ sound state tier := by
  cases state <;> cases tier <;> decide

/-- **Top-level soundness statement (the H.4 acceptance lemma).** For every
    asserted state and every evidence tier, the state produced by the gate's
    corrective transition is within the evidence ceiling, and the corrective
    transition reduces exactly to the IFC-legal soundness condition. This is the
    conjunction `FE-CLAIM-025` cites: the gate's output is always sound, and that
    soundness is the same property the Biba integrity dual enforces. -/
theorem claim_evidence_integrity_is_sound (state : ClaimState) (tier : EvidenceTier) :
    sound (gateState state tier) tier
      ∧ (flowLegal state tier = true ↔ sound state tier) :=
  ⟨gate_transition_sound state tier, flow_legal_iff_sound state tier⟩

end FrankenEngine.ClaimEvidence
