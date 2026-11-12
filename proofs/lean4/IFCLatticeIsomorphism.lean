/-
# IFC Lattice Isomorphism Proof

Proves that the Rust implementation in `crates/franken-engine/src/ifc_artifacts.rs`
is isomorphic to the formal lattice specification in `IFCLatticeSpecification.lean`.

Related: bd-cixqu.7.3, ADR-0006, ADR-0007
-/

import IFCLatticeSpecification

-- =============================================================================
-- Rust Implementation Model
-- =============================================================================

/-- Model of the Rust Label enum with its numeric level() discriminant (0..4). -/
structure RustLabelClass where
  discriminant : Fin 5
deriving DecidableEq, Repr

namespace RustLabelClass

def pubLabel : RustLabelClass := ⟨⟨0, by decide⟩⟩
def internal : RustLabelClass := ⟨⟨1, by decide⟩⟩
def confidential : RustLabelClass := ⟨⟨2, by decide⟩⟩
def secret : RustLabelClass := ⟨⟨3, by decide⟩⟩
def topSecret : RustLabelClass := ⟨⟨4, by decide⟩⟩

def level (r : RustLabelClass) : Nat := r.discriminant.val

def join (a b : RustLabelClass) : RustLabelClass :=
  if a.level ≥ b.level then a else b

def meet (a b : RustLabelClass) : RustLabelClass :=
  if a.level ≤ b.level then a else b

instance : LE RustLabelClass where
  le a b := a.level ≤ b.level

instance decidableLE (a b : RustLabelClass) : Decidable (a ≤ b) :=
  Nat.decLe a.level b.level

end RustLabelClass

/-- Model of the Rust Clearance enum (discriminants 0..4). -/
structure RustClearance where
  discriminant : Fin 5
deriving DecidableEq, Repr

namespace RustClearance

def openSink : RustClearance := ⟨⟨0, by decide⟩⟩
def restrictedSink : RustClearance := ⟨⟨1, by decide⟩⟩
def auditedSink : RustClearance := ⟨⟨2, by decide⟩⟩
def sealedSink : RustClearance := ⟨⟨3, by decide⟩⟩
def neverSink : RustClearance := ⟨⟨4, by decide⟩⟩

def level (r : RustClearance) : Nat := r.discriminant.val

def maxLabelLevel (r : RustClearance) : Nat :=
  match r.discriminant.val with
  | 0 => 4  -- OpenSink can receive everything
  | 1 => 1  -- RestrictedSink up to Internal
  | 2 => 2  -- AuditedSink up to Confidential
  | 3 => 3  -- SealedSink up to Secret
  | _ => 0  -- NeverSink only Public

def canReceiveLabel (clearance : RustClearance) (label : RustLabelClass) : Prop :=
  label.level ≤ clearance.maxLabelLevel

instance decidableCanReceiveLabel (clearance : RustClearance) (label : RustLabelClass) :
    Decidable (canReceiveLabel clearance label) :=
  Nat.decLe label.level clearance.maxLabelLevel

end RustClearance

-- =============================================================================
-- Isomorphism Functions
-- =============================================================================

def labelClassToRust : LabelClass → RustLabelClass
  | LabelClass.Public       => RustLabelClass.pubLabel
  | LabelClass.Internal     => RustLabelClass.internal
  | LabelClass.Confidential => RustLabelClass.confidential
  | LabelClass.Secret       => RustLabelClass.secret
  | LabelClass.TopSecret    => RustLabelClass.topSecret

def rustToLabelClass (r : RustLabelClass) : LabelClass :=
  match r.discriminant.val with
  | 0 => LabelClass.Public
  | 1 => LabelClass.Internal
  | 2 => LabelClass.Confidential
  | 3 => LabelClass.Secret
  | _ => LabelClass.TopSecret

def clearanceToRust : Clearance → RustClearance
  | Clearance.OpenSink       => RustClearance.openSink
  | Clearance.RestrictedSink => RustClearance.restrictedSink
  | Clearance.AuditedSink    => RustClearance.auditedSink
  | Clearance.SealedSink     => RustClearance.sealedSink
  | Clearance.NeverSink      => RustClearance.neverSink

def rustToClearance (r : RustClearance) : Clearance :=
  match r.discriminant.val with
  | 0 => Clearance.OpenSink
  | 1 => Clearance.RestrictedSink
  | 2 => Clearance.AuditedSink
  | 3 => Clearance.SealedSink
  | _ => Clearance.NeverSink

-- =============================================================================
-- Isomorphism Proofs
-- =============================================================================

theorem labelClass_left_inv (l : LabelClass) :
    rustToLabelClass (labelClassToRust l) = l := by
  cases l <;> rfl

theorem labelClass_right_inv (r : RustLabelClass) :
    labelClassToRust (rustToLabelClass r) = r := by
  obtain ⟨⟨v, hv⟩⟩ := r
  match v with
  | 0 | 1 | 2 | 3 | 4 => rfl
  | n + 5 => omega

/-- The isomorphisms are mutual inverses for LabelClass. -/
theorem labelClass_isomorphism_inverse :
    (∀ l : LabelClass, rustToLabelClass (labelClassToRust l) = l) ∧
    (∀ r : RustLabelClass, labelClassToRust (rustToLabelClass r) = r) :=
  ⟨labelClass_left_inv, labelClass_right_inv⟩

theorem clearance_left_inv (c : Clearance) :
    rustToClearance (clearanceToRust c) = c := by
  cases c <;> rfl

theorem clearance_right_inv (r : RustClearance) :
    clearanceToRust (rustToClearance r) = r := by
  obtain ⟨⟨v, hv⟩⟩ := r
  match v with
  | 0 | 1 | 2 | 3 | 4 => rfl
  | n + 5 => omega

/-- The isomorphisms are mutual inverses for Clearance. -/
theorem clearance_isomorphism_inverse :
    (∀ c : Clearance, rustToClearance (clearanceToRust c) = c) ∧
    (∀ r : RustClearance, clearanceToRust (rustToClearance r) = r) :=
  ⟨clearance_left_inv, clearance_right_inv⟩

theorem level_correspondence_label (l : LabelClass) :
    (labelClassToRust l).level = l.level := by
  cases l <;> rfl

theorem level_correspondence_clearance (c : Clearance) :
    (clearanceToRust c).level = c.level := by
  cases c <;> rfl

theorem maxLabelLevel_correspondence (c : Clearance) :
    (clearanceToRust c).maxLabelLevel = c.maxLabelLevel := by
  cases c <;> rfl

theorem join_correspondence_label (l1 l2 : LabelClass) :
    labelClassToRust (l1 ⊔ l2) =
      RustLabelClass.join (labelClassToRust l1) (labelClassToRust l2) := by
  cases l1 <;> cases l2 <;> rfl

theorem meet_correspondence_label (l1 l2 : LabelClass) :
    labelClassToRust (l1 ⊓ l2) =
      RustLabelClass.meet (labelClassToRust l1) (labelClassToRust l2) := by
  cases l1 <;> cases l2 <;> rfl

theorem flow_correspondence (l : LabelClass) (c : Clearance) :
    Clearance.canFlowTo l c ↔
      RustClearance.canReceiveLabel (clearanceToRust c) (labelClassToRust l) := by
  cases l <;> cases c <;> decide

-- =============================================================================
-- Main Isomorphism Theorem
-- =============================================================================

/-- Main theorem: The Rust implementation is a faithful order- and lattice-isomorphism
    of the formal IFC lattice specification. -/
theorem rust_implementation_isomorphic :
    (∀ l1 l2 : LabelClass,
       labelClassToRust (l1 ⊔ l2) = RustLabelClass.join (labelClassToRust l1) (labelClassToRust l2) ∧
       labelClassToRust (l1 ⊓ l2) = RustLabelClass.meet (labelClassToRust l1) (labelClassToRust l2)) ∧
    (∀ l1 l2 : LabelClass,
       l1 ≤ l2 ↔ labelClassToRust l1 ≤ labelClassToRust l2) ∧
    (∀ l : LabelClass, ∀ c : Clearance,
       Clearance.canFlowTo l c ↔
       RustClearance.canReceiveLabel (clearanceToRust c) (labelClassToRust l)) ∧
    (∀ l : LabelClass, rustToLabelClass (labelClassToRust l) = l) ∧
    (∀ r : RustLabelClass, labelClassToRust (rustToLabelClass r) = r) ∧
    (∀ c : Clearance, rustToClearance (clearanceToRust c) = c) ∧
    (∀ r : RustClearance, clearanceToRust (rustToClearance r) = r) := by
  refine ⟨?_, ?_, flow_correspondence, labelClass_left_inv, labelClass_right_inv,
          clearance_left_inv, clearance_right_inv⟩
  · intro l1 l2
    exact ⟨join_correspondence_label l1 l2, meet_correspondence_label l1 l2⟩
  · intro l1 l2
    cases l1 <;> cases l2 <;> decide

/-- Alias retained for legacy runner bundles (`IFCLatticeIsomorphism.isomorphism`). -/
theorem isomorphism :
    (∀ l1 l2 : LabelClass,
       labelClassToRust (l1 ⊔ l2) = RustLabelClass.join (labelClassToRust l1) (labelClassToRust l2) ∧
       labelClassToRust (l1 ⊓ l2) = RustLabelClass.meet (labelClassToRust l1) (labelClassToRust l2)) ∧
    (∀ l : LabelClass, ∀ c : Clearance,
       Clearance.canFlowTo l c ↔
       RustClearance.canReceiveLabel (clearanceToRust c) (labelClassToRust l)) :=
  ⟨rust_implementation_isomorphic.1, rust_implementation_isomorphic.2.2.1⟩

/-- Corollary: All lattice axioms proven for the formal specification hold in Rust. -/
theorem rust_satisfies_lattice_axioms :
    ∀ (r1 r2 r3 : RustLabelClass),
      (RustLabelClass.join r1 r1 = r1) ∧ (RustLabelClass.meet r1 r1 = r1) ∧
      (RustLabelClass.join r1 r2 = RustLabelClass.join r2 r1) ∧
      (RustLabelClass.meet r1 r2 = RustLabelClass.meet r2 r1) ∧
      (RustLabelClass.join (RustLabelClass.join r1 r2) r3 =
       RustLabelClass.join r1 (RustLabelClass.join r2 r3)) ∧
      (RustLabelClass.meet (RustLabelClass.meet r1 r2) r3 =
       RustLabelClass.meet r1 (RustLabelClass.meet r2 r3)) ∧
      (RustLabelClass.join r1 (RustLabelClass.meet r1 r2) = r1) ∧
      (RustLabelClass.meet r1 (RustLabelClass.join r1 r2) = r1) := by
  intro r1 r2 r3
  let l1 := rustToLabelClass r1
  let l2 := rustToLabelClass r2
  let l3 := rustToLabelClass r3
  have hr1 : r1 = labelClassToRust l1 := (labelClass_right_inv r1).symm
  have hr2 : r2 = labelClassToRust l2 := (labelClass_right_inv r2).symm
  have hr3 : r3 = labelClassToRust l3 := (labelClass_right_inv r3).symm
  rw [hr1, hr2, hr3]
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · rw [← join_correspondence_label, LabelClass.join_idempotent]
  · rw [← meet_correspondence_label, LabelClass.meet_idempotent]
  · rw [← join_correspondence_label, ← join_correspondence_label, LabelClass.join_commutative]
  · rw [← meet_correspondence_label, ← meet_correspondence_label, LabelClass.meet_commutative]
  · rw [← join_correspondence_label, ← join_correspondence_label,
        ← join_correspondence_label, ← join_correspondence_label, LabelClass.join_associative]
  · rw [← meet_correspondence_label, ← meet_correspondence_label,
        ← meet_correspondence_label, ← meet_correspondence_label, LabelClass.meet_associative]
  · rw [← meet_correspondence_label, ← join_correspondence_label, LabelClass.join_absorption]
  · rw [← join_correspondence_label, ← meet_correspondence_label, LabelClass.meet_absorption]

/-- Corollary: Flow control properties from formal spec hold in Rust, including monotonicity. -/
theorem rust_flow_properties :
    (∀ c : RustClearance,
       RustClearance.canReceiveLabel c RustLabelClass.pubLabel) ∧
    (∀ c : RustClearance,
       RustClearance.canReceiveLabel c RustLabelClass.topSecret ↔
       c = RustClearance.openSink) ∧
    (∀ r1 r2 : RustLabelClass, ∀ c : RustClearance,
       r1 ≤ r2 → RustClearance.canReceiveLabel c r2 → RustClearance.canReceiveLabel c r1) := by
  refine ⟨?_, ?_, ?_⟩
  · intro c
    have hc : c = clearanceToRust (rustToClearance c) := (clearance_right_inv c).symm
    rw [hc]
    exact (flow_correspondence LabelClass.Public (rustToClearance c)).mp
      (public_flows_everywhere (rustToClearance c))
  · intro c
    obtain ⟨⟨v, hv⟩⟩ := c
    match v with
    | 0 | 1 | 2 | 3 | 4 => revert hv; decide
    | n + 5 => omega
  · intro r1 r2 c h_order h_r2
    exact Nat.le_trans h_order h_r2

/-- Non-vacuous capstone theorem bundling isomorphism, lattice laws, and flow monotonicity. -/
theorem ifc_lattice_implementation_verified :
    (∀ l : LabelClass, rustToLabelClass (labelClassToRust l) = l) ∧
    (∀ r : RustLabelClass, labelClassToRust (rustToLabelClass r) = r) ∧
    (∀ r1 r2 : RustLabelClass, ∀ c : RustClearance,
       r1 ≤ r2 → RustClearance.canReceiveLabel c r2 → RustClearance.canReceiveLabel c r1) :=
  ⟨labelClass_left_inv, labelClass_right_inv, rust_flow_properties.2.2⟩
