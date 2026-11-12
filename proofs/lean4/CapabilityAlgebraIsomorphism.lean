/-
# Capability Algebra Isomorphism Proof

Proves that the Rust implementation model (`crates/franken-engine/src/capability.rs`)
is isomorphic to the formal `CapabilityProfile` algebra in
`CapabilityAlgebraSpecification.lean`, including preservation of `ValidProfile`.

Related: bd-cixqu.7.5, bd-rc-2026-11-11-epic-g2vrp.10
-/

import CapabilityAlgebraSpecification

-- =============================================================================
-- Rust Implementation Model
-- =============================================================================

structure RustRuntimeCapability where
  discriminant : Fin 22
deriving DecidableEq, Repr

namespace RustRuntimeCapability

def vmDispatch        : RustRuntimeCapability := ⟨⟨0, by decide⟩⟩
def gcInvoke          : RustRuntimeCapability := ⟨⟨1, by decide⟩⟩
def irLowering        : RustRuntimeCapability := ⟨⟨2, by decide⟩⟩
def policyRead        : RustRuntimeCapability := ⟨⟨3, by decide⟩⟩
def policyWrite       : RustRuntimeCapability := ⟨⟨4, by decide⟩⟩
def evidenceEmit      : RustRuntimeCapability := ⟨⟨5, by decide⟩⟩
def decisionInvoke    : RustRuntimeCapability := ⟨⟨6, by decide⟩⟩
def networkEgress     : RustRuntimeCapability := ⟨⟨7, by decide⟩⟩
def leaseManagement   : RustRuntimeCapability := ⟨⟨8, by decide⟩⟩
def idempotencyDerive : RustRuntimeCapability := ⟨⟨9, by decide⟩⟩
def extensionLifecycle : RustRuntimeCapability := ⟨⟨10, by decide⟩⟩
def heapAllocate      : RustRuntimeCapability := ⟨⟨11, by decide⟩⟩
def envRead           : RustRuntimeCapability := ⟨⟨12, by decide⟩⟩
def processSpawn      : RustRuntimeCapability := ⟨⟨13, by decide⟩⟩
def fsRead            : RustRuntimeCapability := ⟨⟨14, by decide⟩⟩
def fsWrite           : RustRuntimeCapability := ⟨⟨15, by decide⟩⟩
def moduleLoad        : RustRuntimeCapability := ⟨⟨16, by decide⟩⟩
def console           : RustRuntimeCapability := ⟨⟨17, by decide⟩⟩
def timer             : RustRuntimeCapability := ⟨⟨18, by decide⟩⟩
def builtin           : RustRuntimeCapability := ⟨⟨19, by decide⟩⟩
def declassify        : RustRuntimeCapability := ⟨⟨20, by decide⟩⟩
def randomRead        : RustRuntimeCapability := ⟨⟨21, by decide⟩⟩

end RustRuntimeCapability

/-- Model of the Rust `CapabilityProfile` struct with discriminant kind `0..4` and 22-bit set. -/
structure RustCapabilityProfile where
  kind_discriminant : Fin 5
  capabilities : BitVec 22
deriving DecidableEq, Repr

namespace RustCapabilityProfile

def fullKind        : Fin 5 := ⟨0, by decide⟩
def engineCoreKind  : Fin 5 := ⟨1, by decide⟩
def policyKind      : Fin 5 := ⟨2, by decide⟩
def remoteKind      : Fin 5 := ⟨3, by decide⟩
def computeOnlyKind : Fin 5 := ⟨4, by decide⟩

def full : RustCapabilityProfile :=
  ⟨fullKind, CapabilityProfile.fullCaps.mask⟩

def engineCore : RustCapabilityProfile :=
  ⟨engineCoreKind, CapabilityProfile.engineCoreCaps.mask⟩

def policy : RustCapabilityProfile :=
  ⟨policyKind, CapabilityProfile.policyCaps.mask⟩

def remote : RustCapabilityProfile :=
  ⟨remoteKind, CapabilityProfile.remoteCaps.mask⟩

def computeOnly : RustCapabilityProfile :=
  ⟨computeOnlyKind, 0#22⟩

def classifyKind (caps : BitVec 22) : Fin 5 :=
  if caps = 0#22 then computeOnlyKind
  else if caps = full.capabilities then fullKind
  else if caps = engineCore.capabilities then engineCoreKind
  else if caps = policy.capabilities then policyKind
  else if caps = remote.capabilities then remoteKind
  else computeOnlyKind

def ValidRustProfile (p : RustCapabilityProfile) : Prop :=
  p.kind_discriminant = classifyKind p.capabilities

instance decidableValidRustProfile (p : RustCapabilityProfile) :
    Decidable (ValidRustProfile p) :=
  inferInstanceAs (Decidable (p.kind_discriminant = classifyKind p.capabilities))

def has (profile : RustCapabilityProfile) (cap : Fin 22) : Prop :=
  profile.capabilities.getLsbD cap.val = true

def subsumes (a b : RustCapabilityProfile) : Prop :=
  (b.capabilities &&& a.capabilities) = b.capabilities

def intersect (a b : RustCapabilityProfile) : RustCapabilityProfile :=
  let caps := a.capabilities &&& b.capabilities
  ⟨classifyKind caps, caps⟩

end RustCapabilityProfile

-- =============================================================================
-- Isomorphism Functions
-- =============================================================================

def runtimeCapabilityToRust (c : RuntimeCapability) : RustRuntimeCapability :=
  ⟨c.index⟩

def rustToRuntimeCapability (r : RustRuntimeCapability) : RuntimeCapability :=
  RuntimeCapability.ofFin r.discriminant

def profileKindToRust : ProfileKind → Fin 5
  | ProfileKind.Full        => RustCapabilityProfile.fullKind
  | ProfileKind.EngineCore  => RustCapabilityProfile.engineCoreKind
  | ProfileKind.Policy      => RustCapabilityProfile.policyKind
  | ProfileKind.Remote      => RustCapabilityProfile.remoteKind
  | ProfileKind.ComputeOnly => RustCapabilityProfile.computeOnlyKind

def rustToProfileKind (k : Fin 5) : ProfileKind :=
  match k.val with
  | 0 => ProfileKind.Full
  | 1 => ProfileKind.EngineCore
  | 2 => ProfileKind.Policy
  | 3 => ProfileKind.Remote
  | _ => ProfileKind.ComputeOnly

def capabilityProfileToRust (p : CapabilityProfile) : RustCapabilityProfile :=
  ⟨profileKindToRust p.kind, p.capabilities.mask⟩

def rustToCapabilityProfile (r : RustCapabilityProfile) : CapabilityProfile :=
  ⟨rustToProfileKind r.kind_discriminant, ⟨r.capabilities⟩⟩

-- =============================================================================
-- Isomorphism & Correspondence Proofs
-- =============================================================================

theorem capability_isomorphism_inverse :
    (∀ cap : RuntimeCapability, rustToRuntimeCapability (runtimeCapabilityToRust cap) = cap) ∧
    (∀ r : RustRuntimeCapability, runtimeCapabilityToRust (rustToRuntimeCapability r) = r) := by
  refine ⟨RuntimeCapability.ofFin_index, ?_⟩
  intro ⟨i⟩
  simp [runtimeCapabilityToRust, rustToRuntimeCapability, RuntimeCapability.index_ofFin]

theorem profileKind_left_inv (k : ProfileKind) :
    rustToProfileKind (profileKindToRust k) = k := by
  cases k <;> rfl

theorem profileKind_right_inv (k : Fin 5) :
    profileKindToRust (rustToProfileKind k) = k := by
  obtain ⟨v, hv⟩ := k
  match v with
  | 0 | 1 | 2 | 3 | 4 => rfl
  | n + 5 => omega

theorem profile_left_inv (p : CapabilityProfile) :
    rustToCapabilityProfile (capabilityProfileToRust p) = p := by
  cases p with | mk k caps =>
  cases caps with | mk mask =>
  simp [capabilityProfileToRust, rustToCapabilityProfile, profileKind_left_inv]

theorem profile_right_inv (r : RustCapabilityProfile) :
    capabilityProfileToRust (rustToCapabilityProfile r) = r := by
  cases r with | mk k mask =>
  simp [capabilityProfileToRust, rustToCapabilityProfile, profileKind_right_inv]

theorem profile_isomorphism_inverse :
    (∀ profile : CapabilityProfile, rustToCapabilityProfile (capabilityProfileToRust profile) = profile) ∧
    (∀ r : RustCapabilityProfile, capabilityProfileToRust (rustToCapabilityProfile r) = r) :=
  ⟨profile_left_inv, profile_right_inv⟩

theorem classifyKind_correspondence (caps : CapabilitySet) :
    profileKindToRust (CapabilityProfile.classifyKind caps) =
      RustCapabilityProfile.classifyKind caps.mask := by
  cases caps with | mk mask =>
  have hmk : ∀ s : CapabilitySet, (⟨mask⟩ : CapabilitySet) = s ↔ mask = s.mask := by
    intro s; cases s; simp
  simp only [CapabilityProfile.classifyKind, RustCapabilityProfile.classifyKind,
             hmk, CapabilitySet.empty, RustCapabilityProfile.full,
             RustCapabilityProfile.engineCore, RustCapabilityProfile.policy,
             RustCapabilityProfile.remote]
  repeat (split <;> try rfl)

theorem valid_profile_correspondence (p : CapabilityProfile) :
    CapabilityProfile.ValidProfile p ↔
      RustCapabilityProfile.ValidRustProfile (capabilityProfileToRust p) := by
  cases p with | mk k caps =>
  simp only [CapabilityProfile.ValidProfile, RustCapabilityProfile.ValidRustProfile,
             capabilityProfileToRust, ← classifyKind_correspondence]
  constructor
  · intro h; rw [h]
  · intro h
    have h' := congrArg rustToProfileKind h
    simpa [profileKind_left_inv] using h'

theorem has_correspondence (profile : CapabilityProfile) (cap : RuntimeCapability) :
    CapabilityProfile.has profile cap ↔
      RustCapabilityProfile.has (capabilityProfileToRust profile)
        (runtimeCapabilityToRust cap).discriminant := by
  rfl

theorem subsumes_correspondence (a b : CapabilityProfile) :
    CapabilityProfile.subsumes a b ↔
      RustCapabilityProfile.subsumes (capabilityProfileToRust a) (capabilityProfileToRust b) := by
  rfl

theorem intersect_correspondence (a b : CapabilityProfile) :
    capabilityProfileToRust (CapabilityProfile.intersect a b) =
      RustCapabilityProfile.intersect (capabilityProfileToRust a) (capabilityProfileToRust b) := by
  simp [CapabilityProfile.intersect, RustCapabilityProfile.intersect,
        capabilityProfileToRust, CapabilitySet.inter, classifyKind_correspondence]

/-- Main theorem: The Rust model is bijectively and algebraically isomorphic to `CapabilityProfile`. -/
theorem rust_capability_algebra_isomorphic :
    (∀ a b : CapabilityProfile,
       capabilityProfileToRust (CapabilityProfile.intersect a b) =
       RustCapabilityProfile.intersect (capabilityProfileToRust a) (capabilityProfileToRust b)) ∧
    (∀ a b : CapabilityProfile,
       CapabilityProfile.subsumes a b ↔
       RustCapabilityProfile.subsumes (capabilityProfileToRust a) (capabilityProfileToRust b)) ∧
    (∀ profile : CapabilityProfile, ∀ cap : RuntimeCapability,
       CapabilityProfile.has profile cap ↔
       RustCapabilityProfile.has (capabilityProfileToRust profile)
         (runtimeCapabilityToRust cap).discriminant) ∧
    (∀ profile : CapabilityProfile, rustToCapabilityProfile (capabilityProfileToRust profile) = profile) ∧
    (∀ r : RustCapabilityProfile, capabilityProfileToRust (rustToCapabilityProfile r) = r) :=
  ⟨intersect_correspondence,
   subsumes_correspondence,
   has_correspondence,
   profile_left_inv,
   profile_right_inv⟩

/-- Corollary: All algebraic properties hold on `RustCapabilityProfile` (with `ValidRustProfile` for idempotence). -/
theorem rust_satisfies_capability_algebra :
    (∀ a b : RustCapabilityProfile,
       RustCapabilityProfile.intersect a b = RustCapabilityProfile.intersect b a) ∧
    (∀ a : RustCapabilityProfile,
       RustCapabilityProfile.ValidRustProfile a →
       RustCapabilityProfile.intersect a a = a) ∧
    (∀ a b c : RustCapabilityProfile,
       RustCapabilityProfile.intersect (RustCapabilityProfile.intersect a b) c =
       RustCapabilityProfile.intersect a (RustCapabilityProfile.intersect b c)) ∧
    (∀ a b : RustCapabilityProfile,
       let result := RustCapabilityProfile.intersect a b
       RustCapabilityProfile.subsumes a result ∧ RustCapabilityProfile.subsumes b result) ∧
    (RustCapabilityProfile.intersect RustCapabilityProfile.engineCore RustCapabilityProfile.policy =
     RustCapabilityProfile.computeOnly) ∧
    (RustCapabilityProfile.intersect RustCapabilityProfile.engineCore RustCapabilityProfile.remote =
     RustCapabilityProfile.computeOnly) ∧
    (RustCapabilityProfile.intersect RustCapabilityProfile.policy RustCapabilityProfile.remote =
     RustCapabilityProfile.computeOnly) ∧
    (∀ profile : RustCapabilityProfile,
       RustCapabilityProfile.subsumes RustCapabilityProfile.full profile) ∧
    (∀ profile : RustCapabilityProfile,
       RustCapabilityProfile.subsumes profile RustCapabilityProfile.computeOnly) := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro a b
    have ha := (profile_right_inv a).symm
    have hb := (profile_right_inv b).symm
    rw [ha, hb, ← intersect_correspondence, ← intersect_correspondence,
        CapabilityProfile.intersect_commutative]
  · intro a hvalid
    have ha := (profile_right_inv a).symm
    have hformal : CapabilityProfile.ValidProfile (rustToCapabilityProfile a) := by
      rw [valid_profile_correspondence, profile_right_inv]
      exact hvalid
    calc
      RustCapabilityProfile.intersect a a
          = RustCapabilityProfile.intersect
              (capabilityProfileToRust (rustToCapabilityProfile a))
              (capabilityProfileToRust (rustToCapabilityProfile a)) := by rw [← ha]
      _   = capabilityProfileToRust
              (CapabilityProfile.intersect (rustToCapabilityProfile a) (rustToCapabilityProfile a)) :=
            (intersect_correspondence _ _).symm
      _   = capabilityProfileToRust (rustToCapabilityProfile a) := by
            rw [CapabilityProfile.intersect_idempotent _ hformal]
      _   = a := profile_right_inv a
  · intro a b c
    simp [RustCapabilityProfile.intersect, BitVec.and_assoc]
  · intro a b
    exact ⟨CapabilitySet.inter_subsumes_left ⟨a.capabilities⟩ ⟨b.capabilities⟩,
           CapabilitySet.inter_subsumes_right ⟨a.capabilities⟩ ⟨b.capabilities⟩⟩
  · decide
  · decide
  · decide
  · intro p
    exact CapabilitySet.full_subsumes ⟨p.capabilities⟩
  · intro p
    exact CapabilitySet.subsumes_empty ⟨p.capabilities⟩

/-- Non-vacuous capstone verification theorem for the capability algebra. -/
theorem capability_algebra_implementation_verified :
    (∀ a : RustCapabilityProfile,
       RustCapabilityProfile.ValidRustProfile a →
       RustCapabilityProfile.intersect a a = a) ∧
    (RustCapabilityProfile.intersect RustCapabilityProfile.engineCore RustCapabilityProfile.policy =
     RustCapabilityProfile.computeOnly) :=
  ⟨rust_satisfies_capability_algebra.2.1, rust_satisfies_capability_algebra.2.2.2.2.1⟩
