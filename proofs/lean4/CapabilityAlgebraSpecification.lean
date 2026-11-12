/-
# Capability Algebra Specification for FrankenEngine

Formal specification of the capability algebra used in FrankenEngine's authority
partitioning system (`crates/franken-engine/src/capability.rs`).

## Well-Formedness Invariant (`ValidProfile`)
In Rust (`capability.rs`), `CapabilityProfile` smart constructors (`full()`, `engine_core()`,
`policy()`, `remote()`, `compute_only()`, `intersect()`) maintain the invariant that
`profile.kind` equals the canonical partition classification of `profile.capabilities`.
Raw arbitrary structs `<Full, empty>` violate this invariant and falsify `intersect a a = a`.
Here we formalize `ValidProfile` explicitly, prove all smart constructors and `intersect`
preserve `ValidProfile`, prove `intersect_idempotent` for all `ValidProfile` values, and
machine-check the explicit counterexample for raw invalid structs.

Related: bd-cixqu.7.5, bd-rc-2026-11-11-epic-g2vrp.10
-/

import IFCLatticeSpecification

-- =============================================================================
-- RuntimeCapability: Atomic permission units (22 variants)
-- =============================================================================

/-- Atomic capabilities that can be granted to subsystems (`RuntimeCapability` in `capability.rs`). -/
inductive RuntimeCapability : Type
  | VmDispatch         : RuntimeCapability
  | GcInvoke           : RuntimeCapability
  | IrLowering         : RuntimeCapability
  | PolicyRead         : RuntimeCapability
  | PolicyWrite        : RuntimeCapability
  | EvidenceEmit       : RuntimeCapability
  | DecisionInvoke     : RuntimeCapability
  | NetworkEgress      : RuntimeCapability
  | LeaseManagement    : RuntimeCapability
  | IdempotencyDerive  : RuntimeCapability
  | ExtensionLifecycle : RuntimeCapability
  | HeapAllocate       : RuntimeCapability
  | EnvRead            : RuntimeCapability
  | ProcessSpawn       : RuntimeCapability
  | FsRead             : RuntimeCapability
  | FsWrite            : RuntimeCapability
  | ModuleLoad         : RuntimeCapability
  | Console            : RuntimeCapability
  | Timer              : RuntimeCapability
  | Builtin            : RuntimeCapability
  | Declassify         : RuntimeCapability
  | RandomRead         : RuntimeCapability
deriving DecidableEq, Repr

namespace RuntimeCapability

/-- Canonical discriminant index `0..21` matching Rust declaration order. -/
def index : RuntimeCapability → Fin 22
  | VmDispatch         => ⟨0, by decide⟩
  | GcInvoke           => ⟨1, by decide⟩
  | IrLowering         => ⟨2, by decide⟩
  | PolicyRead         => ⟨3, by decide⟩
  | PolicyWrite        => ⟨4, by decide⟩
  | EvidenceEmit       => ⟨5, by decide⟩
  | DecisionInvoke     => ⟨6, by decide⟩
  | NetworkEgress      => ⟨7, by decide⟩
  | LeaseManagement    => ⟨8, by decide⟩
  | IdempotencyDerive  => ⟨9, by decide⟩
  | ExtensionLifecycle => ⟨10, by decide⟩
  | HeapAllocate       => ⟨11, by decide⟩
  | EnvRead            => ⟨12, by decide⟩
  | ProcessSpawn       => ⟨13, by decide⟩
  | FsRead             => ⟨14, by decide⟩
  | FsWrite            => ⟨15, by decide⟩
  | ModuleLoad         => ⟨16, by decide⟩
  | Console            => ⟨17, by decide⟩
  | Timer              => ⟨18, by decide⟩
  | Builtin            => ⟨19, by decide⟩
  | Declassify         => ⟨20, by decide⟩
  | RandomRead         => ⟨21, by decide⟩

/-- Inverse mapping from `Fin 22` to `RuntimeCapability`. -/
def ofFin (i : Fin 22) : RuntimeCapability :=
  match i.val with
  | 0  => VmDispatch
  | 1  => GcInvoke
  | 2  => IrLowering
  | 3  => PolicyRead
  | 4  => PolicyWrite
  | 5  => EvidenceEmit
  | 6  => DecisionInvoke
  | 7  => NetworkEgress
  | 8  => LeaseManagement
  | 9  => IdempotencyDerive
  | 10 => ExtensionLifecycle
  | 11 => HeapAllocate
  | 12 => EnvRead
  | 13 => ProcessSpawn
  | 14 => FsRead
  | 15 => FsWrite
  | 16 => ModuleLoad
  | 17 => Console
  | 18 => Timer
  | 19 => Builtin
  | 20 => Declassify
  | _  => RandomRead

theorem ofFin_index (c : RuntimeCapability) : ofFin c.index = c := by
  cases c <;> rfl

theorem index_ofFin (i : Fin 22) : (ofFin i).index = i := by
  obtain ⟨v, hv⟩ := i
  match v with
  | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9
  | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 => rfl
  | n + 22 => omega

/-- All runtime capability variants in canonical order (matches Rust `ALL` array). -/
def ALL : List RuntimeCapability := [
  VmDispatch, GcInvoke, IrLowering, PolicyRead, PolicyWrite,
  EvidenceEmit, DecisionInvoke, NetworkEgress, LeaseManagement, IdempotencyDerive,
  ExtensionLifecycle, HeapAllocate, EnvRead, ProcessSpawn, FsRead,
  FsWrite, ModuleLoad, Console, Timer, Builtin, Declassify, RandomRead
]

theorem all_count : ALL.length = 22 := rfl

theorem all_nodup : ALL.Pairwise (· ≠ ·) := by decide

theorem all_complete (cap : RuntimeCapability) : cap ∈ ALL := by
  cases cap <;> decide

/-- Single-bit mask `(1 <<< index)` in `BitVec 22`. -/
def bitMask (cap : RuntimeCapability) : BitVec 22 :=
  BitVec.ofNat 22 (1 <<< cap.index.val)

end RuntimeCapability

-- =============================================================================
-- ProfileKind: Named authority partitions
-- =============================================================================

/-- Named capability profile identifying a standard authority partition. -/
inductive ProfileKind : Type
  | Full        : ProfileKind
  | EngineCore  : ProfileKind
  | Policy      : ProfileKind
  | Remote      : ProfileKind
  | ComputeOnly : ProfileKind
deriving DecidableEq, Repr

-- =============================================================================
-- CapabilitySet: Canonical 22-bit capability set (pure Lean 4 core)
-- =============================================================================

/-- Canonical capability set represented as a 22-bit bitset over `RuntimeCapability`. -/
structure CapabilitySet where
  mask : BitVec 22
deriving DecidableEq, Repr

namespace CapabilitySet

def empty : CapabilitySet := ⟨0#22⟩

def full : CapabilitySet := ⟨BitVec.allOnes 22⟩

def ofList (caps : List RuntimeCapability) : CapabilitySet :=
  ⟨caps.foldl (fun acc c => acc ||| c.bitMask) 0#22⟩

def inter (a b : CapabilitySet) : CapabilitySet :=
  ⟨a.mask &&& b.mask⟩

def union (a b : CapabilitySet) : CapabilitySet :=
  ⟨a.mask ||| b.mask⟩

def hasBool (s : CapabilitySet) (cap : RuntimeCapability) : Bool :=
  s.mask.getLsbD cap.index.val

def has (s : CapabilitySet) (cap : RuntimeCapability) : Prop :=
  s.hasBool cap = true

instance decidableHas (s : CapabilitySet) (cap : RuntimeCapability) : Decidable (s.has cap) :=
  inferInstanceAs (Decidable (s.hasBool cap = true))

/-- Subset relation: `a` subsumes `b` iff `b ∩ a = b` (`b.mask &&& a.mask == b.mask`). -/
def subsumes (a b : CapabilitySet) : Prop :=
  (b.mask &&& a.mask) = b.mask

instance decidableSubsumes (a b : CapabilitySet) : Decidable (subsumes a b) :=
  inferInstanceAs (Decidable ((b.mask &&& a.mask) = b.mask))

/-- Cardinality: count of granted capabilities across `RuntimeCapability.ALL`. -/
def card (s : CapabilitySet) : Nat :=
  (RuntimeCapability.ALL.filter (fun c => s.hasBool c)).length

theorem inter_comm (a b : CapabilitySet) : inter a b = inter b a := by
  cases a; cases b
  simp [inter, BitVec.and_comm]

theorem inter_self (a : CapabilitySet) : inter a a = a := by
  cases a
  simp [inter, BitVec.and_self]

theorem inter_assoc (a b c : CapabilitySet) :
    inter (inter a b) c = inter a (inter b c) := by
  cases a; cases b; cases c
  simp [inter, BitVec.and_assoc]

theorem inter_subsumes_left (a b : CapabilitySet) : subsumes a (inter a b) := by
  cases a with | mk ma =>
  cases b with | mk mb =>
  simp only [subsumes, inter]
  rw [BitVec.and_comm ma mb, BitVec.and_assoc, BitVec.and_self]

theorem inter_subsumes_right (a b : CapabilitySet) : subsumes b (inter a b) := by
  cases a with | mk ma =>
  cases b with | mk mb =>
  simp only [subsumes, inter]
  rw [BitVec.and_assoc, BitVec.and_self]

theorem full_subsumes (s : CapabilitySet) : subsumes full s := by
  cases s with | mk ms =>
  change (ms &&& BitVec.allOnes 22) = ms
  exact BitVec.and_allOnes

theorem subsumes_empty (s : CapabilitySet) : subsumes s empty := by
  cases s with | mk ms =>
  simp [subsumes, empty, BitVec.zero_and]

theorem subsumes_refl (s : CapabilitySet) : subsumes s s := by
  cases s with | mk ms =>
  simp [subsumes, BitVec.and_self]

theorem subsumes_trans (a b c : CapabilitySet)
    (hab : subsumes a b) (hbc : subsumes b c) : subsumes a c := by
  cases a with | mk ma =>
  cases b with | mk mb =>
  cases c with | mk mc =>
  simp only [subsumes] at hab hbc ⊢
  calc
    mc &&& ma = (mc &&& mb) &&& ma := by rw [hbc]
    _         = mc &&& (mb &&& ma) := by rw [BitVec.and_assoc]
    _         = mc &&& mb          := by rw [hab]
    _         = mc                 := hbc

end CapabilitySet

-- =============================================================================
-- CapabilityProfile: Concrete capability profiles + ValidProfile invariant
-- =============================================================================

structure CapabilityProfile where
  kind : ProfileKind
  capabilities : CapabilitySet
deriving DecidableEq, Repr

namespace CapabilityProfile

def fullCaps : CapabilitySet := CapabilitySet.full

def engineCoreCaps : CapabilitySet := CapabilitySet.ofList [
  RuntimeCapability.VmDispatch, RuntimeCapability.GcInvoke, RuntimeCapability.IrLowering,
  RuntimeCapability.HeapAllocate, RuntimeCapability.Console, RuntimeCapability.Timer,
  RuntimeCapability.Builtin
]

def policyCaps : CapabilitySet := CapabilitySet.ofList [
  RuntimeCapability.PolicyRead, RuntimeCapability.PolicyWrite,
  RuntimeCapability.EvidenceEmit, RuntimeCapability.DecisionInvoke
]

def remoteCaps : CapabilitySet := CapabilitySet.ofList [
  RuntimeCapability.NetworkEgress, RuntimeCapability.LeaseManagement,
  RuntimeCapability.IdempotencyDerive
]

/-- Canonical kind classifier matching Rust `CapabilityProfile::intersect`. -/
def classifyKind (caps : CapabilitySet) : ProfileKind :=
  if caps = CapabilitySet.empty then ProfileKind.ComputeOnly
  else if caps = fullCaps then ProfileKind.Full
  else if caps = engineCoreCaps then ProfileKind.EngineCore
  else if caps = policyCaps then ProfileKind.Policy
  else if caps = remoteCaps then ProfileKind.Remote
  else ProfileKind.ComputeOnly

/-- Well-formedness invariant maintained by all Rust `CapabilityProfile` constructors. -/
def ValidProfile (p : CapabilityProfile) : Prop :=
  p.kind = classifyKind p.capabilities

instance decidableValidProfile (p : CapabilityProfile) : Decidable (ValidProfile p) :=
  inferInstanceAs (Decidable (p.kind = classifyKind p.capabilities))

def full : CapabilityProfile := ⟨ProfileKind.Full, fullCaps⟩
def engineCore : CapabilityProfile := ⟨ProfileKind.EngineCore, engineCoreCaps⟩
def policy : CapabilityProfile := ⟨ProfileKind.Policy, policyCaps⟩
def remote : CapabilityProfile := ⟨ProfileKind.Remote, remoteCaps⟩
def computeOnly : CapabilityProfile := ⟨ProfileKind.ComputeOnly, CapabilitySet.empty⟩

theorem valid_full : ValidProfile full := by decide
theorem valid_engineCore : ValidProfile engineCore := by decide
theorem valid_policy : ValidProfile policy := by decide
theorem valid_remote : ValidProfile remote := by decide
theorem valid_computeOnly : ValidProfile computeOnly := by decide

def has (profile : CapabilityProfile) (cap : RuntimeCapability) : Prop :=
  profile.capabilities.has cap

instance decidableHas (profile : CapabilityProfile) (cap : RuntimeCapability) :
    Decidable (has profile cap) :=
  CapabilitySet.decidableHas profile.capabilities cap

def subsumes (profile other : CapabilityProfile) : Prop :=
  CapabilitySet.subsumes profile.capabilities other.capabilities

instance decidableSubsumes (profile other : CapabilityProfile) :
    Decidable (subsumes profile other) :=
  CapabilitySet.decidableSubsumes profile.capabilities other.capabilities

/-- Intersect two profiles (narrowing — always safe and always produces a `ValidProfile`). -/
def intersect (profile other : CapabilityProfile) : CapabilityProfile :=
  let caps := CapabilitySet.inter profile.capabilities other.capabilities
  ⟨classifyKind caps, caps⟩

def len (profile : CapabilityProfile) : Nat :=
  profile.capabilities.card

def isEmpty (profile : CapabilityProfile) : Prop :=
  profile.capabilities = CapabilitySet.empty

instance decidableIsEmpty (profile : CapabilityProfile) : Decidable (isEmpty profile) :=
  inferInstanceAs (Decidable (profile.capabilities = CapabilitySet.empty))

theorem valid_intersect (a b : CapabilityProfile) : ValidProfile (intersect a b) := rfl

-- =============================================================================
-- Algebraic Properties (Complete Mechanized Proofs)
-- =============================================================================

/-- Intersection is commutative: `a ⊓ b = b ⊓ a`. -/
theorem intersect_commutative (a b : CapabilityProfile) :
    intersect a b = intersect b a := by
  simp [intersect, CapabilitySet.inter_comm]

/-- Intersection is idempotent on all well-formed profiles (`ValidProfile a`). -/
theorem intersect_idempotent (a : CapabilityProfile) (ha : ValidProfile a) :
    intersect a a = a := by
  cases a with | mk k caps =>
  simp only [ValidProfile] at ha
  simp [intersect, CapabilitySet.inter_self, ha]

/-- Explicit counterexample showing why raw arbitrary structs violate idempotence
    without `ValidProfile`: `<Full, empty>` narrows its tag to `ComputeOnly`. -/
theorem raw_invalid_profile_not_idempotent :
    ∃ bad : CapabilityProfile, ¬ ValidProfile bad ∧ intersect bad bad ≠ bad := by
  refine ⟨⟨ProfileKind.Full, CapabilitySet.empty⟩, ?_, ?_⟩ <;> decide

/-- Intersection is unconditionally associative: `(a ⊓ b) ⊓ c = a ⊓ (b ⊓ c)`. -/
theorem intersect_associative (a b c : CapabilityProfile) :
    intersect (intersect a b) c = intersect a (intersect b c) := by
  simp [intersect, CapabilitySet.inter_assoc]

/-- Alias retained for `scripts/run_lean_proof_check.sh` (`compose_associativity`). -/
theorem compose_associativity (a b c : CapabilityProfile) :
    intersect (intersect a b) c = intersect a (intersect b c) :=
  intersect_associative a b c

/-- Intersection is attenuation: the result is subsumed by both operands. -/
theorem intersect_attenuation (a b : CapabilityProfile) :
    subsumes a (intersect a b) ∧ subsumes b (intersect a b) :=
  ⟨CapabilitySet.inter_subsumes_left a.capabilities b.capabilities,
   CapabilitySet.inter_subsumes_right a.capabilities b.capabilities⟩

/-- Authority partitions are pairwise disjoint. -/
theorem authority_partitions_disjoint :
    intersect engineCore policy = computeOnly ∧
    intersect engineCore remote = computeOnly ∧
    intersect policy remote = computeOnly := by
  decide

/-- Full profile subsumes all profiles. -/
theorem full_subsumes_all (profile : CapabilityProfile) :
    subsumes full profile :=
  CapabilitySet.full_subsumes profile.capabilities

/-- ComputeOnly is subsumed by all profiles. -/
theorem all_subsume_computeOnly (profile : CapabilityProfile) :
    subsumes profile computeOnly :=
  CapabilitySet.subsumes_empty profile.capabilities

/-- Subsumption is reflexive. -/
theorem subsumes_refl (profile : CapabilityProfile) :
    subsumes profile profile :=
  CapabilitySet.subsumes_refl profile.capabilities

/-- Subsumption is transitive. -/
theorem subsumes_trans (a b c : CapabilityProfile) :
    subsumes a b → subsumes b c → subsumes a c :=
  CapabilitySet.subsumes_trans a.capabilities b.capabilities c.capabilities

-- =============================================================================
-- Profile Cardinality & Membership Specifications
-- =============================================================================

theorem engineCore_count : len engineCore = 7 := by decide
theorem policy_count : len policy = 4 := by decide
theorem remote_count : len remote = 3 := by decide
theorem computeOnly_empty : isEmpty computeOnly := rfl
theorem full_count : len full = 22 := by decide

theorem full_has_all (cap : RuntimeCapability) : has full cap := by
  cases cap <;> decide

/-- Main theorem: Well-formed capability profiles form an attenuating security semilattice. -/
theorem capability_profile_security_algebra :
    (∀ a b : CapabilityProfile, intersect a b = intersect b a) ∧
    (∀ a : CapabilityProfile, ValidProfile a → intersect a a = a) ∧
    (∀ a b c : CapabilityProfile, intersect (intersect a b) c = intersect a (intersect b c)) ∧
    (∀ a b : CapabilityProfile, subsumes a (intersect a b) ∧ subsumes b (intersect a b)) ∧
    (intersect engineCore policy = computeOnly) ∧
    (intersect engineCore remote = computeOnly) ∧
    (intersect policy remote = computeOnly) ∧
    (∀ profile : CapabilityProfile, subsumes full profile) ∧
    (∀ profile : CapabilityProfile, subsumes profile computeOnly) ∧
    (∀ profile : CapabilityProfile, subsumes profile profile) ∧
    (∀ a b c : CapabilityProfile, subsumes a b → subsumes b c → subsumes a c) :=
  ⟨intersect_commutative,
   intersect_idempotent,
   intersect_associative,
   intersect_attenuation,
   authority_partitions_disjoint.1,
   authority_partitions_disjoint.2.1,
   authority_partitions_disjoint.2.2,
   full_subsumes_all,
   all_subsume_computeOnly,
   subsumes_refl,
   subsumes_trans⟩

/-- Canonical string tag for `ProfileKind` matching Rust `ProfileKind` variant names. -/
def kindAsStr : ProfileKind → String
  | ProfileKind.Full        => "Full"
  | ProfileKind.EngineCore  => "EngineCore"
  | ProfileKind.Policy      => "Policy"
  | ProfileKind.Remote      => "Remote"
  | ProfileKind.ComputeOnly => "ComputeOnly"

/-- Canonical string tag for `RuntimeCapability` matching Rust `RuntimeCapability` variant names. -/
def capabilityAsStr : RuntimeCapability → String
  | RuntimeCapability.VmDispatch         => "VmDispatch"
  | RuntimeCapability.GcInvoke           => "GcInvoke"
  | RuntimeCapability.IrLowering         => "IrLowering"
  | RuntimeCapability.PolicyRead         => "PolicyRead"
  | RuntimeCapability.PolicyWrite        => "PolicyWrite"
  | RuntimeCapability.EvidenceEmit       => "EvidenceEmit"
  | RuntimeCapability.DecisionInvoke     => "DecisionInvoke"
  | RuntimeCapability.NetworkEgress      => "NetworkEgress"
  | RuntimeCapability.LeaseManagement    => "LeaseManagement"
  | RuntimeCapability.IdempotencyDerive  => "IdempotencyDerive"
  | RuntimeCapability.ExtensionLifecycle => "ExtensionLifecycle"
  | RuntimeCapability.HeapAllocate       => "HeapAllocate"
  | RuntimeCapability.EnvRead            => "EnvRead"
  | RuntimeCapability.ProcessSpawn       => "ProcessSpawn"
  | RuntimeCapability.FsRead             => "FsRead"
  | RuntimeCapability.FsWrite            => "FsWrite"
  | RuntimeCapability.ModuleLoad         => "ModuleLoad"
  | RuntimeCapability.Console            => "Console"
  | RuntimeCapability.Timer              => "Timer"
  | RuntimeCapability.Builtin            => "Builtin"
  | RuntimeCapability.Declassify         => "Declassify"
  | RuntimeCapability.RandomRead         => "RandomRead"

/-- All five canonical `CapabilityProfile` values in deterministic order. -/
def allNamedProfiles : List CapabilityProfile :=
  [full, engineCore, policy, remote, computeOnly]

/-- Exhaustive `#eval`-ready JSON truth-vector generator for IFC lattice and
    `CapabilityProfile` algebra differential verification in `cargo test` (`g2vrp.10`). -/
def exportFiniteTruthVectorsJson : String :=
  let boolJson (b : Bool) : String := if b then "true" else "false"
  let clearances : List Clearance :=
    [Clearance.OpenSink, Clearance.RestrictedSink, Clearance.AuditedSink,
     Clearance.SealedSink, Clearance.NeverSink]
  let labelPairs := LabelClass.all.flatMap (fun a =>
    LabelClass.all.map (fun b =>
      "{\"lhs\":\"" ++ a.asStr ++ "\",\"rhs\":\"" ++ b.asStr ++
      "\",\"join\":\"" ++ (LabelClass.join a b).asStr ++
      "\",\"meet\":\"" ++ (LabelClass.meet a b).asStr ++
      "\",\"le\":" ++ boolJson (decide (a ≤ b)) ++ "}"))
  let flowPairs := LabelClass.all.flatMap (fun l =>
    clearances.map (fun c =>
      "{\"label\":\"" ++ l.asStr ++ "\",\"clearance\":\"" ++ c.asStr ++
      "\",\"can_flow\":" ++ boolJson (decide (Clearance.canFlowTo l c)) ++ "}"))
  let capMembership := allNamedProfiles.flatMap (fun p =>
    RuntimeCapability.ALL.map (fun c =>
      "{\"profile\":\"" ++ kindAsStr p.kind ++
      "\",\"capability\":\"" ++ capabilityAsStr c ++
      "\",\"granted\":" ++ boolJson (p.capabilities.hasBool c) ++ "}"))
  let profilePairs := allNamedProfiles.flatMap (fun a =>
    allNamedProfiles.map (fun b =>
      let inter := intersect a b
      "{\"lhs\":\"" ++ kindAsStr a.kind ++ "\",\"rhs\":\"" ++ kindAsStr b.kind ++
      "\",\"intersect_kind\":\"" ++ kindAsStr inter.kind ++
      "\",\"intersect_len\":" ++ toString inter.len ++
      ",\"subsumes\":" ++ boolJson (decide (subsumes a b)) ++ "}"))
  "{\"schema_version\":\"franken-engine.lean-finite-truth-vectors.v1\"," ++
  "\"ifc_label_lattice\":[" ++ String.intercalate "," labelPairs ++ "]," ++
  "\"ifc_clearance_flows\":[" ++ String.intercalate "," flowPairs ++ "]," ++
  "\"capability_membership\":[" ++ String.intercalate "," capMembership ++ "]," ++
  "\"capability_intersections\":[" ++ String.intercalate "," profilePairs ++ "]}"

end CapabilityProfile
