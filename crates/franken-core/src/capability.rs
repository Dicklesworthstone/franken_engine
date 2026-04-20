//! Canonical runtime capability profiles.
//!
//! Defines five authority partitions enforced at API boundaries:
//! `FullCaps`, `EngineCoreCaps`, `PolicyCaps`, `RemoteCaps`,
//! `ComputeOnlyCaps`.  Each profile grants a specific subset of
//! runtime capabilities, preventing ambient authority leaks.
//!
//! Plan references: Section 10.11 item 1, 9G.1 (capability-context-first
//! runtime), Top-10 #2 (Guardplane), #7 (capability lattice), #8 (budgets).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

pub mod trust_zone;

// ---------------------------------------------------------------------------
// RuntimeCapability — the atomic permission unit
// ---------------------------------------------------------------------------

/// Atomic capabilities that can be granted to subsystems.
///
/// Each capability represents a single, indivisible permission.
/// Profiles compose subsets of these capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RuntimeCapability {
    /// Execute VM dispatch (interpreter, IR lowering).
    VmDispatch,
    /// Invoke garbage collector.
    GcInvoke,
    /// Perform IR lowering passes.
    IrLowering,
    /// Read policy configuration.
    PolicyRead,
    /// Write/mutate policy configuration.
    PolicyWrite,
    /// Emit evidence entries to the evidence ledger.
    EvidenceEmit,
    /// Invoke decision contracts.
    DecisionInvoke,
    /// Perform network egress operations.
    NetworkEgress,
    /// Manage remote leases.
    LeaseManagement,
    /// Derive idempotency keys for remote operations.
    IdempotencyDerive,
    /// Manage extension lifecycle (load, start, suspend, terminate).
    ExtensionLifecycle,
    /// Allocate from extension heaps.
    HeapAllocate,
    /// Read environment variables.
    EnvRead,
    /// Spawn external processes.
    ProcessSpawn,
    /// Perform filesystem reads.
    FsRead,
    /// Perform filesystem writes.
    FsWrite,
    /// Load modules (require/import).
    ModuleLoad,
}

impl fmt::Display for RuntimeCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::VmDispatch => "vm_dispatch",
            Self::GcInvoke => "gc_invoke",
            Self::IrLowering => "ir_lowering",
            Self::PolicyRead => "policy_read",
            Self::PolicyWrite => "policy_write",
            Self::EvidenceEmit => "evidence_emit",
            Self::DecisionInvoke => "decision_invoke",
            Self::NetworkEgress => "network_egress",
            Self::LeaseManagement => "lease_management",
            Self::IdempotencyDerive => "idempotency_derive",
            Self::ExtensionLifecycle => "extension_lifecycle",
            Self::HeapAllocate => "heap_allocate",
            Self::EnvRead => "env_read",
            Self::ProcessSpawn => "process_spawn",
            Self::FsRead => "fs_read",
            Self::FsWrite => "fs_write",
            Self::ModuleLoad => "module_load",
        };
        f.write_str(name)
    }
}

impl RuntimeCapability {
    /// Map a capability-tag string (as used in [`CapabilityTag`] / hostcall
    /// dispatch) to the corresponding typed capability.
    ///
    /// Returns `None` for internal-only tags (e.g. `"promise:*"`) that are
    /// not security capabilities.
    pub fn from_tag_str(tag: &str) -> Option<Self> {
        match tag {
            // Canonical snake_case names (from Display)
            "vm_dispatch" => Some(Self::VmDispatch),
            "gc_invoke" => Some(Self::GcInvoke),
            "ir_lowering" => Some(Self::IrLowering),
            "policy_read" => Some(Self::PolicyRead),
            "policy_write" => Some(Self::PolicyWrite),
            "evidence_emit" => Some(Self::EvidenceEmit),
            "decision_invoke" => Some(Self::DecisionInvoke),
            "network_egress" => Some(Self::NetworkEgress),
            "lease_management" => Some(Self::LeaseManagement),
            "idempotency_derive" => Some(Self::IdempotencyDerive),
            "extension_lifecycle" => Some(Self::ExtensionLifecycle),
            "heap_allocate" => Some(Self::HeapAllocate),
            "env_read" => Some(Self::EnvRead),
            "process_spawn" => Some(Self::ProcessSpawn),
            "fs_read" => Some(Self::FsRead),
            "fs_write" => Some(Self::FsWrite),
            "module_load" => Some(Self::ModuleLoad),

            // Short aliases used in IR / tests
            "network" | "net" | "net:connect" | "net:fetch" | "net:outbound" | "net.write"
            | "network.write" => Some(Self::NetworkEgress),
            "fs" | "fs:read" | "fs.read" => Some(Self::FsRead),
            "fs:write" | "fs.write" => Some(Self::FsWrite),
            "module:require" | "module:import" | "module.import" => Some(Self::ModuleLoad),

            // Unknown / internal tags — not mapped
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// CapabilityProfile — named profiles with their capability sets
// ---------------------------------------------------------------------------

/// Named capability profile identifying a standard authority partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProfileKind {
    /// Union of all capabilities — orchestrator and test harness only.
    Full,
    /// VM dispatch, GC, IR lowering, heap allocation — no network, no policy mutation.
    EngineCore,
    /// Policy read/write, evidence emission, decision contracts — no VM, no network.
    Policy,
    /// Network egress, lease management, idempotency — no policy mutation, no VM.
    Remote,
    /// Pure computation, zero side effects — no I/O, no network, no policy.
    ComputeOnly,
}

impl fmt::Display for ProfileKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Full => "FullCaps",
            Self::EngineCore => "EngineCoreCaps",
            Self::Policy => "PolicyCaps",
            Self::Remote => "RemoteCaps",
            Self::ComputeOnly => "ComputeOnlyCaps",
        };
        f.write_str(name)
    }
}

/// A concrete capability profile: a named set of granted capabilities.
///
/// Uses `BTreeSet` for deterministic serialization and iteration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityProfile {
    pub kind: ProfileKind,
    pub capabilities: BTreeSet<RuntimeCapability>,
}

impl CapabilityProfile {
    /// Create the `FullCaps` profile (all capabilities).
    pub fn full() -> Self {
        use RuntimeCapability::*;
        Self {
            kind: ProfileKind::Full,
            capabilities: BTreeSet::from([
                VmDispatch,
                GcInvoke,
                IrLowering,
                PolicyRead,
                PolicyWrite,
                EvidenceEmit,
                DecisionInvoke,
                NetworkEgress,
                LeaseManagement,
                IdempotencyDerive,
                ExtensionLifecycle,
                HeapAllocate,
                EnvRead,
                ProcessSpawn,
                FsRead,
                FsWrite,
                ModuleLoad,
            ]),
        }
    }

    /// Create the `EngineCoreCaps` profile.
    pub fn engine_core() -> Self {
        use RuntimeCapability::*;
        Self {
            kind: ProfileKind::EngineCore,
            capabilities: BTreeSet::from([VmDispatch, GcInvoke, IrLowering, HeapAllocate]),
        }
    }

    /// Create the `PolicyCaps` profile.
    pub fn policy() -> Self {
        use RuntimeCapability::*;
        Self {
            kind: ProfileKind::Policy,
            capabilities: BTreeSet::from([PolicyRead, PolicyWrite, EvidenceEmit, DecisionInvoke]),
        }
    }

    /// Create the `RemoteCaps` profile.
    pub fn remote() -> Self {
        use RuntimeCapability::*;
        Self {
            kind: ProfileKind::Remote,
            capabilities: BTreeSet::from([NetworkEgress, LeaseManagement, IdempotencyDerive]),
        }
    }

    /// Create the `ComputeOnlyCaps` profile (zero side effects).
    pub fn compute_only() -> Self {
        Self {
            kind: ProfileKind::ComputeOnly,
            capabilities: BTreeSet::new(),
        }
    }

    /// Check whether this profile grants a specific capability.
    pub fn has(&self, cap: RuntimeCapability) -> bool {
        self.capabilities.contains(&cap)
    }

    /// Check whether this profile is a superset of another.
    pub fn subsumes(&self, other: &CapabilityProfile) -> bool {
        other.capabilities.is_subset(&self.capabilities)
    }

    /// Intersect two profiles (narrowing — always safe).
    ///
    /// The result contains only capabilities present in both profiles.
    /// The resulting kind is `ComputeOnly` since intersection produces
    /// a non-standard profile.
    pub fn intersect(&self, other: &CapabilityProfile) -> CapabilityProfile {
        let caps: BTreeSet<RuntimeCapability> = self
            .capabilities
            .intersection(&other.capabilities)
            .copied()
            .collect();

        // Determine the correct ProfileKind based on the intersection
        let kind = if caps.is_empty() {
            ProfileKind::ComputeOnly
        } else if caps == CapabilityProfile::full().capabilities {
            ProfileKind::Full
        } else if caps == CapabilityProfile::engine_core().capabilities {
            ProfileKind::EngineCore
        } else if caps == CapabilityProfile::policy().capabilities {
            ProfileKind::Policy
        } else if caps == CapabilityProfile::remote().capabilities {
            ProfileKind::Remote
        } else {
            // If no exact match with named profiles, use ComputeOnly as default
            // (This could be enhanced to use Custom in future if that variant is added)
            ProfileKind::ComputeOnly
        };

        CapabilityProfile {
            kind,
            capabilities: caps,
        }
    }

    /// Number of capabilities in this profile.
    pub fn len(&self) -> usize {
        self.capabilities.len()
    }

    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }
}

impl fmt::Display for CapabilityProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}[{}]", self.kind, self.capabilities.len())
    }
}

// ---------------------------------------------------------------------------
// CapabilityCheck — runtime capability enforcement
// ---------------------------------------------------------------------------

/// Error returned when a required capability is not held.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityDenied {
    /// The capability that was required.
    pub required: RuntimeCapability,
    /// The profile that was held.
    pub held_profile: ProfileKind,
    /// The component that attempted the operation.
    pub component: String,
}

impl fmt::Display for CapabilityDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "capability denied: '{}' requires '{}' but held profile '{}' does not grant it",
            self.component, self.required, self.held_profile
        )
    }
}

impl std::error::Error for CapabilityDenied {}

/// Check that a profile grants a required capability.
///
/// Returns `Ok(())` if granted, `Err(CapabilityDenied)` if not.
pub fn require_capability(
    profile: &CapabilityProfile,
    required: RuntimeCapability,
    component: &str,
) -> Result<(), CapabilityDenied> {
    if profile.has(required) {
        Ok(())
    } else {
        Err(CapabilityDenied {
            required,
            held_profile: profile.kind,
            component: component.to_string(),
        })
    }
}

/// Check that a profile grants all required capabilities.
///
/// Returns all denials (not fail-fast) for structured error reporting.
pub fn require_all(
    profile: &CapabilityProfile,
    required: &[RuntimeCapability],
    component: &str,
) -> Result<(), Vec<CapabilityDenied>> {
    let denials: Vec<CapabilityDenied> = required
        .iter()
        .filter(|cap| !profile.has(**cap))
        .map(|cap| CapabilityDenied {
            required: *cap,
            held_profile: profile.kind,
            component: component.to_string(),
        })
        .collect();

    if denials.is_empty() {
        Ok(())
    } else {
        Err(denials)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Profile contents --

    #[test]
    fn full_caps_contains_all_capabilities() {
        let full = CapabilityProfile::full();
        assert_eq!(full.len(), 17);
        assert!(full.has(RuntimeCapability::VmDispatch));
        assert!(full.has(RuntimeCapability::PolicyWrite));
        assert!(full.has(RuntimeCapability::NetworkEgress));
        assert!(full.has(RuntimeCapability::FsWrite));
    }

    #[test]
    fn engine_core_caps_contains_only_vm_gc_ir_heap() {
        let ec = CapabilityProfile::engine_core();
        assert_eq!(ec.len(), 4);
        assert!(ec.has(RuntimeCapability::VmDispatch));
        assert!(ec.has(RuntimeCapability::GcInvoke));
        assert!(ec.has(RuntimeCapability::IrLowering));
        assert!(ec.has(RuntimeCapability::HeapAllocate));
        // Must NOT have policy, network, or lifecycle.
        assert!(!ec.has(RuntimeCapability::PolicyWrite));
        assert!(!ec.has(RuntimeCapability::NetworkEgress));
        assert!(!ec.has(RuntimeCapability::ExtensionLifecycle));
    }

    #[test]
    fn policy_caps_contains_only_policy_evidence_decision() {
        let pol = CapabilityProfile::policy();
        assert_eq!(pol.len(), 4);
        assert!(pol.has(RuntimeCapability::PolicyRead));
        assert!(pol.has(RuntimeCapability::PolicyWrite));
        assert!(pol.has(RuntimeCapability::EvidenceEmit));
        assert!(pol.has(RuntimeCapability::DecisionInvoke));
        // Must NOT have VM or network.
        assert!(!pol.has(RuntimeCapability::VmDispatch));
        assert!(!pol.has(RuntimeCapability::NetworkEgress));
    }

    #[test]
    fn remote_caps_contains_only_network_lease_idempotency() {
        let rem = CapabilityProfile::remote();
        assert_eq!(rem.len(), 3);
        assert!(rem.has(RuntimeCapability::NetworkEgress));
        assert!(rem.has(RuntimeCapability::LeaseManagement));
        assert!(rem.has(RuntimeCapability::IdempotencyDerive));
        // Must NOT have policy or VM.
        assert!(!rem.has(RuntimeCapability::PolicyWrite));
        assert!(!rem.has(RuntimeCapability::VmDispatch));
    }

    #[test]
    fn compute_only_caps_is_empty() {
        let co = CapabilityProfile::compute_only();
        assert!(co.is_empty());
        assert_eq!(co.len(), 0);
        assert!(!co.has(RuntimeCapability::VmDispatch));
    }

    // -- Profiles are disjoint (except Full) --

    #[test]
    fn standard_profiles_are_pairwise_disjoint() {
        let ec = CapabilityProfile::engine_core();
        let pol = CapabilityProfile::policy();
        let rem = CapabilityProfile::remote();

        assert!(ec.intersect(&pol).is_empty());
        assert!(ec.intersect(&rem).is_empty());
        assert!(pol.intersect(&rem).is_empty());
    }

    // -- Subsumption --

    #[test]
    fn full_subsumes_all_profiles() {
        let full = CapabilityProfile::full();
        assert!(full.subsumes(&CapabilityProfile::engine_core()));
        assert!(full.subsumes(&CapabilityProfile::policy()));
        assert!(full.subsumes(&CapabilityProfile::remote()));
        assert!(full.subsumes(&CapabilityProfile::compute_only()));
    }

    #[test]
    fn narrow_profile_does_not_subsume_broader() {
        let ec = CapabilityProfile::engine_core();
        let full = CapabilityProfile::full();
        assert!(!ec.subsumes(&full));
    }

    #[test]
    fn profile_subsumes_itself() {
        let ec = CapabilityProfile::engine_core();
        assert!(ec.subsumes(&ec));
    }

    // -- Intersection --

    #[test]
    fn intersection_produces_common_caps() {
        let mut custom_a = CapabilityProfile::engine_core();
        custom_a.capabilities.insert(RuntimeCapability::PolicyRead);

        let pol = CapabilityProfile::policy();
        let inter = custom_a.intersect(&pol);
        assert_eq!(inter.len(), 1);
        assert!(inter.has(RuntimeCapability::PolicyRead));
    }

    #[test]
    fn intersection_is_monotonic_narrowing() {
        let full = CapabilityProfile::full();
        let ec = CapabilityProfile::engine_core();
        let inter = full.intersect(&ec);
        assert_eq!(inter.capabilities, ec.capabilities);
    }

    // -- Capability checks --

    #[test]
    fn require_capability_succeeds_when_granted() {
        let ec = CapabilityProfile::engine_core();
        assert!(require_capability(&ec, RuntimeCapability::VmDispatch, "test-vm").is_ok());
    }

    #[test]
    fn require_capability_fails_when_denied() {
        let ec = CapabilityProfile::engine_core();
        let err =
            require_capability(&ec, RuntimeCapability::NetworkEgress, "test-net").unwrap_err();
        assert_eq!(err.required, RuntimeCapability::NetworkEgress);
        assert_eq!(err.held_profile, ProfileKind::EngineCore);
        assert_eq!(err.component, "test-net");
    }

    #[test]
    fn require_all_succeeds_when_all_granted() {
        let full = CapabilityProfile::full();
        assert!(
            require_all(
                &full,
                &[
                    RuntimeCapability::VmDispatch,
                    RuntimeCapability::PolicyWrite
                ],
                "test"
            )
            .is_ok()
        );
    }

    #[test]
    fn require_all_collects_all_denials() {
        let co = CapabilityProfile::compute_only();
        let denials = require_all(
            &co,
            &[
                RuntimeCapability::VmDispatch,
                RuntimeCapability::NetworkEgress,
                RuntimeCapability::PolicyWrite,
            ],
            "test-multi",
        )
        .unwrap_err();
        assert_eq!(denials.len(), 3);
    }

    // -- Display --

    #[test]
    fn profile_kind_display() {
        assert_eq!(ProfileKind::Full.to_string(), "FullCaps");
        assert_eq!(ProfileKind::EngineCore.to_string(), "EngineCoreCaps");
        assert_eq!(ProfileKind::Policy.to_string(), "PolicyCaps");
        assert_eq!(ProfileKind::Remote.to_string(), "RemoteCaps");
        assert_eq!(ProfileKind::ComputeOnly.to_string(), "ComputeOnlyCaps");
    }

    #[test]
    fn capability_display() {
        assert_eq!(RuntimeCapability::VmDispatch.to_string(), "vm_dispatch");
        assert_eq!(RuntimeCapability::PolicyWrite.to_string(), "policy_write");
        assert_eq!(
            RuntimeCapability::NetworkEgress.to_string(),
            "network_egress"
        );
    }

    #[test]
    fn capability_denied_display() {
        let err = CapabilityDenied {
            required: RuntimeCapability::NetworkEgress,
            held_profile: ProfileKind::EngineCore,
            component: "remote-sender".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "capability denied: 'remote-sender' requires 'network_egress' but held profile 'EngineCoreCaps' does not grant it"
        );
    }

    #[test]
    fn capability_profile_display() {
        let ec = CapabilityProfile::engine_core();
        assert_eq!(ec.to_string(), "EngineCoreCaps[4]");
    }

    // -- Serialization --

    #[test]
    fn capability_profile_serialization_round_trip() {
        let full = CapabilityProfile::full();
        // SAFETY: CapabilityProfile derives Serialize and has no non-serializable fields
        let json = serde_json::to_string(&full).unwrap();
        // SAFETY: JSON was just produced by valid CapabilityProfile serialization
        let restored: CapabilityProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(full, restored);
    }

    #[test]
    fn all_profiles_serialize_deterministically() {
        let profiles = [
            CapabilityProfile::full(),
            CapabilityProfile::engine_core(),
            CapabilityProfile::policy(),
            CapabilityProfile::remote(),
            CapabilityProfile::compute_only(),
        ];
        for profile in &profiles {
            // SAFETY: CapabilityProfile derives Serialize and has no non-serializable fields
            let json1 = serde_json::to_string(profile).unwrap();
            // SAFETY: CapabilityProfile derives Serialize and has no non-serializable fields
            let json2 = serde_json::to_string(profile).unwrap();
            assert_eq!(
                json1, json2,
                "non-deterministic serialization for {}",
                profile.kind
            );
        }
    }

    // -- Enrichment: serde, ordering, std::error --

    #[test]
    fn runtime_capability_serde_all_variants() {
        let all = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::GcInvoke,
            RuntimeCapability::IrLowering,
            RuntimeCapability::PolicyRead,
            RuntimeCapability::PolicyWrite,
            RuntimeCapability::EvidenceEmit,
            RuntimeCapability::DecisionInvoke,
            RuntimeCapability::NetworkEgress,
            RuntimeCapability::LeaseManagement,
            RuntimeCapability::IdempotencyDerive,
            RuntimeCapability::ExtensionLifecycle,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::EnvRead,
            RuntimeCapability::ProcessSpawn,
            RuntimeCapability::FsRead,
            RuntimeCapability::FsWrite,
        ];
        for cap in &all {
            // SAFETY: RuntimeCapability derives Serialize and has no non-serializable fields
            let json = serde_json::to_string(cap).unwrap();
            // SAFETY: JSON was just produced by valid RuntimeCapability serialization
            let restored: RuntimeCapability = serde_json::from_str(&json).unwrap();
            assert_eq!(*cap, restored);
        }
    }

    #[test]
    fn profile_kind_serde_all_variants() {
        let all = [
            ProfileKind::Full,
            ProfileKind::EngineCore,
            ProfileKind::Policy,
            ProfileKind::Remote,
            ProfileKind::ComputeOnly,
        ];
        for kind in &all {
            // SAFETY: ProfileKind derives Serialize and has no non-serializable fields
            let json = serde_json::to_string(kind).unwrap();
            // SAFETY: JSON was just produced by valid ProfileKind serialization
            let restored: ProfileKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, restored);
        }
    }

    #[test]
    fn runtime_capability_ordering() {
        assert!(RuntimeCapability::VmDispatch < RuntimeCapability::GcInvoke);
        assert!(RuntimeCapability::GcInvoke < RuntimeCapability::IrLowering);
        assert!(RuntimeCapability::IrLowering < RuntimeCapability::PolicyRead);
        assert!(RuntimeCapability::FsRead < RuntimeCapability::FsWrite);
    }

    #[test]
    fn profile_kind_ordering() {
        assert!(ProfileKind::Full < ProfileKind::EngineCore);
        assert!(ProfileKind::EngineCore < ProfileKind::Policy);
        assert!(ProfileKind::Policy < ProfileKind::Remote);
        assert!(ProfileKind::Remote < ProfileKind::ComputeOnly);
    }

    #[test]
    fn capability_denied_implements_std_error() {
        let denied = CapabilityDenied {
            required: RuntimeCapability::PolicyWrite,
            held_profile: ProfileKind::EngineCore,
            component: "test".to_string(),
        };
        let err: &dyn std::error::Error = &denied;
        assert!(!format!("{err}").is_empty());
        assert!(err.source().is_none());
    }

    #[test]
    fn capability_denied_serialization_round_trip() {
        let denied = CapabilityDenied {
            required: RuntimeCapability::PolicyWrite,
            held_profile: ProfileKind::EngineCore,
            component: "test".to_string(),
        };
        let json = serde_json::to_string(&denied).unwrap();
        let restored: CapabilityDenied = serde_json::from_str(&json).unwrap();
        assert_eq!(denied, restored);
    }

    // ── Enrichment: intersection edge cases ──────────────────────

    #[test]
    fn intersection_with_self_preserves_capabilities() {
        let ec = CapabilityProfile::engine_core();
        let inter = ec.intersect(&ec);
        assert_eq!(inter.capabilities, ec.capabilities);
    }

    #[test]
    fn intersection_with_compute_only_is_empty() {
        let full = CapabilityProfile::full();
        let co = CapabilityProfile::compute_only();
        let inter = full.intersect(&co);
        assert!(inter.is_empty());
    }

    #[test]
    fn intersection_is_commutative() {
        let ec = CapabilityProfile::engine_core();
        let pol = CapabilityProfile::policy();
        let ab = ec.intersect(&pol);
        let ba = pol.intersect(&ec);
        assert_eq!(ab.capabilities, ba.capabilities);
    }

    #[test]
    fn intersection_result_kind_matches_actual_capabilities() {
        let full = CapabilityProfile::full();
        let ec = CapabilityProfile::engine_core();
        let inter = full.intersect(&ec);
        // full ∩ engine_core = engine_core capabilities, so kind should be EngineCore
        assert_eq!(inter.kind, ProfileKind::EngineCore);
        assert_eq!(inter.capabilities, ec.capabilities);
    }

    // ── Enrichment: has / len / is_empty ─────────────────────────

    #[test]
    fn full_profile_has_all_16_capabilities() {
        let full = CapabilityProfile::full();
        let all = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::GcInvoke,
            RuntimeCapability::IrLowering,
            RuntimeCapability::PolicyRead,
            RuntimeCapability::PolicyWrite,
            RuntimeCapability::EvidenceEmit,
            RuntimeCapability::DecisionInvoke,
            RuntimeCapability::NetworkEgress,
            RuntimeCapability::LeaseManagement,
            RuntimeCapability::IdempotencyDerive,
            RuntimeCapability::ExtensionLifecycle,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::EnvRead,
            RuntimeCapability::ProcessSpawn,
            RuntimeCapability::FsRead,
            RuntimeCapability::FsWrite,
        ];
        for cap in &all {
            assert!(full.has(*cap), "full should have {:?}", cap);
        }
        assert_eq!(full.len(), all.len());
        assert!(!full.is_empty());
    }

    #[test]
    fn compute_only_has_no_capability() {
        let co = CapabilityProfile::compute_only();
        assert!(!co.has(RuntimeCapability::VmDispatch));
        assert!(!co.has(RuntimeCapability::FsWrite));
        assert!(!co.has(RuntimeCapability::ExtensionLifecycle));
    }

    // ── Enrichment: subsumption transitivity ─────────────────────

    #[test]
    fn compute_only_subsumes_nothing_but_itself() {
        let co = CapabilityProfile::compute_only();
        assert!(co.subsumes(&co));
        assert!(!co.subsumes(&CapabilityProfile::engine_core()));
        assert!(!co.subsumes(&CapabilityProfile::policy()));
        assert!(!co.subsumes(&CapabilityProfile::remote()));
    }

    #[test]
    fn no_non_full_profile_subsumes_full() {
        let full = CapabilityProfile::full();
        assert!(!CapabilityProfile::engine_core().subsumes(&full));
        assert!(!CapabilityProfile::policy().subsumes(&full));
        assert!(!CapabilityProfile::remote().subsumes(&full));
        assert!(!CapabilityProfile::compute_only().subsumes(&full));
    }

    // ── Enrichment: require_all edge cases ───────────────────────

    #[test]
    fn require_all_empty_requirements_succeeds() {
        let co = CapabilityProfile::compute_only();
        assert!(require_all(&co, &[], "test-empty").is_ok());
    }

    #[test]
    fn require_all_denials_have_correct_component() {
        let co = CapabilityProfile::compute_only();
        let denials =
            require_all(&co, &[RuntimeCapability::VmDispatch], "my-component").unwrap_err();
        assert_eq!(denials[0].component, "my-component");
        assert_eq!(denials[0].held_profile, ProfileKind::ComputeOnly);
    }

    // ── Enrichment: Display completeness ─────────────────────────

    #[test]
    fn all_runtime_capabilities_have_display() {
        let all = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::GcInvoke,
            RuntimeCapability::IrLowering,
            RuntimeCapability::PolicyRead,
            RuntimeCapability::PolicyWrite,
            RuntimeCapability::EvidenceEmit,
            RuntimeCapability::DecisionInvoke,
            RuntimeCapability::NetworkEgress,
            RuntimeCapability::LeaseManagement,
            RuntimeCapability::IdempotencyDerive,
            RuntimeCapability::ExtensionLifecycle,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::EnvRead,
            RuntimeCapability::ProcessSpawn,
            RuntimeCapability::FsRead,
            RuntimeCapability::FsWrite,
        ];
        for cap in &all {
            let s = cap.to_string();
            assert!(!s.is_empty());
            assert!(s.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
        }
    }

    #[test]
    fn capability_profile_display_includes_count() {
        let full = CapabilityProfile::full();
        assert_eq!(full.to_string(), "FullCaps[16]");
        let co = CapabilityProfile::compute_only();
        assert_eq!(co.to_string(), "ComputeOnlyCaps[0]");
    }

    // ── Enrichment: profile disjointness exhaustive ──────────────

    #[test]
    fn engine_core_policy_remote_union_is_subset_of_full() {
        let full = CapabilityProfile::full();
        let ec = CapabilityProfile::engine_core();
        let pol = CapabilityProfile::policy();
        let rem = CapabilityProfile::remote();
        let mut combined = BTreeSet::new();
        combined.extend(&ec.capabilities);
        combined.extend(&pol.capabilities);
        combined.extend(&rem.capabilities);
        assert!(combined.is_subset(&full.capabilities));
    }

    // ── Enrichment: deterministic serialization ──────────────────

    #[test]
    fn capability_denied_serde_preserves_all_fields() {
        let denied = CapabilityDenied {
            required: RuntimeCapability::FsWrite,
            held_profile: ProfileKind::Remote,
            component: "fs-writer".to_string(),
        };
        let json = serde_json::to_string(&denied).unwrap();
        let back: CapabilityDenied = serde_json::from_str(&json).unwrap();
        assert_eq!(back.required, RuntimeCapability::FsWrite);
        assert_eq!(back.held_profile, ProfileKind::Remote);
        assert_eq!(back.component, "fs-writer");
    }

    // -- Enrichment batch 3: deeper edge cases --

    #[test]
    fn profile_clone_preserves_equality() {
        let full = CapabilityProfile::full();
        let cloned = full.clone();
        assert_eq!(full, cloned);
        assert_eq!(full.kind, cloned.kind);
        assert_eq!(full.capabilities, cloned.capabilities);
    }

    #[test]
    fn same_profile_created_twice_is_equal() {
        assert_eq!(CapabilityProfile::full(), CapabilityProfile::full());
        assert_eq!(
            CapabilityProfile::engine_core(),
            CapabilityProfile::engine_core()
        );
        assert_eq!(CapabilityProfile::policy(), CapabilityProfile::policy());
        assert_eq!(CapabilityProfile::remote(), CapabilityProfile::remote());
        assert_eq!(
            CapabilityProfile::compute_only(),
            CapabilityProfile::compute_only()
        );
    }

    #[test]
    fn different_profiles_are_not_equal() {
        assert_ne!(CapabilityProfile::full(), CapabilityProfile::engine_core());
        assert_ne!(
            CapabilityProfile::engine_core(),
            CapabilityProfile::policy()
        );
        assert_ne!(CapabilityProfile::policy(), CapabilityProfile::remote());
        assert_ne!(
            CapabilityProfile::remote(),
            CapabilityProfile::compute_only()
        );
    }

    #[test]
    fn require_all_partial_denials() {
        let ec = CapabilityProfile::engine_core();
        // VmDispatch is granted, NetworkEgress is not
        let denials = require_all(
            &ec,
            &[
                RuntimeCapability::VmDispatch,
                RuntimeCapability::NetworkEgress,
            ],
            "partial-test",
        )
        .unwrap_err();
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].required, RuntimeCapability::NetworkEgress);
    }

    #[test]
    fn intersection_associativity() {
        let full = CapabilityProfile::full();
        let ec = CapabilityProfile::engine_core();
        let pol = CapabilityProfile::policy();
        let ab_c = full.intersect(&ec).intersect(&pol);
        let a_bc = full.intersect(&ec.intersect(&pol));
        assert_eq!(ab_c.capabilities, a_bc.capabilities);
    }

    #[test]
    fn full_profile_is_not_empty() {
        let full = CapabilityProfile::full();
        assert!(!full.is_empty());
    }

    #[test]
    fn require_capability_on_full_always_succeeds() {
        let full = CapabilityProfile::full();
        let all_caps = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::GcInvoke,
            RuntimeCapability::IrLowering,
            RuntimeCapability::PolicyRead,
            RuntimeCapability::PolicyWrite,
            RuntimeCapability::EvidenceEmit,
            RuntimeCapability::DecisionInvoke,
            RuntimeCapability::NetworkEgress,
            RuntimeCapability::LeaseManagement,
            RuntimeCapability::IdempotencyDerive,
            RuntimeCapability::ExtensionLifecycle,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::EnvRead,
            RuntimeCapability::ProcessSpawn,
            RuntimeCapability::FsRead,
            RuntimeCapability::FsWrite,
        ];
        for cap in &all_caps {
            assert!(
                require_capability(&full, *cap, "full-test").is_ok(),
                "full should grant {:?}",
                cap
            );
        }
    }

    #[test]
    fn require_all_on_full_with_all_caps() {
        let full = CapabilityProfile::full();
        let all_caps = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::GcInvoke,
            RuntimeCapability::IrLowering,
            RuntimeCapability::PolicyRead,
            RuntimeCapability::PolicyWrite,
            RuntimeCapability::EvidenceEmit,
            RuntimeCapability::DecisionInvoke,
            RuntimeCapability::NetworkEgress,
            RuntimeCapability::LeaseManagement,
            RuntimeCapability::IdempotencyDerive,
            RuntimeCapability::ExtensionLifecycle,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::EnvRead,
            RuntimeCapability::ProcessSpawn,
            RuntimeCapability::FsRead,
            RuntimeCapability::FsWrite,
        ];
        assert!(require_all(&full, &all_caps, "all-caps-test").is_ok());
    }

    #[test]
    fn capability_denied_display_contains_all_fields() {
        let denied = CapabilityDenied {
            required: RuntimeCapability::ProcessSpawn,
            held_profile: ProfileKind::Policy,
            component: "task-runner".to_string(),
        };
        let display = denied.to_string();
        assert!(display.contains("task-runner"));
        assert!(display.contains("process_spawn"));
        assert!(display.contains("PolicyCaps"));
    }

    #[test]
    fn runtime_capability_copy_semantics() {
        let cap = RuntimeCapability::VmDispatch;
        let cap2 = cap;
        assert_eq!(cap, cap2);
    }

    #[test]
    fn profile_kind_copy_semantics() {
        let kind = ProfileKind::Full;
        let kind2 = kind;
        assert_eq!(kind, kind2);
    }

    #[test]
    fn capability_profile_json_contains_expected_fields() {
        let ec = CapabilityProfile::engine_core();
        let json = serde_json::to_string(&ec).unwrap();
        assert!(json.contains("\"kind\""));
        assert!(json.contains("\"capabilities\""));
        assert!(json.contains("EngineCore"));
    }

    #[test]
    fn intersect_full_with_full_equals_full_caps() {
        let full1 = CapabilityProfile::full();
        let full2 = CapabilityProfile::full();
        let inter = full1.intersect(&full2);
        assert_eq!(inter.capabilities, full1.capabilities);
    }

    #[test]
    fn profile_kind_display_all_unique() {
        let displays: BTreeSet<String> = [
            ProfileKind::Full,
            ProfileKind::EngineCore,
            ProfileKind::Policy,
            ProfileKind::Remote,
            ProfileKind::ComputeOnly,
        ]
        .iter()
        .map(|k| k.to_string())
        .collect();
        assert_eq!(
            displays.len(),
            5,
            "all 5 ProfileKind variants have unique Display"
        );
    }

    #[test]
    fn runtime_capability_display_all_16_unique() {
        let displays: BTreeSet<String> = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::GcInvoke,
            RuntimeCapability::IrLowering,
            RuntimeCapability::PolicyRead,
            RuntimeCapability::PolicyWrite,
            RuntimeCapability::EvidenceEmit,
            RuntimeCapability::DecisionInvoke,
            RuntimeCapability::NetworkEgress,
            RuntimeCapability::LeaseManagement,
            RuntimeCapability::IdempotencyDerive,
            RuntimeCapability::ExtensionLifecycle,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::EnvRead,
            RuntimeCapability::ProcessSpawn,
            RuntimeCapability::FsRead,
            RuntimeCapability::FsWrite,
        ]
        .iter()
        .map(|c| c.to_string())
        .collect();
        assert_eq!(
            displays.len(),
            16,
            "all 16 RuntimeCapability variants have unique Display"
        );
    }

    #[test]
    fn engine_core_has_no_remote_caps() {
        let ec = CapabilityProfile::engine_core();
        assert!(!ec.has(RuntimeCapability::NetworkEgress));
        assert!(!ec.has(RuntimeCapability::LeaseManagement));
        assert!(!ec.has(RuntimeCapability::IdempotencyDerive));
    }

    #[test]
    fn remote_has_no_policy_caps() {
        let rem = CapabilityProfile::remote();
        assert!(!rem.has(RuntimeCapability::PolicyRead));
        assert!(!rem.has(RuntimeCapability::PolicyWrite));
        assert!(!rem.has(RuntimeCapability::EvidenceEmit));
        assert!(!rem.has(RuntimeCapability::DecisionInvoke));
    }

    #[test]
    fn require_all_with_single_requirement() {
        let ec = CapabilityProfile::engine_core();
        assert!(require_all(&ec, &[RuntimeCapability::VmDispatch], "single").is_ok());
        let denied = require_all(&ec, &[RuntimeCapability::PolicyWrite], "single").unwrap_err();
        assert_eq!(denied.len(), 1);
    }

    #[test]
    fn capability_denied_for_compute_only_contains_profile_name() {
        let denied = CapabilityDenied {
            required: RuntimeCapability::VmDispatch,
            held_profile: ProfileKind::ComputeOnly,
            component: "vm".to_string(),
        };
        assert!(denied.to_string().contains("ComputeOnlyCaps"));
    }

    #[test]
    fn subsumption_reflexive_for_all_profiles() {
        let profiles = [
            CapabilityProfile::full(),
            CapabilityProfile::engine_core(),
            CapabilityProfile::policy(),
            CapabilityProfile::remote(),
            CapabilityProfile::compute_only(),
        ];
        for p in &profiles {
            assert!(p.subsumes(p), "{} should subsume itself", p.kind);
        }
    }

    #[test]
    fn compute_only_subsumes_compute_only() {
        let co1 = CapabilityProfile::compute_only();
        let co2 = CapabilityProfile::compute_only();
        assert!(co1.subsumes(&co2));
    }

    #[test]
    fn all_profiles_serde_roundtrip() {
        let profiles = [
            CapabilityProfile::full(),
            CapabilityProfile::engine_core(),
            CapabilityProfile::policy(),
            CapabilityProfile::remote(),
            CapabilityProfile::compute_only(),
        ];
        for p in &profiles {
            let json = serde_json::to_string(p).unwrap();
            let restored: CapabilityProfile = serde_json::from_str(&json).unwrap();
            assert_eq!(*p, restored, "serde roundtrip failed for {}", p.kind);
        }
    }

    #[test]
    fn full_profile_display_shows_count_16() {
        assert_eq!(CapabilityProfile::full().to_string(), "FullCaps[16]");
    }

    #[test]
    fn remote_profile_display_shows_count_3() {
        assert_eq!(CapabilityProfile::remote().to_string(), "RemoteCaps[3]");
    }

    #[test]
    fn policy_profile_display_shows_count_4() {
        assert_eq!(CapabilityProfile::policy().to_string(), "PolicyCaps[4]");
    }

    // -- Enum completeness --------------------------------------------------

    #[test]
    fn full_profile_contains_all_16_capabilities() {
        use RuntimeCapability::*;
        let all = [
            VmDispatch,
            GcInvoke,
            IrLowering,
            PolicyRead,
            PolicyWrite,
            EvidenceEmit,
            DecisionInvoke,
            NetworkEgress,
            LeaseManagement,
            IdempotencyDerive,
            ExtensionLifecycle,
            HeapAllocate,
            EnvRead,
            ProcessSpawn,
            FsRead,
            FsWrite,
        ];
        let full = CapabilityProfile::full();
        for cap in &all {
            assert!(full.has(*cap), "full profile should have {:?}", cap);
        }
        assert_eq!(full.len(), 17);
    }

    #[test]
    fn runtime_capability_display_all_unique() {
        use RuntimeCapability::*;
        let all = [
            VmDispatch,
            GcInvoke,
            IrLowering,
            PolicyRead,
            PolicyWrite,
            EvidenceEmit,
            DecisionInvoke,
            NetworkEgress,
            LeaseManagement,
            IdempotencyDerive,
            ExtensionLifecycle,
            HeapAllocate,
            EnvRead,
            ProcessSpawn,
            FsRead,
            FsWrite,
        ];
        let strings: BTreeSet<String> = all.iter().map(|c| c.to_string()).collect();
        assert_eq!(strings.len(), 16, "all display strings should be unique");
    }

    // -- Profile disjointness pairwise matrix -------------------------------

    #[test]
    fn narrow_profiles_pairwise_disjoint() {
        let ec = CapabilityProfile::engine_core();
        let pol = CapabilityProfile::policy();
        let rem = CapabilityProfile::remote();
        // engine_core ∩ policy = ∅
        assert!(ec.intersect(&pol).is_empty());
        // engine_core ∩ remote = ∅
        assert!(ec.intersect(&rem).is_empty());
        // policy ∩ remote = ∅
        assert!(pol.intersect(&rem).is_empty());
    }

    // -- Subsumption exhaustive pairwise ------------------------------------

    #[test]
    fn subsumption_pairwise_matrix() {
        let profiles = [
            CapabilityProfile::full(),
            CapabilityProfile::engine_core(),
            CapabilityProfile::policy(),
            CapabilityProfile::remote(),
            CapabilityProfile::compute_only(),
        ];
        for (i, a) in profiles.iter().enumerate() {
            for (j, b) in profiles.iter().enumerate() {
                if i == j {
                    assert!(a.subsumes(b), "{} should subsume itself", a.kind);
                } else if i == 0 {
                    // Full subsumes everything.
                    assert!(a.subsumes(b), "full should subsume {}", b.kind);
                } else if j == 4 {
                    // Everything subsumes compute_only (empty set).
                    assert!(a.subsumes(b), "{} should subsume compute_only", a.kind);
                } else if i != 0 && j != 4 && i != j {
                    // Narrow profiles should not subsume each other.
                    assert!(!a.subsumes(b), "{} should not subsume {}", a.kind, b.kind);
                }
            }
        }
    }

    // -- Intersection properties --------------------------------------------

    #[test]
    fn intersection_idempotent() {
        let ec = CapabilityProfile::engine_core();
        let pol = CapabilityProfile::policy();
        let ab = ec.intersect(&pol);
        let ab_b = ab.intersect(&pol);
        assert_eq!(ab.capabilities, ab_b.capabilities);
    }

    #[test]
    fn intersection_with_full_preserves_caps() {
        let full = CapabilityProfile::full();
        let ec = CapabilityProfile::engine_core();
        let result = full.intersect(&ec);
        assert_eq!(result.capabilities, ec.capabilities);
    }

    #[test]
    fn intersection_result_kind_reflects_actual_intersection() {
        let full = CapabilityProfile::full();
        let ec = CapabilityProfile::engine_core();
        let result = full.intersect(&ec);
        // full ∩ engine_core should have EngineCore kind since it contains exactly EngineCore capabilities
        assert_eq!(result.kind, ProfileKind::EngineCore);
        assert_eq!(result.capabilities, ec.capabilities);
    }

    // -- Capability profile intersection kind correctness tests (bd-3pa1u.4) --

    #[test]
    fn intersect_full_with_full_returns_full_kind() {
        let full1 = CapabilityProfile::full();
        let full2 = CapabilityProfile::full();
        let result = full1.intersect(&full2);
        assert_eq!(result.kind, ProfileKind::Full);
        assert_eq!(result.capabilities, full1.capabilities);
    }

    #[test]
    fn intersect_compute_only_with_anything_returns_compute_only() {
        let co = CapabilityProfile::compute_only();
        let ec = CapabilityProfile::engine_core();
        let full = CapabilityProfile::full();
        let policy = CapabilityProfile::policy();

        let result1 = co.intersect(&ec);
        assert_eq!(result1.kind, ProfileKind::ComputeOnly);
        assert!(result1.is_empty());

        let result2 = ec.intersect(&co);
        assert_eq!(result2.kind, ProfileKind::ComputeOnly);
        assert!(result2.is_empty());

        let result3 = co.intersect(&full);
        assert_eq!(result3.kind, ProfileKind::ComputeOnly);
        assert!(result3.is_empty());

        let result4 = policy.intersect(&co);
        assert_eq!(result4.kind, ProfileKind::ComputeOnly);
        assert!(result4.is_empty());
    }

    #[test]
    fn intersect_engine_core_with_remote_has_no_overlap() {
        let ec = CapabilityProfile::engine_core();
        let remote = CapabilityProfile::remote();
        let result = ec.intersect(&remote);
        // EngineCore and Remote have no overlapping capabilities, so intersection is empty
        assert_eq!(result.kind, ProfileKind::ComputeOnly);
        assert!(result.is_empty());
    }

    #[test]
    fn intersect_profile_with_itself_preserves_identity() {
        let profiles = [
            CapabilityProfile::full(),
            CapabilityProfile::engine_core(),
            CapabilityProfile::policy(),
            CapabilityProfile::remote(),
            CapabilityProfile::compute_only(),
        ];

        for profile in &profiles {
            let result = profile.intersect(profile);
            assert_eq!(result.kind, profile.kind);
            assert_eq!(result.capabilities, profile.capabilities);
        }
    }

    #[test]
    fn intersect_full_with_engine_core_returns_engine_core_kind() {
        let full = CapabilityProfile::full();
        let ec = CapabilityProfile::engine_core();
        let result = full.intersect(&ec);
        // This is the key test case from the bead requirements
        assert_eq!(result.kind, ProfileKind::EngineCore);
        assert_eq!(result.capabilities, ec.capabilities);
    }

    #[test]
    fn sequential_intersections_narrow_to_empty() {
        let mut result = CapabilityProfile::full();
        result = result.intersect(&CapabilityProfile::engine_core());
        assert_eq!(result.len(), 4);
        result = result.intersect(&CapabilityProfile::policy());
        assert!(result.is_empty(), "ec ∩ policy should be empty");
    }

    // -- Custom profile construction ----------------------------------------

    #[test]
    fn custom_profile_has_and_len() {
        let profile = CapabilityProfile {
            kind: ProfileKind::ComputeOnly,
            capabilities: BTreeSet::from([RuntimeCapability::FsRead, RuntimeCapability::FsWrite]),
        };
        assert_eq!(profile.len(), 2);
        assert!(profile.has(RuntimeCapability::FsRead));
        assert!(profile.has(RuntimeCapability::FsWrite));
        assert!(!profile.has(RuntimeCapability::NetworkEgress));
    }

    #[test]
    fn custom_profile_subsumption() {
        let fs_only = CapabilityProfile {
            kind: ProfileKind::ComputeOnly,
            capabilities: BTreeSet::from([RuntimeCapability::FsRead, RuntimeCapability::FsWrite]),
        };
        let full = CapabilityProfile::full();
        assert!(full.subsumes(&fs_only));
        assert!(!fs_only.subsumes(&full));
    }

    // -- require_all edge cases ---------------------------------------------

    #[test]
    fn require_all_empty_requirements_always_ok() {
        let co = CapabilityProfile::compute_only();
        assert!(require_all(&co, &[], "test").is_ok());
    }

    #[test]
    fn require_all_duplicate_requirements() {
        let ec = CapabilityProfile::engine_core();
        // Duplicate missing cap should produce duplicate denials.
        let result = require_all(
            &ec,
            &[
                RuntimeCapability::NetworkEgress,
                RuntimeCapability::NetworkEgress,
            ],
            "test",
        );
        let denials = result.unwrap_err();
        assert_eq!(denials.len(), 2);
    }

    #[test]
    fn require_all_collects_all_denials_with_component() {
        let co = CapabilityProfile::compute_only();
        let caps = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::PolicyRead,
            RuntimeCapability::NetworkEgress,
        ];
        let denials = require_all(&co, &caps, "orchestrator").unwrap_err();
        assert_eq!(denials.len(), 3);
        for denial in &denials {
            assert_eq!(denial.component, "orchestrator");
            assert_eq!(denial.held_profile, ProfileKind::ComputeOnly);
        }
    }

    #[test]
    fn require_all_partial_denials_specific_caps() {
        let ec = CapabilityProfile::engine_core();
        let caps = [
            RuntimeCapability::VmDispatch,    // granted
            RuntimeCapability::PolicyRead,    // denied
            RuntimeCapability::HeapAllocate,  // granted
            RuntimeCapability::NetworkEgress, // denied
        ];
        let denials = require_all(&ec, &caps, "mixed").unwrap_err();
        assert_eq!(denials.len(), 2);
        assert!(
            denials
                .iter()
                .any(|d| d.required == RuntimeCapability::PolicyRead)
        );
        assert!(
            denials
                .iter()
                .any(|d| d.required == RuntimeCapability::NetworkEgress)
        );
    }

    // -- require_capability edge cases --------------------------------------

    #[test]
    fn require_capability_denied_fields() {
        let ec = CapabilityProfile::engine_core();
        let err = require_capability(&ec, RuntimeCapability::FsWrite, "writer").unwrap_err();
        assert_eq!(err.required, RuntimeCapability::FsWrite);
        assert_eq!(err.held_profile, ProfileKind::EngineCore);
        assert_eq!(err.component, "writer");
    }

    #[test]
    fn require_capability_display_message() {
        let err = CapabilityDenied {
            required: RuntimeCapability::ProcessSpawn,
            held_profile: ProfileKind::Remote,
            component: "sandbox".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("sandbox"));
        assert!(msg.contains("process_spawn"));
        assert!(msg.contains("RemoteCaps"));
    }

    // -- CapabilityDenied serde roundtrip -----------------------------------

    #[test]
    fn capability_denied_serde_roundtrip() {
        let denied = CapabilityDenied {
            required: RuntimeCapability::GcInvoke,
            held_profile: ProfileKind::Remote,
            component: "gc-manager".to_string(),
        };
        let json = serde_json::to_string(&denied).unwrap();
        let back: CapabilityDenied = serde_json::from_str(&json).unwrap();
        assert_eq!(denied, back);
    }

    // -- ProfileKind ordering full chain ------------------------------------

    #[test]
    fn profile_kind_ordering_full_chain() {
        assert!(ProfileKind::Full < ProfileKind::EngineCore);
        assert!(ProfileKind::EngineCore < ProfileKind::Policy);
        assert!(ProfileKind::Policy < ProfileKind::Remote);
        assert!(ProfileKind::Remote < ProfileKind::ComputeOnly);
    }

    #[test]
    fn profile_kind_display_strings_unique() {
        let kinds = [
            ProfileKind::Full,
            ProfileKind::EngineCore,
            ProfileKind::Policy,
            ProfileKind::Remote,
            ProfileKind::ComputeOnly,
        ];
        let strings: BTreeSet<String> = kinds.iter().map(|k| k.to_string()).collect();
        assert_eq!(strings.len(), 5);
    }

    // -- RuntimeCapability ordering -----------------------------------------

    #[test]
    fn runtime_capability_ordering_full_chain() {
        use RuntimeCapability::*;
        let ordered = [
            VmDispatch,
            GcInvoke,
            IrLowering,
            PolicyRead,
            PolicyWrite,
            EvidenceEmit,
            DecisionInvoke,
            NetworkEgress,
            LeaseManagement,
            IdempotencyDerive,
            ExtensionLifecycle,
            HeapAllocate,
            EnvRead,
            ProcessSpawn,
            FsRead,
            FsWrite,
        ];
        for i in 0..ordered.len() {
            for j in (i + 1)..ordered.len() {
                assert!(
                    ordered[i] < ordered[j],
                    "{:?} should be < {:?}",
                    ordered[i],
                    ordered[j]
                );
            }
        }
    }

    // -- Profile union coverage check ---------------------------------------

    #[test]
    fn narrow_profiles_union_equals_full_minus_extras() {
        let ec = CapabilityProfile::engine_core();
        let pol = CapabilityProfile::policy();
        let rem = CapabilityProfile::remote();
        let mut union_caps: BTreeSet<RuntimeCapability> = BTreeSet::new();
        union_caps.extend(&ec.capabilities);
        union_caps.extend(&pol.capabilities);
        union_caps.extend(&rem.capabilities);
        // The union of narrow profiles should be a subset of full.
        let full = CapabilityProfile::full();
        assert!(union_caps.is_subset(&full.capabilities));
        // But should not cover all 16 (missing ExtensionLifecycle, EnvRead, ProcessSpawn, FsRead, FsWrite).
        assert!(union_caps.len() < 16);
    }

    // -- Deterministic serialization ----------------------------------------

    #[test]
    fn profile_serialization_deterministic() {
        let p1 = CapabilityProfile::full();
        let p2 = CapabilityProfile::full();
        let j1 = serde_json::to_string(&p1).unwrap();
        let j2 = serde_json::to_string(&p2).unwrap();
        assert_eq!(j1, j2);
    }

    // -- is_empty correctness -----------------------------------------------

    #[test]
    fn compute_only_is_empty() {
        assert!(CapabilityProfile::compute_only().is_empty());
    }

    #[test]
    fn full_is_not_empty() {
        assert!(!CapabilityProfile::full().is_empty());
    }

    #[test]
    fn engine_core_is_not_empty() {
        assert!(!CapabilityProfile::engine_core().is_empty());
    }

    // -- from_tag_str mapping --

    #[test]
    fn from_tag_str_canonical_names() {
        assert_eq!(
            RuntimeCapability::from_tag_str("vm_dispatch"),
            Some(RuntimeCapability::VmDispatch)
        );
        assert_eq!(
            RuntimeCapability::from_tag_str("fs_read"),
            Some(RuntimeCapability::FsRead)
        );
        assert_eq!(
            RuntimeCapability::from_tag_str("network_egress"),
            Some(RuntimeCapability::NetworkEgress)
        );
        assert_eq!(
            RuntimeCapability::from_tag_str("module_load"),
            Some(RuntimeCapability::ModuleLoad)
        );
    }

    #[test]
    fn from_tag_str_short_aliases() {
        assert_eq!(
            RuntimeCapability::from_tag_str("network"),
            Some(RuntimeCapability::NetworkEgress)
        );
        assert_eq!(
            RuntimeCapability::from_tag_str("net"),
            Some(RuntimeCapability::NetworkEgress)
        );
        assert_eq!(
            RuntimeCapability::from_tag_str("fs"),
            Some(RuntimeCapability::FsRead)
        );
        assert_eq!(
            RuntimeCapability::from_tag_str("fs:read"),
            Some(RuntimeCapability::FsRead)
        );
        assert_eq!(
            RuntimeCapability::from_tag_str("fs:write"),
            Some(RuntimeCapability::FsWrite)
        );
        assert_eq!(
            RuntimeCapability::from_tag_str("net:connect"),
            Some(RuntimeCapability::NetworkEgress)
        );
        assert_eq!(
            RuntimeCapability::from_tag_str("module:require"),
            Some(RuntimeCapability::ModuleLoad)
        );
        assert_eq!(
            RuntimeCapability::from_tag_str("module:import"),
            Some(RuntimeCapability::ModuleLoad)
        );
    }

    #[test]
    fn from_tag_str_unknown_returns_none() {
        assert_eq!(RuntimeCapability::from_tag_str("promise:resolve"), None);
        assert_eq!(RuntimeCapability::from_tag_str("unknown"), None);
        assert_eq!(RuntimeCapability::from_tag_str(""), None);
    }

    #[test]
    fn full_profile_includes_module_load() {
        let full = CapabilityProfile::full();
        assert!(full.has(RuntimeCapability::ModuleLoad));
    }
}
