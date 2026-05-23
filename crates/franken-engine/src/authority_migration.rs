//! Authority migration layer for unified algebra consumption.
//!
//! Provides compatibility functions that bridge existing separate flow_lattice,
//! capability operations, and budget envelope manipulation to the unified
//! AuthorityLattice API. Ensures existing per-axis tests continue to pass while
//! enabling new combined-axis operations.
//!
//! This module implements bd-cixqu.26.3: migrating existing types and tests to
//! consume the unified algebra where operations cross axes.

use std::collections::BTreeSet;

use crate::capability::{CapabilityProfile, RuntimeCapability};
use crate::flow_lattice::LabelClass;
use crate::unified_authority_algebra::{
    AuthorityLattice, AuthorityLatticeError, BudgetEnvelope, CapabilityKind, CapabilitySet,
};

// ---------------------------------------------------------------------------
// Migration utilities for existing capability operations
// ---------------------------------------------------------------------------

/// Convert a `RuntimeCapability` to the unified algebra `CapabilityKind`.
pub fn runtime_cap_to_unified(cap: RuntimeCapability) -> Option<CapabilityKind> {
    match cap {
        RuntimeCapability::FsRead => Some(CapabilityKind::FsRead),
        RuntimeCapability::FsWrite => Some(CapabilityKind::FsWrite),
        RuntimeCapability::NetworkEgress => Some(CapabilityKind::NetConnect),
        RuntimeCapability::ProcessSpawn => Some(CapabilityKind::ProcSpawn),
        RuntimeCapability::EnvRead => Some(CapabilityKind::EnvRead),
        RuntimeCapability::PolicyRead | RuntimeCapability::PolicyWrite => {
            Some(CapabilityKind::PolicyRequest)
        }
        RuntimeCapability::Timer => Some(CapabilityKind::ClockRead),
        RuntimeCapability::Builtin => Some(CapabilityKind::Global),
        // Other RuntimeCapabilities don't have direct unified equivalents
        _ => None,
    }
}

/// Convert a `CapabilityProfile` to a unified `CapabilitySet`.
pub fn profile_to_unified_capset(profile: &CapabilityProfile) -> CapabilitySet {
    let mut unified_caps = BTreeSet::new();

    for &runtime_cap in profile.capabilities() {
        if let Some(unified_cap) = runtime_cap_to_unified(runtime_cap) {
            unified_caps.insert(unified_cap);
        }
    }

    CapabilitySet::from_iter(unified_caps)
}

/// Create a default budget envelope with reasonable defaults.
pub fn default_budget_envelope() -> BudgetEnvelope {
    // Default: 1 CPU second, 100MB memory, 5 seconds wall time, 10MB I/O
    BudgetEnvelope::try_new(
        1_000_000,   // 1.0 CPU second
        100_000_000, // 100.0 MB memory
        5_000_000,   // 5.0 seconds wall time
        10_000_000,  // 10.0 MB I/O
    ).expect("default budget values should be valid")
}

/// Create a minimal budget envelope with low resource limits.
pub fn minimal_budget_envelope() -> BudgetEnvelope {
    BudgetEnvelope::try_new(
        100_000,   // 0.1 CPU second
        1_000_000, // 1.0 MB memory
        500_000,   // 0.5 seconds wall time
        500_000,   // 0.5 MB I/O
    ).expect("minimal budget values should be valid")
}

// ---------------------------------------------------------------------------
// Unified authority operations bridging existing APIs
// ---------------------------------------------------------------------------

/// Unified authority subsumption check that replaces separate axis operations.
///
/// This replaces patterns like:
/// ```ignore
/// label_a.level() >= label_b.level() &&
/// cap_profile_a.subsumes(&cap_profile_b) &&
/// budget_a.dominates(&budget_b)
/// ```
pub fn unified_subsumes(
    auth_a: &AuthorityLattice,
    auth_b: &AuthorityLattice,
) -> bool {
    auth_a.subsumes(auth_b)
}

/// Unified authority join that replaces separate axis join operations.
///
/// This replaces patterns like:
/// ```ignore
/// let joined_label = label_a.join(&label_b);
/// let joined_caps = cap_a.union(&cap_b);
/// let joined_budget = budget_a.max(&budget_b);
/// ```
pub fn unified_join(
    auth_a: &AuthorityLattice,
    auth_b: &AuthorityLattice,
) -> AuthorityLattice {
    auth_a.join(auth_b)
}

/// Unified authority meet that replaces separate axis meet operations.
///
/// This replaces patterns like:
/// ```ignore
/// let met_label = label_a.meet(&label_b);
/// let met_caps = cap_a.intersection(&cap_b);
/// let met_budget = budget_a.min(&budget_b);
/// ```
pub fn unified_meet(
    auth_a: &AuthorityLattice,
    auth_b: &AuthorityLattice,
) -> AuthorityLattice {
    auth_a.meet(auth_b)
}

/// Create unified authority from separate components.
pub fn create_unified_authority(
    ifc_label: LabelClass,
    capability_profile: &CapabilityProfile,
    budget: Option<BudgetEnvelope>,
) -> AuthorityLattice {
    let unified_caps = profile_to_unified_capset(capability_profile);
    let budget_envelope = budget.unwrap_or_else(default_budget_envelope);

    AuthorityLattice::new(ifc_label, unified_caps, budget_envelope)
}

/// Extract IFC label from unified authority (for backward compatibility).
pub fn extract_ifc_label(auth: &AuthorityLattice) -> LabelClass {
    auth.ifc_label
}

/// Check if unified authority has a specific capability (for backward compatibility).
pub fn has_capability(auth: &AuthorityLattice, cap: CapabilityKind) -> bool {
    auth.capability_set.contains(&cap)
}

/// Get budget values from unified authority (for backward compatibility).
pub fn extract_budget(auth: &AuthorityLattice) -> &BudgetEnvelope {
    &auth.budget_envelope
}

// ---------------------------------------------------------------------------
// Combined-axis operations (new functionality enabled by unified API)
// ---------------------------------------------------------------------------

/// Check if an authority context can safely delegate to another context.
///
/// This is a combined-axis operation that ensures delegation safety across
/// all three dimensions: IFC, capabilities, and resource budget.
pub fn safe_delegation(
    delegator: &AuthorityLattice,
    delegatee: &AuthorityLattice,
) -> bool {
    // Delegator must subsume delegatee on all axes
    delegator.subsumes(delegatee)
}

/// Compute minimum authority required for a set of operations.
///
/// This combines requirements across all three axes into a unified authority
/// that can satisfy all the given operations.
pub fn minimum_authority_for_operations(
    required_label: LabelClass,
    required_capabilities: &[CapabilityKind],
    required_cpu_millionths: i64,
    required_memory_millionths: i64,
    required_wall_time_millionths: i64,
    required_io_millionths: i64,
) -> Result<AuthorityLattice, AuthorityLatticeError> {
    let cap_set = CapabilitySet::from_iter(required_capabilities.iter().copied());
    let budget = BudgetEnvelope::try_new(
        required_cpu_millionths,
        required_memory_millionths,
        required_wall_time_millionths,
        required_io_millionths,
    )?;

    Ok(AuthorityLattice::new(required_label, cap_set, budget))
}

/// Authority narrowing: compute intersection of multiple authority contexts.
///
/// This is useful for computing the effective authority when multiple
/// constraints need to be satisfied simultaneously.
pub fn narrow_authority(authorities: &[AuthorityLattice]) -> Option<AuthorityLattice> {
    authorities.iter().copied().reduce(|acc, auth| acc.meet(&auth))
}

/// Authority widening: compute union of multiple authority contexts.
///
/// This is useful for computing the maximum authority when any of several
/// contexts could be active.
pub fn widen_authority(authorities: &[AuthorityLattice]) -> Option<AuthorityLattice> {
    authorities.iter().copied().reduce(|acc, auth| acc.join(&auth))
}

// ---------------------------------------------------------------------------
// Conversion functions for test compatibility
// ---------------------------------------------------------------------------

/// Convert unified authority back to separate components for legacy tests.
pub fn unified_to_separate_components(
    auth: &AuthorityLattice,
) -> (LabelClass, CapabilitySet, BudgetEnvelope) {
    (auth.ifc_label, auth.capability_set.clone(), auth.budget_envelope)
}

/// Create a test authority with specific characteristics.
pub fn test_authority(
    label: LabelClass,
    caps: &[CapabilityKind],
    cpu: i64,
    memory: i64,
    wall_time: i64,
    io: i64,
) -> AuthorityLattice {
    let cap_set = CapabilitySet::from_iter(caps.iter().copied());
    let budget = BudgetEnvelope::try_new(cpu, memory, wall_time, io)
        .expect("test budget values should be valid");
    AuthorityLattice::new(label, cap_set, budget)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Test utility
    fn test_capability_profile() -> CapabilityProfile {
        CapabilityProfile::engine_core()
    }

    #[test]
    fn runtime_cap_to_unified_mapping() {
        assert_eq!(
            runtime_cap_to_unified(RuntimeCapability::FsRead),
            Some(CapabilityKind::FsRead)
        );
        assert_eq!(
            runtime_cap_to_unified(RuntimeCapability::NetworkEgress),
            Some(CapabilityKind::NetConnect)
        );
        assert_eq!(
            runtime_cap_to_unified(RuntimeCapability::PolicyRead),
            Some(CapabilityKind::PolicyRequest)
        );
        // Should handle unmappable capabilities
        assert_eq!(
            runtime_cap_to_unified(RuntimeCapability::VmDispatch),
            None
        );
    }

    #[test]
    fn profile_to_unified_capset_conversion() {
        let profile = test_capability_profile();
        let unified = profile_to_unified_capset(&profile);

        // Should convert mappable capabilities
        assert!(!unified.is_empty());

        // Should have consistent size relationship (may be smaller due to unmappable caps)
        assert!(unified.len() <= profile.len());
    }

    #[test]
    fn default_budget_envelope_valid() {
        let budget = default_budget_envelope();
        assert!(budget.cpu_millionths > 0);
        assert!(budget.memory_millionths > 0);
        assert!(budget.wall_time_millionths > 0);
        assert!(budget.io_millionths > 0);
    }

    #[test]
    fn unified_subsumes_replaces_separate_checks() {
        let auth_a = test_authority(
            LabelClass::Secret,
            &[CapabilityKind::FsRead, CapabilityKind::FsWrite],
            2_000_000, 200_000_000, 10_000_000, 20_000_000
        );

        let auth_b = test_authority(
            LabelClass::Internal,
            &[CapabilityKind::FsRead],
            1_000_000, 100_000_000, 5_000_000, 10_000_000
        );

        // auth_a should subsume auth_b
        assert!(unified_subsumes(&auth_a, &auth_b));

        // auth_b should not subsume auth_a
        assert!(!unified_subsumes(&auth_b, &auth_a));
    }

    #[test]
    fn unified_join_combines_all_axes() {
        let auth_a = test_authority(
            LabelClass::Internal,
            &[CapabilityKind::FsRead],
            1_000_000, 100_000_000, 5_000_000, 10_000_000
        );

        let auth_b = test_authority(
            LabelClass::Secret,
            &[CapabilityKind::FsWrite],
            2_000_000, 50_000_000, 3_000_000, 20_000_000
        );

        let joined = unified_join(&auth_a, &auth_b);

        // Should take maximum IFC label
        assert_eq!(joined.ifc_label, LabelClass::Secret);

        // Should union capabilities
        assert!(joined.capability_set.contains(&CapabilityKind::FsRead));
        assert!(joined.capability_set.contains(&CapabilityKind::FsWrite));

        // Should take maximum budget values
        assert_eq!(joined.budget_envelope.cpu_millionths, 2_000_000);
        assert_eq!(joined.budget_envelope.memory_millionths, 100_000_000);
        assert_eq!(joined.budget_envelope.wall_time_millionths, 5_000_000);
        assert_eq!(joined.budget_envelope.io_millionths, 20_000_000);
    }

    #[test]
    fn unified_meet_intersects_all_axes() {
        let auth_a = test_authority(
            LabelClass::Secret,
            &[CapabilityKind::FsRead, CapabilityKind::FsWrite],
            2_000_000, 200_000_000, 10_000_000, 30_000_000
        );

        let auth_b = test_authority(
            LabelClass::Confidential,
            &[CapabilityKind::FsRead, CapabilityKind::NetConnect],
            1_000_000, 150_000_000, 7_000_000, 20_000_000
        );

        let met = unified_meet(&auth_a, &auth_b);

        // Should take minimum IFC label
        assert_eq!(met.ifc_label, LabelClass::Confidential);

        // Should intersect capabilities
        assert!(met.capability_set.contains(&CapabilityKind::FsRead));
        assert!(!met.capability_set.contains(&CapabilityKind::FsWrite));
        assert!(!met.capability_set.contains(&CapabilityKind::NetConnect));

        // Should take minimum budget values
        assert_eq!(met.budget_envelope.cpu_millionths, 1_000_000);
        assert_eq!(met.budget_envelope.memory_millionths, 150_000_000);
        assert_eq!(met.budget_envelope.wall_time_millionths, 7_000_000);
        assert_eq!(met.budget_envelope.io_millionths, 20_000_000);
    }

    #[test]
    fn create_unified_authority_from_components() {
        let profile = test_capability_profile();
        let auth = create_unified_authority(
            LabelClass::Confidential,
            &profile,
            None // Use default budget
        );

        assert_eq!(auth.ifc_label, LabelClass::Confidential);
        assert!(!auth.capability_set.is_empty());
        assert!(auth.budget_envelope.cpu_millionths > 0);
    }

    #[test]
    fn safe_delegation_enforces_all_axes() {
        let delegator = test_authority(
            LabelClass::Secret,
            &[CapabilityKind::FsRead, CapabilityKind::FsWrite],
            2_000_000, 200_000_000, 10_000_000, 20_000_000
        );

        let safe_delegatee = test_authority(
            LabelClass::Internal,
            &[CapabilityKind::FsRead],
            1_000_000, 100_000_000, 5_000_000, 10_000_000
        );

        let unsafe_delegatee = test_authority(
            LabelClass::TopSecret, // Higher IFC level - unsafe!
            &[CapabilityKind::FsRead],
            1_000_000, 100_000_000, 5_000_000, 10_000_000
        );

        assert!(safe_delegation(&delegator, &safe_delegatee));
        assert!(!safe_delegation(&delegator, &unsafe_delegatee));
    }

    #[test]
    fn minimum_authority_for_operations_combines_requirements() {
        let auth = minimum_authority_for_operations(
            LabelClass::Internal,
            &[CapabilityKind::FsRead, CapabilityKind::NetConnect],
            500_000,   // 0.5 CPU seconds
            50_000_000, // 50 MB memory
            2_000_000,  // 2 seconds wall time
            5_000_000,  // 5 MB I/O
        ).expect("should create valid authority");

        assert_eq!(auth.ifc_label, LabelClass::Internal);
        assert_eq!(auth.capability_set.len(), 2);
        assert!(auth.capability_set.contains(&CapabilityKind::FsRead));
        assert!(auth.capability_set.contains(&CapabilityKind::NetConnect));
        assert_eq!(auth.budget_envelope.cpu_millionths, 500_000);
    }

    #[test]
    fn narrow_authority_computes_intersection() {
        let auth1 = test_authority(
            LabelClass::Secret,
            &[CapabilityKind::FsRead, CapabilityKind::FsWrite],
            2_000_000, 200_000_000, 10_000_000, 20_000_000
        );

        let auth2 = test_authority(
            LabelClass::Internal,
            &[CapabilityKind::FsRead, CapabilityKind::NetConnect],
            1_000_000, 150_000_000, 5_000_000, 15_000_000
        );

        let narrowed = narrow_authority(&[auth1, auth2]).expect("should narrow");

        // Should be intersection of both
        assert_eq!(narrowed.ifc_label, LabelClass::Internal); // min
        assert_eq!(narrowed.capability_set.len(), 1); // intersection
        assert!(narrowed.capability_set.contains(&CapabilityKind::FsRead));
        assert_eq!(narrowed.budget_envelope.cpu_millionths, 1_000_000); // min
    }

    #[test]
    fn widen_authority_computes_union() {
        let auth1 = test_authority(
            LabelClass::Internal,
            &[CapabilityKind::FsRead],
            1_000_000, 100_000_000, 5_000_000, 10_000_000
        );

        let auth2 = test_authority(
            LabelClass::Secret,
            &[CapabilityKind::NetConnect],
            2_000_000, 150_000_000, 7_000_000, 15_000_000
        );

        let widened = widen_authority(&[auth1, auth2]).expect("should widen");

        // Should be union of both
        assert_eq!(widened.ifc_label, LabelClass::Secret); // max
        assert_eq!(widened.capability_set.len(), 2); // union
        assert!(widened.capability_set.contains(&CapabilityKind::FsRead));
        assert!(widened.capability_set.contains(&CapabilityKind::NetConnect));
        assert_eq!(widened.budget_envelope.cpu_millionths, 2_000_000); // max
    }

    #[test]
    fn backward_compatibility_extraction() {
        let auth = test_authority(
            LabelClass::Confidential,
            &[CapabilityKind::FsRead],
            1_000_000, 100_000_000, 5_000_000, 10_000_000
        );

        // Should be able to extract individual components
        assert_eq!(extract_ifc_label(&auth), LabelClass::Confidential);
        assert!(has_capability(&auth, CapabilityKind::FsRead));
        assert!(!has_capability(&auth, CapabilityKind::FsWrite));

        let budget = extract_budget(&auth);
        assert_eq!(budget.cpu_millionths, 1_000_000);

        // Should be able to convert back to separate components
        let (label, caps, budget_env) = unified_to_separate_components(&auth);
        assert_eq!(label, LabelClass::Confidential);
        assert_eq!(caps.len(), 1);
        assert_eq!(budget_env.cpu_millionths, 1_000_000);
    }
}