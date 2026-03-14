#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::capability::{
    CapabilityDenied, CapabilityProfile, ProfileKind, RuntimeCapability, require_all,
    require_capability,
};

// =========================================================================
// A. BTreeSet ordering and dedup for RuntimeCapability
// =========================================================================

#[test]
fn enrichment_runtime_capability_btreeset_ordering_dedup() {
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
    let mut set = BTreeSet::new();
    for cap in &all {
        set.insert(*cap);
    }
    // Insert duplicates
    set.insert(RuntimeCapability::VmDispatch);
    set.insert(RuntimeCapability::FsWrite);
    assert_eq!(set.len(), 16);
    let ordered: Vec<_> = set.into_iter().collect();
    for i in 1..ordered.len() {
        assert!(ordered[i - 1] < ordered[i]);
    }
}

#[test]
fn enrichment_profile_kind_btreeset_ordering_dedup() {
    let mut set = BTreeSet::new();
    set.insert(ProfileKind::Full);
    set.insert(ProfileKind::EngineCore);
    set.insert(ProfileKind::Policy);
    set.insert(ProfileKind::Remote);
    set.insert(ProfileKind::ComputeOnly);
    set.insert(ProfileKind::Full); // duplicate
    assert_eq!(set.len(), 5);
    let ordered: Vec<_> = set.into_iter().collect();
    for i in 1..ordered.len() {
        assert!(ordered[i - 1] < ordered[i]);
    }
}

// =========================================================================
// B. Hash consistency
// =========================================================================

#[test]
fn enrichment_runtime_capability_hash_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
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
        let mut h1 = DefaultHasher::new();
        cap.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        cap.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }
}

#[test]
fn enrichment_profile_kind_hash_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let kinds = [
        ProfileKind::Full,
        ProfileKind::EngineCore,
        ProfileKind::Policy,
        ProfileKind::Remote,
        ProfileKind::ComputeOnly,
    ];
    for kind in &kinds {
        let mut h1 = DefaultHasher::new();
        kind.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        kind.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }
}

// =========================================================================
// C. Display values distinct
// =========================================================================

#[test]
fn enrichment_runtime_capability_display_all_distinct() {
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
    let displays: BTreeSet<String> = all.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), 16);
}

#[test]
fn enrichment_profile_kind_display_all_distinct() {
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
    assert_eq!(displays.len(), 5);
}

// =========================================================================
// D. Debug nonempty
// =========================================================================

#[test]
fn enrichment_debug_nonempty_all_types() {
    // RuntimeCapability
    assert!(!format!("{:?}", RuntimeCapability::VmDispatch).is_empty());
    assert!(!format!("{:?}", RuntimeCapability::FsWrite).is_empty());

    // ProfileKind
    assert!(!format!("{:?}", ProfileKind::Full).is_empty());
    assert!(!format!("{:?}", ProfileKind::ComputeOnly).is_empty());

    // CapabilityProfile
    let full = CapabilityProfile::full();
    assert!(!format!("{full:?}").is_empty());
    let co = CapabilityProfile::compute_only();
    assert!(!format!("{co:?}").is_empty());

    // CapabilityDenied
    let denied = CapabilityDenied {
        required: RuntimeCapability::NetworkEgress,
        held_profile: ProfileKind::EngineCore,
        component: "test".to_string(),
    };
    assert!(!format!("{denied:?}").is_empty());
}

// =========================================================================
// E. Clone independence
// =========================================================================

#[test]
fn enrichment_clone_independence_capability_profile() {
    let original = CapabilityProfile::engine_core();
    let mut cloned = original.clone();
    cloned.capabilities.insert(RuntimeCapability::NetworkEgress);
    // Original should be unaffected
    assert!(!original.has(RuntimeCapability::NetworkEgress));
    assert!(cloned.has(RuntimeCapability::NetworkEgress));
}

#[test]
fn enrichment_clone_independence_capability_denied() {
    let original = CapabilityDenied {
        required: RuntimeCapability::VmDispatch,
        held_profile: ProfileKind::ComputeOnly,
        component: "original".to_string(),
    };
    let mut cloned = original.clone();
    cloned.component = "modified".to_string();
    assert_eq!(original.component, "original");
}

// =========================================================================
// F. Copy semantics for enums
// =========================================================================

#[test]
fn enrichment_copy_semantics_runtime_capability() {
    let a = RuntimeCapability::LeaseManagement;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_copy_semantics_profile_kind() {
    let a = ProfileKind::Policy;
    let b = a;
    assert_eq!(a, b);
}

// =========================================================================
// G. Serde roundtrips for CapabilityDenied
// =========================================================================

#[test]
fn enrichment_capability_denied_serde_all_profile_kinds() {
    let kinds = [
        ProfileKind::Full,
        ProfileKind::EngineCore,
        ProfileKind::Policy,
        ProfileKind::Remote,
        ProfileKind::ComputeOnly,
    ];
    for kind in &kinds {
        let denied = CapabilityDenied {
            required: RuntimeCapability::VmDispatch,
            held_profile: *kind,
            component: "test".to_string(),
        };
        let json = serde_json::to_string(&denied).unwrap();
        let back: CapabilityDenied = serde_json::from_str(&json).unwrap();
        assert_eq!(denied, back);
    }
}

// =========================================================================
// H. Profile capability disjointness exhaustive
// =========================================================================

#[test]
fn enrichment_engine_core_and_remote_are_disjoint() {
    let ec = CapabilityProfile::engine_core();
    let rem = CapabilityProfile::remote();
    let inter = ec.intersect(&rem);
    assert!(inter.is_empty());
}

#[test]
fn enrichment_policy_and_remote_are_disjoint() {
    let pol = CapabilityProfile::policy();
    let rem = CapabilityProfile::remote();
    let inter = pol.intersect(&rem);
    assert!(inter.is_empty());
}

#[test]
fn enrichment_engine_core_and_policy_are_disjoint() {
    let ec = CapabilityProfile::engine_core();
    let pol = CapabilityProfile::policy();
    let inter = ec.intersect(&pol);
    assert!(inter.is_empty());
}

// =========================================================================
// I. Full profile covers all three partitions
// =========================================================================

#[test]
fn enrichment_full_covers_engine_core_policy_remote() {
    let full = CapabilityProfile::full();
    let ec = CapabilityProfile::engine_core();
    let pol = CapabilityProfile::policy();
    let rem = CapabilityProfile::remote();
    for cap in &ec.capabilities {
        assert!(full.has(*cap), "full missing engine_core cap {cap}");
    }
    for cap in &pol.capabilities {
        assert!(full.has(*cap), "full missing policy cap {cap}");
    }
    for cap in &rem.capabilities {
        assert!(full.has(*cap), "full missing remote cap {cap}");
    }
}

#[test]
fn enrichment_full_has_extra_caps_beyond_partitions() {
    let ec = CapabilityProfile::engine_core();
    let pol = CapabilityProfile::policy();
    let rem = CapabilityProfile::remote();
    let full = CapabilityProfile::full();
    let mut combined = BTreeSet::new();
    combined.extend(&ec.capabilities);
    combined.extend(&pol.capabilities);
    combined.extend(&rem.capabilities);
    // Full has capabilities not in any partition (EnvRead, ProcessSpawn, FsRead, FsWrite, ExtensionLifecycle)
    assert!(full.len() > combined.len());
    let extras: BTreeSet<_> = full.capabilities.difference(&combined).copied().collect();
    assert!(extras.contains(&RuntimeCapability::EnvRead));
    assert!(extras.contains(&RuntimeCapability::ProcessSpawn));
    assert!(extras.contains(&RuntimeCapability::FsRead));
    assert!(extras.contains(&RuntimeCapability::FsWrite));
    assert!(extras.contains(&RuntimeCapability::ExtensionLifecycle));
}

// =========================================================================
// J. require_all reports exact missing capabilities
// =========================================================================

#[test]
fn enrichment_require_all_partial_missing() {
    // EngineCore has VmDispatch but not PolicyWrite
    let ec = CapabilityProfile::engine_core();
    let denials = require_all(
        &ec,
        &[
            RuntimeCapability::VmDispatch,
            RuntimeCapability::PolicyWrite,
        ],
        "test",
    )
    .unwrap_err();
    assert_eq!(denials.len(), 1);
    assert_eq!(denials[0].required, RuntimeCapability::PolicyWrite);
}

#[test]
fn enrichment_require_all_all_missing_from_compute_only() {
    let co = CapabilityProfile::compute_only();
    let all_caps = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::GcInvoke,
        RuntimeCapability::IrLowering,
        RuntimeCapability::PolicyRead,
    ];
    let denials = require_all(&co, &all_caps, "test").unwrap_err();
    assert_eq!(denials.len(), 4);
}

// =========================================================================
// K. CapabilityProfile Display format
// =========================================================================

#[test]
fn enrichment_all_profiles_display_format() {
    let profiles = [
        (CapabilityProfile::full(), "FullCaps[16]"),
        (CapabilityProfile::engine_core(), "EngineCoreCaps[4]"),
        (CapabilityProfile::policy(), "PolicyCaps[4]"),
        (CapabilityProfile::remote(), "RemoteCaps[3]"),
        (CapabilityProfile::compute_only(), "ComputeOnlyCaps[0]"),
    ];
    for (profile, expected) in &profiles {
        assert_eq!(profile.to_string(), *expected);
    }
}

// =========================================================================
// L. Intersection associativity
// =========================================================================

#[test]
fn enrichment_intersection_associative() {
    let a = CapabilityProfile::full();
    let b = CapabilityProfile::engine_core();
    let c = CapabilityProfile::policy();
    let ab_c = a.intersect(&b).intersect(&c);
    let a_bc = a.intersect(&b.intersect(&c));
    assert_eq!(ab_c.capabilities, a_bc.capabilities);
}

// =========================================================================
// M. Error trait for CapabilityDenied
// =========================================================================

#[test]
fn enrichment_capability_denied_error_trait() {
    let denied = CapabilityDenied {
        required: RuntimeCapability::FsWrite,
        held_profile: ProfileKind::Remote,
        component: "fs-writer".to_string(),
    };
    let err: &dyn std::error::Error = &denied;
    let display = err.to_string();
    assert!(display.contains("fs_write"));
    assert!(display.contains("RemoteCaps"));
    assert!(display.contains("fs-writer"));
    assert!(err.source().is_none());
}

// =========================================================================
// N. require_capability for each profile boundary
// =========================================================================

#[test]
fn enrichment_require_capability_boundary_per_profile() {
    // Engine core: has VmDispatch, not NetworkEgress
    assert!(
        require_capability(
            &CapabilityProfile::engine_core(),
            RuntimeCapability::VmDispatch,
            "t"
        )
        .is_ok()
    );
    assert!(
        require_capability(
            &CapabilityProfile::engine_core(),
            RuntimeCapability::NetworkEgress,
            "t"
        )
        .is_err()
    );

    // Policy: has PolicyRead, not VmDispatch
    assert!(
        require_capability(
            &CapabilityProfile::policy(),
            RuntimeCapability::PolicyRead,
            "t"
        )
        .is_ok()
    );
    assert!(
        require_capability(
            &CapabilityProfile::policy(),
            RuntimeCapability::VmDispatch,
            "t"
        )
        .is_err()
    );

    // Remote: has NetworkEgress, not PolicyWrite
    assert!(
        require_capability(
            &CapabilityProfile::remote(),
            RuntimeCapability::NetworkEgress,
            "t"
        )
        .is_ok()
    );
    assert!(
        require_capability(
            &CapabilityProfile::remote(),
            RuntimeCapability::PolicyWrite,
            "t"
        )
        .is_err()
    );

    // ComputeOnly: has nothing
    assert!(
        require_capability(
            &CapabilityProfile::compute_only(),
            RuntimeCapability::VmDispatch,
            "t"
        )
        .is_err()
    );
}

// =========================================================================
// O. Serde roundtrips for all profiles
// =========================================================================

#[test]
fn enrichment_all_profiles_serde_roundtrip() {
    let profiles = [
        CapabilityProfile::full(),
        CapabilityProfile::engine_core(),
        CapabilityProfile::policy(),
        CapabilityProfile::remote(),
        CapabilityProfile::compute_only(),
    ];
    for profile in &profiles {
        let json = serde_json::to_string(profile).unwrap();
        let back: CapabilityProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(*profile, back);
    }
}

// =========================================================================
// P. Subsumption reflexivity and asymmetry
// =========================================================================

#[test]
fn enrichment_subsumption_reflexive_all_profiles() {
    let profiles = [
        CapabilityProfile::full(),
        CapabilityProfile::engine_core(),
        CapabilityProfile::policy(),
        CapabilityProfile::remote(),
        CapabilityProfile::compute_only(),
    ];
    for profile in &profiles {
        assert!(
            profile.subsumes(profile),
            "{} should subsume itself",
            profile.kind
        );
    }
}

#[test]
fn enrichment_subsumption_asymmetric_full_vs_others() {
    let full = CapabilityProfile::full();
    let others = [
        CapabilityProfile::engine_core(),
        CapabilityProfile::policy(),
        CapabilityProfile::remote(),
    ];
    for other in &others {
        assert!(full.subsumes(other));
        assert!(!other.subsumes(&full));
    }
}

// ===== PearlTower enrichment =====

// =========================================================================
// Q. Serde roundtrip for CapabilityProfile — modified custom profile
// =========================================================================

#[test]
fn enrichment_capability_profile_serde_roundtrip_custom() {
    // Build a custom profile by starting from engine_core and inserting extra caps.
    let mut profile = CapabilityProfile::engine_core();
    profile.capabilities.insert(RuntimeCapability::EvidenceEmit);
    profile.capabilities.insert(RuntimeCapability::PolicyRead);
    let json = serde_json::to_string(&profile).unwrap();
    let back: CapabilityProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(profile, back);
    assert_eq!(back.capabilities.len(), 6);
    assert!(back.capabilities.contains(&RuntimeCapability::EvidenceEmit));
    assert!(back.capabilities.contains(&RuntimeCapability::PolicyRead));
}

#[test]
fn enrichment_runtime_capability_serde_roundtrip_all_variants() {
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
        let json = serde_json::to_string(cap).unwrap();
        let back: RuntimeCapability = serde_json::from_str(&json).unwrap();
        assert_eq!(*cap, back, "serde roundtrip failed for {cap:?}");
    }
}

// =========================================================================
// R. ProfileKind exhaustive serde roundtrip
// =========================================================================

#[test]
fn enrichment_profile_kind_serde_roundtrip_all_variants() {
    let all = [
        ProfileKind::Full,
        ProfileKind::EngineCore,
        ProfileKind::Policy,
        ProfileKind::Remote,
        ProfileKind::ComputeOnly,
    ];
    for kind in &all {
        let json = serde_json::to_string(kind).unwrap();
        let back: ProfileKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back, "serde roundtrip failed for {kind:?}");
        // Ensure the JSON is a non-empty string.
        assert!(json.len() > 2);
    }
}

// =========================================================================
// S. RuntimeCapability set operations — union simulation using BTreeSet
// =========================================================================

#[test]
fn enrichment_btreeset_union_engine_core_and_policy() {
    let ec = CapabilityProfile::engine_core();
    let pol = CapabilityProfile::policy();
    let union: BTreeSet<RuntimeCapability> =
        ec.capabilities.union(&pol.capabilities).copied().collect();
    assert_eq!(union.len(), 8);
    assert!(union.contains(&RuntimeCapability::VmDispatch));
    assert!(union.contains(&RuntimeCapability::GcInvoke));
    assert!(union.contains(&RuntimeCapability::IrLowering));
    assert!(union.contains(&RuntimeCapability::HeapAllocate));
    assert!(union.contains(&RuntimeCapability::PolicyRead));
    assert!(union.contains(&RuntimeCapability::PolicyWrite));
    assert!(union.contains(&RuntimeCapability::EvidenceEmit));
    assert!(union.contains(&RuntimeCapability::DecisionInvoke));
}

#[test]
fn enrichment_btreeset_intersection_full_and_engine_core_equals_engine_core() {
    let full = CapabilityProfile::full();
    let ec = CapabilityProfile::engine_core();
    let inter: BTreeSet<RuntimeCapability> = full
        .capabilities
        .intersection(&ec.capabilities)
        .copied()
        .collect();
    assert_eq!(inter, ec.capabilities);
}

#[test]
fn enrichment_btreeset_subset_all_partitions_within_full() {
    let full = CapabilityProfile::full();
    let partitions = [
        CapabilityProfile::engine_core(),
        CapabilityProfile::policy(),
        CapabilityProfile::remote(),
        CapabilityProfile::compute_only(),
    ];
    for partition in &partitions {
        assert!(
            partition.capabilities.is_subset(&full.capabilities),
            "{:?} capabilities are not a subset of full",
            partition.kind
        );
    }
}

// =========================================================================
// T. Edge cases — empty and maximum capability profiles
// =========================================================================

#[test]
fn enrichment_edge_case_empty_profile_compute_only() {
    let co = CapabilityProfile::compute_only();
    assert!(co.is_empty());
    assert_eq!(co.len(), 0);
    // Subsumes nothing except itself and other empty profiles.
    assert!(co.subsumes(&co));
    // require_capability always fails on empty.
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
            require_capability(&co, *cap, "edge-empty").is_err(),
            "compute_only should not grant {cap}"
        );
    }
}

#[test]
fn enrichment_edge_case_full_profile_grants_all_capabilities() {
    let full = CapabilityProfile::full();
    assert!(!full.is_empty());
    assert_eq!(full.len(), 16);
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
            require_capability(&full, *cap, "edge-full").is_ok(),
            "full should grant {cap}"
        );
    }
}

// =========================================================================
// U. SecurityEpoch interaction — epoch-tagged capability decisions
// =========================================================================

#[test]
fn enrichment_security_epoch_genesis_and_advance() {
    use frankenengine_engine::security_epoch::SecurityEpoch;
    let e0 = SecurityEpoch::GENESIS;
    assert_eq!(e0.as_u64(), 0);
    let e1 = e0.next();
    assert_eq!(e1.as_u64(), 1);
    let e2 = e1.next();
    assert!(e2 > e1 && e1 > e0);
}

#[test]
fn enrichment_security_epoch_with_capability_profile_serde() {
    use frankenengine_engine::security_epoch::SecurityEpoch;
    // Simulate an epoch-tagged capability grant record.
    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct EpochGrant {
        epoch: SecurityEpoch,
        profile: CapabilityProfile,
    }
    let grant = EpochGrant {
        epoch: SecurityEpoch::from_raw(42),
        profile: CapabilityProfile::engine_core(),
    };
    let json = serde_json::to_string(&grant).unwrap();
    let back: EpochGrant = serde_json::from_str(&json).unwrap();
    assert_eq!(grant, back);
    assert_eq!(back.epoch.as_u64(), 42);
    assert_eq!(back.profile.kind, ProfileKind::EngineCore);
}

#[test]
fn enrichment_security_epoch_ordering_with_capability_decisions() {
    use frankenengine_engine::security_epoch::SecurityEpoch;
    // Capability decisions made at different epochs should respect epoch ordering.
    let epochs: Vec<SecurityEpoch> = (0u64..5).map(SecurityEpoch::from_raw).collect();
    for i in 1..epochs.len() {
        assert!(epochs[i] > epochs[i - 1]);
    }
    // A profile at a later epoch should still hold its capabilities.
    let profile = CapabilityProfile::policy();
    let latest_epoch = epochs[4];
    assert_eq!(latest_epoch.as_u64(), 4);
    assert!(profile.has(RuntimeCapability::PolicyRead));
    assert!(profile.has(RuntimeCapability::PolicyWrite));
}

// =========================================================================
// V. Clone and Debug derive verification
// =========================================================================

#[test]
fn enrichment_clone_debug_capability_profile_all_variants() {
    let profiles = [
        CapabilityProfile::full(),
        CapabilityProfile::engine_core(),
        CapabilityProfile::policy(),
        CapabilityProfile::remote(),
        CapabilityProfile::compute_only(),
    ];
    for profile in &profiles {
        let cloned = profile.clone();
        assert_eq!(*profile, cloned);
        let debug_str = format!("{profile:?}");
        assert!(!debug_str.is_empty());
        assert!(debug_str.contains("CapabilityProfile"));
    }
}

#[test]
fn enrichment_clone_debug_runtime_capability_all_variants() {
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
        let cloned = *cap; // Copy
        assert_eq!(*cap, cloned);
        let debug_str = format!("{cap:?}");
        assert!(!debug_str.is_empty());
    }
}

#[test]
fn enrichment_clone_debug_profile_kind_all_variants() {
    let all = [
        ProfileKind::Full,
        ProfileKind::EngineCore,
        ProfileKind::Policy,
        ProfileKind::Remote,
        ProfileKind::ComputeOnly,
    ];
    for kind in &all {
        let cloned = *kind; // Copy
        assert_eq!(*kind, cloned);
        let debug_str = format!("{kind:?}");
        assert!(!debug_str.is_empty());
    }
}

#[test]
fn enrichment_clone_debug_capability_denied_all_capabilities() {
    let all_caps = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::GcInvoke,
        RuntimeCapability::IrLowering,
        RuntimeCapability::PolicyRead,
        RuntimeCapability::PolicyWrite,
        RuntimeCapability::EvidenceEmit,
        RuntimeCapability::DecisionInvoke,
        RuntimeCapability::NetworkEgress,
    ];
    for cap in &all_caps {
        let denied = CapabilityDenied {
            required: *cap,
            held_profile: ProfileKind::ComputeOnly,
            component: format!("component-{cap}"),
        };
        let cloned = denied.clone();
        assert_eq!(denied, cloned);
        let debug_str = format!("{denied:?}");
        assert!(!debug_str.is_empty());
        assert!(debug_str.contains("CapabilityDenied"));
    }
}
