//! Integration tests for the `capability` module.
//!
//! Tests runtime capability profiles, profile composition (intersect,
//! subsumption), capability enforcement, and serde roundtrips.

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
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::capability::{
    CapabilityDenied, CapabilityProfile, ProfileKind, RuntimeCapability, require_all,
    require_capability,
};

// ---------------------------------------------------------------------------
// RuntimeCapability display
// ---------------------------------------------------------------------------

#[test]
fn capability_display_all_variants() {
    assert_eq!(RuntimeCapability::VmDispatch.to_string(), "vm_dispatch");
    assert_eq!(RuntimeCapability::GcInvoke.to_string(), "gc_invoke");
    assert_eq!(RuntimeCapability::IrLowering.to_string(), "ir_lowering");
    assert_eq!(RuntimeCapability::PolicyRead.to_string(), "policy_read");
    assert_eq!(RuntimeCapability::PolicyWrite.to_string(), "policy_write");
    assert_eq!(RuntimeCapability::EvidenceEmit.to_string(), "evidence_emit");
    assert_eq!(
        RuntimeCapability::DecisionInvoke.to_string(),
        "decision_invoke"
    );
    assert_eq!(
        RuntimeCapability::NetworkEgress.to_string(),
        "network_egress"
    );
    assert_eq!(
        RuntimeCapability::LeaseManagement.to_string(),
        "lease_management"
    );
    assert_eq!(
        RuntimeCapability::IdempotencyDerive.to_string(),
        "idempotency_derive"
    );
    assert_eq!(
        RuntimeCapability::ExtensionLifecycle.to_string(),
        "extension_lifecycle"
    );
    assert_eq!(RuntimeCapability::HeapAllocate.to_string(), "heap_allocate");
    assert_eq!(RuntimeCapability::EnvRead.to_string(), "env_read");
    assert_eq!(RuntimeCapability::ProcessSpawn.to_string(), "process_spawn");
    assert_eq!(RuntimeCapability::FsRead.to_string(), "fs_read");
    assert_eq!(RuntimeCapability::FsWrite.to_string(), "fs_write");
}

// ---------------------------------------------------------------------------
// ProfileKind display
// ---------------------------------------------------------------------------

#[test]
fn profile_kind_display() {
    assert_eq!(ProfileKind::Full.to_string(), "FullCaps");
    assert_eq!(ProfileKind::EngineCore.to_string(), "EngineCoreCaps");
    assert_eq!(ProfileKind::Policy.to_string(), "PolicyCaps");
    assert_eq!(ProfileKind::Remote.to_string(), "RemoteCaps");
    assert_eq!(ProfileKind::ComputeOnly.to_string(), "ComputeOnlyCaps");
}

// ---------------------------------------------------------------------------
// Profile contents
// ---------------------------------------------------------------------------

#[test]
fn full_caps_contains_all() {
    let full = CapabilityProfile::full();
    assert_eq!(full.len(), 16);
    assert_eq!(full.kind, ProfileKind::Full);
    assert!(full.has(RuntimeCapability::VmDispatch));
    assert!(full.has(RuntimeCapability::PolicyWrite));
    assert!(full.has(RuntimeCapability::NetworkEgress));
    assert!(full.has(RuntimeCapability::FsWrite));
    assert!(full.has(RuntimeCapability::ExtensionLifecycle));
}

#[test]
fn engine_core_caps() {
    let ec = CapabilityProfile::engine_core();
    assert_eq!(ec.len(), 4);
    assert_eq!(ec.kind, ProfileKind::EngineCore);
    assert!(ec.has(RuntimeCapability::VmDispatch));
    assert!(ec.has(RuntimeCapability::GcInvoke));
    assert!(ec.has(RuntimeCapability::IrLowering));
    assert!(ec.has(RuntimeCapability::HeapAllocate));
    assert!(!ec.has(RuntimeCapability::PolicyWrite));
    assert!(!ec.has(RuntimeCapability::NetworkEgress));
}

#[test]
fn policy_caps() {
    let pol = CapabilityProfile::policy();
    assert_eq!(pol.len(), 4);
    assert_eq!(pol.kind, ProfileKind::Policy);
    assert!(pol.has(RuntimeCapability::PolicyRead));
    assert!(pol.has(RuntimeCapability::PolicyWrite));
    assert!(pol.has(RuntimeCapability::EvidenceEmit));
    assert!(pol.has(RuntimeCapability::DecisionInvoke));
    assert!(!pol.has(RuntimeCapability::VmDispatch));
}

#[test]
fn remote_caps() {
    let rem = CapabilityProfile::remote();
    assert_eq!(rem.len(), 3);
    assert_eq!(rem.kind, ProfileKind::Remote);
    assert!(rem.has(RuntimeCapability::NetworkEgress));
    assert!(rem.has(RuntimeCapability::LeaseManagement));
    assert!(rem.has(RuntimeCapability::IdempotencyDerive));
    assert!(!rem.has(RuntimeCapability::PolicyWrite));
}

#[test]
fn compute_only_caps() {
    let co = CapabilityProfile::compute_only();
    assert!(co.is_empty());
    assert_eq!(co.len(), 0);
    assert_eq!(co.kind, ProfileKind::ComputeOnly);
    assert!(!co.has(RuntimeCapability::VmDispatch));
}

// ---------------------------------------------------------------------------
// Profile display
// ---------------------------------------------------------------------------

#[test]
fn capability_profile_display() {
    assert_eq!(
        CapabilityProfile::engine_core().to_string(),
        "EngineCoreCaps[4]"
    );
    assert_eq!(CapabilityProfile::full().to_string(), "FullCaps[16]");
    assert_eq!(
        CapabilityProfile::compute_only().to_string(),
        "ComputeOnlyCaps[0]"
    );
}

// ---------------------------------------------------------------------------
// Subsumption
// ---------------------------------------------------------------------------

#[test]
fn full_subsumes_all_profiles() {
    let full = CapabilityProfile::full();
    assert!(full.subsumes(&CapabilityProfile::engine_core()));
    assert!(full.subsumes(&CapabilityProfile::policy()));
    assert!(full.subsumes(&CapabilityProfile::remote()));
    assert!(full.subsumes(&CapabilityProfile::compute_only()));
}

#[test]
fn narrow_does_not_subsume_broader() {
    assert!(!CapabilityProfile::engine_core().subsumes(&CapabilityProfile::full()));
    assert!(!CapabilityProfile::policy().subsumes(&CapabilityProfile::full()));
    assert!(!CapabilityProfile::remote().subsumes(&CapabilityProfile::full()));
}

#[test]
fn profile_subsumes_itself() {
    let ec = CapabilityProfile::engine_core();
    assert!(ec.subsumes(&ec));
}

// ---------------------------------------------------------------------------
// Intersection
// ---------------------------------------------------------------------------

#[test]
fn standard_profiles_pairwise_disjoint() {
    let ec = CapabilityProfile::engine_core();
    let pol = CapabilityProfile::policy();
    let rem = CapabilityProfile::remote();
    assert!(ec.intersect(&pol).is_empty());
    assert!(ec.intersect(&rem).is_empty());
    assert!(pol.intersect(&rem).is_empty());
}

#[test]
fn intersection_with_full_preserves_profile() {
    let full = CapabilityProfile::full();
    let ec = CapabilityProfile::engine_core();
    let inter = full.intersect(&ec);
    assert_eq!(inter.capabilities, ec.capabilities);
}

#[test]
fn intersection_produces_common_caps() {
    let mut custom = CapabilityProfile::engine_core();
    custom.capabilities.insert(RuntimeCapability::PolicyRead);
    let pol = CapabilityProfile::policy();
    let inter = custom.intersect(&pol);
    assert_eq!(inter.len(), 1);
    assert!(inter.has(RuntimeCapability::PolicyRead));
}

#[test]
fn intersection_result_is_compute_only_kind() {
    let full = CapabilityProfile::full();
    let ec = CapabilityProfile::engine_core();
    let inter = full.intersect(&ec);
    assert_eq!(inter.kind, ProfileKind::ComputeOnly);
}

// ---------------------------------------------------------------------------
// Capability enforcement
// ---------------------------------------------------------------------------

#[test]
fn require_capability_succeeds() {
    let ec = CapabilityProfile::engine_core();
    require_capability(&ec, RuntimeCapability::VmDispatch, "test").unwrap();
}

#[test]
fn require_capability_fails() {
    let ec = CapabilityProfile::engine_core();
    let err = require_capability(&ec, RuntimeCapability::NetworkEgress, "test-net").unwrap_err();
    assert_eq!(err.required, RuntimeCapability::NetworkEgress);
    assert_eq!(err.held_profile, ProfileKind::EngineCore);
    assert_eq!(err.component, "test-net");
}

#[test]
fn require_all_succeeds() {
    let full = CapabilityProfile::full();
    require_all(
        &full,
        &[
            RuntimeCapability::VmDispatch,
            RuntimeCapability::PolicyWrite,
        ],
        "test",
    )
    .unwrap();
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
        "test",
    )
    .unwrap_err();
    assert_eq!(denials.len(), 3);
}

#[test]
fn require_all_empty_succeeds() {
    let co = CapabilityProfile::compute_only();
    require_all(&co, &[], "test").unwrap();
}

// ---------------------------------------------------------------------------
// CapabilityDenied display
// ---------------------------------------------------------------------------

#[test]
fn capability_denied_display() {
    let err = CapabilityDenied {
        required: RuntimeCapability::NetworkEgress,
        held_profile: ProfileKind::EngineCore,
        component: "remote-sender".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("remote-sender"));
    assert!(s.contains("network_egress"));
    assert!(s.contains("EngineCoreCaps"));
}

#[test]
fn capability_denied_is_std_error() {
    let err = CapabilityDenied {
        required: RuntimeCapability::FsWrite,
        held_profile: ProfileKind::ComputeOnly,
        component: "test".to_string(),
    };
    let _: &dyn std::error::Error = &err;
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn runtime_capability_serde_roundtrip() {
    let caps = [
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
    for c in &caps {
        let json = serde_json::to_string(c).unwrap();
        let restored: RuntimeCapability = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, restored);
    }
}

#[test]
fn profile_kind_serde_roundtrip() {
    let kinds = [
        ProfileKind::Full,
        ProfileKind::EngineCore,
        ProfileKind::Policy,
        ProfileKind::Remote,
        ProfileKind::ComputeOnly,
    ];
    for k in &kinds {
        let json = serde_json::to_string(k).unwrap();
        let restored: ProfileKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, restored);
    }
}

#[test]
fn capability_profile_serde_roundtrip() {
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
        assert_eq!(*p, restored);
    }
}

#[test]
fn capability_denied_serde_roundtrip() {
    let denied = CapabilityDenied {
        required: RuntimeCapability::PolicyWrite,
        held_profile: ProfileKind::EngineCore,
        component: "test".to_string(),
    };
    let json = serde_json::to_string(&denied).unwrap();
    let restored: CapabilityDenied = serde_json::from_str(&json).unwrap();
    assert_eq!(denied, restored);
}

// ---------------------------------------------------------------------------
// Deterministic serialization
// ---------------------------------------------------------------------------

#[test]
fn deterministic_profile_serialization() {
    let profiles = [
        CapabilityProfile::full(),
        CapabilityProfile::engine_core(),
        CapabilityProfile::policy(),
        CapabilityProfile::remote(),
        CapabilityProfile::compute_only(),
    ];
    for p in &profiles {
        let j1 = serde_json::to_string(p).unwrap();
        let j2 = serde_json::to_string(p).unwrap();
        assert_eq!(j1, j2);
    }
}

#[test]
fn capability_profile_debug_is_nonempty() {
    for profile in [
        CapabilityProfile::full(),
        CapabilityProfile::engine_core(),
        CapabilityProfile::policy(),
        CapabilityProfile::remote(),
        CapabilityProfile::compute_only(),
    ] {
        assert!(!format!("{profile:?}").is_empty());
    }
}

#[test]
fn capability_profile_serialized_length_exceeds_minimum() {
    for profile in [
        CapabilityProfile::full(),
        CapabilityProfile::engine_core(),
        CapabilityProfile::policy(),
        CapabilityProfile::remote(),
        CapabilityProfile::compute_only(),
    ] {
        let json = serde_json::to_string(&profile).expect("serialize");
        assert!(
            json.len() > 20,
            "serialized profile should be >20 chars, got {}",
            json.len()
        );
    }
}

#[test]
fn require_all_empty_succeeds_for_all_profiles() {
    for profile in [
        CapabilityProfile::full(),
        CapabilityProfile::engine_core(),
        CapabilityProfile::policy(),
        CapabilityProfile::remote(),
        CapabilityProfile::compute_only(),
    ] {
        assert!(require_all(&profile, &[], "test-trace").is_ok());
    }
}

// ---------------------------------------------------------------------------
// Intersection symmetry and idempotence
// ---------------------------------------------------------------------------

#[test]
fn intersection_is_symmetric() {
    let ec = CapabilityProfile::engine_core();
    let full = CapabilityProfile::full();
    let a = ec.intersect(&full);
    let b = full.intersect(&ec);
    assert_eq!(a.capabilities, b.capabilities);
    assert_eq!(a.len(), b.len());
}

#[test]
fn intersection_with_self_preserves_capabilities() {
    let pol = CapabilityProfile::policy();
    let inter = pol.intersect(&pol);
    assert_eq!(inter.capabilities, pol.capabilities);
    assert_eq!(inter.len(), pol.len());
}

// ---------------------------------------------------------------------------
// require_all partial denial reports only missing caps
// ---------------------------------------------------------------------------

#[test]
fn require_all_partial_denial_reports_exact_missing_caps() {
    let ec = CapabilityProfile::engine_core();
    // VmDispatch is held, PolicyWrite and NetworkEgress are NOT held
    let denials = require_all(
        &ec,
        &[
            RuntimeCapability::VmDispatch,
            RuntimeCapability::PolicyWrite,
            RuntimeCapability::NetworkEgress,
        ],
        "partial-test",
    )
    .unwrap_err();
    assert_eq!(denials.len(), 2);
    assert!(
        denials
            .iter()
            .any(|d| d.required == RuntimeCapability::PolicyWrite)
    );
    assert!(
        denials
            .iter()
            .any(|d| d.required == RuntimeCapability::NetworkEgress)
    );
    assert!(denials.iter().all(|d| d.component == "partial-test"));
    assert!(
        denials
            .iter()
            .all(|d| d.held_profile == ProfileKind::EngineCore)
    );
}

// ---------------------------------------------------------------------------
// Clone equality
// ---------------------------------------------------------------------------

#[test]
fn capability_profile_clone_equals_original() {
    let profiles = [
        CapabilityProfile::full(),
        CapabilityProfile::engine_core(),
        CapabilityProfile::policy(),
        CapabilityProfile::remote(),
        CapabilityProfile::compute_only(),
    ];
    for p in &profiles {
        let cloned = p.clone();
        assert_eq!(*p, cloned);
        assert_eq!(p.kind, cloned.kind);
        assert_eq!(p.len(), cloned.len());
    }
}

// ---------------------------------------------------------------------------
// RuntimeCapability Ord ordering is deterministic
// ---------------------------------------------------------------------------

#[test]
fn runtime_capability_ord_is_deterministic() {
    use std::collections::BTreeSet;
    let caps = [
        RuntimeCapability::FsWrite,
        RuntimeCapability::VmDispatch,
        RuntimeCapability::NetworkEgress,
        RuntimeCapability::PolicyRead,
        RuntimeCapability::HeapAllocate,
    ];
    let set1: BTreeSet<RuntimeCapability> = caps.iter().copied().collect();
    let set2: BTreeSet<RuntimeCapability> = caps.iter().rev().copied().collect();
    let v1: Vec<RuntimeCapability> = set1.into_iter().collect();
    let v2: Vec<RuntimeCapability> = set2.into_iter().collect();
    assert_eq!(
        v1, v2,
        "BTreeSet ordering must be independent of insertion order"
    );
}

// ---------------------------------------------------------------------------
// Runtime capability count
// ---------------------------------------------------------------------------

#[test]
fn runtime_capability_all_sixteen_variants() {
    let all: std::collections::BTreeSet<RuntimeCapability> = [
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
    .into_iter()
    .collect();
    assert_eq!(all.len(), 16);
}

// ---------------------------------------------------------------------------
// Compute-only subsumes nothing except itself
// ---------------------------------------------------------------------------

#[test]
fn compute_only_subsumes_only_itself() {
    let co = CapabilityProfile::compute_only();
    assert!(co.subsumes(&co));
    assert!(!co.subsumes(&CapabilityProfile::engine_core()));
    assert!(!co.subsumes(&CapabilityProfile::policy()));
    assert!(!co.subsumes(&CapabilityProfile::remote()));
}

// ---------------------------------------------------------------------------
// Intersection with compute_only is always empty
// ---------------------------------------------------------------------------

#[test]
fn intersection_with_compute_only_is_empty() {
    let co = CapabilityProfile::compute_only();
    for profile in [
        CapabilityProfile::full(),
        CapabilityProfile::engine_core(),
        CapabilityProfile::policy(),
        CapabilityProfile::remote(),
    ] {
        let inter = profile.intersect(&co);
        assert!(
            inter.is_empty(),
            "intersection with compute_only should be empty"
        );
    }
}

// ---------------------------------------------------------------------------
// CapabilityDenied — display contains all fields
// ---------------------------------------------------------------------------

#[test]
fn capability_denied_display_contains_profile_and_capability() {
    let denied = CapabilityDenied {
        required: RuntimeCapability::FsWrite,
        held_profile: ProfileKind::Remote,
        component: "fs-writer".to_string(),
    };
    let s = denied.to_string();
    assert!(s.contains("fs_write"));
    assert!(s.contains("RemoteCaps"));
    assert!(s.contains("fs-writer"));
}

// ---------------------------------------------------------------------------
// require_capability — all caps against all profiles
// ---------------------------------------------------------------------------

#[test]
fn require_capability_engine_core_allows_vm_dispatch() {
    let ec = CapabilityProfile::engine_core();
    assert!(require_capability(&ec, RuntimeCapability::VmDispatch, "test").is_ok());
    assert!(require_capability(&ec, RuntimeCapability::GcInvoke, "test").is_ok());
    assert!(require_capability(&ec, RuntimeCapability::IrLowering, "test").is_ok());
    assert!(require_capability(&ec, RuntimeCapability::HeapAllocate, "test").is_ok());
}

#[test]
fn require_capability_engine_core_denies_network() {
    let ec = CapabilityProfile::engine_core();
    assert!(require_capability(&ec, RuntimeCapability::NetworkEgress, "test").is_err());
    assert!(require_capability(&ec, RuntimeCapability::FsWrite, "test").is_err());
    assert!(require_capability(&ec, RuntimeCapability::PolicyWrite, "test").is_err());
}

// ---------------------------------------------------------------------------
// ProfileKind — Ord ordering
// ---------------------------------------------------------------------------

#[test]
fn profile_kind_ordering() {
    assert!(ProfileKind::Full < ProfileKind::EngineCore);
    assert!(ProfileKind::EngineCore < ProfileKind::Policy);
    assert!(ProfileKind::Policy < ProfileKind::Remote);
    assert!(ProfileKind::Remote < ProfileKind::ComputeOnly);
}

// ---------------------------------------------------------------------------
// Profile — has returns false for all capabilities in empty profile
// ---------------------------------------------------------------------------

#[test]
fn compute_only_has_returns_false_for_all() {
    let co = CapabilityProfile::compute_only();
    for cap in [
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
    ] {
        assert!(!co.has(cap), "compute_only should not have {:?}", cap);
    }
}

// ---------------------------------------------------------------------------
// CapabilityDenied clone and eq
// ---------------------------------------------------------------------------

#[test]
fn capability_denied_clone_eq() {
    let denied = CapabilityDenied {
        required: RuntimeCapability::ProcessSpawn,
        held_profile: ProfileKind::Policy,
        component: "spawner".to_string(),
    };
    let cloned = denied.clone();
    assert_eq!(denied, cloned);
}
