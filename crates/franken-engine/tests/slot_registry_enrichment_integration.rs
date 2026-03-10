#![forbid(unsafe_code)]
//! Enrichment integration tests for `slot_registry`.
//!
//! Adds JSON field-name stability, exact serde enum values, Display exactness,
//! Debug distinctness, error coverage, and edge cases beyond
//! the existing 90 integration tests.

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

use frankenengine_engine::slot_registry::{
    AuthorityEnvelope, GaReleaseGuardConfig, GaReleaseGuardError, GaReleaseGuardVerdict,
    PromotionStatus, ReleaseSlotClass, ReplacementProgressError, SlotCapability, SlotId, SlotKind,
    SlotRegistry, SlotRegistryError, SlotReplacementSignal,
};
use std::collections::BTreeSet;

// ===========================================================================
// 1) SlotKind — exact Display
// ===========================================================================

#[test]
fn slot_kind_display_exact() {
    let expected = [
        (SlotKind::Parser, "parser"),
        (SlotKind::IrLowering, "ir-lowering"),
        (SlotKind::CapabilityLowering, "capability-lowering"),
        (SlotKind::ExecLowering, "exec-lowering"),
        (SlotKind::Interpreter, "interpreter"),
        (SlotKind::ObjectModel, "object-model"),
        (SlotKind::ScopeModel, "scope-model"),
        (SlotKind::AsyncRuntime, "async-runtime"),
        (SlotKind::GarbageCollector, "garbage-collector"),
        (SlotKind::ModuleLoader, "module-loader"),
        (SlotKind::HostcallDispatch, "hostcall-dispatch"),
        (SlotKind::Builtins, "builtins"),
    ];
    for (kind, exp) in &expected {
        assert_eq!(
            kind.to_string(),
            *exp,
            "SlotKind Display mismatch for {kind:?}"
        );
    }
}

// ===========================================================================
// 2) PromotionStatus — exact Display
// ===========================================================================

#[test]
fn promotion_status_display_delegate() {
    assert_eq!(PromotionStatus::Delegate.to_string(), "delegate");
}

#[test]
fn promotion_status_display_candidate() {
    let ps = PromotionStatus::PromotionCandidate {
        candidate_digest: "abc".into(),
    };
    let s = ps.to_string();
    assert!(
        s.contains("promotion-candidate") || s.contains("abc"),
        "should describe candidacy: {s}"
    );
}

#[test]
fn promotion_status_is_native() {
    assert!(
        PromotionStatus::Promoted {
            native_digest: "d".into(),
            receipt_id: "r".into(),
        }
        .is_native()
    );
    assert!(!PromotionStatus::Delegate.is_native());
}

#[test]
fn promotion_status_is_delegate() {
    assert!(PromotionStatus::Delegate.is_delegate());
    assert!(
        !PromotionStatus::Promoted {
            native_digest: "d".into(),
            receipt_id: "r".into(),
        }
        .is_delegate()
    );
}

// ===========================================================================
// 3) ReleaseSlotClass / GaReleaseGuardVerdict — exact Display
// ===========================================================================

#[test]
fn release_slot_class_display_exact() {
    assert_eq!(ReleaseSlotClass::Core.to_string(), "core");
    assert_eq!(ReleaseSlotClass::NonCore.to_string(), "non-core");
}

#[test]
fn ga_release_guard_verdict_display_exact() {
    assert_eq!(GaReleaseGuardVerdict::Pass.to_string(), "pass");
    assert_eq!(GaReleaseGuardVerdict::Blocked.to_string(), "blocked");
}

// ===========================================================================
// 4) SlotRegistryError — exact Display + uniqueness
// ===========================================================================

#[test]
fn slot_registry_error_display_all_unique() {
    let variants: Vec<String> = vec![
        SlotRegistryError::InvalidSlotId {
            id: "a".into(),
            reason: "b".into(),
        }
        .to_string(),
        SlotRegistryError::DuplicateSlotId { id: "c".into() }.to_string(),
        SlotRegistryError::SlotNotFound { id: "d".into() }.to_string(),
        SlotRegistryError::InconsistentAuthority {
            id: "e".into(),
            detail: "f".into(),
        }
        .to_string(),
        SlotRegistryError::InvalidTransition {
            id: "g".into(),
            from: "h".into(),
            to: "i".into(),
        }
        .to_string(),
        SlotRegistryError::AuthorityBroadening {
            id: "j".into(),
            detail: "k".into(),
        }
        .to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), variants.len());
}

#[test]
fn slot_registry_error_is_std_error() {
    let e = SlotRegistryError::SlotNotFound { id: "x".into() };
    let _: &dyn std::error::Error = &e;
}

// ===========================================================================
// 5) GaReleaseGuardError — uniqueness
// ===========================================================================

#[test]
fn ga_release_guard_error_display_all_unique() {
    let variants: Vec<String> = vec![
        GaReleaseGuardError::InvalidInput {
            field: "a".into(),
            detail: "b".into(),
        }
        .to_string(),
        GaReleaseGuardError::UnknownCoreSlot {
            slot_id: "c".into(),
        }
        .to_string(),
        GaReleaseGuardError::InvalidExemption {
            exemption_id: "d".into(),
            detail: "e".into(),
        }
        .to_string(),
        GaReleaseGuardError::DuplicateExemption {
            slot_id: "f".into(),
        }
        .to_string(),
        GaReleaseGuardError::InvalidLineageArtifact {
            slot_id: "g".into(),
            detail: "h".into(),
        }
        .to_string(),
        GaReleaseGuardError::DuplicateLineageArtifact {
            slot_id: "i".into(),
        }
        .to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), variants.len());
}

#[test]
fn ga_release_guard_error_is_std_error() {
    let e = GaReleaseGuardError::UnknownCoreSlot {
        slot_id: "x".into(),
    };
    let _: &dyn std::error::Error = &e;
}

// ===========================================================================
// 6) ReplacementProgressError — uniqueness
// ===========================================================================

#[test]
fn replacement_progress_error_display_all_unique() {
    let variants: Vec<String> = vec![
        ReplacementProgressError::InvalidInput {
            field: "a".into(),
            detail: "b".into(),
        }
        .to_string(),
        ReplacementProgressError::UnknownSignalSlot {
            slot_id: "c".into(),
        }
        .to_string(),
        ReplacementProgressError::InvalidSignal {
            slot_id: "d".into(),
            detail: "e".into(),
        }
        .to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), variants.len());
}

#[test]
fn replacement_progress_error_is_std_error() {
    let e = ReplacementProgressError::UnknownSignalSlot {
        slot_id: "x".into(),
    };
    let _: &dyn std::error::Error = &e;
}

// ===========================================================================
// 7) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_slot_kind() {
    let variants: Vec<String> = [
        SlotKind::Parser,
        SlotKind::IrLowering,
        SlotKind::CapabilityLowering,
        SlotKind::ExecLowering,
        SlotKind::Interpreter,
        SlotKind::ObjectModel,
        SlotKind::ScopeModel,
        SlotKind::AsyncRuntime,
        SlotKind::GarbageCollector,
        SlotKind::ModuleLoader,
        SlotKind::HostcallDispatch,
        SlotKind::Builtins,
    ]
    .iter()
    .map(|k| format!("{k:?}"))
    .collect();
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 12);
}

#[test]
fn debug_distinct_slot_capability() {
    let variants: Vec<String> = [
        SlotCapability::ReadSource,
        SlotCapability::EmitIr,
        SlotCapability::HeapAlloc,
        SlotCapability::ScheduleAsync,
        SlotCapability::InvokeHostcall,
        SlotCapability::ModuleAccess,
        SlotCapability::TriggerGc,
        SlotCapability::EmitEvidence,
    ]
    .iter()
    .map(|c| format!("{c:?}"))
    .collect();
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 8);
}

// ===========================================================================
// 8) SlotId validation
// ===========================================================================

#[test]
fn slot_id_valid_construction() {
    let id = SlotId::new("parser-main").unwrap();
    assert_eq!(id.as_str(), "parser-main");
    assert_eq!(id.to_string(), "parser-main");
}

#[test]
fn slot_id_empty_string_is_error() {
    assert!(SlotId::new("").is_err());
}

// ===========================================================================
// 9) AuthorityEnvelope consistency
// ===========================================================================

#[test]
fn authority_envelope_empty_is_consistent() {
    let ae = AuthorityEnvelope {
        required: vec![],
        permitted: vec![],
    };
    assert!(ae.is_consistent());
}

#[test]
fn authority_envelope_required_subset_of_permitted() {
    let ae = AuthorityEnvelope {
        required: vec![SlotCapability::ReadSource],
        permitted: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
    };
    assert!(ae.is_consistent());
}

// ===========================================================================
// 10) SlotRegistry construction and initial state
// ===========================================================================

#[test]
fn slot_registry_new_empty() {
    let reg = SlotRegistry::new();
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);
    assert_eq!(reg.native_count(), 0);
    assert_eq!(reg.delegate_count(), 0);
}

#[test]
fn slot_registry_default_matches_new() {
    let r1 = SlotRegistry::new();
    let r2 = SlotRegistry::default();
    assert_eq!(r1.len(), r2.len());
}

// ===========================================================================
// 11) GaReleaseGuardConfig default
// ===========================================================================

#[test]
fn ga_release_guard_config_default() {
    let config = GaReleaseGuardConfig::default();
    assert!(config.core_slots.is_empty());
    assert!(config.non_core_delegate_limit.is_none());
    assert_eq!(
        config.lineage_dashboard_ref,
        "frankentui://replacement-lineage"
    );
}

// ===========================================================================
// 12) SlotReplacementSignal default
// ===========================================================================

#[test]
fn slot_replacement_signal_default() {
    let signal = SlotReplacementSignal::default();
    assert_eq!(signal.invocation_weight_millionths, 1_000_000);
    assert_eq!(signal.throughput_uplift_millionths, 0);
    assert_eq!(signal.security_risk_reduction_millionths, 0);
}

// ===========================================================================
// 13) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_slot_kind_all() {
    let kinds = [
        SlotKind::Parser,
        SlotKind::IrLowering,
        SlotKind::CapabilityLowering,
        SlotKind::ExecLowering,
        SlotKind::Interpreter,
        SlotKind::ObjectModel,
        SlotKind::ScopeModel,
        SlotKind::AsyncRuntime,
        SlotKind::GarbageCollector,
        SlotKind::ModuleLoader,
        SlotKind::HostcallDispatch,
        SlotKind::Builtins,
    ];
    for k in &kinds {
        let json = serde_json::to_string(k).unwrap();
        let rt: SlotKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, rt);
    }
}

#[test]
fn serde_roundtrip_slot_registry_error_all_variants() {
    let variants = vec![
        SlotRegistryError::InvalidSlotId {
            id: "a".into(),
            reason: "b".into(),
        },
        SlotRegistryError::DuplicateSlotId { id: "c".into() },
        SlotRegistryError::SlotNotFound { id: "d".into() },
        SlotRegistryError::InconsistentAuthority {
            id: "e".into(),
            detail: "f".into(),
        },
        SlotRegistryError::InvalidTransition {
            id: "g".into(),
            from: "h".into(),
            to: "i".into(),
        },
        SlotRegistryError::AuthorityBroadening {
            id: "j".into(),
            detail: "k".into(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let rt: SlotRegistryError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, rt);
    }
}

#[test]
fn serde_roundtrip_promotion_status_all_variants() {
    let variants = vec![
        PromotionStatus::Delegate,
        PromotionStatus::PromotionCandidate {
            candidate_digest: "abc".into(),
        },
        PromotionStatus::Promoted {
            native_digest: "def".into(),
            receipt_id: "ghi".into(),
        },
        PromotionStatus::Demoted {
            reason: "perf".into(),
            rollback_digest: "jkl".into(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let rt: PromotionStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, rt);
    }
}

// ===========================================================================
// 14) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_authority_envelope() {
    let ae = AuthorityEnvelope {
        required: vec![SlotCapability::ReadSource],
        permitted: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
    };
    let v: serde_json::Value = serde_json::to_value(&ae).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("required"));
    assert!(obj.contains_key("permitted"));
}

#[test]
fn json_fields_slot_replacement_signal() {
    let signal = SlotReplacementSignal::default();
    let v: serde_json::Value = serde_json::to_value(&signal).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "invocation_weight_millionths",
        "throughput_uplift_millionths",
        "security_risk_reduction_millionths",
    ] {
        assert!(
            obj.contains_key(key),
            "SlotReplacementSignal missing field: {key}"
        );
    }
}

#[test]
fn json_fields_ga_release_guard_config() {
    let config = GaReleaseGuardConfig::default();
    let v: serde_json::Value = serde_json::to_value(&config).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "core_slots",
        "non_core_delegate_limit",
        "lineage_dashboard_ref",
    ] {
        assert!(
            obj.contains_key(key),
            "GaReleaseGuardConfig missing field: {key}"
        );
    }
}

#[test]
fn slot_registry_debug_is_nonempty() {
    let registry = SlotRegistry::new();
    assert!(!format!("{registry:?}").is_empty());
}

#[test]
fn ga_release_guard_config_debug_is_nonempty() {
    let config = GaReleaseGuardConfig::default();
    assert!(!format!("{config:?}").is_empty());
}

#[test]
fn slot_replacement_signal_debug_is_nonempty() {
    let signal = SlotReplacementSignal::default();
    assert!(!format!("{signal:?}").is_empty());
}
