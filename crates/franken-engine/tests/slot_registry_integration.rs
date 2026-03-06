//! Integration tests for the `slot_registry` module.
//!
//! Covers: SlotId validation edge cases, SlotKind Display for all 12 variants,
//! AuthorityEnvelope with all 8 capabilities, PromotionStatus lifecycle,
//! multi-slot registry operations, GA release guard input validation and
//! complex scenarios, replacement progress metrics, error Display impls,
//! and serialization round-trips.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::slot_registry::{
    AuthorityEnvelope, CoreSlotExemption, GaReleaseGuardConfig, GaReleaseGuardError,
    GaReleaseGuardInput, GaReleaseGuardVerdict, GaSignedLineageArtifact, PromotionStatus,
    PromotionTransition, ReleaseSlotClass, ReplacementProgressError, SlotCapability, SlotId,
    SlotKind, SlotRegistry, SlotRegistryError, SlotReplacementSignal,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn test_authority() -> AuthorityEnvelope {
    AuthorityEnvelope {
        required: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
        permitted: vec![
            SlotCapability::ReadSource,
            SlotCapability::EmitIr,
            SlotCapability::EmitEvidence,
        ],
    }
}

fn narrower_authority() -> AuthorityEnvelope {
    AuthorityEnvelope {
        required: vec![SlotCapability::ReadSource],
        permitted: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
    }
}

fn all_capabilities_authority() -> AuthorityEnvelope {
    AuthorityEnvelope {
        required: vec![
            SlotCapability::ReadSource,
            SlotCapability::EmitIr,
            SlotCapability::HeapAlloc,
            SlotCapability::ScheduleAsync,
            SlotCapability::InvokeHostcall,
            SlotCapability::ModuleAccess,
            SlotCapability::TriggerGc,
            SlotCapability::EmitEvidence,
        ],
        permitted: vec![
            SlotCapability::ReadSource,
            SlotCapability::EmitIr,
            SlotCapability::HeapAlloc,
            SlotCapability::ScheduleAsync,
            SlotCapability::InvokeHostcall,
            SlotCapability::ModuleAccess,
            SlotCapability::TriggerGc,
            SlotCapability::EmitEvidence,
        ],
    }
}

fn register_slot(registry: &mut SlotRegistry, name: &str, kind: SlotKind, digest: &str) -> SlotId {
    let slot_id = SlotId::new(name).expect("valid slot id");
    registry
        .register_delegate(
            slot_id.clone(),
            kind,
            test_authority(),
            digest.to_string(),
            "2026-02-21T00:00:00Z".to_string(),
        )
        .expect("register delegate");
    slot_id
}

fn promote_slot(registry: &mut SlotRegistry, id: &SlotId, digest: &str) {
    registry
        .begin_candidacy(
            id,
            format!("{digest}-candidate"),
            "2026-02-21T00:00:01Z".to_string(),
        )
        .expect("begin candidacy");
    registry
        .promote(
            id,
            digest.to_string(),
            &narrower_authority(),
            format!("receipt-{digest}"),
            "2026-02-21T00:00:02Z".to_string(),
        )
        .expect("promote");
}

fn guard_input(
    core_slots: BTreeSet<SlotId>,
    non_core_delegate_limit: Option<usize>,
) -> GaReleaseGuardInput {
    GaReleaseGuardInput {
        trace_id: "trace-integ-001".to_string(),
        decision_id: "decision-integ-001".to_string(),
        policy_id: "policy-integ-001".to_string(),
        current_epoch: SecurityEpoch::from_raw(42),
        config: GaReleaseGuardConfig {
            core_slots,
            non_core_delegate_limit,
            lineage_dashboard_ref: "frankentui://replacement-lineage/integration-test".to_string(),
        },
        exemptions: Vec::new(),
        lineage_artifacts: Vec::new(),
        remediation_estimates: BTreeMap::new(),
    }
}

fn lineage_artifact(
    slot_id: &SlotId,
    former_delegate_digest: &str,
    replacement_component_digest: &str,
) -> GaSignedLineageArtifact {
    GaSignedLineageArtifact {
        slot_id: slot_id.clone(),
        former_delegate_digest: former_delegate_digest.to_string(),
        replacement_component_digest: replacement_component_digest.to_string(),
        replacement_author: "native-team".to_string(),
        replacement_timestamp: "2026-02-21T00:00:03Z".to_string(),
        lineage_signature: "sig:lineage-proof-integ".to_string(),
        trust_anchor_ref: "trust-anchor://integ-v1".to_string(),
        signature_verified: true,
        equivalence_suite_ref: "suite://integ-equivalence-v1".to_string(),
        equivalence_passed: true,
        delegate_fallback_reachable: false,
    }
}

fn exemption_for(slot_id: SlotId) -> CoreSlotExemption {
    CoreSlotExemption {
        exemption_id: format!("exemption-{}", slot_id.as_str()),
        slot_id,
        approved_by: "gov-council".to_string(),
        signed_risk_acknowledgement: "sig:risk-ack-integ".to_string(),
        remediation_plan: "replace within one sprint".to_string(),
        remediation_deadline_epoch: 48,
        expires_at_epoch: 50,
    }
}

// ---------------------------------------------------------------------------
// SlotId validation edge cases
// ---------------------------------------------------------------------------

#[test]
fn slot_id_accepts_digits_only() {
    let id = SlotId::new("123").unwrap();
    assert_eq!(id.as_str(), "123");
}

#[test]
fn slot_id_accepts_single_char() {
    let id = SlotId::new("a").unwrap();
    assert_eq!(id.as_str(), "a");
}

#[test]
fn slot_id_accepts_leading_hyphen() {
    let id = SlotId::new("-leading").unwrap();
    assert_eq!(id.as_str(), "-leading");
}

#[test]
fn slot_id_accepts_trailing_hyphen() {
    let id = SlotId::new("trailing-").unwrap();
    assert_eq!(id.as_str(), "trailing-");
}

#[test]
fn slot_id_rejects_underscore() {
    assert!(matches!(
        SlotId::new("has_underscore"),
        Err(SlotRegistryError::InvalidSlotId { .. })
    ));
}

#[test]
fn slot_id_rejects_period() {
    assert!(matches!(
        SlotId::new("has.period"),
        Err(SlotRegistryError::InvalidSlotId { .. })
    ));
}

#[test]
fn slot_id_rejects_space() {
    assert!(matches!(
        SlotId::new("has space"),
        Err(SlotRegistryError::InvalidSlotId { .. })
    ));
}

#[test]
fn slot_id_rejects_colon() {
    assert!(matches!(
        SlotId::new("sha256:abc"),
        Err(SlotRegistryError::InvalidSlotId { .. })
    ));
}

#[test]
fn slot_id_display_matches_as_str() {
    let id = SlotId::new("my-slot-42").unwrap();
    assert_eq!(format!("{id}"), "my-slot-42");
    assert_eq!(id.to_string(), id.as_str());
}

#[test]
fn slot_id_ord_is_lexicographic() {
    let a = SlotId::new("aaa").unwrap();
    let b = SlotId::new("bbb").unwrap();
    let c = SlotId::new("ccc").unwrap();
    assert!(a < b);
    assert!(b < c);
}

// ---------------------------------------------------------------------------
// SlotKind Display — all 12 variants
// ---------------------------------------------------------------------------

#[test]
fn slot_kind_display_all_variants() {
    let cases: Vec<(SlotKind, &str)> = vec![
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
    for (kind, expected) in cases {
        assert_eq!(kind.to_string(), expected, "SlotKind::{kind:?}");
    }
}

// ---------------------------------------------------------------------------
// AuthorityEnvelope
// ---------------------------------------------------------------------------

#[test]
fn authority_all_caps_is_consistent() {
    assert!(all_capabilities_authority().is_consistent());
}

#[test]
fn authority_empty_is_consistent() {
    let authority = AuthorityEnvelope {
        required: vec![],
        permitted: vec![],
    };
    assert!(authority.is_consistent());
}

#[test]
fn authority_empty_required_nonempty_permitted_is_consistent() {
    let authority = AuthorityEnvelope {
        required: vec![],
        permitted: vec![SlotCapability::HeapAlloc],
    };
    assert!(authority.is_consistent());
}

#[test]
fn authority_subsumes_itself() {
    let auth = test_authority();
    assert!(auth.subsumes(&auth));
}

#[test]
fn authority_all_caps_subsumes_narrower() {
    let all = all_capabilities_authority();
    let narrow = narrower_authority();
    assert!(all.subsumes(&narrow));
    assert!(!narrow.subsumes(&all));
}

#[test]
fn authority_subsumes_empty() {
    let auth = test_authority();
    let empty = AuthorityEnvelope {
        required: vec![],
        permitted: vec![],
    };
    assert!(auth.subsumes(&empty));
}

// ---------------------------------------------------------------------------
// PromotionStatus — Display and predicates
// ---------------------------------------------------------------------------

#[test]
fn promotion_status_delegate_display() {
    assert_eq!(PromotionStatus::Delegate.to_string(), "delegate");
    assert!(PromotionStatus::Delegate.is_delegate());
    assert!(!PromotionStatus::Delegate.is_native());
}

#[test]
fn promotion_status_candidate_display() {
    let status = PromotionStatus::PromotionCandidate {
        candidate_digest: "sha256:cand".into(),
    };
    assert_eq!(status.to_string(), "promotion-candidate(sha256:cand)");
    assert!(!status.is_delegate());
    assert!(!status.is_native());
}

#[test]
fn promotion_status_promoted_display() {
    let status = PromotionStatus::Promoted {
        native_digest: "sha256:native-v1".into(),
        receipt_id: "receipt-001".into(),
    };
    assert_eq!(
        status.to_string(),
        "promoted(sha256:native-v1, receipt=receipt-001)"
    );
    assert!(!status.is_delegate());
    assert!(status.is_native());
}

#[test]
fn promotion_status_demoted_display() {
    let status = PromotionStatus::Demoted {
        reason: "regression".into(),
        rollback_digest: "sha256:rollback".into(),
    };
    assert_eq!(
        status.to_string(),
        "demoted(reason=regression, rollback=sha256:rollback)"
    );
    assert!(status.is_delegate());
    assert!(!status.is_native());
}

// ---------------------------------------------------------------------------
// ReleaseSlotClass and GaReleaseGuardVerdict Display
// ---------------------------------------------------------------------------

#[test]
fn release_slot_class_display() {
    assert_eq!(ReleaseSlotClass::Core.to_string(), "core");
    assert_eq!(ReleaseSlotClass::NonCore.to_string(), "non_core");
}

#[test]
fn ga_release_guard_verdict_display() {
    assert_eq!(GaReleaseGuardVerdict::Pass.to_string(), "pass");
    assert_eq!(GaReleaseGuardVerdict::Blocked.to_string(), "blocked");
}

// ---------------------------------------------------------------------------
// SlotRegistryError Display
// ---------------------------------------------------------------------------

#[test]
fn slot_registry_error_display_all_variants() {
    let cases: Vec<(SlotRegistryError, &str)> = vec![
        (
            SlotRegistryError::InvalidSlotId {
                id: "BAD".into(),
                reason: "uppercase".into(),
            },
            "invalid slot id 'BAD': uppercase",
        ),
        (
            SlotRegistryError::DuplicateSlotId {
                id: "parser".into(),
            },
            "duplicate slot id 'parser'",
        ),
        (
            SlotRegistryError::SlotNotFound { id: "ghost".into() },
            "slot 'ghost' not found",
        ),
        (
            SlotRegistryError::InconsistentAuthority {
                id: "parser".into(),
                detail: "bad caps".into(),
            },
            "inconsistent authority for 'parser': bad caps",
        ),
        (
            SlotRegistryError::InvalidTransition {
                id: "parser".into(),
                from: "delegate".into(),
                to: "promoted".into(),
            },
            "invalid transition for 'parser': delegate -> promoted",
        ),
        (
            SlotRegistryError::AuthorityBroadening {
                id: "parser".into(),
                detail: "exceeds envelope".into(),
            },
            "authority broadening rejected for 'parser': exceeds envelope",
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
    }
}

// ---------------------------------------------------------------------------
// GaReleaseGuardError Display
// ---------------------------------------------------------------------------

#[test]
fn ga_release_guard_error_display_all_variants() {
    let cases: Vec<(GaReleaseGuardError, &str)> = vec![
        (
            GaReleaseGuardError::InvalidInput {
                field: "trace_id".into(),
                detail: "must not be empty".into(),
            },
            "invalid input for `trace_id`: must not be empty",
        ),
        (
            GaReleaseGuardError::UnknownCoreSlot {
                slot_id: "ghost".into(),
            },
            "core slot `ghost` is not registered",
        ),
        (
            GaReleaseGuardError::InvalidExemption {
                exemption_id: "ex-1".into(),
                detail: "expired".into(),
            },
            "invalid exemption `ex-1`: expired",
        ),
        (
            GaReleaseGuardError::DuplicateExemption {
                slot_id: "parser".into(),
            },
            "duplicate exemption for slot `parser`",
        ),
        (
            GaReleaseGuardError::InvalidLineageArtifact {
                slot_id: "parser".into(),
                detail: "empty digest".into(),
            },
            "invalid lineage artifact for slot `parser`: empty digest",
        ),
        (
            GaReleaseGuardError::DuplicateLineageArtifact {
                slot_id: "parser".into(),
            },
            "duplicate lineage artifact for slot `parser`",
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
    }
}

// ---------------------------------------------------------------------------
// ReplacementProgressError Display
// ---------------------------------------------------------------------------

#[test]
fn replacement_progress_error_display_all_variants() {
    let cases: Vec<(ReplacementProgressError, &str)> = vec![
        (
            ReplacementProgressError::InvalidInput {
                field: "trace_id".into(),
                detail: "must not be empty".into(),
            },
            "invalid replacement progress input `trace_id`: must not be empty",
        ),
        (
            ReplacementProgressError::UnknownSignalSlot {
                slot_id: "ghost".into(),
            },
            "replacement progress signal references unknown slot `ghost`",
        ),
        (
            ReplacementProgressError::InvalidSignal {
                slot_id: "parser".into(),
                detail: "zero weight".into(),
            },
            "invalid replacement progress signal for `parser`: zero weight",
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
    }
}

// ---------------------------------------------------------------------------
// SlotRegistry — multi-slot registration with all 12 SlotKinds
// ---------------------------------------------------------------------------

fn all_slot_kinds() -> Vec<(&'static str, SlotKind)> {
    vec![
        ("parser", SlotKind::Parser),
        ("ir-lowering", SlotKind::IrLowering),
        ("capability-lowering", SlotKind::CapabilityLowering),
        ("exec-lowering", SlotKind::ExecLowering),
        ("interpreter", SlotKind::Interpreter),
        ("object-model", SlotKind::ObjectModel),
        ("scope-model", SlotKind::ScopeModel),
        ("async-runtime", SlotKind::AsyncRuntime),
        ("garbage-collector", SlotKind::GarbageCollector),
        ("module-loader", SlotKind::ModuleLoader),
        ("hostcall-dispatch", SlotKind::HostcallDispatch),
        ("builtins", SlotKind::Builtins),
    ]
}

#[test]
fn register_all_12_slot_kinds() {
    let mut registry = SlotRegistry::new();
    for (name, kind) in all_slot_kinds() {
        register_slot(
            &mut registry,
            name,
            kind,
            &format!("sha256:delegate-{name}"),
        );
    }
    assert_eq!(registry.len(), 12);
    assert_eq!(registry.delegate_count(), 12);
    assert_eq!(registry.native_count(), 0);
    assert!((registry.native_coverage() - 0.0).abs() < f64::EPSILON);
    assert!(!registry.is_ga_ready());
    assert!(!registry.is_empty());
}

#[test]
fn promote_all_12_slots_to_native() {
    let mut registry = SlotRegistry::new();
    let mut ids = Vec::new();
    for (name, kind) in all_slot_kinds() {
        let id = register_slot(
            &mut registry,
            name,
            kind,
            &format!("sha256:delegate-{name}"),
        );
        ids.push(id);
    }

    for id in &ids {
        promote_slot(&mut registry, id, &format!("sha256:native-{}", id.as_str()));
    }

    assert_eq!(registry.native_count(), 12);
    assert_eq!(registry.delegate_count(), 0);
    assert!((registry.native_coverage() - 1.0).abs() < f64::EPSILON);
    assert!(registry.is_ga_ready());
}

// ---------------------------------------------------------------------------
// Lifecycle — re-promotion after demotion
// ---------------------------------------------------------------------------

#[test]
fn re_promotion_after_demotion_full_cycle() {
    let mut registry = SlotRegistry::new();
    let id = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-v1",
    );

    // First promotion
    promote_slot(&mut registry, &id, "sha256:native-v1");
    assert!(registry.get(&id).unwrap().status.is_native());
    assert_eq!(registry.native_count(), 1);

    // Demote
    registry
        .demote(&id, "regression-v1".into(), "2026-02-21T01:00:00Z".into())
        .unwrap();
    let entry = registry.get(&id).unwrap();
    assert!(entry.status.is_delegate());
    assert!(matches!(entry.status, PromotionStatus::Demoted { .. }));

    // Re-promote (candidacy → promote again)
    registry
        .begin_candidacy(
            &id,
            "sha256:native-v2-candidate".into(),
            "2026-02-21T02:00:00Z".into(),
        )
        .unwrap();
    let entry = registry.get(&id).unwrap();
    assert!(matches!(
        entry.status,
        PromotionStatus::PromotionCandidate { .. }
    ));

    registry
        .promote(
            &id,
            "sha256:native-v2".into(),
            &narrower_authority(),
            "receipt-v2".into(),
            "2026-02-21T03:00:00Z".into(),
        )
        .unwrap();
    let entry = registry.get(&id).unwrap();
    assert!(entry.status.is_native());
    assert_eq!(entry.implementation_digest, "sha256:native-v2");

    // Lineage should have 6 events:
    // register, candidacy-1, promote-1, demote, candidacy-2, promote-2
    assert_eq!(entry.promotion_lineage.len(), 6);
    assert_eq!(
        entry.promotion_lineage[0].transition,
        PromotionTransition::RegisteredDelegate
    );
    assert_eq!(
        entry.promotion_lineage[1].transition,
        PromotionTransition::EnteredCandidacy
    );
    assert_eq!(
        entry.promotion_lineage[2].transition,
        PromotionTransition::PromotedToNative
    );
    assert_eq!(
        entry.promotion_lineage[3].transition,
        PromotionTransition::DemotedToDelegate
    );
    assert_eq!(
        entry.promotion_lineage[4].transition,
        PromotionTransition::EnteredCandidacy
    );
    assert_eq!(
        entry.promotion_lineage[5].transition,
        PromotionTransition::PromotedToNative
    );
}

#[test]
fn rollback_target_set_on_promotion() {
    let mut registry = SlotRegistry::new();
    let id = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-v1",
    );

    // Before promotion, no rollback target
    assert!(registry.get(&id).unwrap().rollback_target.is_none());

    promote_slot(&mut registry, &id, "sha256:native-v1");
    // After promotion, rollback target is the delegate digest
    assert_eq!(
        registry.get(&id).unwrap().rollback_target.as_deref(),
        Some("sha256:delegate-v1")
    );

    // After demotion, implementation_digest should be the rollback target
    registry
        .demote(&id, "regression".into(), "2026-02-21T01:00:00Z".into())
        .unwrap();
    assert_eq!(
        registry.get(&id).unwrap().implementation_digest,
        "sha256:delegate-v1"
    );
}

// ---------------------------------------------------------------------------
// Registry counting and coverage
// ---------------------------------------------------------------------------

#[test]
fn mixed_native_delegate_coverage() {
    let mut registry = SlotRegistry::new();
    let p = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-parser");
    let _i = register_slot(
        &mut registry,
        "interpreter",
        SlotKind::Interpreter,
        "sha256:d-interp",
    );
    let _o = register_slot(
        &mut registry,
        "object-model",
        SlotKind::ObjectModel,
        "sha256:d-obj",
    );
    let _b = register_slot(
        &mut registry,
        "builtins",
        SlotKind::Builtins,
        "sha256:d-built",
    );

    // Promote 1 of 4
    promote_slot(&mut registry, &p, "sha256:n-parser");
    assert_eq!(registry.native_count(), 1);
    assert_eq!(registry.delegate_count(), 3);
    assert!((registry.native_coverage() - 0.25).abs() < f64::EPSILON);
    assert!(!registry.is_ga_ready());
}

#[test]
fn empty_registry_edge_cases() {
    let registry = SlotRegistry::new();
    assert!(registry.is_empty());
    assert_eq!(registry.len(), 0);
    assert_eq!(registry.native_count(), 0);
    assert_eq!(registry.delegate_count(), 0);
    assert!((registry.native_coverage() - 0.0).abs() < f64::EPSILON);
    assert!(!registry.is_ga_ready());
    assert_eq!(registry.iter().count(), 0);
}

#[test]
fn get_returns_none_for_missing_slot() {
    let registry = SlotRegistry::new();
    let id = SlotId::new("nonexistent").unwrap();
    assert!(registry.get(&id).is_none());
}

// ---------------------------------------------------------------------------
// Iterator determinism
// ---------------------------------------------------------------------------

#[test]
fn iterator_order_is_deterministic_across_insertion_orders() {
    // Insert in reverse, verify iteration is sorted
    let mut registry = SlotRegistry::new();
    for name in ["zzz-last", "mmm-middle", "aaa-first"] {
        register_slot(
            &mut registry,
            name,
            SlotKind::Builtins,
            &format!("sha256:{name}"),
        );
    }
    let ids: Vec<&str> = registry.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(ids, vec!["aaa-first", "mmm-middle", "zzz-last"]);
}

// ---------------------------------------------------------------------------
// Lifecycle error transitions
// ---------------------------------------------------------------------------

#[test]
fn begin_candidacy_from_promoted_is_invalid() {
    let mut registry = SlotRegistry::new();
    let id = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-v1",
    );
    promote_slot(&mut registry, &id, "sha256:native-v1");

    assert!(matches!(
        registry.begin_candidacy(&id, "sha256:cand".into(), "t".into()),
        Err(SlotRegistryError::InvalidTransition { .. })
    ));
}

#[test]
fn begin_candidacy_from_candidate_is_invalid() {
    let mut registry = SlotRegistry::new();
    let id = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-v1",
    );
    registry
        .begin_candidacy(&id, "sha256:cand-1".into(), "t0".into())
        .unwrap();

    assert!(matches!(
        registry.begin_candidacy(&id, "sha256:cand-2".into(), "t1".into()),
        Err(SlotRegistryError::InvalidTransition { .. })
    ));
}

#[test]
fn promote_nonexistent_slot_is_not_found() {
    let mut registry = SlotRegistry::new();
    let id = SlotId::new("ghost").unwrap();
    assert!(matches!(
        registry.promote(
            &id,
            "sha256:n".into(),
            &narrower_authority(),
            "r".into(),
            "t".into()
        ),
        Err(SlotRegistryError::SlotNotFound { .. })
    ));
}

#[test]
fn demote_nonexistent_slot_is_not_found() {
    let mut registry = SlotRegistry::new();
    let id = SlotId::new("ghost").unwrap();
    assert!(matches!(
        registry.demote(&id, "reason".into(), "t".into()),
        Err(SlotRegistryError::SlotNotFound { .. })
    ));
}

#[test]
fn promote_rejects_inconsistent_native_authority() {
    let mut registry = SlotRegistry::new();
    let id = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-v1",
    );
    registry
        .begin_candidacy(&id, "sha256:cand".into(), "t0".into())
        .unwrap();
    let bad_native_authority = AuthorityEnvelope {
        required: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
        permitted: vec![SlotCapability::ReadSource],
    };

    assert!(matches!(
        registry.promote(
            &id,
            "sha256:native-v1".into(),
            &bad_native_authority,
            "receipt-native-v1".into(),
            "t1".into()
        ),
        Err(SlotRegistryError::InconsistentAuthority { .. })
    ));

    let entry = registry.get(&id).expect("slot remains registered");
    assert!(matches!(
        entry.status,
        PromotionStatus::PromotionCandidate { .. }
    ));
    assert_eq!(entry.implementation_digest, "sha256:delegate-v1");
    assert_eq!(entry.rollback_target, None);
}

#[test]
fn demote_from_candidate_is_invalid() {
    let mut registry = SlotRegistry::new();
    let id = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-v1",
    );
    registry
        .begin_candidacy(&id, "sha256:cand".into(), "t0".into())
        .unwrap();

    assert!(matches!(
        registry.demote(&id, "reason".into(), "t1".into()),
        Err(SlotRegistryError::InvalidTransition { .. })
    ));
}

// ---------------------------------------------------------------------------
// GA Release Guard — input validation
// ---------------------------------------------------------------------------

#[test]
fn ga_guard_rejects_empty_trace_id() {
    let registry = SlotRegistry::new();
    let mut input = guard_input(BTreeSet::new(), None);
    input.trace_id = "".into();
    assert!(matches!(
        registry.evaluate_ga_release_guard(&input),
        Err(GaReleaseGuardError::InvalidInput { field, .. }) if field == "trace_id"
    ));
}

#[test]
fn ga_guard_rejects_empty_decision_id() {
    let registry = SlotRegistry::new();
    let mut input = guard_input(BTreeSet::new(), None);
    input.decision_id = "   ".into();
    assert!(matches!(
        registry.evaluate_ga_release_guard(&input),
        Err(GaReleaseGuardError::InvalidInput { field, .. }) if field == "decision_id"
    ));
}

#[test]
fn ga_guard_rejects_empty_policy_id() {
    let registry = SlotRegistry::new();
    let mut input = guard_input(BTreeSet::new(), None);
    input.policy_id = "".into();
    assert!(matches!(
        registry.evaluate_ga_release_guard(&input),
        Err(GaReleaseGuardError::InvalidInput { field, .. }) if field == "policy_id"
    ));
}

#[test]
fn ga_guard_rejects_empty_lineage_dashboard_ref() {
    let registry = SlotRegistry::new();
    let mut input = guard_input(BTreeSet::new(), None);
    input.config.lineage_dashboard_ref = "".into();
    assert!(matches!(
        registry.evaluate_ga_release_guard(&input),
        Err(GaReleaseGuardError::InvalidInput { field, .. }) if field == "lineage_dashboard_ref"
    ));
}

#[test]
fn ga_guard_rejects_unknown_core_slot() {
    let registry = SlotRegistry::new();
    let ghost = SlotId::new("ghost-slot").unwrap();
    let input = guard_input(BTreeSet::from([ghost.clone()]), None);
    assert!(matches!(
        registry.evaluate_ga_release_guard(&input),
        Err(GaReleaseGuardError::UnknownCoreSlot { slot_id }) if slot_id == "ghost-slot"
    ));
}

// ---------------------------------------------------------------------------
// GA Release Guard — exemption validation
// ---------------------------------------------------------------------------

#[test]
fn ga_guard_rejects_exemption_with_empty_approved_by() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-parser",
    );
    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    let mut exemption = exemption_for(parser);
    exemption.approved_by = "".into();
    input.exemptions = vec![exemption];

    let err = registry
        .evaluate_ga_release_guard(&input)
        .expect_err("should fail");
    assert!(matches!(
        err,
        GaReleaseGuardError::InvalidExemption { detail, .. }
        if detail.contains("approved_by")
    ));
}

#[test]
fn ga_guard_rejects_exemption_with_empty_risk_ack() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-parser",
    );
    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    let mut exemption = exemption_for(parser);
    exemption.signed_risk_acknowledgement = "  ".into();
    input.exemptions = vec![exemption];

    let err = registry
        .evaluate_ga_release_guard(&input)
        .expect_err("should fail");
    assert!(matches!(
        err,
        GaReleaseGuardError::InvalidExemption { detail, .. }
        if detail.contains("signed_risk_acknowledgement")
    ));
}

#[test]
fn ga_guard_rejects_exemption_with_empty_remediation_plan() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-parser",
    );
    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    let mut exemption = exemption_for(parser);
    exemption.remediation_plan = "".into();
    input.exemptions = vec![exemption];

    let err = registry
        .evaluate_ga_release_guard(&input)
        .expect_err("should fail");
    assert!(matches!(
        err,
        GaReleaseGuardError::InvalidExemption { detail, .. }
        if detail.contains("remediation_plan")
    ));
}

#[test]
fn ga_guard_rejects_exemption_with_empty_exemption_id() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-parser",
    );
    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    let mut exemption = exemption_for(parser);
    exemption.exemption_id = "".into();
    input.exemptions = vec![exemption];

    let err = registry
        .evaluate_ga_release_guard(&input)
        .expect_err("should fail");
    assert!(matches!(
        err,
        GaReleaseGuardError::InvalidExemption { detail, .. }
        if detail.contains("exemption_id")
    ));
}

#[test]
fn ga_guard_rejects_exemption_with_past_remediation_deadline() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-parser",
    );
    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    let mut exemption = exemption_for(parser);
    // current_epoch is 42 — set deadline to 42 (not in the future)
    exemption.remediation_deadline_epoch = 42;
    input.exemptions = vec![exemption];

    let err = registry
        .evaluate_ga_release_guard(&input)
        .expect_err("should fail");
    assert!(matches!(
        err,
        GaReleaseGuardError::InvalidExemption { detail, .. }
        if detail.contains("remediation_deadline_epoch")
    ));
}

#[test]
fn ga_guard_rejects_exemption_for_non_core_slot() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-parser",
    );
    let builtins = register_slot(
        &mut registry,
        "builtins",
        SlotKind::Builtins,
        "sha256:delegate-builtins",
    );
    // Only parser is core
    let core_slots = BTreeSet::from([parser]);
    let mut input = guard_input(core_slots, None);
    // But exemption references builtins (non-core)
    input.exemptions = vec![exemption_for(builtins)];

    let err = registry
        .evaluate_ga_release_guard(&input)
        .expect_err("should fail");
    assert!(matches!(
        err,
        GaReleaseGuardError::InvalidExemption { detail, .. }
        if detail.contains("not configured as a core slot")
    ));
}

#[test]
fn ga_guard_rejects_duplicate_exemptions() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-parser",
    );
    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    let ex1 = exemption_for(parser.clone());
    let mut ex2 = exemption_for(parser);
    ex2.exemption_id = "different-id".into();
    input.exemptions = vec![ex1, ex2];

    assert!(matches!(
        registry.evaluate_ga_release_guard(&input),
        Err(GaReleaseGuardError::DuplicateExemption { .. })
    ));
}

// ---------------------------------------------------------------------------
// GA Release Guard — lineage artifact validation
// ---------------------------------------------------------------------------

#[test]
fn ga_guard_rejects_lineage_for_non_core_slot() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-parser",
    );
    let builtins = register_slot(
        &mut registry,
        "builtins",
        SlotKind::Builtins,
        "sha256:delegate-builtins",
    );
    promote_slot(&mut registry, &builtins, "sha256:native-builtins");

    // Only parser is core
    let core_slots = BTreeSet::from([parser]);
    let mut input = guard_input(core_slots, None);
    // Lineage artifact references builtins (non-core)
    input.lineage_artifacts = vec![lineage_artifact(
        &builtins,
        "sha256:delegate-builtins",
        "sha256:native-builtins",
    )];

    let err = registry
        .evaluate_ga_release_guard(&input)
        .expect_err("should fail");
    assert!(matches!(
        err,
        GaReleaseGuardError::InvalidLineageArtifact { detail, .. }
        if detail.contains("non-core slot")
    ));
}

#[test]
fn ga_guard_rejects_lineage_with_empty_former_digest() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-parser",
    );
    promote_slot(&mut registry, &parser, "sha256:native-parser");

    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    let mut art = lineage_artifact(&parser, "sha256:delegate-parser", "sha256:native-parser");
    art.former_delegate_digest = "".into();
    input.lineage_artifacts = vec![art];

    let err = registry
        .evaluate_ga_release_guard(&input)
        .expect_err("should fail");
    assert!(matches!(
        err,
        GaReleaseGuardError::InvalidLineageArtifact { detail, .. }
        if detail.contains("former_delegate_digest")
    ));
}

#[test]
fn ga_guard_rejects_duplicate_lineage_artifacts() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-parser",
    );
    promote_slot(&mut registry, &parser, "sha256:native-parser");

    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    let art = lineage_artifact(&parser, "sha256:delegate-parser", "sha256:native-parser");
    input.lineage_artifacts = vec![art.clone(), art];

    assert!(matches!(
        registry.evaluate_ga_release_guard(&input),
        Err(GaReleaseGuardError::DuplicateLineageArtifact { .. })
    ));
}

// ---------------------------------------------------------------------------
// GA Release Guard — lineage digest mismatch
// ---------------------------------------------------------------------------

#[test]
fn ga_guard_blocks_on_lineage_digest_mismatch() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-parser",
    );
    promote_slot(&mut registry, &parser, "sha256:native-parser");

    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    // Lineage claims a different replacement digest than what's actually active
    input.lineage_artifacts = vec![lineage_artifact(
        &parser,
        "sha256:delegate-parser",
        "sha256:wrong-digest",
    )];

    let artifact = registry
        .evaluate_ga_release_guard(&input)
        .expect("guard should complete");
    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);
    assert_eq!(artifact.core_slots_lineage_mismatch, vec![parser]);
    assert!(
        artifact
            .events
            .iter()
            .any(|e| { e.error_code.as_deref() == Some("FE-GA-LINEAGE-DIGEST-MISMATCH") })
    );
}

#[test]
fn ga_guard_blocks_on_former_delegate_digest_mismatch() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-parser",
    );
    promote_slot(&mut registry, &parser, "sha256:native-parser");

    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    input.lineage_artifacts = vec![lineage_artifact(
        &parser,
        "sha256:someone-elses-delegate",
        "sha256:native-parser",
    )];

    let artifact = registry
        .evaluate_ga_release_guard(&input)
        .expect("guard should complete");
    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);
    assert_eq!(artifact.core_slots_lineage_mismatch, vec![parser.clone()]);
    assert!(artifact.events.iter().any(|event| {
        event.slot_id.as_deref() == Some(parser.as_str())
            && event.error_code.as_deref() == Some("FE-GA-LINEAGE-DIGEST-MISMATCH")
            && event.detail.contains("former delegate digest")
    }));
}

// ---------------------------------------------------------------------------
// GA Release Guard — equivalence failure
// ---------------------------------------------------------------------------

#[test]
fn ga_guard_blocks_on_equivalence_failure() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-parser",
    );
    promote_slot(&mut registry, &parser, "sha256:native-parser");

    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    let mut art = lineage_artifact(&parser, "sha256:delegate-parser", "sha256:native-parser");
    art.equivalence_passed = false;
    input.lineage_artifacts = vec![art];

    let artifact = registry
        .evaluate_ga_release_guard(&input)
        .expect("guard should complete");
    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);
    assert_eq!(artifact.core_slots_equivalence_failed, vec![parser]);
    assert!(
        artifact
            .events
            .iter()
            .any(|e| { e.error_code.as_deref() == Some("FE-GA-EQUIVALENCE-FAILED") })
    );
}

// ---------------------------------------------------------------------------
// GA Release Guard — complex multi-slot scenario
// ---------------------------------------------------------------------------

#[test]
fn ga_guard_complex_multi_slot_pass_with_mixed_core_and_noncore() {
    let mut registry = SlotRegistry::new();

    // Core slots: parser and interpreter
    let parser = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-parser");
    let interp = register_slot(
        &mut registry,
        "interpreter",
        SlotKind::Interpreter,
        "sha256:d-interp",
    );

    // Non-core slots: builtins, object-model
    register_slot(
        &mut registry,
        "builtins",
        SlotKind::Builtins,
        "sha256:d-builtins",
    );
    register_slot(
        &mut registry,
        "object-model",
        SlotKind::ObjectModel,
        "sha256:d-obj",
    );

    // Promote all core slots
    promote_slot(&mut registry, &parser, "sha256:n-parser");
    promote_slot(&mut registry, &interp, "sha256:n-interp");

    let core_slots = BTreeSet::from([parser.clone(), interp.clone()]);
    // Allow up to 2 non-core delegates (we have exactly 2)
    let mut input = guard_input(core_slots, Some(2));
    input.lineage_artifacts = vec![
        lineage_artifact(&parser, "sha256:d-parser", "sha256:n-parser"),
        lineage_artifact(&interp, "sha256:d-interp", "sha256:n-interp"),
    ];

    let artifact = registry
        .evaluate_ga_release_guard(&input)
        .expect("guard should complete");

    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Pass);
    assert_eq!(artifact.total_slots, 4);
    assert_eq!(artifact.core_slot_count, 2);
    assert_eq!(artifact.core_delegate_count, 0);
    assert_eq!(artifact.non_core_delegate_count, 2);
    assert!(artifact.blocking_slots.is_empty());
    assert_eq!(artifact.slot_statuses.len(), 4);

    // Verify lineage verification fields for core slots
    for status in &artifact.slot_statuses {
        if status.slot_class == ReleaseSlotClass::Core {
            assert_eq!(status.lineage_signature_verified, Some(true));
            assert_eq!(status.equivalence_passed, Some(true));
            assert_eq!(status.delegate_fallback_reachable, Some(false));
        }
    }
}

#[test]
fn ga_guard_complex_blocked_multiple_reasons() {
    let mut registry = SlotRegistry::new();

    // Core slots: parser (delegate, no exemption), interpreter (native, bad lineage)
    let parser = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-parser");
    let interp = register_slot(
        &mut registry,
        "interpreter",
        SlotKind::Interpreter,
        "sha256:d-interp",
    );
    promote_slot(&mut registry, &interp, "sha256:n-interp");

    // Non-core beyond limit
    register_slot(
        &mut registry,
        "builtins",
        SlotKind::Builtins,
        "sha256:d-builtins",
    );
    register_slot(
        &mut registry,
        "object-model",
        SlotKind::ObjectModel,
        "sha256:d-obj",
    );

    let core_slots = BTreeSet::from([parser.clone(), interp.clone()]);
    // Non-core limit = 0 (both builtins and object-model are over)
    let mut input = guard_input(core_slots, Some(0));
    // Provide lineage for interpreter but with bad signature
    let mut bad_lineage = lineage_artifact(&interp, "sha256:d-interp", "sha256:n-interp");
    bad_lineage.signature_verified = false;
    input.lineage_artifacts = vec![bad_lineage];

    let artifact = registry
        .evaluate_ga_release_guard(&input)
        .expect("guard should complete");

    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);
    // parser is delegate-backed core → blocks
    assert_eq!(artifact.core_delegate_count, 1);
    // interpreter has invalid signature → blocks
    assert_eq!(artifact.core_slots_invalid_signature, vec![interp]);
    // 2 non-core delegates exceed limit of 0
    assert_eq!(artifact.non_core_delegate_count, 2);
    // All blocking: parser (core delegate), builtins & object-model (non-core limit), interpreter (bad sig)
    assert!(artifact.blocking_slots.len() >= 4);
}

#[test]
fn ga_guard_non_core_limit_breach_marks_slot_events_as_fail() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-parser",
    );
    promote_slot(&mut registry, &parser, "sha256:native-parser");

    let builtins = register_slot(
        &mut registry,
        "builtins",
        SlotKind::Builtins,
        "sha256:delegate-builtins",
    );
    let module_loader = register_slot(
        &mut registry,
        "module-loader",
        SlotKind::ModuleLoader,
        "sha256:delegate-module-loader",
    );

    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, Some(1));
    input.lineage_artifacts = vec![lineage_artifact(
        &parser,
        "sha256:delegate-parser",
        "sha256:native-parser",
    )];

    let artifact = registry
        .evaluate_ga_release_guard(&input)
        .expect("guard should complete");

    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);
    assert_eq!(artifact.non_core_delegate_count, 2);
    for slot_id in [builtins, module_loader] {
        assert!(
            artifact.events.iter().any(|event| {
                event.event == "slot_status_evaluated"
                    && event.slot_id.as_deref() == Some(slot_id.as_str())
                    && event.outcome == "fail"
                    && event.error_code.as_deref() == Some("FE-GA-NONCORE-DELEGATE-LIMIT")
            }),
            "slot {} should emit a failing per-slot event when the aggregate limit is breached",
            slot_id
        );
    }
}

// ---------------------------------------------------------------------------
// GA Release Guard — empty registry passes with no core slots
// ---------------------------------------------------------------------------

#[test]
fn ga_guard_empty_registry_passes_when_no_core_required() {
    let registry = SlotRegistry::new();
    let input = guard_input(BTreeSet::new(), None);
    let artifact = registry
        .evaluate_ga_release_guard(&input)
        .expect("guard should pass");
    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Pass);
    assert_eq!(artifact.total_slots, 0);
    assert!(artifact.blocking_slots.is_empty());
}

// ---------------------------------------------------------------------------
// GA Release Guard — non-core limit None means unlimited
// ---------------------------------------------------------------------------

#[test]
fn ga_guard_no_non_core_limit_allows_unlimited_delegates() {
    let mut registry = SlotRegistry::new();
    for i in 0..5 {
        register_slot(
            &mut registry,
            &format!("slot-{i}"),
            SlotKind::Builtins,
            &format!("sha256:d-{i}"),
        );
    }
    // No core slots, no non-core limit
    let input = guard_input(BTreeSet::new(), None);
    let artifact = registry
        .evaluate_ga_release_guard(&input)
        .expect("guard should pass");
    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Pass);
    assert_eq!(artifact.non_core_delegate_count, 5);
}

// ---------------------------------------------------------------------------
// Replacement progress — input validation
// ---------------------------------------------------------------------------

#[test]
fn replacement_progress_rejects_empty_trace_id() {
    let registry = SlotRegistry::new();
    let err = registry
        .snapshot_replacement_progress("", "decision", "policy", &BTreeMap::new())
        .expect_err("should fail");
    assert!(matches!(
        err,
        ReplacementProgressError::InvalidInput { field, .. } if field == "trace_id"
    ));
}

#[test]
fn replacement_progress_rejects_whitespace_decision_id() {
    let registry = SlotRegistry::new();
    let err = registry
        .snapshot_replacement_progress("trace", "   ", "policy", &BTreeMap::new())
        .expect_err("should fail");
    assert!(matches!(
        err,
        ReplacementProgressError::InvalidInput { field, .. } if field == "decision_id"
    ));
}

#[test]
fn replacement_progress_rejects_empty_policy_id() {
    let registry = SlotRegistry::new();
    let err = registry
        .snapshot_replacement_progress("trace", "decision", "", &BTreeMap::new())
        .expect_err("should fail");
    assert!(matches!(
        err,
        ReplacementProgressError::InvalidInput { field, .. } if field == "policy_id"
    ));
}

// ---------------------------------------------------------------------------
// Replacement progress — all native
// ---------------------------------------------------------------------------

#[test]
fn replacement_progress_all_native_has_empty_replacement_order() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-parser");
    let interp = register_slot(
        &mut registry,
        "interpreter",
        SlotKind::Interpreter,
        "sha256:d-interp",
    );
    promote_slot(&mut registry, &parser, "sha256:n-parser");
    promote_slot(&mut registry, &interp, "sha256:n-interp");

    let snapshot = registry
        .snapshot_replacement_progress("trace-1", "decision-1", "policy-1", &BTreeMap::new())
        .expect("snapshot should succeed");

    assert_eq!(snapshot.total_slots, 2);
    assert_eq!(snapshot.native_slots, 2);
    assert_eq!(snapshot.delegate_slots, 0);
    assert_eq!(snapshot.native_coverage_millionths, 1_000_000);
    assert_eq!(snapshot.weighted_native_coverage_millionths, 1_000_000);
    assert!(snapshot.recommended_replacement_order.is_empty());
}

// ---------------------------------------------------------------------------
// Replacement progress — EV ranking determinism with tie-breaking
// ---------------------------------------------------------------------------

#[test]
fn replacement_progress_ev_tiebreak_is_slot_id_alphabetical() {
    let mut registry = SlotRegistry::new();
    let bbb = register_slot(
        &mut registry,
        "bbb-slot",
        SlotKind::Builtins,
        "sha256:d-bbb",
    );
    let aaa = register_slot(&mut registry, "aaa-slot", SlotKind::Parser, "sha256:d-aaa");

    // Both have the same EV score (100k + 100k = 200k) and same weight
    let mut signals = BTreeMap::new();
    signals.insert(
        bbb,
        SlotReplacementSignal {
            invocation_weight_millionths: 1_000_000,
            throughput_uplift_millionths: 100_000,
            security_risk_reduction_millionths: 100_000,
        },
    );
    signals.insert(
        aaa,
        SlotReplacementSignal {
            invocation_weight_millionths: 1_000_000,
            throughput_uplift_millionths: 100_000,
            security_risk_reduction_millionths: 100_000,
        },
    );

    let snapshot = registry
        .snapshot_replacement_progress("trace", "decision", "policy", &signals)
        .expect("snapshot");

    // With identical EV, tie-break is alphabetical by slot_id
    assert_eq!(snapshot.recommended_replacement_order.len(), 2);
    assert_eq!(
        snapshot.recommended_replacement_order[0].slot_id.as_str(),
        "aaa-slot"
    );
    assert_eq!(
        snapshot.recommended_replacement_order[1].slot_id.as_str(),
        "bbb-slot"
    );
}

// ---------------------------------------------------------------------------
// Replacement progress — event structure
// ---------------------------------------------------------------------------

#[test]
fn replacement_progress_events_have_correct_trace_ids() {
    let mut registry = SlotRegistry::new();
    register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-parser");

    let snapshot = registry
        .snapshot_replacement_progress("my-trace", "my-decision", "my-policy", &BTreeMap::new())
        .expect("snapshot");

    for event in &snapshot.events {
        assert_eq!(event.trace_id, "my-trace");
        assert_eq!(event.decision_id, "my-decision");
        assert_eq!(event.policy_id, "my-policy");
        assert_eq!(event.component, "self_replacement_progress");
    }

    // Should have candidate ranking event + final snapshot event
    assert!(
        snapshot
            .events
            .iter()
            .any(|e| e.event == "replacement_candidate_ranked")
    );
    assert!(
        snapshot
            .events
            .iter()
            .any(|e| e.event == "replacement_progress_snapshot_generated")
    );
}

// ---------------------------------------------------------------------------
// Replacement progress — empty registry
// ---------------------------------------------------------------------------

#[test]
fn replacement_progress_empty_registry() {
    let registry = SlotRegistry::new();
    let snapshot = registry
        .snapshot_replacement_progress("trace", "decision", "policy", &BTreeMap::new())
        .expect("snapshot");
    assert_eq!(snapshot.total_slots, 0);
    assert_eq!(snapshot.native_slots, 0);
    assert_eq!(snapshot.delegate_slots, 0);
    assert_eq!(snapshot.native_coverage_millionths, 0);
    assert!(snapshot.recommended_replacement_order.is_empty());
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn slot_registry_serde_round_trip_with_mixed_states() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-parser");
    let interp = register_slot(
        &mut registry,
        "interpreter",
        SlotKind::Interpreter,
        "sha256:d-interp",
    );
    let builtins = register_slot(
        &mut registry,
        "builtins",
        SlotKind::Builtins,
        "sha256:d-builtins",
    );

    // parser: promoted
    promote_slot(&mut registry, &parser, "sha256:n-parser");
    // interpreter: candidate
    registry
        .begin_candidacy(&interp, "sha256:cand-interp".into(), "t1".into())
        .unwrap();
    // builtins: delegate (unchanged)

    let json = serde_json::to_string(&registry).expect("serialize");
    let roundtrip: SlotRegistry = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(registry.len(), roundtrip.len());
    assert_eq!(registry.native_count(), roundtrip.native_count());
    assert_eq!(registry.delegate_count(), roundtrip.delegate_count());

    // Verify each slot preserved
    let rt_parser = roundtrip.get(&parser).unwrap();
    assert!(rt_parser.status.is_native());
    assert_eq!(rt_parser.kind, SlotKind::Parser);

    let rt_interp = roundtrip.get(&interp).unwrap();
    assert!(matches!(
        rt_interp.status,
        PromotionStatus::PromotionCandidate { .. }
    ));

    let rt_builtins = roundtrip.get(&builtins).unwrap();
    assert_eq!(rt_builtins.status, PromotionStatus::Delegate);
}

#[test]
fn slot_id_serde_round_trip() {
    let id = SlotId::new("my-slot").unwrap();
    let json = serde_json::to_string(&id).expect("serialize");
    let roundtrip: SlotId = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(id, roundtrip);
}

#[test]
fn slot_kind_serde_round_trip_all_variants() {
    for (_, kind) in all_slot_kinds() {
        let json = serde_json::to_string(&kind).expect("serialize");
        let roundtrip: SlotKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(kind, roundtrip);
    }
}

#[test]
fn slot_capability_serde_round_trip_all_variants() {
    let caps = vec![
        SlotCapability::ReadSource,
        SlotCapability::EmitIr,
        SlotCapability::HeapAlloc,
        SlotCapability::ScheduleAsync,
        SlotCapability::InvokeHostcall,
        SlotCapability::ModuleAccess,
        SlotCapability::TriggerGc,
        SlotCapability::EmitEvidence,
    ];
    for cap in caps {
        let json = serde_json::to_string(&cap).expect("serialize");
        let roundtrip: SlotCapability = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cap, roundtrip);
    }
}

#[test]
fn promotion_status_serde_round_trip_all_variants() {
    let statuses = vec![
        PromotionStatus::Delegate,
        PromotionStatus::PromotionCandidate {
            candidate_digest: "sha256:cand".into(),
        },
        PromotionStatus::Promoted {
            native_digest: "sha256:native".into(),
            receipt_id: "receipt-001".into(),
        },
        PromotionStatus::Demoted {
            reason: "regression".into(),
            rollback_digest: "sha256:rollback".into(),
        },
    ];
    for status in statuses {
        let json = serde_json::to_string(&status).expect("serialize");
        let roundtrip: PromotionStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(status, roundtrip);
    }
}

#[test]
fn ga_release_guard_artifact_serde_round_trip() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-parser");
    promote_slot(&mut registry, &parser, "sha256:n-parser");

    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    input.lineage_artifacts = vec![lineage_artifact(
        &parser,
        "sha256:d-parser",
        "sha256:n-parser",
    )];

    let artifact = registry
        .evaluate_ga_release_guard(&input)
        .expect("guard should pass");

    let json = serde_json::to_string(&artifact).expect("serialize");
    let roundtrip: frankenengine_engine::slot_registry::GaReleaseGuardArtifact =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact.verdict, roundtrip.verdict);
    assert_eq!(artifact.total_slots, roundtrip.total_slots);
    assert_eq!(
        artifact.blocking_slots.len(),
        roundtrip.blocking_slots.len()
    );
    assert_eq!(artifact.events.len(), roundtrip.events.len());
}

#[test]
fn replacement_progress_snapshot_serde_round_trip() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-parser");
    register_slot(
        &mut registry,
        "interpreter",
        SlotKind::Interpreter,
        "sha256:d-interp",
    );
    promote_slot(&mut registry, &parser, "sha256:n-parser");

    let snapshot = registry
        .snapshot_replacement_progress("trace", "decision", "policy", &BTreeMap::new())
        .expect("snapshot");

    let json = serde_json::to_string(&snapshot).expect("serialize");
    let roundtrip: frankenengine_engine::slot_registry::ReplacementProgressSnapshot =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(snapshot.total_slots, roundtrip.total_slots);
    assert_eq!(snapshot.native_slots, roundtrip.native_slots);
    assert_eq!(snapshot.delegate_slots, roundtrip.delegate_slots);
    assert_eq!(
        snapshot.recommended_replacement_order.len(),
        roundtrip.recommended_replacement_order.len()
    );
}

// ---------------------------------------------------------------------------
// SlotEntry — lineage event receipt IDs
// ---------------------------------------------------------------------------

#[test]
fn lineage_events_have_correct_receipt_ids() {
    let mut registry = SlotRegistry::new();
    let id = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-v1",
    );
    promote_slot(&mut registry, &id, "sha256:native-v1");
    registry
        .demote(&id, "regression".into(), "2026-02-21T01:00:00Z".into())
        .unwrap();

    let entry = registry.get(&id).unwrap();
    // RegisteredDelegate — no receipt
    assert!(entry.promotion_lineage[0].receipt_id.is_none());
    // EnteredCandidacy — no receipt
    assert!(entry.promotion_lineage[1].receipt_id.is_none());
    // PromotedToNative — has receipt
    assert!(entry.promotion_lineage[2].receipt_id.is_some());
    assert!(
        entry.promotion_lineage[2]
            .receipt_id
            .as_ref()
            .unwrap()
            .starts_with("receipt-")
    );
    // DemotedToDelegate — no receipt
    assert!(entry.promotion_lineage[3].receipt_id.is_none());
}

// ---------------------------------------------------------------------------
// GA Release Guard — remediation estimates
// ---------------------------------------------------------------------------

#[test]
fn ga_guard_includes_remediation_estimates_in_slot_statuses() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-parser");
    let builtins = register_slot(
        &mut registry,
        "builtins",
        SlotKind::Builtins,
        "sha256:d-builtins",
    );
    promote_slot(&mut registry, &parser, "sha256:n-parser");

    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    input.lineage_artifacts = vec![lineage_artifact(
        &parser,
        "sha256:d-parser",
        "sha256:n-parser",
    )];
    input
        .remediation_estimates
        .insert(builtins.clone(), "3 weeks".into());

    let artifact = registry
        .evaluate_ga_release_guard(&input)
        .expect("guard should pass");

    let builtins_status = artifact
        .slot_statuses
        .iter()
        .find(|s| s.slot_id == builtins)
        .expect("builtins status");
    assert_eq!(builtins_status.estimated_remediation, "3 weeks");

    // Parser has no estimate — should default to "unknown"
    let parser_status = artifact
        .slot_statuses
        .iter()
        .find(|s| s.slot_id == parser)
        .expect("parser status");
    assert_eq!(parser_status.estimated_remediation, "unknown");
}

// ---------------------------------------------------------------------------
// GA Release Guard — GA guard artifact has correct field values
// ---------------------------------------------------------------------------

#[test]
fn ga_guard_artifact_trace_ids_match_input() {
    let mut registry = SlotRegistry::new();
    register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-parser");

    let input = guard_input(BTreeSet::new(), None);
    let artifact = registry
        .evaluate_ga_release_guard(&input)
        .expect("guard should pass");

    assert_eq!(artifact.trace_id, "trace-integ-001");
    assert_eq!(artifact.decision_id, "decision-integ-001");
    assert_eq!(artifact.policy_id, "policy-integ-001");
    assert_eq!(artifact.component, "ga_release_delegate_guard");
    assert_eq!(
        artifact.lineage_dashboard_ref,
        "frankentui://replacement-lineage/integration-test"
    );
}

// ---------------------------------------------------------------------------
// Registration with all-capabilities authority
// ---------------------------------------------------------------------------

#[test]
fn register_with_all_capabilities_authority() {
    let mut registry = SlotRegistry::new();
    let id = SlotId::new("gc-slot").unwrap();
    let entry = registry
        .register_delegate(
            id.clone(),
            SlotKind::GarbageCollector,
            all_capabilities_authority(),
            "sha256:gc-delegate".into(),
            "2026-02-21T00:00:00Z".into(),
        )
        .unwrap();
    assert_eq!(entry.authority.permitted.len(), 8);
    assert_eq!(entry.authority.required.len(), 8);
    assert!(entry.authority.is_consistent());
}

// ---------------------------------------------------------------------------
// Promotion with exact same authority (not narrower, not broader)
// ---------------------------------------------------------------------------

#[test]
fn promotion_with_equal_authority_succeeds() {
    let mut registry = SlotRegistry::new();
    let id = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-v1",
    );
    registry
        .begin_candidacy(&id, "sha256:cand".into(), "t0".into())
        .unwrap();

    // Promote with same authority as the delegate was registered with
    let result = registry.promote(
        &id,
        "sha256:native-v1".into(),
        &test_authority(),
        "receipt-1".into(),
        "t1".into(),
    );
    assert!(result.is_ok());
    assert!(registry.get(&id).unwrap().status.is_native());
}

// ---------------------------------------------------------------------------
// Default impls
// ---------------------------------------------------------------------------

#[test]
fn slot_registry_default_is_empty() {
    let registry = SlotRegistry::default();
    assert!(registry.is_empty());
    assert_eq!(registry.len(), 0);
}

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

#[test]
fn slot_replacement_signal_default() {
    let signal = SlotReplacementSignal::default();
    assert_eq!(signal.invocation_weight_millionths, 1_000_000);
    assert_eq!(signal.throughput_uplift_millionths, 0);
    assert_eq!(signal.security_risk_reduction_millionths, 0);
}

// ---------------------------------------------------------------------------
// Replacement progress — negative EV scores rank last
// ---------------------------------------------------------------------------

#[test]
fn replacement_progress_negative_ev_ranks_after_positive() {
    let mut registry = SlotRegistry::new();
    let good = register_slot(
        &mut registry,
        "good-slot",
        SlotKind::Parser,
        "sha256:d-good",
    );
    let bad = register_slot(
        &mut registry,
        "bad-slot",
        SlotKind::Interpreter,
        "sha256:d-bad",
    );

    let mut signals = BTreeMap::new();
    // good-slot: positive EV (100k + 200k = 300k)
    signals.insert(
        good,
        SlotReplacementSignal {
            invocation_weight_millionths: 1_000_000,
            throughput_uplift_millionths: 100_000,
            security_risk_reduction_millionths: 200_000,
        },
    );
    // bad-slot: negative EV (-500k + 100k = -400k)
    signals.insert(
        bad,
        SlotReplacementSignal {
            invocation_weight_millionths: 1_000_000,
            throughput_uplift_millionths: -500_000,
            security_risk_reduction_millionths: 100_000,
        },
    );

    let snapshot = registry
        .snapshot_replacement_progress("trace", "decision", "policy", &signals)
        .expect("snapshot");

    assert_eq!(snapshot.recommended_replacement_order.len(), 2);
    assert_eq!(
        snapshot.recommended_replacement_order[0].slot_id.as_str(),
        "good-slot"
    );
    assert!(snapshot.recommended_replacement_order[0].expected_value_score_millionths > 0);
    assert_eq!(
        snapshot.recommended_replacement_order[1].slot_id.as_str(),
        "bad-slot"
    );
    assert!(snapshot.recommended_replacement_order[1].expected_value_score_millionths < 0);
}

// ---------------------------------------------------------------------------
// GA Guard — native coverage millionths in artifact
// ---------------------------------------------------------------------------

#[test]
fn ga_guard_reports_native_coverage_millionths() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-parser");
    register_slot(
        &mut registry,
        "interpreter",
        SlotKind::Interpreter,
        "sha256:d-interp",
    );
    register_slot(
        &mut registry,
        "builtins",
        SlotKind::Builtins,
        "sha256:d-builtins",
    );

    promote_slot(&mut registry, &parser, "sha256:n-parser");

    let input = guard_input(BTreeSet::new(), None);
    let artifact = registry
        .evaluate_ga_release_guard(&input)
        .expect("guard should pass");

    // 1 native out of 3 total = 333_333 millionths
    assert_eq!(artifact.native_coverage_millionths, 333_333);
}

// ---------------------------------------------------------------------------
// GA Guard — lineage artifact field validation
// ---------------------------------------------------------------------------

#[test]
fn ga_guard_rejects_lineage_with_empty_replacement_author() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-parser");
    promote_slot(&mut registry, &parser, "sha256:n-parser");

    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    let mut art = lineage_artifact(&parser, "sha256:d-parser", "sha256:n-parser");
    art.replacement_author = "  ".into();
    input.lineage_artifacts = vec![art];

    let err = registry
        .evaluate_ga_release_guard(&input)
        .expect_err("should fail");
    assert!(matches!(
        err,
        GaReleaseGuardError::InvalidLineageArtifact { detail, .. }
        if detail.contains("replacement_author")
    ));
}

#[test]
fn ga_guard_rejects_lineage_with_empty_lineage_signature() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-parser");
    promote_slot(&mut registry, &parser, "sha256:n-parser");

    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    let mut art = lineage_artifact(&parser, "sha256:d-parser", "sha256:n-parser");
    art.lineage_signature = "".into();
    input.lineage_artifacts = vec![art];

    let err = registry
        .evaluate_ga_release_guard(&input)
        .expect_err("should fail");
    assert!(matches!(
        err,
        GaReleaseGuardError::InvalidLineageArtifact { detail, .. }
        if detail.contains("lineage_signature")
    ));
}

#[test]
fn ga_guard_rejects_lineage_with_empty_trust_anchor_ref() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-parser");
    promote_slot(&mut registry, &parser, "sha256:n-parser");

    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    let mut art = lineage_artifact(&parser, "sha256:d-parser", "sha256:n-parser");
    art.trust_anchor_ref = "".into();
    input.lineage_artifacts = vec![art];

    let err = registry
        .evaluate_ga_release_guard(&input)
        .expect_err("should fail");
    assert!(matches!(
        err,
        GaReleaseGuardError::InvalidLineageArtifact { detail, .. }
        if detail.contains("trust_anchor_ref")
    ));
}

#[test]
fn ga_guard_rejects_lineage_with_empty_equivalence_suite_ref() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-parser");
    promote_slot(&mut registry, &parser, "sha256:n-parser");

    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    let mut art = lineage_artifact(&parser, "sha256:d-parser", "sha256:n-parser");
    art.equivalence_suite_ref = "".into();
    input.lineage_artifacts = vec![art];

    let err = registry
        .evaluate_ga_release_guard(&input)
        .expect_err("should fail");
    assert!(matches!(
        err,
        GaReleaseGuardError::InvalidLineageArtifact { detail, .. }
        if detail.contains("equivalence_suite_ref")
    ));
}

#[test]
fn ga_guard_rejects_lineage_with_empty_replacement_timestamp() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-parser");
    promote_slot(&mut registry, &parser, "sha256:n-parser");

    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    let mut art = lineage_artifact(&parser, "sha256:d-parser", "sha256:n-parser");
    art.replacement_timestamp = "".into();
    input.lineage_artifacts = vec![art];

    let err = registry
        .evaluate_ga_release_guard(&input)
        .expect_err("should fail");
    assert!(matches!(
        err,
        GaReleaseGuardError::InvalidLineageArtifact { detail, .. }
        if detail.contains("replacement_timestamp")
    ));
}

#[test]
fn ga_guard_rejects_lineage_with_empty_replacement_component_digest() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-parser");
    promote_slot(&mut registry, &parser, "sha256:n-parser");

    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    let mut art = lineage_artifact(&parser, "sha256:d-parser", "sha256:n-parser");
    art.replacement_component_digest = "".into();
    input.lineage_artifacts = vec![art];

    let err = registry
        .evaluate_ga_release_guard(&input)
        .expect_err("should fail");
    assert!(matches!(
        err,
        GaReleaseGuardError::InvalidLineageArtifact { detail, .. }
        if detail.contains("replacement_component_digest")
    ));
}
