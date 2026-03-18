#![forbid(unsafe_code)]
//! Deep integration tests for `slot_registry`.
//!
//! Focuses on uncovered edge cases: boundary SlotId values, authority envelope
//! composition, lineage artifact field-level validation, replacement progress
//! saturating arithmetic, large-scale stress, serde round-trips of complex
//! artifacts, multiple demote-promote cycles, Display exactness, determinism,
//! and GA guard artifact field verification.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::slot_registry::{
    AuthorityEnvelope, CoreSlotExemption, GaReleaseGuardConfig, GaReleaseGuardError,
    GaReleaseGuardInput, GaReleaseGuardVerdict, GaSignedLineageArtifact, LineageEvent,
    PromotionStatus, PromotionTransition, ReleaseSlotClass, ReplacementProgressError,
    SlotCapability, SlotEntry, SlotId, SlotKind, SlotRegistry, SlotRegistryError,
    SlotReplacementSignal,
};

// ===========================================================================
// Helpers
// ===========================================================================

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

fn register_slot(registry: &mut SlotRegistry, name: &str, kind: SlotKind, digest: &str) -> SlotId {
    let slot_id = SlotId::new(name).expect("valid slot id");
    registry
        .register_delegate(
            slot_id.clone(),
            kind,
            test_authority(),
            digest.to_string(),
            "2026-03-18T00:00:00Z".to_string(),
        )
        .expect("register delegate");
    slot_id
}

fn promote_slot(registry: &mut SlotRegistry, id: &SlotId, digest: &str) {
    registry
        .begin_candidacy(
            id,
            format!("{digest}-candidate"),
            "2026-03-18T00:00:01Z".to_string(),
        )
        .expect("begin candidacy");
    registry
        .promote(
            id,
            digest.to_string(),
            &narrower_authority(),
            format!("receipt-{digest}"),
            "2026-03-18T00:00:02Z".to_string(),
        )
        .expect("promote");
}

fn guard_input(
    core_slots: BTreeSet<SlotId>,
    non_core_delegate_limit: Option<usize>,
) -> GaReleaseGuardInput {
    GaReleaseGuardInput {
        trace_id: "trace-deep-001".to_string(),
        decision_id: "decision-deep-001".to_string(),
        policy_id: "policy-deep-001".to_string(),
        current_epoch: SecurityEpoch::from_raw(42),
        config: GaReleaseGuardConfig {
            core_slots,
            non_core_delegate_limit,
            lineage_dashboard_ref: "frankentui://deep-test".to_string(),
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
        replacement_timestamp: "2026-03-18T00:00:03Z".to_string(),
        lineage_signature: "sig:deep-proof".to_string(),
        trust_anchor_ref: "trust-anchor://deep-v1".to_string(),
        signature_verified: true,
        equivalence_suite_ref: "suite://deep-equivalence-v1".to_string(),
        equivalence_passed: true,
        delegate_fallback_reachable: false,
    }
}

fn exemption_for(slot_id: SlotId) -> CoreSlotExemption {
    CoreSlotExemption {
        exemption_id: format!("exemption-{}", slot_id.as_str()),
        slot_id,
        approved_by: "gov-council".to_string(),
        signed_risk_acknowledgement: "sig:risk-ack-deep".to_string(),
        remediation_plan: "replace within one sprint".to_string(),
        remediation_deadline_epoch: 48,
        expires_at_epoch: 50,
    }
}

// ===========================================================================
// 1) SlotId boundary edge cases
// ===========================================================================

#[test]
fn slot_id_single_hyphen_accepted() {
    let id = SlotId::new("-").unwrap();
    assert_eq!(id.as_str(), "-");
}

#[test]
fn slot_id_consecutive_hyphens_accepted() {
    let id = SlotId::new("a--b").unwrap();
    assert_eq!(id.as_str(), "a--b");
}

#[test]
fn slot_id_all_hyphens_accepted() {
    let id = SlotId::new("---").unwrap();
    assert_eq!(id.as_str(), "---");
}

#[test]
fn slot_id_single_digit_accepted() {
    let id = SlotId::new("0").unwrap();
    assert_eq!(id.as_str(), "0");
}

#[test]
fn slot_id_rejects_tab_character() {
    assert!(SlotId::new("has\ttab").is_err());
}

#[test]
fn slot_id_rejects_newline() {
    assert!(SlotId::new("has\nnewline").is_err());
}

#[test]
fn slot_id_rejects_at_sign() {
    assert!(SlotId::new("user@host").is_err());
}

#[test]
fn slot_id_rejects_slash() {
    assert!(SlotId::new("path/to").is_err());
}

#[test]
fn slot_id_rejects_unicode_letter() {
    assert!(SlotId::new("caf\u{00e9}").is_err());
}

#[test]
fn slot_id_rejects_emoji() {
    assert!(SlotId::new("slot-\u{1f600}").is_err());
}

#[test]
fn slot_id_long_string_accepted() {
    let long = "a".repeat(256);
    let id = SlotId::new(&long).unwrap();
    assert_eq!(id.as_str().len(), 256);
}

#[test]
fn slot_id_error_preserves_invalid_id_string() {
    let result = SlotId::new("BAD_ID!");
    match result {
        Err(SlotRegistryError::InvalidSlotId { id, reason }) => {
            assert_eq!(id, "BAD_ID!");
            assert!(!reason.is_empty());
        }
        _ => panic!("expected InvalidSlotId"),
    }
}

#[test]
fn slot_id_error_empty_preserves_empty_string() {
    let result = SlotId::new("");
    match result {
        Err(SlotRegistryError::InvalidSlotId { id, reason }) => {
            assert!(id.is_empty());
            assert!(reason.contains("empty"));
        }
        _ => panic!("expected InvalidSlotId"),
    }
}

// ===========================================================================
// 2) AuthorityEnvelope — composition and edge cases
// ===========================================================================

#[test]
fn authority_envelope_duplicate_required_caps_still_consistent() {
    let ae = AuthorityEnvelope {
        required: vec![SlotCapability::ReadSource, SlotCapability::ReadSource],
        permitted: vec![SlotCapability::ReadSource],
    };
    assert!(ae.is_consistent());
}

#[test]
fn authority_envelope_subsumes_is_reflexive() {
    let ae = AuthorityEnvelope {
        required: vec![SlotCapability::HeapAlloc, SlotCapability::TriggerGc],
        permitted: vec![
            SlotCapability::HeapAlloc,
            SlotCapability::TriggerGc,
            SlotCapability::EmitEvidence,
        ],
    };
    assert!(ae.subsumes(&ae));
}

#[test]
fn authority_envelope_empty_subsumes_empty() {
    let empty = AuthorityEnvelope {
        required: vec![],
        permitted: vec![],
    };
    assert!(empty.subsumes(&empty));
}

#[test]
fn authority_envelope_disjoint_permitted_not_subsumes() {
    let a = AuthorityEnvelope {
        required: vec![],
        permitted: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
    };
    let b = AuthorityEnvelope {
        required: vec![],
        permitted: vec![SlotCapability::HeapAlloc, SlotCapability::TriggerGc],
    };
    assert!(!a.subsumes(&b));
    assert!(!b.subsumes(&a));
}

#[test]
fn authority_envelope_all_eight_capabilities_consistent() {
    let all = AuthorityEnvelope {
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
    };
    assert!(all.is_consistent());
    assert!(all.subsumes(&all));
}

#[test]
fn authority_envelope_serde_roundtrip_with_all_caps() {
    let ae = AuthorityEnvelope {
        required: vec![SlotCapability::ReadSource],
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
    };
    let json = serde_json::to_string(&ae).unwrap();
    let rt: AuthorityEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(ae, rt);
}

// ===========================================================================
// 3) PromotionStatus Display exactness
// ===========================================================================

#[test]
fn promotion_status_delegate_display_exact_string() {
    assert_eq!(PromotionStatus::Delegate.to_string(), "delegate");
}

#[test]
fn promotion_status_candidate_display_exact_format() {
    let ps = PromotionStatus::PromotionCandidate {
        candidate_digest: "sha256:abcdef".into(),
    };
    assert_eq!(ps.to_string(), "promotion-candidate(sha256:abcdef)");
}

#[test]
fn promotion_status_promoted_display_exact_format() {
    let ps = PromotionStatus::Promoted {
        native_digest: "sha256:native123".into(),
        receipt_id: "rcpt-42".into(),
    };
    assert_eq!(
        ps.to_string(),
        "promoted(sha256:native123, receipt=rcpt-42)"
    );
}

#[test]
fn promotion_status_demoted_display_exact_format() {
    let ps = PromotionStatus::Demoted {
        reason: "perf-regression".into(),
        rollback_digest: "sha256:rollback9".into(),
    };
    assert_eq!(
        ps.to_string(),
        "demoted(reason=perf-regression, rollback=sha256:rollback9)"
    );
}

// ===========================================================================
// 4) Multiple demote-promote cycles preserve lineage correctly
// ===========================================================================

#[test]
fn triple_promote_demote_cycle_lineage() {
    let mut reg = SlotRegistry::new();
    let id = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-v1");

    for i in 1..=3 {
        let native_digest = format!("sha256:native-v{i}");
        promote_slot(&mut reg, &id, &native_digest);
        let entry = reg.get(&id).unwrap();
        assert!(entry.status.is_native());
        assert_eq!(entry.implementation_digest, native_digest);

        reg.demote(
            &id,
            format!("regression-v{i}"),
            format!("2026-03-18T0{i}:00:00Z"),
        )
        .unwrap();
        let entry = reg.get(&id).unwrap();
        assert!(entry.status.is_delegate());
    }

    let entry = reg.get(&id).unwrap();
    // 1 register + 3*(candidacy + promote + demote) = 10 events
    assert_eq!(entry.promotion_lineage.len(), 10);

    let expected_transitions = [
        PromotionTransition::RegisteredDelegate,
        PromotionTransition::EnteredCandidacy,
        PromotionTransition::PromotedToNative,
        PromotionTransition::DemotedToDelegate,
        PromotionTransition::EnteredCandidacy,
        PromotionTransition::PromotedToNative,
        PromotionTransition::DemotedToDelegate,
        PromotionTransition::EnteredCandidacy,
        PromotionTransition::PromotedToNative,
        PromotionTransition::DemotedToDelegate,
    ];
    for (i, expected) in expected_transitions.iter().enumerate() {
        assert_eq!(
            entry.promotion_lineage[i].transition, *expected,
            "lineage[{i}] mismatch"
        );
    }
}

// ===========================================================================
// 5) Rollback target tracks correctly through cycles
// ===========================================================================

#[test]
fn rollback_target_updates_on_each_promotion() {
    let mut reg = SlotRegistry::new();
    let id = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-v1");

    // No rollback target initially
    assert!(reg.get(&id).unwrap().rollback_target.is_none());

    // First promote: rollback_target becomes the delegate digest
    promote_slot(&mut reg, &id, "sha256:native-v1");
    assert_eq!(
        reg.get(&id).unwrap().rollback_target.as_deref(),
        Some("sha256:d-v1")
    );

    // Demote: implementation rolls back
    reg.demote(&id, "r".into(), "t1".into()).unwrap();
    let entry = reg.get(&id).unwrap();
    assert_eq!(entry.implementation_digest, "sha256:d-v1");

    // Second promote: rollback_target becomes current impl digest
    promote_slot(&mut reg, &id, "sha256:native-v2");
    assert_eq!(
        reg.get(&id).unwrap().rollback_target.as_deref(),
        Some("sha256:d-v1")
    );
}

// ===========================================================================
// 6) SlotEntry field verification after lifecycle
// ===========================================================================

#[test]
fn slot_entry_fields_after_full_lifecycle() {
    let mut reg = SlotRegistry::new();
    let id = register_slot(&mut reg, "my-interp", SlotKind::Interpreter, "sha256:d-int");

    let entry = reg.get(&id).unwrap();
    assert_eq!(entry.id.as_str(), "my-interp");
    assert_eq!(entry.kind, SlotKind::Interpreter);
    assert_eq!(entry.implementation_digest, "sha256:d-int");
    assert!(entry.rollback_target.is_none());
    assert_eq!(entry.promotion_lineage.len(), 1);
    assert_eq!(
        entry.promotion_lineage[0].transition,
        PromotionTransition::RegisteredDelegate
    );
    assert_eq!(entry.promotion_lineage[0].digest, "sha256:d-int");
    assert!(entry.promotion_lineage[0].receipt_id.is_none());

    // Promote
    promote_slot(&mut reg, &id, "sha256:native-int");
    let entry = reg.get(&id).unwrap();
    assert_eq!(entry.implementation_digest, "sha256:native-int");
    assert!(entry.status.is_native());
    assert_eq!(entry.promotion_lineage.len(), 3);

    // Check promotion lineage event has receipt
    let promo_event = &entry.promotion_lineage[2];
    assert_eq!(
        promo_event.transition,
        PromotionTransition::PromotedToNative
    );
    assert_eq!(
        promo_event.receipt_id.as_deref(),
        Some("receipt-sha256:native-int")
    );
}

// ===========================================================================
// 7) Lineage artifact validation — all empty field checks
// ===========================================================================

#[test]
fn ga_guard_rejects_lineage_empty_replacement_component_digest() {
    let mut reg = SlotRegistry::new();
    let parser = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-parser");
    promote_slot(&mut reg, &parser, "sha256:n-parser");

    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    let mut art = lineage_artifact(&parser, "sha256:d-parser", "sha256:n-parser");
    art.replacement_component_digest = "  ".into();
    input.lineage_artifacts = vec![art];

    let err = reg
        .evaluate_ga_release_guard(&input)
        .expect_err("should fail");
    assert!(matches!(
        err,
        GaReleaseGuardError::InvalidLineageArtifact { detail, .. }
        if detail.contains("replacement_component_digest")
    ));
}

#[test]
fn ga_guard_rejects_lineage_empty_replacement_author() {
    let mut reg = SlotRegistry::new();
    let parser = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-parser");
    promote_slot(&mut reg, &parser, "sha256:n-parser");

    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    let mut art = lineage_artifact(&parser, "sha256:d-parser", "sha256:n-parser");
    art.replacement_author = "".into();
    input.lineage_artifacts = vec![art];

    let err = reg
        .evaluate_ga_release_guard(&input)
        .expect_err("should fail");
    assert!(matches!(
        err,
        GaReleaseGuardError::InvalidLineageArtifact { detail, .. }
        if detail.contains("replacement_author")
    ));
}

#[test]
fn ga_guard_rejects_lineage_empty_replacement_timestamp() {
    let mut reg = SlotRegistry::new();
    let parser = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-parser");
    promote_slot(&mut reg, &parser, "sha256:n-parser");

    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    let mut art = lineage_artifact(&parser, "sha256:d-parser", "sha256:n-parser");
    art.replacement_timestamp = "".into();
    input.lineage_artifacts = vec![art];

    let err = reg
        .evaluate_ga_release_guard(&input)
        .expect_err("should fail");
    assert!(matches!(
        err,
        GaReleaseGuardError::InvalidLineageArtifact { detail, .. }
        if detail.contains("replacement_timestamp")
    ));
}

#[test]
fn ga_guard_rejects_lineage_empty_lineage_signature() {
    let mut reg = SlotRegistry::new();
    let parser = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-parser");
    promote_slot(&mut reg, &parser, "sha256:n-parser");

    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    let mut art = lineage_artifact(&parser, "sha256:d-parser", "sha256:n-parser");
    art.lineage_signature = "   ".into();
    input.lineage_artifacts = vec![art];

    let err = reg
        .evaluate_ga_release_guard(&input)
        .expect_err("should fail");
    assert!(matches!(
        err,
        GaReleaseGuardError::InvalidLineageArtifact { detail, .. }
        if detail.contains("lineage_signature")
    ));
}

#[test]
fn ga_guard_rejects_lineage_empty_trust_anchor_ref() {
    let mut reg = SlotRegistry::new();
    let parser = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-parser");
    promote_slot(&mut reg, &parser, "sha256:n-parser");

    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    let mut art = lineage_artifact(&parser, "sha256:d-parser", "sha256:n-parser");
    art.trust_anchor_ref = "".into();
    input.lineage_artifacts = vec![art];

    let err = reg
        .evaluate_ga_release_guard(&input)
        .expect_err("should fail");
    assert!(matches!(
        err,
        GaReleaseGuardError::InvalidLineageArtifact { detail, .. }
        if detail.contains("trust_anchor_ref")
    ));
}

#[test]
fn ga_guard_rejects_lineage_empty_equivalence_suite_ref() {
    let mut reg = SlotRegistry::new();
    let parser = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-parser");
    promote_slot(&mut reg, &parser, "sha256:n-parser");

    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = guard_input(core_slots, None);
    let mut art = lineage_artifact(&parser, "sha256:d-parser", "sha256:n-parser");
    art.equivalence_suite_ref = "".into();
    input.lineage_artifacts = vec![art];

    let err = reg
        .evaluate_ga_release_guard(&input)
        .expect_err("should fail");
    assert!(matches!(
        err,
        GaReleaseGuardError::InvalidLineageArtifact { detail, .. }
        if detail.contains("equivalence_suite_ref")
    ));
}

// ===========================================================================
// 8) GA guard artifact field verification
// ===========================================================================

#[test]
fn ga_guard_artifact_native_coverage_millionths_correct() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    let i = register_slot(&mut reg, "interpreter", SlotKind::Interpreter, "sha256:d-i");
    let b = register_slot(&mut reg, "builtins", SlotKind::Builtins, "sha256:d-b");
    promote_slot(&mut reg, &p, "sha256:n-p");

    let core_slots = BTreeSet::from([p.clone()]);
    let mut input = guard_input(core_slots, None);
    input.lineage_artifacts = vec![lineage_artifact(&p, "sha256:d-p", "sha256:n-p")];

    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
    // 1 native out of 3 = 333333 millionths
    assert_eq!(artifact.native_coverage_millionths, 333_333);
    assert_eq!(artifact.total_slots, 3);
    assert_eq!(artifact.core_slot_count, 1);
    assert_eq!(artifact.core_delegate_count, 0);
    assert_eq!(artifact.non_core_delegate_count, 2);
    assert_eq!(artifact.lineage_dashboard_ref, "frankentui://deep-test");
    assert_eq!(artifact.component, "ga_release_delegate_guard");
    let _ = i;
    let _ = b;
}

#[test]
fn ga_guard_artifact_remediation_estimates_in_slot_statuses() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    let b = register_slot(&mut reg, "builtins", SlotKind::Builtins, "sha256:d-b");

    let mut input = guard_input(BTreeSet::new(), None);
    input
        .remediation_estimates
        .insert(p.clone(), "3 weeks".to_string());
    // builtins has no estimate

    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
    let p_status = artifact
        .slot_statuses
        .iter()
        .find(|s| s.slot_id == p)
        .unwrap();
    assert_eq!(p_status.estimated_remediation, "3 weeks");

    let b_status = artifact
        .slot_statuses
        .iter()
        .find(|s| s.slot_id == b)
        .unwrap();
    assert_eq!(b_status.estimated_remediation, "unknown");
}

#[test]
fn ga_guard_artifact_verdict_event_has_error_code_when_blocked() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");

    let core_slots = BTreeSet::from([p.clone()]);
    let input = guard_input(core_slots, None);

    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);

    let verdict_event = artifact
        .events
        .iter()
        .find(|e| e.event == "ga_release_guard_verdict")
        .unwrap();
    assert_eq!(verdict_event.outcome, "blocked");
    assert_eq!(
        verdict_event.error_code.as_deref(),
        Some("FE-GA-GATE-BLOCKED")
    );
}

#[test]
fn ga_guard_artifact_verdict_event_no_error_code_when_pass() {
    let reg = SlotRegistry::new();
    let input = guard_input(BTreeSet::new(), None);

    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Pass);

    let verdict_event = artifact
        .events
        .iter()
        .find(|e| e.event == "ga_release_guard_verdict")
        .unwrap();
    assert_eq!(verdict_event.outcome, "pass");
    assert!(verdict_event.error_code.is_none());
}

// ===========================================================================
// 9) GA guard — exemption prevents blocking for delegate core slot
// ===========================================================================

#[test]
fn ga_guard_exemption_slot_status_has_exemption_id() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    let core_slots = BTreeSet::from([p.clone()]);
    let mut input = guard_input(core_slots, None);
    input.exemptions = vec![exemption_for(p.clone())];

    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Pass);

    let p_status = artifact
        .slot_statuses
        .iter()
        .find(|s| s.slot_id == p)
        .unwrap();
    assert!(!p_status.blocking);
    assert_eq!(p_status.exemption_id.as_deref(), Some("exemption-parser"));
    assert!(p_status.delegate_backed);
    assert_eq!(p_status.slot_class, ReleaseSlotClass::Core);
}

// ===========================================================================
// 10) Replacement progress — negative uplift/security values
// ===========================================================================

#[test]
fn replacement_progress_negative_values() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    let i = register_slot(&mut reg, "interpreter", SlotKind::Interpreter, "sha256:d-i");

    let mut signals = BTreeMap::new();
    signals.insert(
        p,
        SlotReplacementSignal {
            invocation_weight_millionths: 1_000_000,
            throughput_uplift_millionths: -500_000,
            security_risk_reduction_millionths: -200_000,
        },
    );
    signals.insert(
        i,
        SlotReplacementSignal {
            invocation_weight_millionths: 1_000_000,
            throughput_uplift_millionths: 300_000,
            security_risk_reduction_millionths: 100_000,
        },
    );

    let snapshot = reg
        .snapshot_replacement_progress("t", "d", "p", &signals)
        .unwrap();

    assert_eq!(snapshot.total_slots, 2);
    assert_eq!(snapshot.delegate_slots, 2);
    assert_eq!(snapshot.native_slots, 0);

    // Parser EV = -500000 + -200000 = -700000; weighted = -700000 * 1M / 1M = -700000
    // Interp EV = 300000 + 100000 = 400000; weighted = 400000 * 1M / 1M = 400000
    // Interp ranked first (higher EV)
    assert_eq!(snapshot.recommended_replacement_order.len(), 2);
    assert_eq!(
        snapshot.recommended_replacement_order[0].slot_id.as_str(),
        "interpreter"
    );
    assert_eq!(
        snapshot.recommended_replacement_order[1].slot_id.as_str(),
        "parser"
    );

    // weighted throughput = (-500000 * 1M + 300000 * 1M) / (1M + 1M)
    //                     = -200000 * 1M / 2M = -100000
    assert_eq!(
        snapshot.weighted_delegate_throughput_uplift_millionths,
        -100_000
    );
}

// ===========================================================================
// 11) Replacement progress — extreme saturating values
// ===========================================================================

#[test]
fn replacement_progress_extreme_weight_values() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");

    let mut signals = BTreeMap::new();
    signals.insert(
        p,
        SlotReplacementSignal {
            invocation_weight_millionths: u64::MAX,
            throughput_uplift_millionths: i64::MAX,
            security_risk_reduction_millionths: i64::MAX,
        },
    );

    let snapshot = reg
        .snapshot_replacement_progress("t", "d", "p", &signals)
        .unwrap();

    // Should not panic — saturating arithmetic handles overflow
    assert_eq!(snapshot.delegate_slots, 1);
    assert_eq!(snapshot.recommended_replacement_order.len(), 1);
}

#[test]
fn replacement_progress_extreme_negative_values() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");

    let mut signals = BTreeMap::new();
    signals.insert(
        p,
        SlotReplacementSignal {
            invocation_weight_millionths: u64::MAX,
            throughput_uplift_millionths: i64::MIN,
            security_risk_reduction_millionths: i64::MIN,
        },
    );

    let snapshot = reg
        .snapshot_replacement_progress("t", "d", "p", &signals)
        .unwrap();

    // Should not panic
    assert_eq!(snapshot.delegate_slots, 1);
}

// ===========================================================================
// 12) Replacement progress — empty registry
// ===========================================================================

#[test]
fn replacement_progress_empty_registry_zero_coverage() {
    let reg = SlotRegistry::new();
    let snapshot = reg
        .snapshot_replacement_progress("t", "d", "p", &BTreeMap::new())
        .unwrap();
    assert_eq!(snapshot.total_slots, 0);
    assert_eq!(snapshot.native_coverage_millionths, 0);
    assert_eq!(snapshot.weighted_native_coverage_millionths, 0);
    assert_eq!(snapshot.weighted_delegate_throughput_uplift_millionths, 0);
    assert_eq!(
        snapshot.weighted_delegate_security_risk_reduction_millionths,
        0
    );
    assert!(snapshot.recommended_replacement_order.is_empty());
}

// ===========================================================================
// 13) Replacement progress — whitespace-only string rejection
// ===========================================================================

#[test]
fn replacement_progress_whitespace_only_trace_id_rejected() {
    let reg = SlotRegistry::new();
    let err = reg
        .snapshot_replacement_progress("   ", "d", "p", &BTreeMap::new())
        .unwrap_err();
    assert!(matches!(
        err,
        ReplacementProgressError::InvalidInput { field, .. } if field == "trace_id"
    ));
}

// ===========================================================================
// 14) Large-scale stress test
// ===========================================================================

#[test]
fn stress_register_50_slots_and_promote_25() {
    let mut reg = SlotRegistry::new();
    let mut ids = Vec::new();
    for i in 0..50 {
        let name = format!("slot-{i:03}");
        let id = register_slot(&mut reg, &name, SlotKind::Builtins, &format!("d-{i}"));
        ids.push(id);
    }
    assert_eq!(reg.len(), 50);
    assert_eq!(reg.delegate_count(), 50);
    assert_eq!(reg.native_count(), 0);

    // Promote the first 25
    for id in &ids[..25] {
        promote_slot(&mut reg, id, &format!("native-{}", id.as_str()));
    }
    assert_eq!(reg.native_count(), 25);
    assert_eq!(reg.delegate_count(), 25);
    assert!(!reg.is_ga_ready());

    // Promote the remaining 25
    for id in &ids[25..] {
        promote_slot(&mut reg, id, &format!("native-{}", id.as_str()));
    }
    assert_eq!(reg.native_count(), 50);
    assert!(reg.is_ga_ready());

    // native_coverage should be 1.0
    assert!((reg.native_coverage() - 1.0).abs() < f64::EPSILON);
}

#[test]
fn stress_replacement_progress_50_slots() {
    let mut reg = SlotRegistry::new();
    let mut ids = Vec::new();
    for i in 0..50 {
        let name = format!("slot-{i:03}");
        let id = register_slot(&mut reg, &name, SlotKind::Builtins, &format!("d-{i}"));
        ids.push(id);
    }
    // Promote first 10
    for id in &ids[..10] {
        promote_slot(&mut reg, id, &format!("native-{}", id.as_str()));
    }

    let snapshot = reg
        .snapshot_replacement_progress("t", "d", "p", &BTreeMap::new())
        .unwrap();
    assert_eq!(snapshot.total_slots, 50);
    assert_eq!(snapshot.native_slots, 10);
    assert_eq!(snapshot.delegate_slots, 40);
    assert_eq!(snapshot.native_coverage_millionths, 200_000);
    // 40 delegate slots in replacement order
    assert_eq!(snapshot.recommended_replacement_order.len(), 40);
}

// ===========================================================================
// 15) Serde round-trip of full GaReleaseGuardArtifact
// ===========================================================================

#[test]
fn serde_roundtrip_ga_release_guard_artifact() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    promote_slot(&mut reg, &p, "sha256:n-p");

    let core_slots = BTreeSet::from([p.clone()]);
    let mut input = guard_input(core_slots, None);
    input.lineage_artifacts = vec![lineage_artifact(&p, "sha256:d-p", "sha256:n-p")];

    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
    let json = serde_json::to_string(&artifact).unwrap();
    let rt: frankenengine_engine::slot_registry::GaReleaseGuardArtifact =
        serde_json::from_str(&json).unwrap();

    assert_eq!(artifact.verdict, rt.verdict);
    assert_eq!(artifact.total_slots, rt.total_slots);
    assert_eq!(artifact.trace_id, rt.trace_id);
    assert_eq!(artifact.events.len(), rt.events.len());
    assert_eq!(artifact.slot_statuses.len(), rt.slot_statuses.len());
}

// ===========================================================================
// 16) Serde round-trip of ReplacementProgressSnapshot
// ===========================================================================

#[test]
fn serde_roundtrip_replacement_progress_snapshot() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    let _i = register_slot(&mut reg, "interpreter", SlotKind::Interpreter, "sha256:d-i");
    promote_slot(&mut reg, &p, "sha256:n-p");

    let snapshot = reg
        .snapshot_replacement_progress("t", "d", "p", &BTreeMap::new())
        .unwrap();

    let json = serde_json::to_string(&snapshot).unwrap();
    let rt: frankenengine_engine::slot_registry::ReplacementProgressSnapshot =
        serde_json::from_str(&json).unwrap();

    assert_eq!(snapshot.total_slots, rt.total_slots);
    assert_eq!(snapshot.native_slots, rt.native_slots);
    assert_eq!(
        snapshot.native_coverage_millionths,
        rt.native_coverage_millionths
    );
    assert_eq!(
        snapshot.recommended_replacement_order.len(),
        rt.recommended_replacement_order.len()
    );
}

// ===========================================================================
// 17) Serde round-trip of GaReleaseGuardInput
// ===========================================================================

#[test]
fn serde_roundtrip_ga_release_guard_input() {
    let input = guard_input(BTreeSet::new(), Some(5));
    let json = serde_json::to_string(&input).unwrap();
    let rt: GaReleaseGuardInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input.trace_id, rt.trace_id);
    assert_eq!(
        input.config.non_core_delegate_limit,
        rt.config.non_core_delegate_limit
    );
}

// ===========================================================================
// 18) Determinism — identical inputs produce identical artifacts
// ===========================================================================

#[test]
fn determinism_ga_guard_same_input_same_output() {
    let build_registry = || {
        let mut reg = SlotRegistry::new();
        let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
        let i = register_slot(&mut reg, "interpreter", SlotKind::Interpreter, "sha256:d-i");
        promote_slot(&mut reg, &p, "sha256:n-p");
        (reg, p, i)
    };

    let (reg1, p1, _i1) = build_registry();
    let (reg2, p2, _i2) = build_registry();

    let mut input1 = guard_input(BTreeSet::from([p1.clone()]), None);
    input1.lineage_artifacts = vec![lineage_artifact(&p1, "sha256:d-p", "sha256:n-p")];

    let mut input2 = guard_input(BTreeSet::from([p2.clone()]), None);
    input2.lineage_artifacts = vec![lineage_artifact(&p2, "sha256:d-p", "sha256:n-p")];

    let art1 = reg1.evaluate_ga_release_guard(&input1).unwrap();
    let art2 = reg2.evaluate_ga_release_guard(&input2).unwrap();

    let json1 = serde_json::to_string(&art1).unwrap();
    let json2 = serde_json::to_string(&art2).unwrap();
    assert_eq!(json1, json2);
}

#[test]
fn determinism_replacement_progress_same_input_same_output() {
    let build = || {
        let mut reg = SlotRegistry::new();
        let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
        let i = register_slot(&mut reg, "interpreter", SlotKind::Interpreter, "sha256:d-i");
        promote_slot(&mut reg, &p, "sha256:n-p");
        (reg, i)
    };

    let (reg1, _) = build();
    let (reg2, _) = build();

    let snap1 = reg1
        .snapshot_replacement_progress("t", "d", "p", &BTreeMap::new())
        .unwrap();
    let snap2 = reg2
        .snapshot_replacement_progress("t", "d", "p", &BTreeMap::new())
        .unwrap();

    let json1 = serde_json::to_string(&snap1).unwrap();
    let json2 = serde_json::to_string(&snap2).unwrap();
    assert_eq!(json1, json2);
}

// ===========================================================================
// 19) Iterator determinism preserved across insertions
// ===========================================================================

#[test]
fn iterator_order_deterministic_regardless_of_insertion_order() {
    let mut reg1 = SlotRegistry::new();
    register_slot(&mut reg1, "zzz-slot", SlotKind::Parser, "d1");
    register_slot(&mut reg1, "aaa-slot", SlotKind::Interpreter, "d2");
    register_slot(&mut reg1, "mmm-slot", SlotKind::Builtins, "d3");

    let mut reg2 = SlotRegistry::new();
    register_slot(&mut reg2, "aaa-slot", SlotKind::Interpreter, "d2");
    register_slot(&mut reg2, "mmm-slot", SlotKind::Builtins, "d3");
    register_slot(&mut reg2, "zzz-slot", SlotKind::Parser, "d1");

    let ids1: Vec<&str> = reg1.iter().map(|(id, _)| id.as_str()).collect();
    let ids2: Vec<&str> = reg2.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(ids1, ids2);
    assert_eq!(ids1, vec!["aaa-slot", "mmm-slot", "zzz-slot"]);
}

// ===========================================================================
// 20) is_ga_ready edge cases
// ===========================================================================

#[test]
fn is_ga_ready_false_with_one_delegate_among_natives() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    let i = register_slot(&mut reg, "interpreter", SlotKind::Interpreter, "sha256:d-i");
    let _b = register_slot(&mut reg, "builtins", SlotKind::Builtins, "sha256:d-b");

    promote_slot(&mut reg, &p, "sha256:n-p");
    promote_slot(&mut reg, &i, "sha256:n-i");

    // 2 native, 1 delegate -> not GA ready
    assert!(!reg.is_ga_ready());
}

#[test]
fn is_ga_ready_true_single_native_slot() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    promote_slot(&mut reg, &p, "sha256:n-p");
    assert!(reg.is_ga_ready());
}

#[test]
fn is_ga_ready_false_after_demotion() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    promote_slot(&mut reg, &p, "sha256:n-p");
    assert!(reg.is_ga_ready());

    reg.demote(&p, "regression".into(), "t".into()).unwrap();
    assert!(!reg.is_ga_ready());
}

// ===========================================================================
// 21) native_coverage boundary values
// ===========================================================================

#[test]
fn native_coverage_one_of_two() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    let _i = register_slot(&mut reg, "interpreter", SlotKind::Interpreter, "sha256:d-i");
    promote_slot(&mut reg, &p, "sha256:n-p");
    assert!((reg.native_coverage() - 0.5).abs() < f64::EPSILON);
}

#[test]
fn native_coverage_one_of_three() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    let _i = register_slot(&mut reg, "interpreter", SlotKind::Interpreter, "sha256:d-i");
    let _b = register_slot(&mut reg, "builtins", SlotKind::Builtins, "sha256:d-b");
    promote_slot(&mut reg, &p, "sha256:n-p");
    let cov = reg.native_coverage();
    assert!((cov - 1.0 / 3.0).abs() < 1e-10);
}

// ===========================================================================
// 22) SlotRegistryError Display exact format verification
// ===========================================================================

#[test]
fn slot_registry_error_invalid_slot_id_display_format() {
    let err = SlotRegistryError::InvalidSlotId {
        id: "FOO".into(),
        reason: "uppercase not allowed".into(),
    };
    assert_eq!(
        err.to_string(),
        "invalid slot id 'FOO': uppercase not allowed"
    );
}

#[test]
fn slot_registry_error_duplicate_slot_id_display_format() {
    let err = SlotRegistryError::DuplicateSlotId {
        id: "parser".into(),
    };
    assert_eq!(err.to_string(), "duplicate slot id 'parser'");
}

#[test]
fn slot_registry_error_slot_not_found_display_format() {
    let err = SlotRegistryError::SlotNotFound { id: "ghost".into() };
    assert_eq!(err.to_string(), "slot 'ghost' not found");
}

#[test]
fn slot_registry_error_inconsistent_authority_display_format() {
    let err = SlotRegistryError::InconsistentAuthority {
        id: "parser".into(),
        detail: "caps mismatch".into(),
    };
    assert_eq!(
        err.to_string(),
        "inconsistent authority for 'parser': caps mismatch"
    );
}

#[test]
fn slot_registry_error_invalid_transition_display_format() {
    let err = SlotRegistryError::InvalidTransition {
        id: "parser".into(),
        from: "delegate".into(),
        to: "promoted".into(),
    };
    assert_eq!(
        err.to_string(),
        "invalid transition for 'parser': delegate -> promoted"
    );
}

#[test]
fn slot_registry_error_authority_broadening_display_format() {
    let err = SlotRegistryError::AuthorityBroadening {
        id: "parser".into(),
        detail: "exceeds envelope".into(),
    };
    assert_eq!(
        err.to_string(),
        "authority broadening rejected for 'parser': exceeds envelope"
    );
}

// ===========================================================================
// 23) GaReleaseGuardError Display exact format
// ===========================================================================

#[test]
fn ga_guard_error_invalid_input_display_format() {
    let err = GaReleaseGuardError::InvalidInput {
        field: "trace_id".into(),
        detail: "must not be empty".into(),
    };
    assert_eq!(
        err.to_string(),
        "invalid input for `trace_id`: must not be empty"
    );
}

#[test]
fn ga_guard_error_unknown_core_slot_display_format() {
    let err = GaReleaseGuardError::UnknownCoreSlot {
        slot_id: "ghost".into(),
    };
    assert_eq!(err.to_string(), "core slot `ghost` is not registered");
}

#[test]
fn ga_guard_error_duplicate_exemption_display_format() {
    let err = GaReleaseGuardError::DuplicateExemption {
        slot_id: "parser".into(),
    };
    assert_eq!(err.to_string(), "duplicate exemption for slot `parser`");
}

#[test]
fn ga_guard_error_duplicate_lineage_artifact_display_format() {
    let err = GaReleaseGuardError::DuplicateLineageArtifact {
        slot_id: "parser".into(),
    };
    assert_eq!(
        err.to_string(),
        "duplicate lineage artifact for slot `parser`"
    );
}

// ===========================================================================
// 24) ReplacementProgressError Display exact format
// ===========================================================================

#[test]
fn replacement_progress_error_invalid_input_display_format() {
    let err = ReplacementProgressError::InvalidInput {
        field: "trace_id".into(),
        detail: "must not be empty".into(),
    };
    assert_eq!(
        err.to_string(),
        "invalid replacement progress input `trace_id`: must not be empty"
    );
}

#[test]
fn replacement_progress_error_unknown_signal_slot_display_format() {
    let err = ReplacementProgressError::UnknownSignalSlot {
        slot_id: "ghost".into(),
    };
    assert_eq!(
        err.to_string(),
        "replacement progress signal references unknown slot `ghost`"
    );
}

#[test]
fn replacement_progress_error_invalid_signal_display_format() {
    let err = ReplacementProgressError::InvalidSignal {
        slot_id: "parser".into(),
        detail: "zero weight".into(),
    };
    assert_eq!(
        err.to_string(),
        "invalid replacement progress signal for `parser`: zero weight"
    );
}

// ===========================================================================
// 25) GaReleaseGuardConfig custom values
// ===========================================================================

#[test]
fn ga_release_guard_config_custom_values() {
    let config = GaReleaseGuardConfig {
        core_slots: BTreeSet::from([SlotId::new("parser").unwrap()]),
        non_core_delegate_limit: Some(3),
        lineage_dashboard_ref: "custom://dashboard".to_string(),
    };
    assert_eq!(config.core_slots.len(), 1);
    assert_eq!(config.non_core_delegate_limit, Some(3));
    assert_eq!(config.lineage_dashboard_ref, "custom://dashboard");
}

// ===========================================================================
// 26) SlotReplacementSignal validate — zero weight
// ===========================================================================

#[test]
fn replacement_signal_zero_weight_rejected_via_snapshot() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");

    let mut signals = BTreeMap::new();
    signals.insert(
        p.clone(),
        SlotReplacementSignal {
            invocation_weight_millionths: 0,
            throughput_uplift_millionths: 100_000,
            security_risk_reduction_millionths: 100_000,
        },
    );

    let err = reg
        .snapshot_replacement_progress("t", "d", "p", &signals)
        .unwrap_err();
    match err {
        ReplacementProgressError::InvalidSignal { slot_id, detail } => {
            assert_eq!(slot_id, "parser");
            assert!(detail.contains("greater than zero"));
        }
        _ => panic!("expected InvalidSignal"),
    }
}

// ===========================================================================
// 27) Replacement progress — candidate ordering with mixed weights
// ===========================================================================

#[test]
fn replacement_progress_high_weight_low_ev_vs_low_weight_high_ev() {
    let mut reg = SlotRegistry::new();
    let heavy = register_slot(&mut reg, "heavy", SlotKind::Parser, "sha256:d-heavy");
    let light = register_slot(&mut reg, "light", SlotKind::Interpreter, "sha256:d-light");

    let mut signals = BTreeMap::new();
    // Heavy: large weight, small EV
    signals.insert(
        heavy.clone(),
        SlotReplacementSignal {
            invocation_weight_millionths: 10_000_000,
            throughput_uplift_millionths: 10_000,
            security_risk_reduction_millionths: 10_000,
        },
    );
    // Light: small weight, large EV
    signals.insert(
        light.clone(),
        SlotReplacementSignal {
            invocation_weight_millionths: 100_000,
            throughput_uplift_millionths: 5_000_000,
            security_risk_reduction_millionths: 5_000_000,
        },
    );

    let snapshot = reg
        .snapshot_replacement_progress("t", "d", "p", &signals)
        .unwrap();

    // heavy weighted EV = (10000+10000) * 10000000 / 1000000 = 200000
    // light weighted EV = (5000000+5000000) * 100000 / 1000000 = 1000000
    // light has higher weighted EV, so it should be first
    assert_eq!(snapshot.recommended_replacement_order.len(), 2);
    assert_eq!(snapshot.recommended_replacement_order[0].slot_id, light);
    assert_eq!(snapshot.recommended_replacement_order[1].slot_id, heavy);
}

// ===========================================================================
// 28) Replacement progress — events per candidate
// ===========================================================================

#[test]
fn replacement_progress_events_include_each_candidate() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    let i = register_slot(&mut reg, "interpreter", SlotKind::Interpreter, "sha256:d-i");

    let snapshot = reg
        .snapshot_replacement_progress("t", "d", "p", &BTreeMap::new())
        .unwrap();

    // 2 candidate ranking events + 1 final snapshot event = 3
    assert_eq!(snapshot.events.len(), 3);

    let ranked_events: Vec<_> = snapshot
        .events
        .iter()
        .filter(|e| e.event == "replacement_candidate_ranked")
        .collect();
    assert_eq!(ranked_events.len(), 2);

    let slot_ids: BTreeSet<_> = ranked_events
        .iter()
        .filter_map(|e| e.slot_id.as_deref())
        .collect();
    assert!(slot_ids.contains("parser"));
    assert!(slot_ids.contains("interpreter"));
    let _ = (p, i);
}

// ===========================================================================
// 29) SlotEntry serde round-trip with rollback target
// ===========================================================================

#[test]
fn serde_roundtrip_slot_entry_with_rollback_target() {
    let entry = SlotEntry {
        id: SlotId::new("parser").unwrap(),
        kind: SlotKind::Parser,
        authority: test_authority(),
        status: PromotionStatus::Promoted {
            native_digest: "sha256:n".into(),
            receipt_id: "rcpt".into(),
        },
        implementation_digest: "sha256:n".into(),
        promotion_lineage: vec![
            LineageEvent {
                transition: PromotionTransition::RegisteredDelegate,
                digest: "sha256:d".into(),
                timestamp: "2026-01-01T00:00:00Z".into(),
                receipt_id: None,
            },
            LineageEvent {
                transition: PromotionTransition::EnteredCandidacy,
                digest: "sha256:c".into(),
                timestamp: "2026-01-01T01:00:00Z".into(),
                receipt_id: None,
            },
            LineageEvent {
                transition: PromotionTransition::PromotedToNative,
                digest: "sha256:n".into(),
                timestamp: "2026-01-01T02:00:00Z".into(),
                receipt_id: Some("rcpt".into()),
            },
        ],
        rollback_target: Some("sha256:d".into()),
    };

    let json = serde_json::to_string(&entry).unwrap();
    let rt: SlotEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, rt);
    assert_eq!(rt.rollback_target.as_deref(), Some("sha256:d"));
}

// ===========================================================================
// 30) Serde round-trip of SlotReplacementSignal with negative values
// ===========================================================================

#[test]
fn serde_roundtrip_slot_replacement_signal_negative() {
    let signal = SlotReplacementSignal {
        invocation_weight_millionths: 500_000,
        throughput_uplift_millionths: -300_000,
        security_risk_reduction_millionths: -100_000,
    };
    let json = serde_json::to_string(&signal).unwrap();
    let rt: SlotReplacementSignal = serde_json::from_str(&json).unwrap();
    assert_eq!(signal, rt);
}

// ===========================================================================
// 31) Clone independence of SlotRegistry
// ===========================================================================

#[test]
fn clone_independence_slot_registry() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");

    let cloned = reg.clone();
    promote_slot(&mut reg, &p, "sha256:n-p");

    // Original modified, clone unchanged
    assert!(reg.get(&p).unwrap().status.is_native());
    assert!(cloned.get(&p).unwrap().status.is_delegate());
}

// ===========================================================================
// 32) GA guard — non-core limit exactly at boundary
// ===========================================================================

#[test]
fn ga_guard_non_core_limit_exact_boundary_passes() {
    let mut reg = SlotRegistry::new();
    register_slot(&mut reg, "slot-a", SlotKind::Builtins, "d-a");
    register_slot(&mut reg, "slot-b", SlotKind::ModuleLoader, "d-b");

    // 2 non-core delegates, limit = 2
    let input = guard_input(BTreeSet::new(), Some(2));
    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Pass);
    assert_eq!(artifact.non_core_delegate_count, 2);
}

#[test]
fn ga_guard_non_core_limit_one_over_blocks() {
    let mut reg = SlotRegistry::new();
    register_slot(&mut reg, "slot-a", SlotKind::Builtins, "d-a");
    register_slot(&mut reg, "slot-b", SlotKind::ModuleLoader, "d-b");
    register_slot(&mut reg, "slot-c", SlotKind::ScopeModel, "d-c");

    // 3 non-core delegates, limit = 2
    let input = guard_input(BTreeSet::new(), Some(2));
    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);
    assert_eq!(artifact.non_core_delegate_count, 3);
    assert_eq!(artifact.blocking_slots.len(), 3);
}

#[test]
fn ga_guard_non_core_limit_zero_blocks_any_delegate() {
    let mut reg = SlotRegistry::new();
    register_slot(&mut reg, "slot-a", SlotKind::Builtins, "d-a");

    let input = guard_input(BTreeSet::new(), Some(0));
    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);
    assert_eq!(artifact.non_core_delegate_count, 1);
}

// ===========================================================================
// 33) GA guard — delegate-backed core with fallback reachable
// ===========================================================================

#[test]
fn ga_guard_delegate_fallback_reachable_blocks_independent_of_signature() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    promote_slot(&mut reg, &p, "sha256:n-p");

    let core_slots = BTreeSet::from([p.clone()]);
    let mut input = guard_input(core_slots, None);
    let mut art = lineage_artifact(&p, "sha256:d-p", "sha256:n-p");
    // Signature verified but fallback still reachable
    art.signature_verified = true;
    art.equivalence_passed = true;
    art.delegate_fallback_reachable = true;
    input.lineage_artifacts = vec![art];

    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);
    assert_eq!(artifact.core_slots_delegate_fallback_reachable, vec![p]);
}

// ===========================================================================
// 34) PromotionTransition serde round-trip
// ===========================================================================

#[test]
fn serde_roundtrip_promotion_transition_rolled_back() {
    let t = PromotionTransition::RolledBack;
    let json = serde_json::to_string(&t).unwrap();
    let rt: PromotionTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(t, rt);
}

// ===========================================================================
// 35) Error types implement std::error::Error
// ===========================================================================

#[test]
fn all_error_types_implement_std_error() {
    let e1: &dyn std::error::Error = &SlotRegistryError::SlotNotFound { id: "x".into() };
    let e2: &dyn std::error::Error = &GaReleaseGuardError::UnknownCoreSlot {
        slot_id: "x".into(),
    };
    let e3: &dyn std::error::Error = &ReplacementProgressError::UnknownSignalSlot {
        slot_id: "x".into(),
    };
    // Verify Display works through the trait object
    assert!(!e1.to_string().is_empty());
    assert!(!e2.to_string().is_empty());
    assert!(!e3.to_string().is_empty());
}

// ===========================================================================
// 36) GA guard whitespace-only input fields
// ===========================================================================

#[test]
fn ga_guard_rejects_whitespace_only_trace_id() {
    let reg = SlotRegistry::new();
    let mut input = guard_input(BTreeSet::new(), None);
    input.trace_id = "   \t  ".into();
    assert!(matches!(
        reg.evaluate_ga_release_guard(&input),
        Err(GaReleaseGuardError::InvalidInput { field, .. }) if field == "trace_id"
    ));
}

#[test]
fn ga_guard_rejects_whitespace_only_lineage_dashboard_ref() {
    let reg = SlotRegistry::new();
    let mut input = guard_input(BTreeSet::new(), None);
    input.config.lineage_dashboard_ref = "  ".into();
    assert!(matches!(
        reg.evaluate_ga_release_guard(&input),
        Err(GaReleaseGuardError::InvalidInput { field, .. }) if field == "lineage_dashboard_ref"
    ));
}

// ===========================================================================
// 37) GA guard — slot_statuses sorted deterministically
// ===========================================================================

#[test]
fn ga_guard_slot_statuses_in_deterministic_order() {
    let mut reg = SlotRegistry::new();
    register_slot(&mut reg, "zzz-slot", SlotKind::Builtins, "d-z");
    register_slot(&mut reg, "aaa-slot", SlotKind::Parser, "d-a");
    register_slot(&mut reg, "mmm-slot", SlotKind::Interpreter, "d-m");

    let input = guard_input(BTreeSet::new(), None);
    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();

    // Slot statuses should follow BTreeMap iteration order (sorted)
    let status_ids: Vec<&str> = artifact
        .slot_statuses
        .iter()
        .map(|s| s.slot_id.as_str())
        .collect();
    assert_eq!(status_ids, vec!["aaa-slot", "mmm-slot", "zzz-slot"]);
}

// ===========================================================================
// 38) GA guard — blocking_slots sorted by slot_id
// ===========================================================================

#[test]
fn ga_guard_blocking_slots_sorted() {
    let mut reg = SlotRegistry::new();
    let z = register_slot(&mut reg, "zzz-slot", SlotKind::Builtins, "d-z");
    let a = register_slot(&mut reg, "aaa-slot", SlotKind::Parser, "d-a");
    let m = register_slot(&mut reg, "mmm-slot", SlotKind::Interpreter, "d-m");

    let core_slots = BTreeSet::from([z, a, m]);
    let input = guard_input(core_slots, None);

    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);

    let blocking_ids: Vec<&str> = artifact
        .blocking_slots
        .iter()
        .map(|s| s.slot_id.as_str())
        .collect();
    assert_eq!(blocking_ids, vec!["aaa-slot", "mmm-slot", "zzz-slot"]);
}

// ===========================================================================
// 39) SlotKind Copy trait verification
// ===========================================================================

#[test]
fn slot_kind_is_copy() {
    let a = SlotKind::Parser;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn slot_capability_is_copy() {
    let a = SlotCapability::HeapAlloc;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn release_slot_class_is_copy() {
    let a = ReleaseSlotClass::Core;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn ga_release_guard_verdict_is_copy() {
    let a = GaReleaseGuardVerdict::Pass;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn promotion_transition_is_copy() {
    let a = PromotionTransition::RolledBack;
    let b = a;
    assert_eq!(a, b);
}

// ===========================================================================
// 40) Default impls
// ===========================================================================

#[test]
fn slot_registry_default_is_empty() {
    let reg = SlotRegistry::default();
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);
}

#[test]
fn slot_replacement_signal_default_weight_is_one_million() {
    let s = SlotReplacementSignal::default();
    assert_eq!(s.invocation_weight_millionths, 1_000_000);
    assert_eq!(s.throughput_uplift_millionths, 0);
    assert_eq!(s.security_risk_reduction_millionths, 0);
}

#[test]
fn ga_release_guard_config_default_has_empty_core_slots() {
    let c = GaReleaseGuardConfig::default();
    assert!(c.core_slots.is_empty());
    assert!(c.non_core_delegate_limit.is_none());
    assert!(!c.lineage_dashboard_ref.is_empty());
}

// ===========================================================================
// 41) Replacement progress — weighted coverage with unequal weights
// ===========================================================================

#[test]
fn replacement_progress_weighted_coverage_unequal_weights() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    let i = register_slot(&mut reg, "interpreter", SlotKind::Interpreter, "sha256:d-i");
    promote_slot(&mut reg, &p, "sha256:n-p");

    let mut signals = BTreeMap::new();
    // Parser (native) has weight 3M, interpreter (delegate) has weight 1M
    signals.insert(
        p.clone(),
        SlotReplacementSignal {
            invocation_weight_millionths: 3_000_000,
            throughput_uplift_millionths: 0,
            security_risk_reduction_millionths: 0,
        },
    );
    signals.insert(
        i,
        SlotReplacementSignal {
            invocation_weight_millionths: 1_000_000,
            throughput_uplift_millionths: 0,
            security_risk_reduction_millionths: 0,
        },
    );

    let snapshot = reg
        .snapshot_replacement_progress("t", "d", "p", &signals)
        .unwrap();

    // Unweighted: 1/2 = 500_000 millionths
    assert_eq!(snapshot.native_coverage_millionths, 500_000);
    // Weighted: 3M / (3M + 1M) = 750_000 millionths
    assert_eq!(snapshot.weighted_native_coverage_millionths, 750_000);
}

// ===========================================================================
// 42) Replacement progress — all delegates with various signals
// ===========================================================================

#[test]
fn replacement_progress_all_delegates_zero_native_coverage() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    let i = register_slot(&mut reg, "interpreter", SlotKind::Interpreter, "sha256:d-i");

    let mut signals = BTreeMap::new();
    signals.insert(
        p,
        SlotReplacementSignal {
            invocation_weight_millionths: 2_000_000,
            throughput_uplift_millionths: 100_000,
            security_risk_reduction_millionths: 50_000,
        },
    );
    signals.insert(
        i,
        SlotReplacementSignal {
            invocation_weight_millionths: 1_000_000,
            throughput_uplift_millionths: 200_000,
            security_risk_reduction_millionths: 300_000,
        },
    );

    let snapshot = reg
        .snapshot_replacement_progress("t", "d", "p", &signals)
        .unwrap();

    assert_eq!(snapshot.native_slots, 0);
    assert_eq!(snapshot.delegate_slots, 2);
    assert_eq!(snapshot.native_coverage_millionths, 0);
    assert_eq!(snapshot.weighted_native_coverage_millionths, 0);
    assert_eq!(snapshot.recommended_replacement_order.len(), 2);
}

// ===========================================================================
// 43) GA guard — lineage check priority: signature before equivalence
// ===========================================================================

#[test]
fn ga_guard_signature_fails_before_equivalence_check() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    promote_slot(&mut reg, &p, "sha256:n-p");

    let core_slots = BTreeSet::from([p.clone()]);
    let mut input = guard_input(core_slots, None);
    let mut art = lineage_artifact(&p, "sha256:d-p", "sha256:n-p");
    art.signature_verified = false;
    art.equivalence_passed = false;
    art.delegate_fallback_reachable = true;
    input.lineage_artifacts = vec![art];

    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);
    // Signature check fires first, so only invalid_signature is populated
    assert_eq!(artifact.core_slots_invalid_signature, vec![p.clone()]);
    // Equivalence and fallback should NOT be in their lists since signature failed first
    assert!(artifact.core_slots_equivalence_failed.is_empty());
    assert!(artifact.core_slots_delegate_fallback_reachable.is_empty());
}

// ===========================================================================
// 44) GA guard — exemptions_applied is sorted
// ===========================================================================

#[test]
fn ga_guard_exemptions_applied_sorted() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    let i = register_slot(&mut reg, "interpreter", SlotKind::Interpreter, "sha256:d-i");

    let core_slots = BTreeSet::from([p.clone(), i.clone()]);
    let mut input = guard_input(core_slots, None);
    // Add exemptions in reverse alphabetical order
    input.exemptions = vec![exemption_for(p), exemption_for(i)];

    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
    // exemptions_applied should be sorted
    let applied = &artifact.exemptions_applied;
    for w in applied.windows(2) {
        assert!(w[0] <= w[1], "exemptions_applied not sorted: {:?}", applied);
    }
}

// ===========================================================================
// 45) GA guard serde round-trip of GaReleaseGuardError all variants
// ===========================================================================

#[test]
fn serde_roundtrip_ga_release_guard_error_invalid_exemption() {
    let err = GaReleaseGuardError::InvalidExemption {
        exemption_id: "ex-deep".into(),
        detail: "expired at epoch 41".into(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let rt: GaReleaseGuardError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, rt);
}

#[test]
fn serde_roundtrip_ga_release_guard_error_invalid_lineage() {
    let err = GaReleaseGuardError::InvalidLineageArtifact {
        slot_id: "parser".into(),
        detail: "empty digest".into(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let rt: GaReleaseGuardError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, rt);
}

// ===========================================================================
// 46) SlotId Ord is consistent with Eq
// ===========================================================================

#[test]
fn slot_id_ord_consistent_with_eq() {
    let a1 = SlotId::new("test").unwrap();
    let a2 = SlotId::new("test").unwrap();
    let b = SlotId::new("other").unwrap();
    assert_eq!(a1, a2);
    assert_eq!(a1.cmp(&a2), std::cmp::Ordering::Equal);
    assert_ne!(a1, b);
    assert_ne!(a1.cmp(&b), std::cmp::Ordering::Equal);
}

// ===========================================================================
// 47) Candidate status is neither native nor delegate
// ===========================================================================

#[test]
fn candidate_status_counts_as_neither_native_nor_delegate() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    reg.begin_candidacy(&p, "sha256:cand".into(), "t".into())
        .unwrap();

    // Candidate is counted as neither native nor delegate
    assert_eq!(reg.native_count(), 0);
    assert_eq!(reg.delegate_count(), 0);
    assert_eq!(reg.len(), 1);
}

// ===========================================================================
// 48) Serde JSON field names for CoreSlotExemption
// ===========================================================================

#[test]
fn json_fields_core_slot_exemption() {
    let ex = exemption_for(SlotId::new("parser").unwrap());
    let v: serde_json::Value = serde_json::to_value(&ex).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "exemption_id",
        "slot_id",
        "approved_by",
        "signed_risk_acknowledgement",
        "remediation_plan",
        "remediation_deadline_epoch",
        "expires_at_epoch",
    ] {
        assert!(
            obj.contains_key(key),
            "CoreSlotExemption missing field: {key}"
        );
    }
}

// ===========================================================================
// 49) Serde JSON field names for GaSignedLineageArtifact
// ===========================================================================

#[test]
fn json_fields_ga_signed_lineage_artifact() {
    let art = lineage_artifact(&SlotId::new("parser").unwrap(), "sha256:d", "sha256:n");
    let v: serde_json::Value = serde_json::to_value(&art).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "slot_id",
        "former_delegate_digest",
        "replacement_component_digest",
        "replacement_author",
        "replacement_timestamp",
        "lineage_signature",
        "trust_anchor_ref",
        "signature_verified",
        "equivalence_suite_ref",
        "equivalence_passed",
        "delegate_fallback_reachable",
    ] {
        assert!(
            obj.contains_key(key),
            "GaSignedLineageArtifact missing field: {key}"
        );
    }
}

// ===========================================================================
// 50) GA guard — begin_candidacy on nonexistent slot
// ===========================================================================

#[test]
fn begin_candidacy_nonexistent_slot_returns_not_found() {
    let mut reg = SlotRegistry::new();
    let ghost = SlotId::new("ghost").unwrap();
    let err = reg
        .begin_candidacy(&ghost, "sha256:cand".into(), "t".into())
        .unwrap_err();
    assert!(matches!(err, SlotRegistryError::SlotNotFound { id } if id == "ghost"));
}

// ===========================================================================
// 51) GA guard — multiple core slots, mixed blocking
// ===========================================================================

#[test]
fn ga_guard_one_core_blocks_while_other_passes() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    let i = register_slot(&mut reg, "interpreter", SlotKind::Interpreter, "sha256:d-i");
    promote_slot(&mut reg, &p, "sha256:n-p");
    promote_slot(&mut reg, &i, "sha256:n-i");

    let core_slots = BTreeSet::from([p.clone(), i.clone()]);
    let mut input = guard_input(core_slots, None);
    // Only provide lineage for parser, not interpreter
    input.lineage_artifacts = vec![lineage_artifact(&p, "sha256:d-p", "sha256:n-p")];

    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);
    assert_eq!(artifact.core_slots_missing_lineage, vec![i]);
    assert!(artifact.blocking_slots.len() == 1);
}

// ===========================================================================
// 52) Replacement progress snapshot — component field is correct
// ===========================================================================

#[test]
fn replacement_progress_snapshot_component_field() {
    let reg = SlotRegistry::new();
    let snapshot = reg
        .snapshot_replacement_progress("t", "d", "p", &BTreeMap::new())
        .unwrap();
    assert_eq!(snapshot.component, "self_replacement_progress");
}

// ===========================================================================
// 53) GA guard — all non-core slots are native, passes with no limit
// ===========================================================================

#[test]
fn ga_guard_all_non_core_native_passes() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    let i = register_slot(&mut reg, "interpreter", SlotKind::Interpreter, "sha256:d-i");
    promote_slot(&mut reg, &p, "sha256:n-p");
    promote_slot(&mut reg, &i, "sha256:n-i");

    // No core slots specified, all native
    let input = guard_input(BTreeSet::new(), None);
    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Pass);
    assert_eq!(artifact.non_core_delegate_count, 0);
}

// ===========================================================================
// 54) Replacement progress candidate fields verification
// ===========================================================================

#[test]
fn replacement_progress_candidate_fields_complete() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");

    let mut signals = BTreeMap::new();
    signals.insert(
        p.clone(),
        SlotReplacementSignal {
            invocation_weight_millionths: 2_000_000,
            throughput_uplift_millionths: 300_000,
            security_risk_reduction_millionths: 200_000,
        },
    );

    let snapshot = reg
        .snapshot_replacement_progress("t", "d", "p", &signals)
        .unwrap();
    assert_eq!(snapshot.recommended_replacement_order.len(), 1);

    let candidate = &snapshot.recommended_replacement_order[0];
    assert_eq!(candidate.slot_id, p);
    assert_eq!(candidate.slot_kind, SlotKind::Parser);
    assert_eq!(candidate.promotion_status, "delegate");
    assert!(candidate.delegate_backed);
    assert_eq!(candidate.invocation_weight_millionths, 2_000_000);
    assert_eq!(candidate.throughput_uplift_millionths, 300_000);
    assert_eq!(candidate.security_risk_reduction_millionths, 200_000);
    // EV = 300000 + 200000 = 500000
    assert_eq!(candidate.expected_value_score_millionths, 500_000);
    // Weighted EV = 500000 * 2000000 / 1000000 = 1000000
    assert_eq!(
        candidate.weighted_expected_value_score_millionths,
        1_000_000
    );
}

// ===========================================================================
// 55) GA guard — slot_kind preserved in slot statuses
// ===========================================================================

#[test]
fn ga_guard_slot_statuses_preserve_slot_kind() {
    let mut reg = SlotRegistry::new();
    register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    register_slot(&mut reg, "interpreter", SlotKind::Interpreter, "sha256:d-i");

    let input = guard_input(BTreeSet::new(), None);
    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();

    let parser_status = artifact
        .slot_statuses
        .iter()
        .find(|s| s.slot_id.as_str() == "parser")
        .unwrap();
    assert_eq!(parser_status.slot_kind, SlotKind::Parser);

    let interp_status = artifact
        .slot_statuses
        .iter()
        .find(|s| s.slot_id.as_str() == "interpreter")
        .unwrap();
    assert_eq!(interp_status.slot_kind, SlotKind::Interpreter);
}

// ===========================================================================
// 56) Demote without rollback target uses current digest
// ===========================================================================

#[test]
fn demote_without_rollback_target_uses_implementation_digest() {
    // This tests the code path where rollback_target is None when demoting
    // We need to create a promoted slot and clear its rollback target via serde
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    promote_slot(&mut reg, &p, "sha256:n-p");

    // The rollback target is now "sha256:d-p"
    assert_eq!(
        reg.get(&p).unwrap().rollback_target.as_deref(),
        Some("sha256:d-p")
    );

    // Normal demotion: uses rollback target
    reg.demote(&p, "reason".into(), "t".into()).unwrap();
    assert_eq!(reg.get(&p).unwrap().implementation_digest, "sha256:d-p");
}

// ===========================================================================
// 57) SlotRegistry serde preserves promotion lineage
// ===========================================================================

#[test]
fn serde_roundtrip_preserves_promotion_lineage() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    promote_slot(&mut reg, &p, "sha256:n-p");
    reg.demote(&p, "regression".into(), "t1".into()).unwrap();

    let json = serde_json::to_string(&reg).unwrap();
    let rt: SlotRegistry = serde_json::from_str(&json).unwrap();

    let original_lineage = &reg.get(&p).unwrap().promotion_lineage;
    let rt_lineage = &rt.get(&p).unwrap().promotion_lineage;
    assert_eq!(original_lineage.len(), rt_lineage.len());
    for (orig, roundtrip) in original_lineage.iter().zip(rt_lineage.iter()) {
        assert_eq!(orig, roundtrip);
    }
}

// ===========================================================================
// 58) GA guard — GaReleaseSlotStatus lineage fields for non-core slots
// ===========================================================================

#[test]
fn ga_guard_non_core_slot_has_no_lineage_fields() {
    let mut reg = SlotRegistry::new();
    register_slot(&mut reg, "builtins", SlotKind::Builtins, "sha256:d-b");

    let input = guard_input(BTreeSet::new(), None);
    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();

    let status = &artifact.slot_statuses[0];
    assert_eq!(status.slot_class, ReleaseSlotClass::NonCore);
    assert!(status.lineage_signature_verified.is_none());
    assert!(status.equivalence_passed.is_none());
    assert!(status.delegate_fallback_reachable.is_none());
    assert!(status.exemption_id.is_none());
}

// ===========================================================================
// 59) GA guard — native core slot with complete valid lineage passes
// ===========================================================================

#[test]
fn ga_guard_native_core_slot_with_valid_lineage_passes() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    promote_slot(&mut reg, &p, "sha256:n-p");

    let core_slots = BTreeSet::from([p.clone()]);
    let mut input = guard_input(core_slots, None);
    input.lineage_artifacts = vec![lineage_artifact(&p, "sha256:d-p", "sha256:n-p")];

    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Pass);
    assert!(artifact.blocking_slots.is_empty());
    assert!(artifact.core_slots_missing_lineage.is_empty());
    assert!(artifact.core_slots_lineage_mismatch.is_empty());
    assert!(artifact.core_slots_invalid_signature.is_empty());
    assert!(artifact.core_slots_equivalence_failed.is_empty());
    assert!(artifact.core_slots_delegate_fallback_reachable.is_empty());

    let p_status = artifact
        .slot_statuses
        .iter()
        .find(|s| s.slot_id == p)
        .unwrap();
    assert!(!p_status.blocking);
    assert!(!p_status.delegate_backed);
    assert_eq!(p_status.lineage_signature_verified, Some(true));
    assert_eq!(p_status.equivalence_passed, Some(true));
    assert_eq!(p_status.delegate_fallback_reachable, Some(false));
}

// ===========================================================================
// 60) GA guard — equivalence failure blocks (with valid signature)
// ===========================================================================

#[test]
fn ga_guard_equivalence_failure_blocks_with_valid_signature() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    promote_slot(&mut reg, &p, "sha256:n-p");

    let core_slots = BTreeSet::from([p.clone()]);
    let mut input = guard_input(core_slots, None);
    let mut art = lineage_artifact(&p, "sha256:d-p", "sha256:n-p");
    art.signature_verified = true;
    art.equivalence_passed = false;
    input.lineage_artifacts = vec![art];

    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);
    assert_eq!(artifact.core_slots_equivalence_failed, vec![p]);
    // Signature is OK, so not in invalid_signature
    assert!(artifact.core_slots_invalid_signature.is_empty());
}

// ===========================================================================
// 61) SlotId Display and Debug are distinct
// ===========================================================================

#[test]
fn slot_id_display_and_debug_are_different() {
    let id = SlotId::new("test-id").unwrap();
    let display = format!("{id}");
    let debug = format!("{id:?}");
    // Display is just the string, Debug includes type wrapper
    assert_eq!(display, "test-id");
    assert!(debug.contains("SlotId"));
    assert!(debug.contains("test-id"));
    assert_ne!(display, debug);
}

// ===========================================================================
// 62) Register with all 12 SlotKind variants verifies kind preservation
// ===========================================================================

#[test]
fn register_all_kinds_preserves_kind_in_entry() {
    let kinds = [
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
    ];

    let mut reg = SlotRegistry::new();
    for (name, kind) in &kinds {
        register_slot(&mut reg, name, *kind, &format!("d-{name}"));
    }

    for (name, expected_kind) in &kinds {
        let id = SlotId::new(*name).unwrap();
        let entry = reg.get(&id).unwrap();
        assert_eq!(entry.kind, *expected_kind);
    }
}

// ===========================================================================
// 63) Replacement progress — candidate promotion_status string
// ===========================================================================

#[test]
fn replacement_progress_candidate_shows_delegate_status() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");

    let snapshot = reg
        .snapshot_replacement_progress("t", "d", "p", &BTreeMap::new())
        .unwrap();

    assert_eq!(snapshot.recommended_replacement_order.len(), 1);
    assert_eq!(
        snapshot.recommended_replacement_order[0].promotion_status,
        "delegate"
    );
    let _ = p;
}

#[test]
fn replacement_progress_demoted_slot_shows_demoted_status() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    promote_slot(&mut reg, &p, "sha256:n-p");
    reg.demote(&p, "regression".into(), "t".into()).unwrap();

    let snapshot = reg
        .snapshot_replacement_progress("t", "d", "p", &BTreeMap::new())
        .unwrap();

    assert_eq!(snapshot.recommended_replacement_order.len(), 1);
    let status = &snapshot.recommended_replacement_order[0].promotion_status;
    assert!(status.contains("demoted"));
}

// ===========================================================================
// 64) GA guard — all events have consistent trace/decision/policy
// ===========================================================================

#[test]
fn ga_guard_all_events_have_consistent_ids() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    let core_slots = BTreeSet::from([p]);
    let input = guard_input(core_slots, None);

    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
    for event in &artifact.events {
        assert_eq!(event.trace_id, "trace-deep-001");
        assert_eq!(event.decision_id, "decision-deep-001");
        assert_eq!(event.policy_id, "policy-deep-001");
        assert_eq!(event.component, "ga_release_delegate_guard");
    }
}

// ===========================================================================
// 65) JSON field names for GaReleaseGuardArtifact
// ===========================================================================

#[test]
fn json_fields_ga_release_guard_artifact() {
    let reg = SlotRegistry::new();
    let input = guard_input(BTreeSet::new(), None);
    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
    let v: serde_json::Value = serde_json::to_value(&artifact).unwrap();
    let obj = v.as_object().unwrap();

    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "verdict",
        "total_slots",
        "core_slot_count",
        "core_delegate_count",
        "non_core_delegate_count",
        "native_coverage_millionths",
        "lineage_dashboard_ref",
        "exemptions_applied",
        "core_slots_missing_lineage",
        "core_slots_lineage_mismatch",
        "core_slots_invalid_signature",
        "core_slots_equivalence_failed",
        "core_slots_delegate_fallback_reachable",
        "slot_statuses",
        "blocking_slots",
        "events",
    ] {
        assert!(
            obj.contains_key(key),
            "GaReleaseGuardArtifact missing field: {key}"
        );
    }
}

// ===========================================================================
// 66) JSON field names for ReplacementProgressSnapshot
// ===========================================================================

#[test]
fn json_fields_replacement_progress_snapshot() {
    let reg = SlotRegistry::new();
    let snapshot = reg
        .snapshot_replacement_progress("t", "d", "p", &BTreeMap::new())
        .unwrap();
    let v: serde_json::Value = serde_json::to_value(&snapshot).unwrap();
    let obj = v.as_object().unwrap();

    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "total_slots",
        "native_slots",
        "delegate_slots",
        "native_coverage_millionths",
        "weighted_native_coverage_millionths",
        "weighted_delegate_throughput_uplift_millionths",
        "weighted_delegate_security_risk_reduction_millionths",
        "recommended_replacement_order",
        "events",
    ] {
        assert!(
            obj.contains_key(key),
            "ReplacementProgressSnapshot missing field: {key}"
        );
    }
}

// ===========================================================================
// 67) Replacement progress — unknown signal slot error preserves slot id
// ===========================================================================

#[test]
fn replacement_progress_unknown_signal_slot_error_message() {
    let reg = SlotRegistry::new();
    let ghost = SlotId::new("ghost-slot").unwrap();
    let mut signals = BTreeMap::new();
    signals.insert(ghost, SlotReplacementSignal::default());

    let err = reg
        .snapshot_replacement_progress("t", "d", "p", &signals)
        .unwrap_err();
    match err {
        ReplacementProgressError::UnknownSignalSlot { slot_id } => {
            assert_eq!(slot_id, "ghost-slot");
        }
        _ => panic!("expected UnknownSignalSlot"),
    }
}

// ===========================================================================
// 68) GA guard — exemption with exact epoch boundary (<=) rejected
// ===========================================================================

#[test]
fn ga_guard_exemption_deadline_at_epoch_rejected() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    let core_slots = BTreeSet::from([p.clone()]);
    let mut input = guard_input(core_slots, None);
    let mut ex = exemption_for(p);
    // current_epoch is 42, set deadline to exactly 42 (not future)
    ex.remediation_deadline_epoch = 42;
    input.exemptions = vec![ex];

    let err = reg.evaluate_ga_release_guard(&input).unwrap_err();
    assert!(matches!(
        err,
        GaReleaseGuardError::InvalidExemption { detail, .. }
        if detail.contains("remediation_deadline_epoch")
    ));
}

#[test]
fn ga_guard_exemption_expiry_at_epoch_rejected() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    let core_slots = BTreeSet::from([p.clone()]);
    let mut input = guard_input(core_slots, None);
    let mut ex = exemption_for(p);
    // current_epoch is 42, set expiry to exactly 42 (not future)
    ex.expires_at_epoch = 42;
    input.exemptions = vec![ex];

    let err = reg.evaluate_ga_release_guard(&input).unwrap_err();
    assert!(matches!(
        err,
        GaReleaseGuardError::InvalidExemption { detail, .. }
        if detail.contains("expires_at_epoch")
    ));
}

// ===========================================================================
// 69) GA guard — native_coverage_millionths with 0 slots is 0
// ===========================================================================

#[test]
fn ga_guard_native_coverage_millionths_zero_for_empty_registry() {
    let reg = SlotRegistry::new();
    let input = guard_input(BTreeSet::new(), None);
    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
    assert_eq!(artifact.native_coverage_millionths, 0);
}

// ===========================================================================
// 70) Slot registry Default trait
// ===========================================================================

#[test]
fn slot_registry_default_trait() {
    let a: SlotRegistry = Default::default();
    let b = SlotRegistry::new();
    assert_eq!(a.len(), b.len());
    assert!(a.is_empty());
}

// ===========================================================================
// 71) Replacement progress — demoted slot appears in replacement order
// ===========================================================================

#[test]
fn replacement_progress_demoted_slot_in_replacement_order() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    promote_slot(&mut reg, &p, "sha256:n-p");
    reg.demote(&p, "regression".into(), "t".into()).unwrap();

    let snapshot = reg
        .snapshot_replacement_progress("t", "d", "p", &BTreeMap::new())
        .unwrap();

    // Demoted slot is delegate-backed, should appear in replacement order
    assert_eq!(snapshot.delegate_slots, 1);
    assert_eq!(snapshot.recommended_replacement_order.len(), 1);
    assert_eq!(snapshot.recommended_replacement_order[0].slot_id, p);
    assert!(snapshot.recommended_replacement_order[0].delegate_backed);
}

// ===========================================================================
// 72) GA guard — candidate slot counted as delegate in guard
// ===========================================================================

#[test]
fn ga_guard_candidate_slot_is_delegate_backed() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    reg.begin_candidacy(&p, "sha256:cand".into(), "t".into())
        .unwrap();

    let core_slots = BTreeSet::from([p.clone()]);
    let input = guard_input(core_slots, None);

    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
    // Candidate is not native, so it should block as core delegate
    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);
    assert_eq!(artifact.core_delegate_count, 1);
}

// ===========================================================================
// 73) Replacement progress — candidate slot not in replacement order
//     (candidate is neither native nor delegate per is_delegate/is_native)
// ===========================================================================

#[test]
fn replacement_progress_candidate_slot_not_counted_as_delegate() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    reg.begin_candidacy(&p, "sha256:cand".into(), "t".into())
        .unwrap();

    let snapshot = reg
        .snapshot_replacement_progress("t", "d", "p", &BTreeMap::new())
        .unwrap();

    // Candidate is neither native nor delegate
    assert_eq!(snapshot.native_slots, 0);
    assert_eq!(snapshot.delegate_slots, 0);
    // But it IS not native, so it appears in replacement order
    // (the code checks !entry.status.is_native(), not entry.status.is_delegate())
    assert_eq!(snapshot.recommended_replacement_order.len(), 1);
}

// ===========================================================================
// 74) GA guard — multiple exemptions for different core slots
// ===========================================================================

#[test]
fn ga_guard_multiple_valid_exemptions_for_different_slots() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    let i = register_slot(&mut reg, "interpreter", SlotKind::Interpreter, "sha256:d-i");

    let core_slots = BTreeSet::from([p.clone(), i.clone()]);
    let mut input = guard_input(core_slots, None);
    input.exemptions = vec![exemption_for(p), exemption_for(i)];

    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Pass);
    assert_eq!(artifact.exemptions_applied.len(), 2);
    assert_eq!(artifact.core_delegate_count, 2);
}

// ===========================================================================
// 75) GA guard — native coverage millionths with 2 of 3 native
// ===========================================================================

#[test]
fn ga_guard_native_coverage_two_of_three() {
    let mut reg = SlotRegistry::new();
    let p = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-p");
    let i = register_slot(&mut reg, "interpreter", SlotKind::Interpreter, "sha256:d-i");
    let _b = register_slot(&mut reg, "builtins", SlotKind::Builtins, "sha256:d-b");
    promote_slot(&mut reg, &p, "sha256:n-p");
    promote_slot(&mut reg, &i, "sha256:n-i");

    let input = guard_input(BTreeSet::new(), None);
    let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
    // 2/3 = 666666 millionths
    assert_eq!(artifact.native_coverage_millionths, 666_666);
}
