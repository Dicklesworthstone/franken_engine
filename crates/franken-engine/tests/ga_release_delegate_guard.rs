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
use std::path::PathBuf;

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::slot_registry::{
    AuthorityEnvelope, CoreSlotExemption, GaReleaseGuardConfig, GaReleaseGuardError,
    GaReleaseGuardInput, GaReleaseGuardVerdict, GaSignedLineageArtifact, LineageEvent,
    PromotionStatus, PromotionTransition, ReleaseSlotClass, ReplacementProgressError,
    SlotCapability, SlotEntry, SlotId, SlotKind, SlotRegistry, SlotRegistryError,
    SlotReplacementSignal,
};

fn test_authority() -> AuthorityEnvelope {
    AuthorityEnvelope {
        required: vec![SlotCapability::ReadSource],
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

fn register_slot(registry: &mut SlotRegistry, id: &str, kind: SlotKind, digest: &str) -> SlotId {
    let slot_id = SlotId::new(id).expect("valid slot id");
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

fn promote_slot(registry: &mut SlotRegistry, slot_id: &SlotId, digest: &str) {
    registry
        .begin_candidacy(
            slot_id,
            format!("{digest}-candidate"),
            "2026-02-21T00:00:01Z".to_string(),
        )
        .expect("begin candidacy");
    registry
        .promote(
            slot_id,
            digest.to_string(),
            &narrower_authority(),
            format!("receipt-{digest}"),
            "2026-02-21T00:00:02Z".to_string(),
        )
        .expect("promote");
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
        replacement_author: "ga-release-operator".to_string(),
        replacement_timestamp: "2026-02-21T00:00:03Z".to_string(),
        lineage_signature: "sig:ga-lineage".to_string(),
        trust_anchor_ref: "trust-anchor://ga-lineage-v1".to_string(),
        signature_verified: true,
        equivalence_suite_ref: "suite://ga-core-equivalence-v1".to_string(),
        equivalence_passed: true,
        delegate_fallback_reachable: false,
    }
}

fn pipeline_input(
    core_slots: BTreeSet<SlotId>,
    non_core_limit: Option<usize>,
) -> GaReleaseGuardInput {
    let mut remediation_estimates = BTreeMap::new();
    remediation_estimates.insert(
        SlotId::new("parser").expect("valid parser id"),
        "4 engineering-days".to_string(),
    );
    remediation_estimates.insert(
        SlotId::new("builtins").expect("valid builtins id"),
        "2 engineering-days".to_string(),
    );

    GaReleaseGuardInput {
        trace_id: "trace-ga-pipeline-001".to_string(),
        decision_id: "decision-ga-pipeline-001".to_string(),
        policy_id: "policy-ga-release-readiness-v1".to_string(),
        current_epoch: SecurityEpoch::from_raw(100),
        config: GaReleaseGuardConfig {
            core_slots,
            non_core_delegate_limit: non_core_limit,
            lineage_dashboard_ref: "frankentui://replacement-lineage/ga-release".to_string(),
        },
        exemptions: Vec::new(),
        lineage_artifacts: Vec::new(),
        remediation_estimates,
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn mock_release_pipeline_blocks_when_core_delegate_slot_exists() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-parser",
    );
    let interpreter = register_slot(
        &mut registry,
        "interpreter",
        SlotKind::Interpreter,
        "sha256:delegate-interpreter",
    );
    let _builtins = register_slot(
        &mut registry,
        "builtins",
        SlotKind::Builtins,
        "sha256:delegate-builtins",
    );
    promote_slot(&mut registry, &interpreter, "sha256:native-interpreter");

    let core_slots = BTreeSet::from([parser.clone(), interpreter.clone()]);
    let mut input = pipeline_input(core_slots, Some(2));
    input.lineage_artifacts = vec![lineage_artifact(
        &interpreter,
        "sha256:delegate-interpreter",
        "sha256:native-interpreter",
    )];
    let artifact = registry
        .evaluate_ga_release_guard(&input)
        .expect("guard should evaluate");

    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);
    assert_eq!(artifact.blocking_slots.len(), 1);
    assert_eq!(artifact.blocking_slots[0].slot_id, parser);
    assert_eq!(
        artifact.blocking_slots[0].estimated_remediation,
        "4 engineering-days"
    );
    assert!(artifact.events.iter().all(|event| {
        event.trace_id == "trace-ga-pipeline-001"
            && event.decision_id == "decision-ga-pipeline-001"
            && event.policy_id == "policy-ga-release-readiness-v1"
            && event.component == "ga_release_delegate_guard"
    }));
}

#[test]
fn mock_release_pipeline_passes_when_core_slots_are_native() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-parser",
    );
    let interpreter = register_slot(
        &mut registry,
        "interpreter",
        SlotKind::Interpreter,
        "sha256:delegate-interpreter",
    );
    let _builtins = register_slot(
        &mut registry,
        "builtins",
        SlotKind::Builtins,
        "sha256:delegate-builtins",
    );

    promote_slot(&mut registry, &parser, "sha256:native-parser");
    promote_slot(&mut registry, &interpreter, "sha256:native-interpreter");

    let core_slots = BTreeSet::from([parser.clone(), interpreter.clone()]);
    let mut input = pipeline_input(core_slots, Some(2));
    input.lineage_artifacts = vec![
        lineage_artifact(&parser, "sha256:delegate-parser", "sha256:native-parser"),
        lineage_artifact(
            &interpreter,
            "sha256:delegate-interpreter",
            "sha256:native-interpreter",
        ),
    ];
    let artifact = registry
        .evaluate_ga_release_guard(&input)
        .expect("guard should evaluate");

    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Pass);
    assert!(artifact.blocking_slots.is_empty());
    assert_eq!(artifact.core_delegate_count, 0);
    assert_eq!(artifact.non_core_delegate_count, 1);
    assert_eq!(
        artifact.lineage_dashboard_ref,
        "frankentui://replacement-lineage/ga-release"
    );
}

#[test]
fn version_matrix_workflow_runs_ga_delegate_guard_check() {
    let workflow_path = repo_root().join(".github/workflows/version_matrix_conformance.yml");
    let workflow = std::fs::read_to_string(&workflow_path).expect("read workflow");
    assert!(
        workflow.contains("./scripts/check_ga_delegate_core_slots.sh ci"),
        "workflow must run GA delegate guard check script"
    );
}

// ────────────────────────────────────────────────────────────
// Enrichment: serde, display, validation, edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn slot_kind_serde_round_trip_all_variants() {
    for kind in [
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
    ] {
        let json = serde_json::to_string(&kind).expect("serialize");
        let recovered: SlotKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(kind, recovered);
    }
}

#[test]
fn slot_capability_serde_round_trip_all_variants() {
    for cap in [
        SlotCapability::ReadSource,
        SlotCapability::EmitIr,
        SlotCapability::HeapAlloc,
        SlotCapability::ScheduleAsync,
        SlotCapability::InvokeHostcall,
        SlotCapability::ModuleAccess,
        SlotCapability::TriggerGc,
        SlotCapability::EmitEvidence,
    ] {
        let json = serde_json::to_string(&cap).expect("serialize");
        let recovered: SlotCapability = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cap, recovered);
    }
}

#[test]
fn slot_id_valid_and_invalid_construction() {
    assert!(SlotId::new("parser").is_ok());
    assert!(SlotId::new("ir-lowering").is_ok());
    assert!(SlotId::new("scope123").is_ok());

    assert!(SlotId::new("").is_err());
    assert!(SlotId::new("Parser").is_err()); // uppercase
    assert!(SlotId::new("slot_name").is_err()); // underscore
}

#[test]
fn slot_id_display_matches_inner_value() {
    let id = SlotId::new("parser").expect("valid id");
    assert_eq!(id.to_string(), "parser");
    assert_eq!(id.as_str(), "parser");
}

#[test]
fn slot_registry_error_display_is_non_empty() {
    let err = SlotRegistryError::InvalidSlotId {
        id: "BAD".to_string(),
        reason: "uppercase chars".to_string(),
    };
    assert!(!err.to_string().is_empty());
    assert!(err.to_string().contains("BAD"));

    let err2 = SlotRegistryError::DuplicateSlotId {
        id: "parser".to_string(),
    };
    assert!(!err2.to_string().is_empty());
}

#[test]
fn ga_release_guard_verdict_display_formats() {
    assert_eq!(GaReleaseGuardVerdict::Pass.to_string(), "pass");
    assert_eq!(GaReleaseGuardVerdict::Blocked.to_string(), "blocked");
}

#[test]
fn authority_envelope_serde_round_trip() {
    let envelope = AuthorityEnvelope {
        required: vec![SlotCapability::ReadSource],
        permitted: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
    };
    let json = serde_json::to_string(&envelope).expect("serialize");
    let recovered: AuthorityEnvelope = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(envelope, recovered);
}

#[test]
fn promotion_status_serde_round_trip_all_variants() {
    let variants: Vec<PromotionStatus> = vec![
        PromotionStatus::Delegate,
        PromotionStatus::PromotionCandidate {
            candidate_digest: "sha256:candidate".to_string(),
        },
        PromotionStatus::Promoted {
            native_digest: "sha256:native".to_string(),
            receipt_id: "receipt-001".to_string(),
        },
        PromotionStatus::Demoted {
            reason: "regression detected".to_string(),
            rollback_digest: "sha256:rollback".to_string(),
        },
    ];
    for status in variants {
        let json = serde_json::to_string(&status).expect("serialize");
        let recovered: PromotionStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(status, recovered);
    }
}

#[test]
fn ga_release_guard_verdict_serde_round_trip() {
    for verdict in [GaReleaseGuardVerdict::Pass, GaReleaseGuardVerdict::Blocked] {
        let json = serde_json::to_string(&verdict).expect("serialize");
        let recovered: GaReleaseGuardVerdict = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(verdict, recovered);
    }
}

#[test]
fn duplicate_slot_registration_returns_error() {
    let mut registry = SlotRegistry::new();
    register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:a");
    let dup = registry.register_delegate(
        SlotId::new("parser").expect("valid"),
        SlotKind::Parser,
        test_authority(),
        "sha256:b".to_string(),
        "2026-02-21T00:00:00Z".to_string(),
    );
    assert!(dup.is_err());
}

#[test]
fn ga_signed_lineage_artifact_serde_round_trip() {
    let parser_id = SlotId::new("parser").expect("valid");
    let artifact = lineage_artifact(&parser_id, "sha256:old", "sha256:new");
    let json = serde_json::to_string(&artifact).expect("serialize");
    let recovered: GaSignedLineageArtifact = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact.slot_id, recovered.slot_id);
    assert_eq!(
        artifact.former_delegate_digest,
        recovered.former_delegate_digest
    );
    assert_eq!(
        artifact.replacement_component_digest,
        recovered.replacement_component_digest
    );
    assert!(recovered.signature_verified);
    assert!(recovered.equivalence_passed);
}

#[test]
fn ga_release_guard_config_serde_round_trip() {
    let core_slots = BTreeSet::from([SlotId::new("parser").expect("valid")]);
    let config = GaReleaseGuardConfig {
        core_slots,
        non_core_delegate_limit: Some(5),
        lineage_dashboard_ref: "frankentui://test".to_string(),
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: GaReleaseGuardConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, recovered);
}

#[test]
fn slot_registry_new_is_empty() {
    let registry = SlotRegistry::new();
    let json = serde_json::to_string(&registry).expect("serialize");
    let recovered: SlotRegistry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        json,
        serde_json::to_string(&recovered).expect("re-serialize")
    );
}

#[test]
fn pipeline_input_has_correct_governance_fields() {
    let core_slots = BTreeSet::new();
    let input = pipeline_input(core_slots, None);
    assert_eq!(input.trace_id, "trace-ga-pipeline-001");
    assert_eq!(input.decision_id, "decision-ga-pipeline-001");
    assert_eq!(input.policy_id, "policy-ga-release-readiness-v1");
}

#[test]
fn narrower_authority_permitted_is_subset_of_test_authority() {
    let full = test_authority();
    let narrow = narrower_authority();
    for cap in &narrow.permitted {
        assert!(
            full.permitted.contains(cap),
            "narrower authority cap {cap:?} not in full permitted list"
        );
    }
    assert!(narrow.permitted.len() <= full.permitted.len());
}

#[test]
fn slot_id_serde_round_trip() {
    let id = SlotId::new("parser").expect("valid");
    let json = serde_json::to_string(&id).expect("serialize");
    let recovered: SlotId = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(id, recovered);
    assert_eq!(id.as_str(), recovered.as_str());
}

#[test]
fn slot_kind_serde_roundtrip() {
    for kind in [
        SlotKind::Parser,
        SlotKind::IrLowering,
        SlotKind::Interpreter,
    ] {
        let json = serde_json::to_string(&kind).expect("serialize");
        let recovered: SlotKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, kind);
    }
}

#[test]
fn promotion_status_delegate_serde_roundtrip() {
    let status = PromotionStatus::Delegate;
    let json = serde_json::to_string(&status).expect("serialize");
    let recovered: PromotionStatus = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, status);
}

#[test]
fn slot_registry_error_display_is_nonempty() {
    let err = SlotRegistryError::SlotNotFound {
        id: "missing".to_string(),
    };
    let msg = format!("{err}");
    assert!(!msg.trim().is_empty());
}

#[test]
fn ga_release_guard_verdict_debug_is_nonempty() {
    let verdict = GaReleaseGuardVerdict::Pass;
    let debug = format!("{verdict:?}");
    assert!(!debug.trim().is_empty());
}

#[test]
fn slot_capability_debug_is_nonempty() {
    let cap = SlotCapability::ReadSource;
    let debug = format!("{cap:?}");
    assert!(!debug.trim().is_empty());
}

#[test]
fn authority_envelope_debug_is_nonempty() {
    let authority = test_authority();
    let debug = format!("{authority:?}");
    assert!(!debug.trim().is_empty());
}

// ---------- enrichment: edge cases, coverage, determinism ----------

#[test]
fn empty_registry_ga_guard_passes_with_no_core_slots() {
    let registry = SlotRegistry::new();
    let core_slots = BTreeSet::new();
    let input = pipeline_input(core_slots, Some(0));
    let artifact = registry
        .evaluate_ga_release_guard(&input)
        .expect("guard should evaluate on empty registry");
    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Pass);
    assert!(artifact.blocking_slots.is_empty());
    assert_eq!(artifact.core_delegate_count, 0);
    assert_eq!(artifact.non_core_delegate_count, 0);
}

#[test]
fn non_core_delegate_limit_none_allows_unlimited_delegates() {
    let mut registry = SlotRegistry::new();
    let _parser = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-parser");
    let _interp = register_slot(
        &mut registry,
        "interpreter",
        SlotKind::Interpreter,
        "sha256:d-interp",
    );
    let _builtins = register_slot(
        &mut registry,
        "builtins",
        SlotKind::Builtins,
        "sha256:d-builtins",
    );
    // No core slots => all are non-core delegates, but limit is None => unlimited
    let core_slots = BTreeSet::new();
    let input = pipeline_input(core_slots, None);
    let artifact = registry
        .evaluate_ga_release_guard(&input)
        .expect("guard should evaluate");
    // No core slots means Pass even with all delegates
    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Pass);
    assert_eq!(artifact.non_core_delegate_count, 3);
}

#[test]
fn lineage_artifact_with_unverified_signature_still_does_not_panic() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-parser");
    promote_slot(&mut registry, &parser, "sha256:native-parser");

    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = pipeline_input(core_slots, Some(5));
    let mut la = lineage_artifact(&parser, "sha256:d-parser", "sha256:native-parser");
    la.signature_verified = false;
    input.lineage_artifacts = vec![la];
    // Should not panic regardless of verification flag
    let _artifact = registry.evaluate_ga_release_guard(&input);
}

#[test]
fn slot_registry_native_and_delegate_counts_track_promotions() {
    let mut registry = SlotRegistry::new();
    assert_eq!(registry.native_count(), 0);
    assert_eq!(registry.delegate_count(), 0);
    assert!(registry.is_empty());

    let parser = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-p");
    assert_eq!(registry.delegate_count(), 1);
    assert_eq!(registry.native_count(), 0);
    assert_eq!(registry.len(), 1);

    promote_slot(&mut registry, &parser, "sha256:native-p");
    assert_eq!(registry.delegate_count(), 0);
    assert_eq!(registry.native_count(), 1);
    assert_eq!(registry.len(), 1);
}

#[test]
fn ga_release_guard_input_serde_round_trip() {
    let core_slots = BTreeSet::from([
        SlotId::new("parser").expect("valid"),
        SlotId::new("interpreter").expect("valid"),
    ]);
    let input = pipeline_input(core_slots, Some(3));
    let json = serde_json::to_string(&input).expect("serialize");
    let recovered: GaReleaseGuardInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(input.trace_id, recovered.trace_id);
    assert_eq!(input.decision_id, recovered.decision_id);
    assert_eq!(input.policy_id, recovered.policy_id);
    assert_eq!(input.config.core_slots, recovered.config.core_slots);
    assert_eq!(
        input.config.non_core_delegate_limit,
        recovered.config.non_core_delegate_limit
    );
}

// ---------- enrichment: demotion, is_ga_ready, authority subsumes ----------

#[test]
fn demoted_slot_reverts_to_delegate_status() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-p");
    promote_slot(&mut registry, &parser, "sha256:native-p");
    assert_eq!(registry.native_count(), 1);

    registry
        .demote(
            &parser,
            "regression detected".to_string(),
            "sha256:d-p".to_string(),
        )
        .expect("demote");

    assert_eq!(registry.native_count(), 0);
    assert_eq!(registry.delegate_count(), 1);
    let entry = registry.get(&parser).expect("slot should exist");
    assert!(entry.status.is_delegate());
}

#[test]
fn is_ga_ready_false_when_delegates_remain() {
    let mut registry = SlotRegistry::new();
    let _parser = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-p");
    assert!(
        !registry.is_ga_ready(),
        "registry with delegates should not be GA-ready"
    );
}

#[test]
fn is_ga_ready_true_when_all_promoted() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-p");
    promote_slot(&mut registry, &parser, "sha256:native-p");
    assert!(
        registry.is_ga_ready(),
        "registry with all native slots should be GA-ready"
    );
}

#[test]
fn authority_envelope_subsumes_itself() {
    let auth = test_authority();
    assert!(auth.subsumes(&auth), "authority should subsume itself");
}

#[test]
fn authority_envelope_is_consistent_when_required_subset_of_permitted() {
    let auth = test_authority();
    assert!(auth.is_consistent(), "test authority should be consistent");

    let narrow = narrower_authority();
    assert!(
        narrow.is_consistent(),
        "narrower authority should be consistent"
    );
    // Full authority should subsume narrower authority
    assert!(
        auth.subsumes(&narrow),
        "full authority should subsume narrower"
    );
}

// ────────────────────────────────────────────────────────────
// Enrichment: PearlTower 2026-03-14 — expanded API coverage
// ────────────────────────────────────────────────────────────

#[test]
fn slot_kind_display_all_twelve_variants() {
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
    let mut seen = BTreeSet::new();
    for (kind, label) in expected {
        assert_eq!(kind.to_string(), label);
        assert!(seen.insert(label), "duplicate kind label");
    }
    assert_eq!(seen.len(), 12);
}

#[test]
fn slot_capability_display_all_eight_variants() {
    for cap in [
        SlotCapability::ReadSource,
        SlotCapability::EmitIr,
        SlotCapability::HeapAlloc,
        SlotCapability::ScheduleAsync,
        SlotCapability::InvokeHostcall,
        SlotCapability::ModuleAccess,
        SlotCapability::TriggerGc,
        SlotCapability::EmitEvidence,
    ] {
        let debug = format!("{cap:?}");
        assert!(!debug.is_empty());
    }
}

#[test]
fn promotion_status_is_native_and_is_delegate() {
    assert!(PromotionStatus::Delegate.is_delegate());
    assert!(!PromotionStatus::Delegate.is_native());

    let candidate = PromotionStatus::PromotionCandidate {
        candidate_digest: "sha256:c".to_string(),
    };
    assert!(!candidate.is_native());
    assert!(!candidate.is_delegate());

    let promoted = PromotionStatus::Promoted {
        native_digest: "sha256:n".to_string(),
        receipt_id: "r".to_string(),
    };
    assert!(promoted.is_native());
    assert!(!promoted.is_delegate());

    let demoted = PromotionStatus::Demoted {
        reason: "regression".to_string(),
        rollback_digest: "sha256:rb".to_string(),
    };
    assert!(demoted.is_delegate());
    assert!(!demoted.is_native());
}

#[test]
fn promotion_transition_serde_roundtrip_all_variants() {
    for transition in [
        PromotionTransition::RegisteredDelegate,
        PromotionTransition::EnteredCandidacy,
        PromotionTransition::PromotedToNative,
        PromotionTransition::DemotedToDelegate,
        PromotionTransition::RolledBack,
    ] {
        let json = serde_json::to_string(&transition).expect("serialize");
        let recovered: PromotionTransition = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(transition, recovered);
    }
}

#[test]
fn lineage_event_serde_roundtrip() {
    let event = LineageEvent {
        transition: PromotionTransition::PromotedToNative,
        digest: "sha256:native-parser".to_string(),
        timestamp: "2026-03-14T00:00:00Z".to_string(),
        receipt_id: Some("receipt-001".to_string()),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: LineageEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, recovered);

    let event_no_receipt = LineageEvent {
        transition: PromotionTransition::RegisteredDelegate,
        digest: "sha256:delegate".to_string(),
        timestamp: "2026-03-14T00:00:00Z".to_string(),
        receipt_id: None,
    };
    let json2 = serde_json::to_string(&event_no_receipt).expect("serialize");
    let recovered2: LineageEvent = serde_json::from_str(&json2).expect("deserialize");
    assert_eq!(event_no_receipt, recovered2);
}

#[test]
fn slot_entry_serde_roundtrip() {
    let mut registry = SlotRegistry::new();
    let parser_id = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-p");
    let entry = registry.get(&parser_id).expect("slot should exist").clone();
    let json = serde_json::to_string(&entry).expect("serialize");
    let recovered: SlotEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(entry, recovered);
}

#[test]
fn release_slot_class_display_and_serde() {
    assert_eq!(ReleaseSlotClass::Core.to_string(), "core");
    assert_eq!(ReleaseSlotClass::NonCore.to_string(), "non-core");

    for class in [ReleaseSlotClass::Core, ReleaseSlotClass::NonCore] {
        let json = serde_json::to_string(&class).expect("serialize");
        let recovered: ReleaseSlotClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(class, recovered);
    }
}

#[test]
fn slot_registry_error_all_variants_display() {
    let errors: Vec<SlotRegistryError> = vec![
        SlotRegistryError::InvalidSlotId {
            id: "BAD".to_string(),
            reason: "uppercase".to_string(),
        },
        SlotRegistryError::DuplicateSlotId {
            id: "parser".to_string(),
        },
        SlotRegistryError::SlotNotFound {
            id: "missing".to_string(),
        },
        SlotRegistryError::InconsistentAuthority {
            id: "x".to_string(),
            detail: "required not in permitted".to_string(),
        },
        SlotRegistryError::InvalidTransition {
            id: "y".to_string(),
            from: "delegate".to_string(),
            to: "promoted".to_string(),
        },
        SlotRegistryError::AuthorityBroadening {
            id: "z".to_string(),
            detail: "wider than delegate".to_string(),
        },
    ];
    let mut messages = BTreeSet::new();
    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty());
        assert!(messages.insert(msg), "duplicate error message");
    }
    assert_eq!(messages.len(), 6);
}

#[test]
fn slot_registry_error_serde_roundtrip() {
    let err = SlotRegistryError::InvalidTransition {
        id: "parser".to_string(),
        from: "delegate".to_string(),
        to: "promoted".to_string(),
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: SlotRegistryError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, recovered);
}

#[test]
fn ga_release_guard_error_display_all_variants() {
    let errors: Vec<GaReleaseGuardError> = vec![
        GaReleaseGuardError::InvalidInput {
            field: "trace_id".to_string(),
            detail: "empty".to_string(),
        },
        GaReleaseGuardError::UnknownCoreSlot {
            slot_id: "missing".to_string(),
        },
        GaReleaseGuardError::InvalidExemption {
            exemption_id: "ex-1".to_string(),
            detail: "expired".to_string(),
        },
        GaReleaseGuardError::DuplicateExemption {
            slot_id: "parser".to_string(),
        },
        GaReleaseGuardError::InvalidLineageArtifact {
            slot_id: "parser".to_string(),
            detail: "bad digest".to_string(),
        },
        GaReleaseGuardError::DuplicateLineageArtifact {
            slot_id: "parser".to_string(),
        },
    ];
    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty());
    }
}

#[test]
fn ga_release_guard_error_serde_roundtrip() {
    let err = GaReleaseGuardError::UnknownCoreSlot {
        slot_id: "parser".to_string(),
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: GaReleaseGuardError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, recovered);
}

#[test]
fn slot_replacement_signal_default_values() {
    let signal = SlotReplacementSignal::default();
    assert_eq!(signal.invocation_weight_millionths, 1_000_000);
    assert_eq!(signal.throughput_uplift_millionths, 0);
    assert_eq!(signal.security_risk_reduction_millionths, 0);
}

#[test]
fn slot_replacement_signal_serde_roundtrip() {
    let signal = SlotReplacementSignal {
        invocation_weight_millionths: 500_000,
        throughput_uplift_millionths: 200_000,
        security_risk_reduction_millionths: -100_000,
    };
    let json = serde_json::to_string(&signal).expect("serialize");
    let recovered: SlotReplacementSignal = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(signal, recovered);
}

#[test]
fn replacement_progress_error_display_all_variants() {
    let errors: Vec<ReplacementProgressError> = vec![
        ReplacementProgressError::InvalidInput {
            field: "trace_id".to_string(),
            detail: "empty".to_string(),
        },
        ReplacementProgressError::UnknownSignalSlot {
            slot_id: "x".to_string(),
        },
        ReplacementProgressError::InvalidSignal {
            slot_id: "y".to_string(),
            detail: "zero weight".to_string(),
        },
    ];
    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty());
    }
}

#[test]
fn replacement_progress_error_serde_roundtrip() {
    let err = ReplacementProgressError::InvalidSignal {
        slot_id: "parser".to_string(),
        detail: "weight is zero".to_string(),
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: ReplacementProgressError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, recovered);
}

#[test]
fn slot_registry_iter_returns_all_registered_slots() {
    let mut registry = SlotRegistry::new();
    register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:p");
    register_slot(
        &mut registry,
        "interpreter",
        SlotKind::Interpreter,
        "sha256:i",
    );
    register_slot(&mut registry, "builtins", SlotKind::Builtins, "sha256:b");

    let ids: BTreeSet<String> = registry
        .iter()
        .map(|(id, _)| id.as_str().to_string())
        .collect();
    assert_eq!(ids.len(), 3);
    assert!(ids.contains("parser"));
    assert!(ids.contains("interpreter"));
    assert!(ids.contains("builtins"));
}

#[test]
fn slot_registry_native_coverage_tracks_promotions() {
    let mut registry = SlotRegistry::new();
    assert!(registry.native_coverage() == 0.0 || registry.native_coverage().is_nan());

    let parser = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d");
    let _interp = register_slot(
        &mut registry,
        "interpreter",
        SlotKind::Interpreter,
        "sha256:d2",
    );
    // 0 of 2 promoted
    assert!(registry.native_coverage() < 0.01);

    promote_slot(&mut registry, &parser, "sha256:n");
    // 1 of 2 promoted = 0.5
    let coverage = registry.native_coverage();
    assert!((coverage - 0.5).abs() < 0.01);
}

#[test]
fn authority_envelope_not_consistent_when_required_exceeds_permitted() {
    let auth = AuthorityEnvelope {
        required: vec![SlotCapability::ReadSource, SlotCapability::TriggerGc],
        permitted: vec![SlotCapability::ReadSource],
    };
    assert!(!auth.is_consistent());
}

#[test]
fn authority_envelope_subsumes_fails_when_candidate_has_wider_caps() {
    let narrow = AuthorityEnvelope {
        required: vec![SlotCapability::ReadSource],
        permitted: vec![SlotCapability::ReadSource],
    };
    let wide = AuthorityEnvelope {
        required: vec![SlotCapability::ReadSource],
        permitted: vec![
            SlotCapability::ReadSource,
            SlotCapability::EmitIr,
            SlotCapability::HeapAlloc,
        ],
    };
    assert!(!narrow.subsumes(&wide));
    assert!(wide.subsumes(&narrow));
}

#[test]
fn core_slot_exemption_serde_roundtrip() {
    let exemption = CoreSlotExemption {
        exemption_id: "ex-001".to_string(),
        slot_id: SlotId::new("parser").expect("valid"),
        approved_by: "eng-lead".to_string(),
        signed_risk_acknowledgement: "acknowledged".to_string(),
        remediation_plan: "promote parser by epoch 200".to_string(),
        remediation_deadline_epoch: 200,
        expires_at_epoch: 150,
    };
    let json = serde_json::to_string(&exemption).expect("serialize");
    let recovered: CoreSlotExemption = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(exemption, recovered);
}

#[test]
fn ga_release_guard_artifact_serde_roundtrip() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-p");
    promote_slot(&mut registry, &parser, "sha256:n-p");
    let core_slots = BTreeSet::from([parser.clone()]);
    let mut input = pipeline_input(core_slots, Some(5));
    input.lineage_artifacts = vec![lineage_artifact(&parser, "sha256:d-p", "sha256:n-p")];
    let artifact = registry
        .evaluate_ga_release_guard(&input)
        .expect("guard evaluation");
    let json = serde_json::to_string(&artifact).expect("serialize");
    let recovered: frankenengine_engine::slot_registry::GaReleaseGuardArtifact =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact, recovered);
}

#[test]
fn slot_registry_serde_roundtrip_with_data() {
    let mut registry = SlotRegistry::new();
    register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-p");
    register_slot(
        &mut registry,
        "interpreter",
        SlotKind::Interpreter,
        "sha256:d-i",
    );
    let json = serde_json::to_string(&registry).expect("serialize");
    let recovered: SlotRegistry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(registry.len(), recovered.len());
    assert_eq!(registry.native_count(), recovered.native_count());
    assert_eq!(registry.delegate_count(), recovered.delegate_count());
}

#[test]
fn slot_registry_promotion_lineage_records_events() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(&mut registry, "parser", SlotKind::Parser, "sha256:d-p");
    let entry = registry.get(&parser).expect("slot exists");
    assert_eq!(entry.promotion_lineage.len(), 1);
    assert_eq!(
        entry.promotion_lineage[0].transition,
        PromotionTransition::RegisteredDelegate
    );

    promote_slot(&mut registry, &parser, "sha256:n-p");
    let entry = registry.get(&parser).expect("slot exists");
    // RegisteredDelegate + EnteredCandidacy + PromotedToNative = 3
    assert_eq!(entry.promotion_lineage.len(), 3);
    assert_eq!(
        entry.promotion_lineage[1].transition,
        PromotionTransition::EnteredCandidacy
    );
    assert_eq!(
        entry.promotion_lineage[2].transition,
        PromotionTransition::PromotedToNative
    );
}
