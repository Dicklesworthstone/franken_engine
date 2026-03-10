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
    AuthorityEnvelope, GaReleaseGuardConfig, GaReleaseGuardInput, GaReleaseGuardVerdict,
    GaSignedLineageArtifact, PromotionStatus, SlotCapability, SlotId, SlotKind, SlotRegistry,
    SlotRegistryError,
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
