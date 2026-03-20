#![forbid(unsafe_code)]
//! Comprehensive integration tests for the `execution_orchestrator` module.

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
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterError, LaneChoice};
use frankenengine_engine::bayesian_posterior::RiskState;
use frankenengine_engine::control_plane_mock_inventory::{
    OrchestratorContextRefactorOutcome, OrchestratorContextRefactorRunManifest,
    write_orchestrator_context_refactor_bundle_in_root,
};
use frankenengine_engine::declassification_pipeline::{
    DeclassificationPipeline, DeclassificationRequest, LossAssessment,
};
use frankenengine_engine::execution_cell::CellError;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LossMatrixPreset, OrchestratorConfig,
    OrchestratorError, OrchestratorResult,
};
use frankenengine_engine::expected_loss_selector::ContainmentAction;
use frankenengine_engine::ifc_artifacts::{
    DeclassificationRoute, FlowPolicy, IfcSchemaVersion, Label,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{SIGNATURE_SENTINEL, Signature, SigningKey};

const TEST_DECLASS_ROUTE_ID: &str = "declassify.audit";
const EXPECTED_REPLAY_HINT: &str = "frankenctl replay run --trace <trace.json> --mode strict";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn simple_package(id: &str, source: &str) -> ExtensionPackage {
    ExtensionPackage {
        extension_id: id.to_string(),
        source: source.to_string(),
        source_file: None,
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    }
}

fn package_with_caps(id: &str, source: &str, caps: &[&str]) -> ExtensionPackage {
    ExtensionPackage {
        extension_id: id.to_string(),
        source: source.to_string(),
        source_file: None,
        capabilities: caps.iter().map(|c| c.to_string()).collect(),
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    }
}

fn package_with_metadata(id: &str, source: &str, meta: &[(&str, &str)]) -> ExtensionPackage {
    let mut metadata = BTreeMap::new();
    for (k, v) in meta {
        metadata.insert(k.to_string(), v.to_string());
    }
    ExtensionPackage {
        extension_id: id.to_string(),
        source: source.to_string(),
        source_file: None,
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata,
    }
}

fn default_orch() -> ExecutionOrchestrator {
    ExecutionOrchestrator::with_defaults()
}

fn orch_with_preset(preset: LossMatrixPreset) -> ExecutionOrchestrator {
    ExecutionOrchestrator::new(OrchestratorConfig {
        loss_matrix_preset: preset,
        ..OrchestratorConfig::default()
    })
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be monotonic enough for temp paths")
        .as_nanos();
    let dir = env::temp_dir().join(format!("{prefix}-{nanos}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn execute_simple(orch: &mut ExecutionOrchestrator) -> OrchestratorResult {
    orch.execute(&simple_package("ext-test", "42"))
        .expect("execute should succeed")
}

fn declassification_policy(extension_id: &str) -> FlowPolicy {
    FlowPolicy {
        policy_id: "policy-orchestrator-declass".to_string(),
        extension_id: extension_id.to_string(),
        label_classes: [
            Label::Public,
            Label::Internal,
            Label::Confidential,
            Label::Secret,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>(),
        clearance_classes: [
            Label::Public,
            Label::Internal,
            Label::Confidential,
            Label::Secret,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>(),
        allowed_flows: vec![],
        prohibited_flows: vec![],
        declassification_routes: vec![DeclassificationRoute {
            route_id: TEST_DECLASS_ROUTE_ID.to_string(),
            source_label: Label::Secret,
            target_clearance: Label::Public,
            conditions: vec!["audit_approval".to_string()],
        }],
        epoch_id: 1,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    }
}

fn low_loss_assessment() -> LossAssessment {
    LossAssessment {
        expected_loss_milli: 10_000,
        data_sensitivity_bps: 1_200,
        sink_exposure_bps: 800,
        historical_abuse_detected: false,
        summary: "low risk".to_string(),
    }
}

fn approved_receipt_for_prepared_declassification(
    orch: &mut ExecutionOrchestrator,
    pkg: &ExtensionPackage,
    prepared: &frankenengine_engine::execution_orchestrator::PreparedRuntimeFlowGuards,
    signing_key: &SigningKey,
) -> (
    String,
    frankenengine_engine::ifc_artifacts::DeclassificationReceipt,
) {
    let obligation = prepared
        .ir2_flow_proof_artifact
        .required_declassifications
        .first()
        .expect("prepared flow guards should expose one declassification obligation");
    let request = DeclassificationRequest {
        request_id: format!("req-{}", prepared.trace_id),
        source_label: Label::Secret,
        sink_clearance: Label::Public,
        extension_id: pkg.extension_id.clone(),
        code_location: "execution_orchestrator_integration::declassify".to_string(),
        trace_id: prepared.trace_id.clone(),
        requested_route_id: obligation
            .declassification_route_ref
            .clone()
            .unwrap_or_else(|| TEST_DECLASS_ROUTE_ID.to_string()),
        decision_contract_id: prepared.decision_id.clone(),
        is_emergency: false,
        timestamp_ms: 1_700_000_010_000,
    };
    let mut pipeline = DeclassificationPipeline::default();
    let receipt = pipeline
        .process(
            &request,
            &declassification_policy(&pkg.extension_id),
            &low_loss_assessment(),
            signing_key,
        )
        .expect("declassification request should be approved");
    assert_eq!(
        receipt.declassification_route_ref.as_str(),
        obligation
            .declassification_route_ref
            .as_deref()
            .unwrap_or(TEST_DECLASS_ROUTE_ID)
    );

    orch.trust_declassification_authorizer_for_contract(
        prepared.decision_id.clone(),
        signing_key.verification_key(),
    );

    (obligation.obligation_id.clone(), receipt)
}

fn assert_required_declassification_summary_in_detail(
    detail: &str,
    obligation: &frankenengine_engine::lowering_pipeline::RequiredDeclassificationArtifactEntry,
) {
    let mut expected_parts = vec![format!(
        "{}@op{}",
        obligation.obligation_id, obligation.op_index
    )];
    if let Some(capability) = obligation.capability.as_deref() {
        expected_parts.push(format!("capability={capability}"));
    }
    expected_parts.push(format!(
        "decision_contract={}",
        obligation.decision_contract_id
    ));
    if let Some(route) = obligation.declassification_route_ref.as_deref() {
        expected_parts.push(format!("route={route}"));
    }
    expected_parts.push(format!("replay_hint='{EXPECTED_REPLAY_HINT}'"));

    let expected_summary = expected_parts.join(" ");
    assert!(detail.contains(&expected_summary));
    assert!(!detail.contains("--obligation"));
}

// =========================================================================
// Section 1: End-to-end pipeline
// =========================================================================

#[test]
fn e2e_simple_literal_produces_complete_result() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);

    assert_eq!(result.extension_id, "ext-test");
    assert!(!result.trace_id.is_empty());
    assert!(!result.decision_id.is_empty());
    assert!(!result.source_label.is_empty());
    assert!(result.posterior.is_valid());
    assert!(!result.evidence_entries.is_empty());
    assert!(result.instructions_executed > 0);
    assert_eq!(result.epoch, SecurityEpoch::from_raw(1));
}

#[test]
fn declared_package_capability_allows_orchestrated_hostcall_execution() {
    let mut orch = default_orch();
    let pkg = package_with_caps(
        "ext-hostcall-allow",
        r#""hostcall<\"net.write\">";"#,
        &["net.write"],
    );

    let result = orch
        .execute(&pkg)
        .expect("declared package capability should reach the interpreter lane");

    assert_eq!(result.execution_value, "undefined");
    assert!(result.instructions_executed > 0);
}

#[test]
fn missing_package_capability_denies_orchestrated_hostcall_execution() {
    let mut orch = default_orch();
    let pkg = simple_package("ext-hostcall-deny", r#""hostcall<\"net.write\">";"#);

    let err = orch
        .execute(&pkg)
        .expect_err("hostcall should fail closed when package capability is missing");

    match err {
        OrchestratorError::Interpreter(InterpreterError::CapabilityDenied { capability }) => {
            assert_eq!(capability, "net.write");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn staged_receipt_allows_public_orchestrator_declassification_without_internal_guard_capability() {
    let mut orch = default_orch();
    let pkg = package_with_caps(
        "ext-declassify-allow",
        r#""hostcall<\"declassify.audit\"> secret_token";"#,
        &["declassify.audit"],
    );

    assert!(
        !pkg.capabilities.iter().any(|cap| cap == "ifc.check_flow"),
        "packages should not need to declare the internal IFC runtime guard capability"
    );

    let prepared = orch
        .prepare_next_runtime_flow_guards(&pkg)
        .expect("preflight should expose the declassification obligation");
    assert_eq!(
        prepared
            .ir2_flow_proof_artifact
            .required_declassifications
            .len(),
        1
    );
    let obligation = &prepared.ir2_flow_proof_artifact.required_declassifications[0];
    assert_eq!(obligation.capability.as_deref(), Some("declassify.audit"));
    assert_eq!(obligation.decision_contract_id, prepared.decision_id);
    assert_eq!(
        obligation.declassification_route_ref.as_deref(),
        Some(TEST_DECLASS_ROUTE_ID)
    );

    let signing_key = SigningKey::from_bytes([23u8; 32]);
    let (obligation_id, receipt) =
        approved_receipt_for_prepared_declassification(&mut orch, &pkg, &prepared, &signing_key);
    assert_eq!(
        receipt.declassification_route_ref.as_str(),
        TEST_DECLASS_ROUTE_ID
    );
    orch.stage_declassification_receipt_for_obligation(
        prepared.trace_id.clone(),
        obligation_id,
        receipt,
    );

    let result = orch
        .execute(&pkg)
        .expect("approved staged receipt should allow the runtime-guarded declassification path");

    assert_eq!(result.trace_id, prepared.trace_id);
    assert_eq!(result.decision_id, prepared.decision_id);
    assert_eq!(result.execution_value, "undefined");
    assert!(result.instructions_executed > 0);
}

#[test]
fn unresolved_declassification_obligation_surfaces_operator_detail_on_execute_path() {
    let mut orch = default_orch();
    let pkg = package_with_caps(
        "ext-declassify-unresolved",
        r#""hostcall<\"declassify.audit\"> secret_token";"#,
        &["declassify.audit"],
    );

    let prepared = orch
        .prepare_next_runtime_flow_guards(&pkg)
        .expect("preflight should expose the declassification obligation");
    let obligation = prepared
        .ir2_flow_proof_artifact
        .required_declassifications
        .first()
        .expect("preflight should expose one declassification obligation");

    let err = orch
        .execute(&pkg)
        .expect_err("unresolved declassification should fail closed on the execute path");
    match err {
        OrchestratorError::IfcRuntimeGuardBlocked { detail } => {
            assert!(detail.contains("unresolved IFC runtime obligations"));
            assert!(detail.contains("pending declassifications=1"));
            assert_required_declassification_summary_in_detail(&detail, obligation);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn staged_receipt_with_route_mismatch_fails_closed_after_preflight() {
    let mut orch = default_orch();
    let pkg = package_with_caps(
        "ext-declassify-route-mismatch",
        r#""hostcall<\"declassify.audit\"> secret_token";"#,
        &["declassify.audit"],
    );

    let prepared = orch
        .prepare_next_runtime_flow_guards(&pkg)
        .expect("preflight should expose the declassification obligation");
    let obligation = prepared
        .ir2_flow_proof_artifact
        .required_declassifications
        .first()
        .expect("preflight should expose one declassification obligation");
    assert_eq!(
        obligation.declassification_route_ref.as_deref(),
        Some(TEST_DECLASS_ROUTE_ID)
    );

    let signing_key = SigningKey::from_bytes([41u8; 32]);
    let (obligation_id, receipt) =
        approved_receipt_for_prepared_declassification(&mut orch, &pkg, &prepared, &signing_key);
    let mut wrong_route_receipt = receipt.clone();
    wrong_route_receipt.declassification_route_ref = "declassify.other".to_string();
    wrong_route_receipt
        .sign(&signing_key)
        .expect("mutated route receipt should be re-signed");
    orch.stage_declassification_receipt_for_obligation(
        prepared.trace_id.clone(),
        obligation_id,
        wrong_route_receipt,
    );

    let err = orch
        .execute(&pkg)
        .expect_err("route-mismatched staged receipt must fail closed");
    match err {
        OrchestratorError::IfcRuntimeGuardBlocked { detail } => {
            assert!(detail.contains("receipt-linked declassification failed"));
            assert!(detail.contains("route"));
            assert_required_declassification_summary_in_detail(&detail, obligation);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn failed_staged_receipt_with_decision_contract_mismatch_allows_clean_retry() {
    let mut orch = default_orch();
    let pkg = package_with_caps(
        "ext-declassify-contract-mismatch",
        r#""hostcall<\"declassify.audit\"> secret_token";"#,
        &["declassify.audit"],
    );

    let first_prepared = orch
        .prepare_next_runtime_flow_guards(&pkg)
        .expect("initial preflight should succeed");
    let first_obligation = first_prepared
        .ir2_flow_proof_artifact
        .required_declassifications
        .first()
        .expect("initial preflight should expose a declassification obligation");

    let bad_signing_key = SigningKey::from_bytes([26u8; 32]);
    let (_, bad_receipt) = approved_receipt_for_prepared_declassification(
        &mut orch,
        &pkg,
        &first_prepared,
        &bad_signing_key,
    );
    let mut wrong_contract_receipt = bad_receipt.clone();
    wrong_contract_receipt.decision_contract_id = "decision-other".to_string();
    wrong_contract_receipt
        .sign(&bad_signing_key)
        .expect("mutated receipt should be re-signed for a valid contract-mismatch test");
    orch.stage_declassification_receipt_for_obligation(
        first_prepared.trace_id.clone(),
        first_obligation.obligation_id.clone(),
        wrong_contract_receipt,
    );

    let first_err = orch
        .execute(&pkg)
        .expect_err("contract-mismatched staged receipt should fail closed");
    match first_err {
        OrchestratorError::IfcRuntimeGuardBlocked { detail } => {
            assert!(detail.contains("receipt-linked declassification failed"));
            assert!(detail.contains("decision contract"));
            assert_required_declassification_summary_in_detail(&detail, first_obligation);
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let second_prepared = orch
        .prepare_next_runtime_flow_guards(&pkg)
        .expect("fresh preflight should still succeed after the failed attempt");
    assert_ne!(second_prepared.trace_id, first_prepared.trace_id);
    assert_ne!(second_prepared.decision_id, first_prepared.decision_id);

    let good_signing_key = SigningKey::from_bytes([27u8; 32]);
    let (second_obligation_id, good_receipt) = approved_receipt_for_prepared_declassification(
        &mut orch,
        &pkg,
        &second_prepared,
        &good_signing_key,
    );
    orch.stage_declassification_receipt_for_obligation(
        second_prepared.trace_id.clone(),
        second_obligation_id,
        good_receipt,
    );

    let result = orch
        .execute(&pkg)
        .expect("fresh preflight and valid receipt should recover after contract mismatch");
    assert_eq!(result.trace_id, second_prepared.trace_id);
    assert_eq!(result.decision_id, second_prepared.decision_id);
    assert_eq!(result.execution_value, "undefined");
}

#[test]
fn failed_staged_receipt_with_source_label_mismatch_allows_clean_retry() {
    let mut orch = default_orch();
    let pkg = package_with_caps(
        "ext-declassify-source-mismatch",
        r#""hostcall<\"declassify.audit\"> secret_token";"#,
        &["declassify.audit"],
    );

    let first_prepared = orch
        .prepare_next_runtime_flow_guards(&pkg)
        .expect("initial preflight should succeed");
    let first_obligation = first_prepared
        .ir2_flow_proof_artifact
        .required_declassifications
        .first()
        .expect("initial preflight should expose a declassification obligation");

    let bad_signing_key = SigningKey::from_bytes([28u8; 32]);
    let (_, bad_receipt) = approved_receipt_for_prepared_declassification(
        &mut orch,
        &pkg,
        &first_prepared,
        &bad_signing_key,
    );
    let mut wrong_source_receipt = bad_receipt.clone();
    wrong_source_receipt.source_label = Label::Public;
    wrong_source_receipt
        .sign(&bad_signing_key)
        .expect("mutated receipt should be re-signed for a valid source-label mismatch test");
    orch.stage_declassification_receipt_for_obligation(
        first_prepared.trace_id.clone(),
        first_obligation.obligation_id.clone(),
        wrong_source_receipt,
    );

    let first_err = orch
        .execute(&pkg)
        .expect_err("source-label-mismatched staged receipt should fail closed");
    match first_err {
        OrchestratorError::IfcRuntimeGuardBlocked { detail } => {
            assert!(detail.contains("receipt-linked declassification failed"));
            assert!(detail.contains("source label does not match"));
            assert_required_declassification_summary_in_detail(&detail, first_obligation);
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let second_prepared = orch
        .prepare_next_runtime_flow_guards(&pkg)
        .expect("fresh preflight should still succeed after the failed attempt");
    assert_ne!(second_prepared.trace_id, first_prepared.trace_id);
    assert_ne!(second_prepared.decision_id, first_prepared.decision_id);

    let good_signing_key = SigningKey::from_bytes([29u8; 32]);
    let (second_obligation_id, good_receipt) = approved_receipt_for_prepared_declassification(
        &mut orch,
        &pkg,
        &second_prepared,
        &good_signing_key,
    );
    orch.stage_declassification_receipt_for_obligation(
        second_prepared.trace_id.clone(),
        second_obligation_id,
        good_receipt,
    );

    let result = orch
        .execute(&pkg)
        .expect("fresh preflight and valid receipt should recover after source-label mismatch");
    assert_eq!(result.trace_id, second_prepared.trace_id);
    assert_eq!(result.decision_id, second_prepared.decision_id);
    assert_eq!(result.execution_value, "undefined");
}

#[test]
fn failed_staged_receipt_with_sink_clearance_mismatch_allows_clean_retry() {
    let mut orch = default_orch();
    let pkg = package_with_caps(
        "ext-declassify-sink-mismatch",
        r#""hostcall<\"declassify.audit\"> secret_token";"#,
        &["declassify.audit"],
    );

    let first_prepared = orch
        .prepare_next_runtime_flow_guards(&pkg)
        .expect("initial preflight should succeed");
    let first_obligation = first_prepared
        .ir2_flow_proof_artifact
        .required_declassifications
        .first()
        .expect("initial preflight should expose a declassification obligation");

    let bad_signing_key = SigningKey::from_bytes([30u8; 32]);
    let (_, bad_receipt) = approved_receipt_for_prepared_declassification(
        &mut orch,
        &pkg,
        &first_prepared,
        &bad_signing_key,
    );
    let mut wrong_sink_receipt = bad_receipt.clone();
    wrong_sink_receipt.sink_clearance = Label::Internal;
    wrong_sink_receipt
        .sign(&bad_signing_key)
        .expect("mutated receipt should be re-signed for a valid sink-clearance mismatch test");
    orch.stage_declassification_receipt_for_obligation(
        first_prepared.trace_id.clone(),
        first_obligation.obligation_id.clone(),
        wrong_sink_receipt,
    );

    let first_err = orch
        .execute(&pkg)
        .expect_err("sink-clearance-mismatched staged receipt should fail closed");
    match first_err {
        OrchestratorError::IfcRuntimeGuardBlocked { detail } => {
            assert!(detail.contains("receipt-linked declassification failed"));
            assert!(detail.contains("sink clearance internal cannot flow"));
            assert_required_declassification_summary_in_detail(&detail, first_obligation);
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let second_prepared = orch
        .prepare_next_runtime_flow_guards(&pkg)
        .expect("fresh preflight should still succeed after the failed attempt");
    assert_ne!(second_prepared.trace_id, first_prepared.trace_id);
    assert_ne!(second_prepared.decision_id, first_prepared.decision_id);

    let good_signing_key = SigningKey::from_bytes([31u8; 32]);
    let (second_obligation_id, good_receipt) = approved_receipt_for_prepared_declassification(
        &mut orch,
        &pkg,
        &second_prepared,
        &good_signing_key,
    );
    orch.stage_declassification_receipt_for_obligation(
        second_prepared.trace_id.clone(),
        second_obligation_id,
        good_receipt,
    );

    let result = orch
        .execute(&pkg)
        .expect("fresh preflight and valid receipt should recover after sink-clearance mismatch");
    assert_eq!(result.trace_id, second_prepared.trace_id);
    assert_eq!(result.decision_id, second_prepared.decision_id);
    assert_eq!(result.execution_value, "undefined");
}

#[test]
fn failed_staged_receipt_allows_clean_retry_via_fresh_preflight_and_receipt() {
    let mut orch = default_orch();
    let pkg = package_with_caps(
        "ext-declassify-retry",
        r#""hostcall<\"declassify.audit\"> secret_token";"#,
        &["declassify.audit"],
    );

    let first_prepared = orch
        .prepare_next_runtime_flow_guards(&pkg)
        .expect("initial preflight should succeed");
    let first_obligation = first_prepared
        .ir2_flow_proof_artifact
        .required_declassifications
        .first()
        .expect("initial preflight should expose a declassification obligation");
    let bad_signing_key = SigningKey::from_bytes([24u8; 32]);
    let (_, bad_receipt) = approved_receipt_for_prepared_declassification(
        &mut orch,
        &pkg,
        &first_prepared,
        &bad_signing_key,
    );
    let mut wrong_trace_receipt = bad_receipt.clone();
    wrong_trace_receipt.replay_linkage = "trace-other".to_string();
    wrong_trace_receipt
        .sign(&bad_signing_key)
        .expect("mutated receipt should be re-signed for a valid invalid-linkage test");
    orch.stage_declassification_receipt_for_obligation(
        first_prepared.trace_id.clone(),
        first_obligation.obligation_id.clone(),
        wrong_trace_receipt,
    );

    let first_err = orch
        .execute(&pkg)
        .expect_err("invalid staged receipt should fail closed");
    match first_err {
        OrchestratorError::IfcRuntimeGuardBlocked { detail } => {
            assert!(detail.contains("receipt-linked declassification failed"));
            assert!(detail.contains("replay linkage does not match trace"));
            assert_required_declassification_summary_in_detail(&detail, first_obligation);
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let second_prepared = orch
        .prepare_next_runtime_flow_guards(&pkg)
        .expect("fresh preflight should still succeed after the failed attempt");
    assert_ne!(second_prepared.trace_id, first_prepared.trace_id);
    assert_ne!(second_prepared.decision_id, first_prepared.decision_id);

    let good_signing_key = SigningKey::from_bytes([25u8; 32]);
    let (second_obligation_id, good_receipt) = approved_receipt_for_prepared_declassification(
        &mut orch,
        &pkg,
        &second_prepared,
        &good_signing_key,
    );
    orch.stage_declassification_receipt_for_obligation(
        second_prepared.trace_id.clone(),
        second_obligation_id,
        good_receipt,
    );

    let result = orch
        .execute(&pkg)
        .expect("fresh preflight and valid receipt should recover after the failed attempt");
    assert_eq!(result.trace_id, second_prepared.trace_id);
    assert_eq!(result.decision_id, second_prepared.decision_id);
    assert_eq!(result.execution_value, "undefined");
}

#[test]
fn e2e_result_has_lowering_witnesses() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    assert!(!result.lowering_witnesses.is_empty());
}

#[test]
fn e2e_result_has_lowering_events() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    assert!(!result.lowering_events.is_empty());
}

#[test]
fn e2e_result_has_cell_events() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    assert!(!result.cell_events.is_empty());
}

#[test]
fn e2e_result_has_finalize_result() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    assert!(result.finalize_result.is_some());
}

#[test]
fn low_cell_close_budget_returns_cell_budget_exhausted_error() {
    let cfg = OrchestratorConfig {
        cell_close_budget_ms: 1,
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(cfg);
    let err = orch
        .execute(&simple_package("ext-budget", "42"))
        .expect_err("close budget should fail fast");

    match err {
        OrchestratorError::Cell(CellError::BudgetExhausted {
            requested_ms,
            remaining_ms,
            ..
        }) => {
            assert_eq!(requested_ms, 2);
            assert_eq!(remaining_ms, 1);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn production_orchestrator_source_avoids_control_plane_mocks() {
    let path = format!(
        "{}/src/execution_orchestrator.rs",
        env!("CARGO_MANIFEST_DIR")
    );
    let source = fs::read_to_string(path).expect("read execution_orchestrator source");

    assert!(!source.contains("use crate::control_plane::mocks"));
    assert!(!source.contains("MockCx::new("));
    assert!(!source.contains("MockBudget::new("));
    assert!(!source.contains("trace_id_from_seed"));
}

#[test]
fn orchestrator_context_refactor_bundle_emits_expected_artifacts() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize workspace root");
    let out_dir = unique_temp_dir("orchestrator-context-refactor");
    let commands = vec![
        "cargo run -p frankenengine-engine --bin franken_orchestrator_context_refactor -- --out-dir /tmp/out"
            .to_string(),
    ];

    let artifacts =
        write_orchestrator_context_refactor_bundle_in_root(&workspace_root, &out_dir, &commands)
            .expect("bundle should be written");

    assert_eq!(artifacts.outcome, OrchestratorContextRefactorOutcome::Pass);
    assert!(artifacts.contract_path.exists());
    assert!(artifacts.report_path.exists());
    assert!(artifacts.trace_ids_path.exists());
    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.events_path.exists());
    assert!(artifacts.commands_path.exists());
    assert!(artifacts.step_logs_dir.join("step_001_scan.log").exists());
    assert!(artifacts.summary_path.exists());
    assert!(artifacts.env_path.exists());
    assert!(artifacts.repro_lock_path.exists());

    let manifest: OrchestratorContextRefactorRunManifest =
        serde_json::from_slice(&fs::read(&artifacts.run_manifest_path).expect("read manifest"))
            .expect("manifest should deserialize");
    assert_eq!(manifest.outcome, OrchestratorContextRefactorOutcome::Pass);
    assert_eq!(
        manifest.artifact_paths.production_context_path_contract,
        "production_context_path_contract.json"
    );
    assert_eq!(
        manifest.artifact_paths.orchestrator_context_refactor_report,
        "orchestrator_context_refactor_report.json"
    );

    let _ = fs::remove_dir_all(out_dir);
}

#[test]
fn e2e_result_has_adaptive_router_summary() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    assert!(result.adaptive_router_summary.is_some());
}

#[test]
fn e2e_result_has_ir3_schedule_cost() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    assert!(result.ir3_schedule_cost.is_some());
}

#[test]
fn e2e_result_has_optimal_stopping_certificate() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    assert!(result.optimal_stopping_certificate.is_some());
}

#[test]
fn e2e_result_has_evidence_compression_certificate() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    assert!(result.evidence_compression_certificate.is_some());
}

// =========================================================================
// Section 2: Validation errors
// =========================================================================

#[test]
fn empty_source_returns_empty_source_error() {
    let mut orch = default_orch();
    let pkg = simple_package("ext-1", "");
    let err = orch.execute(&pkg).expect_err("should fail");
    assert!(matches!(err, OrchestratorError::EmptySource));
}

#[test]
fn whitespace_only_source_returns_empty_source_error() {
    let mut orch = default_orch();
    let pkg = simple_package("ext-ws", "   \t\n  ");
    let err = orch.execute(&pkg).expect_err("should fail");
    assert!(matches!(err, OrchestratorError::EmptySource));
}

#[test]
fn empty_extension_id_returns_empty_id_error() {
    let mut orch = default_orch();
    let pkg = simple_package("", "42");
    let err = orch.execute(&pkg).expect_err("should fail");
    assert!(matches!(err, OrchestratorError::EmptyExtensionId));
}

#[test]
fn whitespace_only_extension_id_returns_empty_id_error() {
    let mut orch = default_orch();
    let pkg = simple_package("   ", "42");
    let err = orch.execute(&pkg).expect_err("should fail");
    assert!(matches!(err, OrchestratorError::EmptyExtensionId));
}

#[test]
fn both_empty_source_and_id_returns_first_validation_error() {
    let mut orch = default_orch();
    let pkg = simple_package("", "");
    let err = orch.execute(&pkg).expect_err("should fail");
    // Source is checked first in validate_package
    assert!(matches!(err, OrchestratorError::EmptySource));
}

// =========================================================================
// Section 3: OrchestratorError Display + trait
// =========================================================================

#[test]
fn error_display_empty_source_contains_keyword() {
    let err = OrchestratorError::EmptySource;
    assert!(err.to_string().contains("empty"), "got: {}", err);
}

#[test]
fn error_display_empty_extension_id_contains_keyword() {
    let err = OrchestratorError::EmptyExtensionId;
    let msg = err.to_string();
    assert!(
        msg.contains("extension_id") || msg.contains("empty"),
        "got: {msg}"
    );
}

#[test]
fn error_display_variants_are_distinct() {
    let a = OrchestratorError::EmptySource.to_string();
    let b = OrchestratorError::EmptyExtensionId.to_string();
    assert_ne!(a, b);
}

#[test]
fn error_implements_std_error_trait() {
    let e: Box<dyn std::error::Error> = Box::new(OrchestratorError::EmptySource);
    assert!(!e.to_string().is_empty());
}

// =========================================================================
// Section 4: LossMatrixPreset
// =========================================================================

#[test]
fn loss_matrix_preset_serde_roundtrip_all_variants() {
    for preset in [
        LossMatrixPreset::Balanced,
        LossMatrixPreset::Conservative,
        LossMatrixPreset::Permissive,
    ] {
        let json = serde_json::to_string(&preset).unwrap();
        let back: LossMatrixPreset = serde_json::from_str(&json).unwrap();
        assert_eq!(preset, back, "roundtrip failed for {preset:?}");
    }
}

#[test]
fn loss_matrix_preset_debug_format() {
    assert_eq!(format!("{:?}", LossMatrixPreset::Balanced), "Balanced");
    assert_eq!(
        format!("{:?}", LossMatrixPreset::Conservative),
        "Conservative"
    );
    assert_eq!(format!("{:?}", LossMatrixPreset::Permissive), "Permissive");
}

#[test]
fn loss_matrix_preset_copy_and_clone() {
    let a = LossMatrixPreset::Balanced;
    let b = a; // Copy
    let c = a; // Clone
    assert_eq!(a, b);
    assert_eq!(a, c);
}

#[test]
fn loss_matrix_preset_eq_ne() {
    assert_eq!(LossMatrixPreset::Balanced, LossMatrixPreset::Balanced);
    assert_ne!(LossMatrixPreset::Balanced, LossMatrixPreset::Conservative);
    assert_ne!(LossMatrixPreset::Conservative, LossMatrixPreset::Permissive);
    assert_ne!(LossMatrixPreset::Permissive, LossMatrixPreset::Balanced);
}

// =========================================================================
// Section 5: OrchestratorConfig
// =========================================================================

#[test]
fn default_config_field_values() {
    let cfg = OrchestratorConfig::default();
    assert_eq!(cfg.loss_matrix_preset, LossMatrixPreset::Balanced);
    assert!(cfg.force_lane.is_none());
    assert_eq!(cfg.drain_deadline_ticks, 10_000);
    assert_eq!(cfg.cell_close_budget_ms, 10_000);
    assert_eq!(cfg.max_concurrent_sagas, 4);
    assert_eq!(cfg.epoch, SecurityEpoch::from_raw(1));
    assert_eq!(cfg.parse_goal, ParseGoal::Script);
    assert_eq!(cfg.trace_id_prefix, "orch");
    assert_eq!(cfg.policy_id, "default-policy");
}

#[test]
fn config_clone_preserves_all_fields() {
    let cfg = OrchestratorConfig {
        loss_matrix_preset: LossMatrixPreset::Conservative,
        force_lane: Some(LaneChoice::V8),
        drain_deadline_ticks: 99_999,
        cell_close_budget_ms: 77,
        max_concurrent_sagas: 16,
        epoch: SecurityEpoch::from_raw(77),
        parse_goal: ParseGoal::Module,
        trace_id_prefix: "clone-test".to_string(),
        policy_id: "policy-clone".to_string(),
        parser_options: Default::default(),
    };
    let cloned = cfg.clone();
    assert_eq!(cloned.loss_matrix_preset, LossMatrixPreset::Conservative);
    assert_eq!(cloned.force_lane, Some(LaneChoice::V8));
    assert_eq!(cloned.drain_deadline_ticks, 99_999);
    assert_eq!(cloned.cell_close_budget_ms, 77);
    assert_eq!(cloned.max_concurrent_sagas, 16);
    assert_eq!(cloned.epoch, SecurityEpoch::from_raw(77));
    assert_eq!(cloned.parse_goal, ParseGoal::Module);
    assert_eq!(cloned.trace_id_prefix, "clone-test");
    assert_eq!(cloned.policy_id, "policy-clone");
}

// =========================================================================
// Section 6: ExtensionPackage serde
// =========================================================================

#[test]
fn extension_package_serde_roundtrip() {
    let pkg = ExtensionPackage {
        extension_id: "ext-serde".to_string(),
        source: "1+2".to_string(),
        source_file: None,
        capabilities: vec!["fs_read".to_string(), "net".to_string()],
        version: "2.0.0".to_string(),
        metadata: {
            let mut m = BTreeMap::new();
            m.insert("author".to_string(), "test".to_string());
            m
        },
    };
    let json = serde_json::to_string(&pkg).unwrap();
    let back: ExtensionPackage = serde_json::from_str(&json).unwrap();
    assert_eq!(back.extension_id, "ext-serde");
    assert_eq!(back.source, "1+2");
    assert_eq!(back.capabilities.len(), 2);
    assert_eq!(back.version, "2.0.0");
    assert_eq!(back.metadata.get("author").unwrap(), "test");
}

#[test]
fn extension_package_empty_metadata_serde() {
    let pkg = simple_package("ext-empty-meta", "42");
    let json = serde_json::to_string(&pkg).unwrap();
    let restored: ExtensionPackage = serde_json::from_str(&json).unwrap();
    assert!(restored.metadata.is_empty());
    assert_eq!(restored.extension_id, "ext-empty-meta");
}

#[test]
fn extension_package_serde_deterministic() {
    let pkg = simple_package("det-ext", "42");
    let json1 = serde_json::to_string(&pkg).unwrap();
    let json2 = serde_json::to_string(&pkg).unwrap();
    assert_eq!(json1, json2);
}

#[test]
fn extension_package_many_capabilities_serde() {
    let caps: Vec<String> = (0..20).map(|i| format!("cap_{i}")).collect();
    let pkg = ExtensionPackage {
        extension_id: "many-cap".to_string(),
        source: "42".to_string(),
        source_file: None,
        capabilities: caps.clone(),
        version: "3.0.0".to_string(),
        metadata: BTreeMap::new(),
    };
    let json = serde_json::to_string(&pkg).unwrap();
    let back: ExtensionPackage = serde_json::from_str(&json).unwrap();
    assert_eq!(back.capabilities.len(), 20);
}

// =========================================================================
// Section 7: Fresh orchestrator state
// =========================================================================

#[test]
fn fresh_orchestrator_execution_count_zero() {
    let orch = default_orch();
    assert_eq!(orch.execution_count(), 0);
}

#[test]
fn fresh_orchestrator_ledger_empty() {
    let orch = default_orch();
    assert_eq!(orch.ledger().len(), 0);
    assert!(orch.ledger().is_empty());
}

#[test]
fn fresh_orchestrator_saga_orchestrator_empty() {
    let orch = default_orch();
    assert_eq!(orch.saga_orchestrator().active_count(), 0);
}

// =========================================================================
// Section 8: Execution counting
// =========================================================================

#[test]
fn execution_count_increments_per_call() {
    let mut orch = default_orch();
    assert_eq!(orch.execution_count(), 0);
    orch.execute(&simple_package("ext-a", "42")).unwrap();
    assert_eq!(orch.execution_count(), 1);
    orch.execute(&simple_package("ext-b", "42")).unwrap();
    assert_eq!(orch.execution_count(), 2);
    orch.execute(&simple_package("ext-c", "42")).unwrap();
    assert_eq!(orch.execution_count(), 3);
}

#[test]
fn execution_count_does_not_increment_on_validation_error() {
    let mut orch = default_orch();
    let _ = orch.execute(&simple_package("", "42"));
    assert_eq!(orch.execution_count(), 0);
}

// =========================================================================
// Section 9: Multiple executions
// =========================================================================

#[test]
fn multiple_executions_accumulate_ledger_entries() {
    let mut orch = default_orch();
    for i in 0..5 {
        let pkg = simple_package(&format!("ext-{i}"), "42");
        orch.execute(&pkg).expect("execute");
    }
    assert_eq!(orch.execution_count(), 5);
    assert!(orch.ledger().len() >= 5);
}

#[test]
fn successive_trace_ids_are_unique() {
    let mut orch = default_orch();
    let r0 = orch.execute(&simple_package("ext-0", "42")).unwrap();
    let r1 = orch.execute(&simple_package("ext-1", "42")).unwrap();
    let r2 = orch.execute(&simple_package("ext-2", "42")).unwrap();
    assert_ne!(r0.trace_id, r1.trace_id);
    assert_ne!(r1.trace_id, r2.trace_id);
    assert_ne!(r0.trace_id, r2.trace_id);
}

#[test]
fn successive_decision_ids_are_unique() {
    let mut orch = default_orch();
    let r0 = orch.execute(&simple_package("ext-0", "42")).unwrap();
    let r1 = orch.execute(&simple_package("ext-1", "42")).unwrap();
    assert_ne!(r0.decision_id, r1.decision_id);
}

// =========================================================================
// Section 10: Trace and decision ID format
// =========================================================================

#[test]
fn trace_id_uses_configured_prefix() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    assert!(result.trace_id.starts_with("orch:"));
}

#[test]
fn decision_id_uses_configured_prefix() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    assert!(result.decision_id.starts_with("orch:decision:"));
}

#[test]
fn custom_trace_prefix_appears_in_ids() {
    let cfg = OrchestratorConfig {
        trace_id_prefix: "myprefix".to_string(),
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(cfg);
    let result = orch.execute(&simple_package("ext-x", "42")).unwrap();
    assert!(result.trace_id.starts_with("myprefix:"));
    assert!(result.decision_id.starts_with("myprefix:decision:"));
}

// =========================================================================
// Section 11: Source label
// =========================================================================

#[test]
fn source_label_contains_extension_id() {
    let mut orch = default_orch();
    let result = orch.execute(&simple_package("my-ext-123", "42")).unwrap();
    assert!(
        result.source_label.contains("my-ext-123"),
        "got: {}",
        result.source_label
    );
}

// =========================================================================
// Section 12: Preset variations
// =========================================================================

#[test]
fn balanced_preset_produces_valid_result() {
    let mut orch = orch_with_preset(LossMatrixPreset::Balanced);
    let result = orch.execute(&simple_package("ext-b", "42")).unwrap();
    assert!(result.posterior.is_valid());
    assert!(!result.evidence_entries.is_empty());
}

#[test]
fn conservative_preset_produces_valid_result() {
    let mut orch = orch_with_preset(LossMatrixPreset::Conservative);
    let result = orch.execute(&simple_package("ext-c", "42")).unwrap();
    assert!(result.posterior.is_valid());
    assert!(!result.evidence_entries.is_empty());
}

#[test]
fn permissive_preset_produces_valid_result() {
    let mut orch = orch_with_preset(LossMatrixPreset::Permissive);
    let result = orch.execute(&simple_package("ext-p", "42")).unwrap();
    assert!(result.posterior.is_valid());
    assert!(!result.evidence_entries.is_empty());
}

#[test]
fn all_presets_produce_valid_posteriors() {
    for preset in [
        LossMatrixPreset::Balanced,
        LossMatrixPreset::Conservative,
        LossMatrixPreset::Permissive,
    ] {
        let mut orch = orch_with_preset(preset);
        let result = orch
            .execute(&simple_package("ext-all", "42"))
            .unwrap_or_else(|e| panic!("{preset:?} failed: {e}"));
        assert!(result.posterior.is_valid(), "{preset:?}: invalid posterior");
    }
}

// =========================================================================
// Section 13: Epoch propagation
// =========================================================================

#[test]
fn custom_epoch_propagates_to_result() {
    let cfg = OrchestratorConfig {
        epoch: SecurityEpoch::from_raw(42),
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(cfg);
    let result = orch.execute(&simple_package("ext-ep", "42")).unwrap();
    assert_eq!(result.epoch, SecurityEpoch::from_raw(42));
}

#[test]
fn high_epoch_propagates() {
    let cfg = OrchestratorConfig {
        epoch: SecurityEpoch::from_raw(999_999),
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(cfg);
    let result = orch.execute(&simple_package("ext-high", "42")).unwrap();
    assert_eq!(result.epoch, SecurityEpoch::from_raw(999_999));
}

// =========================================================================
// Section 14: Evidence entry field validation
// =========================================================================

#[test]
fn evidence_entry_has_trace_id_matching_result() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    for entry in &result.evidence_entries {
        assert_eq!(entry.trace_id, result.trace_id);
    }
}

#[test]
fn evidence_entry_has_decision_id_matching_result() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    for entry in &result.evidence_entries {
        assert_eq!(entry.decision_id, result.decision_id);
    }
}

#[test]
fn evidence_entry_has_populated_fields() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    let entry = &result.evidence_entries[0];
    assert!(!entry.entry_id.is_empty());
    assert!(!entry.evidence_hash.is_empty());
    assert!(!entry.candidates.is_empty());
    assert!(!entry.chosen_action.action_name.is_empty());
    assert!(!entry.witnesses.is_empty());
}

#[test]
fn evidence_entry_metadata_contains_extension_fields() {
    let mut orch = default_orch();
    let result = orch.execute(&simple_package("ext-meta", "42")).unwrap();
    let entry = &result.evidence_entries[0];
    assert!(entry.metadata.contains_key("extension_id"));
    assert!(entry.metadata.contains_key("extension_version"));
    assert!(entry.metadata.contains_key("capabilities_count"));
}

#[test]
fn evidence_entry_metadata_contains_adaptive_router_fields() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    let entry = &result.evidence_entries[0];
    assert!(entry.metadata.contains_key("adaptive_router_regime"));
    assert!(entry.metadata.contains_key("adaptive_router_regret"));
    assert!(entry.metadata.contains_key("adaptive_router_bound"));
    assert!(entry.metadata.contains_key("adaptive_router_exact_regret"));
}

#[test]
fn evidence_entry_metadata_contains_ir3_schedule_cost() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    let entry = &result.evidence_entries[0];
    assert!(entry.metadata.contains_key("ir3_schedule_cost"));
}

#[test]
fn evidence_entry_metadata_contains_optimal_stopping_fields() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    let entry = &result.evidence_entries[0];
    assert!(entry.metadata.contains_key("optimal_stopping_algorithm"));
    assert!(entry.metadata.contains_key("optimal_stopping_observations"));
}

#[test]
fn evidence_entry_metadata_contains_compression_fields() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    let entry = &result.evidence_entries[0];
    assert!(entry.metadata.contains_key("evidence_entropy_millibits"));
    assert!(entry.metadata.contains_key("evidence_shannon_bound_bits"));
    assert!(
        entry
            .metadata
            .contains_key("evidence_overhead_ratio_millionths")
    );
}

// =========================================================================
// Section 15: Capabilities propagation
// =========================================================================

#[test]
fn capabilities_count_recorded_in_evidence_metadata() {
    let pkg = package_with_caps("ext-cap", "42", &["fs_read", "net", "crypto"]);
    let mut orch = default_orch();
    let result = orch.execute(&pkg).unwrap();
    let entry = &result.evidence_entries[0];
    let count = entry.metadata.get("capabilities_count").unwrap();
    assert_eq!(count, "3");
}

#[test]
fn zero_capabilities_recorded_correctly() {
    let pkg = simple_package("ext-no-cap", "42");
    let mut orch = default_orch();
    let result = orch.execute(&pkg).unwrap();
    let entry = &result.evidence_entries[0];
    let count = entry.metadata.get("capabilities_count").unwrap();
    assert_eq!(count, "0");
}

#[test]
fn high_capability_extension_executes_successfully() {
    let caps: Vec<&str> = (0..16).map(|_| "cap").collect();
    let pkg = package_with_caps("high-cap", "42", &caps);
    let mut orch = orch_with_preset(LossMatrixPreset::Conservative);
    let result = orch.execute(&pkg).unwrap();
    assert!(result.posterior.is_valid());
    let entry = &result.evidence_entries[0];
    assert_eq!(entry.metadata.get("capabilities_count").unwrap(), "16");
}

// =========================================================================
// Section 16: Metadata propagation
// =========================================================================

#[test]
fn package_metadata_does_not_break_execution() {
    let pkg = package_with_metadata(
        "ext-with-meta",
        "42",
        &[("author", "tester"), ("env", "ci")],
    );
    let mut orch = default_orch();
    let result = orch.execute(&pkg).unwrap();
    assert_eq!(result.extension_id, "ext-with-meta");
}

// =========================================================================
// Section 17: Risk assessment
// =========================================================================

#[test]
fn simple_source_produces_benign_risk_state() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    // A simple `42` literal should not trigger malicious classification.
    assert!(
        result.risk_state == RiskState::Benign || result.risk_state == RiskState::Unknown,
        "unexpected risk: {:?}",
        result.risk_state
    );
}

#[test]
fn posterior_probabilities_valid_after_execution() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    assert!(result.posterior.is_valid());
    // All probabilities should be non-negative
    assert!(result.posterior.p_benign >= 0);
    assert!(result.posterior.p_anomalous >= 0);
    assert!(result.posterior.p_malicious >= 0);
    assert!(result.posterior.p_unknown >= 0);
}

// =========================================================================
// Section 18: Containment action
// =========================================================================

#[test]
fn simple_source_gets_low_severity_containment() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    // Simple benign code should not trigger harsh containment.
    let severity = result.containment_action.severity();
    assert!(
        severity <= 3,
        "unexpected high severity {severity} for simple source"
    );
}

#[test]
fn containment_action_severity_method_works() {
    assert_eq!(ContainmentAction::Allow.severity(), 0);
    assert_eq!(ContainmentAction::Challenge.severity(), 1);
    assert_eq!(ContainmentAction::Sandbox.severity(), 2);
    assert_eq!(ContainmentAction::Suspend.severity(), 3);
    assert_eq!(ContainmentAction::Terminate.severity(), 4);
    assert_eq!(ContainmentAction::Quarantine.severity(), 5);
}

// =========================================================================
// Section 19: Optimal stopping certificate
// =========================================================================

#[test]
fn optimal_stopping_certificate_has_valid_fields() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    let cert = result.optimal_stopping_certificate.as_ref().unwrap();
    assert!(!cert.schema.is_empty());
    assert!(!cert.algorithm.is_empty());
    assert!(cert.cusum_statistic_millionths.is_some());
    assert!(cert.arl0_lower_bound.is_some());
    assert_eq!(cert.epoch, SecurityEpoch::from_raw(1));
}

// =========================================================================
// Section 20: Compression certificate
// =========================================================================

#[test]
fn compression_certificate_has_valid_fields() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    let cert = result.evidence_compression_certificate.as_ref().unwrap();
    assert!(cert.entropy_millibits_per_symbol >= 0);
    assert!(cert.shannon_lower_bound_bits >= 0);
    assert!(cert.achieved_bits >= 0);
}

// =========================================================================
// Section 21: Adaptive router summary
// =========================================================================

#[test]
fn adaptive_router_summary_has_two_arms() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    let summary = result.adaptive_router_summary.as_ref().unwrap();
    assert_eq!(summary.num_arms, 2);
}

#[test]
fn adaptive_router_summary_one_round_after_first_execution() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    let summary = result.adaptive_router_summary.as_ref().unwrap();
    assert_eq!(summary.rounds, 1);
}

#[test]
fn adaptive_router_summary_accumulates_rounds() {
    let mut orch = default_orch();
    orch.execute(&simple_package("ext-0", "42")).unwrap();
    let result = orch.execute(&simple_package("ext-1", "42")).unwrap();
    let summary = result.adaptive_router_summary.as_ref().unwrap();
    assert_eq!(summary.rounds, 2);
}

// =========================================================================
// Section 22: Lane and lane reason
// =========================================================================

#[test]
fn lane_is_valid_variant() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    // Should be one of the two valid lanes
    assert!(
        result.lane == LaneChoice::QuickJs || result.lane == LaneChoice::V8,
        "unexpected lane: {:?}",
        result.lane
    );
}

// =========================================================================
// Section 23: Force lane
// =========================================================================

#[test]
fn force_lane_quickjs_produces_quickjs() {
    let cfg = OrchestratorConfig {
        force_lane: Some(LaneChoice::QuickJs),
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(cfg);
    let result = orch.execute(&simple_package("ext-qjs", "42")).unwrap();
    assert_eq!(result.lane, LaneChoice::QuickJs);
}

#[test]
fn force_lane_v8_produces_v8() {
    let cfg = OrchestratorConfig {
        force_lane: Some(LaneChoice::V8),
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(cfg);
    let result = orch.execute(&simple_package("ext-v8", "42")).unwrap();
    assert_eq!(result.lane, LaneChoice::V8);
}

// =========================================================================
// Section 24: Containment receipts and sagas
// =========================================================================

#[test]
fn simple_source_receipt_matches_selected_containment_action() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);

    if result.containment_action == ContainmentAction::Allow {
        assert!(result.containment_receipt.is_none());
        assert!(result.saga_id.is_none());
    } else if result.containment_action == ContainmentAction::Challenge
        || result.containment_action == ContainmentAction::Sandbox
    {
        let receipt = result
            .containment_receipt
            .as_ref()
            .expect("challenge/sandbox actions should emit a containment receipt");
        assert_eq!(receipt.action, result.containment_action);
        assert!(result.saga_id.is_none());
    }
}

// =========================================================================
// Section 25: Expected loss
// =========================================================================

#[test]
fn expected_loss_is_non_negative_for_simple_source() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    // Expected loss should be a valid number; it can be zero.
    assert!(
        result.expected_loss_millionths >= 0,
        "negative expected loss: {}",
        result.expected_loss_millionths
    );
}

// =========================================================================
// Section 26: Module parse goal
// =========================================================================

#[test]
fn module_parse_goal_does_not_panic() {
    let cfg = OrchestratorConfig {
        parse_goal: ParseGoal::Module,
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(cfg);
    // May succeed or fail depending on parser strictness, but must not panic.
    let _ = orch.execute(&simple_package("ext-mod", "42"));
}

// =========================================================================
// Section 27: Custom policy_id
// =========================================================================

#[test]
fn custom_policy_id_propagates_to_evidence() {
    let cfg = OrchestratorConfig {
        policy_id: "custom-policy-42".to_string(),
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(cfg);
    let result = orch.execute(&simple_package("ext-pol", "42")).unwrap();
    let entry = &result.evidence_entries[0];
    assert_eq!(entry.policy_id, "custom-policy-42");
}

// =========================================================================
// Section 28: Drain deadline ticks
// =========================================================================

#[test]
fn custom_drain_deadline_does_not_break_execution() {
    let cfg = OrchestratorConfig {
        drain_deadline_ticks: 1,
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(cfg);
    // Even with a very short deadline, execution should complete.
    let result = orch.execute(&simple_package("ext-dd", "42")).unwrap();
    assert!(result.posterior.is_valid());
}

#[test]
fn large_drain_deadline_does_not_break_execution() {
    let cfg = OrchestratorConfig {
        drain_deadline_ticks: 1_000_000,
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(cfg);
    let result = orch.execute(&simple_package("ext-ldd", "42")).unwrap();
    assert!(result.posterior.is_valid());
}

// =========================================================================
// Section 29: Saga orchestrator accessor
// =========================================================================

#[test]
fn saga_orchestrator_accessible_and_initially_empty() {
    let orch = default_orch();
    assert_eq!(orch.saga_orchestrator().active_count(), 0);
    assert_eq!(orch.saga_orchestrator().total_count(), 0);
}

// =========================================================================
// Section 30: Different extension IDs
// =========================================================================

#[test]
fn different_extensions_produce_different_extension_ids_in_result() {
    let mut orch = default_orch();
    let r1 = orch.execute(&simple_package("alpha", "42")).unwrap();
    let r2 = orch.execute(&simple_package("beta", "42")).unwrap();
    assert_eq!(r1.extension_id, "alpha");
    assert_eq!(r2.extension_id, "beta");
}

// =========================================================================
// Section 31: Execution value
// =========================================================================

#[test]
fn execution_value_is_populated() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    // The execution value should be some string representation of the result.
    assert!(!result.execution_value.is_empty());
}

// =========================================================================
// Section 32: Action decision
// =========================================================================

#[test]
fn action_decision_has_valid_action() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    // The action decision should have a valid containment action.
    let _ = result.action_decision.action.severity();
    let _ = result.action_decision.runner_up_action.severity();
}

// =========================================================================
// Section 33: Max concurrent sagas configuration
// =========================================================================

#[test]
fn custom_max_concurrent_sagas_accepted() {
    let cfg = OrchestratorConfig {
        max_concurrent_sagas: 1,
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(cfg);
    let result = orch.execute(&simple_package("ext-saga", "42")).unwrap();
    assert!(result.posterior.is_valid());
}

// =========================================================================
// Section 34: Ledger accessor
// =========================================================================

#[test]
fn ledger_grows_with_executions() {
    let mut orch = default_orch();
    assert_eq!(orch.ledger().len(), 0);
    orch.execute(&simple_package("ext-0", "42")).unwrap();
    assert_eq!(orch.ledger().len(), 1);
    orch.execute(&simple_package("ext-1", "42")).unwrap();
    assert_eq!(orch.ledger().len(), 2);
}

// =========================================================================
// Section 35: Extension version propagation
// =========================================================================

#[test]
fn extension_version_recorded_in_evidence() {
    let pkg = ExtensionPackage {
        extension_id: "ext-ver".to_string(),
        source: "42".to_string(),
        source_file: None,
        capabilities: vec![],
        version: "5.3.1".to_string(),
        metadata: BTreeMap::new(),
    };
    let mut orch = default_orch();
    let result = orch.execute(&pkg).unwrap();
    let entry = &result.evidence_entries[0];
    assert_eq!(entry.metadata.get("extension_version").unwrap(), "5.3.1");
}

// =========================================================================
// Section 36: Stopping policies are per-extension
// =========================================================================

#[test]
fn stopping_policies_isolated_per_extension_across_executions() {
    let mut orch = default_orch();
    orch.execute(&simple_package("ext-a", "42")).unwrap();
    orch.execute(&simple_package("ext-b", "42")).unwrap();
    // Both extensions have their own stopping state - certificates should exist
    let ra = orch.execute(&simple_package("ext-a", "42")).unwrap();
    let rb = orch.execute(&simple_package("ext-b", "42")).unwrap();
    let cert_a = ra.optimal_stopping_certificate.as_ref().unwrap();
    let cert_b = rb.optimal_stopping_certificate.as_ref().unwrap();
    // Both should have 2 observations for their respective extension
    assert_eq!(cert_a.observations_before_stop, 2);
    assert_eq!(cert_b.observations_before_stop, 2);
}
