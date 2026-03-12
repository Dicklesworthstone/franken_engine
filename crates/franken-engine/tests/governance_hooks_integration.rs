//! Integration tests for the governance_hooks module.
//!
//! Validates policy compilation, validation, audit export, compliance evidence
//! bundling, and governance pipeline orchestration from a pure external API
//! perspective.

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

use frankenengine_engine::engine_object_id::{self, ObjectDomain, SchemaId};
use frankenengine_engine::governance_hooks::{
    AuditExportFormat, AuditExportRequest, ComplianceFramework, DiagnosticSeverity, EvidenceEntry,
    GovernanceError, GovernanceHookType, GovernancePipeline, GovernancePipelineConfig,
    PolicyArtifact, PolicyCompilationResult, PolicySource, compile_policy, export_audit_evidence,
    generate_compliance_bundle, run_governance_pipeline, validate_policy,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ts(tick: u64) -> DeterministicTimestamp {
    DeterministicTimestamp(tick)
}

fn toml_bytes() -> &'static [u8] {
    b"[runtime]\nmax_fuel = 1000000\nallow_network = false"
}

fn json_bytes() -> &'static [u8] {
    b"{\"runtime\":{\"max_fuel\":1000000}}"
}

fn compile_toml(name: &str, version: u64) -> PolicyCompilationResult {
    compile_policy(
        PolicySource::InlineToml {
            label: name.to_string(),
        },
        toml_bytes(),
        name,
        version,
        ts(1),
        BTreeSet::new(),
    )
}

fn compile_json(name: &str, version: u64) -> PolicyCompilationResult {
    compile_policy(
        PolicySource::InlineJson {
            label: name.to_string(),
        },
        json_bytes(),
        name,
        version,
        ts(1),
        BTreeSet::new(),
    )
}

fn extract_artifact(result: &PolicyCompilationResult) -> &PolicyArtifact {
    result.artifact().expect("expected success")
}

fn make_evidence_entry(kind: &str, tick: u64) -> EvidenceEntry {
    let summary = format!("{kind} at tick {tick}");
    let evidence_hash = ContentHash::compute(summary.as_bytes());
    let schema = SchemaId::from_definition(b"TestEntry.v1");
    let canonical = format!("{kind}:{tick}");
    let entry_id = engine_object_id::derive_id(
        ObjectDomain::EvidenceRecord,
        "test",
        &schema,
        canonical.as_bytes(),
    )
    .unwrap();
    EvidenceEntry {
        entry_id,
        kind: kind.to_string(),
        timestamp: ts(tick),
        summary,
        attributes: BTreeMap::new(),
        evidence_hash,
    }
}

fn full_evidence_set() -> Vec<EvidenceEntry> {
    vec![
        make_evidence_entry("capability_decision", 10),
        make_evidence_entry("policy_update", 20),
        make_evidence_entry("security_action", 30),
        make_evidence_entry("epoch_transition", 40),
        make_evidence_entry("activation_lifecycle", 50),
        make_evidence_entry("revocation", 60),
    ]
}

// ---------------------------------------------------------------------------
// Policy compilation — TOML
// ---------------------------------------------------------------------------

#[test]
fn compile_toml_policy_succeeds() {
    let result = compile_toml("test_policy_v1", 1);
    assert!(result.is_success());
    let artifact = extract_artifact(&result);
    assert_eq!(artifact.policy_name, "test_policy_v1");
    assert_eq!(artifact.version, 1);
    assert!(!artifact.compiled_bytes.is_empty());
}

#[test]
fn compile_toml_policy_deterministic_id() {
    let r1 = compile_toml("det_policy", 1);
    let r2 = compile_toml("det_policy", 1);
    assert_eq!(
        extract_artifact(&r1).artifact_id,
        extract_artifact(&r2).artifact_id
    );
}

#[test]
fn compile_toml_different_bytes_different_id() {
    let r1 = compile_policy(
        PolicySource::InlineToml {
            label: "a".to_string(),
        },
        b"[section]\nkey = 1",
        "a",
        1,
        ts(1),
        BTreeSet::new(),
    );
    let r2 = compile_policy(
        PolicySource::InlineToml {
            label: "b".to_string(),
        },
        b"[section]\nkey = 2",
        "b",
        1,
        ts(1),
        BTreeSet::new(),
    );
    assert_ne!(
        extract_artifact(&r1).artifact_id,
        extract_artifact(&r2).artifact_id
    );
}

#[test]
fn compile_toml_preserves_tags() {
    let mut tags = BTreeSet::new();
    tags.insert("env:production".to_string());
    tags.insert("team:security".to_string());
    let result = compile_policy(
        PolicySource::InlineToml {
            label: "tagged".to_string(),
        },
        toml_bytes(),
        "tagged",
        1,
        ts(1),
        tags.clone(),
    );
    assert_eq!(extract_artifact(&result).tags, tags);
}

#[test]
fn compile_toml_preserves_source() {
    let source = PolicySource::GitRepo {
        repo_url: "https://example.com/repo.git".to_string(),
        commit_sha: "abcdef0123456789abcdef0123456789abcdef01".to_string(),
        file_path: "policies/runtime.toml".to_string(),
    };
    let result = compile_policy(
        source.clone(),
        toml_bytes(),
        "git_policy",
        1,
        ts(1),
        BTreeSet::new(),
    );
    assert_eq!(extract_artifact(&result).source, source);
}

// ---------------------------------------------------------------------------
// Policy compilation — JSON
// ---------------------------------------------------------------------------

#[test]
fn compile_json_policy_succeeds() {
    let result = compile_json("json_policy", 1);
    assert!(result.is_success());
    assert!(!extract_artifact(&result).compiled_bytes.is_empty());
}

#[test]
fn compile_json_array_succeeds() {
    let result = compile_policy(
        PolicySource::InlineJson {
            label: "arr".to_string(),
        },
        b"[{\"key\":1}]",
        "arr",
        1,
        ts(1),
        BTreeSet::new(),
    );
    assert!(result.is_success());
}

// ---------------------------------------------------------------------------
// Policy compilation — failures
// ---------------------------------------------------------------------------

#[test]
fn compile_empty_definition_fails() {
    let result = compile_policy(
        PolicySource::InlineToml {
            label: "empty".to_string(),
        },
        b"",
        "empty",
        1,
        ts(1),
        BTreeSet::new(),
    );
    assert!(!result.is_success());
    assert!(!result.diagnostics().is_empty());
    assert_eq!(result.diagnostics()[0].severity, DiagnosticSeverity::Error);
}

#[test]
fn compile_invalid_toml_no_equals_fails() {
    let result = compile_policy(
        PolicySource::InlineToml {
            label: "bad".to_string(),
        },
        b"this is just plain text without any key value pairs",
        "bad",
        1,
        ts(1),
        BTreeSet::new(),
    );
    assert!(!result.is_success());
}

#[test]
fn compile_invalid_json_no_brace_fails() {
    let result = compile_policy(
        PolicySource::InlineJson {
            label: "bad".to_string(),
        },
        b"not json at all",
        "bad",
        1,
        ts(1),
        BTreeSet::new(),
    );
    assert!(!result.is_success());
}

#[test]
fn compile_failure_has_error_summary() {
    let result = compile_policy(
        PolicySource::InlineToml {
            label: "empty".to_string(),
        },
        b"",
        "empty",
        1,
        ts(1),
        BTreeSet::new(),
    );
    if let PolicyCompilationResult::Failure { error_summary, .. } = &result {
        assert!(!error_summary.is_empty());
    } else {
        panic!("expected failure");
    }
}

// ---------------------------------------------------------------------------
// Policy compilation — diagnostics
// ---------------------------------------------------------------------------

#[test]
fn compile_success_diagnostics_empty_or_info() {
    let result = compile_toml("clean", 1);
    // Successful compilations should have no error-level diagnostics.
    assert_eq!(result.count_at_severity(DiagnosticSeverity::Error), 0);
}

#[test]
fn compile_failure_count_at_severity() {
    let result = compile_policy(
        PolicySource::InlineToml {
            label: "empty".to_string(),
        },
        b"",
        "empty",
        1,
        ts(1),
        BTreeSet::new(),
    );
    assert!(result.count_at_severity(DiagnosticSeverity::Error) > 0);
}

// ---------------------------------------------------------------------------
// validate_policy
// ---------------------------------------------------------------------------

#[test]
fn validate_valid_artifact_passes() {
    let result = compile_toml("valid", 1);
    let artifact = extract_artifact(&result);
    assert!(validate_policy(artifact, None).is_ok());
}

#[test]
fn validate_version_zero_fails() {
    let result = compile_toml("zero_v", 0);
    // Version 0 should fail validation (if compilation succeeded).
    if result.is_success() {
        let artifact = extract_artifact(&result);
        let err = validate_policy(artifact, None);
        assert!(matches!(
            err,
            Err(GovernanceError::PolicySchemaViolation { .. })
        ));
    }
}

#[test]
fn validate_version_below_minimum_fails() {
    let result = compile_toml("low_v", 3);
    let artifact = extract_artifact(&result);
    let err = validate_policy(artifact, Some(5));
    assert!(matches!(
        err,
        Err(GovernanceError::PolicySchemaViolation { .. })
    ));
}

#[test]
fn validate_version_at_minimum_passes() {
    let result = compile_toml("exact_v", 5);
    let artifact = extract_artifact(&result);
    assert!(validate_policy(artifact, Some(5)).is_ok());
}

#[test]
fn validate_tampered_hash_fails() {
    let result = compile_toml("tampered", 1);
    let mut artifact = extract_artifact(&result).clone();
    // Tamper with compiled bytes.
    artifact.compiled_bytes.push(0xFF);
    let err = validate_policy(&artifact, None);
    assert!(matches!(
        err,
        Err(GovernanceError::PolicySchemaViolation { .. })
    ));
}

#[test]
fn validate_empty_compiled_bytes_fails() {
    let result = compile_toml("empty_bytes", 1);
    let mut artifact = extract_artifact(&result).clone();
    artifact.compiled_bytes.clear();
    let err = validate_policy(&artifact, None);
    assert!(matches!(
        err,
        Err(GovernanceError::PolicySchemaViolation { .. })
    ));
}

#[test]
fn validate_empty_policy_name_fails() {
    let result = compile_toml("temp", 1);
    let mut artifact = extract_artifact(&result).clone();
    artifact.policy_name = "   ".to_string();
    let err = validate_policy(&artifact, None);
    assert!(matches!(
        err,
        Err(GovernanceError::PolicySchemaViolation { .. })
    ));
}

// ---------------------------------------------------------------------------
// export_audit_evidence
// ---------------------------------------------------------------------------

#[test]
fn export_jsonlines_basic() {
    let entries = full_evidence_set();
    let request = AuditExportRequest {
        format: AuditExportFormat::JsonLines,
        start_tick: ts(0),
        end_tick: ts(100),
        evidence_kinds: None,
        max_entries: None,
        requester: "test_user".to_string(),
        correlation_id: None,
    };
    let result = export_audit_evidence(request, entries, ts(200)).unwrap();
    assert_eq!(result.entry_count, 6);
    assert_eq!(result.format, AuditExportFormat::JsonLines);
    assert!(!result.payload_bytes.is_empty());
}

#[test]
fn export_csv_basic() {
    let entries = full_evidence_set();
    let request = AuditExportRequest {
        format: AuditExportFormat::Csv,
        start_tick: ts(0),
        end_tick: ts(100),
        evidence_kinds: None,
        max_entries: None,
        requester: "test_user".to_string(),
        correlation_id: None,
    };
    let result = export_audit_evidence(request, entries, ts(200)).unwrap();
    assert_eq!(result.entry_count, 6);
    // CSV should have a header line.
    let payload = String::from_utf8_lossy(&result.payload_bytes);
    assert!(payload.starts_with("entry_id,kind,timestamp,summary,evidence_hash\n"));
}

#[test]
fn export_parquet_basic() {
    let entries = full_evidence_set();
    let request = AuditExportRequest {
        format: AuditExportFormat::Parquet,
        start_tick: ts(0),
        end_tick: ts(100),
        evidence_kinds: None,
        max_entries: None,
        requester: "test_user".to_string(),
        correlation_id: None,
    };
    let result = export_audit_evidence(request, entries, ts(200)).unwrap();
    let payload = String::from_utf8_lossy(&result.payload_bytes);
    assert!(payload.starts_with("FRANKEN_PARQUET_V1\n"));
}

#[test]
fn export_compliance_pdf_basic() {
    let entries = full_evidence_set();
    let request = AuditExportRequest {
        format: AuditExportFormat::CompliancePdf,
        start_tick: ts(0),
        end_tick: ts(100),
        evidence_kinds: None,
        max_entries: None,
        requester: "test_user".to_string(),
        correlation_id: None,
    };
    let result = export_audit_evidence(request, entries, ts(200)).unwrap();
    let payload = String::from_utf8_lossy(&result.payload_bytes);
    assert!(payload.starts_with("FRANKEN_COMPLIANCE_REPORT_V1\n"));
}

#[test]
fn export_filters_by_time_range() {
    let entries = full_evidence_set(); // ticks 10..60
    let request = AuditExportRequest {
        format: AuditExportFormat::JsonLines,
        start_tick: ts(20),
        end_tick: ts(40),
        evidence_kinds: None,
        max_entries: None,
        requester: "test_user".to_string(),
        correlation_id: None,
    };
    let result = export_audit_evidence(request, entries, ts(200)).unwrap();
    assert_eq!(result.entry_count, 3); // ticks 20, 30, 40
}

#[test]
fn export_filters_by_evidence_kind() {
    let entries = full_evidence_set();
    let mut kinds = BTreeSet::new();
    kinds.insert("policy_update".to_string());
    kinds.insert("revocation".to_string());
    let request = AuditExportRequest {
        format: AuditExportFormat::JsonLines,
        start_tick: ts(0),
        end_tick: ts(100),
        evidence_kinds: Some(kinds),
        max_entries: None,
        requester: "test_user".to_string(),
        correlation_id: None,
    };
    let result = export_audit_evidence(request, entries, ts(200)).unwrap();
    assert_eq!(result.entry_count, 2);
}

#[test]
fn export_respects_max_entries() {
    let entries = full_evidence_set();
    let request = AuditExportRequest {
        format: AuditExportFormat::JsonLines,
        start_tick: ts(0),
        end_tick: ts(100),
        evidence_kinds: None,
        max_entries: Some(2),
        requester: "test_user".to_string(),
        correlation_id: None,
    };
    let result = export_audit_evidence(request, entries, ts(200)).unwrap();
    assert_eq!(result.entry_count, 2);
}

#[test]
fn export_invalid_time_range_fails() {
    let request = AuditExportRequest {
        format: AuditExportFormat::JsonLines,
        start_tick: ts(100),
        end_tick: ts(10), // start > end
        evidence_kinds: None,
        max_entries: None,
        requester: "test_user".to_string(),
        correlation_id: None,
    };
    let err = export_audit_evidence(request, vec![], ts(200));
    assert!(matches!(err, Err(GovernanceError::InvalidTimeRange { .. })));
}

#[test]
fn export_empty_entries_succeeds() {
    let request = AuditExportRequest {
        format: AuditExportFormat::JsonLines,
        start_tick: ts(0),
        end_tick: ts(100),
        evidence_kinds: None,
        max_entries: None,
        requester: "test_user".to_string(),
        correlation_id: None,
    };
    let result = export_audit_evidence(request, vec![], ts(200)).unwrap();
    assert_eq!(result.entry_count, 0);
}

#[test]
fn export_id_deterministic() {
    let entries = full_evidence_set();
    let make_req = || AuditExportRequest {
        format: AuditExportFormat::JsonLines,
        start_tick: ts(0),
        end_tick: ts(100),
        evidence_kinds: None,
        max_entries: None,
        requester: "test_user".to_string(),
        correlation_id: None,
    };
    let r1 = export_audit_evidence(make_req(), entries.clone(), ts(200)).unwrap();
    let r2 = export_audit_evidence(make_req(), entries, ts(200)).unwrap();
    assert_eq!(r1.export_id, r2.export_id);
    assert_eq!(r1.payload_hash, r2.payload_hash);
}

// ---------------------------------------------------------------------------
// generate_compliance_bundle
// ---------------------------------------------------------------------------

#[test]
fn compliance_bundle_soc2_full_evidence() {
    let entries = full_evidence_set();
    let (bundle, contract) =
        generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), entries, ts(200))
            .unwrap();
    assert_eq!(bundle.framework, ComplianceFramework::Soc2);
    assert_eq!(bundle.entries.len(), 6);
    // SOC 2 has 4 controls; all should be satisfied with full evidence.
    assert_eq!(contract.controls.len(), 4);
    assert_eq!(contract.unsatisfied_count(), 0);
    assert_eq!(contract.satisfaction_rate_millionths, 1_000_000);
}

#[test]
fn compliance_bundle_iso27001() {
    let entries = full_evidence_set();
    let (_, contract) = generate_compliance_bundle(
        ComplianceFramework::Iso27001,
        ts(0),
        ts(100),
        entries,
        ts(200),
    )
    .unwrap();
    assert_eq!(contract.controls.len(), 3);
    assert_eq!(contract.framework, ComplianceFramework::Iso27001);
}

#[test]
fn compliance_bundle_hipaa() {
    let entries = full_evidence_set();
    let (_, contract) =
        generate_compliance_bundle(ComplianceFramework::Hipaa, ts(0), ts(100), entries, ts(200))
            .unwrap();
    assert_eq!(contract.controls.len(), 3);
}

#[test]
fn compliance_bundle_pci_dss() {
    let entries = full_evidence_set();
    let (_, contract) = generate_compliance_bundle(
        ComplianceFramework::PciDss,
        ts(0),
        ts(100),
        entries,
        ts(200),
    )
    .unwrap();
    assert_eq!(contract.controls.len(), 4);
}

#[test]
fn compliance_bundle_gdpr() {
    let entries = full_evidence_set();
    let (_, contract) =
        generate_compliance_bundle(ComplianceFramework::Gdpr, ts(0), ts(100), entries, ts(200))
            .unwrap();
    assert_eq!(contract.controls.len(), 3);
}

#[test]
fn compliance_bundle_custom_framework() {
    let entries = full_evidence_set();
    let (_, contract) = generate_compliance_bundle(
        ComplianceFramework::Custom("INTERNAL-SEC".to_string()),
        ts(0),
        ts(100),
        entries,
        ts(200),
    )
    .unwrap();
    assert_eq!(contract.controls.len(), 2);
}

#[test]
fn compliance_bundle_partial_evidence_has_gaps() {
    // Only provide "capability_decision" — SOC 2 CC6.2 requires "activation_lifecycle".
    let entries = vec![make_evidence_entry("capability_decision", 10)];
    let (_, contract) =
        generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), entries, ts(200))
            .unwrap();
    assert!(contract.unsatisfied_count() > 0);
    let gaps = contract.all_gaps();
    assert!(!gaps.is_empty());
}

#[test]
fn compliance_bundle_no_evidence_all_gaps() {
    let entries = vec![];
    let (_, contract) =
        generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), entries, ts(200))
            .unwrap();
    // All controls unsatisfied.
    assert_eq!(contract.unsatisfied_count(), contract.controls.len());
    assert_eq!(contract.satisfaction_rate_millionths, 0);
}

#[test]
fn compliance_bundle_find_control() {
    let entries = full_evidence_set();
    let (_, contract) =
        generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), entries, ts(200))
            .unwrap();
    assert!(contract.find_control("CC6.1").is_some());
    assert!(contract.find_control("NONEXISTENT").is_none());
}

#[test]
fn compliance_bundle_invalid_time_range() {
    let err =
        generate_compliance_bundle(ComplianceFramework::Soc2, ts(100), ts(10), vec![], ts(200));
    assert!(matches!(err, Err(GovernanceError::InvalidTimeRange { .. })));
}

#[test]
fn compliance_bundle_deterministic_ids() {
    let entries = full_evidence_set();
    let (b1, c1) = generate_compliance_bundle(
        ComplianceFramework::Soc2,
        ts(0),
        ts(100),
        entries.clone(),
        ts(200),
    )
    .unwrap();
    let (b2, c2) =
        generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), entries, ts(200))
            .unwrap();
    assert_eq!(b1.bundle_id, b2.bundle_id);
    assert_eq!(c1.contract_id, c2.contract_id);
}

#[test]
fn compliance_bundle_hash_chain() {
    let entries = full_evidence_set();
    let (bundle, _) =
        generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), entries, ts(200))
            .unwrap();
    // Bundle hash should be non-empty.
    assert!(!bundle.bundle_hash.as_bytes().is_empty());
}

// ---------------------------------------------------------------------------
// run_governance_pipeline
// ---------------------------------------------------------------------------

#[test]
fn pipeline_all_hooks_pass_with_full_evidence() {
    let artifact = extract_artifact(&compile_toml("pipe_policy", 1)).clone();
    let entries = full_evidence_set();
    let config = GovernancePipelineConfig::default();
    let mut pipeline = GovernancePipeline::new(config);

    let results = run_governance_pipeline(&mut pipeline, &[artifact], entries, ts(200)).unwrap();
    // All 5 default hooks should fire.
    assert_eq!(results.len(), 5);
    for r in &results {
        assert!(r.passed, "hook {} should pass", r.hook_type);
    }
    assert_eq!(pipeline.events().len(), 5);
}

#[test]
fn pipeline_halts_on_failure_when_configured() {
    // Use an artifact with version 0 (invalid) — PreDeploy will fail.
    let mut artifact = extract_artifact(&compile_toml("bad", 1)).clone();
    artifact.version = 0;
    let entries = full_evidence_set();
    let config = GovernancePipelineConfig {
        halt_on_failure: true,
        ..Default::default()
    };
    let mut pipeline = GovernancePipeline::new(config);

    let err = run_governance_pipeline(&mut pipeline, &[artifact], entries, ts(200));
    assert!(matches!(err, Err(GovernanceError::HookFailed { .. })));
    // Only one event should have been recorded (PreDeploy failed immediately).
    assert_eq!(pipeline.events().len(), 1);
}

#[test]
fn pipeline_continues_on_failure_when_not_halting() {
    let mut artifact = extract_artifact(&compile_toml("bad", 1)).clone();
    artifact.version = 0;
    let entries = full_evidence_set();
    let config = GovernancePipelineConfig {
        halt_on_failure: false,
        ..Default::default()
    };
    let mut pipeline = GovernancePipeline::new(config);

    let results = run_governance_pipeline(&mut pipeline, &[artifact], entries, ts(200)).unwrap();
    // All 5 hooks should have fired.
    assert_eq!(results.len(), 5);
    // PreDeploy should have failed.
    assert!(!results[0].passed);
}

#[test]
fn pipeline_custom_hook_order() {
    let artifact = extract_artifact(&compile_toml("ordered", 1)).clone();
    let entries = full_evidence_set();
    let config = GovernancePipelineConfig {
        hooks: vec![
            GovernanceHookType::AuditExport,
            GovernanceHookType::PostDeploy,
        ],
        halt_on_failure: true,
        max_export_entries: 100,
        frameworks: vec![],
    };
    let mut pipeline = GovernancePipeline::new(config);

    let results = run_governance_pipeline(&mut pipeline, &[artifact], entries, ts(200)).unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].hook_type, GovernanceHookType::AuditExport);
    assert_eq!(results[1].hook_type, GovernanceHookType::PostDeploy);
}

#[test]
fn pipeline_empty_artifacts_still_runs() {
    let entries = full_evidence_set();
    let config = GovernancePipelineConfig {
        hooks: vec![GovernanceHookType::AuditExport],
        halt_on_failure: true,
        max_export_entries: 100,
        frameworks: vec![],
    };
    let mut pipeline = GovernancePipeline::new(config);

    let results = run_governance_pipeline(&mut pipeline, &[], entries, ts(200)).unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].passed);
}

#[test]
fn pipeline_policy_change_detects_duplicate_hash() {
    let artifact = extract_artifact(&compile_toml("dup", 1)).clone();
    let entries = full_evidence_set();
    let config = GovernancePipelineConfig {
        hooks: vec![GovernanceHookType::PolicyChange],
        halt_on_failure: true,
        max_export_entries: 100,
        frameworks: vec![],
    };
    let mut pipeline = GovernancePipeline::new(config);

    // Two identical artifacts should trigger duplicate detection.
    let err = run_governance_pipeline(
        &mut pipeline,
        &[artifact.clone(), artifact],
        entries,
        ts(200),
    );
    assert!(matches!(err, Err(GovernanceError::HookFailed { .. })));
}

#[test]
fn pipeline_events_have_deterministic_ids() {
    let artifact = extract_artifact(&compile_toml("det_ev", 1)).clone();
    let entries = full_evidence_set();
    let config = GovernancePipelineConfig {
        hooks: vec![GovernanceHookType::PreDeploy],
        halt_on_failure: true,
        max_export_entries: 100,
        frameworks: vec![],
    };
    let mut p1 = GovernancePipeline::new(config.clone());
    let mut p2 = GovernancePipeline::new(config);

    run_governance_pipeline(
        &mut p1,
        std::slice::from_ref(&artifact),
        entries.clone(),
        ts(200),
    )
    .unwrap();
    run_governance_pipeline(&mut p2, std::slice::from_ref(&artifact), entries, ts(200)).unwrap();

    assert_eq!(p1.events()[0].event_id, p2.events()[0].event_id);
}

// ---------------------------------------------------------------------------
// PolicySource
// ---------------------------------------------------------------------------

#[test]
fn policy_source_all_tags() {
    let tags = PolicySource::all_tags();
    assert_eq!(tags.len(), 4);
    assert!(tags.contains(&"git_repo"));
    assert!(tags.contains(&"filesystem"));
    assert!(tags.contains(&"inline_toml"));
    assert!(tags.contains(&"inline_json"));
}

#[test]
fn policy_source_display() {
    let src = PolicySource::GitRepo {
        repo_url: "https://example.com/repo.git".to_string(),
        commit_sha: "abcdef0123456789abcdef0123456789abcdef01".to_string(),
        file_path: "policy.toml".to_string(),
    };
    let display = format!("{src}");
    assert!(display.contains("git_repo:"));
    assert!(display.contains("abcdef01")); // first 8 chars of sha

    let fs = PolicySource::FileSystem {
        absolute_path: "/etc/policy.toml".to_string(),
    };
    assert!(format!("{fs}").contains("filesystem:"));
}

// ---------------------------------------------------------------------------
// ComplianceFramework
// ---------------------------------------------------------------------------

#[test]
fn compliance_framework_all_builtin() {
    let all = ComplianceFramework::all_builtin();
    assert_eq!(all.len(), 5);
}

#[test]
fn compliance_framework_display() {
    assert_eq!(format!("{}", ComplianceFramework::Soc2), "soc2");
    assert_eq!(format!("{}", ComplianceFramework::Iso27001), "iso27001");
    assert_eq!(format!("{}", ComplianceFramework::Hipaa), "hipaa");
    assert_eq!(format!("{}", ComplianceFramework::PciDss), "pci_dss");
    assert_eq!(format!("{}", ComplianceFramework::Gdpr), "gdpr");
    assert_eq!(
        format!("{}", ComplianceFramework::Custom("MY_FW".to_string())),
        "MY_FW"
    );
}

// ---------------------------------------------------------------------------
// AuditExportFormat
// ---------------------------------------------------------------------------

#[test]
fn audit_export_format_all() {
    assert_eq!(AuditExportFormat::all().len(), 4);
}

#[test]
fn audit_export_format_file_extensions() {
    assert_eq!(AuditExportFormat::JsonLines.file_extension(), "jsonl");
    assert_eq!(AuditExportFormat::Csv.file_extension(), "csv");
    assert_eq!(AuditExportFormat::Parquet.file_extension(), "parquet");
    assert_eq!(AuditExportFormat::CompliancePdf.file_extension(), "pdf");
}

#[test]
fn audit_export_format_display() {
    for fmt in AuditExportFormat::all() {
        let display = format!("{fmt}");
        assert!(!display.is_empty());
    }
}

// ---------------------------------------------------------------------------
// GovernanceHookType
// ---------------------------------------------------------------------------

#[test]
fn governance_hook_type_all() {
    assert_eq!(GovernanceHookType::all().len(), 5);
}

#[test]
fn governance_hook_type_display() {
    for ht in GovernanceHookType::all() {
        let display = format!("{ht}");
        assert!(!display.is_empty());
        assert_eq!(display, ht.as_str());
    }
}

// ---------------------------------------------------------------------------
// DiagnosticSeverity
// ---------------------------------------------------------------------------

#[test]
fn diagnostic_severity_all() {
    assert_eq!(DiagnosticSeverity::all().len(), 3);
}

#[test]
fn diagnostic_severity_ordering() {
    assert!(DiagnosticSeverity::Info < DiagnosticSeverity::Warning);
    assert!(DiagnosticSeverity::Warning < DiagnosticSeverity::Error);
}

#[test]
fn diagnostic_severity_display() {
    assert_eq!(format!("{}", DiagnosticSeverity::Info), "info");
    assert_eq!(format!("{}", DiagnosticSeverity::Warning), "warning");
    assert_eq!(format!("{}", DiagnosticSeverity::Error), "error");
}

// ---------------------------------------------------------------------------
// GovernanceError
// ---------------------------------------------------------------------------

#[test]
fn governance_error_display_all_variants() {
    let errors: Vec<GovernanceError> = vec![
        GovernanceError::EmptyPolicyDefinition,
        GovernanceError::InvalidPolicySyntax {
            expected_format: "toml".to_string(),
            reason: "bad".to_string(),
        },
        GovernanceError::PolicySchemaViolation {
            constraint: "test".to_string(),
        },
        GovernanceError::IdDerivationFailed {
            detail: "fail".to_string(),
        },
        GovernanceError::InvalidTimeRange {
            start: ts(10),
            end: ts(5),
        },
        GovernanceError::NoEvidenceInRange {
            start: ts(0),
            end: ts(100),
        },
        GovernanceError::UnknownFramework {
            framework: "alien".to_string(),
        },
        GovernanceError::MissingControl {
            control_id: "CC1.1".to_string(),
        },
        GovernanceError::HookFailed {
            hook_type: GovernanceHookType::PreDeploy,
            reason: "invalid".to_string(),
        },
        GovernanceError::SerialisationFailed {
            reason: "oops".to_string(),
        },
    ];
    for e in &errors {
        let display = format!("{e}");
        assert!(!display.is_empty(), "display should be non-empty for {e:?}");
    }
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn serde_policy_artifact_roundtrip() {
    let result = compile_toml("serde_test", 1);
    let artifact = extract_artifact(&result);
    let json = serde_json::to_string(artifact).unwrap();
    let back: PolicyArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, &back);
}

#[test]
fn serde_policy_compilation_result_roundtrip() {
    let result = compile_toml("serde_result", 1);
    let json = serde_json::to_string(&result).unwrap();
    let back: PolicyCompilationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn serde_compliance_contract_roundtrip() {
    let entries = full_evidence_set();
    let (_, contract) =
        generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), entries, ts(200))
            .unwrap();
    let json = serde_json::to_string(&contract).unwrap();
    let back: frankenengine_engine::governance_hooks::ComplianceEvidenceContract =
        serde_json::from_str(&json).unwrap();
    assert_eq!(contract, back);
}

#[test]
fn serde_governance_error_roundtrip() {
    let err = GovernanceError::HookFailed {
        hook_type: GovernanceHookType::PreDeploy,
        reason: "test".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: GovernanceError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

// ---------------------------------------------------------------------------
// Enrichment: PearlTower 2026-03-12 — 65 new tests
// ---------------------------------------------------------------------------

// --- PolicySource serde roundtrips (all 4 variants) ---

#[test]
fn serde_policy_source_git_repo_roundtrip() {
    let src = PolicySource::GitRepo {
        repo_url: "https://example.com/repo.git".to_string(),
        commit_sha: "a]".repeat(20),
        file_path: "policies/runtime.toml".to_string(),
    };
    let json = serde_json::to_string(&src).unwrap();
    let back: PolicySource = serde_json::from_str(&json).unwrap();
    assert_eq!(src, back);
}

#[test]
fn serde_policy_source_filesystem_roundtrip() {
    let src = PolicySource::FileSystem {
        absolute_path: "/etc/franken/policy.toml".to_string(),
    };
    let json = serde_json::to_string(&src).unwrap();
    let back: PolicySource = serde_json::from_str(&json).unwrap();
    assert_eq!(src, back);
}

#[test]
fn serde_policy_source_inline_toml_roundtrip() {
    let src = PolicySource::InlineToml {
        label: "admin_ctx".to_string(),
    };
    let json = serde_json::to_string(&src).unwrap();
    let back: PolicySource = serde_json::from_str(&json).unwrap();
    assert_eq!(src, back);
}

#[test]
fn serde_policy_source_inline_json_roundtrip() {
    let src = PolicySource::InlineJson {
        label: "api_ctx".to_string(),
    };
    let json = serde_json::to_string(&src).unwrap();
    let back: PolicySource = serde_json::from_str(&json).unwrap();
    assert_eq!(src, back);
}

// --- PolicySource as_str for all variants ---

#[test]
fn policy_source_as_str_all_variants() {
    let git = PolicySource::GitRepo {
        repo_url: "u".to_string(),
        commit_sha: "c".repeat(40),
        file_path: "f".to_string(),
    };
    assert_eq!(git.as_str(), "git_repo");

    let fs = PolicySource::FileSystem {
        absolute_path: "/p".to_string(),
    };
    assert_eq!(fs.as_str(), "filesystem");

    let toml = PolicySource::InlineToml {
        label: "t".to_string(),
    };
    assert_eq!(toml.as_str(), "inline_toml");

    let json = PolicySource::InlineJson {
        label: "j".to_string(),
    };
    assert_eq!(json.as_str(), "inline_json");
}

// --- PolicySource Display for filesystem and inline variants ---

#[test]
fn policy_source_display_filesystem() {
    let src = PolicySource::FileSystem {
        absolute_path: "/etc/policy.toml".to_string(),
    };
    assert_eq!(format!("{src}"), "filesystem:/etc/policy.toml");
}

#[test]
fn policy_source_display_inline_toml() {
    let src = PolicySource::InlineToml {
        label: "my_context".to_string(),
    };
    assert_eq!(format!("{src}"), "inline_toml:my_context");
}

#[test]
fn policy_source_display_inline_json() {
    let src = PolicySource::InlineJson {
        label: "api_context".to_string(),
    };
    assert_eq!(format!("{src}"), "inline_json:api_context");
}

// --- PolicySource Ord ordering ---

#[test]
fn policy_source_ord_ordering() {
    let git = PolicySource::GitRepo {
        repo_url: "u".to_string(),
        commit_sha: "a".repeat(40),
        file_path: "f".to_string(),
    };
    let fs = PolicySource::FileSystem {
        absolute_path: "/p".to_string(),
    };
    let toml = PolicySource::InlineToml {
        label: "t".to_string(),
    };
    let json = PolicySource::InlineJson {
        label: "j".to_string(),
    };
    assert!(git < fs, "GitRepo should sort before FileSystem");
    assert!(fs < toml, "FileSystem should sort before InlineToml");
    assert!(toml < json, "InlineToml should sort before InlineJson");
}

// --- DiagnosticSeverity serde all 3 variants ---

#[test]
fn serde_diagnostic_severity_all_variants() {
    for sev in DiagnosticSeverity::all() {
        let json = serde_json::to_string(sev).unwrap();
        let back: DiagnosticSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*sev, back);
    }
}

// --- DiagnosticSeverity as_str ---

#[test]
fn diagnostic_severity_as_str_all() {
    assert_eq!(DiagnosticSeverity::Info.as_str(), "info");
    assert_eq!(DiagnosticSeverity::Warning.as_str(), "warning");
    assert_eq!(DiagnosticSeverity::Error.as_str(), "error");
}

// --- AuditExportFormat as_str ---

#[test]
fn audit_export_format_as_str_all() {
    assert_eq!(AuditExportFormat::JsonLines.as_str(), "jsonlines");
    assert_eq!(AuditExportFormat::Csv.as_str(), "csv");
    assert_eq!(AuditExportFormat::Parquet.as_str(), "parquet");
    assert_eq!(AuditExportFormat::CompliancePdf.as_str(), "compliance_pdf");
}

// --- AuditExportFormat serde all 4 variants ---

#[test]
fn serde_audit_export_format_all_variants() {
    for fmt in AuditExportFormat::all() {
        let json = serde_json::to_string(fmt).unwrap();
        let back: AuditExportFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(*fmt, back);
    }
}

// --- AuditExportFormat Ord ordering ---

#[test]
fn audit_export_format_ord_ordering() {
    assert!(AuditExportFormat::JsonLines < AuditExportFormat::Csv);
    assert!(AuditExportFormat::Csv < AuditExportFormat::Parquet);
    assert!(AuditExportFormat::Parquet < AuditExportFormat::CompliancePdf);
}

// --- GovernanceHookType as_str all variants ---

#[test]
fn governance_hook_type_as_str_all() {
    assert_eq!(GovernanceHookType::PreDeploy.as_str(), "pre_deploy");
    assert_eq!(GovernanceHookType::PostDeploy.as_str(), "post_deploy");
    assert_eq!(GovernanceHookType::PolicyChange.as_str(), "policy_change");
    assert_eq!(GovernanceHookType::AuditExport.as_str(), "audit_export");
    assert_eq!(
        GovernanceHookType::ComplianceCheck.as_str(),
        "compliance_check"
    );
}

// --- GovernanceHookType serde all variants ---

#[test]
fn serde_governance_hook_type_all_variants() {
    for ht in GovernanceHookType::all() {
        let json = serde_json::to_string(ht).unwrap();
        let back: GovernanceHookType = serde_json::from_str(&json).unwrap();
        assert_eq!(*ht, back);
    }
}

// --- GovernanceHookType Ord ordering ---

#[test]
fn governance_hook_type_ord_ordering() {
    assert!(GovernanceHookType::PreDeploy < GovernanceHookType::PostDeploy);
    assert!(GovernanceHookType::PostDeploy < GovernanceHookType::PolicyChange);
    assert!(GovernanceHookType::PolicyChange < GovernanceHookType::AuditExport);
    assert!(GovernanceHookType::AuditExport < GovernanceHookType::ComplianceCheck);
}

// --- ComplianceFramework as_str all variants ---

#[test]
fn compliance_framework_as_str_all() {
    assert_eq!(ComplianceFramework::Soc2.as_str(), "soc2");
    assert_eq!(ComplianceFramework::Iso27001.as_str(), "iso27001");
    assert_eq!(ComplianceFramework::Hipaa.as_str(), "hipaa");
    assert_eq!(ComplianceFramework::PciDss.as_str(), "pci_dss");
    assert_eq!(ComplianceFramework::Gdpr.as_str(), "gdpr");
    assert_eq!(
        ComplianceFramework::Custom("MY_FW".to_string()).as_str(),
        "MY_FW"
    );
}

// --- ComplianceFramework Ord ordering ---

#[test]
fn compliance_framework_ord_ordering() {
    assert!(ComplianceFramework::Soc2 < ComplianceFramework::Iso27001);
    assert!(ComplianceFramework::Iso27001 < ComplianceFramework::Hipaa);
    assert!(ComplianceFramework::Hipaa < ComplianceFramework::PciDss);
    assert!(ComplianceFramework::PciDss < ComplianceFramework::Gdpr);
    assert!(ComplianceFramework::Gdpr < ComplianceFramework::Custom("z".to_string()));
}

// --- ComplianceFramework serde all 6 variants ---

#[test]
fn serde_compliance_framework_all_6_variants() {
    let variants = vec![
        ComplianceFramework::Soc2,
        ComplianceFramework::Iso27001,
        ComplianceFramework::Hipaa,
        ComplianceFramework::PciDss,
        ComplianceFramework::Gdpr,
        ComplianceFramework::Custom("INTERNAL".to_string()),
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: ComplianceFramework = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// --- GovernanceError serde all 10 variants ---

#[test]
fn serde_governance_error_all_10_variants() {
    let errors: Vec<GovernanceError> = vec![
        GovernanceError::EmptyPolicyDefinition,
        GovernanceError::InvalidPolicySyntax {
            expected_format: "toml".to_string(),
            reason: "parse error".to_string(),
        },
        GovernanceError::PolicySchemaViolation {
            constraint: "version".to_string(),
        },
        GovernanceError::IdDerivationFailed {
            detail: "bad bytes".to_string(),
        },
        GovernanceError::InvalidTimeRange {
            start: ts(100),
            end: ts(50),
        },
        GovernanceError::NoEvidenceInRange {
            start: ts(0),
            end: ts(100),
        },
        GovernanceError::UnknownFramework {
            framework: "mystery".to_string(),
        },
        GovernanceError::MissingControl {
            control_id: "CC6.1".to_string(),
        },
        GovernanceError::HookFailed {
            hook_type: GovernanceHookType::PostDeploy,
            reason: "hash mismatch".to_string(),
        },
        GovernanceError::SerialisationFailed {
            reason: "IO".to_string(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: GovernanceError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
    assert_eq!(errors.len(), 10);
}

// --- GovernanceError std::error::Error impl ---

#[test]
fn governance_error_implements_std_error() {
    let variants: Vec<Box<dyn std::error::Error>> = vec![
        Box::new(GovernanceError::EmptyPolicyDefinition),
        Box::new(GovernanceError::InvalidPolicySyntax {
            expected_format: "json".to_string(),
            reason: "bad".to_string(),
        }),
        Box::new(GovernanceError::PolicySchemaViolation {
            constraint: "c".to_string(),
        }),
        Box::new(GovernanceError::IdDerivationFailed {
            detail: "d".to_string(),
        }),
        Box::new(GovernanceError::InvalidTimeRange {
            start: ts(100),
            end: ts(50),
        }),
        Box::new(GovernanceError::NoEvidenceInRange {
            start: ts(0),
            end: ts(100),
        }),
        Box::new(GovernanceError::UnknownFramework {
            framework: "x".to_string(),
        }),
        Box::new(GovernanceError::MissingControl {
            control_id: "c".to_string(),
        }),
        Box::new(GovernanceError::HookFailed {
            hook_type: GovernanceHookType::PreDeploy,
            reason: "r".to_string(),
        }),
        Box::new(GovernanceError::SerialisationFailed {
            reason: "r".to_string(),
        }),
    ];
    let mut displays = BTreeSet::new();
    for v in &variants {
        let msg = format!("{v}");
        assert!(!msg.is_empty());
        displays.insert(msg);
    }
    assert_eq!(
        displays.len(),
        10,
        "all 10 variants produce distinct messages"
    );
}

// --- GovernanceError::source() returns None ---

#[test]
fn governance_error_source_returns_none() {
    use std::error::Error;
    let errors = vec![
        GovernanceError::EmptyPolicyDefinition,
        GovernanceError::SerialisationFailed {
            reason: "io".to_string(),
        },
    ];
    for e in &errors {
        assert!(e.source().is_none());
    }
}

// --- GovernanceError Display exact format ---

#[test]
fn governance_error_display_exact_empty_policy_definition() {
    assert_eq!(
        GovernanceError::EmptyPolicyDefinition.to_string(),
        "policy definition bytes are empty"
    );
}

#[test]
fn governance_error_display_exact_invalid_policy_syntax() {
    let err = GovernanceError::InvalidPolicySyntax {
        expected_format: "toml".to_string(),
        reason: "missing =".to_string(),
    };
    assert_eq!(err.to_string(), "invalid toml policy syntax: missing =");
}

#[test]
fn governance_error_display_exact_policy_schema_violation() {
    let err = GovernanceError::PolicySchemaViolation {
        constraint: "version must be non-zero".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "policy schema violation: version must be non-zero"
    );
}

#[test]
fn governance_error_display_exact_id_derivation_failed() {
    let err = GovernanceError::IdDerivationFailed {
        detail: "empty bytes".to_string(),
    };
    assert_eq!(err.to_string(), "ID derivation failed: empty bytes");
}

#[test]
fn governance_error_display_exact_unknown_framework() {
    let err = GovernanceError::UnknownFramework {
        framework: "soc3".to_string(),
    };
    assert_eq!(err.to_string(), "unknown compliance framework: soc3");
}

#[test]
fn governance_error_display_exact_missing_control() {
    let err = GovernanceError::MissingControl {
        control_id: "CC6.1".to_string(),
    };
    assert_eq!(err.to_string(), "missing compliance control: CC6.1");
}

#[test]
fn governance_error_display_exact_serialisation_failed() {
    let err = GovernanceError::SerialisationFailed {
        reason: "IO error".to_string(),
    };
    assert_eq!(err.to_string(), "serialisation failed: IO error");
}

// --- PolicyDiagnostic serde roundtrip (with and without span) ---

#[test]
fn serde_policy_diagnostic_with_span() {
    let diag = frankenengine_engine::governance_hooks::PolicyDiagnostic {
        severity: DiagnosticSeverity::Warning,
        code: "W0001".to_string(),
        message: "deprecated field".to_string(),
        span: Some((10, 42)),
    };
    let json = serde_json::to_string(&diag).unwrap();
    let back: frankenengine_engine::governance_hooks::PolicyDiagnostic =
        serde_json::from_str(&json).unwrap();
    assert_eq!(diag, back);
}

#[test]
fn serde_policy_diagnostic_without_span() {
    let diag = frankenengine_engine::governance_hooks::PolicyDiagnostic {
        severity: DiagnosticSeverity::Info,
        code: "I0001".to_string(),
        message: "informational hint".to_string(),
        span: None,
    };
    let json = serde_json::to_string(&diag).unwrap();
    let back: frankenengine_engine::governance_hooks::PolicyDiagnostic =
        serde_json::from_str(&json).unwrap();
    assert_eq!(diag, back);
}

// --- PolicyCompilationResult serde success and failure variants ---

#[test]
fn serde_policy_compilation_result_success_variant() {
    let result = compile_toml("serde_success", 1);
    assert!(result.is_success());
    let json = serde_json::to_string(&result).unwrap();
    let back: PolicyCompilationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn serde_policy_compilation_result_failure_variant() {
    let result = compile_policy(
        PolicySource::InlineToml {
            label: "bad".to_string(),
        },
        b"",
        "bad",
        1,
        ts(1),
        BTreeSet::new(),
    );
    assert!(!result.is_success());
    let json = serde_json::to_string(&result).unwrap();
    let back: PolicyCompilationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// --- PolicyCompilationResult method coverage ---

#[test]
fn policy_compilation_result_artifact_returns_none_on_failure() {
    let result = compile_policy(
        PolicySource::InlineToml {
            label: "x".to_string(),
        },
        b"",
        "x",
        1,
        ts(1),
        BTreeSet::new(),
    );
    assert!(result.artifact().is_none());
}

#[test]
fn policy_compilation_result_diagnostics_on_success() {
    let result = compile_toml("clean_policy", 1);
    assert!(result.is_success());
    // Successful compilation should have zero error-level diagnostics.
    assert_eq!(result.count_at_severity(DiagnosticSeverity::Error), 0);
    // diagnostics() should return a slice (possibly empty).
    let _ = result.diagnostics();
}

// --- AuditExportRequest serde roundtrip ---

#[test]
fn serde_audit_export_request_full_fields() {
    let mut kinds = BTreeSet::new();
    kinds.insert("policy_update".to_string());
    kinds.insert("revocation".to_string());
    let req = AuditExportRequest {
        format: AuditExportFormat::Parquet,
        start_tick: ts(10),
        end_tick: ts(90),
        evidence_kinds: Some(kinds),
        max_entries: Some(50),
        requester: "auditor_x".to_string(),
        correlation_id: Some("CORR-001".to_string()),
    };
    let json = serde_json::to_string(&req).unwrap();
    let back: AuditExportRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

#[test]
fn serde_audit_export_request_minimal_fields() {
    let req = AuditExportRequest {
        format: AuditExportFormat::JsonLines,
        start_tick: ts(0),
        end_tick: ts(100),
        evidence_kinds: None,
        max_entries: None,
        requester: "system".to_string(),
        correlation_id: None,
    };
    let json = serde_json::to_string(&req).unwrap();
    let back: AuditExportRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

// --- AuditExportResult serde roundtrip ---

#[test]
fn serde_audit_export_result_roundtrip() {
    let entries = vec![make_evidence_entry("policy_update", 10)];
    let request = AuditExportRequest {
        format: AuditExportFormat::Csv,
        start_tick: ts(0),
        end_tick: ts(100),
        evidence_kinds: None,
        max_entries: None,
        requester: "test".to_string(),
        correlation_id: None,
    };
    let result = export_audit_evidence(request, entries, ts(200)).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: frankenengine_engine::governance_hooks::AuditExportResult =
        serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// --- EvidenceEntry serde roundtrip ---

#[test]
fn serde_evidence_entry_roundtrip() {
    let entry = make_evidence_entry("capability_decision", 42);
    let json = serde_json::to_string(&entry).unwrap();
    let back: EvidenceEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// --- EvidenceEntry with attributes ---

#[test]
fn serde_evidence_entry_with_attributes() {
    let mut entry = make_evidence_entry("policy_update", 10);
    entry
        .attributes
        .insert("actor".to_string(), "admin".to_string());
    entry
        .attributes
        .insert("scope".to_string(), "global".to_string());
    let json = serde_json::to_string(&entry).unwrap();
    let back: EvidenceEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
    assert_eq!(back.attributes.len(), 2);
}

// --- ComplianceControl serde roundtrip ---

#[test]
fn serde_compliance_control_unsatisfied() {
    let ctrl = frankenengine_engine::governance_hooks::ComplianceControl {
        control_id: "CC6.2".to_string(),
        description: "User registration".to_string(),
        satisfied: false,
        evidence_entry_ids: vec![],
        gaps: vec!["no evidence of kind 'activation_lifecycle'".to_string()],
    };
    let json = serde_json::to_string(&ctrl).unwrap();
    let back: frankenengine_engine::governance_hooks::ComplianceControl =
        serde_json::from_str(&json).unwrap();
    assert_eq!(ctrl, back);
}

// --- ComplianceEvidence serde roundtrip ---

#[test]
fn serde_compliance_evidence_roundtrip() {
    let entries = full_evidence_set();
    let (bundle, _) =
        generate_compliance_bundle(ComplianceFramework::Gdpr, ts(0), ts(100), entries, ts(200))
            .unwrap();
    let json = serde_json::to_string(&bundle).unwrap();
    let back: frankenengine_engine::governance_hooks::ComplianceEvidence =
        serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
}

// --- ComplianceEvidence methods ---

#[test]
fn compliance_evidence_entry_count() {
    let entries = full_evidence_set();
    let count = entries.len();
    let (bundle, _) = generate_compliance_bundle(
        ComplianceFramework::Custom("test".to_string()),
        ts(0),
        ts(100),
        entries,
        ts(200),
    )
    .unwrap();
    assert_eq!(bundle.entry_count(), count);
}

#[test]
fn compliance_evidence_ids_for_kind() {
    let entries = vec![
        make_evidence_entry("policy_update", 10),
        make_evidence_entry("security_action", 20),
        make_evidence_entry("policy_update", 30),
    ];
    let (bundle, _) = generate_compliance_bundle(
        ComplianceFramework::Custom("test".to_string()),
        ts(0),
        ts(100),
        entries,
        ts(200),
    )
    .unwrap();
    assert_eq!(bundle.ids_for_kind("policy_update").len(), 2);
    assert_eq!(bundle.ids_for_kind("security_action").len(), 1);
    assert!(bundle.ids_for_kind("nonexistent").is_empty());
}

// --- ComplianceEvidenceContract methods ---

#[test]
fn compliance_contract_unsatisfied_count_all_unsatisfied() {
    let (_, contract) =
        generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), vec![], ts(200))
            .unwrap();
    assert_eq!(contract.unsatisfied_count(), contract.controls.len());
    assert_eq!(contract.satisfaction_rate_millionths, 0);
}

#[test]
fn compliance_contract_all_gaps_prefixed_with_control_id() {
    let (_, contract) =
        generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), vec![], ts(200))
            .unwrap();
    let gaps = contract.all_gaps();
    assert!(!gaps.is_empty());
    for gap in &gaps {
        assert!(
            gap.starts_with('['),
            "gap should be prefixed with [control_id]: {gap}"
        );
    }
}

#[test]
fn compliance_contract_find_control_existing() {
    let entries = full_evidence_set();
    let (_, contract) = generate_compliance_bundle(
        ComplianceFramework::Iso27001,
        ts(0),
        ts(100),
        entries,
        ts(200),
    )
    .unwrap();
    let ctrl = contract.find_control("A.9.1").unwrap();
    assert_eq!(ctrl.control_id, "A.9.1");
    assert!(ctrl.satisfied);
}

#[test]
fn compliance_contract_find_control_nonexistent() {
    let entries = full_evidence_set();
    let (_, contract) =
        generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), entries, ts(200))
            .unwrap();
    assert!(contract.find_control("NONEXISTENT_CTRL").is_none());
}

// --- GovernanceHookResult constructors and Display ---

#[test]
fn governance_hook_result_pass_constructor() {
    let r = frankenengine_engine::governance_hooks::GovernanceHookResult::pass(
        GovernanceHookType::PreDeploy,
        "all checks passed",
        ts(100),
    );
    assert!(r.passed);
    assert_eq!(r.hook_type, GovernanceHookType::PreDeploy);
    assert_eq!(r.message, "all checks passed");
    assert!(r.details.is_empty());
    assert_eq!(r.completed_at, ts(100));
}

#[test]
fn governance_hook_result_fail_constructor() {
    let r = frankenengine_engine::governance_hooks::GovernanceHookResult::fail(
        GovernanceHookType::PostDeploy,
        "hash mismatch",
        ts(200),
    );
    assert!(!r.passed);
    assert_eq!(r.hook_type, GovernanceHookType::PostDeploy);
    assert_eq!(r.message, "hash mismatch");
    assert!(r.details.is_empty());
}

#[test]
fn governance_hook_result_display_pass_format() {
    let r = frankenengine_engine::governance_hooks::GovernanceHookResult::pass(
        GovernanceHookType::AuditExport,
        "exported 100 entries",
        ts(1),
    );
    let s = format!("{r}");
    assert!(s.contains("[PASS]"));
    assert!(s.contains("audit_export"));
    assert!(s.contains("exported 100 entries"));
}

#[test]
fn governance_hook_result_display_fail_format() {
    let r = frankenengine_engine::governance_hooks::GovernanceHookResult::fail(
        GovernanceHookType::ComplianceCheck,
        "below threshold",
        ts(1),
    );
    let s = format!("{r}");
    assert!(s.contains("[FAIL]"));
    assert!(s.contains("compliance_check"));
    assert!(s.contains("below threshold"));
}

// --- GovernanceHookResult serde roundtrip ---

#[test]
fn serde_governance_hook_result_roundtrip() {
    let mut r = frankenengine_engine::governance_hooks::GovernanceHookResult::pass(
        GovernanceHookType::PolicyChange,
        "2 artifacts verified",
        ts(42),
    );
    r.details
        .insert("unique_count".to_string(), "2".to_string());
    let json = serde_json::to_string(&r).unwrap();
    let back: frankenengine_engine::governance_hooks::GovernanceHookResult =
        serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// --- GovernancePipelineConfig Default ---

#[test]
fn governance_pipeline_config_default_values() {
    let cfg = GovernancePipelineConfig::default();
    assert_eq!(cfg.hooks.len(), 5);
    assert!(cfg.halt_on_failure);
    assert_eq!(cfg.max_export_entries, 100_000);
    assert_eq!(cfg.frameworks.len(), 5);
}

// --- GovernancePipelineConfig serde roundtrip ---

#[test]
fn serde_governance_pipeline_config_roundtrip() {
    let cfg = GovernancePipelineConfig {
        hooks: vec![
            GovernanceHookType::PreDeploy,
            GovernanceHookType::AuditExport,
        ],
        halt_on_failure: false,
        max_export_entries: 42,
        frameworks: vec![ComplianceFramework::Soc2],
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GovernancePipelineConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn serde_governance_pipeline_config_default_roundtrip() {
    let cfg = GovernancePipelineConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GovernancePipelineConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// --- GovernancePipeline: new + config + events ---

#[test]
fn governance_pipeline_new_starts_empty() {
    let pipeline = GovernancePipeline::new(GovernancePipelineConfig::default());
    assert!(pipeline.events().is_empty());
}

#[test]
fn governance_pipeline_config_accessor() {
    let cfg = GovernancePipelineConfig {
        hooks: vec![GovernanceHookType::PreDeploy],
        halt_on_failure: false,
        max_export_entries: 77,
        frameworks: vec![ComplianceFramework::Gdpr],
    };
    let pipeline = GovernancePipeline::new(cfg.clone());
    assert_eq!(pipeline.config().hooks, cfg.hooks);
    assert!(!pipeline.config().halt_on_failure);
    assert_eq!(pipeline.config().max_export_entries, 77);
    assert_eq!(pipeline.config().frameworks.len(), 1);
}

// --- GovernanceEvent serde roundtrip ---

#[test]
fn serde_governance_event_roundtrip() {
    let schema = SchemaId::from_definition(b"GovernanceEvent.test.v1");
    let event_id = engine_object_id::derive_id(
        ObjectDomain::EvidenceRecord,
        "governance",
        &schema,
        b"test_event_roundtrip",
    )
    .unwrap();
    let mut attrs = BTreeMap::new();
    attrs.insert("key".to_string(), "value".to_string());
    let event = frankenengine_engine::governance_hooks::GovernanceEvent {
        event_id,
        hook_type: GovernanceHookType::ComplianceCheck,
        passed: true,
        summary: "compliance passed".to_string(),
        attributes: attrs,
        timestamp: ts(999),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: frankenengine_engine::governance_hooks::GovernanceEvent =
        serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// --- Compile edge cases ---

#[test]
fn compile_whitespace_only_fails() {
    let result = compile_policy(
        PolicySource::InlineToml {
            label: "ws".to_string(),
        },
        b"   \n  \t  ",
        "ws",
        1,
        ts(1),
        BTreeSet::new(),
    );
    assert!(!result.is_success());
}

#[test]
fn compile_invalid_utf8_fails() {
    let bad = [0xFF, 0xFE, 0x00];
    let result = compile_policy(
        PolicySource::InlineToml {
            label: "bad_utf8".to_string(),
        },
        &bad,
        "bad_utf8",
        1,
        ts(1),
        BTreeSet::new(),
    );
    assert!(!result.is_success());
}

#[test]
fn compile_json_array_source_succeeds() {
    let result = compile_policy(
        PolicySource::InlineJson {
            label: "arr".to_string(),
        },
        b"[{\"key\":\"value\"}]",
        "array_policy",
        1,
        ts(1),
        BTreeSet::new(),
    );
    assert!(result.is_success());
}

#[test]
fn compile_filesystem_source_succeeds() {
    let result = compile_policy(
        PolicySource::FileSystem {
            absolute_path: "/etc/franken/policy.toml".to_string(),
        },
        toml_bytes(),
        "fs_policy",
        1,
        ts(1),
        BTreeSet::new(),
    );
    assert!(result.is_success());
}

#[test]
fn compile_git_repo_source_succeeds() {
    let result = compile_policy(
        PolicySource::GitRepo {
            repo_url: "https://example.com/repo.git".to_string(),
            commit_sha: "a".repeat(40),
            file_path: "policies/runtime.toml".to_string(),
        },
        toml_bytes(),
        "git_policy",
        3,
        ts(1),
        BTreeSet::new(),
    );
    assert!(result.is_success());
    let artifact = extract_artifact(&result);
    assert_eq!(artifact.version, 3);
}

// --- Export edge cases ---

#[test]
fn export_with_correlation_id_preserved() {
    let request = AuditExportRequest {
        format: AuditExportFormat::JsonLines,
        start_tick: ts(0),
        end_tick: ts(100),
        evidence_kinds: None,
        max_entries: None,
        requester: "auditor".to_string(),
        correlation_id: Some("AUDIT-2026-001".to_string()),
    };
    let result = export_audit_evidence(request, vec![], ts(200)).unwrap();
    assert_eq!(
        result.request.correlation_id,
        Some("AUDIT-2026-001".to_string())
    );
}

#[test]
fn export_max_entries_larger_than_available_preserves_all() {
    let entries: Vec<EvidenceEntry> = (0..3)
        .map(|i| make_evidence_entry("policy_update", i * 10))
        .collect();
    let request = AuditExportRequest {
        format: AuditExportFormat::JsonLines,
        start_tick: ts(0),
        end_tick: ts(100),
        evidence_kinds: None,
        max_entries: Some(999),
        requester: "test".to_string(),
        correlation_id: None,
    };
    let result = export_audit_evidence(request, entries, ts(200)).unwrap();
    assert_eq!(result.entry_count, 3);
}

#[test]
fn export_zero_width_time_window() {
    let entries = vec![
        make_evidence_entry("policy_update", 50),
        make_evidence_entry("policy_update", 51),
    ];
    let request = AuditExportRequest {
        format: AuditExportFormat::JsonLines,
        start_tick: ts(50),
        end_tick: ts(50),
        evidence_kinds: None,
        max_entries: None,
        requester: "test".to_string(),
        correlation_id: None,
    };
    let result = export_audit_evidence(request, entries, ts(200)).unwrap();
    assert_eq!(result.entry_count, 1);
}

#[test]
fn export_csv_escapes_commas_in_summary() {
    let mut entry = make_evidence_entry("policy_update", 10);
    entry.summary = "contains, a comma".to_string();
    let request = AuditExportRequest {
        format: AuditExportFormat::Csv,
        start_tick: ts(0),
        end_tick: ts(100),
        evidence_kinds: None,
        max_entries: None,
        requester: "test".to_string(),
        correlation_id: None,
    };
    let result = export_audit_evidence(request, vec![entry], ts(200)).unwrap();
    let payload = String::from_utf8_lossy(&result.payload_bytes);
    assert!(
        payload.contains("\"contains, a comma\""),
        "CSV should quote fields with commas: {payload}"
    );
}

#[test]
fn export_payload_hash_consistency() {
    let entries = vec![make_evidence_entry("security_action", 20)];
    let request = AuditExportRequest {
        format: AuditExportFormat::JsonLines,
        start_tick: ts(0),
        end_tick: ts(100),
        evidence_kinds: None,
        max_entries: None,
        requester: "test".to_string(),
        correlation_id: None,
    };
    let result = export_audit_evidence(request, entries, ts(200)).unwrap();
    assert_eq!(
        result.payload_hash,
        ContentHash::compute(&result.payload_bytes)
    );
}

#[test]
fn export_id_differs_by_format() {
    let entries = vec![make_evidence_entry("policy_update", 10)];
    let req_jl = AuditExportRequest {
        format: AuditExportFormat::JsonLines,
        start_tick: ts(0),
        end_tick: ts(100),
        evidence_kinds: None,
        max_entries: None,
        requester: "test".to_string(),
        correlation_id: None,
    };
    let result_jl = export_audit_evidence(req_jl, entries.clone(), ts(200)).unwrap();
    let req_csv = AuditExportRequest {
        format: AuditExportFormat::Csv,
        start_tick: ts(0),
        end_tick: ts(100),
        evidence_kinds: None,
        max_entries: None,
        requester: "test".to_string(),
        correlation_id: None,
    };
    let result_csv = export_audit_evidence(req_csv, entries, ts(200)).unwrap();
    assert_ne!(result_jl.export_id, result_csv.export_id);
}

// --- Compliance bundle edge cases ---

#[test]
fn compliance_bundle_hash_differs_for_different_entries() {
    let entries_a = vec![make_evidence_entry("policy_update", 10)];
    let entries_b = vec![make_evidence_entry("security_action", 10)];
    let (ba, _) = generate_compliance_bundle(
        ComplianceFramework::Custom("f".to_string()),
        ts(0),
        ts(100),
        entries_a,
        ts(200),
    )
    .unwrap();
    let (bb, _) = generate_compliance_bundle(
        ComplianceFramework::Custom("f".to_string()),
        ts(0),
        ts(100),
        entries_b,
        ts(200),
    )
    .unwrap();
    assert_ne!(ba.bundle_hash, bb.bundle_hash);
}

#[test]
fn compliance_bundle_id_sensitive_to_framework() {
    let entries = vec![make_evidence_entry("policy_update", 10)];
    let (b_soc2, _) = generate_compliance_bundle(
        ComplianceFramework::Soc2,
        ts(0),
        ts(100),
        entries.clone(),
        ts(200),
    )
    .unwrap();
    let (b_gdpr, _) =
        generate_compliance_bundle(ComplianceFramework::Gdpr, ts(0), ts(100), entries, ts(200))
            .unwrap();
    assert_ne!(b_soc2.bundle_id, b_gdpr.bundle_id);
}

#[test]
fn compliance_bundle_window_filtering() {
    let entries = vec![
        make_evidence_entry("policy_update", 10),
        make_evidence_entry("policy_update", 500),
    ];
    let (bundle, _) = generate_compliance_bundle(
        ComplianceFramework::Custom("f".to_string()),
        ts(0),
        ts(100),
        entries,
        ts(200),
    )
    .unwrap();
    assert_eq!(bundle.entries.len(), 1);
}

#[test]
fn compliance_bundle_hash_determinism_across_timestamps() {
    let entries = vec![make_evidence_entry("policy_update", 10)];
    let (b1, _) = generate_compliance_bundle(
        ComplianceFramework::Custom("f".to_string()),
        ts(0),
        ts(100),
        entries.clone(),
        ts(200),
    )
    .unwrap();
    let (b2, _) = generate_compliance_bundle(
        ComplianceFramework::Custom("f".to_string()),
        ts(0),
        ts(100),
        entries,
        ts(999),
    )
    .unwrap();
    assert_eq!(b1.bundle_hash, b2.bundle_hash);
}

// --- Pipeline edge cases ---

#[test]
fn pipeline_empty_hooks_returns_empty_results() {
    let config = GovernancePipelineConfig {
        hooks: vec![],
        halt_on_failure: true,
        max_export_entries: 100,
        frameworks: vec![],
    };
    let mut pipeline = GovernancePipeline::new(config);
    let results = run_governance_pipeline(&mut pipeline, &[], vec![], ts(1)).unwrap();
    assert!(results.is_empty());
    assert!(pipeline.events().is_empty());
}

#[test]
fn pipeline_post_deploy_hash_corruption_fails() {
    let mut artifact = extract_artifact(&compile_toml("good", 1)).clone();
    artifact.compiled_hash = ContentHash::compute(b"corrupted");
    let config = GovernancePipelineConfig {
        hooks: vec![GovernanceHookType::PostDeploy],
        halt_on_failure: true,
        max_export_entries: 100,
        frameworks: vec![],
    };
    let mut pipeline = GovernancePipeline::new(config);
    let err = run_governance_pipeline(&mut pipeline, &[artifact], vec![], ts(100));
    assert!(matches!(err, Err(GovernanceError::HookFailed { .. })));
}

#[test]
fn pipeline_compliance_check_with_full_evidence_passes() {
    let artifact = extract_artifact(&compile_toml("comp_ok", 1)).clone();
    let entries = full_evidence_set();
    let config = GovernancePipelineConfig {
        hooks: vec![GovernanceHookType::ComplianceCheck],
        halt_on_failure: true,
        max_export_entries: 100,
        frameworks: vec![ComplianceFramework::Soc2],
    };
    let mut pipeline = GovernancePipeline::new(config);
    let results = run_governance_pipeline(&mut pipeline, &[artifact], entries, ts(200)).unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].passed);
}

#[test]
fn pipeline_compliance_check_no_evidence_fails() {
    let config = GovernancePipelineConfig {
        hooks: vec![GovernanceHookType::ComplianceCheck],
        halt_on_failure: true,
        max_export_entries: 100,
        frameworks: vec![ComplianceFramework::Soc2],
    };
    let mut pipeline = GovernancePipeline::new(config);
    let err = run_governance_pipeline(&mut pipeline, &[], vec![], ts(200));
    assert!(matches!(err, Err(GovernanceError::HookFailed { .. })));
}

#[test]
fn pipeline_events_match_results_count() {
    let artifact = extract_artifact(&compile_toml("evt_test", 1)).clone();
    let entries = full_evidence_set();
    let config = GovernancePipelineConfig::default();
    let mut pipeline = GovernancePipeline::new(config);
    let results = run_governance_pipeline(&mut pipeline, &[artifact], entries, ts(200)).unwrap();
    assert_eq!(pipeline.events().len(), results.len());
}

#[test]
fn pipeline_events_have_nonempty_summaries() {
    let artifact = extract_artifact(&compile_toml("sum_test", 1)).clone();
    let entries = full_evidence_set();
    let config = GovernancePipelineConfig {
        hooks: vec![
            GovernanceHookType::PreDeploy,
            GovernanceHookType::AuditExport,
        ],
        halt_on_failure: true,
        max_export_entries: 100,
        frameworks: vec![],
    };
    let mut pipeline = GovernancePipeline::new(config);
    run_governance_pipeline(&mut pipeline, &[artifact], entries, ts(200)).unwrap();
    for event in pipeline.events() {
        assert!(!event.summary.is_empty());
    }
}

#[test]
fn pipeline_policy_change_distinct_artifacts_passes() {
    let art1 = extract_artifact(&compile_policy(
        PolicySource::InlineToml {
            label: "a".to_string(),
        },
        b"key1 = true",
        "policy_a",
        1,
        ts(1),
        BTreeSet::new(),
    ))
    .clone();
    let art2 = extract_artifact(&compile_policy(
        PolicySource::InlineToml {
            label: "b".to_string(),
        },
        b"key2 = false",
        "policy_b",
        1,
        ts(1),
        BTreeSet::new(),
    ))
    .clone();
    let config = GovernancePipelineConfig {
        hooks: vec![GovernanceHookType::PolicyChange],
        halt_on_failure: true,
        max_export_entries: 100,
        frameworks: vec![],
    };
    let mut pipeline = GovernancePipeline::new(config);
    let results = run_governance_pipeline(&mut pipeline, &[art1, art2], vec![], ts(200)).unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].passed);
}

#[test]
fn pipeline_audit_export_hook_reports_entry_count() {
    let entries = vec![
        make_evidence_entry("policy_update", 10),
        make_evidence_entry("security_action", 20),
    ];
    let config = GovernancePipelineConfig {
        hooks: vec![GovernanceHookType::AuditExport],
        halt_on_failure: true,
        max_export_entries: 100,
        frameworks: vec![],
    };
    let mut pipeline = GovernancePipeline::new(config);
    let results = run_governance_pipeline(&mut pipeline, &[], entries, ts(200)).unwrap();
    assert!(results[0].details.contains_key("entry_count"));
    assert_eq!(
        results[0].details.get("entry_count"),
        Some(&"2".to_string())
    );
}

#[test]
fn pipeline_pre_deploy_reports_artifact_count() {
    let artifact = extract_artifact(&compile_toml("art_count", 1)).clone();
    let config = GovernancePipelineConfig {
        hooks: vec![GovernanceHookType::PreDeploy],
        halt_on_failure: true,
        max_export_entries: 100,
        frameworks: vec![],
    };
    let mut pipeline = GovernancePipeline::new(config);
    let results = run_governance_pipeline(&mut pipeline, &[artifact], vec![], ts(200)).unwrap();
    assert_eq!(
        results[0].details.get("artifact_count"),
        Some(&"1".to_string())
    );
}

#[test]
fn pipeline_compliance_check_event_has_framework_key() {
    let entries = full_evidence_set();
    let config = GovernancePipelineConfig {
        hooks: vec![GovernanceHookType::ComplianceCheck],
        halt_on_failure: false,
        max_export_entries: 100,
        frameworks: vec![ComplianceFramework::Soc2],
    };
    let mut pipeline = GovernancePipeline::new(config);
    run_governance_pipeline(&mut pipeline, &[], entries, ts(200)).unwrap();
    let event = &pipeline.events()[0];
    assert!(event.attributes.contains_key("soc2"));
}
