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
