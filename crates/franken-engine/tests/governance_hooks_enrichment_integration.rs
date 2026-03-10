//! Enrichment integration tests for governance_hooks.
//!
//! Adds JSON field-name stability, serde exact enum values, Debug
//! distinctness, error Display exact messages, helper edge cases,
//! compliance control verification, pipeline detail attributes, and
//! additional serde roundtrips beyond the existing 66 integration tests.

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
    GovernanceError, GovernanceEvent, GovernanceHookResult, GovernanceHookType, GovernancePipeline,
    GovernancePipelineConfig, PolicyArtifact, PolicyCompilationResult, PolicyDiagnostic,
    PolicySource, compile_policy, export_audit_evidence, generate_compliance_bundle,
    run_governance_pipeline, validate_policy,
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
// 1. JSON field-name stability
// ---------------------------------------------------------------------------

#[test]
fn json_fields_policy_artifact() {
    let result = compile_toml("field_test", 1);
    let artifact = extract_artifact(&result);
    let json = serde_json::to_string(artifact).unwrap();
    for field in [
        "artifact_id",
        "version",
        "definition_hash",
        "compiled_hash",
        "compiled_bytes",
        "source",
        "compiled_at",
        "policy_name",
        "tags",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn json_fields_policy_diagnostic() {
    let result = compile_policy(
        PolicySource::InlineToml {
            label: "x".to_string(),
        },
        b"",
        "empty",
        1,
        ts(1),
        BTreeSet::new(),
    );
    let diag = &result.diagnostics()[0];
    let json = serde_json::to_string(diag).unwrap();
    for field in ["severity", "code", "message", "span"] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn json_fields_policy_compilation_result_success() {
    let result = compile_toml("success_fields", 1);
    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("artifact"), "missing 'artifact' in Success");
    assert!(
        json.contains("diagnostics"),
        "missing 'diagnostics' in Success"
    );
}

#[test]
fn json_fields_policy_compilation_result_failure() {
    let result = compile_policy(
        PolicySource::InlineToml {
            label: "x".to_string(),
        },
        b"",
        "fail",
        1,
        ts(1),
        BTreeSet::new(),
    );
    let json = serde_json::to_string(&result).unwrap();
    assert!(
        json.contains("diagnostics"),
        "missing 'diagnostics' in Failure"
    );
    assert!(
        json.contains("error_summary"),
        "missing 'error_summary' in Failure"
    );
}

#[test]
fn json_fields_audit_export_request() {
    let req = AuditExportRequest {
        format: AuditExportFormat::JsonLines,
        start_tick: ts(0),
        end_tick: ts(100),
        evidence_kinds: None,
        max_entries: None,
        requester: "tester".to_string(),
        correlation_id: None,
    };
    let json = serde_json::to_string(&req).unwrap();
    for field in [
        "format",
        "start_tick",
        "end_tick",
        "evidence_kinds",
        "max_entries",
        "requester",
        "correlation_id",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn json_fields_audit_export_result() {
    let entries = full_evidence_set();
    let req = AuditExportRequest {
        format: AuditExportFormat::JsonLines,
        start_tick: ts(0),
        end_tick: ts(100),
        evidence_kinds: None,
        max_entries: None,
        requester: "tester".to_string(),
        correlation_id: None,
    };
    let result = export_audit_evidence(req, entries, ts(200)).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    for field in [
        "export_id",
        "format",
        "payload_hash",
        "payload_bytes",
        "entry_count",
        "exported_at",
        "request",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn json_fields_evidence_entry() {
    let entry = make_evidence_entry("test_kind", 42);
    let json = serde_json::to_string(&entry).unwrap();
    for field in [
        "entry_id",
        "kind",
        "timestamp",
        "summary",
        "attributes",
        "evidence_hash",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn json_fields_compliance_control() {
    let entries = full_evidence_set();
    let (_, contract) =
        generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), entries, ts(200))
            .unwrap();
    let control = &contract.controls[0];
    let json = serde_json::to_string(control).unwrap();
    for field in [
        "control_id",
        "description",
        "satisfied",
        "evidence_entry_ids",
        "gaps",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn json_fields_compliance_evidence() {
    let entries = full_evidence_set();
    let (bundle, _) =
        generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), entries, ts(200))
            .unwrap();
    let json = serde_json::to_string(&bundle).unwrap();
    for field in [
        "bundle_id",
        "framework",
        "window_start",
        "window_end",
        "entries",
        "bundle_hash",
        "assembled_at",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn json_fields_compliance_evidence_contract() {
    let entries = full_evidence_set();
    let (_, contract) =
        generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), entries, ts(200))
            .unwrap();
    let json = serde_json::to_string(&contract).unwrap();
    for field in [
        "contract_id",
        "framework",
        "controls",
        "evidence_bundle_id",
        "satisfaction_rate_millionths",
        "evaluated_at",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn json_fields_governance_hook_result() {
    let hr = GovernanceHookResult::pass(GovernanceHookType::PreDeploy, "ok", ts(1));
    let json = serde_json::to_string(&hr).unwrap();
    for field in ["hook_type", "passed", "message", "details", "completed_at"] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn json_fields_governance_event() {
    let artifact = extract_artifact(&compile_toml("evt_test", 1)).clone();
    let config = GovernancePipelineConfig {
        hooks: vec![GovernanceHookType::PreDeploy],
        halt_on_failure: true,
        max_export_entries: 100,
        frameworks: vec![],
    };
    let mut pipeline = GovernancePipeline::new(config);
    let entries = full_evidence_set();
    run_governance_pipeline(
        &mut pipeline,
        std::slice::from_ref(&artifact),
        entries,
        ts(200),
    )
    .unwrap();
    let event = &pipeline.events()[0];
    let json = serde_json::to_string(event).unwrap();
    for field in [
        "event_id",
        "hook_type",
        "passed",
        "summary",
        "attributes",
        "timestamp",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// ---------------------------------------------------------------------------
// 2. Serde exact enum values
// ---------------------------------------------------------------------------

#[test]
fn serde_exact_policy_source_all_variants() {
    let sources = vec![
        (
            PolicySource::GitRepo {
                repo_url: "u".to_string(),
                commit_sha: "c".to_string(),
                file_path: "f".to_string(),
            },
            "GitRepo",
        ),
        (
            PolicySource::FileSystem {
                absolute_path: "/p".to_string(),
            },
            "FileSystem",
        ),
        (
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            "InlineToml",
        ),
        (
            PolicySource::InlineJson {
                label: "j".to_string(),
            },
            "InlineJson",
        ),
    ];
    for (src, expected_tag) in sources {
        let json = serde_json::to_string(&src).unwrap();
        assert!(
            json.contains(expected_tag),
            "missing tag {expected_tag} in {json}"
        );
        let back: PolicySource = serde_json::from_str(&json).unwrap();
        assert_eq!(src, back);
    }
}

#[test]
fn serde_exact_diagnostic_severity() {
    for (sev, expected) in [
        (DiagnosticSeverity::Info, "\"Info\""),
        (DiagnosticSeverity::Warning, "\"Warning\""),
        (DiagnosticSeverity::Error, "\"Error\""),
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        assert_eq!(json, expected, "unexpected serde for {sev:?}");
    }
}

#[test]
fn serde_exact_compliance_framework() {
    for (fw, expected_tag) in [
        (ComplianceFramework::Soc2, "Soc2"),
        (ComplianceFramework::Iso27001, "Iso27001"),
        (ComplianceFramework::Hipaa, "Hipaa"),
        (ComplianceFramework::PciDss, "PciDss"),
        (ComplianceFramework::Gdpr, "Gdpr"),
    ] {
        let json = serde_json::to_string(&fw).unwrap();
        assert!(
            json.contains(expected_tag),
            "missing tag {expected_tag} in {json}"
        );
        let back: ComplianceFramework = serde_json::from_str(&json).unwrap();
        assert_eq!(fw, back);
    }
    // Custom variant
    let custom = ComplianceFramework::Custom("MY_FW".to_string());
    let json = serde_json::to_string(&custom).unwrap();
    assert!(json.contains("Custom"), "missing Custom tag in {json}");
    assert!(json.contains("MY_FW"));
    let back: ComplianceFramework = serde_json::from_str(&json).unwrap();
    assert_eq!(custom, back);
}

#[test]
fn serde_exact_audit_export_format() {
    for (fmt, expected) in [
        (AuditExportFormat::JsonLines, "\"JsonLines\""),
        (AuditExportFormat::Csv, "\"Csv\""),
        (AuditExportFormat::Parquet, "\"Parquet\""),
        (AuditExportFormat::CompliancePdf, "\"CompliancePdf\""),
    ] {
        let json = serde_json::to_string(&fmt).unwrap();
        assert_eq!(json, expected, "unexpected serde for {fmt:?}");
    }
}

#[test]
fn serde_exact_governance_hook_type() {
    for (ht, expected) in [
        (GovernanceHookType::PreDeploy, "\"PreDeploy\""),
        (GovernanceHookType::PostDeploy, "\"PostDeploy\""),
        (GovernanceHookType::PolicyChange, "\"PolicyChange\""),
        (GovernanceHookType::AuditExport, "\"AuditExport\""),
        (GovernanceHookType::ComplianceCheck, "\"ComplianceCheck\""),
    ] {
        let json = serde_json::to_string(&ht).unwrap();
        assert_eq!(json, expected, "unexpected serde for {ht:?}");
    }
}

#[test]
fn serde_exact_governance_error_all_variants() {
    let errors = vec![
        GovernanceError::EmptyPolicyDefinition,
        GovernanceError::InvalidPolicySyntax {
            expected_format: "toml".to_string(),
            reason: "bad".to_string(),
        },
        GovernanceError::PolicySchemaViolation {
            constraint: "c".to_string(),
        },
        GovernanceError::IdDerivationFailed {
            detail: "d".to_string(),
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
            reason: "r".to_string(),
        },
        GovernanceError::SerialisationFailed {
            reason: "oops".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: GovernanceError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back, "roundtrip failed for {err:?}");
    }
}

// ---------------------------------------------------------------------------
// 3. Debug distinctness
// ---------------------------------------------------------------------------

#[test]
fn debug_distinct_policy_source() {
    let variants: Vec<String> = vec![
        format!(
            "{:?}",
            PolicySource::GitRepo {
                repo_url: "u".to_string(),
                commit_sha: "c".to_string(),
                file_path: "f".to_string(),
            }
        ),
        format!(
            "{:?}",
            PolicySource::FileSystem {
                absolute_path: "/p".to_string(),
            }
        ),
        format!(
            "{:?}",
            PolicySource::InlineToml {
                label: "t".to_string(),
            }
        ),
        format!(
            "{:?}",
            PolicySource::InlineJson {
                label: "j".to_string(),
            }
        ),
    ];
    for i in 0..variants.len() {
        for j in (i + 1)..variants.len() {
            assert_ne!(variants[i], variants[j]);
        }
    }
}

#[test]
fn debug_distinct_diagnostic_severity() {
    let debugs: Vec<String> = DiagnosticSeverity::all()
        .iter()
        .map(|s| format!("{s:?}"))
        .collect();
    for i in 0..debugs.len() {
        for j in (i + 1)..debugs.len() {
            assert_ne!(debugs[i], debugs[j]);
        }
    }
}

#[test]
fn debug_distinct_compliance_framework() {
    let mut debugs: Vec<String> = ComplianceFramework::all_builtin()
        .iter()
        .map(|f| format!("{f:?}"))
        .collect();
    debugs.push(format!(
        "{:?}",
        ComplianceFramework::Custom("X".to_string())
    ));
    for i in 0..debugs.len() {
        for j in (i + 1)..debugs.len() {
            assert_ne!(debugs[i], debugs[j]);
        }
    }
}

#[test]
fn debug_distinct_audit_export_format() {
    let debugs: Vec<String> = AuditExportFormat::all()
        .iter()
        .map(|f| format!("{f:?}"))
        .collect();
    for i in 0..debugs.len() {
        for j in (i + 1)..debugs.len() {
            assert_ne!(debugs[i], debugs[j]);
        }
    }
}

#[test]
fn debug_distinct_governance_hook_type() {
    let debugs: Vec<String> = GovernanceHookType::all()
        .iter()
        .map(|h| format!("{h:?}"))
        .collect();
    for i in 0..debugs.len() {
        for j in (i + 1)..debugs.len() {
            assert_ne!(debugs[i], debugs[j]);
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Error Display exact messages
// ---------------------------------------------------------------------------

#[test]
fn error_display_empty_policy_definition() {
    let e = GovernanceError::EmptyPolicyDefinition;
    assert_eq!(format!("{e}"), "policy definition bytes are empty");
}

#[test]
fn error_display_invalid_policy_syntax() {
    let e = GovernanceError::InvalidPolicySyntax {
        expected_format: "toml".to_string(),
        reason: "missing key".to_string(),
    };
    assert_eq!(format!("{e}"), "invalid toml policy syntax: missing key");
}

#[test]
fn error_display_policy_schema_violation() {
    let e = GovernanceError::PolicySchemaViolation {
        constraint: "version must be non-zero".to_string(),
    };
    assert_eq!(
        format!("{e}"),
        "policy schema violation: version must be non-zero"
    );
}

#[test]
fn error_display_id_derivation_failed() {
    let e = GovernanceError::IdDerivationFailed {
        detail: "bad input".to_string(),
    };
    assert_eq!(format!("{e}"), "ID derivation failed: bad input");
}

#[test]
fn error_display_invalid_time_range() {
    let e = GovernanceError::InvalidTimeRange {
        start: ts(10),
        end: ts(5),
    };
    let display = format!("{e}");
    assert!(display.contains("invalid time range"));
    assert!(display.contains("10"));
    assert!(display.contains("5"));
}

#[test]
fn error_display_no_evidence_in_range() {
    let e = GovernanceError::NoEvidenceInRange {
        start: ts(0),
        end: ts(100),
    };
    let display = format!("{e}");
    assert!(display.contains("no evidence found in range"));
}

#[test]
fn error_display_unknown_framework() {
    let e = GovernanceError::UnknownFramework {
        framework: "alien".to_string(),
    };
    assert_eq!(format!("{e}"), "unknown compliance framework: alien");
}

#[test]
fn error_display_missing_control() {
    let e = GovernanceError::MissingControl {
        control_id: "CC1.1".to_string(),
    };
    assert_eq!(format!("{e}"), "missing compliance control: CC1.1");
}

#[test]
fn error_display_hook_failed() {
    let e = GovernanceError::HookFailed {
        hook_type: GovernanceHookType::PreDeploy,
        reason: "version 0".to_string(),
    };
    assert_eq!(
        format!("{e}"),
        "governance hook pre_deploy failed: version 0"
    );
}

#[test]
fn error_display_serialisation_failed() {
    let e = GovernanceError::SerialisationFailed {
        reason: "codec error".to_string(),
    };
    assert_eq!(format!("{e}"), "serialisation failed: codec error");
}

// ---------------------------------------------------------------------------
// 5. std::error::Error impl
// ---------------------------------------------------------------------------

#[test]
fn governance_error_is_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(GovernanceError::EmptyPolicyDefinition);
    assert!(!e.to_string().is_empty());
}

// ---------------------------------------------------------------------------
// 6. GovernanceHookResult factories and Display
// ---------------------------------------------------------------------------

#[test]
fn hook_result_pass_factory() {
    let hr = GovernanceHookResult::pass(GovernanceHookType::PostDeploy, "all good", ts(42));
    assert!(hr.passed);
    assert_eq!(hr.hook_type, GovernanceHookType::PostDeploy);
    assert_eq!(hr.message, "all good");
    assert_eq!(hr.completed_at, ts(42));
    assert!(hr.details.is_empty());
}

#[test]
fn hook_result_fail_factory() {
    let hr = GovernanceHookResult::fail(GovernanceHookType::PreDeploy, "bad version", ts(99));
    assert!(!hr.passed);
    assert_eq!(hr.hook_type, GovernanceHookType::PreDeploy);
    assert_eq!(hr.message, "bad version");
    assert_eq!(hr.completed_at, ts(99));
    assert!(hr.details.is_empty());
}

#[test]
fn hook_result_display_pass_and_fail() {
    let pass = GovernanceHookResult::pass(GovernanceHookType::AuditExport, "exported", ts(1));
    let fail = GovernanceHookResult::fail(GovernanceHookType::PolicyChange, "dup hash", ts(2));

    let pass_str = format!("{pass}");
    assert!(pass_str.starts_with("[PASS]"), "got: {pass_str}");
    assert!(pass_str.contains("audit_export"));
    assert!(pass_str.contains("exported"));

    let fail_str = format!("{fail}");
    assert!(fail_str.starts_with("[FAIL]"), "got: {fail_str}");
    assert!(fail_str.contains("policy_change"));
    assert!(fail_str.contains("dup hash"));
}

// ---------------------------------------------------------------------------
// 7. GovernancePipelineConfig defaults
// ---------------------------------------------------------------------------

#[test]
fn pipeline_config_default_fields() {
    let cfg = GovernancePipelineConfig::default();
    assert_eq!(cfg.hooks.len(), 5, "default should have all 5 hooks");
    assert!(
        cfg.halt_on_failure,
        "default halt_on_failure should be true"
    );
    assert_eq!(cfg.max_export_entries, 100_000);
    assert_eq!(
        cfg.frameworks.len(),
        5,
        "default should have 5 built-in frameworks"
    );
    // Verify hook order matches GovernanceHookType::all()
    assert_eq!(cfg.hooks, GovernanceHookType::all().to_vec());
}

#[test]
fn pipeline_config_serde_roundtrip() {
    let cfg = GovernancePipelineConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GovernancePipelineConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ---------------------------------------------------------------------------
// 8. GovernancePipeline accessors
// ---------------------------------------------------------------------------

#[test]
fn pipeline_config_and_events_accessors() {
    let config = GovernancePipelineConfig {
        hooks: vec![GovernanceHookType::AuditExport],
        halt_on_failure: false,
        max_export_entries: 42,
        frameworks: vec![],
    };
    let pipeline = GovernancePipeline::new(config.clone());
    assert_eq!(*pipeline.config(), config);
    assert!(pipeline.events().is_empty());
}

// ---------------------------------------------------------------------------
// 9. ComplianceEvidence helpers
// ---------------------------------------------------------------------------

#[test]
fn compliance_evidence_entry_count() {
    let entries = full_evidence_set();
    let (bundle, _) =
        generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), entries, ts(200))
            .unwrap();
    assert_eq!(bundle.entry_count(), 6);
}

#[test]
fn compliance_evidence_ids_for_kind_match() {
    let entries = full_evidence_set();
    let (bundle, _) =
        generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), entries, ts(200))
            .unwrap();
    let cap_ids = bundle.ids_for_kind("capability_decision");
    assert_eq!(cap_ids.len(), 1);
}

#[test]
fn compliance_evidence_ids_for_kind_no_match() {
    let entries = full_evidence_set();
    let (bundle, _) =
        generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), entries, ts(200))
            .unwrap();
    let none = bundle.ids_for_kind("nonexistent_kind");
    assert!(none.is_empty());
}

// ---------------------------------------------------------------------------
// 10. ComplianceEvidenceContract helpers
// ---------------------------------------------------------------------------

#[test]
fn contract_find_control_present_and_absent() {
    let entries = full_evidence_set();
    let (_, contract) =
        generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), entries, ts(200))
            .unwrap();
    assert!(contract.find_control("CC6.1").is_some());
    assert!(contract.find_control("CC6.2").is_some());
    assert!(contract.find_control("CC7.2").is_some());
    assert!(contract.find_control("CC9.2").is_some());
    assert!(contract.find_control("NONEXISTENT").is_none());
}

#[test]
fn contract_unsatisfied_count_full_evidence() {
    let entries = full_evidence_set();
    let (_, contract) =
        generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), entries, ts(200))
            .unwrap();
    assert_eq!(contract.unsatisfied_count(), 0);
}

#[test]
fn contract_all_gaps_format() {
    // Only provide "capability_decision" — SOC 2 CC6.2 needs activation_lifecycle.
    let entries = vec![make_evidence_entry("capability_decision", 10)];
    let (_, contract) =
        generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), entries, ts(200))
            .unwrap();
    let gaps = contract.all_gaps();
    assert!(!gaps.is_empty());
    // Gaps should have format "[control_id] message"
    for gap in &gaps {
        assert!(gap.starts_with('['), "gap should start with '[': {gap}");
        assert!(gap.contains(']'), "gap should contain ']': {gap}");
    }
}

#[test]
fn contract_satisfaction_rate_partial() {
    // Provide only capability_decision and policy_update.
    // SOC 2 controls:
    //   CC6.1: needs capability_decision + policy_update → satisfied
    //   CC6.2: needs activation_lifecycle → unsatisfied
    //   CC7.2: needs security_action + epoch_transition → unsatisfied
    //   CC9.2: needs revocation → unsatisfied
    // 1 out of 4 satisfied = 250_000 ppm
    let entries = vec![
        make_evidence_entry("capability_decision", 10),
        make_evidence_entry("policy_update", 20),
    ];
    let (_, contract) =
        generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), entries, ts(200))
            .unwrap();
    assert_eq!(contract.satisfaction_rate_millionths, 250_000);
    assert_eq!(contract.unsatisfied_count(), 3);
}

// ---------------------------------------------------------------------------
// 11. PolicyCompilationResult helpers
// ---------------------------------------------------------------------------

#[test]
fn compilation_result_helpers_on_success() {
    let result = compile_toml("helper_test", 1);
    assert!(result.is_success());
    assert!(result.artifact().is_some());
    assert_eq!(result.count_at_severity(DiagnosticSeverity::Error), 0);
}

#[test]
fn compilation_result_helpers_on_failure() {
    let result = compile_policy(
        PolicySource::InlineToml {
            label: "x".to_string(),
        },
        b"",
        "fail",
        1,
        ts(1),
        BTreeSet::new(),
    );
    assert!(!result.is_success());
    assert!(result.artifact().is_none());
    assert!(result.count_at_severity(DiagnosticSeverity::Error) > 0);
    assert!(result.count_at_severity(DiagnosticSeverity::Info) > 0); // error >= info
}

// ---------------------------------------------------------------------------
// 12. Diagnostic codes from compile failures
// ---------------------------------------------------------------------------

#[test]
fn diagnostic_code_e0001_empty_bytes() {
    let result = compile_policy(
        PolicySource::InlineToml {
            label: "x".to_string(),
        },
        b"",
        "empty",
        1,
        ts(1),
        BTreeSet::new(),
    );
    assert_eq!(result.diagnostics()[0].code, "E0001");
}

#[test]
fn diagnostic_code_e0010_invalid_toml() {
    let result = compile_policy(
        PolicySource::InlineToml {
            label: "x".to_string(),
        },
        b"this is just plain text without any key value pairs",
        "bad_toml",
        1,
        ts(1),
        BTreeSet::new(),
    );
    assert!(!result.is_success());
    assert_eq!(result.diagnostics()[0].code, "E0010");
}

#[test]
fn diagnostic_code_e0011_invalid_json() {
    let result = compile_policy(
        PolicySource::InlineJson {
            label: "x".to_string(),
        },
        b"not-json",
        "bad_json",
        1,
        ts(1),
        BTreeSet::new(),
    );
    assert!(!result.is_success());
    assert_eq!(result.diagnostics()[0].code, "E0011");
}

// ---------------------------------------------------------------------------
// 13. Export with correlation_id
// ---------------------------------------------------------------------------

#[test]
fn export_preserves_correlation_id() {
    let entries = full_evidence_set();
    let req = AuditExportRequest {
        format: AuditExportFormat::JsonLines,
        start_tick: ts(0),
        end_tick: ts(100),
        evidence_kinds: None,
        max_entries: None,
        requester: "tester".to_string(),
        correlation_id: Some("corr-123".to_string()),
    };
    let result = export_audit_evidence(req, entries, ts(200)).unwrap();
    assert_eq!(result.request.correlation_id, Some("corr-123".to_string()));
}

// ---------------------------------------------------------------------------
// 14. Compliance controls per framework
// ---------------------------------------------------------------------------

#[test]
fn soc2_controls_are_cc61_cc62_cc72_cc92() {
    let entries = full_evidence_set();
    let (_, contract) =
        generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), entries, ts(200))
            .unwrap();
    let ids: Vec<&str> = contract
        .controls
        .iter()
        .map(|c| c.control_id.as_str())
        .collect();
    assert_eq!(ids, vec!["CC6.1", "CC6.2", "CC7.2", "CC9.2"]);
}

#[test]
fn iso27001_controls_are_a91_a124_a161() {
    let entries = full_evidence_set();
    let (_, contract) = generate_compliance_bundle(
        ComplianceFramework::Iso27001,
        ts(0),
        ts(100),
        entries,
        ts(200),
    )
    .unwrap();
    let ids: Vec<&str> = contract
        .controls
        .iter()
        .map(|c| c.control_id.as_str())
        .collect();
    assert_eq!(ids, vec!["A.9.1", "A.12.4", "A.16.1"]);
}

#[test]
fn hipaa_controls() {
    let entries = full_evidence_set();
    let (_, contract) =
        generate_compliance_bundle(ComplianceFramework::Hipaa, ts(0), ts(100), entries, ts(200))
            .unwrap();
    let ids: Vec<&str> = contract
        .controls
        .iter()
        .map(|c| c.control_id.as_str())
        .collect();
    assert_eq!(
        ids,
        vec!["164.312(a)(1)", "164.312(b)", "164.312(e)(2)(ii)"]
    );
}

#[test]
fn pci_dss_controls() {
    let entries = full_evidence_set();
    let (_, contract) = generate_compliance_bundle(
        ComplianceFramework::PciDss,
        ts(0),
        ts(100),
        entries,
        ts(200),
    )
    .unwrap();
    let ids: Vec<&str> = contract
        .controls
        .iter()
        .map(|c| c.control_id.as_str())
        .collect();
    assert_eq!(ids, vec!["10.1", "10.2", "10.6", "12.10"]);
}

#[test]
fn gdpr_controls() {
    let entries = full_evidence_set();
    let (_, contract) =
        generate_compliance_bundle(ComplianceFramework::Gdpr, ts(0), ts(100), entries, ts(200))
            .unwrap();
    let ids: Vec<&str> = contract
        .controls
        .iter()
        .map(|c| c.control_id.as_str())
        .collect();
    assert_eq!(ids, vec!["Art.30", "Art.32", "Art.33"]);
}

#[test]
fn custom_framework_controls() {
    let entries = full_evidence_set();
    let (_, contract) = generate_compliance_bundle(
        ComplianceFramework::Custom("INTERNAL".to_string()),
        ts(0),
        ts(100),
        entries,
        ts(200),
    )
    .unwrap();
    let ids: Vec<&str> = contract
        .controls
        .iter()
        .map(|c| c.control_id.as_str())
        .collect();
    assert_eq!(ids, vec!["CUSTOM-1", "CUSTOM-2"]);
}

// ---------------------------------------------------------------------------
// 15. Pipeline hook result details
// ---------------------------------------------------------------------------

#[test]
fn pipeline_pre_deploy_details_artifact_count() {
    let artifact = extract_artifact(&compile_toml("det_pre", 1)).clone();
    let config = GovernancePipelineConfig {
        hooks: vec![GovernanceHookType::PreDeploy],
        halt_on_failure: true,
        max_export_entries: 100,
        frameworks: vec![],
    };
    let mut pipeline = GovernancePipeline::new(config);
    let results = run_governance_pipeline(
        &mut pipeline,
        std::slice::from_ref(&artifact),
        full_evidence_set(),
        ts(200),
    )
    .unwrap();
    assert_eq!(results[0].details.get("artifact_count").unwrap(), "1");
}

#[test]
fn pipeline_post_deploy_details_artifact_count() {
    let artifact = extract_artifact(&compile_toml("det_post", 1)).clone();
    let config = GovernancePipelineConfig {
        hooks: vec![GovernanceHookType::PostDeploy],
        halt_on_failure: true,
        max_export_entries: 100,
        frameworks: vec![],
    };
    let mut pipeline = GovernancePipeline::new(config);
    let results = run_governance_pipeline(
        &mut pipeline,
        std::slice::from_ref(&artifact),
        full_evidence_set(),
        ts(200),
    )
    .unwrap();
    assert_eq!(results[0].details.get("artifact_count").unwrap(), "1");
}

#[test]
fn pipeline_policy_change_details_unique_count() {
    let a1 = extract_artifact(&compile_toml("pc_a", 1)).clone();
    let a2 = extract_artifact(&compile_policy(
        PolicySource::InlineToml {
            label: "pc_b".to_string(),
        },
        b"[other]\nkey = 999",
        "pc_b",
        2,
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
    let results =
        run_governance_pipeline(&mut pipeline, &[a1, a2], full_evidence_set(), ts(200)).unwrap();
    assert!(results[0].passed);
    assert_eq!(results[0].details.get("unique_count").unwrap(), "2");
}

#[test]
fn pipeline_audit_export_details_entry_count() {
    let config = GovernancePipelineConfig {
        hooks: vec![GovernanceHookType::AuditExport],
        halt_on_failure: true,
        max_export_entries: 100,
        frameworks: vec![],
    };
    let mut pipeline = GovernancePipeline::new(config);
    let results =
        run_governance_pipeline(&mut pipeline, &[], full_evidence_set(), ts(200)).unwrap();
    assert_eq!(results[0].details.get("entry_count").unwrap(), "6");
}

#[test]
fn pipeline_compliance_check_details_per_framework() {
    let config = GovernancePipelineConfig {
        hooks: vec![GovernanceHookType::ComplianceCheck],
        halt_on_failure: false,
        max_export_entries: 100,
        frameworks: vec![ComplianceFramework::Soc2, ComplianceFramework::Hipaa],
    };
    let mut pipeline = GovernancePipeline::new(config);
    let results =
        run_governance_pipeline(&mut pipeline, &[], full_evidence_set(), ts(200)).unwrap();
    assert!(results[0].details.contains_key("soc2"));
    assert!(results[0].details.contains_key("hipaa"));
}

// ---------------------------------------------------------------------------
// 16. Serde roundtrips for remaining types
// ---------------------------------------------------------------------------

#[test]
fn serde_roundtrip_governance_hook_result() {
    let mut hr = GovernanceHookResult::pass(GovernanceHookType::PostDeploy, "ok", ts(42));
    hr.details.insert("key".to_string(), "value".to_string());
    let json = serde_json::to_string(&hr).unwrap();
    let back: GovernanceHookResult = serde_json::from_str(&json).unwrap();
    assert_eq!(hr, back);
}

#[test]
fn serde_roundtrip_governance_event() {
    let artifact = extract_artifact(&compile_toml("serde_evt", 1)).clone();
    let config = GovernancePipelineConfig {
        hooks: vec![GovernanceHookType::PreDeploy],
        halt_on_failure: true,
        max_export_entries: 100,
        frameworks: vec![],
    };
    let mut pipeline = GovernancePipeline::new(config);
    run_governance_pipeline(
        &mut pipeline,
        std::slice::from_ref(&artifact),
        full_evidence_set(),
        ts(200),
    )
    .unwrap();
    let event = &pipeline.events()[0];
    let json = serde_json::to_string(event).unwrap();
    let back: GovernanceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(*event, back);
}

#[test]
fn serde_roundtrip_audit_export_request() {
    let mut kinds = BTreeSet::new();
    kinds.insert("policy_update".to_string());
    let req = AuditExportRequest {
        format: AuditExportFormat::Csv,
        start_tick: ts(10),
        end_tick: ts(50),
        evidence_kinds: Some(kinds),
        max_entries: Some(5),
        requester: "admin".to_string(),
        correlation_id: Some("xyz".to_string()),
    };
    let json = serde_json::to_string(&req).unwrap();
    let back: AuditExportRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

#[test]
fn serde_roundtrip_policy_diagnostic() {
    let diag = PolicyDiagnostic {
        severity: DiagnosticSeverity::Warning,
        code: "W0001".to_string(),
        message: "watch out".to_string(),
        span: Some((10, 20)),
    };
    let json = serde_json::to_string(&diag).unwrap();
    let back: PolicyDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, back);
}

#[test]
fn serde_roundtrip_evidence_entry() {
    let entry = make_evidence_entry("test_kind", 42);
    let json = serde_json::to_string(&entry).unwrap();
    let back: EvidenceEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ---------------------------------------------------------------------------
// 17. as_str exact values
// ---------------------------------------------------------------------------

#[test]
fn compliance_framework_as_str_exact() {
    assert_eq!(ComplianceFramework::Soc2.as_str(), "soc2");
    assert_eq!(ComplianceFramework::Iso27001.as_str(), "iso27001");
    assert_eq!(ComplianceFramework::Hipaa.as_str(), "hipaa");
    assert_eq!(ComplianceFramework::PciDss.as_str(), "pci_dss");
    assert_eq!(ComplianceFramework::Gdpr.as_str(), "gdpr");
    assert_eq!(
        ComplianceFramework::Custom("FOO".to_string()).as_str(),
        "FOO"
    );
}

#[test]
fn audit_export_format_as_str_exact() {
    assert_eq!(AuditExportFormat::JsonLines.as_str(), "jsonlines");
    assert_eq!(AuditExportFormat::Csv.as_str(), "csv");
    assert_eq!(AuditExportFormat::Parquet.as_str(), "parquet");
    assert_eq!(AuditExportFormat::CompliancePdf.as_str(), "compliance_pdf");
}

#[test]
fn governance_hook_type_as_str_exact() {
    assert_eq!(GovernanceHookType::PreDeploy.as_str(), "pre_deploy");
    assert_eq!(GovernanceHookType::PostDeploy.as_str(), "post_deploy");
    assert_eq!(GovernanceHookType::PolicyChange.as_str(), "policy_change");
    assert_eq!(GovernanceHookType::AuditExport.as_str(), "audit_export");
    assert_eq!(
        GovernanceHookType::ComplianceCheck.as_str(),
        "compliance_check"
    );
}

#[test]
fn policy_source_as_str_exact() {
    assert_eq!(
        PolicySource::GitRepo {
            repo_url: "u".to_string(),
            commit_sha: "c".to_string(),
            file_path: "f".to_string(),
        }
        .as_str(),
        "git_repo"
    );
    assert_eq!(
        PolicySource::FileSystem {
            absolute_path: "/p".to_string(),
        }
        .as_str(),
        "filesystem"
    );
    assert_eq!(
        PolicySource::InlineToml {
            label: "t".to_string(),
        }
        .as_str(),
        "inline_toml"
    );
    assert_eq!(
        PolicySource::InlineJson {
            label: "j".to_string(),
        }
        .as_str(),
        "inline_json"
    );
}

#[test]
fn diagnostic_severity_as_str_exact() {
    assert_eq!(DiagnosticSeverity::Info.as_str(), "info");
    assert_eq!(DiagnosticSeverity::Warning.as_str(), "warning");
    assert_eq!(DiagnosticSeverity::Error.as_str(), "error");
}

// ---------------------------------------------------------------------------
// 18. Export payload format details
// ---------------------------------------------------------------------------

#[test]
fn export_csv_header_and_data_rows() {
    let entries = vec![make_evidence_entry("policy_update", 20)];
    let req = AuditExportRequest {
        format: AuditExportFormat::Csv,
        start_tick: ts(0),
        end_tick: ts(100),
        evidence_kinds: None,
        max_entries: None,
        requester: "t".to_string(),
        correlation_id: None,
    };
    let result = export_audit_evidence(req, entries, ts(200)).unwrap();
    let payload = String::from_utf8_lossy(&result.payload_bytes);
    let lines: Vec<&str> = payload.lines().collect();
    assert_eq!(
        lines[0], "entry_id,kind,timestamp,summary,evidence_hash",
        "CSV header mismatch"
    );
    assert!(lines.len() >= 2, "should have header + at least 1 data row");
    assert!(lines[1].contains("policy_update"));
}

#[test]
fn export_jsonlines_entries_are_json_objects() {
    let entries = vec![
        make_evidence_entry("policy_update", 20),
        make_evidence_entry("revocation", 60),
    ];
    let req = AuditExportRequest {
        format: AuditExportFormat::JsonLines,
        start_tick: ts(0),
        end_tick: ts(100),
        evidence_kinds: None,
        max_entries: None,
        requester: "t".to_string(),
        correlation_id: None,
    };
    let result = export_audit_evidence(req, entries, ts(200)).unwrap();
    let payload = String::from_utf8_lossy(&result.payload_bytes);
    let non_empty_lines: Vec<&str> = payload.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(non_empty_lines.len(), 2);
    for line in &non_empty_lines {
        assert!(line.starts_with('{'), "expected JSON object start");
        assert!(line.ends_with('}'), "expected JSON object end");
    }
}

#[test]
fn export_parquet_header_and_tab_delimited() {
    let entries = vec![make_evidence_entry("security_action", 30)];
    let req = AuditExportRequest {
        format: AuditExportFormat::Parquet,
        start_tick: ts(0),
        end_tick: ts(100),
        evidence_kinds: None,
        max_entries: None,
        requester: "t".to_string(),
        correlation_id: None,
    };
    let result = export_audit_evidence(req, entries, ts(200)).unwrap();
    let payload = String::from_utf8_lossy(&result.payload_bytes);
    let lines: Vec<&str> = payload.lines().collect();
    assert_eq!(lines[0], "FRANKEN_PARQUET_V1");
    assert!(
        lines[1].contains('\t'),
        "parquet records should be tab-delimited"
    );
}

#[test]
fn export_compliance_pdf_total_entries_line() {
    let entries = full_evidence_set();
    let req = AuditExportRequest {
        format: AuditExportFormat::CompliancePdf,
        start_tick: ts(0),
        end_tick: ts(100),
        evidence_kinds: None,
        max_entries: None,
        requester: "t".to_string(),
        correlation_id: None,
    };
    let result = export_audit_evidence(req, entries, ts(200)).unwrap();
    let payload = String::from_utf8_lossy(&result.payload_bytes);
    let lines: Vec<&str> = payload.lines().collect();
    assert_eq!(lines[0], "FRANKEN_COMPLIANCE_REPORT_V1");
    assert_eq!(lines[1], "total_entries: 6");
}

// ---------------------------------------------------------------------------
// 19. Pipeline with no frameworks on compliance check
// ---------------------------------------------------------------------------

#[test]
fn pipeline_compliance_check_no_frameworks_passes() {
    let config = GovernancePipelineConfig {
        hooks: vec![GovernanceHookType::ComplianceCheck],
        halt_on_failure: true,
        max_export_entries: 100,
        frameworks: vec![],
    };
    let mut pipeline = GovernancePipeline::new(config);
    let results =
        run_governance_pipeline(&mut pipeline, &[], full_evidence_set(), ts(200)).unwrap();
    assert!(results[0].passed, "no frameworks means nothing can fail");
}

// ---------------------------------------------------------------------------
// 20. Pipeline event propagation
// ---------------------------------------------------------------------------

#[test]
fn pipeline_events_track_all_hooks() {
    let artifact = extract_artifact(&compile_toml("evt_all", 1)).clone();
    let config = GovernancePipelineConfig {
        hooks: vec![
            GovernanceHookType::PreDeploy,
            GovernanceHookType::PostDeploy,
            GovernanceHookType::AuditExport,
        ],
        halt_on_failure: true,
        max_export_entries: 100,
        frameworks: vec![],
    };
    let mut pipeline = GovernancePipeline::new(config);
    run_governance_pipeline(
        &mut pipeline,
        std::slice::from_ref(&artifact),
        full_evidence_set(),
        ts(200),
    )
    .unwrap();
    assert_eq!(pipeline.events().len(), 3);
    assert_eq!(
        pipeline.events()[0].hook_type,
        GovernanceHookType::PreDeploy
    );
    assert_eq!(
        pipeline.events()[1].hook_type,
        GovernanceHookType::PostDeploy
    );
    assert_eq!(
        pipeline.events()[2].hook_type,
        GovernanceHookType::AuditExport
    );
    // All should have passed.
    for event in pipeline.events() {
        assert!(event.passed);
        assert!(!event.summary.is_empty());
    }
}

// ---------------------------------------------------------------------------
// 21. Validate policy specific constraint messages
// ---------------------------------------------------------------------------

#[test]
fn validate_empty_bytes_error_constraint_message() {
    let result = compile_toml("veb", 1);
    let mut artifact = extract_artifact(&result).clone();
    artifact.compiled_bytes.clear();
    let err = validate_policy(&artifact, None).unwrap_err();
    if let GovernanceError::PolicySchemaViolation { constraint } = &err {
        assert!(constraint.contains("compiled_bytes must be non-empty"));
    } else {
        panic!("expected PolicySchemaViolation, got: {err:?}");
    }
}

#[test]
fn validate_hash_mismatch_constraint_message() {
    let result = compile_toml("vhm", 1);
    let mut artifact = extract_artifact(&result).clone();
    artifact.compiled_bytes.push(0xFF);
    let err = validate_policy(&artifact, None).unwrap_err();
    if let GovernanceError::PolicySchemaViolation { constraint } = &err {
        assert!(constraint.contains("compiled_hash mismatch"));
    } else {
        panic!("expected PolicySchemaViolation, got: {err:?}");
    }
}

#[test]
fn validate_version_zero_constraint_message() {
    let result = compile_toml("vz", 1);
    let mut artifact = extract_artifact(&result).clone();
    artifact.version = 0;
    // Must recompute hash since we changed version (which is a field, not in hash).
    // Actually version is not in compiled_hash, so hash is still valid.
    let err = validate_policy(&artifact, None).unwrap_err();
    if let GovernanceError::PolicySchemaViolation { constraint } = &err {
        assert!(constraint.contains("version must be non-zero"));
    } else {
        panic!("expected PolicySchemaViolation, got: {err:?}");
    }
}

#[test]
fn validate_version_below_min_constraint_message() {
    let result = compile_toml("vbm", 3);
    let artifact = extract_artifact(&result);
    let err = validate_policy(artifact, Some(5)).unwrap_err();
    if let GovernanceError::PolicySchemaViolation { constraint } = &err {
        assert!(constraint.contains("below required minimum"));
        assert!(constraint.contains("3"));
        assert!(constraint.contains("5"));
    } else {
        panic!("expected PolicySchemaViolation, got: {err:?}");
    }
}

#[test]
fn validate_empty_name_constraint_message() {
    let result = compile_toml("ven", 1);
    let mut artifact = extract_artifact(&result).clone();
    artifact.policy_name = "   ".to_string();
    let err = validate_policy(&artifact, None).unwrap_err();
    if let GovernanceError::PolicySchemaViolation { constraint } = &err {
        assert!(constraint.contains("policy_name must be non-empty"));
    } else {
        panic!("expected PolicySchemaViolation, got: {err:?}");
    }
}

// ---------------------------------------------------------------------------
// 22. Export equal start/end tick
// ---------------------------------------------------------------------------

#[test]
fn export_equal_start_end_tick_succeeds() {
    let entries = vec![make_evidence_entry("policy_update", 50)];
    let req = AuditExportRequest {
        format: AuditExportFormat::JsonLines,
        start_tick: ts(50),
        end_tick: ts(50),
        evidence_kinds: None,
        max_entries: None,
        requester: "t".to_string(),
        correlation_id: None,
    };
    let result = export_audit_evidence(req, entries, ts(200)).unwrap();
    assert_eq!(result.entry_count, 1);
}

// ---------------------------------------------------------------------------
// 23. PolicySource Display exact format
// ---------------------------------------------------------------------------

#[test]
fn policy_source_display_inline_toml_exact() {
    let src = PolicySource::InlineToml {
        label: "my_label".to_string(),
    };
    assert_eq!(format!("{src}"), "inline_toml:my_label");
}

#[test]
fn policy_source_display_inline_json_exact() {
    let src = PolicySource::InlineJson {
        label: "json_label".to_string(),
    };
    assert_eq!(format!("{src}"), "inline_json:json_label");
}

#[test]
fn policy_source_display_filesystem_exact() {
    let src = PolicySource::FileSystem {
        absolute_path: "/etc/engine/policy.toml".to_string(),
    };
    assert_eq!(format!("{src}"), "filesystem:/etc/engine/policy.toml");
}

#[test]
fn policy_source_display_git_repo_truncates_sha() {
    let src = PolicySource::GitRepo {
        repo_url: "https://github.com/org/repo.git".to_string(),
        commit_sha: "abcdef0123456789abcdef0123456789abcdef01".to_string(),
        file_path: "policies/runtime.toml".to_string(),
    };
    let display = format!("{src}");
    assert_eq!(
        display,
        "git_repo:https://github.com/org/repo.git@abcdef01:policies/runtime.toml"
    );
}

// ---------------------------------------------------------------------------
// 24. Export with attributes in evidence entries
// ---------------------------------------------------------------------------

#[test]
fn export_jsonlines_includes_attributes() {
    let mut entry = make_evidence_entry("policy_update", 20);
    entry
        .attributes
        .insert("action".to_string(), "create".to_string());
    let req = AuditExportRequest {
        format: AuditExportFormat::JsonLines,
        start_tick: ts(0),
        end_tick: ts(100),
        evidence_kinds: None,
        max_entries: None,
        requester: "t".to_string(),
        correlation_id: None,
    };
    let result = export_audit_evidence(req, vec![entry], ts(200)).unwrap();
    let payload = String::from_utf8_lossy(&result.payload_bytes);
    assert!(payload.contains("action"), "attributes should appear");
    assert!(payload.contains("create"), "attribute value should appear");
}

// ---------------------------------------------------------------------------
// 25. Compliance bundle with empty window
// ---------------------------------------------------------------------------

#[test]
fn compliance_bundle_equal_window_tick() {
    let entries = vec![make_evidence_entry("policy_update", 50)];
    let (bundle, _) =
        generate_compliance_bundle(ComplianceFramework::Soc2, ts(50), ts(50), entries, ts(200))
            .unwrap();
    assert_eq!(bundle.entry_count(), 1);
}
