//! Integration tests for the conformance harness module.
//!
//! These tests exercise the full conformance pipeline end-to-end, including:
//! - Full runner pipeline with on-disk fixtures
//! - Evidence collection to temporary directories
//! - Delta classification across all failure classes
//! - Minimization preservation
//! - Waiver TOML parsing and active-waiver filtering
//! - CI gate enforcement (pass/fail)
//! - IFC-specific conformance flows (benign, exfil, declassify)
//! - Serde round-trips for all public types
//! - Replay verification contracts

#![allow(clippy::too_many_lines)]
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

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use frankenengine_engine::conformance_harness::{
    ConformanceAssetManifest, ConformanceAssetRecord, ConformanceCiGateError,
    ConformanceDeltaClassification, ConformanceDeltaKind, ConformanceEvidenceCollector,
    ConformanceFailureClass, ConformanceFailureSeverity, ConformanceIssueLink, ConformanceLogEvent,
    ConformanceMinimizationSummary, ConformanceMinimizedFailingVector,
    ConformanceMinimizedReproArtifact, ConformanceReplayContract, ConformanceReproEnvironment,
    ConformanceReproMetadata, ConformanceRunLinkage, ConformanceRunResult, ConformanceRunSummary,
    ConformanceRunner, ConformanceRunnerConfig, ConformanceWaiver, ConformanceWaiverSet,
    DeterministicRng, DonorFixture, DonorHarnessAdapter, DonorHarnessApi, WaiverReasonCode,
    canonicalize_conformance_output, classify_conformance_delta, classify_failure_class,
    severity_for_failure_class,
};

// ─── Helpers ───────────────────────────────────────────────────────────────

fn temp_dir(label: &str) -> PathBuf {
    let id = std::process::id();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("conformance_harness_integ_{label}_{id}_{ts}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(data);
    hex::encode(hash)
}

fn make_fixture_json(source: &str, observed_output: &str) -> String {
    serde_json::to_string(&serde_json::json!({
        "donor_harness": "test262",
        "source": source,
        "observed_output": observed_output
    }))
    .unwrap()
}

fn make_manifest(assets: Vec<ConformanceAssetRecord>) -> ConformanceAssetManifest {
    ConformanceAssetManifest {
        schema_version: ConformanceAssetManifest::CURRENT_SCHEMA.to_string(),
        generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
        assets,
    }
}

fn make_asset_record(
    id: &str,
    fixture_path: &str,
    fixture_hash: &str,
    expected_output_path: &str,
    expected_output_hash: &str,
) -> ConformanceAssetRecord {
    ConformanceAssetRecord {
        asset_id: id.to_string(),
        source_donor: "test262".to_string(),
        semantic_domain: "expressions".to_string(),
        normative_reference: "ECMA-262 12.5".to_string(),
        fixture_path: fixture_path.to_string(),
        fixture_hash: fixture_hash.to_string(),
        expected_output_path: expected_output_path.to_string(),
        expected_output_hash: expected_output_hash.to_string(),
        import_date: "2026-01-01".to_string(),
        category: None,
        source_labels: Vec::new(),
        sink_clearances: Vec::new(),
        flow_path_type: None,
        expected_outcome: None,
        expected_evidence_type: None,
    }
}

struct IfcAssetInput<'a> {
    id: &'a str,
    fixture_path: &'a str,
    fixture_hash: &'a str,
    expected_output_path: &'a str,
    expected_output_hash: &'a str,
    category: &'a str,
    source_labels: Vec<&'a str>,
    sink_clearances: Vec<&'a str>,
    flow_path_type: &'a str,
    expected_outcome: &'a str,
    expected_evidence_type: &'a str,
}

fn make_ifc_asset_record(input: &IfcAssetInput<'_>) -> ConformanceAssetRecord {
    ConformanceAssetRecord {
        asset_id: input.id.to_string(),
        source_donor: "ifc-corpus".to_string(),
        semantic_domain: "ifc_corpus/basic".to_string(),
        normative_reference: "FrankenEngine IFC Policy v1".to_string(),
        fixture_path: input.fixture_path.to_string(),
        fixture_hash: input.fixture_hash.to_string(),
        expected_output_path: input.expected_output_path.to_string(),
        expected_output_hash: input.expected_output_hash.to_string(),
        import_date: "2026-01-01".to_string(),
        category: Some(input.category.to_string()),
        source_labels: input
            .source_labels
            .iter()
            .map(ToString::to_string)
            .collect(),
        sink_clearances: input
            .sink_clearances
            .iter()
            .map(ToString::to_string)
            .collect(),
        flow_path_type: Some(input.flow_path_type.to_string()),
        expected_outcome: Some(input.expected_outcome.to_string()),
        expected_evidence_type: Some(input.expected_evidence_type.to_string()),
    }
}

/// Write a fixture JSON file and expected output file, returning (fixture_hash, expected_hash).
fn write_fixture_pair(
    dir: &std::path::Path,
    fixture_name: &str,
    expected_name: &str,
    source: &str,
    observed_output: &str,
    expected_output: &str,
) -> (String, String) {
    let fixture_content = make_fixture_json(source, observed_output);
    let fixture_path = dir.join(fixture_name);
    fs::write(&fixture_path, &fixture_content).unwrap();
    let fixture_hash = sha256_hex(fixture_content.as_bytes());

    let expected_path = dir.join(expected_name);
    fs::write(&expected_path, expected_output).unwrap();
    let expected_hash = sha256_hex(expected_output.as_bytes());

    (fixture_hash, expected_hash)
}

// ─── Section 1: DeterministicRng ───────────────────────────────────────────

#[test]
fn rng_seeded_produces_deterministic_sequence() {
    let mut rng1 = DeterministicRng::seeded(42);
    let mut rng2 = DeterministicRng::seeded(42);
    let seq1: Vec<u64> = (0..100).map(|_| rng1.next_u64()).collect();
    let seq2: Vec<u64> = (0..100).map(|_| rng2.next_u64()).collect();
    assert_eq!(seq1, seq2, "same seed must produce same sequence");
}

#[test]
fn rng_different_seeds_differ() {
    let mut rng1 = DeterministicRng::seeded(1);
    let mut rng2 = DeterministicRng::seeded(2);
    let v1 = rng1.next_u64();
    let v2 = rng2.next_u64();
    assert_ne!(v1, v2, "different seeds should produce different values");
}

#[test]
fn rng_zero_seed_uses_default_state() {
    let mut rng = DeterministicRng::seeded(0);
    let v = rng.next_u64();
    assert_ne!(v, 0, "zero seed should use non-zero default state");
}

#[test]
fn rng_serde_round_trip() {
    let rng = DeterministicRng::seeded(77);
    let json = serde_json::to_string(&rng).unwrap();
    let restored: DeterministicRng = serde_json::from_str(&json).unwrap();
    assert_eq!(rng, restored);
}

// ─── Section 2: Output Canonicalization ────────────────────────────────────

#[test]
fn canonicalize_trims_empty_lines() {
    let raw = "\n  hello  \n\n  world  \n\n";
    let canonical = canonicalize_conformance_output(raw);
    assert_eq!(canonical, "hello\nworld");
}

#[test]
fn canonicalize_normalizes_crlf() {
    let raw = "line1\r\nline2\rline3";
    let canonical = canonicalize_conformance_output(raw);
    assert_eq!(canonical, "line1\nline2\nline3");
}

#[test]
fn canonicalize_sorts_props() {
    let raw = "props: z, a, m, b";
    let canonical = canonicalize_conformance_output(raw);
    assert_eq!(canonical, "props:a,b,m,z");
}

#[test]
fn canonicalize_sorts_but_preserves_duplicate_props() {
    // canonicalize_conformance_output sorts but does not dedup on the output path;
    // dedup happens inside parse_props_fields (used by delta classification)
    let raw = "props: a, b, a, c, b";
    let canonical = canonicalize_conformance_output(raw);
    assert_eq!(canonical, "props:a,a,b,b,c");
}

#[test]
fn canonicalize_normalizes_error_format() {
    let raw = "TypeError: cannot read property";
    let canonical = canonicalize_conformance_output(raw);
    assert!(
        canonical.contains("TypeError|"),
        "should normalize error separator: {canonical}"
    );
}

#[test]
fn canonicalize_normalizes_floats_to_six_decimals() {
    let raw = "result 3.14 more 2.7";
    let canonical = canonicalize_conformance_output(raw);
    assert_eq!(canonical, "result 3.140000 more 2.700000");
}

#[test]
fn canonicalize_preserves_non_numeric_tokens() {
    let raw = "hello world foo";
    let canonical = canonicalize_conformance_output(raw);
    assert_eq!(canonical, "hello world foo");
}

// ─── Section 3: Delta Classification ───────────────────────────────────────

#[test]
fn delta_classification_identical_returns_empty() {
    let deltas = classify_conformance_delta("hello\nworld", "hello\nworld");
    assert!(
        deltas.is_empty(),
        "identical outputs should produce no deltas"
    );
}

#[test]
fn delta_classification_schema_field_removed() {
    let expected = "props: a, b, c";
    let actual = "props: a, c";
    let deltas = classify_conformance_delta(expected, actual);
    assert!(!deltas.is_empty());
    assert!(
        deltas
            .iter()
            .any(|d| d.kind == ConformanceDeltaKind::SchemaFieldRemoved),
        "should detect removed field: {deltas:?}"
    );
}

#[test]
fn delta_classification_schema_field_added() {
    let expected = "props: a, b";
    let actual = "props: a, b, c";
    let deltas = classify_conformance_delta(expected, actual);
    assert!(!deltas.is_empty());
    assert!(
        deltas
            .iter()
            .any(|d| d.kind == ConformanceDeltaKind::SchemaFieldAdded),
        "should detect added field: {deltas:?}"
    );
}

#[test]
fn delta_classification_schema_field_modified() {
    // Same fields but different values in the overall structure
    let expected = "props: a, b";
    let actual = "props: c, d";
    let deltas = classify_conformance_delta(expected, actual);
    assert!(!deltas.is_empty());
    // Could be add+remove or modified
    let has_schema_delta = deltas.iter().any(|d| {
        matches!(
            d.kind,
            ConformanceDeltaKind::SchemaFieldRemoved
                | ConformanceDeltaKind::SchemaFieldAdded
                | ConformanceDeltaKind::SchemaFieldModified
        )
    });
    assert!(has_schema_delta, "should detect schema changes: {deltas:?}");
}

#[test]
fn delta_classification_error_format_change() {
    let expected = "TypeError: old message";
    let actual = "ReferenceError: new message";
    let deltas = classify_conformance_delta(expected, actual);
    assert!(!deltas.is_empty());
    assert!(
        deltas
            .iter()
            .any(|d| d.kind == ConformanceDeltaKind::ErrorFormatChange),
        "should detect error format change: {deltas:?}"
    );
}

#[test]
fn delta_classification_timing_change() {
    let expected = "latency 100 ms";
    let actual = "latency 200 ms";
    let deltas = classify_conformance_delta(expected, actual);
    assert!(!deltas.is_empty());
    assert!(
        deltas
            .iter()
            .any(|d| d.kind == ConformanceDeltaKind::TimingChange),
        "should detect timing change: {deltas:?}"
    );
}

#[test]
fn delta_classification_behavioral_semantic_shift() {
    let expected = "output: true";
    let actual = "output: false";
    let deltas = classify_conformance_delta(expected, actual);
    assert!(!deltas.is_empty());
    assert!(
        deltas
            .iter()
            .any(|d| d.kind == ConformanceDeltaKind::BehavioralSemanticShift),
        "should detect behavioral shift: {deltas:?}"
    );
}

// ─── Section 4: Failure Classification ─────────────────────────────────────

#[test]
fn failure_class_empty_deltas_returns_behavioral() {
    let class = classify_failure_class(&[]);
    assert_eq!(class, ConformanceFailureClass::Behavioral);
}

#[test]
fn failure_class_schema_removed_is_breaking() {
    let deltas = vec![ConformanceDeltaClassification {
        kind: ConformanceDeltaKind::SchemaFieldRemoved,
        field: Some("x".to_string()),
        expected: Some("present".to_string()),
        actual: Some("missing".to_string()),
        detail: "test".to_string(),
    }];
    assert_eq!(
        classify_failure_class(&deltas),
        ConformanceFailureClass::Breaking
    );
}

#[test]
fn failure_class_timing_is_performance() {
    let deltas = vec![ConformanceDeltaClassification {
        kind: ConformanceDeltaKind::TimingChange,
        field: None,
        expected: Some("100".to_string()),
        actual: Some("200".to_string()),
        detail: "test".to_string(),
    }];
    assert_eq!(
        classify_failure_class(&deltas),
        ConformanceFailureClass::Performance
    );
}

#[test]
fn failure_class_error_format_is_observability() {
    let deltas = vec![ConformanceDeltaClassification {
        kind: ConformanceDeltaKind::ErrorFormatChange,
        field: None,
        expected: None,
        actual: None,
        detail: "test".to_string(),
    }];
    assert_eq!(
        classify_failure_class(&deltas),
        ConformanceFailureClass::Observability
    );
}

#[test]
fn failure_class_multiple_deltas_uses_highest_priority() {
    let deltas = vec![
        ConformanceDeltaClassification {
            kind: ConformanceDeltaKind::TimingChange,
            field: None,
            expected: None,
            actual: None,
            detail: "perf".to_string(),
        },
        ConformanceDeltaClassification {
            kind: ConformanceDeltaKind::SchemaFieldRemoved,
            field: Some("x".to_string()),
            expected: None,
            actual: None,
            detail: "breaking".to_string(),
        },
    ];
    assert_eq!(
        classify_failure_class(&deltas),
        ConformanceFailureClass::Breaking,
        "breaking should dominate timing"
    );
}

// ─── Section 5: Severity Mapping ───────────────────────────────────────────

#[test]
fn severity_breaking_is_critical() {
    assert_eq!(
        severity_for_failure_class(ConformanceFailureClass::Breaking),
        ConformanceFailureSeverity::Critical
    );
}

#[test]
fn severity_behavioral_is_error() {
    assert_eq!(
        severity_for_failure_class(ConformanceFailureClass::Behavioral),
        ConformanceFailureSeverity::Error
    );
}

#[test]
fn severity_observability_is_warning() {
    assert_eq!(
        severity_for_failure_class(ConformanceFailureClass::Observability),
        ConformanceFailureSeverity::Warning
    );
}

#[test]
fn severity_performance_is_warning() {
    assert_eq!(
        severity_for_failure_class(ConformanceFailureClass::Performance),
        ConformanceFailureSeverity::Warning
    );
}

// ─── Section 6: WaiverReasonCode ───────────────────────────────────────────

#[test]
fn waiver_reason_code_serde_round_trip() {
    for code in [
        WaiverReasonCode::HarnessGap,
        WaiverReasonCode::HostHookMissing,
        WaiverReasonCode::IntentionalDivergence,
        WaiverReasonCode::NotYetImplemented,
    ] {
        let json = serde_json::to_string(&code).unwrap();
        let restored: WaiverReasonCode = serde_json::from_str(&json).unwrap();
        assert_eq!(code, restored, "round-trip failed for {code:?}");
    }
}

// ─── Section 7: ConformanceWaiver serde ────────────────────────────────────

#[test]
fn conformance_waiver_serde_round_trip() {
    let waiver = ConformanceWaiver {
        asset_id: "test-001".to_string(),
        reason_code: WaiverReasonCode::HarnessGap,
        tracking_bead: "bd-abc".to_string(),
        expiry_date: "2026-12-31".to_string(),
    };
    let json = serde_json::to_string(&waiver).unwrap();
    let restored: ConformanceWaiver = serde_json::from_str(&json).unwrap();
    assert_eq!(waiver, restored);
}

// ─── Section 8: ConformanceWaiverSet TOML parsing ──────────────────────────

#[test]
fn waiver_set_load_nonexistent_returns_empty() {
    let set = ConformanceWaiverSet::load_toml("/nonexistent/path/waivers.toml").unwrap();
    assert!(set.waivers.is_empty());
}

#[test]
fn waiver_set_load_toml_single_waiver() {
    let dir = temp_dir("waiver_single");
    let path = dir.join("waivers.toml");
    fs::write(
        &path,
        r#"
[[waiver]]
asset_id = "test-001"
reason_code = "harness_gap"
tracking_bead = "bd-abc"
expiry_date = "2026-12-31"
"#,
    )
    .unwrap();

    let set = ConformanceWaiverSet::load_toml(&path).unwrap();
    assert_eq!(set.waivers.len(), 1);
    assert_eq!(set.waivers[0].asset_id, "test-001");
    assert_eq!(set.waivers[0].reason_code, WaiverReasonCode::HarnessGap);
}

#[test]
fn waiver_set_load_toml_multiple_waivers() {
    let dir = temp_dir("waiver_multi");
    let path = dir.join("waivers.toml");
    fs::write(
        &path,
        r#"
[[waiver]]
asset_id = "test-001"
reason_code = "harness_gap"
tracking_bead = "bd-abc"
expiry_date = "2026-12-31"

[[waiver]]
asset_id = "test-002"
reason_code = "not_yet_implemented"
tracking_bead = "bd-def"
expiry_date = "2026-06-30"
"#,
    )
    .unwrap();

    let set = ConformanceWaiverSet::load_toml(&path).unwrap();
    assert_eq!(set.waivers.len(), 2);
    assert_eq!(
        set.waivers[1].reason_code,
        WaiverReasonCode::NotYetImplemented
    );
}

// ─── Section 9: ConformanceRunnerConfig validation ─────────────────────────

#[test]
fn runner_config_default_is_valid() {
    let config = ConformanceRunnerConfig::default();
    let runner = ConformanceRunner {
        config,
        adapter: DonorHarnessAdapter,
    };
    // Config should pass validation (will fail on manifest load, not config validation)
    // We test config validation indirectly through the runner
    assert!(!runner.config.trace_prefix.is_empty());
    assert!(!runner.config.policy_id.is_empty());
    assert_eq!(runner.config.locale, "C");
    assert_eq!(runner.config.timezone, "UTC");
    assert_eq!(runner.config.gc_schedule, "deterministic");
}

// ─── Section 10: DonorHarnessAdapter ───────────────────────────────────────

#[test]
fn donor_adapter_transforms_test262_builtins() {
    let adapter = DonorHarnessAdapter;
    let source = "$262.createRealm(); $DONE; print(x);";
    let adapted = adapter.adapt_source(source);
    assert!(adapted.contains("__franken_create_realm()"));
    assert!(adapted.contains("__franken_done"));
    assert!(adapted.contains("franken_print(x)"));
    assert!(!adapted.contains("$262"));
    assert!(!adapted.contains("$DONE"));
}

#[test]
fn donor_adapter_preserves_normal_code() {
    let adapter = DonorHarnessAdapter;
    let source = "let x = 1 + 2;";
    let adapted = adapter.adapt_source(source);
    assert_eq!(adapted, source);
}

// ─── Section 11: Full Runner Pipeline (on-disk fixtures) ───────────────────

#[test]
fn runner_full_pass_scenario() {
    let dir = temp_dir("runner_pass");

    // Create a passing fixture: observed output matches expected
    let source = "let x = 1 + 2;";
    let output = "result: 3";
    let (fixture_hash, expected_hash) =
        write_fixture_pair(&dir, "fixture.json", "expected.txt", source, output, output);

    let manifest = make_manifest(vec![make_asset_record(
        "pass-001",
        "fixture.json",
        &fixture_hash,
        "expected.txt",
        &expected_hash,
    )]);

    let manifest_path = dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();

    let runner = ConformanceRunner::default();
    let waivers = ConformanceWaiverSet::default();
    let result = runner.run(&manifest_path, &waivers).unwrap();

    assert_eq!(result.summary.total_assets, 1);
    assert_eq!(result.summary.passed, 1);
    assert_eq!(result.summary.failed, 0);
    assert_eq!(result.summary.waived, 0);
    assert_eq!(result.summary.errored, 0);
    assert!(result.minimized_repros.is_empty());
    assert!(result.enforce_ci_gate().is_ok());
}

#[test]
fn runner_full_fail_scenario_produces_repro() {
    let dir = temp_dir("runner_fail");

    // Create a failing fixture: observed output differs from expected
    let source = "let x = 1 + 2;";
    let observed = "result: 4";
    let expected = "result: 3";
    let (fixture_hash, expected_hash) = write_fixture_pair(
        &dir,
        "fixture.json",
        "expected.txt",
        source,
        observed,
        expected,
    );

    let manifest = make_manifest(vec![make_asset_record(
        "fail-001",
        "fixture.json",
        &fixture_hash,
        "expected.txt",
        &expected_hash,
    )]);

    let manifest_path = dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();

    let runner = ConformanceRunner::default();
    let waivers = ConformanceWaiverSet::default();
    let result = runner.run(&manifest_path, &waivers).unwrap();

    assert_eq!(result.summary.total_assets, 1);
    assert_eq!(result.summary.passed, 0);
    assert_eq!(result.summary.failed, 1);
    assert_eq!(result.minimized_repros.len(), 1);

    // Verify CI gate fails
    let gate_err = result.enforce_ci_gate().unwrap_err();
    assert_eq!(gate_err.failed, 1);
    assert_eq!(gate_err.errored, 0);
}

#[test]
fn runner_waived_asset_does_not_fail() {
    let dir = temp_dir("runner_waive");

    let source = "let x = 1 + 2;";
    let observed = "result: 4";
    let expected = "result: 3";
    let (fixture_hash, expected_hash) = write_fixture_pair(
        &dir,
        "fixture.json",
        "expected.txt",
        source,
        observed,
        expected,
    );

    let manifest = make_manifest(vec![make_asset_record(
        "waive-001",
        "fixture.json",
        &fixture_hash,
        "expected.txt",
        &expected_hash,
    )]);

    let manifest_path = dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();

    // Create a waiver that covers this asset
    let waivers = ConformanceWaiverSet {
        waivers: vec![ConformanceWaiver {
            asset_id: "waive-001".to_string(),
            reason_code: WaiverReasonCode::HarnessGap,
            tracking_bead: "bd-test".to_string(),
            expiry_date: "2099-12-31".to_string(),
        }],
    };

    let runner = ConformanceRunner::default();
    let result = runner.run(&manifest_path, &waivers).unwrap();

    assert_eq!(result.summary.total_assets, 1);
    assert_eq!(result.summary.passed, 0);
    assert_eq!(result.summary.failed, 0);
    assert_eq!(result.summary.waived, 1);
    assert!(result.minimized_repros.is_empty());
    assert!(result.enforce_ci_gate().is_ok());
}

#[test]
fn runner_expired_waiver_still_fails() {
    let dir = temp_dir("runner_expired_waiver");

    let source = "let x = 1;";
    let observed = "result: 2";
    let expected = "result: 1";
    let (fixture_hash, expected_hash) = write_fixture_pair(
        &dir,
        "fixture.json",
        "expected.txt",
        source,
        observed,
        expected,
    );

    let manifest = make_manifest(vec![make_asset_record(
        "expired-001",
        "fixture.json",
        &fixture_hash,
        "expected.txt",
        &expected_hash,
    )]);

    let manifest_path = dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();

    // Waiver expired before the run_date
    let waivers = ConformanceWaiverSet {
        waivers: vec![ConformanceWaiver {
            asset_id: "expired-001".to_string(),
            reason_code: WaiverReasonCode::NotYetImplemented,
            tracking_bead: "bd-expired".to_string(),
            expiry_date: "1960-01-01".to_string(), // Expired before default run_date
        }],
    };

    let runner = ConformanceRunner::default();
    let result = runner.run(&manifest_path, &waivers).unwrap();

    assert_eq!(
        result.summary.failed, 1,
        "expired waiver should not prevent failure"
    );
    assert_eq!(result.summary.waived, 0);
}

#[test]
fn runner_multiple_assets_mixed_results() {
    let dir = temp_dir("runner_mixed");

    // Asset 1: passes
    let (fh1, eh1) = write_fixture_pair(
        &dir,
        "fix1.json",
        "exp1.txt",
        "x=1",
        "result: 1",
        "result: 1",
    );
    // Asset 2: fails
    let (fh2, eh2) = write_fixture_pair(
        &dir,
        "fix2.json",
        "exp2.txt",
        "x=2",
        "result: 99",
        "result: 2",
    );
    // Asset 3: passes
    let (fh3, eh3) = write_fixture_pair(
        &dir,
        "fix3.json",
        "exp3.txt",
        "x=3",
        "result: 3",
        "result: 3",
    );

    let manifest = make_manifest(vec![
        make_asset_record("mix-001", "fix1.json", &fh1, "exp1.txt", &eh1),
        make_asset_record("mix-002", "fix2.json", &fh2, "exp2.txt", &eh2),
        make_asset_record("mix-003", "fix3.json", &fh3, "exp3.txt", &eh3),
    ]);

    let manifest_path = dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();

    let runner = ConformanceRunner::default();
    let waivers = ConformanceWaiverSet::default();
    let result = runner.run(&manifest_path, &waivers).unwrap();

    assert_eq!(result.summary.total_assets, 3);
    assert_eq!(result.summary.passed, 2);
    assert_eq!(result.summary.failed, 1);
    assert_eq!(result.minimized_repros.len(), 1);
    assert!(result.enforce_ci_gate().is_err());
}

// ─── Section 12: Runner Determinism ────────────────────────────────────────

#[test]
fn runner_same_seed_produces_same_run_id() {
    let dir = temp_dir("runner_determinism");
    let (fh, eh) = write_fixture_pair(&dir, "fix.json", "exp.txt", "x=1", "r:1", "r:1");
    let manifest = make_manifest(vec![make_asset_record(
        "det-001", "fix.json", &fh, "exp.txt", &eh,
    )]);
    let manifest_path = dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();

    let runner = ConformanceRunner::default();
    let waivers = ConformanceWaiverSet::default();
    let r1 = runner.run(&manifest_path, &waivers).unwrap();
    let r2 = runner.run(&manifest_path, &waivers).unwrap();

    assert_eq!(
        r1.run_id, r2.run_id,
        "same config+manifest should produce same run_id"
    );
    assert_eq!(
        r1.asset_manifest_hash, r2.asset_manifest_hash,
        "manifest hash should be deterministic"
    );
}

// ─── Section 13: Evidence Collector ────────────────────────────────────────

#[test]
fn evidence_collector_creates_run_manifest() {
    let dir = temp_dir("collector_pass");
    let fixture_dir = temp_dir("collector_pass_fixtures");
    let (fh, eh) = write_fixture_pair(&fixture_dir, "fix.json", "exp.txt", "x=1", "r:1", "r:1");
    let manifest = make_manifest(vec![make_asset_record(
        "coll-001", "fix.json", &fh, "exp.txt", &eh,
    )]);
    let manifest_path = fixture_dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();

    let runner = ConformanceRunner::default();
    let waivers = ConformanceWaiverSet::default();
    let result = runner.run(&manifest_path, &waivers).unwrap();

    let collector = ConformanceEvidenceCollector::new(&dir).unwrap();
    let artifacts = collector.collect(&result).unwrap();

    assert!(
        artifacts.run_manifest_path.exists(),
        "run manifest should be written"
    );
    assert!(
        artifacts.conformance_evidence_path.exists(),
        "conformance evidence JSONL should be written"
    );
}

#[test]
fn evidence_collector_creates_minimized_repros_for_failures() {
    let dir = temp_dir("collector_fail");
    let fixture_dir = temp_dir("collector_fail_fixtures");
    let (fh, eh) = write_fixture_pair(&fixture_dir, "fix.json", "exp.txt", "x=1", "r:2", "r:1");
    let manifest = make_manifest(vec![make_asset_record(
        "coll-fail-001",
        "fix.json",
        &fh,
        "exp.txt",
        &eh,
    )]);
    let manifest_path = fixture_dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();

    let runner = ConformanceRunner::default();
    let waivers = ConformanceWaiverSet::default();
    let result = runner.run(&manifest_path, &waivers).unwrap();

    let collector = ConformanceEvidenceCollector::new(&dir).unwrap();
    let artifacts = collector.collect(&result).unwrap();

    assert!(
        !artifacts.minimized_repro_paths.is_empty(),
        "should have repro artifacts"
    );
    assert!(
        artifacts.minimized_repro_index_path.is_some(),
        "should have repro index"
    );
    assert!(
        artifacts.minimized_repro_events_path.is_some(),
        "should have repro events"
    );

    // Verify index file is valid JSON
    let index_path = artifacts.minimized_repro_index_path.unwrap();
    let index_bytes = fs::read(&index_path).unwrap();
    let _: serde_json::Value = serde_json::from_slice(&index_bytes).unwrap();
}

// ─── Section 14: IFC Conformance Flows ─────────────────────────────────────

#[test]
fn ifc_benign_category_passes_when_output_matches() {
    let dir = temp_dir("ifc_benign");
    let output = "outcome:allow evidence:none";
    let (fh, eh) = write_fixture_pair(&dir, "fix.json", "exp.txt", "safe code", output, output);

    let manifest = make_manifest(vec![make_ifc_asset_record(&IfcAssetInput {
        id: "ifc-benign-001",
        fixture_path: "fix.json",
        fixture_hash: &fh,
        expected_output_path: "exp.txt",
        expected_output_hash: &eh,
        category: "benign",
        source_labels: vec!["credential"],
        sink_clearances: vec!["network_egress"],
        flow_path_type: "direct",
        expected_outcome: "allow",
        expected_evidence_type: "none",
    })]);

    let manifest_path = dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();

    let runner = ConformanceRunner::default();
    let waivers = ConformanceWaiverSet::default();
    let result = runner.run(&manifest_path, &waivers).unwrap();

    assert_eq!(result.summary.passed, 1);
    assert_eq!(result.summary.failed, 0);
    // Verify IFC metadata was captured in logs
    assert!(result.logs[0].category.as_deref() == Some("benign"));
}

#[test]
fn ifc_exfil_category_passes_when_output_matches() {
    let dir = temp_dir("ifc_exfil");
    let output = "outcome:block evidence:flow_violation";
    let (fh, eh) = write_fixture_pair(&dir, "fix.json", "exp.txt", "evil code", output, output);

    let manifest = make_manifest(vec![make_ifc_asset_record(&IfcAssetInput {
        id: "ifc-exfil-001",
        fixture_path: "fix.json",
        fixture_hash: &fh,
        expected_output_path: "exp.txt",
        expected_output_hash: &eh,
        category: "exfil",
        source_labels: vec!["key_material"],
        sink_clearances: vec!["subprocess_ipc"],
        flow_path_type: "indirect",
        expected_outcome: "block",
        expected_evidence_type: "flow_violation",
    })]);

    let manifest_path = dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();

    let runner = ConformanceRunner::default();
    let waivers = ConformanceWaiverSet::default();
    let result = runner.run(&manifest_path, &waivers).unwrap();

    assert_eq!(result.summary.passed, 1);
    assert_eq!(result.summary.failed, 0);
    assert!(result.logs[0].category.as_deref() == Some("exfil"));
    assert!(result.logs[0].expected_outcome.as_deref() == Some("block"));
}

#[test]
fn ifc_declassify_category_passes_when_output_matches() {
    let dir = temp_dir("ifc_declassify");
    let output = "outcome:declassify evidence:declassification_receipt";
    let (fh, eh) = write_fixture_pair(
        &dir,
        "fix.json",
        "exp.txt",
        "declassify code",
        output,
        output,
    );

    let manifest = make_manifest(vec![make_ifc_asset_record(&IfcAssetInput {
        id: "ifc-decl-001",
        fixture_path: "fix.json",
        fixture_hash: &fh,
        expected_output_path: "exp.txt",
        expected_output_hash: &eh,
        category: "declassify",
        source_labels: vec!["policy_protected"],
        sink_clearances: vec!["explicit_declassify"],
        flow_path_type: "direct",
        expected_outcome: "declassify",
        expected_evidence_type: "declassification_receipt",
    })]);

    let manifest_path = dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();

    let runner = ConformanceRunner::default();
    let waivers = ConformanceWaiverSet::default();
    let result = runner.run(&manifest_path, &waivers).unwrap();

    assert_eq!(result.summary.passed, 1);
}

// ─── Section 15: CI Gate Error Display ─────────────────────────────────────

#[test]
fn ci_gate_error_display_format() {
    let err = ConformanceCiGateError {
        failed: 3,
        errored: 1,
    };
    let msg = format!("{err}");
    assert!(msg.contains("failed=3"));
    assert!(msg.contains("errored=1"));
}

#[test]
fn ci_gate_error_is_std_error() {
    let err = ConformanceCiGateError {
        failed: 1,
        errored: 0,
    };
    let _: &dyn std::error::Error = &err;
}

// ─── Section 16: ConformanceRunResult CI Gate ──────────────────────────────

#[test]
fn run_result_ci_gate_passes_on_zero_failures() {
    let result = ConformanceRunResult {
        run_id: "test-run".to_string(),
        asset_manifest_hash: "abc".to_string(),
        logs: Vec::new(),
        summary: ConformanceRunSummary {
            run_id: "test-run".to_string(),
            asset_manifest_hash: "abc".to_string(),
            total_assets: 5,
            passed: 4,
            failed: 0,
            waived: 1,
            errored: 0,
            env_fingerprint: "fp".to_string(),
        },
        minimized_repros: Vec::new(),
    };
    assert!(result.enforce_ci_gate().is_ok());
}

#[test]
fn run_result_ci_gate_fails_on_errors() {
    let result = ConformanceRunResult {
        run_id: "test-run".to_string(),
        asset_manifest_hash: "abc".to_string(),
        logs: Vec::new(),
        summary: ConformanceRunSummary {
            run_id: "test-run".to_string(),
            asset_manifest_hash: "abc".to_string(),
            total_assets: 5,
            passed: 4,
            failed: 0,
            waived: 0,
            errored: 1,
            env_fingerprint: "fp".to_string(),
        },
        minimized_repros: Vec::new(),
    };
    assert!(result.enforce_ci_gate().is_err());
}

// ─── Section 17: Serde Round-Trips ─────────────────────────────────────────

#[test]
fn conformance_asset_manifest_serde_round_trip() {
    let manifest = make_manifest(vec![ConformanceAssetRecord {
        asset_id: "serde-001".to_string(),
        source_donor: "test262".to_string(),
        semantic_domain: "expressions".to_string(),
        normative_reference: "ECMA-262".to_string(),
        fixture_path: "fix.json".to_string(),
        fixture_hash: "abc".to_string(),
        expected_output_path: "exp.txt".to_string(),
        expected_output_hash: "def".to_string(),
        import_date: "2026-01-01".to_string(),
        category: None,
        source_labels: Vec::new(),
        sink_clearances: Vec::new(),
        flow_path_type: None,
        expected_outcome: None,
        expected_evidence_type: None,
    }]);
    let json = serde_json::to_string(&manifest).unwrap();
    let restored: ConformanceAssetManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, restored);
}

#[test]
fn conformance_log_event_serde_round_trip() {
    let event = ConformanceLogEvent {
        trace_id: "tr-001".to_string(),
        decision_id: "dec-001".to_string(),
        policy_id: "pol-001".to_string(),
        component: "runner".to_string(),
        event: "exec".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        asset_id: "asset-001".to_string(),
        workload_id: "wl-001".to_string(),
        semantic_domain: "expressions".to_string(),
        category: Some("benign".to_string()),
        source_labels: vec!["credential".to_string()],
        sink_clearances: vec!["network_egress".to_string()],
        flow_path_type: Some("direct".to_string()),
        expected_outcome: Some("allow".to_string()),
        actual_outcome: Some("allow".to_string()),
        evidence_type: Some("none".to_string()),
        evidence_id: None,
        duration_us: 42,
        error_detail: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: ConformanceLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn conformance_run_summary_serde_round_trip() {
    let summary = ConformanceRunSummary {
        run_id: "run-001".to_string(),
        asset_manifest_hash: "hash-abc".to_string(),
        total_assets: 10,
        passed: 7,
        failed: 2,
        waived: 1,
        errored: 0,
        env_fingerprint: "fp-xyz".to_string(),
    };
    let json = serde_json::to_string(&summary).unwrap();
    let restored: ConformanceRunSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, restored);
}

#[test]
fn conformance_delta_classification_serde_round_trip() {
    for kind in [
        ConformanceDeltaKind::SchemaFieldAdded,
        ConformanceDeltaKind::SchemaFieldRemoved,
        ConformanceDeltaKind::SchemaFieldModified,
        ConformanceDeltaKind::BehavioralSemanticShift,
        ConformanceDeltaKind::TimingChange,
        ConformanceDeltaKind::ErrorFormatChange,
    ] {
        let delta = ConformanceDeltaClassification {
            kind,
            field: Some("test_field".to_string()),
            expected: Some("expected_val".to_string()),
            actual: Some("actual_val".to_string()),
            detail: "test detail".to_string(),
        };
        let json = serde_json::to_string(&delta).unwrap();
        let restored: ConformanceDeltaClassification = serde_json::from_str(&json).unwrap();
        assert_eq!(delta, restored, "round-trip failed for {kind:?}");
    }
}

#[test]
fn conformance_failure_class_serde_round_trip() {
    for class in [
        ConformanceFailureClass::Breaking,
        ConformanceFailureClass::Behavioral,
        ConformanceFailureClass::Observability,
        ConformanceFailureClass::Performance,
    ] {
        let json = serde_json::to_string(&class).unwrap();
        let restored: ConformanceFailureClass = serde_json::from_str(&json).unwrap();
        assert_eq!(class, restored);
    }
}

#[test]
fn conformance_failure_severity_serde_round_trip() {
    for severity in [
        ConformanceFailureSeverity::Info,
        ConformanceFailureSeverity::Warning,
        ConformanceFailureSeverity::Error,
        ConformanceFailureSeverity::Critical,
    ] {
        let json = serde_json::to_string(&severity).unwrap();
        let restored: ConformanceFailureSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(severity, restored);
    }
}

#[test]
fn conformance_repro_metadata_serde_round_trip() {
    let meta = ConformanceReproMetadata {
        version_combination: {
            let mut m = BTreeMap::new();
            m.insert("engine".to_string(), "0.1.0".to_string());
            m
        },
        first_seen_commit: "abc123".to_string(),
        regression_commit: Some("def456".to_string()),
        ci_run_id: Some("ci-789".to_string()),
        issue_tracker_project: "beads".to_string(),
        issue_tracking_bead: Some("bd-test".to_string()),
    };
    let json = serde_json::to_string(&meta).unwrap();
    let restored: ConformanceReproMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(meta, restored);
}

#[test]
fn conformance_minimization_summary_serde_round_trip() {
    let summary = ConformanceMinimizationSummary {
        strategy: "greedy-delta-debugging".to_string(),
        original_source_lines: 100,
        minimized_source_lines: 10,
        original_expected_lines: 50,
        minimized_expected_lines: 5,
        original_actual_lines: 50,
        minimized_actual_lines: 5,
        preserved_failure_class: true,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let restored: ConformanceMinimizationSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, restored);
}

#[test]
fn conformance_runner_config_serde_round_trip() {
    let config = ConformanceRunnerConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let restored: ConformanceRunnerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
}

#[test]
fn donor_fixture_serde_round_trip() {
    let fixture = DonorFixture {
        donor_harness: "test262".to_string(),
        source: "let x = 1;".to_string(),
        observed_output: "1".to_string(),
    };
    let json = serde_json::to_string(&fixture).unwrap();
    let restored: DonorFixture = serde_json::from_str(&json).unwrap();
    assert_eq!(fixture, restored);
}

// ─── Section 18: Replay Verification ───────────────────────────────────────

#[test]
fn repro_artifact_verify_replay_succeeds_for_valid_artifact() {
    let dir = temp_dir("replay_valid");
    let (fh, eh) = write_fixture_pair(&dir, "fix.json", "exp.txt", "x=1", "r:2", "r:1");
    let manifest = make_manifest(vec![make_asset_record(
        "replay-001",
        "fix.json",
        &fh,
        "exp.txt",
        &eh,
    )]);
    let manifest_path = dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();

    let runner = ConformanceRunner::default();
    let waivers = ConformanceWaiverSet::default();
    let result = runner.run(&manifest_path, &waivers).unwrap();

    assert_eq!(result.minimized_repros.len(), 1);
    // verify_replay was already called during the run, but let's call it explicitly
    assert!(result.minimized_repros[0].verify_replay().is_ok());
}

// ─── Section 19: ConformanceMinimizedReproArtifact serde ───────────────────

#[test]
fn minimized_repro_artifact_serde_round_trip() {
    let artifact = ConformanceMinimizedReproArtifact {
        schema_version: ConformanceMinimizedReproArtifact::CURRENT_SCHEMA.to_string(),
        artifact_id: "repro-cf-abc".to_string(),
        failure_id: "cf-abc".to_string(),
        boundary_surface: "test262/expressions".to_string(),
        failure_class: ConformanceFailureClass::Behavioral,
        severity: ConformanceFailureSeverity::Error,
        version_combination: {
            let mut m = BTreeMap::new();
            m.insert("engine".to_string(), "0.1.0".to_string());
            m
        },
        first_seen_commit: "abc123".to_string(),
        regression_commit: None,
        environment: ConformanceReproEnvironment {
            locale: "C".to_string(),
            timezone: "UTC".to_string(),
            gc_schedule: "deterministic".to_string(),
            rust_toolchain: "nightly".to_string(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
        },
        replay: ConformanceReplayContract {
            deterministic_seed: 7,
            replay_command: "franken-conformance replay test.json".to_string(),
            verification_command: "franken-conformance replay test.json --verify".to_string(),
            verification_digest: "digest-abc".to_string(),
        },
        expected_output: "expected".to_string(),
        actual_output: "actual".to_string(),
        delta_classification: vec![ConformanceDeltaClassification {
            kind: ConformanceDeltaKind::BehavioralSemanticShift,
            field: None,
            expected: Some("expected".to_string()),
            actual: Some("actual".to_string()),
            detail: "test".to_string(),
        }],
        minimization: ConformanceMinimizationSummary {
            strategy: "greedy-delta-debugging".to_string(),
            original_source_lines: 10,
            minimized_source_lines: 3,
            original_expected_lines: 5,
            minimized_expected_lines: 2,
            original_actual_lines: 5,
            minimized_actual_lines: 2,
            preserved_failure_class: true,
        },
        failing_vector: ConformanceMinimizedFailingVector {
            asset_id: "test-001".to_string(),
            source_donor: "test262".to_string(),
            semantic_domain: "expressions".to_string(),
            normative_reference: "ECMA-262".to_string(),
            fixture: DonorFixture {
                donor_harness: "test262".to_string(),
                source: "x=1".to_string(),
                observed_output: "actual".to_string(),
            },
            expected_output: "expected".to_string(),
        },
        evidence_ledger_id: "conformance-ledger/cf-abc".to_string(),
        linked_run: ConformanceRunLinkage {
            run_id: "run-001".to_string(),
            trace_id: "tr-001".to_string(),
            decision_id: "dec-001".to_string(),
            ci_run_id: None,
        },
        issue_tracker: ConformanceIssueLink {
            tracker: "beads".to_string(),
            issue_id: "auto/test-001/cf-abc".to_string(),
        },
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let restored: ConformanceMinimizedReproArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, restored);
}

// ─── Section 20: Edge Cases ────────────────────────────────────────────────

#[test]
fn canonicalize_empty_string_returns_empty() {
    assert_eq!(canonicalize_conformance_output(""), "");
}

#[test]
fn canonicalize_only_whitespace_returns_empty() {
    assert_eq!(canonicalize_conformance_output("   \n  \n  "), "");
}

#[test]
fn delta_classification_empty_vs_nonempty() {
    let deltas = classify_conformance_delta("", "hello");
    assert!(
        !deltas.is_empty(),
        "should detect difference between empty and non-empty"
    );
}

#[test]
fn delta_classification_handles_props_with_empty_fields() {
    let expected = "props:";
    let actual = "props: a";
    let deltas = classify_conformance_delta(expected, actual);
    assert!(!deltas.is_empty());
}

#[test]
fn ifc_all_source_labels_validate() {
    // Verify all valid source labels are accepted
    for label in [
        "credential",
        "key_material",
        "privileged_env",
        "policy_protected",
    ] {
        let record = ConformanceAssetRecord {
            asset_id: "validate-label".to_string(),
            source_donor: "ifc".to_string(),
            semantic_domain: "ifc_corpus/test".to_string(),
            normative_reference: "FrankenEngine IFC v1".to_string(),
            fixture_path: "fix.json".to_string(),
            fixture_hash: "abc".to_string(),
            expected_output_path: "exp.txt".to_string(),
            expected_output_hash: "def".to_string(),
            import_date: "2026-01-01".to_string(),
            category: Some("benign".to_string()),
            source_labels: vec![label.to_string()],
            sink_clearances: vec!["network_egress".to_string()],
            flow_path_type: Some("direct".to_string()),
            expected_outcome: Some("allow".to_string()),
            expected_evidence_type: Some("none".to_string()),
        };
        let json = serde_json::to_string(&record).unwrap();
        let _restored: ConformanceAssetRecord = serde_json::from_str(&json).unwrap();
    }
}

#[test]
fn ifc_all_sink_clearances_validate() {
    for clearance in [
        "network_egress",
        "subprocess_ipc",
        "persistence_export",
        "explicit_declassify",
    ] {
        let record = ConformanceAssetRecord {
            asset_id: "validate-clearance".to_string(),
            source_donor: "ifc".to_string(),
            semantic_domain: "ifc_corpus/test".to_string(),
            normative_reference: "FrankenEngine IFC v1".to_string(),
            fixture_path: "fix.json".to_string(),
            fixture_hash: "abc".to_string(),
            expected_output_path: "exp.txt".to_string(),
            expected_output_hash: "def".to_string(),
            import_date: "2026-01-01".to_string(),
            category: Some("benign".to_string()),
            source_labels: vec!["credential".to_string()],
            sink_clearances: vec![clearance.to_string()],
            flow_path_type: Some("direct".to_string()),
            expected_outcome: Some("allow".to_string()),
            expected_evidence_type: Some("none".to_string()),
        };
        let json = serde_json::to_string(&record).unwrap();
        let _: ConformanceAssetRecord = serde_json::from_str(&json).unwrap();
    }
}

#[test]
fn ifc_all_flow_path_types_validate() {
    for flow_type in ["direct", "indirect", "implicit", "temporal", "covert"] {
        let record = ConformanceAssetRecord {
            asset_id: "validate-flow".to_string(),
            source_donor: "ifc".to_string(),
            semantic_domain: "ifc_corpus/test".to_string(),
            normative_reference: "FrankenEngine IFC v1".to_string(),
            fixture_path: "fix.json".to_string(),
            fixture_hash: "abc".to_string(),
            expected_output_path: "exp.txt".to_string(),
            expected_output_hash: "def".to_string(),
            import_date: "2026-01-01".to_string(),
            category: Some("benign".to_string()),
            source_labels: vec!["credential".to_string()],
            sink_clearances: vec!["network_egress".to_string()],
            flow_path_type: Some(flow_type.to_string()),
            expected_outcome: Some("allow".to_string()),
            expected_evidence_type: Some("none".to_string()),
        };
        let json = serde_json::to_string(&record).unwrap();
        let _: ConformanceAssetRecord = serde_json::from_str(&json).unwrap();
    }
}

// ─── Section 21: ConformanceReplayContract serde ───────────────────────────

#[test]
fn replay_contract_serde_round_trip() {
    let contract = ConformanceReplayContract {
        deterministic_seed: 42,
        replay_command: "franken-conformance replay test.json".to_string(),
        verification_command: "franken-conformance replay test.json --verify".to_string(),
        verification_digest: "digest123".to_string(),
    };
    let json = serde_json::to_string(&contract).unwrap();
    let restored: ConformanceReplayContract = serde_json::from_str(&json).unwrap();
    assert_eq!(contract, restored);
}

// ─── Section 22: ConformanceReproEnvironment serde ─────────────────────────

#[test]
fn repro_environment_serde_round_trip() {
    let env = ConformanceReproEnvironment {
        locale: "C".to_string(),
        timezone: "UTC".to_string(),
        gc_schedule: "deterministic".to_string(),
        rust_toolchain: "nightly-2026-02-01".to_string(),
        os: "linux".to_string(),
        arch: "x86_64".to_string(),
    };
    let json = serde_json::to_string(&env).unwrap();
    let restored: ConformanceReproEnvironment = serde_json::from_str(&json).unwrap();
    assert_eq!(env, restored);
}

// ─── Section 23: ConformanceRunLinkage serde ───────────────────────────────

#[test]
fn run_linkage_serde_round_trip() {
    let linkage = ConformanceRunLinkage {
        run_id: "run-001".to_string(),
        trace_id: "tr-001".to_string(),
        decision_id: "dec-001".to_string(),
        ci_run_id: Some("ci-999".to_string()),
    };
    let json = serde_json::to_string(&linkage).unwrap();
    let restored: ConformanceRunLinkage = serde_json::from_str(&json).unwrap();
    assert_eq!(linkage, restored);
}

// ─── Section 24: ConformanceIssueLink serde ────────────────────────────────

#[test]
fn issue_link_serde_round_trip() {
    let link = ConformanceIssueLink {
        tracker: "beads".to_string(),
        issue_id: "bd-test".to_string(),
    };
    let json = serde_json::to_string(&link).unwrap();
    let restored: ConformanceIssueLink = serde_json::from_str(&json).unwrap();
    assert_eq!(link, restored);
}

// ─── Section 25: Evidence Collector with IFC Assets ────────────────────────

#[test]
fn evidence_collector_produces_ifc_evidence_for_ifc_assets() {
    let dir = temp_dir("collector_ifc");
    let fixture_dir = temp_dir("collector_ifc_fixtures");
    let output = "outcome:allow evidence:none";
    let (fh, eh) = write_fixture_pair(
        &fixture_dir,
        "fix.json",
        "exp.txt",
        "safe code",
        output,
        output,
    );

    let manifest = make_manifest(vec![make_ifc_asset_record(&IfcAssetInput {
        id: "ifc-coll-001",
        fixture_path: "fix.json",
        fixture_hash: &fh,
        expected_output_path: "exp.txt",
        expected_output_hash: &eh,
        category: "benign",
        source_labels: vec!["credential"],
        sink_clearances: vec!["network_egress"],
        flow_path_type: "direct",
        expected_outcome: "allow",
        expected_evidence_type: "none",
    })]);

    let manifest_path = fixture_dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();

    let runner = ConformanceRunner::default();
    let waivers = ConformanceWaiverSet::default();
    let result = runner.run(&manifest_path, &waivers).unwrap();

    let collector = ConformanceEvidenceCollector::new(&dir).unwrap();
    let artifacts = collector.collect(&result).unwrap();

    assert!(
        artifacts.ifc_conformance_evidence_path.is_some(),
        "IFC evidence should be produced for IFC assets"
    );
    let ifc_path = artifacts.ifc_conformance_evidence_path.unwrap();
    assert!(ifc_path.exists());
    let content = fs::read_to_string(&ifc_path).unwrap();
    assert!(!content.is_empty(), "IFC evidence file should not be empty");
}

// ─── Section 26: Schema Constants ──────────────────────────────────────────

#[test]
fn conformance_asset_manifest_schema_version_is_v1() {
    assert_eq!(
        ConformanceAssetManifest::CURRENT_SCHEMA,
        "franken-engine.conformance-assets.v1"
    );
}

#[test]
fn minimized_repro_artifact_schema_version_is_v1() {
    assert_eq!(
        ConformanceMinimizedReproArtifact::CURRENT_SCHEMA,
        "franken-engine.conformance-min-repro.v1"
    );
}

// ─── Section 27: Waiver Set serde ──────────────────────────────────────────

#[test]
fn waiver_set_serde_round_trip() {
    let set = ConformanceWaiverSet {
        waivers: vec![
            ConformanceWaiver {
                asset_id: "w1".to_string(),
                reason_code: WaiverReasonCode::HarnessGap,
                tracking_bead: "bd-1".to_string(),
                expiry_date: "2026-12-31".to_string(),
            },
            ConformanceWaiver {
                asset_id: "w2".to_string(),
                reason_code: WaiverReasonCode::IntentionalDivergence,
                tracking_bead: "bd-2".to_string(),
                expiry_date: "2027-06-30".to_string(),
            },
        ],
    };
    let json = serde_json::to_string(&set).unwrap();
    let restored: ConformanceWaiverSet = serde_json::from_str(&json).unwrap();
    assert_eq!(set, restored);
}

// ─── Section 28: ConformanceMinimizedFailingVector serde ───────────────────

#[test]
fn minimized_failing_vector_serde_round_trip() {
    let vector = ConformanceMinimizedFailingVector {
        asset_id: "fv-001".to_string(),
        source_donor: "test262".to_string(),
        semantic_domain: "expressions".to_string(),
        normative_reference: "ECMA-262".to_string(),
        fixture: DonorFixture {
            donor_harness: "test262".to_string(),
            source: "x=1".to_string(),
            observed_output: "2".to_string(),
        },
        expected_output: "1".to_string(),
    };
    let json = serde_json::to_string(&vector).unwrap();
    let restored: ConformanceMinimizedFailingVector = serde_json::from_str(&json).unwrap();
    assert_eq!(vector, restored);
}

// ─── Section 29: ConformanceRunResult serde ────────────────────────────────

#[test]
fn conformance_run_result_serde_round_trip() {
    let result = ConformanceRunResult {
        run_id: "run-serde".to_string(),
        asset_manifest_hash: "hash-serde".to_string(),
        logs: vec![ConformanceLogEvent {
            trace_id: "tr-s".to_string(),
            decision_id: "dec-s".to_string(),
            policy_id: "pol-s".to_string(),
            component: "runner".to_string(),
            event: "exec".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            asset_id: "as-s".to_string(),
            workload_id: "wl-s".to_string(),
            semantic_domain: "expressions".to_string(),
            category: None,
            source_labels: Vec::new(),
            sink_clearances: Vec::new(),
            flow_path_type: None,
            expected_outcome: None,
            actual_outcome: None,
            evidence_type: None,
            evidence_id: None,
            duration_us: 100,
            error_detail: None,
        }],
        summary: ConformanceRunSummary {
            run_id: "run-serde".to_string(),
            asset_manifest_hash: "hash-serde".to_string(),
            total_assets: 1,
            passed: 1,
            failed: 0,
            waived: 0,
            errored: 0,
            env_fingerprint: "fp-serde".to_string(),
        },
        minimized_repros: Vec::new(),
    };
    let json = serde_json::to_string(&result).unwrap();
    let restored: ConformanceRunResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}
