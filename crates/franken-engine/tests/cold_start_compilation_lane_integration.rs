//! Integration tests for the cold-start compilation lane artifact bundle
//! (RGC-610).

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use frankenengine_engine::cold_start_aot_governance::{
    BenchmarkVerdict, DecisionReceipt, GovernanceVerdict, StartupPathKind,
};
use frankenengine_engine::cold_start_compilation_lane::{
    AOT_BUNDLE_FILE, AOT_BUNDLE_SCHEMA_VERSION, AotBundleCompilationReport, ArtifactContext,
    BEAD_ID, COMPONENT, ColdStartCompilationReport, ColdStartObservabilityDeltaArtifact,
    ColdStartObservabilityDeltaRow, EntryKindSummary, OBSERVABILITY_DELTA_FILE,
    OBSERVABILITY_DELTA_SCHEMA_VERSION, PERSISTENT_CACHE_CONTRACT_FILE, PERSISTENT_CACHE_DIR,
    POLICY_ID, REPORT_FILE, REPORT_SCHEMA_VERSION, RUNTIME_IMAGE_MANIFEST_FILE,
    RUNTIME_IMAGE_MANIFEST_SCHEMA_VERSION, RuntimeImageManifestArtifact, SUMMARY_FILE,
    TRACE_IDS_FILE, TRACE_IDS_SCHEMA_VERSION, TraceIdsArtifact, render_summary,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::runtime_image_contract::{ImagePolicy, ImageRegistry};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_report() -> ColdStartCompilationReport {
    ColdStartCompilationReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        policy_id: POLICY_ID.to_string(),
        generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
        run_id: "run-test".to_string(),
        source_commit: "abc123".to_string(),
        toolchain: "nightly".to_string(),
        persistent_cache_contract_path: PERSISTENT_CACHE_CONTRACT_FILE.to_string(),
        cache_contract_receipt_count: 3,
        aot_bundle_report_path: AOT_BUNDLE_FILE.to_string(),
        runtime_image_manifest_path: RUNTIME_IMAGE_MANIFEST_FILE.to_string(),
        observability_delta_path: OBSERVABILITY_DELTA_FILE.to_string(),
        governance_verdict: GovernanceVerdict::Approved,
        aggregate_benchmark_verdict: BenchmarkVerdict::Faster,
        aggregate_speedup_millionths: 150_000,
        rollback_triggers: Vec::new(),
        governance_receipt: DecisionReceipt::new(
            SecurityEpoch::from_raw(1),
            GovernanceVerdict::Approved,
            Vec::new(),
            Vec::new(),
        ),
        evidence: Vec::new(),
        parity_results: Vec::new(),
        required_artifacts: vec!["artifact1.json".to_string(), "artifact2.json".to_string()],
        operator_verification: vec!["jq '.verdict' report.json".to_string()],
    }
}

fn make_batch_report() -> frankenengine_engine::aot_entrygraph_compiler::BatchReport {
    frankenengine_engine::aot_entrygraph_compiler::BatchReport {
        schema_version: "test".to_string(),
        reports: Vec::new(),
        batch_epoch: SecurityEpoch::from_raw(1),
        total_graphs: 0,
        usable_graphs: 0,
        aggregate_success_rate_millionths: 0,
        batch_hash: ContentHash::compute(b"empty"),
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_nonempty() {
    assert!(!BEAD_ID.is_empty());
    assert!(BEAD_ID.starts_with("bd-"));
    assert!(!COMPONENT.is_empty());
    assert_eq!(COMPONENT, "cold_start_compilation_lane");
    assert!(!POLICY_ID.is_empty());
    assert!(POLICY_ID.starts_with("policy-"));
}

#[test]
fn schema_versions_are_versioned() {
    assert!(REPORT_SCHEMA_VERSION.contains(".v1"));
    assert!(AOT_BUNDLE_SCHEMA_VERSION.contains(".v1"));
    assert!(RUNTIME_IMAGE_MANIFEST_SCHEMA_VERSION.contains(".v1"));
    assert!(OBSERVABILITY_DELTA_SCHEMA_VERSION.contains(".v1"));
    assert!(TRACE_IDS_SCHEMA_VERSION.contains(".v1"));
}

#[test]
fn file_names_end_with_json_or_md() {
    assert!(REPORT_FILE.ends_with(".json"));
    assert!(OBSERVABILITY_DELTA_FILE.ends_with(".json"));
    assert!(AOT_BUNDLE_FILE.ends_with(".json"));
    assert!(RUNTIME_IMAGE_MANIFEST_FILE.ends_with(".json"));
    assert!(TRACE_IDS_FILE.ends_with(".json"));
    assert!(SUMMARY_FILE.ends_with(".md"));
}

#[test]
fn persistent_cache_dir_nonempty() {
    assert!(!PERSISTENT_CACHE_DIR.is_empty());
    assert!(!PERSISTENT_CACHE_CONTRACT_FILE.is_empty());
    assert!(PERSISTENT_CACHE_CONTRACT_FILE.starts_with(PERSISTENT_CACHE_DIR));
}

// ---------------------------------------------------------------------------
// ArtifactContext
// ---------------------------------------------------------------------------

#[test]
fn artifact_context_new_fills_defaults() {
    let ctx = ArtifactContext::new("/tmp/test-artifacts");
    assert_eq!(ctx.artifact_dir, PathBuf::from("/tmp/test-artifacts"));
    assert!(ctx.run_id.starts_with("run-cold_start_compilation_lane-"));
    assert_eq!(ctx.trace_id, "trace-rgc-610");
    assert_eq!(ctx.decision_id, "decision-rgc-610");
    assert_eq!(ctx.policy_id, POLICY_ID);
    assert!(!ctx.generated_at_utc.is_empty());
    assert!(!ctx.command_invocation.is_empty());
}

#[test]
fn artifact_context_serde_roundtrip() {
    let ctx = ArtifactContext::new("/tmp/serde-test");
    let json = serde_json::to_string(&ctx).unwrap();
    let decoded: ArtifactContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, decoded);
}

#[test]
fn artifact_context_custom_fields() {
    let mut ctx = ArtifactContext::new("/tmp/custom");
    ctx.source_commit = "deadbeef".to_string();
    ctx.toolchain = "stable".to_string();
    let json = serde_json::to_string(&ctx).unwrap();
    let decoded: ArtifactContext = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.source_commit, "deadbeef");
    assert_eq!(decoded.toolchain, "stable");
}

#[test]
fn artifact_context_run_id_contains_component() {
    let ctx = ArtifactContext::new("/tmp/run-id-test");
    assert!(ctx.run_id.contains(COMPONENT));
}

// ---------------------------------------------------------------------------
// TraceIdsArtifact
// ---------------------------------------------------------------------------

#[test]
fn trace_ids_artifact_serde_roundtrip() {
    let artifact = TraceIdsArtifact {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_ids: vec!["trace-1".to_string(), "trace-2".to_string()],
        decision_id: "dec-1".to_string(),
        policy_id: POLICY_ID.to_string(),
        subordinate_trace_ids: BTreeMap::new(),
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let decoded: TraceIdsArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, decoded);
}

#[test]
fn trace_ids_artifact_with_subordinates() {
    let mut subordinate = BTreeMap::new();
    subordinate.insert("cache".to_string(), "trace-cache-1".to_string());
    subordinate.insert("aot".to_string(), "trace-aot-1".to_string());
    let artifact = TraceIdsArtifact {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_ids: vec!["main-trace".to_string()],
        decision_id: "dec-1".to_string(),
        policy_id: POLICY_ID.to_string(),
        subordinate_trace_ids: subordinate,
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let decoded: TraceIdsArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.subordinate_trace_ids.len(), 2);
}

// ---------------------------------------------------------------------------
// EntryKindSummary
// ---------------------------------------------------------------------------

#[test]
fn entry_kind_summary_serde_roundtrip() {
    let summary = EntryKindSummary {
        total_graphs: 10,
        usable_graphs: 8,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let decoded: EntryKindSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, decoded);
}

#[test]
fn entry_kind_summary_zero_values() {
    let summary = EntryKindSummary {
        total_graphs: 0,
        usable_graphs: 0,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let decoded: EntryKindSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.total_graphs, 0);
    assert_eq!(decoded.usable_graphs, 0);
}

// ---------------------------------------------------------------------------
// AotBundleCompilationReport
// ---------------------------------------------------------------------------

#[test]
fn aot_bundle_compilation_report_serde_roundtrip() {
    let report = AotBundleCompilationReport {
        schema_version: AOT_BUNDLE_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        policy_id: POLICY_ID.to_string(),
        batch_report: make_batch_report(),
        receipts: Vec::new(),
        entry_kind_summary: BTreeMap::new(),
        target_summary: BTreeMap::new(),
    };
    let json = serde_json::to_string(&report).unwrap();
    let decoded: AotBundleCompilationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, decoded);
}

#[test]
fn aot_bundle_with_entry_kind_summary() {
    let mut entry_kind_summary = BTreeMap::new();
    entry_kind_summary.insert(
        "PackageMain".to_string(),
        EntryKindSummary {
            total_graphs: 5,
            usable_graphs: 4,
        },
    );
    entry_kind_summary.insert(
        "SsrEntry".to_string(),
        EntryKindSummary {
            total_graphs: 3,
            usable_graphs: 3,
        },
    );
    let report = AotBundleCompilationReport {
        schema_version: AOT_BUNDLE_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        policy_id: POLICY_ID.to_string(),
        batch_report: make_batch_report(),
        receipts: Vec::new(),
        entry_kind_summary,
        target_summary: BTreeMap::new(),
    };
    let json = serde_json::to_string(&report).unwrap();
    let decoded: AotBundleCompilationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.entry_kind_summary.len(), 2);
}

// ---------------------------------------------------------------------------
// RuntimeImageManifestArtifact
// ---------------------------------------------------------------------------

#[test]
fn runtime_image_manifest_artifact_serde_roundtrip() {
    let manifest = RuntimeImageManifestArtifact {
        schema_version: RUNTIME_IMAGE_MANIFEST_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        registry_hash: ContentHash::compute(b"test-registry"),
        image_count: 3,
        total_bytes: 1024,
        best_warm_start_image_id: Some("img-1".to_string()),
        best_warm_start_mode: Some("prewarmed_pool".to_string()),
        registry: ImageRegistry::new(ImagePolicy::default()),
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let decoded: RuntimeImageManifestArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, decoded);
}

#[test]
fn runtime_image_manifest_no_warm_start() {
    let manifest = RuntimeImageManifestArtifact {
        schema_version: RUNTIME_IMAGE_MANIFEST_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        registry_hash: ContentHash::compute(b"test"),
        image_count: 0,
        total_bytes: 0,
        best_warm_start_image_id: None,
        best_warm_start_mode: None,
        registry: ImageRegistry::new(ImagePolicy::default()),
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let decoded: RuntimeImageManifestArtifact = serde_json::from_str(&json).unwrap();
    assert!(decoded.best_warm_start_image_id.is_none());
    assert!(decoded.best_warm_start_mode.is_none());
}

// ---------------------------------------------------------------------------
// ColdStartObservabilityDeltaRow
// ---------------------------------------------------------------------------

#[test]
fn observability_delta_row_serde_roundtrip() {
    let row = ColdStartObservabilityDeltaRow {
        mode_id: "shipped_budgeted".to_string(),
        startup_path: StartupPathKind::AotRestored,
        baseline_nanos: 100_000_000,
        candidate_nanos: 82_000_000,
        speedup_millionths: 180_000,
        preserves_claim: true,
    };
    let json = serde_json::to_string(&row).unwrap();
    let decoded: ColdStartObservabilityDeltaRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, decoded);
}

#[test]
fn observability_delta_row_negative_speedup() {
    let row = ColdStartObservabilityDeltaRow {
        mode_id: "regression".to_string(),
        startup_path: StartupPathKind::ZygoteFork,
        baseline_nanos: 80_000_000,
        candidate_nanos: 100_000_000,
        speedup_millionths: -250_000,
        preserves_claim: false,
    };
    assert!(row.speedup_millionths < 0);
    assert!(!row.preserves_claim);
}

#[test]
fn observability_delta_row_zero_speedup() {
    let row = ColdStartObservabilityDeltaRow {
        mode_id: "neutral".to_string(),
        startup_path: StartupPathKind::WarmCache,
        baseline_nanos: 100_000_000,
        candidate_nanos: 100_000_000,
        speedup_millionths: 0,
        preserves_claim: false,
    };
    assert_eq!(row.speedup_millionths, 0);
}

// ---------------------------------------------------------------------------
// ColdStartObservabilityDeltaArtifact
// ---------------------------------------------------------------------------

#[test]
fn observability_delta_artifact_serde_roundtrip() {
    let artifact = ColdStartObservabilityDeltaArtifact {
        schema_version: OBSERVABILITY_DELTA_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        policy_id: POLICY_ID.to_string(),
        rows: Vec::new(),
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let decoded: ColdStartObservabilityDeltaArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, decoded);
}

#[test]
fn observability_delta_artifact_with_rows() {
    let artifact = ColdStartObservabilityDeltaArtifact {
        schema_version: OBSERVABILITY_DELTA_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        policy_id: POLICY_ID.to_string(),
        rows: vec![
            ColdStartObservabilityDeltaRow {
                mode_id: "fast".to_string(),
                startup_path: StartupPathKind::AotRestored,
                baseline_nanos: 120_000_000,
                candidate_nanos: 78_000_000,
                speedup_millionths: 350_000,
                preserves_claim: true,
            },
            ColdStartObservabilityDeltaRow {
                mode_id: "slow".to_string(),
                startup_path: StartupPathKind::WarmCache,
                baseline_nanos: 120_000_000,
                candidate_nanos: 115_000_000,
                speedup_millionths: 41_666,
                preserves_claim: true,
            },
        ],
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let decoded: ColdStartObservabilityDeltaArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.rows.len(), 2);
}

// ---------------------------------------------------------------------------
// ColdStartCompilationReport
// ---------------------------------------------------------------------------

#[test]
fn compilation_report_serde_roundtrip() {
    let report = make_report();
    let json = serde_json::to_string(&report).unwrap();
    let decoded: ColdStartCompilationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, decoded);
}

#[test]
fn compilation_report_fields() {
    let report = make_report();
    assert_eq!(report.schema_version, REPORT_SCHEMA_VERSION);
    assert_eq!(report.component, COMPONENT);
    assert_eq!(report.bead_id, BEAD_ID);
    assert_eq!(report.policy_id, POLICY_ID);
    assert_eq!(report.governance_verdict, GovernanceVerdict::Approved);
    assert_eq!(report.aggregate_benchmark_verdict, BenchmarkVerdict::Faster);
}

// ---------------------------------------------------------------------------
// render_summary
// ---------------------------------------------------------------------------

#[test]
fn render_summary_contains_header() {
    let report = make_report();
    let summary = render_summary(&report);
    assert!(summary.contains("Cold-Start Compilation Lane Summary"));
}

#[test]
fn render_summary_contains_bead_id() {
    let report = make_report();
    let summary = render_summary(&report);
    assert!(summary.contains(BEAD_ID));
}

#[test]
fn render_summary_contains_component() {
    let report = make_report();
    let summary = render_summary(&report);
    assert!(summary.contains(COMPONENT));
}

#[test]
fn render_summary_contains_artifacts() {
    let report = make_report();
    let summary = render_summary(&report);
    for artifact in &report.required_artifacts {
        assert!(summary.contains(artifact.as_str()));
    }
}

#[test]
fn render_summary_contains_verification_commands() {
    let report = make_report();
    let summary = render_summary(&report);
    for cmd in &report.operator_verification {
        assert!(summary.contains(cmd.as_str()));
    }
}

#[test]
fn render_summary_contains_verdict() {
    let report = make_report();
    let summary = render_summary(&report);
    assert!(summary.contains("governance_verdict"));
    assert!(summary.contains("aggregate_benchmark_verdict"));
}

#[test]
fn render_summary_contains_speedup() {
    let report = make_report();
    let summary = render_summary(&report);
    assert!(summary.contains("150000"));
}

#[test]
fn render_summary_empty_artifacts_still_has_header() {
    let mut report = make_report();
    report.required_artifacts.clear();
    report.operator_verification.clear();
    let summary = render_summary(&report);
    assert!(summary.contains("Cold-Start Compilation Lane Summary"));
    assert!(summary.contains("Artifacts"));
    assert!(summary.contains("Operator Verification"));
}
