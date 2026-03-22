#![forbid(unsafe_code)]

pub use frankenengine_engine::aot_entrygraph_compiler;
pub use frankenengine_engine::cold_start_aot_governance;
pub use frankenengine_engine::hash_tiers;
pub use frankenengine_engine::persistent_cache_contract;
pub use frankenengine_engine::runtime_image_contract;
pub use frankenengine_engine::security_epoch;

#[path = "../src/cold_start_compilation_lane.rs"]
mod cold_start_compilation_lane;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use cold_start_aot_governance::{BenchmarkVerdict, GovernanceVerdict};
use cold_start_compilation_lane::{
    AOT_BUNDLE_FILE, AOT_BUNDLE_SCHEMA_VERSION, ArtifactContext, BEAD_ID, OBSERVABILITY_DELTA_FILE,
    OBSERVABILITY_DELTA_SCHEMA_VERSION, REPORT_FILE, REPORT_SCHEMA_VERSION,
    RUNTIME_IMAGE_MANIFEST_FILE, RUNTIME_IMAGE_MANIFEST_SCHEMA_VERSION, SUMMARY_FILE,
    TRACE_IDS_FILE, TRACE_IDS_SCHEMA_VERSION, TraceIdsArtifact, emit_default_bundle,
};
use serde::de::DeserializeOwned;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn temp_artifact_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time must move forward")
        .as_nanos();
    std::env::temp_dir().join(format!("franken-engine-{label}-{nanos}"))
}

fn emit_bundle(label: &str) -> cold_start_compilation_lane::BundleWriteReport {
    let artifact_dir = temp_artifact_dir(label);
    let mut context = ArtifactContext::new(&artifact_dir);
    context.generated_at_utc = "2026-03-21T00:00:00Z".to_string();
    context.run_id = format!("run-{label}");
    context.trace_id = format!("trace-{label}");
    context.decision_id = format!("decision-{label}");
    context.source_commit = "deadbeef".to_string();
    context.toolchain = "nightly".to_string();
    emit_default_bundle(&context).expect("bundle should emit")
}

fn parse_json<T: DeserializeOwned>(path: &Path) -> T {
    serde_json::from_str(&read_to_string(path))
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

#[test]
fn rgc_610_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_COLD_START_COMPILATION_LANE_V1.md");
    let doc = read_to_string(&path);

    for section in [
        "# RGC Cold-Start Compilation Lane V1",
        "## Purpose",
        "## Component Inputs",
        "## Bundle Artifacts",
        "## Gate Runner",
        "## Operator Verification",
        "## Replay Workflow",
    ] {
        assert!(
            doc.contains(section),
            "missing section in {}: {section}",
            path.display()
        );
    }
}

#[test]
fn rgc_610_bundle_emits_required_artifacts() {
    let bundle = emit_bundle("artifacts");

    for path in [
        &bundle.report_path,
        &bundle.observability_delta_path,
        &bundle.aot_bundle_report_path,
        &bundle.runtime_image_manifest_path,
        &bundle.trace_ids_path,
        &bundle.summary_path,
    ] {
        assert!(
            path.is_file(),
            "expected artifact file at {}",
            path.display()
        );
    }

    for required in [
        REPORT_FILE,
        OBSERVABILITY_DELTA_FILE,
        AOT_BUNDLE_FILE,
        RUNTIME_IMAGE_MANIFEST_FILE,
        TRACE_IDS_FILE,
        SUMMARY_FILE,
        "persistent_cache_contract/persistent_cache_contract.json",
    ] {
        assert!(
            bundle.written_files.contains_key(required),
            "bundle missing written_files entry for {required}"
        );
    }
}

#[test]
fn rgc_610_report_is_approved_and_references_expected_outputs() {
    let bundle = emit_bundle("report");
    let report: cold_start_compilation_lane::ColdStartCompilationReport =
        parse_json(&bundle.report_path);

    assert_eq!(report.schema_version, REPORT_SCHEMA_VERSION);
    assert_eq!(report.bead_id, BEAD_ID);
    assert_eq!(report.aggregate_benchmark_verdict, BenchmarkVerdict::Faster);
    assert!(matches!(
        report.governance_verdict,
        GovernanceVerdict::Approved
    ));
    assert_eq!(
        report.persistent_cache_contract_path,
        "persistent_cache_contract/persistent_cache_contract.json"
    );
    assert_eq!(report.aot_bundle_report_path, AOT_BUNDLE_FILE);
    assert_eq!(
        report.runtime_image_manifest_path,
        RUNTIME_IMAGE_MANIFEST_FILE
    );
    assert_eq!(report.observability_delta_path, OBSERVABILITY_DELTA_FILE);
    assert!(report.aggregate_speedup_millionths > 0);
    assert!(report.rollback_triggers.is_empty());
    assert!(
        report
            .operator_verification
            .iter()
            .any(|command| command.contains(REPORT_FILE))
    );
}

#[test]
fn rgc_610_trace_ids_include_subbundle_trace() {
    let bundle = emit_bundle("trace");
    let trace_ids: TraceIdsArtifact = parse_json(&bundle.trace_ids_path);

    assert_eq!(trace_ids.schema_version, TRACE_IDS_SCHEMA_VERSION);
    assert_eq!(trace_ids.trace_ids.len(), 2);
    assert!(
        trace_ids
            .subordinate_trace_ids
            .contains_key("persistent_cache_contract")
    );
    assert!(
        trace_ids
            .subordinate_trace_ids
            .contains_key("persistent_cache_contract_trace_ids_path")
    );
}

#[test]
fn rgc_610_observability_delta_covers_all_required_modes() {
    let bundle = emit_bundle("delta");
    let delta: cold_start_compilation_lane::ColdStartObservabilityDeltaArtifact =
        parse_json(&bundle.observability_delta_path);

    assert_eq!(delta.schema_version, OBSERVABILITY_DELTA_SCHEMA_VERSION);
    let mode_ids = delta
        .rows
        .iter()
        .map(|row| row.mode_id.as_str())
        .collect::<BTreeSet<_>>();
    for mode in [
        "observability_off",
        "shipped_budgeted",
        "exact_shadow",
        "incident_full_capture",
    ] {
        assert!(mode_ids.contains(mode), "missing mode row {mode}");
    }
    assert!(delta.rows.iter().all(|row| row.preserves_claim));
}

#[test]
fn rgc_610_runtime_image_manifest_prefers_aot_restore() {
    let bundle = emit_bundle("runtime");
    let runtime_manifest: cold_start_compilation_lane::RuntimeImageManifestArtifact =
        parse_json(&bundle.runtime_image_manifest_path);

    assert_eq!(
        runtime_manifest.schema_version,
        RUNTIME_IMAGE_MANIFEST_SCHEMA_VERSION
    );
    assert_eq!(
        runtime_manifest.best_warm_start_image_id.as_deref(),
        Some("img-aot-demo")
    );
    assert_eq!(
        runtime_manifest.best_warm_start_mode.as_deref(),
        Some("AotRestore")
    );
    assert_eq!(runtime_manifest.image_count, 3);
}

#[test]
fn rgc_610_aot_bundle_report_is_populated() {
    let bundle = emit_bundle("aot");
    let aot_bundle: cold_start_compilation_lane::AotBundleCompilationReport =
        parse_json(&bundle.aot_bundle_report_path);

    assert_eq!(aot_bundle.schema_version, AOT_BUNDLE_SCHEMA_VERSION);
    assert_eq!(aot_bundle.batch_report.total_graphs, 3);
    assert_eq!(aot_bundle.batch_report.usable_graphs, 3);
    assert_eq!(aot_bundle.receipts.len(), 3);
    assert!(aot_bundle.entry_kind_summary.contains_key("PackageMain"));
    assert!(aot_bundle.target_summary.contains_key("FrozenSnapshot"));
}

#[test]
fn rgc_610_summary_mentions_artifacts_and_operator_commands() {
    let bundle = emit_bundle("summary");
    let summary = read_to_string(&bundle.summary_path);

    assert!(summary.contains("# Cold-Start Compilation Lane Summary"));
    assert!(summary.contains("## Artifacts"));
    assert!(summary.contains("## Operator Verification"));
    assert!(summary.contains(REPORT_FILE));
    assert!(summary.contains(OBSERVABILITY_DELTA_FILE));
}

#[test]
fn rgc_610_gate_script_uses_rch_and_targeted_commands() {
    let path = repo_root().join("scripts/run_rgc_cold_start_compilation_lane.sh");
    let script = read_to_string(&path);

    assert!(script.contains("local selected_mode=\"${1:-$mode}\""));
    assert!(script.contains("local mode_exit=0"));
    assert!(script.contains("case \"$selected_mode\" in"));
    assert!(script.contains("run_mode check || mode_exit=$?"));
    assert!(script.contains("if ! run_mode; then"));
    assert!(script.contains("rch exec -- env"));
    assert!(script.contains("target_rch_rgc_cold_start_compilation_lane_"));
    assert!(script.contains(
        "cold_start_compilation_report: (if ($mode == \"run\" or $mode == \"ci\") then $report_path else null end)"
    ));
    assert!(script.contains(
        "trace_ids: (if ($mode == \"run\" or $mode == \"ci\") then $trace_ids_path else null end)"
    ));
    assert!(script.contains(
        "cargo check -p frankenengine-engine --test cold_start_compilation_lane --bin franken_cold_start_compilation_lane"
    ));
    assert!(script.contains(
        "cargo run -p frankenengine-engine --bin franken_cold_start_compilation_lane -- --artifact-dir ${run_dir}"
    ));
    assert!(!script.contains("/tmp/rch_target_rgc_cold_start_compilation_lane"));
}

#[test]
fn rgc_610_replay_script_requires_complete_bundle() {
    let path = repo_root().join("scripts/e2e/rgc_cold_start_compilation_lane_replay.sh");
    let script = read_to_string(&path);

    for artifact in [
        "run_manifest.json",
        "trace_ids.json",
        "events.jsonl",
        "commands.txt",
        "cold_start_compilation_report.json",
        "cold_start_observability_delta.json",
        "aot_bundle_compilation_report.json",
        "runtime_image_manifest.json",
        "summary.md",
        "persistent_cache_contract/persistent_cache_contract.json",
    ] {
        assert!(
            script.contains(artifact),
            "replay script must mention required artifact {artifact}"
        );
    }
    assert!(script.contains("latest complete run directory"));
}

#[test]
fn rgc_610_doc_wires_scripts_and_artifacts() {
    let path = repo_root().join("docs/RGC_COLD_START_COMPILATION_LANE_V1.md");
    let doc = read_to_string(&path);

    assert!(doc.contains("./scripts/run_rgc_cold_start_compilation_lane.sh ci"));
    assert!(doc.contains("./scripts/e2e/rgc_cold_start_compilation_lane_replay.sh ci"));
    assert!(doc.contains(
        "`check` mode emits only `run_manifest.json`, `events.jsonl`, `commands.txt`, and `step_logs/`."
    ));
    assert!(doc.contains("`run` and `ci` emit the full cold-start evidence bundle."));
    assert!(doc.contains(REPORT_FILE));
    assert!(doc.contains(OBSERVABILITY_DELTA_FILE));
    assert!(doc.contains(AOT_BUNDLE_FILE));
    assert!(doc.contains(RUNTIME_IMAGE_MANIFEST_FILE));
}
