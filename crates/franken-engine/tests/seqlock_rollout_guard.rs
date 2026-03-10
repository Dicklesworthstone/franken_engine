#![forbid(unsafe_code)]
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

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use frankenengine_engine::seqlock_rollout_guard::{
    ArtifactContext, BEAD_ID, BundleWriteReport, COMPONENT, DOCS_CONTRACT_SCHEMA_VERSION,
    DocsContractFixture, GuardEvidenceVerdict, LOOM_COVERAGE_SCHEMA_VERSION,
    LoomScheduleCoverageReportArtifact, ManifestArtifactReference, PREDECESSOR_BEAD_ID,
    ROLLOUT_GUARD_SCHEMA_VERSION, RUN_MANIFEST_SCHEMA_VERSION, SAFETY_CASE_SCHEMA_VERSION,
    STARVATION_REPORT_SCHEMA_VERSION, SeqlockRolloutGuardArtifact, SeqlockSafetyCaseArtifact,
    StarvationMicrobenchReportArtifact, StructuredLogEvent, TRACE_IDS_SCHEMA_VERSION,
    TraceIdsArtifact, build_docs_contract_fixture, emit_default_rollout_bundle, render_summary,
    required_artifact_names,
};

fn temp_dir(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before epoch")
        .as_nanos();
    path.push(format!(
        "franken-engine-seqlock-rollout-it-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temp dir");
    path
}

fn make_context(label: &str) -> (PathBuf, ArtifactContext) {
    let artifact_dir = temp_dir(label);
    let mut context = ArtifactContext::new(&artifact_dir);
    context.run_id = format!("run-rgc-test-{label}");
    context.generated_at_utc = "2026-03-06T00:00:00Z".to_string();
    context.source_commit = "deadbeef".to_string();
    context.toolchain = "nightly".to_string();
    context.command_invocation = format!(
        "cargo run -p frankenengine-engine --bin franken_seqlock_rollout_guard -- --artifact-dir {}",
        artifact_dir.display()
    );
    (artifact_dir, context)
}

fn emit_bundle(label: &str) -> (PathBuf, BundleWriteReport) {
    let (artifact_dir, context) = make_context(label);
    let bundle = emit_default_rollout_bundle(&context).expect("bundle should write");
    (artifact_dir, bundle)
}

// ---- Original tests ----

#[test]
fn bundle_writes_required_artifacts_and_defaults_to_fail_closed_guard() {
    let (artifact_dir, bundle) = emit_bundle("bundle");

    for artifact in required_artifact_names() {
        assert!(
            artifact_dir.join(&artifact).exists(),
            "expected artifact `{artifact}` to exist",
        );
    }

    assert!(
        !artifact_dir.join(".seqlock_rollout_guard.lock").exists(),
        "bundle write lock should be cleaned up after publication"
    );

    let guard: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("seqlock_rollout_guard.json")).expect("read guard"),
    )
    .expect("guard should parse");
    assert_eq!(guard["all_candidates_disabled"].as_bool(), Some(true));
    let rows = guard["rows"].as_array().expect("guard rows");
    assert!(
        rows.iter()
            .all(|row| row["enabled"].as_bool() == Some(false)),
        "every candidate should remain disabled until model-check evidence is positive"
    );

    let loom: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("loom_schedule_coverage_report.json")).expect("read loom"),
    )
    .expect("loom report should parse");
    assert!(
        loom["rows"]
            .as_array()
            .expect("loom rows")
            .iter()
            .all(|row| row["verdict"].as_str() == Some("missing")),
        "default rollout guard should fail closed on missing loom/model-check evidence"
    );

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("run_manifest.json")).expect("read run manifest"),
    )
    .expect("run manifest should parse");
    assert_eq!(
        manifest["rollout_guard_hash"].as_str(),
        Some(bundle.rollout_guard.guard_hash.as_str())
    );
    assert_eq!(
        manifest["safety_case_hash"].as_str(),
        Some(bundle.safety_case.safety_case_hash.as_str())
    );

    let _ = fs::remove_dir_all(&artifact_dir);
}

#[test]
fn docs_contract_fixture_matches_checked_in_fixture() {
    let expected = build_docs_contract_fixture();
    let docs_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/rgc_seqlock_rollout_guard_v1.json");
    let actual: DocsContractFixture =
        serde_json::from_slice(&fs::read(&docs_path).expect("read docs fixture"))
            .expect("fixture should parse");

    assert_eq!(actual.schema_version, DOCS_CONTRACT_SCHEMA_VERSION);
    assert_eq!(actual, expected);
    assert!(
        actual
            .default_disabled_candidates
            .contains(&"governance-ledger-head-view".to_string())
    );
}

// ---- New tests ----

#[test]
fn docs_contract_fixture_serde_round_trip() {
    let fixture = build_docs_contract_fixture();
    let json = serde_json::to_string_pretty(&fixture).expect("serialize fixture");
    let deserialized: DocsContractFixture =
        serde_json::from_str(&json).expect("deserialize fixture");
    assert_eq!(fixture, deserialized);
}

#[test]
fn docs_contract_fixture_schema_version_format() {
    assert!(
        DOCS_CONTRACT_SCHEMA_VERSION.starts_with("franken-engine."),
        "schema version should have franken-engine prefix"
    );
    assert!(
        DOCS_CONTRACT_SCHEMA_VERSION.contains("docs"),
        "docs contract schema should mention docs"
    );
}

#[test]
fn docs_contract_fixture_has_all_three_candidates() {
    let fixture = build_docs_contract_fixture();
    let expected_candidates: BTreeSet<&str> = BTreeSet::from([
        "governance-ledger-head-view",
        "guardplane-calibration-snapshot",
        "module-cache-snapshot",
    ]);
    let actual: BTreeSet<&str> = fixture
        .default_disabled_candidates
        .iter()
        .map(|s| s.as_str())
        .collect();
    assert_eq!(actual, expected_candidates);
}

#[test]
fn docs_contract_fixture_required_artifacts_matches_function() {
    let fixture = build_docs_contract_fixture();
    let expected = required_artifact_names();
    assert_eq!(fixture.required_artifacts, expected);
}

#[test]
fn docs_contract_fixture_bead_id_matches_module_constant() {
    let fixture = build_docs_contract_fixture();
    assert_eq!(fixture.bead_id, BEAD_ID);
}

#[test]
fn docs_contract_fixture_candidates_are_sorted() {
    let fixture = build_docs_contract_fixture();
    let mut sorted = fixture.default_disabled_candidates.clone();
    sorted.sort();
    assert_eq!(fixture.default_disabled_candidates, sorted);
}

#[test]
fn artifact_context_default_fields_are_populated() {
    let dir = temp_dir("ctx-defaults");
    let context = ArtifactContext::new(&dir);
    assert!(!context.run_id.is_empty());
    assert!(!context.trace_id.is_empty());
    assert!(!context.decision_id.is_empty());
    assert!(!context.policy_id.is_empty());
    assert!(!context.generated_at_utc.is_empty());
    assert!(!context.toolchain.is_empty());
    assert!(!context.command_invocation.is_empty());
    assert_eq!(context.source_commit, "unknown");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn artifact_context_serde_round_trip() {
    let dir = temp_dir("ctx-serde");
    let context = ArtifactContext::new(&dir);
    let json = serde_json::to_string(&context).expect("serialize");
    let deser: ArtifactContext = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(context.run_id, deser.run_id);
    assert_eq!(context.trace_id, deser.trace_id);
    assert_eq!(context.decision_id, deser.decision_id);
    assert_eq!(context.policy_id, deser.policy_id);
    assert_eq!(context.generated_at_utc, deser.generated_at_utc);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn artifact_context_run_id_contains_component() {
    let dir = temp_dir("ctx-runid");
    let context = ArtifactContext::new(&dir);
    assert!(
        context.run_id.contains(COMPONENT),
        "run_id should include the component name"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn guard_hash_is_deterministic_across_calls() {
    let (dir1, bundle1) = emit_bundle("det1");
    let (dir2, bundle2) = emit_bundle("det2");
    assert_eq!(
        bundle1.rollout_guard.guard_hash, bundle2.rollout_guard.guard_hash,
        "guard hash should be deterministic for the same generated_at_utc"
    );
    let _ = fs::remove_dir_all(&dir1);
    let _ = fs::remove_dir_all(&dir2);
}

#[test]
fn safety_case_hash_is_deterministic_across_calls() {
    let (dir1, bundle1) = emit_bundle("sc-det1");
    let (dir2, bundle2) = emit_bundle("sc-det2");
    assert_eq!(
        bundle1.safety_case.safety_case_hash, bundle2.safety_case.safety_case_hash,
        "safety case hash should be deterministic"
    );
    let _ = fs::remove_dir_all(&dir1);
    let _ = fs::remove_dir_all(&dir2);
}

#[test]
fn starvation_report_hash_is_deterministic() {
    let (dir1, bundle1) = emit_bundle("sr-det1");
    let (dir2, bundle2) = emit_bundle("sr-det2");
    assert_eq!(
        bundle1.starvation_report.report_hash,
        bundle2.starvation_report.report_hash,
    );
    let _ = fs::remove_dir_all(&dir1);
    let _ = fs::remove_dir_all(&dir2);
}

#[test]
fn loom_coverage_hash_is_deterministic() {
    let (dir1, bundle1) = emit_bundle("lc-det1");
    let (dir2, bundle2) = emit_bundle("lc-det2");
    assert_eq!(
        bundle1.loom_coverage.report_hash,
        bundle2.loom_coverage.report_hash,
    );
    let _ = fs::remove_dir_all(&dir1);
    let _ = fs::remove_dir_all(&dir2);
}

#[test]
fn rollout_guard_all_candidates_disabled_is_true() {
    let (dir, bundle) = emit_bundle("all-disabled");
    assert!(bundle.rollout_guard.all_candidates_disabled);
    assert!(
        bundle.rollout_guard.rows.iter().all(|row| !row.enabled),
        "all rows should be disabled"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn rollout_guard_rows_have_required_artifacts() {
    let (dir, bundle) = emit_bundle("req-artifacts");
    for row in &bundle.rollout_guard.rows {
        assert!(!row.required_artifacts.is_empty());
        assert!(
            row.required_artifacts
                .contains(&"seqlock_safety_case.json".to_string())
        );
        assert!(
            row.required_artifacts
                .contains(&"starvation_microbench_report.json".to_string())
        );
        assert!(
            row.required_artifacts
                .contains(&"loom_schedule_coverage_report.json".to_string())
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn rollout_guard_rows_have_disable_reasons() {
    let (dir, bundle) = emit_bundle("disable-reasons");
    for row in &bundle.rollout_guard.rows {
        assert!(
            !row.disable_reasons.is_empty(),
            "each disabled row should have at least one disable reason"
        );
        assert!(
            row.disable_reasons
                .contains(&"model_check_evidence_missing".to_string()),
            "model_check_evidence_missing should be a disable reason"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn safety_case_rows_all_have_model_check_missing() {
    let (dir, bundle) = emit_bundle("sc-missing");
    for row in &bundle.safety_case.rows {
        assert_eq!(row.model_check_verdict, GuardEvidenceVerdict::Missing);
        assert!(!row.rollout_allowed);
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn safety_case_starvation_verdicts_pass() {
    let (dir, bundle) = emit_bundle("sc-starv-pass");
    for row in &bundle.safety_case.rows {
        assert_eq!(
            row.starvation_verdict,
            GuardEvidenceVerdict::Pass,
            "starvation microbench should pass for all accepted candidates"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn safety_case_schema_version_is_correct() {
    let (dir, bundle) = emit_bundle("sc-schema");
    assert_eq!(
        bundle.safety_case.schema_version,
        SAFETY_CASE_SCHEMA_VERSION
    );
    assert_eq!(bundle.safety_case.bead_id, BEAD_ID);
    assert_eq!(bundle.safety_case.predecessor_bead_id, PREDECESSOR_BEAD_ID);
    assert_eq!(bundle.safety_case.component, COMPONENT);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn starvation_report_schema_and_metadata() {
    let (dir, bundle) = emit_bundle("sr-meta");
    assert_eq!(
        bundle.starvation_report.schema_version,
        STARVATION_REPORT_SCHEMA_VERSION
    );
    assert_eq!(bundle.starvation_report.bead_id, BEAD_ID);
    assert_eq!(bundle.starvation_report.component, COMPONENT);
    assert!(!bundle.starvation_report.rows.is_empty());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn loom_coverage_schema_and_all_missing() {
    let (dir, bundle) = emit_bundle("lc-missing");
    assert_eq!(
        bundle.loom_coverage.schema_version,
        LOOM_COVERAGE_SCHEMA_VERSION
    );
    for row in &bundle.loom_coverage.rows {
        assert_eq!(row.verdict, GuardEvidenceVerdict::Missing);
        assert_eq!(row.loom_schedule_count, 0);
        assert!(!row.manual_schedule_cases.is_empty());
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn loom_coverage_manual_schedule_cases_include_writer_pressure() {
    let (dir, bundle) = emit_bundle("lc-cases");
    for row in &bundle.loom_coverage.rows {
        assert!(
            row.manual_schedule_cases
                .contains(&"writer_pressure_fallback".to_string()),
            "writer_pressure_fallback should be a manual schedule case"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn bundle_written_files_map_has_sha256_hashes() {
    let (dir, bundle) = emit_bundle("written-files");
    assert!(!bundle.written_files.is_empty());
    for (name, hash) in &bundle.written_files {
        assert!(
            hash.starts_with("sha256:"),
            "hash for {name} should start with sha256: prefix"
        );
        let hex_part = &hash["sha256:".len()..];
        assert_eq!(
            hex_part.len(),
            64,
            "sha256 hex should be 64 chars for {name}"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn bundle_written_files_include_all_required_artifacts() {
    let (dir, bundle) = emit_bundle("written-all");
    let required = required_artifact_names();
    for name in &required {
        assert!(
            bundle.written_files.contains_key(name),
            "written_files should include {name}"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn events_jsonl_contains_structured_log_events() {
    let (dir, _bundle) = emit_bundle("events");
    let events_raw = fs::read_to_string(dir.join("events.jsonl")).expect("read events");
    let lines: Vec<&str> = events_raw.lines().collect();
    assert!(
        !lines.is_empty(),
        "events.jsonl should contain at least one log line"
    );
    for line in &lines {
        let event: StructuredLogEvent =
            serde_json::from_str(line).expect("each events.jsonl line should parse");
        assert!(!event.trace_id.is_empty());
        assert!(!event.component.is_empty());
        assert!(!event.event.is_empty());
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn events_jsonl_contains_gate_completed_event() {
    let (dir, _bundle) = emit_bundle("gate-event");
    let events_raw = fs::read_to_string(dir.join("events.jsonl")).expect("read events");
    let events: Vec<StructuredLogEvent> = events_raw
        .lines()
        .map(|line| serde_json::from_str(line).expect("parse event"))
        .collect();
    let gate_completed = events
        .iter()
        .find(|e| e.event == "gate_completed")
        .expect("should have gate_completed event");
    assert!(gate_completed.outcome.contains("disabled"));
    assert!(gate_completed.candidate_id.is_none());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn trace_ids_json_validation() {
    let (dir, _bundle) = emit_bundle("trace-ids");
    let trace_ids: TraceIdsArtifact =
        serde_json::from_slice(&fs::read(dir.join("trace_ids.json")).expect("read trace_ids"))
            .expect("parse trace_ids");
    assert_eq!(trace_ids.schema_version, TRACE_IDS_SCHEMA_VERSION);
    assert!(!trace_ids.trace_ids.is_empty());
    assert!(!trace_ids.decision_id.is_empty());
    assert!(!trace_ids.policy_id.is_empty());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn env_json_validation() {
    let (dir, _bundle) = emit_bundle("env-json");
    let env_val: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("env.json")).expect("read env"))
            .expect("parse env");
    assert_eq!(
        env_val["schema_version"].as_str(),
        Some("franken-engine.env.v1")
    );
    assert_eq!(env_val["project"]["name"].as_str(), Some("franken_engine"));
    assert_eq!(env_val["project"]["bead_id"].as_str(), Some(BEAD_ID));
    assert_eq!(env_val["project"]["commit"].as_str(), Some("deadbeef"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn commands_txt_validation() {
    let (dir, _bundle) = emit_bundle("commands");
    let commands = fs::read_to_string(dir.join("commands.txt")).expect("read commands");
    assert!(
        commands.contains("franken_seqlock_rollout_guard"),
        "commands should reference the binary"
    );
    assert!(
        commands.contains("jq"),
        "commands should include jq inspection"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn repro_lock_validation() {
    let (dir, _bundle) = emit_bundle("repro");
    let repro: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("repro.lock")).expect("read repro"))
            .expect("parse repro");
    assert_eq!(
        repro["schema_version"].as_str(),
        Some("franken-engine.repro-lock.v1")
    );
    assert_eq!(repro["bead_id"].as_str(), Some(BEAD_ID));
    let commands = repro["commands"].as_array().expect("commands array");
    assert!(!commands.is_empty());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn manifest_json_has_claim_and_provenance() {
    let (dir, _bundle) = emit_bundle("manifest-claim");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("manifest.json")).expect("read manifest"))
            .expect("parse manifest");
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("franken-engine.manifest.v1")
    );
    assert!(manifest["claim"]["statement"].as_str().is_some());
    assert_eq!(manifest["claim"]["status"].as_str(), Some("fail_closed"));
    assert!(manifest["provenance"]["trace_id"].as_str().is_some());
    assert!(manifest["provenance"]["decision_id"].as_str().is_some());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn manifest_json_artifacts_list_non_empty() {
    let (dir, _bundle) = emit_bundle("manifest-arts");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("manifest.json")).expect("read manifest"))
            .expect("parse manifest");
    let artifacts = manifest["artifacts"].as_array().expect("artifacts");
    assert!(!artifacts.is_empty());
    for artifact in artifacts {
        assert!(artifact["path"].as_str().is_some());
        let sha = artifact["sha256"].as_str().expect("sha256 field");
        assert!(sha.starts_with("sha256:"));
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn run_manifest_has_all_hash_fields() {
    let (dir, bundle) = emit_bundle("run-manifest");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(dir.join("run_manifest.json")).expect("read run manifest"),
    )
    .expect("parse run manifest");
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some(RUN_MANIFEST_SCHEMA_VERSION)
    );
    assert_eq!(manifest["bead_id"].as_str(), Some(BEAD_ID));
    assert_eq!(manifest["component"].as_str(), Some(COMPONENT));
    assert!(manifest["starvation_report_hash"].as_str().is_some());
    assert!(manifest["loom_schedule_coverage_hash"].as_str().is_some());
    assert_eq!(
        manifest["rollout_guard_hash"].as_str(),
        Some(bundle.rollout_guard.guard_hash.as_str())
    );
    assert_eq!(
        manifest["safety_case_hash"].as_str(),
        Some(bundle.safety_case.safety_case_hash.as_str())
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn summary_md_structure_validation() {
    let (dir, bundle) = emit_bundle("summary-md");
    let summary = fs::read_to_string(dir.join("summary.md")).expect("read summary");
    assert!(summary.starts_with("# Seqlock Rollout Guard Summary"));
    assert!(summary.contains("## Enabled"));
    assert!(summary.contains("## Disabled"));
    assert!(summary.contains(&bundle.rollout_guard.guard_hash));
    assert!(summary.contains(&bundle.safety_case.safety_case_hash));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn summary_md_lists_disabled_candidates() {
    let (dir, bundle) = emit_bundle("summary-disabled");
    let summary = fs::read_to_string(dir.join("summary.md")).expect("read summary");
    for row in &bundle.rollout_guard.rows {
        assert!(
            summary.contains(&row.candidate_id),
            "summary should mention disabled candidate {}",
            row.candidate_id
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn render_summary_produces_valid_markdown() {
    let (dir, bundle) = emit_bundle("render-summary");
    let md = render_summary(&bundle.safety_case, &bundle.rollout_guard);
    assert!(md.starts_with("# "));
    assert!(md.contains("## Enabled"));
    assert!(md.contains("## Disabled"));
    assert!(
        md.contains("none (fail-closed"),
        "should indicate no candidates enabled"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn starvation_report_observations_have_burst_data() {
    let (dir, bundle) = emit_bundle("starv-obs");
    for row in &bundle.starvation_report.rows {
        assert_eq!(row.burst_writes, 3);
        assert_eq!(row.observations.len(), 3);
        for obs in &row.observations {
            assert!(obs.committed_value > 0);
        }
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn starvation_report_all_verdicts_pass() {
    let (dir, bundle) = emit_bundle("starv-verdicts");
    for row in &bundle.starvation_report.rows {
        assert_eq!(
            row.verdict,
            GuardEvidenceVerdict::Pass,
            "starvation should pass for candidate {}",
            row.candidate_id
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn starvation_report_telemetry_consistent_with_burst_writes() {
    let (dir, bundle) = emit_bundle("starv-telemetry");
    for row in &bundle.starvation_report.rows {
        let bw = row.burst_writes as u64;
        assert_eq!(row.telemetry.writer_pressure_fallbacks, bw);
        assert_eq!(row.telemetry.fast_path_reads, bw);
        assert_eq!(row.telemetry.fallback_reads, bw);
        assert_eq!(row.telemetry.writes, bw);
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn guard_evidence_verdict_serde_round_trip() {
    for verdict in [
        GuardEvidenceVerdict::Pass,
        GuardEvidenceVerdict::Missing,
        GuardEvidenceVerdict::Fail,
    ] {
        let json = serde_json::to_string(&verdict).expect("serialize verdict");
        let deser: GuardEvidenceVerdict = serde_json::from_str(&json).expect("deserialize verdict");
        assert_eq!(verdict, deser);
    }
}

#[test]
fn guard_evidence_verdict_serde_uses_snake_case() {
    let pass_json = serde_json::to_string(&GuardEvidenceVerdict::Pass).expect("serialize");
    assert_eq!(pass_json, "\"pass\"");
    let missing_json = serde_json::to_string(&GuardEvidenceVerdict::Missing).expect("serialize");
    assert_eq!(missing_json, "\"missing\"");
    let fail_json = serde_json::to_string(&GuardEvidenceVerdict::Fail).expect("serialize");
    assert_eq!(fail_json, "\"fail\"");
}

#[test]
fn required_artifact_names_are_sorted() {
    let names = required_artifact_names();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(
        names, sorted,
        "required artifact names should be in sorted order"
    );
}

#[test]
fn required_artifact_names_count() {
    let names = required_artifact_names();
    assert_eq!(names.len(), 12, "should have exactly 12 required artifacts");
}

#[test]
fn bundle_report_serde_round_trip() {
    let (dir, bundle) = emit_bundle("bundle-serde");
    let json = serde_json::to_string(&bundle).expect("serialize bundle report");
    let deser: BundleWriteReport = serde_json::from_str(&json).expect("deserialize bundle report");
    assert_eq!(
        bundle.rollout_guard.guard_hash,
        deser.rollout_guard.guard_hash
    );
    assert_eq!(
        bundle.safety_case.safety_case_hash,
        deser.safety_case.safety_case_hash
    );
    assert_eq!(bundle.written_files, deser.written_files);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn rollout_guard_artifact_serde_round_trip() {
    let (dir, bundle) = emit_bundle("guard-serde");
    let json = serde_json::to_string_pretty(&bundle.rollout_guard).expect("serialize");
    let deser: SeqlockRolloutGuardArtifact = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(bundle.rollout_guard, deser);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn safety_case_artifact_serde_round_trip() {
    let (dir, bundle) = emit_bundle("sc-serde");
    let json = serde_json::to_string_pretty(&bundle.safety_case).expect("serialize");
    let deser: SeqlockSafetyCaseArtifact = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(bundle.safety_case, deser);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn starvation_report_serde_round_trip() {
    let (dir, bundle) = emit_bundle("sr-serde");
    let json = serde_json::to_string_pretty(&bundle.starvation_report).expect("serialize");
    let deser: StarvationMicrobenchReportArtifact =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(bundle.starvation_report, deser);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn loom_coverage_serde_round_trip() {
    let (dir, bundle) = emit_bundle("lc-serde");
    let json = serde_json::to_string_pretty(&bundle.loom_coverage).expect("serialize");
    let deser: LoomScheduleCoverageReportArtifact =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(bundle.loom_coverage, deser);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn schema_version_constants_are_prefixed() {
    for version in [
        SAFETY_CASE_SCHEMA_VERSION,
        STARVATION_REPORT_SCHEMA_VERSION,
        LOOM_COVERAGE_SCHEMA_VERSION,
        ROLLOUT_GUARD_SCHEMA_VERSION,
        TRACE_IDS_SCHEMA_VERSION,
        RUN_MANIFEST_SCHEMA_VERSION,
        DOCS_CONTRACT_SCHEMA_VERSION,
    ] {
        assert!(
            version.starts_with("franken-engine."),
            "schema version `{version}` should have franken-engine prefix"
        );
        assert!(
            version.ends_with(".v1"),
            "schema version `{version}` should end with .v1"
        );
    }
}

#[test]
fn bead_id_and_predecessor_are_hierarchical() {
    assert!(BEAD_ID.starts_with("bd-"));
    assert!(PREDECESSOR_BEAD_ID.starts_with("bd-"));
    assert_ne!(BEAD_ID, PREDECESSOR_BEAD_ID);
}

#[test]
fn component_constant_matches_module_name() {
    assert_eq!(COMPONENT, "seqlock_rollout_guard");
}

#[test]
fn bundle_artifact_dir_matches_context() {
    let (dir, bundle) = emit_bundle("art-dir");
    assert_eq!(bundle.artifact_dir, dir);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn bundle_trace_ids_path_points_to_existing_file() {
    let (dir, bundle) = emit_bundle("trace-path");
    assert!(
        bundle.trace_ids_path.exists(),
        "trace_ids_path should point to an existing file"
    );
    assert!(
        bundle.trace_ids_path.ends_with("trace_ids.json"),
        "trace_ids_path should end with trace_ids.json"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn events_jsonl_has_model_check_events_with_error_codes() {
    let (dir, _bundle) = emit_bundle("events-errcode");
    let events_raw = fs::read_to_string(dir.join("events.jsonl")).expect("read events");
    let events: Vec<StructuredLogEvent> = events_raw
        .lines()
        .map(|line| serde_json::from_str(line).expect("parse event"))
        .collect();
    let model_check_events: Vec<&StructuredLogEvent> = events
        .iter()
        .filter(|e| e.event == "model_check_evidence_evaluated")
        .collect();
    assert!(!model_check_events.is_empty());
    for event in &model_check_events {
        assert_eq!(event.outcome, "missing");
        assert_eq!(event.error_code.as_deref(), Some("FE-SEQLOCK-ROLL-0001"));
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn events_jsonl_has_rollout_guard_evaluated_events() {
    let (dir, _bundle) = emit_bundle("events-guard");
    let events_raw = fs::read_to_string(dir.join("events.jsonl")).expect("read events");
    let events: Vec<StructuredLogEvent> = events_raw
        .lines()
        .map(|line| serde_json::from_str(line).expect("parse event"))
        .collect();
    let guard_events: Vec<&StructuredLogEvent> = events
        .iter()
        .filter(|e| e.event == "rollout_guard_evaluated")
        .collect();
    assert!(!guard_events.is_empty());
    for event in &guard_events {
        assert_eq!(event.outcome, "disabled");
        assert_eq!(event.error_code.as_deref(), Some("FE-SEQLOCK-ROLL-0002"));
        assert!(event.candidate_id.is_some());
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn events_jsonl_has_starvation_evaluated_events() {
    let (dir, _bundle) = emit_bundle("events-starv");
    let events_raw = fs::read_to_string(dir.join("events.jsonl")).expect("read events");
    let events: Vec<StructuredLogEvent> = events_raw
        .lines()
        .map(|line| serde_json::from_str(line).expect("parse event"))
        .collect();
    let starv_events: Vec<&StructuredLogEvent> = events
        .iter()
        .filter(|e| e.event == "starvation_microbench_evaluated")
        .collect();
    assert!(!starv_events.is_empty());
    for event in &starv_events {
        assert_eq!(event.outcome, "pass");
        assert!(event.candidate_id.is_some());
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn manifest_artifact_reference_serde_round_trip() {
    let reference = ManifestArtifactReference {
        path: "seqlock_rollout_guard.json".to_string(),
        sha256: "sha256:abc123".to_string(),
    };
    let json = serde_json::to_string(&reference).expect("serialize");
    let deser: ManifestArtifactReference = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(reference, deser);
}
