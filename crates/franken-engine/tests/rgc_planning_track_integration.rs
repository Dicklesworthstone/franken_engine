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

use std::fs;
use std::path::PathBuf;

use chrono::{TimeZone, Utc};
use frankenengine_engine::rgc_planning_track::{
    BEAD_ID, EVENT_SCHEMA_VERSION, MILESTONE_GATEBOOK_SCHEMA_VERSION,
    RISK_ACCEPTANCE_LEDGER_SCHEMA_VERSION, SCHEMA_VERSION, SCOPE_CONTRACT_SCHEMA_VERSION,
    WAVE_HANDOFF_MATRIX_SCHEMA_VERSION, build_rgc_planning_track_bundle_with_generated_at,
    write_rgc_planning_track_bundle,
};
use serde_json::Value;
use uuid::Uuid;

const DOC_JSON: &str = include_str!("../../../docs/rgc_planning_track_v1.json");

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn unique_temp_dir(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push("franken_engine_rgc_planning_track");
    path.push(name);
    path.push(Uuid::now_v7().to_string());
    fs::create_dir_all(&path).expect("create temp dir");
    path
}

#[test]
fn rgc_010_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_PLANNING_TRACK_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# RGC Planning Track V1",
        "## Purpose",
        "## Input Contracts",
        "## Emitted Artifacts",
        "## Fail-Closed Policies",
        "## Transition Logging",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "missing required section in {}: {section}",
            path.display()
        );
    }
}

#[test]
fn rgc_010_contract_doc_is_versioned_and_links_source_contracts() {
    let doc: Value = serde_json::from_str(DOC_JSON).expect("doc json must parse");

    assert_eq!(doc["schema_version"], "rgc.planning-track.v1");
    assert_eq!(doc["bead_id"], BEAD_ID);
    assert_eq!(doc["track"]["id"], "RGC-010");

    let source_contracts = doc["source_contracts"]
        .as_array()
        .expect("source_contracts array");
    assert_eq!(source_contracts.len(), 4);
    for source in source_contracts {
        let source_json = source["source_json"].as_str().expect("source_json");
        assert!(
            repo_root().join(source_json).exists(),
            "source json must exist: {source_json}"
        );
    }

    let emitted_artifacts = doc["emitted_artifacts"]
        .as_array()
        .expect("emitted_artifacts array");
    assert!(emitted_artifacts.iter().any(|artifact| {
        artifact["file"].as_str().expect("artifact file") == "scope_contract_snapshot.json"
    }));
}

#[test]
fn planning_track_bundle_emits_required_artifacts_and_manifest() {
    let out_dir = unique_temp_dir("bundle");
    let argv = vec![
        "franken_rgc_planning_track".to_string(),
        "--out-dir".to_string(),
        out_dir.display().to_string(),
    ];

    let artifacts = write_rgc_planning_track_bundle(&out_dir, &argv).expect("write bundle");

    for path in [
        &artifacts.scope_contract_snapshot_path,
        &artifacts.milestone_gatebook_path,
        &artifacts.risk_acceptance_ledger_path,
        &artifacts.wave_handoff_matrix_path,
        &artifacts.run_manifest_path,
        &artifacts.events_path,
        &artifacts.commands_path,
        &artifacts.summary_path,
        &artifacts.trace_ids_path,
    ] {
        assert!(path.exists(), "missing emitted artifact {}", path.display());
    }

    let manifest: Value =
        serde_json::from_slice(&fs::read(&artifacts.run_manifest_path).expect("read run_manifest"))
            .expect("parse run_manifest");
    assert_eq!(manifest["schema_version"], SCHEMA_VERSION);
    assert_eq!(
        manifest["scope_contract_snapshot"],
        "scope_contract_snapshot.json"
    );
    assert_eq!(manifest["milestone_gatebook"], "milestone_gatebook.json");
    assert_eq!(
        manifest["risk_acceptance_ledger"],
        "risk_acceptance_ledger.json"
    );
    assert_eq!(manifest["wave_handoff_matrix"], "wave_handoff_matrix.json");
}

#[test]
fn planning_track_artifact_schemas_are_stable() {
    let bundle =
        build_rgc_planning_track_bundle_with_generated_at(1_772_467_200_000).expect("build bundle");

    assert_eq!(bundle.schema_version, SCHEMA_VERSION);
    assert_eq!(
        bundle.scope_contract_snapshot.schema_version,
        SCOPE_CONTRACT_SCHEMA_VERSION
    );
    assert_eq!(
        bundle.milestone_gatebook.schema_version,
        MILESTONE_GATEBOOK_SCHEMA_VERSION
    );
    assert_eq!(
        bundle.risk_acceptance_ledger.schema_version,
        RISK_ACCEPTANCE_LEDGER_SCHEMA_VERSION
    );
    assert_eq!(
        bundle.wave_handoff_matrix.schema_version,
        WAVE_HANDOFF_MATRIX_SCHEMA_VERSION
    );
}

#[test]
fn risk_acceptance_expiry_rules_fail_closed_after_due_date() {
    let before_due = Utc.with_ymd_and_hms(2026, 3, 1, 0, 0, 0).single().unwrap();
    let after_due = Utc.with_ymd_and_hms(2026, 3, 13, 0, 0, 0).single().unwrap();

    let before = build_rgc_planning_track_bundle_with_generated_at(
        u64::try_from(before_due.timestamp_millis()).unwrap(),
    )
    .expect("build before-due bundle");
    let after = build_rgc_planning_track_bundle_with_generated_at(
        u64::try_from(after_due.timestamp_millis()).unwrap(),
    )
    .expect("build after-due bundle");

    assert!(before.risk_acceptance_ledger.all_acceptances_current);
    assert!(!after.risk_acceptance_ledger.all_acceptances_current);
    assert!(
        after
            .risk_acceptance_ledger
            .expired_risk_ids
            .contains(&"RGC-RISK-001".to_string())
    );
}

#[test]
fn dependency_order_and_wave_handoff_remain_valid() {
    let bundle =
        build_rgc_planning_track_bundle_with_generated_at(1_772_467_200_000).expect("build bundle");

    assert!(bundle.milestone_gatebook.dependency_order_preserved);
    assert!(bundle.milestone_gatebook.all_cargo_commands_rch_backed);
    assert!(bundle.wave_handoff_matrix.protocol_validation.valid);
    assert!(bundle.wave_handoff_matrix.handoff_validation.valid);
    assert!(bundle.wave_handoff_matrix.transition_validation.valid);
    assert_eq!(
        bundle.wave_handoff_matrix.coordination_dry_run.events.len(),
        4
    );
}

#[test]
fn commands_and_event_artifacts_are_replayable() {
    let out_dir = unique_temp_dir("commands");
    let argv = vec![
        "franken_rgc_planning_track".to_string(),
        "--out-dir".to_string(),
        out_dir.display().to_string(),
    ];

    let artifacts = write_rgc_planning_track_bundle(&out_dir, &argv).expect("write bundle");
    let commands = fs::read_to_string(&artifacts.commands_path).expect("read commands");
    assert!(commands.contains("scripts/e2e/run_rgc_planning_track.sh"));
    assert!(commands.contains("rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_rgc_planning_track cargo run -p frankenengine-engine --bin franken_rgc_planning_track"));
    assert!(
        commands
            .contains("cargo check -p frankenengine-engine --test rgc_planning_track_integration")
    );

    let events = fs::read_to_string(&artifacts.events_path).expect("read events");
    let event_lines: Vec<&str> = events.lines().collect();
    assert_eq!(event_lines.len(), 5);
    for line in &event_lines {
        let event: Value = serde_json::from_str(line).expect("event json");
        assert_eq!(event["schema_version"], EVENT_SCHEMA_VERSION);
        assert_eq!(event["component"], "rgc_planning_track");
    }

    let trace_ids = fs::read_to_string(&artifacts.trace_ids_path).expect("read trace_ids");
    assert_eq!(trace_ids.lines().count(), 5);
}
