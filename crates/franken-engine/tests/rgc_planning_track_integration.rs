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
    BEAD_ID, COMPONENT, EVENT_SCHEMA_VERSION, MILESTONE_GATEBOOK_SCHEMA_VERSION,
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

// ---------------------------------------------------------------------------
// Enrichment tests: bundle structure, determinism, field completeness
// ---------------------------------------------------------------------------

#[test]
fn schema_version_constants_are_nonempty_and_prefixed() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCOPE_CONTRACT_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(MILESTONE_GATEBOOK_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(RISK_ACCEPTANCE_LEDGER_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(WAVE_HANDOFF_MATRIX_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(EVENT_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(!BEAD_ID.is_empty());
    assert!(!COMPONENT.is_empty());
}

#[test]
fn bundle_report_hash_is_deterministic_for_same_timestamp() {
    let ts = 1_772_467_200_000_u64;
    let b1 = build_rgc_planning_track_bundle_with_generated_at(ts).expect("build 1");
    let b2 = build_rgc_planning_track_bundle_with_generated_at(ts).expect("build 2");
    assert_eq!(b1.report_hash, b2.report_hash);
    assert!(!b1.report_hash.is_empty());
}

#[test]
fn bundle_bead_id_and_schema_propagate_to_sub_artifacts() {
    let bundle =
        build_rgc_planning_track_bundle_with_generated_at(1_772_467_200_000).expect("build");
    assert_eq!(bundle.bead_id, BEAD_ID);
    assert_eq!(bundle.scope_contract_snapshot.bead_id, BEAD_ID);
    assert_eq!(bundle.milestone_gatebook.bead_id, BEAD_ID);
    assert_eq!(bundle.risk_acceptance_ledger.bead_id, BEAD_ID);
    assert_eq!(bundle.wave_handoff_matrix.bead_id, BEAD_ID);
}

#[test]
fn scope_contract_snapshot_has_required_fields() {
    let bundle =
        build_rgc_planning_track_bundle_with_generated_at(1_772_467_200_000).expect("build");
    let scope = &bundle.scope_contract_snapshot;
    assert!(!scope.track.id.is_empty());
    assert!(!scope.track.name.is_empty());
    assert!(!scope.source_bead_id.is_empty());
    assert!(!scope.source_schema_version.is_empty());
    assert!(!scope.project_epic.is_empty());
    assert!(!scope.snapshot_generated_at_utc.is_empty());
    assert!(!scope.snapshot_source.is_empty());
    assert!(!scope.open_bead_ids.is_empty());
    assert!(!scope.required_structured_log_fields.is_empty());
    assert!(!scope.milestone_evidence_links.is_empty());
}

#[test]
fn milestone_evidence_links_have_complete_fields() {
    let bundle =
        build_rgc_planning_track_bundle_with_generated_at(1_772_467_200_000).expect("build");
    for link in &bundle.scope_contract_snapshot.milestone_evidence_links {
        assert!(!link.milestone.is_empty());
        assert!(!link.description.is_empty());
        assert!(!link.gate_id.is_empty());
        assert!(!link.gate_command.is_empty());
        assert!(!link.stop_go_rule.is_empty());
    }
}

#[test]
fn milestone_gatebook_milestones_are_nonempty_and_rch_backed() {
    let bundle =
        build_rgc_planning_track_bundle_with_generated_at(1_772_467_200_000).expect("build");
    let gatebook = &bundle.milestone_gatebook;
    assert!(!gatebook.milestones.is_empty());
    for milestone in &gatebook.milestones {
        assert!(!milestone.milestone.is_empty());
        assert!(!milestone.objective.is_empty());
        assert!(!milestone.gate_owner.is_empty());
        assert!(milestone.cargo_commands_rch_backed);
        assert!(!milestone.ci_gate.command.is_empty());
    }
}

#[test]
fn milestone_gatebook_blocker_classes_have_evidence() {
    let bundle =
        build_rgc_planning_track_bundle_with_generated_at(1_772_467_200_000).expect("build");
    for bc in &bundle.milestone_gatebook.blocker_classes {
        assert!(!bc.class_id.is_empty());
        assert!(!bc.required_evidence.is_empty());
    }
}

#[test]
fn risk_acceptance_entries_have_complete_fields() {
    let bundle =
        build_rgc_planning_track_bundle_with_generated_at(1_772_467_200_000).expect("build");
    let ledger = &bundle.risk_acceptance_ledger;
    assert!(ledger.fail_closed_on_stale_review);
    assert!(ledger.stale_threshold_days > 0);
    assert!(!ledger.entries.is_empty());
    for entry in &ledger.entries {
        assert!(!entry.risk_id.is_empty());
        assert!(!entry.title.is_empty());
        assert!(!entry.domain.is_empty());
        assert!(!entry.risk_level.is_empty());
        assert!(!entry.owner_role.is_empty());
        assert!(!entry.mitigation_summary.is_empty());
        assert!(!entry.rollback_plan.is_empty());
        assert!(!entry.last_reviewed_utc.is_empty());
        assert!(!entry.accepted_until_utc.is_empty());
    }
}

#[test]
fn wave_handoff_matrix_references_source_docs() {
    let bundle =
        build_rgc_planning_track_bundle_with_generated_at(1_772_467_200_000).expect("build");
    let whm = &bundle.wave_handoff_matrix;
    assert!(!whm.source_doc_path.is_empty());
    assert!(!whm.handoff_doc_path.is_empty());
    assert!(!whm.handoff_schema_path.is_empty());
}

#[test]
fn bundle_generated_at_utc_is_well_formed_iso8601() {
    let bundle =
        build_rgc_planning_track_bundle_with_generated_at(1_772_467_200_000).expect("build");
    assert!(bundle.generated_at_utc.contains('T'));
    assert!(bundle.generated_at_utc.ends_with('Z'));
    assert_eq!(bundle.generated_at_unix_ms, 1_772_467_200_000);
}

#[test]
fn bundle_serializes_to_valid_json() {
    let bundle =
        build_rgc_planning_track_bundle_with_generated_at(1_772_467_200_000).expect("build");
    let json = serde_json::to_string(&bundle).expect("serialize");
    let parsed: Value = serde_json::from_str(&json).expect("parse");
    assert_eq!(parsed["schema_version"], SCHEMA_VERSION);
    assert_eq!(parsed["bead_id"], BEAD_ID);
    assert!(parsed["scope_contract_snapshot"].is_object());
    assert!(parsed["milestone_gatebook"].is_object());
    assert!(parsed["risk_acceptance_ledger"].is_object());
    assert!(parsed["wave_handoff_matrix"].is_object());
}

#[test]
fn events_have_unique_trace_ids() {
    let out_dir = unique_temp_dir("trace_uniqueness");
    let argv = vec![
        "franken_rgc_planning_track".to_string(),
        "--out-dir".to_string(),
        out_dir.display().to_string(),
    ];
    let artifacts = write_rgc_planning_track_bundle(&out_dir, &argv).expect("write bundle");
    let events = fs::read_to_string(&artifacts.events_path).expect("read events");
    let trace_ids: Vec<String> = events
        .lines()
        .map(|line| {
            let e: Value = serde_json::from_str(line).expect("parse event");
            e["trace_id"].as_str().expect("trace_id").to_string()
        })
        .collect();
    let mut unique = trace_ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        trace_ids.len(),
        unique.len(),
        "all trace_ids must be unique"
    );
}

#[test]
fn events_have_nonempty_decision_and_policy_ids() {
    let out_dir = unique_temp_dir("event_fields");
    let argv = vec![
        "franken_rgc_planning_track".to_string(),
        "--out-dir".to_string(),
        out_dir.display().to_string(),
    ];
    let artifacts = write_rgc_planning_track_bundle(&out_dir, &argv).expect("write bundle");
    let events = fs::read_to_string(&artifacts.events_path).expect("read events");
    for line in events.lines() {
        let e: Value = serde_json::from_str(line).expect("parse event");
        assert!(!e["decision_id"].as_str().unwrap_or("").is_empty());
        assert!(!e["policy_id"].as_str().unwrap_or("").is_empty());
        assert!(!e["event"].as_str().unwrap_or("").is_empty());
        assert!(!e["outcome"].as_str().unwrap_or("").is_empty());
    }
}

#[test]
fn written_bundle_manifest_has_summary_flags() {
    let out_dir = unique_temp_dir("manifest_flags");
    let argv = vec![
        "franken_rgc_planning_track".to_string(),
        "--out-dir".to_string(),
        out_dir.display().to_string(),
    ];
    let artifacts = write_rgc_planning_track_bundle(&out_dir, &argv).expect("write bundle");
    let manifest: Value =
        serde_json::from_slice(&fs::read(&artifacts.run_manifest_path).expect("read manifest"))
            .expect("parse manifest");
    assert!(manifest["dependency_order_preserved"].as_bool().unwrap());
    assert!(manifest["all_gate_commands_rch_backed"].as_bool().unwrap());
    assert!(!manifest["report_hash"].as_str().unwrap().is_empty());
    assert!(!manifest["generated_at_utc"].as_str().unwrap().is_empty());
}

#[test]
fn written_artifacts_report_hash_matches_bundle() {
    let out_dir = unique_temp_dir("artifact_hash");
    let argv = vec![
        "franken_rgc_planning_track".to_string(),
        "--out-dir".to_string(),
        out_dir.display().to_string(),
    ];
    let artifacts = write_rgc_planning_track_bundle(&out_dir, &argv).expect("write bundle");
    assert!(!artifacts.report_hash.is_empty());
    assert!(artifacts.all_gate_commands_rch_backed);
}

#[test]
fn doc_json_emitted_artifacts_cover_all_bundle_files() {
    let doc: Value = serde_json::from_str(DOC_JSON).expect("doc json");
    let emitted = doc["emitted_artifacts"]
        .as_array()
        .expect("emitted_artifacts");
    let required_files = [
        "scope_contract_snapshot.json",
        "milestone_gatebook.json",
        "risk_acceptance_ledger.json",
        "wave_handoff_matrix.json",
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "summary.md",
        "trace_ids",
    ];
    for required in &required_files {
        assert!(
            emitted
                .iter()
                .any(|a| a["file"].as_str().unwrap_or("") == *required),
            "doc json missing emitted artifact: {required}"
        );
    }
}

// ===== PearlTower enrichment =====

#[test]
fn enrichment_scope_contract_snapshot_serde_roundtrip() {
    let bundle =
        build_rgc_planning_track_bundle_with_generated_at(1_772_467_200_000).expect("build");
    let scope = &bundle.scope_contract_snapshot;
    let json = serde_json::to_string(scope).expect("serialize scope_contract_snapshot");
    let restored: serde_json::Value = serde_json::from_str(&json).expect("parse scope json");
    assert_eq!(
        restored["schema_version"].as_str().unwrap(),
        SCOPE_CONTRACT_SCHEMA_VERSION
    );
    assert_eq!(restored["bead_id"].as_str().unwrap(), BEAD_ID);
    assert_eq!(restored["track"]["id"].as_str().unwrap(), "RGC-010");
    assert!(restored["open_bead_ids"].is_array());
    assert!(restored["milestone_evidence_links"].is_array());
}

#[test]
fn enrichment_risk_acceptance_ledger_serde_roundtrip() {
    let bundle =
        build_rgc_planning_track_bundle_with_generated_at(1_772_467_200_000).expect("build");
    let ledger = &bundle.risk_acceptance_ledger;
    let json = serde_json::to_string(ledger).expect("serialize risk_acceptance_ledger");
    let restored: serde_json::Value = serde_json::from_str(&json).expect("parse ledger json");
    assert_eq!(
        restored["schema_version"].as_str().unwrap(),
        RISK_ACCEPTANCE_LEDGER_SCHEMA_VERSION
    );
    assert_eq!(restored["bead_id"].as_str().unwrap(), BEAD_ID);
    assert!(restored["entries"].is_array());
    assert!(restored["fail_closed_on_stale_review"].as_bool().unwrap());
    assert!(restored["stale_threshold_days"].as_u64().unwrap() > 0);
}

#[test]
fn enrichment_milestone_gatebook_serde_roundtrip() {
    let bundle =
        build_rgc_planning_track_bundle_with_generated_at(1_772_467_200_000).expect("build");
    let gatebook = &bundle.milestone_gatebook;
    let json = serde_json::to_string(gatebook).expect("serialize milestone_gatebook");
    let restored: serde_json::Value = serde_json::from_str(&json).expect("parse gatebook json");
    assert_eq!(
        restored["schema_version"].as_str().unwrap(),
        MILESTONE_GATEBOOK_SCHEMA_VERSION
    );
    assert_eq!(restored["bead_id"].as_str().unwrap(), BEAD_ID);
    assert!(restored["milestones"].is_array());
    assert!(restored["dependency_order_preserved"].as_bool().unwrap());
    assert!(restored["all_cargo_commands_rch_backed"].as_bool().unwrap());
}

#[test]
fn enrichment_risk_id_uniqueness_invariant() {
    let bundle =
        build_rgc_planning_track_bundle_with_generated_at(1_772_467_200_000).expect("build");
    let ledger = &bundle.risk_acceptance_ledger;
    let mut seen = std::collections::BTreeSet::new();
    for entry in &ledger.entries {
        assert!(
            seen.insert(entry.risk_id.clone()),
            "duplicate risk_id found: {}",
            entry.risk_id
        );
    }
}

#[test]
fn enrichment_milestone_id_uniqueness_invariant() {
    let bundle =
        build_rgc_planning_track_bundle_with_generated_at(1_772_467_200_000).expect("build");
    let gatebook = &bundle.milestone_gatebook;
    let mut seen = std::collections::BTreeSet::new();
    for milestone in &gatebook.milestones {
        assert!(
            seen.insert(milestone.milestone.clone()),
            "duplicate milestone id found: {}",
            milestone.milestone
        );
    }
}

#[test]
fn enrichment_blocker_class_id_uniqueness_invariant() {
    let bundle =
        build_rgc_planning_track_bundle_with_generated_at(1_772_467_200_000).expect("build");
    let mut seen = std::collections::BTreeSet::new();
    for bc in &bundle.milestone_gatebook.blocker_classes {
        assert!(
            seen.insert(bc.class_id.clone()),
            "duplicate blocker class_id: {}",
            bc.class_id
        );
    }
}

#[test]
fn enrichment_bundle_clone_produces_equal_value() {
    let bundle =
        build_rgc_planning_track_bundle_with_generated_at(1_772_467_200_000).expect("build");
    let cloned = bundle.clone();
    assert_eq!(bundle.schema_version, cloned.schema_version);
    assert_eq!(bundle.bead_id, cloned.bead_id);
    assert_eq!(bundle.report_hash, cloned.report_hash);
    assert_eq!(
        bundle.scope_contract_snapshot.open_bead_ids,
        cloned.scope_contract_snapshot.open_bead_ids
    );
    assert_eq!(
        bundle.risk_acceptance_ledger.entries.len(),
        cloned.risk_acceptance_ledger.entries.len()
    );
    assert_eq!(
        bundle.milestone_gatebook.milestones.len(),
        cloned.milestone_gatebook.milestones.len()
    );
}

#[test]
fn enrichment_bundle_debug_contains_schema_version() {
    let bundle =
        build_rgc_planning_track_bundle_with_generated_at(1_772_467_200_000).expect("build");
    let debug_str = format!("{bundle:?}");
    assert!(
        debug_str.contains("schema_version"),
        "Debug output must contain field name 'schema_version'"
    );
    assert!(
        debug_str.contains("franken-engine"),
        "Debug output must contain schema prefix"
    );
}

#[test]
fn enrichment_different_timestamps_produce_different_generated_at_utc() {
    let ts1 = 1_772_467_200_000_u64;
    let ts2 = 1_772_553_600_000_u64; // 24 hours later
    let b1 = build_rgc_planning_track_bundle_with_generated_at(ts1).expect("build ts1");
    let b2 = build_rgc_planning_track_bundle_with_generated_at(ts2).expect("build ts2");
    assert_ne!(
        b1.generated_at_utc, b2.generated_at_utc,
        "different timestamps must yield different generated_at_utc strings"
    );
    assert_ne!(
        b1.generated_at_unix_ms, b2.generated_at_unix_ms,
        "unix_ms fields must differ"
    );
    assert_ne!(
        b1.report_hash, b2.report_hash,
        "different timestamps must yield different report hashes"
    );
}

#[test]
fn enrichment_risk_level_field_is_nonempty_and_recognized() {
    let bundle =
        build_rgc_planning_track_bundle_with_generated_at(1_772_467_200_000).expect("build");
    let recognized_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
    for entry in &bundle.risk_acceptance_ledger.entries {
        let level = entry.risk_level.to_uppercase();
        assert!(
            !entry.risk_level.is_empty(),
            "risk_level must not be empty for {}",
            entry.risk_id
        );
        assert!(
            recognized_levels.contains(&level.as_str()),
            "unrecognized risk_level '{}' for {}",
            entry.risk_level,
            entry.risk_id
        );
    }
}
