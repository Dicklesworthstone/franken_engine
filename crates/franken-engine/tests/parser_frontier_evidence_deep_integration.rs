//! Deep integration tests for parser_frontier_evidence module.
//!
//! Covers: corpus completeness, frontier family coverage, evidence determinism,
//! serde roundtrips, bundle filesystem artifacts, event lifecycle, and
//! contract satisfaction properties.

use frankenengine_engine::parser_frontier_evidence::{
    ActualParseOutcome, ExpectedParseOutcome, FrontierEvidenceArtifactPaths, FrontierEvidenceEvent,
    FrontierEvidenceRunManifest, FrontierSpecimen, FrontierSpecimenEvidence, FrontierVerdict,
    PARSER_FRONTIER_COMPONENT, PARSER_FRONTIER_EVENT_SCHEMA_VERSION,
    PARSER_FRONTIER_EVIDENCE_SCHEMA_VERSION, PARSER_FRONTIER_MANIFEST_SCHEMA_VERSION,
    PARSER_FRONTIER_POLICY_ID, ParserFrontierEvidenceInventory, ParserFrontierFamily,
    frontier_corpus, run_frontier_corpus, write_frontier_evidence_bundle,
};

use std::collections::BTreeSet;
use std::path::PathBuf;

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    std::env::temp_dir().join(format!("{}-{}-{}", prefix, pid, ts))
}

// ---------------------------------------------------------------------------
// Corpus completeness
// ---------------------------------------------------------------------------

#[test]
fn deep_corpus_covers_all_families() {
    let corpus = frontier_corpus();
    let covered: BTreeSet<ParserFrontierFamily> = corpus.iter().map(|s| s.family).collect();
    for family in ParserFrontierFamily::ALL {
        assert!(
            covered.contains(family),
            "Missing corpus coverage for {:?}",
            family
        );
    }
}

#[test]
fn deep_corpus_has_positive_and_negative_specimens() {
    let corpus = frontier_corpus();
    let accepted = corpus
        .iter()
        .filter(|s| s.expected_outcome == ExpectedParseOutcome::Accepted)
        .count();
    let rejected = corpus
        .iter()
        .filter(|s| s.expected_outcome == ExpectedParseOutcome::Rejected)
        .count();
    assert!(accepted > 0, "Need at least one positive specimen");
    assert!(rejected > 0, "Need at least one negative specimen");
}

#[test]
fn deep_corpus_specimens_have_unique_ids() {
    let corpus = frontier_corpus();
    let mut seen = BTreeSet::new();
    for specimen in &corpus {
        assert!(
            seen.insert(&specimen.specimen_id),
            "Duplicate specimen_id: {}",
            specimen.specimen_id
        );
    }
}

#[test]
fn deep_corpus_specimens_have_nonempty_fields() {
    let corpus = frontier_corpus();
    for specimen in &corpus {
        assert!(
            !specimen.specimen_id.is_empty(),
            "specimen_id must not be empty"
        );
        assert!(
            !specimen.description.is_empty(),
            "description must not be empty for {}",
            specimen.specimen_id
        );
        // source can be empty for the rejected empty-source test
    }
}

// ---------------------------------------------------------------------------
// ParserFrontierFamily exhaustive
// ---------------------------------------------------------------------------

#[test]
fn deep_frontier_family_all_count() {
    assert_eq!(ParserFrontierFamily::ALL.len(), 24);
}

#[test]
fn deep_frontier_family_as_str_all() {
    for family in ParserFrontierFamily::ALL {
        let s = family.as_str();
        assert!(!s.is_empty());
        assert!(!s.contains(' '), "as_str should use underscores: {}", s);
    }
}

#[test]
fn deep_frontier_family_serde_roundtrip_all() {
    for family in ParserFrontierFamily::ALL {
        let json = serde_json::to_string(family).unwrap();
        let decoded: ParserFrontierFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*family, decoded);
    }
}

#[test]
fn deep_frontier_family_as_str_unique() {
    let mut names = BTreeSet::new();
    for family in ParserFrontierFamily::ALL {
        assert!(
            names.insert(family.as_str()),
            "Duplicate as_str: {}",
            family.as_str()
        );
    }
}

// ---------------------------------------------------------------------------
// ExpectedParseOutcome
// ---------------------------------------------------------------------------

#[test]
fn deep_expected_outcome_serde_roundtrip() {
    for outcome in [
        ExpectedParseOutcome::Accepted,
        ExpectedParseOutcome::Rejected,
    ] {
        let json = serde_json::to_string(&outcome).unwrap();
        let decoded: ExpectedParseOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, decoded);
    }
}

#[test]
fn deep_expected_outcome_as_str() {
    assert_eq!(ExpectedParseOutcome::Accepted.as_str(), "accepted");
    assert_eq!(ExpectedParseOutcome::Rejected.as_str(), "rejected");
}

// ---------------------------------------------------------------------------
// ActualParseOutcome
// ---------------------------------------------------------------------------

#[test]
fn deep_actual_outcome_serde_roundtrip() {
    for outcome in [ActualParseOutcome::Accepted, ActualParseOutcome::Rejected] {
        let json = serde_json::to_string(&outcome).unwrap();
        let decoded: ActualParseOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, decoded);
    }
}

// ---------------------------------------------------------------------------
// FrontierVerdict
// ---------------------------------------------------------------------------

#[test]
fn deep_frontier_verdict_serde_roundtrip() {
    for verdict in [FrontierVerdict::Pass, FrontierVerdict::Fail] {
        let json = serde_json::to_string(&verdict).unwrap();
        let decoded: FrontierVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(verdict, decoded);
    }
}

// ---------------------------------------------------------------------------
// run_frontier_corpus — evidence properties
// ---------------------------------------------------------------------------

#[test]
fn deep_run_corpus_deterministic() {
    let inv1 = run_frontier_corpus();
    let inv2 = run_frontier_corpus();
    assert_eq!(inv1, inv2, "Corpus run should be deterministic");
}

#[test]
fn deep_run_corpus_contract_satisfied() {
    let inv = run_frontier_corpus();
    assert!(
        inv.contract_satisfied(),
        "Parser frontier contract must be satisfied (0 failures expected)"
    );
}

#[test]
fn deep_run_corpus_zero_failures() {
    let inv = run_frontier_corpus();
    assert_eq!(
        inv.fail_count, 0,
        "No specimen should fail the expected-vs-actual check"
    );
}

#[test]
fn deep_run_corpus_counts_add_up() {
    let inv = run_frontier_corpus();
    assert_eq!(
        inv.pass_count + inv.fail_count,
        inv.specimen_count,
        "pass + fail should equal total specimens"
    );
    assert_eq!(
        inv.accepted_count + inv.rejected_count,
        inv.specimen_count,
        "accepted + rejected should equal total specimens"
    );
}

#[test]
fn deep_run_corpus_schema_version() {
    let inv = run_frontier_corpus();
    assert_eq!(inv.schema_version, PARSER_FRONTIER_EVIDENCE_SCHEMA_VERSION);
}

#[test]
fn deep_run_corpus_component() {
    let inv = run_frontier_corpus();
    assert_eq!(inv.component, PARSER_FRONTIER_COMPONENT);
}

#[test]
fn deep_run_corpus_family_coverage_complete() {
    let inv = run_frontier_corpus();
    for family in ParserFrontierFamily::ALL {
        assert!(
            inv.family_coverage.contains_key(family.as_str()),
            "Missing family coverage for {}",
            family.as_str()
        );
    }
}

#[test]
fn deep_run_corpus_evidence_has_event_ir_hash() {
    let inv = run_frontier_corpus();
    for ev in &inv.evidence {
        assert!(
            ev.event_ir_hash.is_some(),
            "Evidence for {} should have event_ir_hash",
            ev.specimen_id
        );
    }
}

#[test]
fn deep_run_corpus_rejected_specimens_have_error_info() {
    let inv = run_frontier_corpus();
    for ev in inv
        .evidence
        .iter()
        .filter(|e| e.actual_outcome == ActualParseOutcome::Rejected)
    {
        assert!(
            ev.error_code.is_some(),
            "Rejected specimen {} should have error_code",
            ev.specimen_id
        );
        assert!(
            ev.error_message.is_some(),
            "Rejected specimen {} should have error_message",
            ev.specimen_id
        );
    }
}

#[test]
fn deep_run_corpus_accepted_specimens_no_error_info() {
    let inv = run_frontier_corpus();
    for ev in inv
        .evidence
        .iter()
        .filter(|e| e.actual_outcome == ActualParseOutcome::Accepted)
    {
        assert!(
            ev.error_code.is_none(),
            "Accepted specimen {} should not have error_code",
            ev.specimen_id
        );
        assert!(
            ev.error_message.is_none(),
            "Accepted specimen {} should not have error_message",
            ev.specimen_id
        );
    }
}

// ---------------------------------------------------------------------------
// Inventory serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn deep_inventory_serde_roundtrip() {
    let inv = run_frontier_corpus();
    let json = serde_json::to_string_pretty(&inv).unwrap();
    let decoded: ParserFrontierEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, decoded);
}

#[test]
fn deep_inventory_serde_byte_stable() {
    let inv = run_frontier_corpus();
    let json1 = serde_json::to_string_pretty(&inv).unwrap();
    let decoded: ParserFrontierEvidenceInventory = serde_json::from_str(&json1).unwrap();
    let json2 = serde_json::to_string_pretty(&decoded).unwrap();
    assert_eq!(json1, json2);
}

// ---------------------------------------------------------------------------
// Specimen evidence serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn deep_specimen_evidence_serde_roundtrip() {
    let ev = FrontierSpecimenEvidence {
        specimen_id: "deep_test".to_string(),
        family: ParserFrontierFamily::VariableDeclaration,
        expected_outcome: ExpectedParseOutcome::Accepted,
        actual_outcome: ActualParseOutcome::Accepted,
        verdict: FrontierVerdict::Pass,
        error_code: None,
        error_message: None,
        event_ir_hash: Some("abc123".to_string()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let decoded: FrontierSpecimenEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, decoded);
}

// ---------------------------------------------------------------------------
// Specimen serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn deep_specimen_serde_roundtrip() {
    let specimen = FrontierSpecimen {
        specimen_id: "deep_specimen".to_string(),
        family: ParserFrontierFamily::ArrowFunction,
        source: "const f = (x) => x * 2;".to_string(),
        parse_goal: frankenengine_engine::ast::ParseGoal::Script,
        expected_outcome: ExpectedParseOutcome::Accepted,
        description: "Deep test specimen".to_string(),
    };
    let json = serde_json::to_string(&specimen).unwrap();
    let decoded: FrontierSpecimen = serde_json::from_str(&json).unwrap();
    assert_eq!(specimen, decoded);
}

// ---------------------------------------------------------------------------
// Event serde
// ---------------------------------------------------------------------------

#[test]
fn deep_event_serde_roundtrip() {
    let event = FrontierEvidenceEvent {
        schema_version: PARSER_FRONTIER_EVENT_SCHEMA_VERSION.to_string(),
        component: PARSER_FRONTIER_COMPONENT.to_string(),
        event: "specimen_evaluated".to_string(),
        policy_id: PARSER_FRONTIER_POLICY_ID.to_string(),
        specimen_id: Some("test_specimen".to_string()),
        verdict: Some("pass".to_string()),
        detail: Some("expected=accepted, actual=accepted".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: FrontierEvidenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, decoded);
}

// ---------------------------------------------------------------------------
// Run manifest serde
// ---------------------------------------------------------------------------

#[test]
fn deep_run_manifest_serde_roundtrip() {
    let manifest = FrontierEvidenceRunManifest {
        schema_version: PARSER_FRONTIER_MANIFEST_SCHEMA_VERSION.to_string(),
        component: PARSER_FRONTIER_COMPONENT.to_string(),
        trace_id: "trace-deep".to_string(),
        decision_id: "decision-deep".to_string(),
        policy_id: PARSER_FRONTIER_POLICY_ID.to_string(),
        inventory_hash: "deadbeef".to_string(),
        specimen_count: 25,
        pass_count: 25,
        fail_count: 0,
        accepted_count: 22,
        rejected_count: 3,
        contract_satisfied: true,
        artifact_paths: FrontierEvidenceArtifactPaths {
            evidence_inventory: "inventory.json".to_string(),
            run_manifest: "manifest.json".to_string(),
            events_jsonl: "events.jsonl".to_string(),
            commands_txt: "commands.txt".to_string(),
        },
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let decoded: FrontierEvidenceRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, decoded);
}

// ---------------------------------------------------------------------------
// Bundle write — filesystem artifacts
// ---------------------------------------------------------------------------

#[test]
fn deep_bundle_write_creates_all_files() {
    let dir = unique_temp_dir("deep-frontier-evidence-files");
    let commands = vec!["deep_test".to_string()];
    let artifacts = write_frontier_evidence_bundle(&dir, &commands).unwrap();

    assert!(artifacts.inventory_path.exists());
    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.events_path.exists());
    assert!(artifacts.commands_path.exists());
}

#[test]
fn deep_bundle_inventory_matches_direct_run() {
    let dir = unique_temp_dir("deep-frontier-evidence-match");
    let commands = vec!["match_check".to_string()];
    let artifacts = write_frontier_evidence_bundle(&dir, &commands).unwrap();

    let written: ParserFrontierEvidenceInventory =
        serde_json::from_slice(&std::fs::read(&artifacts.inventory_path).unwrap()).unwrap();
    let direct = run_frontier_corpus();
    assert_eq!(written, direct);
}

#[test]
fn deep_bundle_manifest_counts_match() {
    let dir = unique_temp_dir("deep-frontier-evidence-counts");
    let commands = vec!["count_check".to_string()];
    let artifacts = write_frontier_evidence_bundle(&dir, &commands).unwrap();

    let manifest: FrontierEvidenceRunManifest =
        serde_json::from_slice(&std::fs::read(&artifacts.run_manifest_path).unwrap()).unwrap();
    let inventory = run_frontier_corpus();

    assert_eq!(manifest.specimen_count, inventory.specimen_count);
    assert_eq!(manifest.pass_count, inventory.pass_count);
    assert_eq!(manifest.fail_count, inventory.fail_count);
    assert_eq!(manifest.accepted_count, inventory.accepted_count);
    assert_eq!(manifest.rejected_count, inventory.rejected_count);
    assert_eq!(manifest.contract_satisfied, inventory.contract_satisfied());
}

#[test]
fn deep_bundle_events_jsonl_valid() {
    let dir = unique_temp_dir("deep-frontier-evidence-events");
    let commands = vec!["events_check".to_string()];
    let artifacts = write_frontier_evidence_bundle(&dir, &commands).unwrap();

    let events_text = std::fs::read_to_string(&artifacts.events_path).unwrap();
    for line in events_text.lines() {
        let event: FrontierEvidenceEvent = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("Invalid event JSON: {}: {}", e, line));
        assert_eq!(event.schema_version, PARSER_FRONTIER_EVENT_SCHEMA_VERSION);
    }
}

#[test]
fn deep_bundle_events_have_lifecycle() {
    let dir = unique_temp_dir("deep-frontier-evidence-lifecycle");
    let commands = vec!["lifecycle_check".to_string()];
    let artifacts = write_frontier_evidence_bundle(&dir, &commands).unwrap();

    let events_text = std::fs::read_to_string(&artifacts.events_path).unwrap();
    let events: Vec<FrontierEvidenceEvent> = events_text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();

    assert!(events.len() >= 2);
    assert_eq!(
        events.first().unwrap().event,
        "frontier_evidence_run_started"
    );
    assert_eq!(
        events.last().unwrap().event,
        "frontier_evidence_run_completed"
    );
}

#[test]
fn deep_bundle_inventory_hash_deterministic() {
    let dir1 = unique_temp_dir("deep-frontier-evidence-det1");
    let dir2 = unique_temp_dir("deep-frontier-evidence-det2");
    let commands = vec!["det_check".to_string()];

    let a1 = write_frontier_evidence_bundle(&dir1, &commands).unwrap();
    let a2 = write_frontier_evidence_bundle(&dir2, &commands).unwrap();
    assert_eq!(a1.inventory_hash, a2.inventory_hash);
}

#[test]
fn deep_bundle_commands_txt_written() {
    let dir = unique_temp_dir("deep-frontier-evidence-cmds");
    let commands = vec![
        "franken_frontier_evidence".to_string(),
        "--verbose".to_string(),
    ];
    let artifacts = write_frontier_evidence_bundle(&dir, &commands).unwrap();
    let written = std::fs::read_to_string(&artifacts.commands_path).unwrap();
    assert!(written.contains("franken_frontier_evidence"));
    assert!(written.contains("--verbose"));
}

// ---------------------------------------------------------------------------
// Schema version constants
// ---------------------------------------------------------------------------

#[test]
fn deep_schema_versions_nonempty() {
    assert!(!PARSER_FRONTIER_EVIDENCE_SCHEMA_VERSION.is_empty());
    assert!(!PARSER_FRONTIER_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(!PARSER_FRONTIER_EVENT_SCHEMA_VERSION.is_empty());
    assert!(!PARSER_FRONTIER_COMPONENT.is_empty());
    assert!(!PARSER_FRONTIER_POLICY_ID.is_empty());
}

#[test]
fn deep_schema_versions_contain_component_name() {
    assert!(PARSER_FRONTIER_EVIDENCE_SCHEMA_VERSION.contains("parser-frontier-evidence"));
    assert!(PARSER_FRONTIER_MANIFEST_SCHEMA_VERSION.contains("parser-frontier-evidence"));
    assert!(PARSER_FRONTIER_EVENT_SCHEMA_VERSION.contains("parser-frontier-evidence"));
}

// ---------------------------------------------------------------------------
// Artifact paths serde
// ---------------------------------------------------------------------------

#[test]
fn deep_artifact_paths_serde_roundtrip() {
    let paths = FrontierEvidenceArtifactPaths {
        evidence_inventory: "inv.json".to_string(),
        run_manifest: "manifest.json".to_string(),
        events_jsonl: "events.jsonl".to_string(),
        commands_txt: "commands.txt".to_string(),
    };
    let json = serde_json::to_string(&paths).unwrap();
    let decoded: FrontierEvidenceArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(paths, decoded);
}
