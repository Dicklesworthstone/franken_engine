//! Integration tests for the ESM/CJS execution parity evidence harness.

use frankenengine_engine::esm_cjs_parity_evidence::*;
use frankenengine_engine::module_resolver::ModuleSyntax;
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Corpus invariants
// ---------------------------------------------------------------------------

#[test]
fn corpus_returns_non_empty_vec() {
    let corpus = esm_cjs_parity_corpus();
    assert!(!corpus.is_empty());
}

#[test]
fn corpus_ids_are_globally_unique() {
    let corpus = esm_cjs_parity_corpus();
    let ids: BTreeSet<&str> = corpus.iter().map(|s| s.specimen_id.as_str()).collect();
    assert_eq!(ids.len(), corpus.len(), "duplicate specimen IDs detected");
}

#[test]
fn corpus_is_deterministic_across_calls() {
    let a = esm_cjs_parity_corpus();
    let b = esm_cjs_parity_corpus();
    assert_eq!(a, b);
}

#[test]
fn corpus_covers_all_topologies() {
    let corpus = esm_cjs_parity_corpus();
    let topologies: BTreeSet<_> = corpus.iter().map(|s| s.topology).collect();
    assert!(topologies.contains(&ModuleGraphTopology::PureEsm));
    assert!(topologies.contains(&ModuleGraphTopology::PureCjs));
    assert!(topologies.contains(&ModuleGraphTopology::Mixed));
}

#[test]
fn corpus_covers_all_interop_directions() {
    let corpus = esm_cjs_parity_corpus();
    let dirs: BTreeSet<_> = corpus.iter().map(|s| s.interop_direction).collect();
    assert!(dirs.contains(&InteropDirection::None));
    assert!(dirs.contains(&InteropDirection::EsmImportsCjs));
    assert!(dirs.contains(&InteropDirection::CjsRequiresEsm));
    assert!(dirs.contains(&InteropDirection::Bidirectional));
}

#[test]
fn corpus_covers_both_module_syntaxes() {
    let corpus = esm_cjs_parity_corpus();
    let syntaxes: BTreeSet<_> = corpus.iter().map(|s| s.expected_syntax).collect();
    assert!(syntaxes.contains(&ModuleSyntax::EsModule));
    assert!(syntaxes.contains(&ModuleSyntax::CommonJs));
}

#[test]
fn corpus_covers_success_and_failure_outcomes() {
    let corpus = esm_cjs_parity_corpus();
    let outcomes: BTreeSet<_> = corpus.iter().map(|s| s.expected_outcome).collect();
    assert!(outcomes.contains(&EsmCjsExpectedOutcome::ExecuteSuccess));
    assert!(outcomes.contains(&EsmCjsExpectedOutcome::ParseFailure));
}

#[test]
fn corpus_descriptions_all_non_empty() {
    for specimen in &esm_cjs_parity_corpus() {
        assert!(
            !specimen.description.is_empty(),
            "specimen {} has empty description",
            specimen.specimen_id
        );
    }
}

#[test]
fn corpus_ids_all_non_empty() {
    for specimen in &esm_cjs_parity_corpus() {
        assert!(!specimen.specimen_id.is_empty(), "found empty specimen_id");
    }
}

#[test]
fn corpus_has_specimens_with_and_without_source_file() {
    let corpus = esm_cjs_parity_corpus();
    assert!(corpus.iter().any(|s| s.source_file.is_some()));
    assert!(corpus.iter().any(|s| s.source_file.is_none()));
}

// ---------------------------------------------------------------------------
// Runner / Inventory
// ---------------------------------------------------------------------------

#[test]
fn run_corpus_all_pass() {
    let inv = run_esm_cjs_parity_corpus();
    for ev in &inv.evidence {
        assert_eq!(
            ev.verdict,
            EsmCjsParityVerdict::Pass,
            "specimen {} failed: expected={:?} actual={:?} error={:?}",
            ev.specimen_id,
            ev.expected_outcome,
            ev.actual_outcome,
            ev.error_detail,
        );
    }
    assert!(inv.contract_satisfied());
}

#[test]
fn inventory_schema_version_matches_constant() {
    let inv = run_esm_cjs_parity_corpus();
    assert_eq!(inv.schema_version, ESM_CJS_PARITY_SCHEMA_VERSION);
}

#[test]
fn inventory_component_matches_constant() {
    let inv = run_esm_cjs_parity_corpus();
    assert_eq!(inv.component, ESM_CJS_PARITY_COMPONENT);
}

#[test]
fn inventory_counts_add_up() {
    let inv = run_esm_cjs_parity_corpus();
    assert_eq!(inv.pass_count + inv.fail_count, inv.specimen_count);
    assert_eq!(
        inv.pure_esm_count + inv.pure_cjs_count + inv.mixed_count,
        inv.specimen_count
    );
    assert_eq!(inv.evidence.len() as u64, inv.specimen_count);
}

#[test]
fn inventory_is_deterministic() {
    let a = run_esm_cjs_parity_corpus();
    let b = run_esm_cjs_parity_corpus();
    assert_eq!(a, b);
}

#[test]
fn inventory_evidence_ids_match_corpus() {
    let corpus = esm_cjs_parity_corpus();
    let inv = run_esm_cjs_parity_corpus();
    let corpus_ids: Vec<&str> = corpus.iter().map(|s| s.specimen_id.as_str()).collect();
    let evidence_ids: Vec<&str> = inv
        .evidence
        .iter()
        .map(|e| e.specimen_id.as_str())
        .collect();
    assert_eq!(corpus_ids, evidence_ids);
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn specimen_serde_roundtrip() {
    let corpus = esm_cjs_parity_corpus();
    let json = serde_json::to_string_pretty(&corpus).unwrap();
    let decoded: Vec<EsmCjsParitySpecimen> = serde_json::from_str(&json).unwrap();
    assert_eq!(corpus, decoded);
}

#[test]
fn inventory_serde_roundtrip() {
    let inv = run_esm_cjs_parity_corpus();
    let json = serde_json::to_string_pretty(&inv).unwrap();
    let decoded: EsmCjsParityEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, decoded);
}

#[test]
fn manifest_serde_roundtrip() {
    let manifest = EsmCjsParityRunManifest {
        schema_version: ESM_CJS_PARITY_MANIFEST_SCHEMA_VERSION.into(),
        component: ESM_CJS_PARITY_COMPONENT.into(),
        trace_id: "integration-trace-001".into(),
        decision_id: "integration-decision-001".into(),
        policy_id: ESM_CJS_PARITY_POLICY_ID.into(),
        inventory_hash: "deadbeef".into(),
        specimen_count: 10,
        pass_count: 10,
        fail_count: 0,
        contract_satisfied: true,
        artifact_paths: EsmCjsParityArtifactPaths {
            evidence_inventory: "inv.json".into(),
            run_manifest: "manifest.json".into(),
            events_jsonl: "events.jsonl".into(),
            commands_txt: "commands.txt".into(),
        },
    };
    let json = serde_json::to_string_pretty(&manifest).unwrap();
    let decoded: EsmCjsParityRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, decoded);
}

#[test]
fn event_serde_roundtrip() {
    let event = EsmCjsParityEvent {
        schema_version: ESM_CJS_PARITY_EVENT_SCHEMA_VERSION.into(),
        component: ESM_CJS_PARITY_COMPONENT.into(),
        event: "integration_test_event".into(),
        policy_id: ESM_CJS_PARITY_POLICY_ID.into(),
        specimen_id: Some("spec_001".into()),
        verdict: Some("pass".into()),
        detail: Some("all good".into()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: EsmCjsParityEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, decoded);
}

#[test]
fn event_serde_with_none_fields() {
    let event = EsmCjsParityEvent {
        schema_version: ESM_CJS_PARITY_EVENT_SCHEMA_VERSION.into(),
        component: ESM_CJS_PARITY_COMPONENT.into(),
        event: "run_started".into(),
        policy_id: ESM_CJS_PARITY_POLICY_ID.into(),
        specimen_id: None,
        verdict: None,
        detail: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: EsmCjsParityEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, decoded);
}

// ---------------------------------------------------------------------------
// Enum Display and as_str
// ---------------------------------------------------------------------------

#[test]
fn topology_display_matches_as_str() {
    let variants = [
        ModuleGraphTopology::PureEsm,
        ModuleGraphTopology::PureCjs,
        ModuleGraphTopology::Mixed,
    ];
    for v in &variants {
        assert_eq!(v.to_string(), v.as_str());
    }
}

#[test]
fn interop_direction_display_matches_as_str() {
    let variants = [
        InteropDirection::None,
        InteropDirection::EsmImportsCjs,
        InteropDirection::CjsRequiresEsm,
        InteropDirection::Bidirectional,
    ];
    for v in &variants {
        assert_eq!(v.to_string(), v.as_str());
    }
}

#[test]
fn expected_outcome_display_matches_as_str() {
    let variants = [
        EsmCjsExpectedOutcome::ExecuteSuccess,
        EsmCjsExpectedOutcome::ResolutionFailure,
        EsmCjsExpectedOutcome::LinkingFailure,
        EsmCjsExpectedOutcome::EvaluationFailure,
        EsmCjsExpectedOutcome::ParseFailure,
    ];
    for v in &variants {
        assert_eq!(v.to_string(), v.as_str());
    }
}

#[test]
fn actual_outcome_display_matches_as_str() {
    let variants = [
        EsmCjsActualOutcome::ExecuteSuccess,
        EsmCjsActualOutcome::ResolutionFailure,
        EsmCjsActualOutcome::LinkingFailure,
        EsmCjsActualOutcome::EvaluationFailure,
        EsmCjsActualOutcome::ParseFailure,
        EsmCjsActualOutcome::OtherFailure,
    ];
    for v in &variants {
        assert_eq!(v.to_string(), v.as_str());
    }
}

// ---------------------------------------------------------------------------
// Contract satisfaction logic
// ---------------------------------------------------------------------------

#[test]
fn contract_satisfied_when_all_pass() {
    let inv = EsmCjsParityEvidenceInventory {
        schema_version: ESM_CJS_PARITY_SCHEMA_VERSION.into(),
        component: ESM_CJS_PARITY_COMPONENT.into(),
        specimen_count: 20,
        pass_count: 20,
        fail_count: 0,
        pure_esm_count: 8,
        pure_cjs_count: 7,
        mixed_count: 5,
        evidence: vec![],
    };
    assert!(inv.contract_satisfied());
}

#[test]
fn contract_not_satisfied_with_any_failure() {
    let inv = EsmCjsParityEvidenceInventory {
        schema_version: ESM_CJS_PARITY_SCHEMA_VERSION.into(),
        component: ESM_CJS_PARITY_COMPONENT.into(),
        specimen_count: 20,
        pass_count: 19,
        fail_count: 1,
        pure_esm_count: 8,
        pure_cjs_count: 7,
        mixed_count: 5,
        evidence: vec![],
    };
    assert!(!inv.contract_satisfied());
}

#[test]
fn contract_not_satisfied_with_empty_corpus() {
    let inv = EsmCjsParityEvidenceInventory {
        schema_version: ESM_CJS_PARITY_SCHEMA_VERSION.into(),
        component: ESM_CJS_PARITY_COMPONENT.into(),
        specimen_count: 0,
        pass_count: 0,
        fail_count: 0,
        pure_esm_count: 0,
        pure_cjs_count: 0,
        mixed_count: 0,
        evidence: vec![],
    };
    assert!(!inv.contract_satisfied());
}

// ---------------------------------------------------------------------------
// Verdict enum
// ---------------------------------------------------------------------------

#[test]
fn verdict_serde() {
    let pass_json = serde_json::to_string(&EsmCjsParityVerdict::Pass).unwrap();
    assert_eq!(pass_json, "\"pass\"");
    let fail_json = serde_json::to_string(&EsmCjsParityVerdict::Fail).unwrap();
    assert_eq!(fail_json, "\"fail\"");

    let decoded_pass: EsmCjsParityVerdict = serde_json::from_str(&pass_json).unwrap();
    assert_eq!(decoded_pass, EsmCjsParityVerdict::Pass);
    let decoded_fail: EsmCjsParityVerdict = serde_json::from_str(&fail_json).unwrap();
    assert_eq!(decoded_fail, EsmCjsParityVerdict::Fail);
}

#[test]
fn verdict_equality() {
    assert_eq!(EsmCjsParityVerdict::Pass, EsmCjsParityVerdict::Pass);
    assert_ne!(EsmCjsParityVerdict::Pass, EsmCjsParityVerdict::Fail);
}

// ---------------------------------------------------------------------------
// Topology ordering
// ---------------------------------------------------------------------------

#[test]
fn topology_ordering_is_consistent() {
    let mut topologies = [
        ModuleGraphTopology::PureEsm,
        ModuleGraphTopology::Mixed,
        ModuleGraphTopology::PureCjs,
    ];
    topologies.sort();
    // Sorted by discriminant order in the enum definition (alphabetical: Mixed, PureCjs, PureEsm).
    assert_eq!(topologies[0], ModuleGraphTopology::Mixed);
}

// ---------------------------------------------------------------------------
// Evidence per-specimen checks
// ---------------------------------------------------------------------------

#[test]
fn each_evidence_has_matching_specimen_id() {
    let corpus = esm_cjs_parity_corpus();
    let inv = run_esm_cjs_parity_corpus();
    for (specimen, ev) in corpus.iter().zip(inv.evidence.iter()) {
        assert_eq!(specimen.specimen_id, ev.specimen_id);
    }
}

#[test]
fn each_evidence_records_expected_syntax() {
    let corpus = esm_cjs_parity_corpus();
    let inv = run_esm_cjs_parity_corpus();
    for (specimen, ev) in corpus.iter().zip(inv.evidence.iter()) {
        assert_eq!(specimen.expected_syntax, ev.expected_syntax);
    }
}

#[test]
fn each_evidence_records_topology() {
    let corpus = esm_cjs_parity_corpus();
    let inv = run_esm_cjs_parity_corpus();
    for (specimen, ev) in corpus.iter().zip(inv.evidence.iter()) {
        assert_eq!(specimen.topology, ev.topology);
    }
}

#[test]
fn each_evidence_records_interop_direction() {
    let corpus = esm_cjs_parity_corpus();
    let inv = run_esm_cjs_parity_corpus();
    for (specimen, ev) in corpus.iter().zip(inv.evidence.iter()) {
        assert_eq!(specimen.interop_direction, ev.interop_direction);
    }
}

#[test]
fn each_evidence_records_expected_outcome() {
    let corpus = esm_cjs_parity_corpus();
    let inv = run_esm_cjs_parity_corpus();
    for (specimen, ev) in corpus.iter().zip(inv.evidence.iter()) {
        assert_eq!(specimen.expected_outcome, ev.expected_outcome);
    }
}

// ---------------------------------------------------------------------------
// Bundle writer (tempdir)
// ---------------------------------------------------------------------------

#[test]
fn write_bundle_creates_four_files() {
    let dir = std::env::temp_dir().join("esm_cjs_parity_test_bundle");
    let _ = std::fs::remove_dir_all(&dir);

    let result = write_esm_cjs_parity_evidence_bundle(
        &dir,
        &["cargo test".into(), "rch exec cargo test".into()],
    );
    assert!(result.is_ok(), "bundle write failed: {:?}", result.err());

    let bundle = result.unwrap();
    assert!(bundle.inventory_path.exists());
    assert!(bundle.run_manifest_path.exists());
    assert!(bundle.events_path.exists());
    assert!(bundle.commands_path.exists());
    assert!(!bundle.inventory_hash.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_inventory_is_valid_json() {
    let dir = std::env::temp_dir().join("esm_cjs_parity_test_inv_json");
    let _ = std::fs::remove_dir_all(&dir);

    let bundle = write_esm_cjs_parity_evidence_bundle(&dir, &[]).unwrap();
    let content = std::fs::read_to_string(&bundle.inventory_path).unwrap();
    let inv: EsmCjsParityEvidenceInventory = serde_json::from_str(&content).unwrap();
    assert!(inv.contract_satisfied());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_manifest_is_valid_json() {
    let dir = std::env::temp_dir().join("esm_cjs_parity_test_manifest_json");
    let _ = std::fs::remove_dir_all(&dir);

    let bundle = write_esm_cjs_parity_evidence_bundle(&dir, &[]).unwrap();
    let content = std::fs::read_to_string(&bundle.run_manifest_path).unwrap();
    let manifest: EsmCjsParityRunManifest = serde_json::from_str(&content).unwrap();
    assert_eq!(manifest.policy_id, ESM_CJS_PARITY_POLICY_ID);
    assert!(manifest.contract_satisfied);
    assert!(!manifest.inventory_hash.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_events_is_valid_jsonl() {
    let dir = std::env::temp_dir().join("esm_cjs_parity_test_events_jsonl");
    let _ = std::fs::remove_dir_all(&dir);

    let bundle = write_esm_cjs_parity_evidence_bundle(&dir, &[]).unwrap();
    let content = std::fs::read_to_string(&bundle.events_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    // At least: started + N specimens + completed
    let corpus_size = esm_cjs_parity_corpus().len();
    assert_eq!(lines.len(), corpus_size + 2);
    for line in &lines {
        let event: EsmCjsParityEvent = serde_json::from_str(line).unwrap();
        assert_eq!(event.component, ESM_CJS_PARITY_COMPONENT);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_commands_recorded() {
    let dir = std::env::temp_dir().join("esm_cjs_parity_test_commands");
    let _ = std::fs::remove_dir_all(&dir);

    let cmds = vec!["cmd1".to_string(), "cmd2".to_string()];
    let bundle = write_esm_cjs_parity_evidence_bundle(&dir, &cmds).unwrap();
    let content = std::fs::read_to_string(&bundle.commands_path).unwrap();
    assert!(content.contains("cmd1"));
    assert!(content.contains("cmd2"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_inventory_hash_is_deterministic() {
    let dir1 = std::env::temp_dir().join("esm_cjs_parity_hash_a");
    let dir2 = std::env::temp_dir().join("esm_cjs_parity_hash_b");
    let _ = std::fs::remove_dir_all(&dir1);
    let _ = std::fs::remove_dir_all(&dir2);

    let b1 = write_esm_cjs_parity_evidence_bundle(&dir1, &[]).unwrap();
    let b2 = write_esm_cjs_parity_evidence_bundle(&dir2, &[]).unwrap();
    assert_eq!(b1.inventory_hash, b2.inventory_hash);

    let _ = std::fs::remove_dir_all(&dir1);
    let _ = std::fs::remove_dir_all(&dir2);
}

// ---------------------------------------------------------------------------
// Schema version constants
// ---------------------------------------------------------------------------

#[test]
fn schema_versions_are_distinct() {
    let versions = [
        ESM_CJS_PARITY_SCHEMA_VERSION,
        ESM_CJS_PARITY_MANIFEST_SCHEMA_VERSION,
        ESM_CJS_PARITY_EVENT_SCHEMA_VERSION,
    ];
    let unique: BTreeSet<&str> = versions.iter().copied().collect();
    assert_eq!(unique.len(), versions.len());
}

#[test]
fn schema_versions_have_common_prefix() {
    for v in [
        ESM_CJS_PARITY_SCHEMA_VERSION,
        ESM_CJS_PARITY_MANIFEST_SCHEMA_VERSION,
        ESM_CJS_PARITY_EVENT_SCHEMA_VERSION,
    ] {
        assert!(v.starts_with("franken-engine.esm_cjs_parity_"));
    }
}

#[test]
fn policy_id_is_rgc_309c() {
    assert_eq!(ESM_CJS_PARITY_POLICY_ID, "RGC-309C");
}

#[test]
fn component_name_matches_module() {
    assert_eq!(ESM_CJS_PARITY_COMPONENT, "esm_cjs_parity_evidence");
}

// ---------------------------------------------------------------------------
// ModuleSyntax interop
// ---------------------------------------------------------------------------

#[test]
fn module_syntax_esm_serde() {
    let json = serde_json::to_string(&ModuleSyntax::EsModule).unwrap();
    let decoded: ModuleSyntax = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, ModuleSyntax::EsModule);
}

#[test]
fn module_syntax_cjs_serde() {
    let json = serde_json::to_string(&ModuleSyntax::CommonJs).unwrap();
    let decoded: ModuleSyntax = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, ModuleSyntax::CommonJs);
}

// ---------------------------------------------------------------------------
// Artifact paths
// ---------------------------------------------------------------------------

#[test]
fn artifact_paths_serde_roundtrip() {
    let paths = EsmCjsParityArtifactPaths {
        evidence_inventory: "inv.json".into(),
        run_manifest: "manifest.json".into(),
        events_jsonl: "events.jsonl".into(),
        commands_txt: "commands.txt".into(),
    };
    let json = serde_json::to_string(&paths).unwrap();
    let decoded: EsmCjsParityArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(paths, decoded);
}

// ---------------------------------------------------------------------------
// Evidence topology statistics
// ---------------------------------------------------------------------------

#[test]
fn inventory_topology_counts_are_positive() {
    let inv = run_esm_cjs_parity_corpus();
    assert!(inv.pure_esm_count > 0, "expected some pure ESM specimens");
    assert!(inv.pure_cjs_count > 0, "expected some pure CJS specimens");
    assert!(inv.mixed_count > 0, "expected some mixed specimens");
}

#[test]
fn inventory_pass_count_equals_specimen_count_when_all_pass() {
    let inv = run_esm_cjs_parity_corpus();
    if inv.contract_satisfied() {
        assert_eq!(inv.pass_count, inv.specimen_count);
        assert_eq!(inv.fail_count, 0);
    }
}
