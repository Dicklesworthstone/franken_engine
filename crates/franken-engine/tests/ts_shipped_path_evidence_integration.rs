#![forbid(unsafe_code)]
//! Integration tests for the `ts_shipped_path_evidence` module.
//!
//! Exercises the shipped-path evidence harness, corpus validation,
//! inventory contract, bundle writing, and serde round-trips
//! from outside the crate boundary.

use std::collections::BTreeSet;

use frankenengine_engine::ts_normalization::SourceLanguage;
use frankenengine_engine::ts_shipped_path_evidence::{
    ShippedPathActualOutcome, ShippedPathEvidenceArtifactPaths, ShippedPathEvidenceEvent,
    ShippedPathEvidenceRunManifest, ShippedPathExpectedOutcome, ShippedPathSpecimen,
    ShippedPathSpecimenEvidence, ShippedPathVerdict, TsShippedPathEvidenceInventory,
    TS_SHIPPED_PATH_COMPONENT, TS_SHIPPED_PATH_EVENT_SCHEMA_VERSION,
    TS_SHIPPED_PATH_MANIFEST_SCHEMA_VERSION, TS_SHIPPED_PATH_POLICY_ID,
    TS_SHIPPED_PATH_SCHEMA_VERSION, run_shipped_path_corpus, shipped_path_corpus,
    write_shipped_path_evidence_bundle,
};

// ===========================================================================
// 1. Corpus structure
// ===========================================================================

#[test]
fn corpus_is_non_empty() {
    assert!(!shipped_path_corpus().is_empty());
}

#[test]
fn corpus_ids_unique() {
    let corpus = shipped_path_corpus();
    let ids: BTreeSet<&str> = corpus.iter().map(|s| s.specimen_id.as_str()).collect();
    assert_eq!(ids.len(), corpus.len());
}

#[test]
fn corpus_has_js_specimens() {
    let corpus = shipped_path_corpus();
    let js_count = corpus
        .iter()
        .filter(|s| s.expected_language == SourceLanguage::JavaScript)
        .count();
    assert!(js_count >= 3, "expected ≥3 JS specimens, got {js_count}");
}

#[test]
fn corpus_has_ts_specimens() {
    let corpus = shipped_path_corpus();
    let ts_count = corpus
        .iter()
        .filter(|s| s.expected_language == SourceLanguage::TypeScript)
        .count();
    assert!(ts_count >= 5, "expected ≥5 TS specimens, got {ts_count}");
}

#[test]
fn corpus_has_source_file_and_no_source_file_specimens() {
    let corpus = shipped_path_corpus();
    assert!(
        corpus.iter().any(|s| s.source_file.is_some()),
        "expected at least one specimen with source_file"
    );
    assert!(
        corpus.iter().any(|s| s.source_file.is_none()),
        "expected at least one specimen without source_file"
    );
}

#[test]
fn corpus_all_sources_non_empty() {
    for s in &shipped_path_corpus() {
        assert!(
            !s.source.is_empty(),
            "specimen {} has empty source",
            s.specimen_id
        );
    }
}

#[test]
fn corpus_all_descriptions_non_empty() {
    for s in &shipped_path_corpus() {
        assert!(
            !s.description.is_empty(),
            "specimen {} has empty description",
            s.specimen_id
        );
    }
}

#[test]
fn corpus_has_multiple_ts_extensions() {
    let corpus = shipped_path_corpus();
    let extensions: BTreeSet<String> = corpus
        .iter()
        .filter(|s| s.expected_language == SourceLanguage::TypeScript)
        .filter_map(|s| {
            s.source_file
                .as_ref()
                .and_then(|f| f.rsplit('.').next().map(|e| e.to_string()))
        })
        .collect();
    assert!(
        extensions.len() >= 3,
        "expected ≥3 TS extensions, got {extensions:?}"
    );
}

// ===========================================================================
// 2. Evidence runner
// ===========================================================================

#[test]
fn run_corpus_all_pass() {
    let inv = run_shipped_path_corpus();
    assert_eq!(inv.fail_count, 0, "expected 0 failures");
    assert!(inv.specimen_count > 0);
}

#[test]
fn run_corpus_contract_satisfied() {
    let inv = run_shipped_path_corpus();
    assert!(inv.contract_satisfied());
}

#[test]
fn run_corpus_counts_consistent() {
    let inv = run_shipped_path_corpus();
    assert_eq!(inv.pass_count + inv.fail_count, inv.specimen_count);
    assert_eq!(inv.js_count + inv.ts_count, inv.specimen_count);
    assert_eq!(inv.evidence.len() as u64, inv.specimen_count);
}

#[test]
fn run_corpus_deterministic() {
    let a = run_shipped_path_corpus();
    let b = run_shipped_path_corpus();
    assert_eq!(a, b);
}

#[test]
fn run_corpus_evidence_ids_match_corpus() {
    let corpus = shipped_path_corpus();
    let inv = run_shipped_path_corpus();
    let corpus_ids: Vec<&str> = corpus.iter().map(|s| s.specimen_id.as_str()).collect();
    let evidence_ids: Vec<&str> = inv.evidence.iter().map(|e| e.specimen_id.as_str()).collect();
    assert_eq!(corpus_ids, evidence_ids);
}

#[test]
fn run_corpus_js_not_normalized() {
    let inv = run_shipped_path_corpus();
    for ev in &inv.evidence {
        if ev.expected_language == SourceLanguage::JavaScript {
            assert!(
                !ev.actual_normalization,
                "JS specimen {} was unexpectedly normalized",
                ev.specimen_id
            );
        }
    }
}

#[test]
fn run_corpus_ts_are_normalized() {
    let inv = run_shipped_path_corpus();
    for ev in &inv.evidence {
        if ev.expected_language == SourceLanguage::TypeScript
            && ev.expected_outcome == ShippedPathExpectedOutcome::ExecuteSuccess
        {
            assert!(
                ev.actual_normalization,
                "TS specimen {} was not normalized",
                ev.specimen_id
            );
        }
    }
}

#[test]
fn run_corpus_language_detection_correct() {
    let inv = run_shipped_path_corpus();
    for ev in &inv.evidence {
        assert_eq!(
            ev.expected_language, ev.actual_language,
            "language mismatch for {}",
            ev.specimen_id
        );
    }
}

#[test]
fn run_corpus_schema_version_matches_constant() {
    let inv = run_shipped_path_corpus();
    assert_eq!(inv.schema_version, TS_SHIPPED_PATH_SCHEMA_VERSION);
}

#[test]
fn run_corpus_component_matches_constant() {
    let inv = run_shipped_path_corpus();
    assert_eq!(inv.component, TS_SHIPPED_PATH_COMPONENT);
}

// ===========================================================================
// 3. Schema constants
// ===========================================================================

#[test]
fn schema_versions_non_empty() {
    assert!(!TS_SHIPPED_PATH_SCHEMA_VERSION.is_empty());
    assert!(!TS_SHIPPED_PATH_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(!TS_SHIPPED_PATH_EVENT_SCHEMA_VERSION.is_empty());
}

#[test]
fn schema_versions_all_distinct() {
    let versions = [
        TS_SHIPPED_PATH_SCHEMA_VERSION,
        TS_SHIPPED_PATH_MANIFEST_SCHEMA_VERSION,
        TS_SHIPPED_PATH_EVENT_SCHEMA_VERSION,
    ];
    let set: BTreeSet<&str> = versions.iter().copied().collect();
    assert_eq!(set.len(), versions.len());
}

#[test]
fn schema_versions_prefixed() {
    assert!(TS_SHIPPED_PATH_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(TS_SHIPPED_PATH_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(TS_SHIPPED_PATH_EVENT_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn component_constant_matches_module_name() {
    assert_eq!(TS_SHIPPED_PATH_COMPONENT, "ts_shipped_path_evidence");
}

#[test]
fn policy_id_non_empty() {
    assert!(!TS_SHIPPED_PATH_POLICY_ID.is_empty());
}

// ===========================================================================
// 4. Serde round-trips
// ===========================================================================

#[test]
fn inventory_serde_roundtrip() {
    let inv = run_shipped_path_corpus();
    let json = serde_json::to_string_pretty(&inv).unwrap();
    let back: TsShippedPathEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

#[test]
fn specimen_serde_roundtrip() {
    for s in &shipped_path_corpus() {
        let json = serde_json::to_string(s).unwrap();
        let back: ShippedPathSpecimen = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn evidence_serde_roundtrip() {
    let inv = run_shipped_path_corpus();
    for ev in &inv.evidence {
        let json = serde_json::to_string(ev).unwrap();
        let back: ShippedPathSpecimenEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(*ev, back);
    }
}

#[test]
fn expected_outcome_serde_all_variants() {
    for variant in [
        ShippedPathExpectedOutcome::ExecuteSuccess,
        ShippedPathExpectedOutcome::NormalizationFailure,
        ShippedPathExpectedOutcome::ParseFailure,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: ShippedPathExpectedOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn actual_outcome_serde_all_variants() {
    for variant in [
        ShippedPathActualOutcome::ExecuteSuccess,
        ShippedPathActualOutcome::NormalizationFailure,
        ShippedPathActualOutcome::ParseFailure,
        ShippedPathActualOutcome::OtherFailure,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: ShippedPathActualOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn verdict_serde_all_variants() {
    for variant in [ShippedPathVerdict::Pass, ShippedPathVerdict::Fail] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: ShippedPathVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn manifest_serde_roundtrip() {
    let m = ShippedPathEvidenceRunManifest {
        schema_version: TS_SHIPPED_PATH_MANIFEST_SCHEMA_VERSION.into(),
        component: TS_SHIPPED_PATH_COMPONENT.into(),
        trace_id: "trace-1".into(),
        decision_id: "decision-1".into(),
        policy_id: TS_SHIPPED_PATH_POLICY_ID.into(),
        inventory_hash: "abc123".into(),
        specimen_count: 15,
        pass_count: 15,
        fail_count: 0,
        contract_satisfied: true,
        artifact_paths: ShippedPathEvidenceArtifactPaths {
            evidence_inventory: "inventory.json".into(),
            run_manifest: "manifest.json".into(),
            events_jsonl: "events.jsonl".into(),
            commands_txt: "commands.txt".into(),
        },
    };
    let json = serde_json::to_string_pretty(&m).unwrap();
    let back: ShippedPathEvidenceRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn event_serde_roundtrip() {
    let ev = ShippedPathEvidenceEvent {
        schema_version: TS_SHIPPED_PATH_EVENT_SCHEMA_VERSION.into(),
        component: TS_SHIPPED_PATH_COMPONENT.into(),
        event: "test_event".into(),
        policy_id: TS_SHIPPED_PATH_POLICY_ID.into(),
        specimen_id: Some("specimen-1".into()),
        verdict: Some("pass".into()),
        detail: Some("detail text".into()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: ShippedPathEvidenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ===========================================================================
// 5. Contract semantics
// ===========================================================================

#[test]
fn contract_satisfied_when_all_pass() {
    let inv = TsShippedPathEvidenceInventory {
        schema_version: TS_SHIPPED_PATH_SCHEMA_VERSION.into(),
        component: TS_SHIPPED_PATH_COMPONENT.into(),
        specimen_count: 10,
        pass_count: 10,
        fail_count: 0,
        js_count: 4,
        ts_count: 6,
        evidence: vec![],
    };
    assert!(inv.contract_satisfied());
}

#[test]
fn contract_not_satisfied_when_any_fail() {
    let inv = TsShippedPathEvidenceInventory {
        schema_version: TS_SHIPPED_PATH_SCHEMA_VERSION.into(),
        component: TS_SHIPPED_PATH_COMPONENT.into(),
        specimen_count: 10,
        pass_count: 9,
        fail_count: 1,
        js_count: 4,
        ts_count: 6,
        evidence: vec![],
    };
    assert!(!inv.contract_satisfied());
}

#[test]
fn contract_not_satisfied_when_empty_corpus() {
    let inv = TsShippedPathEvidenceInventory {
        schema_version: TS_SHIPPED_PATH_SCHEMA_VERSION.into(),
        component: TS_SHIPPED_PATH_COMPONENT.into(),
        specimen_count: 0,
        pass_count: 0,
        fail_count: 0,
        js_count: 0,
        ts_count: 0,
        evidence: vec![],
    };
    assert!(!inv.contract_satisfied());
}

// ===========================================================================
// 6. Bundle writer
// ===========================================================================

fn test_dir(suffix: &str) -> std::path::PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tid = std::thread::current().id();
    std::env::temp_dir().join(format!("franken_ts_shipped_path_integ_{suffix}-{ts}-{tid:?}"))
}

#[test]
fn write_bundle_creates_all_artifacts() {
    let dir = test_dir("creates");

    let commands = vec!["cargo test --lib".to_string()];
    let artifacts = write_shipped_path_evidence_bundle(&dir, &commands).unwrap();

    assert!(artifacts.inventory_path.exists());
    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.events_path.exists());
    assert!(artifacts.commands_path.exists());

}

#[test]
fn write_bundle_inventory_is_valid_json() {
    let dir = test_dir("inv_json");

    let artifacts =
        write_shipped_path_evidence_bundle(&dir, &["cmd".to_string()]).unwrap();

    let content = std::fs::read_to_string(&artifacts.inventory_path).unwrap();
    let inv: TsShippedPathEvidenceInventory = serde_json::from_str(&content).unwrap();
    assert!(inv.contract_satisfied());

}

#[test]
fn write_bundle_manifest_is_valid_json() {
    let dir = test_dir("manifest_json");

    let artifacts =
        write_shipped_path_evidence_bundle(&dir, &["cmd".to_string()]).unwrap();

    let content = std::fs::read_to_string(&artifacts.run_manifest_path).unwrap();
    let manifest: ShippedPathEvidenceRunManifest = serde_json::from_str(&content).unwrap();
    assert!(manifest.contract_satisfied);
    assert_eq!(manifest.policy_id, TS_SHIPPED_PATH_POLICY_ID);

}

#[test]
fn write_bundle_events_are_jsonl() {
    let dir = test_dir("events_jsonl");

    let artifacts =
        write_shipped_path_evidence_bundle(&dir, &["cmd".to_string()]).unwrap();

    let content = std::fs::read_to_string(&artifacts.events_path).unwrap();
    for line in content.lines() {
        let _ev: ShippedPathEvidenceEvent = serde_json::from_str(line).unwrap();
    }
    // At least start + per-specimen + end = 1 + N + 1
    let corpus_len = shipped_path_corpus().len();
    assert!(content.lines().count() >= corpus_len + 2);

}

#[test]
fn write_bundle_commands_recorded() {
    let dir = test_dir("commands");

    let commands = vec!["alpha".to_string(), "beta".to_string()];
    let artifacts = write_shipped_path_evidence_bundle(&dir, &commands).unwrap();

    let content = std::fs::read_to_string(&artifacts.commands_path).unwrap();
    assert!(content.contains("alpha"));
    assert!(content.contains("beta"));

}

#[test]
fn write_bundle_inventory_hash_non_empty() {
    let dir = test_dir("hash_nonempty");

    let artifacts =
        write_shipped_path_evidence_bundle(&dir, &["cmd".to_string()]).unwrap();
    assert!(!artifacts.inventory_hash.is_empty());
    assert_eq!(artifacts.inventory_hash.len(), 64, "SHA-256 hex = 64 chars");

}

#[test]
fn write_bundle_hash_deterministic() {
    let dir1 = test_dir("hash_det_1");
    let dir2 = test_dir("hash_det_2");


    let a = write_shipped_path_evidence_bundle(&dir1, &["cmd".to_string()]).unwrap();
    let b = write_shipped_path_evidence_bundle(&dir2, &["cmd".to_string()]).unwrap();
    assert_eq!(a.inventory_hash, b.inventory_hash);


}
