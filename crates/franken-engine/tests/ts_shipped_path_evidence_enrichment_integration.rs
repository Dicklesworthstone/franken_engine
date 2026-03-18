//! Enrichment integration tests for `ts_shipped_path_evidence`.
//!
//! Covers gaps: corpus coverage completeness, specimen structure validation,
//! run_shipped_path_corpus correctness, verdict classification logic,
//! ShippedPathVerdict and ShippedPathExpectedOutcome serde roundtrips,
//! TsShippedPathEvidenceInventory contract_satisfied semantics,
//! evidence manifest fields, Display uniqueness, constant values,
//! and language detection correctness for JS/TS/TSX specimens.

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

use std::collections::BTreeSet;

use frankenengine_engine::ts_normalization::SourceLanguage;
use frankenengine_engine::ts_shipped_path_evidence::{
    ShippedPathActualOutcome, ShippedPathExpectedOutcome, ShippedPathSpecimen,
    ShippedPathSpecimenEvidence, ShippedPathVerdict, TS_SHIPPED_PATH_COMPONENT,
    TS_SHIPPED_PATH_EVENT_SCHEMA_VERSION, TS_SHIPPED_PATH_MANIFEST_SCHEMA_VERSION,
    TS_SHIPPED_PATH_POLICY_ID, TS_SHIPPED_PATH_SCHEMA_VERSION, TsShippedPathEvidenceInventory,
    run_shipped_path_corpus, shipped_path_corpus,
};

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_schema_version_has_prefix() {
    assert!(TS_SHIPPED_PATH_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn enrichment_manifest_schema_version_has_prefix() {
    assert!(TS_SHIPPED_PATH_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn enrichment_event_schema_version_has_prefix() {
    assert!(TS_SHIPPED_PATH_EVENT_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn enrichment_component_name_correct() {
    assert_eq!(TS_SHIPPED_PATH_COMPONENT, "ts_shipped_path_evidence");
}

#[test]
fn enrichment_policy_id_nonempty() {
    assert!(!TS_SHIPPED_PATH_POLICY_ID.is_empty());
}

// ===========================================================================
// shipped_path_corpus
// ===========================================================================

#[test]
fn enrichment_corpus_nonempty() {
    let corpus = shipped_path_corpus();
    assert!(!corpus.is_empty());
}

#[test]
fn enrichment_corpus_has_at_least_15_specimens() {
    let corpus = shipped_path_corpus();
    assert!(
        corpus.len() >= 15,
        "Corpus should have at least 15 specimens, got {}",
        corpus.len()
    );
}

#[test]
fn enrichment_corpus_specimen_ids_unique() {
    let corpus = shipped_path_corpus();
    let ids: BTreeSet<&str> = corpus.iter().map(|s| s.specimen_id.as_str()).collect();
    assert_eq!(ids.len(), corpus.len(), "All specimen IDs must be unique");
}

#[test]
fn enrichment_corpus_has_js_specimens() {
    let corpus = shipped_path_corpus();
    let js_count = corpus
        .iter()
        .filter(|s| s.expected_language == SourceLanguage::JavaScript)
        .count();
    assert!(
        js_count >= 5,
        "Should have at least 5 JS specimens, got {js_count}"
    );
}

#[test]
fn enrichment_corpus_has_ts_specimens() {
    let corpus = shipped_path_corpus();
    let ts_count = corpus
        .iter()
        .filter(|s| s.expected_language == SourceLanguage::TypeScript)
        .count();
    assert!(
        ts_count >= 5,
        "Should have at least 5 TS specimens, got {ts_count}"
    );
}

#[test]
fn enrichment_corpus_js_specimens_expect_no_normalization() {
    let corpus = shipped_path_corpus();
    for specimen in &corpus {
        if specimen.expected_language == SourceLanguage::JavaScript {
            assert!(
                !specimen.expected_normalization,
                "JS specimen {} should not expect normalization",
                specimen.specimen_id
            );
        }
    }
}

#[test]
fn enrichment_corpus_ts_specimens_expect_normalization() {
    let corpus = shipped_path_corpus();
    for specimen in &corpus {
        if specimen.expected_language == SourceLanguage::TypeScript {
            assert!(
                specimen.expected_normalization,
                "TS specimen {} should expect normalization",
                specimen.specimen_id
            );
        }
    }
}

#[test]
fn enrichment_corpus_specimens_have_nonempty_source() {
    let corpus = shipped_path_corpus();
    for specimen in &corpus {
        assert!(
            !specimen.source.is_empty(),
            "Specimen {} should have non-empty source",
            specimen.specimen_id
        );
    }
}

#[test]
fn enrichment_corpus_specimens_have_descriptions() {
    let corpus = shipped_path_corpus();
    for specimen in &corpus {
        assert!(
            !specimen.description.is_empty(),
            "Specimen {} should have a description",
            specimen.specimen_id
        );
    }
}

// ===========================================================================
// ShippedPathExpectedOutcome serde roundtrip
// ===========================================================================

#[test]
fn enrichment_expected_outcome_serde_roundtrip() {
    let outcomes = [
        ShippedPathExpectedOutcome::ExecuteSuccess,
        ShippedPathExpectedOutcome::NormalizationFailure,
        ShippedPathExpectedOutcome::ParseFailure,
    ];
    for outcome in &outcomes {
        let json = serde_json::to_string(outcome).unwrap();
        let back: ShippedPathExpectedOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*outcome, back);
    }
}

// ===========================================================================
// ShippedPathActualOutcome serde roundtrip
// ===========================================================================

#[test]
fn enrichment_actual_outcome_serde_roundtrip() {
    let outcomes = [
        ShippedPathActualOutcome::ExecuteSuccess,
        ShippedPathActualOutcome::NormalizationFailure,
        ShippedPathActualOutcome::ParseFailure,
        ShippedPathActualOutcome::OtherFailure,
    ];
    for outcome in &outcomes {
        let json = serde_json::to_string(outcome).unwrap();
        let back: ShippedPathActualOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*outcome, back);
    }
}

// ===========================================================================
// ShippedPathVerdict serde roundtrip
// ===========================================================================

#[test]
fn enrichment_verdict_serde_roundtrip() {
    let verdicts = [ShippedPathVerdict::Pass, ShippedPathVerdict::Fail];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let back: ShippedPathVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// run_shipped_path_corpus
// ===========================================================================

#[test]
fn enrichment_run_corpus_returns_inventory() {
    let inventory = run_shipped_path_corpus();
    assert!(inventory.specimen_count > 0);
}

#[test]
fn enrichment_run_corpus_schema_version_correct() {
    let inventory = run_shipped_path_corpus();
    assert_eq!(inventory.schema_version, TS_SHIPPED_PATH_SCHEMA_VERSION);
}

#[test]
fn enrichment_run_corpus_component_correct() {
    let inventory = run_shipped_path_corpus();
    assert_eq!(inventory.component, TS_SHIPPED_PATH_COMPONENT);
}

#[test]
fn enrichment_run_corpus_counts_consistent() {
    let inventory = run_shipped_path_corpus();
    assert_eq!(
        inventory.pass_count + inventory.fail_count,
        inventory.specimen_count,
        "pass + fail should equal total specimens"
    );
}

#[test]
fn enrichment_run_corpus_js_ts_counts_consistent() {
    let inventory = run_shipped_path_corpus();
    assert_eq!(
        inventory.js_count + inventory.ts_count,
        inventory.specimen_count,
        "js + ts should equal total specimens"
    );
}

#[test]
fn enrichment_run_corpus_evidence_length_matches_count() {
    let inventory = run_shipped_path_corpus();
    assert_eq!(
        inventory.evidence.len() as u64,
        inventory.specimen_count,
        "Evidence entries should match specimen count"
    );
}

#[test]
fn enrichment_run_corpus_each_evidence_has_verdict() {
    let inventory = run_shipped_path_corpus();
    for ev in &inventory.evidence {
        assert!(
            ev.verdict == ShippedPathVerdict::Pass || ev.verdict == ShippedPathVerdict::Fail,
            "Evidence for {} should have a verdict",
            ev.specimen_id
        );
    }
}

#[test]
fn enrichment_run_corpus_evidence_ids_match_corpus() {
    let corpus = shipped_path_corpus();
    let inventory = run_shipped_path_corpus();
    let corpus_ids: BTreeSet<&str> = corpus.iter().map(|s| s.specimen_id.as_str()).collect();
    let evidence_ids: BTreeSet<&str> = inventory
        .evidence
        .iter()
        .map(|e| e.specimen_id.as_str())
        .collect();
    assert_eq!(
        corpus_ids, evidence_ids,
        "Evidence should cover all corpus specimens"
    );
}

// ===========================================================================
// TsShippedPathEvidenceInventory: contract_satisfied
// ===========================================================================

#[test]
fn enrichment_contract_satisfied_when_all_pass() {
    let inventory = TsShippedPathEvidenceInventory {
        schema_version: "v1".to_string(),
        component: "test".to_string(),
        specimen_count: 3,
        pass_count: 3,
        fail_count: 0,
        js_count: 1,
        ts_count: 2,
        evidence: vec![],
    };
    assert!(inventory.contract_satisfied());
}

#[test]
fn enrichment_contract_not_satisfied_when_failures() {
    let inventory = TsShippedPathEvidenceInventory {
        schema_version: "v1".to_string(),
        component: "test".to_string(),
        specimen_count: 3,
        pass_count: 2,
        fail_count: 1,
        js_count: 1,
        ts_count: 2,
        evidence: vec![],
    };
    assert!(!inventory.contract_satisfied());
}

#[test]
fn enrichment_contract_not_satisfied_when_empty() {
    let inventory = TsShippedPathEvidenceInventory {
        schema_version: "v1".to_string(),
        component: "test".to_string(),
        specimen_count: 0,
        pass_count: 0,
        fail_count: 0,
        js_count: 0,
        ts_count: 0,
        evidence: vec![],
    };
    assert!(!inventory.contract_satisfied());
}

// ===========================================================================
// TsShippedPathEvidenceInventory serde roundtrip
// ===========================================================================

#[test]
fn enrichment_inventory_serde_roundtrip() {
    let inventory = run_shipped_path_corpus();
    let json = serde_json::to_string(&inventory).unwrap();
    let back: TsShippedPathEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inventory.specimen_count, back.specimen_count);
    assert_eq!(inventory.pass_count, back.pass_count);
    assert_eq!(inventory.fail_count, back.fail_count);
    assert_eq!(inventory.js_count, back.js_count);
    assert_eq!(inventory.ts_count, back.ts_count);
}

// ===========================================================================
// ShippedPathSpecimen serde roundtrip
// ===========================================================================

#[test]
fn enrichment_specimen_serde_roundtrip() {
    let corpus = shipped_path_corpus();
    let specimen = &corpus[0];
    let json = serde_json::to_string(specimen).unwrap();
    let back: ShippedPathSpecimen = serde_json::from_str(&json).unwrap();
    assert_eq!(specimen.specimen_id, back.specimen_id);
    assert_eq!(specimen.expected_language, back.expected_language);
}

// ===========================================================================
// ShippedPathSpecimenEvidence serde roundtrip
// ===========================================================================

#[test]
fn enrichment_evidence_serde_roundtrip() {
    let inventory = run_shipped_path_corpus();
    if let Some(ev) = inventory.evidence.first() {
        let json = serde_json::to_string(ev).unwrap();
        let back: ShippedPathSpecimenEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(ev.specimen_id, back.specimen_id);
        assert_eq!(ev.verdict, back.verdict);
    }
}

// ===========================================================================
// Corpus determinism
// ===========================================================================

#[test]
fn enrichment_corpus_is_deterministic() {
    let c1 = shipped_path_corpus();
    let c2 = shipped_path_corpus();
    assert_eq!(c1.len(), c2.len());
    for (s1, s2) in c1.iter().zip(c2.iter()) {
        assert_eq!(s1.specimen_id, s2.specimen_id);
        assert_eq!(s1.source, s2.source);
    }
}

#[test]
fn enrichment_run_corpus_is_deterministic() {
    let i1 = run_shipped_path_corpus();
    let i2 = run_shipped_path_corpus();
    assert_eq!(i1.specimen_count, i2.specimen_count);
    assert_eq!(i1.pass_count, i2.pass_count);
    assert_eq!(i1.fail_count, i2.fail_count);
}

// ===========================================================================
// Specific specimen expectations
// ===========================================================================

#[test]
fn enrichment_corpus_contains_js_literal_specimen() {
    let corpus = shipped_path_corpus();
    assert!(
        corpus.iter().any(|s| s.specimen_id == "js_literal"),
        "Corpus should contain 'js_literal' specimen"
    );
}

#[test]
fn enrichment_corpus_contains_ts_type_annotation() {
    let corpus = shipped_path_corpus();
    assert!(
        corpus
            .iter()
            .any(|s| s.specimen_id.contains("ts_type_annotation")),
        "Corpus should contain a TS type annotation specimen"
    );
}

#[test]
fn enrichment_corpus_most_specimens_expect_success() {
    let corpus = shipped_path_corpus();
    let success_count = corpus
        .iter()
        .filter(|s| s.expected_outcome == ShippedPathExpectedOutcome::ExecuteSuccess)
        .count();
    assert!(
        success_count > corpus.len() / 2,
        "Most specimens should expect ExecuteSuccess"
    );
}
