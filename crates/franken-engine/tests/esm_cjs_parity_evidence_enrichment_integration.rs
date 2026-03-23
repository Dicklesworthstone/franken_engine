#![forbid(unsafe_code)]

//! Enrichment integration tests for the ESM/CJS parity evidence module.

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

use frankenengine_engine::esm_cjs_parity_evidence::{
    ESM_CJS_PARITY_COMPONENT, ESM_CJS_PARITY_EVENT_SCHEMA_VERSION,
    ESM_CJS_PARITY_MANIFEST_SCHEMA_VERSION, ESM_CJS_PARITY_POLICY_ID,
    ESM_CJS_PARITY_SCHEMA_VERSION, EsmCjsActualOutcome, EsmCjsCompatibilityDisposition,
    EsmCjsExpectedOutcome, EsmCjsParityArtifactPaths, EsmCjsParityEvent, EsmCjsParityRunManifest,
    EsmCjsParityVerdict, EsmCjsRemediationGuidance, InteropDirection, ModuleGraphTopology,
    esm_cjs_parity_corpus, run_esm_cjs_parity_corpus,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_artifact_paths() -> EsmCjsParityArtifactPaths {
    EsmCjsParityArtifactPaths {
        evidence_inventory: "inv.json".to_string(),
        run_manifest: "manifest.json".to_string(),
        events_jsonl: "events.jsonl".to_string(),
        commands_txt: "commands.txt".to_string(),
    }
}

fn make_manifest() -> EsmCjsParityRunManifest {
    EsmCjsParityRunManifest {
        schema_version: ESM_CJS_PARITY_MANIFEST_SCHEMA_VERSION.to_string(),
        component: ESM_CJS_PARITY_COMPONENT.to_string(),
        trace_id: "trace-001".to_string(),
        decision_id: "dec-001".to_string(),
        policy_id: ESM_CJS_PARITY_POLICY_ID.to_string(),
        inventory_hash: "abc123def456".to_string(),
        specimen_count: 16,
        pass_count: 16,
        fail_count: 0,
        supported_count: 16,
        degraded_count: 0,
        unsupported_count: 0,
        contract_satisfied: true,
        artifact_paths: make_artifact_paths(),
    }
}

fn make_event() -> EsmCjsParityEvent {
    EsmCjsParityEvent {
        schema_version: ESM_CJS_PARITY_EVENT_SCHEMA_VERSION.to_string(),
        component: ESM_CJS_PARITY_COMPONENT.to_string(),
        event: "specimen_evaluated".to_string(),
        policy_id: ESM_CJS_PARITY_POLICY_ID.to_string(),
        specimen_id: Some("sp-1".to_string()),
        verdict: Some("pass".to_string()),
        detail: Some("ok".to_string()),
    }
}

// ---------------------------------------------------------------------------
// ModuleGraphTopology — Copy / BTreeSet / Clone / Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_topology_copy_semantics() {
    let a = ModuleGraphTopology::Mixed;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_topology_btreeset_dedup_3() {
    let mut set = BTreeSet::new();
    set.insert(ModuleGraphTopology::Mixed);
    set.insert(ModuleGraphTopology::PureCjs);
    set.insert(ModuleGraphTopology::PureEsm);
    set.insert(ModuleGraphTopology::Mixed);
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_topology_clone_independence() {
    let a = ModuleGraphTopology::PureEsm;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_topology_debug_all_unique() {
    let all = [
        ModuleGraphTopology::Mixed,
        ModuleGraphTopology::PureCjs,
        ModuleGraphTopology::PureEsm,
    ];
    let dbgs: BTreeSet<String> = all.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 3);
}

// ---------------------------------------------------------------------------
// InteropDirection — Copy / BTreeSet / Clone / Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_interop_direction_copy_semantics() {
    let a = InteropDirection::Bidirectional;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_interop_direction_btreeset_dedup_4() {
    let mut set = BTreeSet::new();
    set.insert(InteropDirection::None);
    set.insert(InteropDirection::EsmImportsCjs);
    set.insert(InteropDirection::CjsRequiresEsm);
    set.insert(InteropDirection::Bidirectional);
    set.insert(InteropDirection::None);
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_interop_direction_clone_independence() {
    let a = InteropDirection::EsmImportsCjs;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_interop_direction_debug_all_unique() {
    let all = [
        InteropDirection::None,
        InteropDirection::EsmImportsCjs,
        InteropDirection::CjsRequiresEsm,
        InteropDirection::Bidirectional,
    ];
    let dbgs: BTreeSet<String> = all.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 4);
}

// ---------------------------------------------------------------------------
// EsmCjsExpectedOutcome — Copy / BTreeSet / Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_expected_outcome_copy_semantics() {
    let a = EsmCjsExpectedOutcome::ExecuteSuccess;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_expected_outcome_btreeset_dedup_5() {
    let mut set = BTreeSet::new();
    set.insert(EsmCjsExpectedOutcome::ExecuteSuccess);
    set.insert(EsmCjsExpectedOutcome::ResolutionFailure);
    set.insert(EsmCjsExpectedOutcome::LinkingFailure);
    set.insert(EsmCjsExpectedOutcome::EvaluationFailure);
    set.insert(EsmCjsExpectedOutcome::ParseFailure);
    set.insert(EsmCjsExpectedOutcome::ExecuteSuccess);
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_expected_outcome_debug_all_unique() {
    let all = [
        EsmCjsExpectedOutcome::ExecuteSuccess,
        EsmCjsExpectedOutcome::ResolutionFailure,
        EsmCjsExpectedOutcome::LinkingFailure,
        EsmCjsExpectedOutcome::EvaluationFailure,
        EsmCjsExpectedOutcome::ParseFailure,
    ];
    let dbgs: BTreeSet<String> = all.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 5);
}

// ---------------------------------------------------------------------------
// EsmCjsActualOutcome — Copy / BTreeSet / Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_actual_outcome_copy_semantics() {
    let a = EsmCjsActualOutcome::OtherFailure;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_actual_outcome_btreeset_dedup_6() {
    let mut set = BTreeSet::new();
    set.insert(EsmCjsActualOutcome::ExecuteSuccess);
    set.insert(EsmCjsActualOutcome::ResolutionFailure);
    set.insert(EsmCjsActualOutcome::LinkingFailure);
    set.insert(EsmCjsActualOutcome::EvaluationFailure);
    set.insert(EsmCjsActualOutcome::ParseFailure);
    set.insert(EsmCjsActualOutcome::OtherFailure);
    set.insert(EsmCjsActualOutcome::ExecuteSuccess);
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_actual_outcome_debug_all_unique() {
    let all = [
        EsmCjsActualOutcome::ExecuteSuccess,
        EsmCjsActualOutcome::ResolutionFailure,
        EsmCjsActualOutcome::LinkingFailure,
        EsmCjsActualOutcome::EvaluationFailure,
        EsmCjsActualOutcome::ParseFailure,
        EsmCjsActualOutcome::OtherFailure,
    ];
    let dbgs: BTreeSet<String> = all.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 6);
}

// ---------------------------------------------------------------------------
// EsmCjsParityVerdict — Copy / BTreeSet / Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verdict_copy_semantics() {
    let a = EsmCjsParityVerdict::Pass;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_verdict_btreeset_dedup_2() {
    let mut set = BTreeSet::new();
    set.insert(EsmCjsParityVerdict::Pass);
    set.insert(EsmCjsParityVerdict::Fail);
    set.insert(EsmCjsParityVerdict::Pass);
    assert_eq!(set.len(), 2);
}

#[test]
fn enrichment_verdict_debug_all_unique() {
    let all = [EsmCjsParityVerdict::Pass, EsmCjsParityVerdict::Fail];
    let dbgs: BTreeSet<String> = all.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 2);
}

// ---------------------------------------------------------------------------
// EsmCjsCompatibilityDisposition / guidance
// ---------------------------------------------------------------------------

#[test]
fn enrichment_compatibility_disposition_all_variants_serde_and_display() {
    for disposition in [
        EsmCjsCompatibilityDisposition::Supported,
        EsmCjsCompatibilityDisposition::Degraded,
        EsmCjsCompatibilityDisposition::Unsupported,
    ] {
        let json = serde_json::to_string(&disposition).unwrap();
        let back: EsmCjsCompatibilityDisposition = serde_json::from_str(&json).unwrap();
        assert_eq!(disposition, back);
        assert_eq!(disposition.to_string(), disposition.as_str());
    }
}

#[test]
fn enrichment_remediation_guidance_serde_roundtrip() {
    let guidance = EsmCjsRemediationGuidance {
        guidance_code: "repair_module_source".to_string(),
        message: "fix the source contract".to_string(),
    };
    let json = serde_json::to_string(&guidance).unwrap();
    let back: EsmCjsRemediationGuidance = serde_json::from_str(&json).unwrap();
    assert_eq!(guidance, back);
}

// ---------------------------------------------------------------------------
// EsmCjsParitySpecimen — Clone / Debug / JSON (via corpus)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_specimen_clone_independence() {
    let corpus = esm_cjs_parity_corpus();
    let a = &corpus[0];
    let b = a.clone();
    assert_eq!(*a, b);
}

#[test]
fn enrichment_specimen_debug_nonempty() {
    let corpus = esm_cjs_parity_corpus();
    assert!(!format!("{:?}", corpus[0]).is_empty());
}

#[test]
fn enrichment_specimen_json_field_names() {
    let corpus = esm_cjs_parity_corpus();
    let json = serde_json::to_string(&corpus[0]).unwrap();
    for field in &[
        "specimen_id",
        "description",
        "source",
        "expected_syntax",
        "topology",
        "interop_direction",
        "expected_outcome",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_specimen_serde_roundtrip_all() {
    let corpus = esm_cjs_parity_corpus();
    for specimen in &corpus {
        let json = serde_json::to_string(specimen).unwrap();
        let rt: frankenengine_engine::esm_cjs_parity_evidence::EsmCjsParitySpecimen =
            serde_json::from_str(&json).unwrap();
        assert_eq!(*specimen, rt);
    }
}

// ---------------------------------------------------------------------------
// EsmCjsParitySpecimenEvidence — Clone / Debug / JSON (via run_corpus)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_specimen_evidence_clone_independence() {
    let inv = run_esm_cjs_parity_corpus();
    let a = &inv.evidence[0];
    let b = a.clone();
    assert_eq!(*a, b);
}

#[test]
fn enrichment_specimen_evidence_debug_nonempty() {
    let inv = run_esm_cjs_parity_corpus();
    assert!(!format!("{:?}", inv.evidence[0]).is_empty());
}

#[test]
fn enrichment_specimen_evidence_json_field_names() {
    let inv = run_esm_cjs_parity_corpus();
    let json = serde_json::to_string(&inv.evidence[0]).unwrap();
    for field in &[
        "specimen_id",
        "expected_syntax",
        "topology",
        "interop_direction",
        "expected_outcome",
        "actual_outcome",
        "verdict",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

// ---------------------------------------------------------------------------
// EsmCjsParityEvidenceInventory — Clone / Debug / JSON
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evidence_inventory_clone_independence() {
    let a = run_esm_cjs_parity_corpus();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_evidence_inventory_debug_nonempty() {
    assert!(!format!("{:?}", run_esm_cjs_parity_corpus()).is_empty());
}

#[test]
fn enrichment_evidence_inventory_json_field_names() {
    let inv = run_esm_cjs_parity_corpus();
    let json = serde_json::to_string(&inv).unwrap();
    for field in &[
        "schema_version",
        "component",
        "specimen_count",
        "pass_count",
        "fail_count",
        "pure_esm_count",
        "pure_cjs_count",
        "mixed_count",
        "evidence",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

// ---------------------------------------------------------------------------
// EsmCjsParityRunManifest — Clone / Debug / JSON / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_run_manifest_clone_independence() {
    let a = make_manifest();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_run_manifest_debug_nonempty() {
    assert!(!format!("{:?}", make_manifest()).is_empty());
}

#[test]
fn enrichment_run_manifest_json_field_names() {
    let json = serde_json::to_string(&make_manifest()).unwrap();
    for field in &[
        "schema_version",
        "component",
        "trace_id",
        "decision_id",
        "policy_id",
        "inventory_hash",
        "specimen_count",
        "pass_count",
        "fail_count",
        "contract_satisfied",
        "artifact_paths",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_run_manifest_serde_roundtrip() {
    let a = make_manifest();
    let json = serde_json::to_string(&a).unwrap();
    let b: EsmCjsParityRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// EsmCjsParityArtifactPaths — Clone / Debug / JSON / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_artifact_paths_clone_independence() {
    let a = make_artifact_paths();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_artifact_paths_debug_nonempty() {
    assert!(!format!("{:?}", make_artifact_paths()).is_empty());
}

#[test]
fn enrichment_artifact_paths_json_field_names() {
    let json = serde_json::to_string(&make_artifact_paths()).unwrap();
    for field in &[
        "evidence_inventory",
        "run_manifest",
        "events_jsonl",
        "commands_txt",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_artifact_paths_serde_roundtrip() {
    let a = make_artifact_paths();
    let json = serde_json::to_string(&a).unwrap();
    let b: EsmCjsParityArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// EsmCjsParityEvent — Clone / Debug / JSON / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evidence_event_clone_independence() {
    let a = make_event();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_evidence_event_debug_nonempty() {
    assert!(!format!("{:?}", make_event()).is_empty());
}

#[test]
fn enrichment_evidence_event_json_field_names() {
    let json = serde_json::to_string(&make_event()).unwrap();
    for field in &[
        "schema_version",
        "component",
        "event",
        "policy_id",
        "specimen_id",
        "verdict",
        "detail",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_evidence_event_serde_roundtrip() {
    let a = make_event();
    let json = serde_json::to_string(&a).unwrap();
    let b: EsmCjsParityEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(a, b);
}

#[test]
fn enrichment_evidence_event_with_nones() {
    let a = EsmCjsParityEvent {
        schema_version: ESM_CJS_PARITY_EVENT_SCHEMA_VERSION.to_string(),
        component: ESM_CJS_PARITY_COMPONENT.to_string(),
        event: "run_started".to_string(),
        policy_id: ESM_CJS_PARITY_POLICY_ID.to_string(),
        specimen_id: None,
        verdict: None,
        detail: None,
    };
    let json = serde_json::to_string(&a).unwrap();
    let b: EsmCjsParityEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// Constants stability
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_exact_values() {
    assert_eq!(
        ESM_CJS_PARITY_SCHEMA_VERSION,
        "franken-engine.esm_cjs_parity_evidence.v1"
    );
    assert_eq!(
        ESM_CJS_PARITY_MANIFEST_SCHEMA_VERSION,
        "franken-engine.esm_cjs_parity_manifest.v1"
    );
    assert_eq!(
        ESM_CJS_PARITY_EVENT_SCHEMA_VERSION,
        "franken-engine.esm_cjs_parity_event.v1"
    );
    assert_eq!(ESM_CJS_PARITY_COMPONENT, "esm_cjs_parity_evidence");
    assert_eq!(ESM_CJS_PARITY_POLICY_ID, "RGC-309C");
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_five_run_determinism_corpus() {
    let jsons: BTreeSet<String> = (0..5)
        .map(|_| serde_json::to_string(&esm_cjs_parity_corpus()).unwrap())
        .collect();
    assert_eq!(jsons.len(), 1, "corpus should be deterministic");
}

#[test]
fn enrichment_five_run_determinism_inventory() {
    let jsons: BTreeSet<String> = (0..5)
        .map(|_| serde_json::to_string(&run_esm_cjs_parity_corpus()).unwrap())
        .collect();
    assert_eq!(jsons.len(), 1, "inventory should be deterministic");
}

// ---------------------------------------------------------------------------
// Cross-cutting invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cross_cutting_all_evidence_has_verdict() {
    let inv = run_esm_cjs_parity_corpus();
    for ev in &inv.evidence {
        // Every evidence entry should have a definite verdict
        let _ = ev.verdict; // just verify it's accessible
    }
}

#[test]
fn enrichment_cross_cutting_topology_counts_sum() {
    let inv = run_esm_cjs_parity_corpus();
    let sum = inv.pure_esm_count + inv.pure_cjs_count + inv.mixed_count;
    assert_eq!(
        sum, inv.specimen_count,
        "topology counts should sum to specimen_count"
    );
}

#[test]
fn enrichment_cross_cutting_pass_fail_sum() {
    let inv = run_esm_cjs_parity_corpus();
    assert_eq!(inv.pass_count + inv.fail_count, inv.specimen_count);
}

#[test]
fn enrichment_cross_cutting_evidence_count_matches() {
    let inv = run_esm_cjs_parity_corpus();
    assert_eq!(inv.evidence.len() as u64, inv.specimen_count);
}

#[test]
fn enrichment_cross_cutting_corpus_ids_match_evidence() {
    let corpus = esm_cjs_parity_corpus();
    let inv = run_esm_cjs_parity_corpus();
    let corpus_ids: BTreeSet<&str> = corpus.iter().map(|s| s.specimen_id.as_str()).collect();
    let evidence_ids: BTreeSet<&str> = inv
        .evidence
        .iter()
        .map(|e| e.specimen_id.as_str())
        .collect();
    assert_eq!(corpus_ids, evidence_ids);
}

#[test]
fn enrichment_cross_cutting_schema_version_in_inventory() {
    let inv = run_esm_cjs_parity_corpus();
    assert_eq!(inv.schema_version, ESM_CJS_PARITY_SCHEMA_VERSION);
}

#[test]
fn enrichment_cross_cutting_component_in_inventory() {
    let inv = run_esm_cjs_parity_corpus();
    assert_eq!(inv.component, ESM_CJS_PARITY_COMPONENT);
}

#[test]
fn enrichment_cross_cutting_mixed_or_interop_execute_success_is_not_supported() {
    let inv = run_esm_cjs_parity_corpus();
    for ev in inv.evidence.iter().filter(|ev| {
        ev.expected_outcome == EsmCjsExpectedOutcome::ExecuteSuccess
            && (ev.topology == ModuleGraphTopology::Mixed
                || ev.interop_direction != InteropDirection::None)
    }) {
        assert_eq!(
            ev.compatibility_disposition,
            EsmCjsCompatibilityDisposition::Degraded
        );
        assert_eq!(
            ev.remediation_guidance.guidance_code,
            "module_graph_oracle_required"
        );
    }
}
