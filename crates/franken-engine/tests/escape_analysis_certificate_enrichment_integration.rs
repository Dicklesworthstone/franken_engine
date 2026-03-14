#![forbid(unsafe_code)]

//! Enrichment integration tests for the escape analysis certificate module.

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

use frankenengine_engine::escape_analysis_certificate::{
    AliasClassId, AliasRelation, AllocationKind, AllocationSite, ESCAPE_CERT_COMPONENT,
    ESCAPE_CERT_EVENT_SCHEMA_VERSION, ESCAPE_CERT_MANIFEST_SCHEMA_VERSION, ESCAPE_CERT_POLICY_ID,
    ESCAPE_CERT_SCHEMA_VERSION, EscapeAnalyzerConfig, EscapeCertArtifactPaths,
    EscapeCertEvidenceEvent, EscapeCertExpectedOutcome, EscapeCertRunManifest,
    EscapeCertSpecimenFamily, EscapeCertVerdict, EscapeState, InvalidationReason, LivenessEnvelope,
    OptimizationEligibilityEnvelope, analyze_escape, escape_cert_corpus, run_escape_cert_corpus,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_site(id: &str, scope: &str, kind: AllocationKind) -> AllocationSite {
    AllocationSite {
        site_id: id.to_string(),
        scope: scope.to_string(),
        allocation_kind: kind,
        estimated_size_bytes: Some(128),
    }
}

fn make_envelope() -> OptimizationEligibilityEnvelope {
    let sites = vec![
        make_site("s1", "fn_a", AllocationKind::ObjectLiteral),
        make_site("s2", "fn_a", AllocationKind::ArrayLiteral),
    ];
    let config = EscapeAnalyzerConfig::default();
    analyze_escape("fn_a", &sites, &[], &config, SecurityEpoch::from_raw(1))
}

fn make_artifact_paths() -> EscapeCertArtifactPaths {
    EscapeCertArtifactPaths {
        evidence_inventory: "inv.json".to_string(),
        run_manifest: "manifest.json".to_string(),
        events_jsonl: "events.jsonl".to_string(),
        commands_txt: "commands.txt".to_string(),
    }
}

// ---------------------------------------------------------------------------
// EscapeState — Copy / BTreeSet / Clone / Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_escape_state_copy_semantics() {
    let a = EscapeState::NoEscape;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_escape_state_btreeset_dedup_4() {
    let mut set = BTreeSet::new();
    set.insert(EscapeState::NoEscape);
    set.insert(EscapeState::ArgEscape);
    set.insert(EscapeState::ThreadEscape);
    set.insert(EscapeState::GlobalEscape);
    set.insert(EscapeState::NoEscape);
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_escape_state_clone_independence() {
    let a = EscapeState::GlobalEscape;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_escape_state_debug_all_unique() {
    let all = EscapeState::ALL;
    let dbgs: BTreeSet<String> = all.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), all.len());
}

// ---------------------------------------------------------------------------
// AliasRelation — Copy / BTreeSet / Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_alias_relation_copy_semantics() {
    let a = AliasRelation::MayAlias;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_alias_relation_btreeset_dedup_3() {
    let mut set = BTreeSet::new();
    set.insert(AliasRelation::NoAlias);
    set.insert(AliasRelation::MayAlias);
    set.insert(AliasRelation::MustAlias);
    set.insert(AliasRelation::NoAlias);
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_alias_relation_debug_all_unique() {
    let all = [
        AliasRelation::NoAlias,
        AliasRelation::MayAlias,
        AliasRelation::MustAlias,
    ];
    let dbgs: BTreeSet<String> = all.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 3);
}

// ---------------------------------------------------------------------------
// AllocationKind — Copy / BTreeSet / Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_allocation_kind_copy_semantics() {
    let a = AllocationKind::Closure;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_allocation_kind_btreeset_dedup_10() {
    let mut set = BTreeSet::new();
    for kind in AllocationKind::ALL {
        set.insert(*kind);
    }
    set.insert(AllocationKind::ObjectLiteral);
    assert_eq!(set.len(), 10);
}

#[test]
fn enrichment_allocation_kind_debug_all_unique() {
    let dbgs: BTreeSet<String> = AllocationKind::ALL
        .iter()
        .map(|v| format!("{:?}", v))
        .collect();
    assert_eq!(dbgs.len(), 10);
}

// ---------------------------------------------------------------------------
// InvalidationReason — Copy / BTreeSet / Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_invalidation_reason_copy_semantics() {
    let a = InvalidationReason::DynamicEval;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_invalidation_reason_btreeset_dedup_8() {
    let mut set = BTreeSet::new();
    set.insert(InvalidationReason::DynamicEval);
    set.insert(InvalidationReason::WithStatement);
    set.insert(InvalidationReason::DynamicPropertyAccess);
    set.insert(InvalidationReason::IndirectCall);
    set.insert(InvalidationReason::ExceptionEscape);
    set.insert(InvalidationReason::ProxyReflect);
    set.insert(InvalidationReason::BudgetExceeded);
    set.insert(InvalidationReason::CrossModuleUnresolvable);
    set.insert(InvalidationReason::DynamicEval);
    assert_eq!(set.len(), 8);
}

#[test]
fn enrichment_invalidation_reason_debug_all_unique() {
    let all = [
        InvalidationReason::DynamicEval,
        InvalidationReason::WithStatement,
        InvalidationReason::DynamicPropertyAccess,
        InvalidationReason::IndirectCall,
        InvalidationReason::ExceptionEscape,
        InvalidationReason::ProxyReflect,
        InvalidationReason::BudgetExceeded,
        InvalidationReason::CrossModuleUnresolvable,
    ];
    let dbgs: BTreeSet<String> = all.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 8);
}

// ---------------------------------------------------------------------------
// EscapeCertSpecimenFamily — Copy / BTreeSet / Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_specimen_family_copy_semantics() {
    let a = EscapeCertSpecimenFamily::EscapeClassification;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_specimen_family_btreeset_dedup_8() {
    let mut set = BTreeSet::new();
    for f in EscapeCertSpecimenFamily::ALL {
        set.insert(*f);
    }
    set.insert(EscapeCertSpecimenFamily::SerdeRoundtrip);
    assert_eq!(set.len(), 8);
}

#[test]
fn enrichment_specimen_family_debug_all_unique() {
    let dbgs: BTreeSet<String> = EscapeCertSpecimenFamily::ALL
        .iter()
        .map(|v| format!("{:?}", v))
        .collect();
    assert_eq!(dbgs.len(), 8);
}

// ---------------------------------------------------------------------------
// EscapeCertExpectedOutcome — Copy / BTreeSet
// ---------------------------------------------------------------------------

#[test]
fn enrichment_expected_outcome_copy_semantics() {
    let a = EscapeCertExpectedOutcome::Classified;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_expected_outcome_btreeset_dedup_10() {
    let mut set = BTreeSet::new();
    set.insert(EscapeCertExpectedOutcome::Classified);
    set.insert(EscapeCertExpectedOutcome::Abstained);
    set.insert(EscapeCertExpectedOutcome::Partitioned);
    set.insert(EscapeCertExpectedOutcome::LivenessKnown);
    set.insert(EscapeCertExpectedOutcome::LivenessUnknown);
    set.insert(EscapeCertExpectedOutcome::BudgetExceeded);
    set.insert(EscapeCertExpectedOutcome::EnvelopeComputed);
    set.insert(EscapeCertExpectedOutcome::CertificateGranted);
    set.insert(EscapeCertExpectedOutcome::CertificateDenied);
    set.insert(EscapeCertExpectedOutcome::RoundtripPreserved);
    set.insert(EscapeCertExpectedOutcome::Classified);
    assert_eq!(set.len(), 10);
}

#[test]
fn enrichment_expected_outcome_debug_all_unique() {
    let all = [
        EscapeCertExpectedOutcome::Classified,
        EscapeCertExpectedOutcome::Abstained,
        EscapeCertExpectedOutcome::Partitioned,
        EscapeCertExpectedOutcome::LivenessKnown,
        EscapeCertExpectedOutcome::LivenessUnknown,
        EscapeCertExpectedOutcome::BudgetExceeded,
        EscapeCertExpectedOutcome::EnvelopeComputed,
        EscapeCertExpectedOutcome::CertificateGranted,
        EscapeCertExpectedOutcome::CertificateDenied,
        EscapeCertExpectedOutcome::RoundtripPreserved,
    ];
    let dbgs: BTreeSet<String> = all.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 10);
}

// ---------------------------------------------------------------------------
// EscapeCertVerdict — Copy / BTreeSet
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verdict_copy_semantics() {
    let a = EscapeCertVerdict::Pass;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_verdict_btreeset_dedup_2() {
    let mut set = BTreeSet::new();
    set.insert(EscapeCertVerdict::Pass);
    set.insert(EscapeCertVerdict::Fail);
    set.insert(EscapeCertVerdict::Pass);
    assert_eq!(set.len(), 2);
}

// ---------------------------------------------------------------------------
// AliasClassId — Clone / Debug / Display
// ---------------------------------------------------------------------------

#[test]
fn enrichment_alias_class_id_clone_independence() {
    let a = AliasClassId::new("test_class");
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_alias_class_id_debug_nonempty() {
    let a = AliasClassId::new("cls");
    assert!(!format!("{:?}", a).is_empty());
}

#[test]
fn enrichment_alias_class_id_display_contains_id() {
    let a = AliasClassId::new("my_class");
    let disp = format!("{}", a);
    assert!(disp.contains("my_class"));
}

// ---------------------------------------------------------------------------
// LivenessEnvelope — Clone / Debug / JSON / span
// ---------------------------------------------------------------------------

#[test]
fn enrichment_liveness_clone_independence() {
    let a = LivenessEnvelope {
        first_use: Some(1),
        last_use: Some(10),
        precise: true,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_liveness_debug_nonempty() {
    let a = LivenessEnvelope {
        first_use: None,
        last_use: None,
        precise: false,
    };
    assert!(!format!("{:?}", a).is_empty());
}

#[test]
fn enrichment_liveness_json_field_names() {
    let a = LivenessEnvelope {
        first_use: Some(5),
        last_use: Some(15),
        precise: true,
    };
    let json = serde_json::to_string(&a).unwrap();
    assert!(json.contains("\"first_use\""));
    assert!(json.contains("\"last_use\""));
    assert!(json.contains("\"precise\""));
}

#[test]
fn enrichment_liveness_span_both_present() {
    let a = LivenessEnvelope {
        first_use: Some(3),
        last_use: Some(10),
        precise: true,
    };
    assert_eq!(a.span(), Some(7));
}

#[test]
fn enrichment_liveness_span_none_when_first_missing() {
    let a = LivenessEnvelope {
        first_use: None,
        last_use: Some(10),
        precise: false,
    };
    assert_eq!(a.span(), None);
}

#[test]
fn enrichment_liveness_is_known_precise() {
    let a = LivenessEnvelope {
        first_use: Some(1),
        last_use: Some(5),
        precise: true,
    };
    assert!(a.is_known());
}

// ---------------------------------------------------------------------------
// AllocationSite — Clone / Debug / JSON
// ---------------------------------------------------------------------------

#[test]
fn enrichment_allocation_site_clone_independence() {
    let a = make_site("s1", "fn_a", AllocationKind::Closure);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_allocation_site_debug_nonempty() {
    let a = make_site("s1", "fn_a", AllocationKind::ObjectLiteral);
    assert!(!format!("{:?}", a).is_empty());
}

#[test]
fn enrichment_allocation_site_json_field_names() {
    let a = make_site("s1", "fn_a", AllocationKind::ArrayLiteral);
    let json = serde_json::to_string(&a).unwrap();
    for field in &[
        "site_id",
        "scope",
        "allocation_kind",
        "estimated_size_bytes",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_allocation_site_serde_roundtrip() {
    let a = make_site("s1", "fn_a", AllocationKind::TemplateLiteral);
    let json = serde_json::to_string(&a).unwrap();
    let b: AllocationSite = serde_json::from_str(&json).unwrap();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// EscapeCertificate — via analyze_escape
// ---------------------------------------------------------------------------

#[test]
fn enrichment_certificate_clone_independence() {
    let env = make_envelope();
    let cert = env.certificates[0].clone();
    let cert2 = cert.clone();
    assert_eq!(cert, cert2);
}

#[test]
fn enrichment_certificate_debug_nonempty() {
    let env = make_envelope();
    assert!(!format!("{:?}", &env.certificates[0]).is_empty());
}

#[test]
fn enrichment_certificate_json_field_names() {
    let env = make_envelope();
    let json = serde_json::to_string(&env.certificates[0]).unwrap();
    for field in &[
        "schema_version",
        "site",
        "escape_state",
        "alias_class",
        "liveness",
        "scalar_replacement_eligible",
        "stack_allocation_eligible",
        "confidence_millionths",
        "invalidation_reasons",
        "abstention",
        "certificate_hash",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_certificate_is_granted_clean() {
    let env = make_envelope();
    for cert in &env.certificates {
        assert!(cert.is_granted(), "clean site should be granted");
    }
}

#[test]
fn enrichment_certificate_invalidated_not_granted() {
    let sites = vec![make_site("s1", "fn_a", AllocationKind::ObjectLiteral)];
    let invalidations = vec![("s1", InvalidationReason::DynamicEval)];
    let config = EscapeAnalyzerConfig::default();
    let env = analyze_escape(
        "fn_a",
        &sites,
        &invalidations,
        &config,
        SecurityEpoch::from_raw(1),
    );
    let cert = &env.certificates[0];
    assert!(!cert.is_granted());
}

#[test]
fn enrichment_certificate_serde_roundtrip() {
    let env = make_envelope();
    let cert = &env.certificates[0];
    let json = serde_json::to_string(cert).unwrap();
    let rt: frankenengine_engine::escape_analysis_certificate::EscapeCertificate =
        serde_json::from_str(&json).unwrap();
    assert_eq!(*cert, rt);
}

// ---------------------------------------------------------------------------
// OptimizationEligibilityEnvelope — Clone / Debug / JSON
// ---------------------------------------------------------------------------

#[test]
fn enrichment_envelope_clone_independence() {
    let a = make_envelope();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_envelope_debug_nonempty() {
    let env = make_envelope();
    assert!(!format!("{:?}", env).is_empty());
}

#[test]
fn enrichment_envelope_json_field_names() {
    let env = make_envelope();
    let json = serde_json::to_string(&env).unwrap();
    for field in &[
        "schema_version",
        "scope_id",
        "total_sites",
        "scalar_replacement_count",
        "stack_allocation_count",
        "abstention_count",
        "alias_class_count",
        "certificates",
        "overall_confidence_millionths",
        "envelope_hash",
        "epoch",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

// ---------------------------------------------------------------------------
// EscapeAnalyzerConfig — Clone / Debug / Default / JSON
// ---------------------------------------------------------------------------

#[test]
fn enrichment_analyzer_config_clone_independence() {
    let a = EscapeAnalyzerConfig::default();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_analyzer_config_debug_nonempty() {
    assert!(!format!("{:?}", EscapeAnalyzerConfig::default()).is_empty());
}

#[test]
fn enrichment_analyzer_config_default_values() {
    let cfg = EscapeAnalyzerConfig::default();
    assert_eq!(cfg.max_sites_per_scope, 256);
    assert_eq!(cfg.min_confidence_millionths, 500_000);
}

#[test]
fn enrichment_analyzer_config_json_field_names() {
    let cfg = EscapeAnalyzerConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    assert!(json.contains("\"max_sites_per_scope\""));
    assert!(json.contains("\"min_confidence_millionths\""));
}

// ---------------------------------------------------------------------------
// EscapeCertSpecimen — via corpus
// ---------------------------------------------------------------------------

#[test]
fn enrichment_specimen_clone_independence() {
    let corpus = escape_cert_corpus();
    let a = &corpus[0];
    let b = a.clone();
    assert_eq!(*a, b);
}

#[test]
fn enrichment_specimen_debug_nonempty() {
    let corpus = escape_cert_corpus();
    assert!(!format!("{:?}", corpus[0]).is_empty());
}

#[test]
fn enrichment_specimen_json_field_names() {
    let corpus = escape_cert_corpus();
    let json = serde_json::to_string(&corpus[0]).unwrap();
    for field in &["specimen_id", "description", "family", "expected_outcome"] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_specimen_serde_roundtrip() {
    let corpus = escape_cert_corpus();
    for specimen in &corpus {
        let json = serde_json::to_string(specimen).unwrap();
        let rt: frankenengine_engine::escape_analysis_certificate::EscapeCertSpecimen =
            serde_json::from_str(&json).unwrap();
        assert_eq!(*specimen, rt);
    }
}

// ---------------------------------------------------------------------------
// EscapeCertSpecimenEvidence — via run_corpus
// ---------------------------------------------------------------------------

#[test]
fn enrichment_specimen_evidence_clone_independence() {
    let inv = run_escape_cert_corpus();
    let a = &inv.evidence[0];
    let b = a.clone();
    assert_eq!(*a, b);
}

#[test]
fn enrichment_specimen_evidence_debug_nonempty() {
    let inv = run_escape_cert_corpus();
    assert!(!format!("{:?}", inv.evidence[0]).is_empty());
}

#[test]
fn enrichment_specimen_evidence_json_field_names() {
    let inv = run_escape_cert_corpus();
    let json = serde_json::to_string(&inv.evidence[0]).unwrap();
    for field in &[
        "specimen_id",
        "family",
        "expected_outcome",
        "verdict",
        "actual_outcome",
        "evidence_hash",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

// ---------------------------------------------------------------------------
// EscapeCertEvidenceInventory — Clone / Debug / JSON
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evidence_inventory_clone_independence() {
    let a = run_escape_cert_corpus();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_evidence_inventory_debug_nonempty() {
    assert!(!format!("{:?}", run_escape_cert_corpus()).is_empty());
}

#[test]
fn enrichment_evidence_inventory_json_field_names() {
    let inv = run_escape_cert_corpus();
    let json = serde_json::to_string(&inv).unwrap();
    for field in &[
        "schema_version",
        "component",
        "specimen_count",
        "pass_count",
        "fail_count",
        "family_coverage",
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
// EscapeCertRunManifest — Clone / Debug / JSON / serde
// ---------------------------------------------------------------------------

fn make_manifest() -> EscapeCertRunManifest {
    EscapeCertRunManifest {
        schema_version: ESCAPE_CERT_MANIFEST_SCHEMA_VERSION.to_string(),
        component: ESCAPE_CERT_COMPONENT.to_string(),
        trace_id: "trace-001".to_string(),
        decision_id: "dec-001".to_string(),
        policy_id: ESCAPE_CERT_POLICY_ID.to_string(),
        inventory_hash: "abcdef1234567890".to_string(),
        specimen_count: 16,
        pass_count: 16,
        fail_count: 0,
        contract_satisfied: true,
        artifact_paths: make_artifact_paths(),
    }
}

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
    let b: EscapeCertRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// EscapeCertArtifactPaths — Clone / Debug / JSON / serde
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
    let b: EscapeCertArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// EscapeCertEvidenceEvent — Clone / Debug / JSON / serde
// ---------------------------------------------------------------------------

fn make_event() -> EscapeCertEvidenceEvent {
    EscapeCertEvidenceEvent {
        schema_version: ESCAPE_CERT_EVENT_SCHEMA_VERSION.to_string(),
        component: ESCAPE_CERT_COMPONENT.to_string(),
        event: "test_event".to_string(),
        policy_id: ESCAPE_CERT_POLICY_ID.to_string(),
        specimen_id: Some("sp-1".to_string()),
        verdict: Some("pass".to_string()),
        detail: Some("detail text".to_string()),
    }
}

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
    let b: EscapeCertEvidenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(a, b);
}

#[test]
fn enrichment_evidence_event_with_nones() {
    let a = EscapeCertEvidenceEvent {
        schema_version: ESCAPE_CERT_EVENT_SCHEMA_VERSION.to_string(),
        component: ESCAPE_CERT_COMPONENT.to_string(),
        event: "run_started".to_string(),
        policy_id: ESCAPE_CERT_POLICY_ID.to_string(),
        specimen_id: None,
        verdict: None,
        detail: None,
    };
    let json = serde_json::to_string(&a).unwrap();
    let b: EscapeCertEvidenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// Constants stability
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_exact_values() {
    assert_eq!(
        ESCAPE_CERT_SCHEMA_VERSION,
        "franken-engine.escape_analysis_certificate.v1"
    );
    assert_eq!(
        ESCAPE_CERT_MANIFEST_SCHEMA_VERSION,
        "franken-engine.escape_analysis_certificate_manifest.v1"
    );
    assert_eq!(
        ESCAPE_CERT_EVENT_SCHEMA_VERSION,
        "franken-engine.escape_analysis_certificate_event.v1"
    );
    assert_eq!(ESCAPE_CERT_COMPONENT, "escape_analysis_certificate");
    assert_eq!(ESCAPE_CERT_POLICY_ID, "RGC-622A");
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_five_run_determinism_analysis() {
    let sites = vec![
        make_site("s1", "fn_a", AllocationKind::ObjectLiteral),
        make_site("s2", "fn_a", AllocationKind::ArrayLiteral),
        make_site("s3", "fn_a", AllocationKind::Closure),
    ];
    let config = EscapeAnalyzerConfig::default();
    let hashes: BTreeSet<String> = (0..5)
        .map(|_| {
            let env = analyze_escape("fn_a", &sites, &[], &config, SecurityEpoch::from_raw(1));
            env.envelope_hash.clone()
        })
        .collect();
    assert_eq!(hashes.len(), 1, "analysis should be deterministic");
}

#[test]
fn enrichment_five_run_determinism_corpus_evidence() {
    let hashes: BTreeSet<String> = (0..5)
        .map(|_| {
            let inv = run_escape_cert_corpus();
            serde_json::to_string(&inv).unwrap()
        })
        .collect();
    assert_eq!(hashes.len(), 1, "corpus evidence should be deterministic");
}

// ---------------------------------------------------------------------------
// Cross-cutting invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cross_cutting_all_certs_same_schema() {
    let env = make_envelope();
    for cert in &env.certificates {
        assert_eq!(cert.schema_version, ESCAPE_CERT_SCHEMA_VERSION);
    }
}

#[test]
fn enrichment_cross_cutting_invalidation_raises_escape() {
    let sites = vec![make_site("s1", "fn_a", AllocationKind::ObjectLiteral)];
    let invalidations = vec![("s1", InvalidationReason::DynamicEval)];
    let config = EscapeAnalyzerConfig::default();
    let env = analyze_escape(
        "fn_a",
        &sites,
        &invalidations,
        &config,
        SecurityEpoch::from_raw(1),
    );
    let cert = &env.certificates[0];
    assert_eq!(cert.escape_state, EscapeState::GlobalEscape);
    assert!(cert.abstention);
}

#[test]
fn enrichment_cross_cutting_envelope_scope_matches() {
    let env = make_envelope();
    assert_eq!(env.scope_id, "fn_a");
}

#[test]
fn enrichment_cross_cutting_cert_count_matches_sites() {
    let sites = vec![
        make_site("s1", "fn_a", AllocationKind::ObjectLiteral),
        make_site("s2", "fn_a", AllocationKind::ArrayLiteral),
        make_site("s3", "fn_a", AllocationKind::Closure),
    ];
    let config = EscapeAnalyzerConfig::default();
    let env = analyze_escape("fn_a", &sites, &[], &config, SecurityEpoch::from_raw(1));
    assert_eq!(env.certificates.len(), 3);
    assert_eq!(env.total_sites, 3);
}

#[test]
fn enrichment_cross_cutting_corpus_families_in_evidence() {
    let inv = run_escape_cert_corpus();
    let families: BTreeSet<String> = inv
        .evidence
        .iter()
        .map(|e| format!("{:?}", e.family))
        .collect();
    assert!(families.len() >= 4, "should cover multiple families");
}

#[test]
fn enrichment_cross_cutting_empty_sites_empty_envelope() {
    let config = EscapeAnalyzerConfig::default();
    let env = analyze_escape("fn_empty", &[], &[], &config, SecurityEpoch::from_raw(1));
    assert_eq!(env.total_sites, 0);
    assert!(env.certificates.is_empty());
    assert_eq!(env.elision_rate_millionths(), 0);
}
