#![forbid(unsafe_code)]

//! Integration tests for the escape analysis certificate module [RGC-622A].

use std::collections::BTreeMap;

use frankenengine_engine::escape_analysis_certificate::{
    self, AliasClassId, AliasRelation, AllocationKind, AllocationSite, ESCAPE_CERT_COMPONENT,
    ESCAPE_CERT_EVENT_SCHEMA_VERSION, ESCAPE_CERT_MANIFEST_SCHEMA_VERSION, ESCAPE_CERT_POLICY_ID,
    ESCAPE_CERT_SCHEMA_VERSION, EscapeAnalyzerConfig, EscapeCertEvidenceInventory,
    EscapeCertSpecimenFamily, EscapeCertVerdict, EscapeState, InvalidationReason, LivenessEnvelope,
    OptimizationEligibilityEnvelope,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn site(id: &str, scope: &str, kind: AllocationKind) -> AllocationSite {
    AllocationSite {
        site_id: id.to_string(),
        scope: scope.to_string(),
        allocation_kind: kind,
        estimated_size_bytes: Some(64),
    }
}

fn analyze(
    scope: &str,
    sites: &[AllocationSite],
    inv: &[(&str, InvalidationReason)],
) -> OptimizationEligibilityEnvelope {
    escape_analysis_certificate::analyze_escape(
        scope,
        sites,
        inv,
        &EscapeAnalyzerConfig::default(),
        SecurityEpoch::from_raw(1),
    )
}

// ---------------------------------------------------------------------------
// Corpus invariants
// ---------------------------------------------------------------------------

#[test]
fn corpus_non_empty() {
    assert!(!escape_analysis_certificate::escape_cert_corpus().is_empty());
}

#[test]
fn corpus_ids_unique() {
    let corpus = escape_analysis_certificate::escape_cert_corpus();
    let ids: std::collections::BTreeSet<&str> =
        corpus.iter().map(|s| s.specimen_id.as_str()).collect();
    assert_eq!(ids.len(), corpus.len());
}

#[test]
fn corpus_descriptions_non_empty() {
    for s in escape_analysis_certificate::escape_cert_corpus() {
        assert!(!s.description.is_empty(), "specimen {}", s.specimen_id);
    }
}

#[test]
fn corpus_covers_all_families() {
    let corpus = escape_analysis_certificate::escape_cert_corpus();
    let covered: std::collections::BTreeSet<EscapeCertSpecimenFamily> =
        corpus.iter().map(|s| s.family).collect();
    for f in EscapeCertSpecimenFamily::ALL {
        assert!(covered.contains(f), "missing {:?}", f);
    }
}

// ---------------------------------------------------------------------------
// Runner / inventory
// ---------------------------------------------------------------------------

#[test]
fn runner_produces_inventory() {
    let inv = escape_analysis_certificate::run_escape_cert_corpus();
    assert!(inv.specimen_count > 0);
}

#[test]
fn all_specimens_pass() {
    let inv = escape_analysis_certificate::run_escape_cert_corpus();
    for ev in &inv.evidence {
        assert_eq!(
            ev.verdict,
            EscapeCertVerdict::Pass,
            "specimen {} failed: {:?}",
            ev.specimen_id,
            ev.error_detail
        );
    }
}

#[test]
fn contract_satisfied() {
    let inv = escape_analysis_certificate::run_escape_cert_corpus();
    assert!(inv.contract_satisfied());
}

#[test]
fn counts_consistent() {
    let inv = escape_analysis_certificate::run_escape_cert_corpus();
    assert_eq!(inv.pass_count + inv.fail_count, inv.specimen_count);
    assert_eq!(inv.evidence.len() as u64, inv.specimen_count);
}

#[test]
fn family_coverage_sums() {
    let inv = escape_analysis_certificate::run_escape_cert_corpus();
    let total: u64 = inv.family_coverage.values().sum();
    assert_eq!(total, inv.specimen_count);
}

#[test]
fn deterministic_runs() {
    let inv1 = escape_analysis_certificate::run_escape_cert_corpus();
    let inv2 = escape_analysis_certificate::run_escape_cert_corpus();
    assert_eq!(inv1, inv2);
}

// ---------------------------------------------------------------------------
// Evidence hashes
// ---------------------------------------------------------------------------

#[test]
fn evidence_hashes_present() {
    let inv = escape_analysis_certificate::run_escape_cert_corpus();
    for ev in &inv.evidence {
        assert!(!ev.evidence_hash.is_empty());
    }
}

#[test]
fn evidence_hashes_64_hex() {
    let inv = escape_analysis_certificate::run_escape_cert_corpus();
    for ev in &inv.evidence {
        assert_eq!(ev.evidence_hash.len(), 64);
        assert!(ev.evidence_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

#[test]
fn evidence_hashes_deterministic() {
    let inv1 = escape_analysis_certificate::run_escape_cert_corpus();
    let inv2 = escape_analysis_certificate::run_escape_cert_corpus();
    for (a, b) in inv1.evidence.iter().zip(&inv2.evidence) {
        assert_eq!(a.evidence_hash, b.evidence_hash);
    }
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn inventory_serde_roundtrip() {
    let inv = escape_analysis_certificate::run_escape_cert_corpus();
    let json = serde_json::to_string(&inv).unwrap();
    let back: EscapeCertEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

#[test]
fn envelope_serde_roundtrip() {
    let sites = vec![
        site("s1", "fn_a", AllocationKind::ObjectLiteral),
        site("s2", "fn_a", AllocationKind::IteratorResult),
    ];
    let env = analyze("fn_a", &sites, &[]);
    let json = serde_json::to_string(&env).unwrap();
    let back: OptimizationEligibilityEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(env, back);
}

#[test]
fn escape_state_serde_roundtrip() {
    for s in EscapeState::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: EscapeState = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn allocation_kind_serde_roundtrip() {
    for k in AllocationKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: AllocationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

#[test]
fn invalidation_reason_serde_roundtrip() {
    for r in [
        InvalidationReason::DynamicEval,
        InvalidationReason::WithStatement,
        InvalidationReason::ProxyReflect,
        InvalidationReason::BudgetExceeded,
    ] {
        let json = serde_json::to_string(&r).unwrap();
        let back: InvalidationReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}

#[test]
fn alias_relation_serde_roundtrip() {
    for r in [
        AliasRelation::NoAlias,
        AliasRelation::MayAlias,
        AliasRelation::MustAlias,
    ] {
        let json = serde_json::to_string(&r).unwrap();
        let back: AliasRelation = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}

#[test]
fn analyzer_config_serde_roundtrip() {
    let c = EscapeAnalyzerConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: EscapeAnalyzerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_non_empty() {
    assert!(!ESCAPE_CERT_SCHEMA_VERSION.is_empty());
    assert!(!ESCAPE_CERT_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(!ESCAPE_CERT_EVENT_SCHEMA_VERSION.is_empty());
}

#[test]
fn schema_versions_prefixed() {
    assert!(ESCAPE_CERT_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(ESCAPE_CERT_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(ESCAPE_CERT_EVENT_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn component_and_policy_id() {
    assert!(!ESCAPE_CERT_COMPONENT.is_empty());
    assert_eq!(ESCAPE_CERT_POLICY_ID, "RGC-622A");
}

// ---------------------------------------------------------------------------
// EscapeState lattice
// ---------------------------------------------------------------------------

#[test]
fn escape_state_ordering() {
    assert!(EscapeState::NoEscape < EscapeState::ArgEscape);
    assert!(EscapeState::ArgEscape < EscapeState::ThreadEscape);
    assert!(EscapeState::ThreadEscape < EscapeState::GlobalEscape);
}

#[test]
fn escape_state_join_idempotent() {
    for s in EscapeState::ALL {
        assert_eq!(s.join(*s), *s);
    }
}

#[test]
fn escape_state_join_commutative() {
    for a in EscapeState::ALL {
        for b in EscapeState::ALL {
            assert_eq!(a.join(*b), b.join(*a));
        }
    }
}

#[test]
fn escape_state_join_associative() {
    for a in EscapeState::ALL {
        for b in EscapeState::ALL {
            for c in EscapeState::ALL {
                assert_eq!(a.join(*b).join(*c), a.join(b.join(*c)));
            }
        }
    }
}

#[test]
fn escape_state_join_monotone() {
    for a in EscapeState::ALL {
        for b in EscapeState::ALL {
            let joined = a.join(*b);
            assert!(joined >= *a);
            assert!(joined >= *b);
        }
    }
}

#[test]
fn no_escape_is_elision_eligible() {
    assert!(EscapeState::NoEscape.is_elision_eligible());
    assert!(!EscapeState::ArgEscape.is_elision_eligible());
    assert!(!EscapeState::GlobalEscape.is_elision_eligible());
}

#[test]
fn no_escape_and_arg_escape_are_caller_managed() {
    assert!(EscapeState::NoEscape.is_caller_managed());
    assert!(EscapeState::ArgEscape.is_caller_managed());
    assert!(!EscapeState::ThreadEscape.is_caller_managed());
    assert!(!EscapeState::GlobalEscape.is_caller_managed());
}

#[test]
fn escape_state_display_matches_as_str() {
    for s in EscapeState::ALL {
        assert_eq!(s.to_string(), s.as_str());
    }
}

// ---------------------------------------------------------------------------
// AliasRelation
// ---------------------------------------------------------------------------

#[test]
fn alias_relation_display_matches_as_str() {
    for r in [
        AliasRelation::NoAlias,
        AliasRelation::MayAlias,
        AliasRelation::MustAlias,
    ] {
        assert_eq!(r.to_string(), r.as_str());
    }
}

// ---------------------------------------------------------------------------
// LivenessEnvelope
// ---------------------------------------------------------------------------

#[test]
fn liveness_known_range() {
    let l = LivenessEnvelope {
        first_use: Some(5),
        last_use: Some(15),
        precise: true,
    };
    assert!(l.is_known());
    assert_eq!(l.span(), Some(10));
}

#[test]
fn liveness_unknown_range() {
    let l = LivenessEnvelope {
        first_use: None,
        last_use: None,
        precise: false,
    };
    assert!(!l.is_known());
    assert_eq!(l.span(), None);
}

#[test]
fn liveness_partial_unknown() {
    let l = LivenessEnvelope {
        first_use: Some(3),
        last_use: None,
        precise: false,
    };
    assert!(!l.is_known());
    assert_eq!(l.span(), None);
}

// ---------------------------------------------------------------------------
// AllocationKind
// ---------------------------------------------------------------------------

#[test]
fn allocation_kind_all_has_10_variants() {
    assert_eq!(AllocationKind::ALL.len(), 10);
}

#[test]
fn allocation_kind_display_matches_as_str() {
    for k in AllocationKind::ALL {
        assert_eq!(k.to_string(), k.as_str());
    }
}

// ---------------------------------------------------------------------------
// InvalidationReason
// ---------------------------------------------------------------------------

#[test]
fn invalidation_reason_display_matches_as_str() {
    for r in [
        InvalidationReason::DynamicEval,
        InvalidationReason::WithStatement,
        InvalidationReason::DynamicPropertyAccess,
        InvalidationReason::IndirectCall,
        InvalidationReason::ExceptionEscape,
        InvalidationReason::ProxyReflect,
        InvalidationReason::BudgetExceeded,
        InvalidationReason::CrossModuleUnresolvable,
    ] {
        assert_eq!(r.to_string(), r.as_str());
    }
}

// ---------------------------------------------------------------------------
// Escape analysis
// ---------------------------------------------------------------------------

#[test]
fn iterator_result_no_escape() {
    let sites = vec![site("s1", "fn_iter", AllocationKind::IteratorResult)];
    let env = analyze("fn_iter", &sites, &[]);
    assert_eq!(env.certificates[0].escape_state, EscapeState::NoEscape);
}

#[test]
fn object_literal_arg_escape() {
    let sites = vec![site("s1", "fn_obj", AllocationKind::ObjectLiteral)];
    let env = analyze("fn_obj", &sites, &[]);
    assert_eq!(env.certificates[0].escape_state, EscapeState::ArgEscape);
}

#[test]
fn closure_global_escape() {
    let sites = vec![site("s1", "fn_cls", AllocationKind::Closure)];
    let env = analyze("fn_cls", &sites, &[]);
    assert_eq!(env.certificates[0].escape_state, EscapeState::GlobalEscape);
}

#[test]
fn arguments_object_no_escape() {
    let sites = vec![site("s1", "fn_args", AllocationKind::ArgumentsObject)];
    let env = analyze("fn_args", &sites, &[]);
    assert_eq!(env.certificates[0].escape_state, EscapeState::NoEscape);
}

#[test]
fn rest_parameter_no_escape() {
    let sites = vec![site("s1", "fn_rest", AllocationKind::RestParameter)];
    let env = analyze("fn_rest", &sites, &[]);
    assert_eq!(env.certificates[0].escape_state, EscapeState::NoEscape);
}

#[test]
fn constructor_call_global_escape() {
    let sites = vec![site("s1", "fn_new", AllocationKind::ConstructorCall)];
    let env = analyze("fn_new", &sites, &[]);
    assert_eq!(env.certificates[0].escape_state, EscapeState::GlobalEscape);
}

#[test]
fn invalidation_forces_global_escape() {
    let sites = vec![site("s1", "fn_bad", AllocationKind::IteratorResult)];
    let inv = vec![("s1", InvalidationReason::DynamicEval)];
    let env = analyze("fn_bad", &sites, &inv);
    assert_eq!(env.certificates[0].escape_state, EscapeState::GlobalEscape);
    assert!(env.certificates[0].abstention);
}

#[test]
fn clean_site_not_abstention() {
    let sites = vec![site("s1", "fn_clean", AllocationKind::ObjectLiteral)];
    let env = analyze("fn_clean", &sites, &[]);
    assert!(!env.certificates[0].abstention);
    assert!(env.certificates[0].is_granted());
}

#[test]
fn can_elide_no_escape_site() {
    let sites = vec![site("s1", "fn_elide", AllocationKind::IteratorResult)];
    let env = analyze("fn_elide", &sites, &[]);
    assert!(env.certificates[0].can_elide());
}

#[test]
fn cannot_elide_arg_escape_site() {
    let sites = vec![site("s1", "fn_arg", AllocationKind::ObjectLiteral)];
    let env = analyze("fn_arg", &sites, &[]);
    assert!(!env.certificates[0].can_elide());
}

// ---------------------------------------------------------------------------
// Alias classes
// ---------------------------------------------------------------------------

#[test]
fn same_scope_kind_share_alias_class() {
    let sites = vec![
        site("s1", "fn_a", AllocationKind::ObjectLiteral),
        site("s2", "fn_a", AllocationKind::ObjectLiteral),
    ];
    let env = analyze("fn_a", &sites, &[]);
    assert_eq!(
        env.certificates[0].alias_class,
        env.certificates[1].alias_class
    );
}

#[test]
fn different_scope_different_alias_class() {
    let sites = vec![
        site("s1", "fn_a", AllocationKind::ObjectLiteral),
        site("s2", "fn_b", AllocationKind::ObjectLiteral),
    ];
    let env = analyze("mixed", &sites, &[]);
    assert_ne!(
        env.certificates[0].alias_class,
        env.certificates[1].alias_class
    );
}

#[test]
fn different_kind_different_alias_class() {
    let sites = vec![
        site("s1", "fn_a", AllocationKind::ObjectLiteral),
        site("s2", "fn_a", AllocationKind::ArrayLiteral),
    ];
    let env = analyze("fn_a", &sites, &[]);
    assert_ne!(
        env.certificates[0].alias_class,
        env.certificates[1].alias_class
    );
}

// ---------------------------------------------------------------------------
// Eligibility envelope
// ---------------------------------------------------------------------------

#[test]
fn envelope_total_sites_correct() {
    let sites = vec![
        site("s1", "fn", AllocationKind::IteratorResult),
        site("s2", "fn", AllocationKind::ObjectLiteral),
        site("s3", "fn", AllocationKind::Closure),
    ];
    let env = analyze("fn", &sites, &[]);
    assert_eq!(env.total_sites, 3);
}

#[test]
fn envelope_scalar_replacement_count() {
    let sites = vec![
        site("s1", "fn", AllocationKind::IteratorResult), // NoEscape → eligible
        site("s2", "fn", AllocationKind::ArgumentsObject), // NoEscape → eligible
        site("s3", "fn", AllocationKind::ObjectLiteral),  // ArgEscape → not eligible
    ];
    let env = analyze("fn", &sites, &[]);
    assert_eq!(env.scalar_replacement_count, 2);
}

#[test]
fn envelope_stack_allocation_count() {
    let sites = vec![
        site("s1", "fn", AllocationKind::IteratorResult), // NoEscape → stack eligible
        site("s2", "fn", AllocationKind::ObjectLiteral),  // ArgEscape → stack eligible
        site("s3", "fn", AllocationKind::Closure),        // GlobalEscape → not eligible
    ];
    let env = analyze("fn", &sites, &[]);
    assert_eq!(env.stack_allocation_count, 2);
}

#[test]
fn envelope_abstention_count_with_invalidations() {
    let sites = vec![
        site("s1", "fn", AllocationKind::ObjectLiteral),
        site("s2", "fn", AllocationKind::ObjectLiteral),
    ];
    let inv = vec![("s1", InvalidationReason::DynamicEval)];
    let env = analyze("fn", &sites, &inv);
    assert_eq!(env.abstention_count, 1);
}

#[test]
fn envelope_elision_rate() {
    let sites = vec![
        site("s1", "fn", AllocationKind::IteratorResult),
        site("s2", "fn", AllocationKind::Closure),
    ];
    let env = analyze("fn", &sites, &[]);
    let rate = env.elision_rate_millionths();
    assert_eq!(rate, 500_000); // 1 out of 2
}

#[test]
fn envelope_elision_rate_zero_when_empty() {
    let env = analyze("fn_empty", &[], &[]);
    assert_eq!(env.elision_rate_millionths(), 0);
}

#[test]
fn envelope_hash_deterministic() {
    let sites = vec![site("s1", "fn", AllocationKind::ObjectLiteral)];
    let e1 = analyze("fn", &sites, &[]);
    let e2 = analyze("fn", &sites, &[]);
    assert_eq!(e1.envelope_hash, e2.envelope_hash);
}

#[test]
fn envelope_hash_is_64_hex() {
    let sites = vec![site("s1", "fn", AllocationKind::ObjectLiteral)];
    let env = analyze("fn", &sites, &[]);
    assert_eq!(env.envelope_hash.len(), 64);
    assert!(env.envelope_hash.chars().all(|c| c.is_ascii_hexdigit()));
}

// ---------------------------------------------------------------------------
// Budget exhaustion
// ---------------------------------------------------------------------------

#[test]
fn budget_exceeded_all_abstain() {
    let config = EscapeAnalyzerConfig {
        max_sites_per_scope: 2,
        ..EscapeAnalyzerConfig::default()
    };
    let sites: Vec<AllocationSite> = (0..5)
        .map(|i| site(&format!("s{i}"), "fn", AllocationKind::ObjectLiteral))
        .collect();
    let env = escape_analysis_certificate::analyze_escape(
        "fn",
        &sites,
        &[],
        &config,
        SecurityEpoch::from_raw(1),
    );
    assert_eq!(env.abstention_count, 5);
    for cert in &env.certificates {
        assert!(cert.abstention);
        assert!(
            cert.invalidation_reasons
                .contains(&InvalidationReason::BudgetExceeded)
        );
    }
}

// ---------------------------------------------------------------------------
// Certificate hashes
// ---------------------------------------------------------------------------

#[test]
fn certificate_hashes_present_and_64_hex() {
    let sites = vec![
        site("s1", "fn", AllocationKind::ObjectLiteral),
        site("s2", "fn", AllocationKind::IteratorResult),
    ];
    let env = analyze("fn", &sites, &[]);
    for cert in &env.certificates {
        assert_eq!(cert.certificate_hash.len(), 64);
        assert!(cert.certificate_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

// ---------------------------------------------------------------------------
// Bundle writer
// ---------------------------------------------------------------------------

#[test]
fn bundle_writer_creates_four_files() {
    let dir = std::env::temp_dir().join("pearl_escape_bundle_test_1");
    let _ = std::fs::remove_dir_all(&dir);
    let result = escape_analysis_certificate::write_escape_cert_evidence_bundle(
        &dir,
        &["cargo test --lib escape_analysis_certificate".to_string()],
    );
    assert!(result.is_ok());
    let artifacts = result.unwrap();
    assert!(artifacts.inventory_path.exists());
    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.events_path.exists());
    assert!(artifacts.commands_path.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_inventory_is_valid_json() {
    let dir = std::env::temp_dir().join("pearl_escape_bundle_test_2");
    let _ = std::fs::remove_dir_all(&dir);
    let artifacts =
        escape_analysis_certificate::write_escape_cert_evidence_bundle(&dir, &[]).unwrap();
    let json = std::fs::read_to_string(&artifacts.inventory_path).unwrap();
    let inv: EscapeCertEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert!(inv.contract_satisfied());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_manifest_has_correct_policy() {
    let dir = std::env::temp_dir().join("pearl_escape_bundle_test_3");
    let _ = std::fs::remove_dir_all(&dir);
    let artifacts =
        escape_analysis_certificate::write_escape_cert_evidence_bundle(&dir, &[]).unwrap();
    let json = std::fs::read_to_string(&artifacts.run_manifest_path).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["policy_id"].as_str().unwrap(), ESCAPE_CERT_POLICY_ID);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_events_has_start_and_end() {
    let dir = std::env::temp_dir().join("pearl_escape_bundle_test_4");
    let _ = std::fs::remove_dir_all(&dir);
    let artifacts =
        escape_analysis_certificate::write_escape_cert_evidence_bundle(&dir, &[]).unwrap();
    let content = std::fs::read_to_string(&artifacts.events_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert!(lines.len() >= 2);
    let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert!(first["event"].as_str().unwrap().contains("started"));
    let last: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
    assert!(last["event"].as_str().unwrap().contains("completed"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_hash_deterministic() {
    let d1 = std::env::temp_dir().join("pearl_escape_bundle_test_5a");
    let d2 = std::env::temp_dir().join("pearl_escape_bundle_test_5b");
    let _ = std::fs::remove_dir_all(&d1);
    let _ = std::fs::remove_dir_all(&d2);
    let a = escape_analysis_certificate::write_escape_cert_evidence_bundle(&d1, &[]).unwrap();
    let b = escape_analysis_certificate::write_escape_cert_evidence_bundle(&d2, &[]).unwrap();
    assert_eq!(a.inventory_hash, b.inventory_hash);
    let _ = std::fs::remove_dir_all(&d1);
    let _ = std::fs::remove_dir_all(&d2);
}

// ---------------------------------------------------------------------------
// Contract satisfaction edge cases
// ---------------------------------------------------------------------------

#[test]
fn contract_not_satisfied_with_failures() {
    let inv = EscapeCertEvidenceInventory {
        schema_version: ESCAPE_CERT_SCHEMA_VERSION.to_string(),
        component: ESCAPE_CERT_COMPONENT.to_string(),
        specimen_count: 5,
        pass_count: 4,
        fail_count: 1,
        family_coverage: BTreeMap::new(),
        evidence: vec![],
    };
    assert!(!inv.contract_satisfied());
}

#[test]
fn contract_not_satisfied_with_zero_specimens() {
    let inv = EscapeCertEvidenceInventory {
        schema_version: ESCAPE_CERT_SCHEMA_VERSION.to_string(),
        component: ESCAPE_CERT_COMPONENT.to_string(),
        specimen_count: 0,
        pass_count: 0,
        fail_count: 0,
        family_coverage: BTreeMap::new(),
        evidence: vec![],
    };
    assert!(!inv.contract_satisfied());
}

// ---------------------------------------------------------------------------
// Specimen family
// ---------------------------------------------------------------------------

#[test]
fn specimen_family_display_matches_as_str() {
    for f in EscapeCertSpecimenFamily::ALL {
        assert_eq!(f.to_string(), f.as_str());
    }
}

#[test]
fn specimen_family_serde_roundtrip() {
    for f in EscapeCertSpecimenFamily::ALL {
        let json = serde_json::to_string(f).unwrap();
        let back: EscapeCertSpecimenFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, back);
    }
}
