#![forbid(unsafe_code)]
//! Enrichment integration tests for `cut_line_automation`.
//!
//! Adds JSON field-name stability, exact serde enum values, Display/as_str
//! exactness, Debug distinctness, and edge cases beyond
//! the existing 49 integration tests.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::cut_line_automation::{
    CutLine, CutLineEvaluator, CutLineSpec, GateCategory, GateInput, GateRequirement,
    InputValidity, PromotionSummary,
};
use frankenengine_engine::hash_tiers::ContentHash;

// ===========================================================================
// 1) CutLine — exact Display / as_str
// ===========================================================================

#[test]
fn cut_line_as_str_exact() {
    assert_eq!(CutLine::C0.as_str(), "C0");
    assert_eq!(CutLine::C1.as_str(), "C1");
    assert_eq!(CutLine::C2.as_str(), "C2");
    assert_eq!(CutLine::C3.as_str(), "C3");
    assert_eq!(CutLine::C4.as_str(), "C4");
    assert_eq!(CutLine::C5.as_str(), "C5");
}

#[test]
fn cut_line_display_matches_as_str() {
    for cl in CutLine::all() {
        assert_eq!(cl.to_string(), cl.as_str());
    }
}

// ===========================================================================
// 2) GateCategory — exact as_str
// ===========================================================================

#[test]
fn gate_category_as_str_exact() {
    let categories = [
        (GateCategory::SemanticContract, "semantic_contract"),
        (GateCategory::CompilerCorrectness, "compiler_correctness"),
        (GateCategory::RuntimeParity, "runtime_parity"),
        (GateCategory::PerformanceBenchmark, "performance_benchmark"),
        (GateCategory::SecuritySurvival, "security_survival"),
        (GateCategory::DeterministicReplay, "deterministic_replay"),
        (
            GateCategory::ObservabilityIntegrity,
            "observability_integrity",
        ),
        (GateCategory::FlakeBurden, "flake_burden"),
        (GateCategory::GovernanceCompliance, "governance_compliance"),
        (GateCategory::HandoffReadiness, "handoff_readiness"),
    ];
    for (cat, expected) in &categories {
        assert_eq!(
            cat.as_str(),
            *expected,
            "GateCategory as_str mismatch for {cat:?}"
        );
    }
}

#[test]
fn gate_category_display_matches_as_str() {
    let all = [
        GateCategory::SemanticContract,
        GateCategory::CompilerCorrectness,
        GateCategory::RuntimeParity,
        GateCategory::PerformanceBenchmark,
        GateCategory::SecuritySurvival,
        GateCategory::DeterministicReplay,
        GateCategory::ObservabilityIntegrity,
        GateCategory::FlakeBurden,
        GateCategory::GovernanceCompliance,
        GateCategory::HandoffReadiness,
    ];
    for cat in &all {
        assert_eq!(cat.to_string(), cat.as_str());
    }
}

// ===========================================================================
// 3) InputValidity — exact Display
// ===========================================================================

#[test]
fn input_validity_display_exact_valid() {
    let iv = InputValidity::Valid;
    assert!(iv.is_valid());
    let s = iv.to_string();
    assert!(!s.is_empty());
}

#[test]
fn input_validity_display_exact_stale() {
    let iv = InputValidity::Stale {
        age_ns: 1_000_000_000,
        max_age_ns: 500_000_000,
    };
    assert!(!iv.is_valid());
    let s = iv.to_string();
    assert!(
        s.contains("1000000000") || s.contains("stale"),
        "should mention staleness: {s}"
    );
}

#[test]
fn input_validity_display_exact_missing() {
    let iv = InputValidity::Missing {
        field: "score".into(),
    };
    assert!(!iv.is_valid());
    let s = iv.to_string();
    assert!(s.contains("score"), "should mention missing field: {s}");
}

// ===========================================================================
// 4) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_cut_line() {
    let variants: Vec<String> = CutLine::all().iter().map(|c| format!("{c:?}")).collect();
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 6);
}

#[test]
fn debug_distinct_gate_category() {
    let variants = [
        format!("{:?}", GateCategory::SemanticContract),
        format!("{:?}", GateCategory::CompilerCorrectness),
        format!("{:?}", GateCategory::RuntimeParity),
        format!("{:?}", GateCategory::PerformanceBenchmark),
        format!("{:?}", GateCategory::SecuritySurvival),
        format!("{:?}", GateCategory::DeterministicReplay),
        format!("{:?}", GateCategory::ObservabilityIntegrity),
        format!("{:?}", GateCategory::FlakeBurden),
        format!("{:?}", GateCategory::GovernanceCompliance),
        format!("{:?}", GateCategory::HandoffReadiness),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 10);
}

// ===========================================================================
// 5) Serde exact enum values
// ===========================================================================

#[test]
fn serde_exact_cut_line_tags() {
    let lines = CutLine::all();
    let expected = ["\"C0\"", "\"C1\"", "\"C2\"", "\"C3\"", "\"C4\"", "\"C5\""];
    for (cl, exp) in lines.iter().zip(expected.iter()) {
        let json = serde_json::to_string(cl).unwrap();
        assert_eq!(json, *exp, "CutLine serde tag mismatch for {cl:?}");
    }
}

#[test]
fn serde_exact_gate_category_tags() {
    let categories = [
        GateCategory::SemanticContract,
        GateCategory::CompilerCorrectness,
        GateCategory::RuntimeParity,
    ];
    let expected = [
        "\"SemanticContract\"",
        "\"CompilerCorrectness\"",
        "\"RuntimeParity\"",
    ];
    for (cat, exp) in categories.iter().zip(expected.iter()) {
        let json = serde_json::to_string(cat).unwrap();
        assert_eq!(json, *exp, "GateCategory serde tag mismatch for {cat:?}");
    }
}

// ===========================================================================
// 6) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_gate_requirement() {
    let gr = GateRequirement {
        category: GateCategory::SemanticContract,
        mandatory: true,
        description: "test".to_string(),
        min_score_millionths: Some(500_000),
    };
    let v: serde_json::Value = serde_json::to_value(&gr).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "category",
        "mandatory",
        "description",
        "min_score_millionths",
    ] {
        assert!(
            obj.contains_key(key),
            "GateRequirement missing field: {key}"
        );
    }
}

#[test]
fn json_fields_cut_line_spec() {
    let spec = CutLineSpec::default_c0();
    let v: serde_json::Value = serde_json::to_value(&spec).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "cut_line",
        "requirements",
        "max_input_staleness_ns",
        "min_schema_major",
        "requires_predecessor",
    ] {
        assert!(obj.contains_key(key), "CutLineSpec missing field: {key}");
    }
}

#[test]
fn json_fields_gate_input() {
    let gi = GateInput {
        category: GateCategory::CompilerCorrectness,
        score_millionths: Some(900_000),
        passed: true,
        evidence_hash: ContentHash::compute(b"ev"),
        evidence_refs: vec!["ref1".into()],
        collected_at_ns: 1_000_000_000,
        schema_major: 1,
        metadata: BTreeMap::new(),
    };
    let v: serde_json::Value = serde_json::to_value(&gi).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "category",
        "score_millionths",
        "passed",
        "evidence_hash",
        "evidence_refs",
        "collected_at_ns",
        "schema_major",
        "metadata",
    ] {
        assert!(obj.contains_key(key), "GateInput missing field: {key}");
    }
}

#[test]
fn json_fields_promotion_summary() {
    let ps = PromotionSummary {
        promoted_lines: vec![CutLine::C0],
        next_line: Some(CutLine::C1),
        total_evaluations: 5,
        approved_count: 3,
        denied_count: 2,
    };
    let v: serde_json::Value = serde_json::to_value(&ps).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "promoted_lines",
        "next_line",
        "total_evaluations",
        "approved_count",
        "denied_count",
    ] {
        assert!(
            obj.contains_key(key),
            "PromotionSummary missing field: {key}"
        );
    }
}

// ===========================================================================
// 7) CutLine predecessor
// ===========================================================================

#[test]
fn cut_line_predecessor_c0_is_none() {
    assert!(CutLine::C0.predecessor().is_none());
}

#[test]
fn cut_line_predecessor_chain() {
    assert_eq!(CutLine::C1.predecessor(), Some(CutLine::C0));
    assert_eq!(CutLine::C2.predecessor(), Some(CutLine::C1));
    assert_eq!(CutLine::C3.predecessor(), Some(CutLine::C2));
    assert_eq!(CutLine::C4.predecessor(), Some(CutLine::C3));
    assert_eq!(CutLine::C5.predecessor(), Some(CutLine::C4));
}

// ===========================================================================
// 8) CutLine::all() returns 6
// ===========================================================================

#[test]
fn cut_line_all_returns_6() {
    assert_eq!(CutLine::all().len(), 6);
}

// ===========================================================================
// 9) CutLine ordering
// ===========================================================================

#[test]
fn cut_line_ordering_stable() {
    let mut lines = vec![
        CutLine::C5,
        CutLine::C0,
        CutLine::C3,
        CutLine::C1,
        CutLine::C4,
        CutLine::C2,
    ];
    lines.sort();
    assert_eq!(lines, CutLine::all());
}

// ===========================================================================
// 10) CutLineSpec defaults
// ===========================================================================

#[test]
fn cut_line_spec_default_c0_has_requirements() {
    let spec = CutLineSpec::default_c0();
    assert_eq!(spec.cut_line, CutLine::C0);
    assert!(!spec.requirements.is_empty());
    assert!(!spec.requires_predecessor);
}

#[test]
fn cut_line_spec_default_c1_requires_predecessor() {
    let spec = CutLineSpec::default_c1();
    assert_eq!(spec.cut_line, CutLine::C1);
    assert!(spec.requires_predecessor);
}

// ===========================================================================
// 11) CutLineEvaluator construction
// ===========================================================================

#[test]
fn evaluator_with_defaults_initial_state() {
    let eval = CutLineEvaluator::with_defaults();
    assert!(!eval.is_promoted(CutLine::C0));
    assert_eq!(eval.history_len(), 0);
}

#[test]
fn evaluator_promotion_summary_empty() {
    let eval = CutLineEvaluator::with_defaults();
    let summary = eval.promotion_summary();
    assert!(summary.promoted_lines.is_empty());
    assert!(!summary.all_promoted());
    assert_eq!(summary.progress_millionths(), 0);
}

// ===========================================================================
// 12) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_cut_line() {
    for cl in CutLine::all() {
        let json = serde_json::to_string(cl).unwrap();
        let rt: CutLine = serde_json::from_str(&json).unwrap();
        assert_eq!(*cl, rt);
    }
}

#[test]
fn serde_roundtrip_gate_requirement() {
    let gr = GateRequirement {
        category: GateCategory::FlakeBurden,
        mandatory: false,
        description: "low flake rate".into(),
        min_score_millionths: None,
    };
    let json = serde_json::to_string(&gr).unwrap();
    let rt: GateRequirement = serde_json::from_str(&json).unwrap();
    assert_eq!(gr, rt);
}

#[test]
fn serde_roundtrip_promotion_summary() {
    let ps = PromotionSummary {
        promoted_lines: vec![CutLine::C0, CutLine::C1],
        next_line: Some(CutLine::C2),
        total_evaluations: 10,
        approved_count: 8,
        denied_count: 2,
    };
    let json = serde_json::to_string(&ps).unwrap();
    let rt: PromotionSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(ps, rt);
}

#[test]
fn serde_roundtrip_input_validity_all_variants() {
    let variants = vec![
        InputValidity::Valid,
        InputValidity::Stale {
            age_ns: 100,
            max_age_ns: 50,
        },
        InputValidity::Missing { field: "x".into() },
        InputValidity::Incompatible { reason: "y".into() },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let rt: InputValidity = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, rt);
    }
}

// ===========================================================================
// 13) CutLineEvaluator — revoke on unpromoted line returns false
// ===========================================================================

#[test]
fn evaluator_revoke_unpromoted_returns_false() {
    let mut eval = CutLineEvaluator::with_defaults();
    assert!(
        !eval.revoke_promotion(CutLine::C0),
        "revoking a line that was never promoted should return false"
    );
}

// ===========================================================================
// 14) CutLineSpec mandatory_count
// ===========================================================================

#[test]
fn cut_line_spec_mandatory_count_default_c0() {
    let spec = CutLineSpec::default_c0();
    let mandatory = spec.mandatory_count();
    assert!(
        mandatory > 0,
        "default C0 spec should have at least one mandatory requirement"
    );
    assert!(
        mandatory <= spec.requirements.len(),
        "mandatory count cannot exceed total requirements"
    );
}

// ===========================================================================
// 15) CutLineSpec serde roundtrip
// ===========================================================================

#[test]
fn cut_line_spec_serde_roundtrip() {
    let spec = CutLineSpec::default_c0();
    let json = serde_json::to_string(&spec).unwrap();
    let recovered: CutLineSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(recovered.cut_line, spec.cut_line);
    assert_eq!(recovered.requirements.len(), spec.requirements.len());
    assert_eq!(recovered.requires_predecessor, spec.requires_predecessor);
}

#[test]
fn cut_line_evaluator_debug_is_nonempty() {
    let eval = CutLineEvaluator::with_defaults();
    assert!(!format!("{eval:?}").is_empty());
}

#[test]
fn input_validity_serde_is_deterministic() {
    let v = InputValidity::Valid;
    let a = serde_json::to_string(&v).expect("first");
    let b = serde_json::to_string(&v).expect("second");
    assert_eq!(a, b);
}

#[test]
fn cut_line_spec_debug_is_nonempty() {
    let spec = CutLineSpec::default_c0();
    assert!(!format!("{spec:?}").is_empty());
}
