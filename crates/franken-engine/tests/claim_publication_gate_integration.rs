//! Integration tests for the claim publication gate module.
//!
//! Tests Layer 3 of the claim-entitlement system: wiring verdicts to
//! publication surfaces (docs, rollout, GA, React, supremacy).
//!
//! Bead: bd-1lsy.1.7.3 [RGC-017C]

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

use frankenengine_engine::claim_entitlement::{ClaimVerdict, ClaimVerdictState};
use frankenengine_engine::claim_publication_gate::{
    ALL_SURFACES, AnnotatedVerdict, CLAIM_PUBLICATION_GATE_BEAD_ID,
    CLAIM_PUBLICATION_GATE_SCHEMA_VERSION, FrontierGapDisclosure, GateDecision,
    MAX_PUBLISHABLE_STALENESS_HOURS, PublicationGateError, PublicationGateEvaluation,
    PublicationSurface, RiskFlag, RiskSeverity, SurfaceRoutingConfig, evaluate_publication_gate,
    render_publication_gate_summary, route_verdict_to_surfaces,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn entitled_verdict(atom_id: &str) -> ClaimVerdict {
    ClaimVerdict {
        atom_id: atom_id.to_string(),
        state: ClaimVerdictState::Entitled,
        supporting_morphism_ids: vec![format!("morph-{atom_id}")],
        active_rule_ids: Vec::new(),
        minimal_cutset_ids: Vec::new(),
        impossibility_certificate_ids: Vec::new(),
    }
}

fn blocked_verdict(atom_id: &str) -> ClaimVerdict {
    ClaimVerdict {
        atom_id: atom_id.to_string(),
        state: ClaimVerdictState::BlockedByMissingEvidence,
        supporting_morphism_ids: Vec::new(),
        active_rule_ids: Vec::new(),
        minimal_cutset_ids: vec![format!("cutset-{atom_id}")],
        impossibility_certificate_ids: Vec::new(),
    }
}

fn not_yet_proven_verdict(atom_id: &str) -> ClaimVerdict {
    ClaimVerdict {
        atom_id: atom_id.to_string(),
        state: ClaimVerdictState::NotYetProven,
        supporting_morphism_ids: Vec::new(),
        active_rule_ids: Vec::new(),
        minimal_cutset_ids: Vec::new(),
        impossibility_certificate_ids: Vec::new(),
    }
}

fn counterexample_verdict(atom_id: &str) -> ClaimVerdict {
    ClaimVerdict {
        atom_id: atom_id.to_string(),
        state: ClaimVerdictState::CurrentlyFalseUnderActiveCounterexample,
        supporting_morphism_ids: Vec::new(),
        active_rule_ids: vec![format!("rule-{atom_id}")],
        minimal_cutset_ids: Vec::new(),
        impossibility_certificate_ids: vec![format!("cert-{atom_id}")],
    }
}

fn av(verdict: ClaimVerdict, domain: &str, tier: &str) -> AnnotatedVerdict {
    AnnotatedVerdict {
        statement: format!("Claim {}", verdict.atom_id),
        verdict,
        domain: domain.to_string(),
        tier: tier.to_string(),
        staleness_hours: 0,
    }
}

fn stale_av(verdict: ClaimVerdict, domain: &str, tier: &str, hours: u64) -> AnnotatedVerdict {
    AnnotatedVerdict {
        statement: format!("Claim {}", verdict.atom_id),
        verdict,
        domain: domain.to_string(),
        tier: tier.to_string(),
        staleness_hours: hours,
    }
}

fn gap(id: &str, domain: &str, surfaces: Vec<PublicationSurface>) -> FrontierGapDisclosure {
    FrontierGapDisclosure {
        gap_id: id.to_string(),
        description: format!("Test gap {id}"),
        domain: domain.to_string(),
        blocks_surfaces: surfaces,
        remediation: "bd-test".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Schema and constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_present() {
    assert!(!CLAIM_PUBLICATION_GATE_SCHEMA_VERSION.is_empty());
    assert!(CLAIM_PUBLICATION_GATE_SCHEMA_VERSION.contains("claim-publication-gate"));
}

#[test]
fn bead_id_present() {
    assert_eq!(CLAIM_PUBLICATION_GATE_BEAD_ID, "bd-1lsy.1.7.3");
}

#[test]
fn max_staleness_reasonable() {
    assert_eq!(MAX_PUBLISHABLE_STALENESS_HOURS, 168); // 1 week
}

#[test]
fn all_surfaces_has_five_entries() {
    assert_eq!(ALL_SURFACES.len(), 5);
}

// ---------------------------------------------------------------------------
// Surface routing
// ---------------------------------------------------------------------------

#[test]
fn route_compatibility_includes_docs_rollout_ga() {
    let config = SurfaceRoutingConfig::default();
    let verdict = av(entitled_verdict("c1"), "compatibility", "shipped_fact");
    let surfaces = route_verdict_to_surfaces(&verdict, &config);
    assert_eq!(surfaces.len(), 3);
    assert!(surfaces.contains(&PublicationSurface::Docs));
    assert!(surfaces.contains(&PublicationSurface::Rollout));
    assert!(surfaces.contains(&PublicationSurface::Ga));
}

#[test]
fn route_supremacy_includes_supremacy_docs() {
    let config = SurfaceRoutingConfig::default();
    let verdict = av(entitled_verdict("s1"), "supremacy", "shipped_fact");
    let surfaces = route_verdict_to_surfaces(&verdict, &config);
    assert!(surfaces.contains(&PublicationSurface::Supremacy));
    assert!(surfaces.contains(&PublicationSurface::Docs));
    assert_eq!(surfaces.len(), 2);
}

#[test]
fn route_react_includes_react_docs_ga() {
    let config = SurfaceRoutingConfig::default();
    let verdict = av(entitled_verdict("r1"), "react", "shipped_fact");
    let surfaces = route_verdict_to_surfaces(&verdict, &config);
    assert!(surfaces.contains(&PublicationSurface::React));
    assert!(surfaces.contains(&PublicationSurface::Docs));
    assert!(surfaces.contains(&PublicationSurface::Ga));
}

#[test]
fn route_security_includes_docs_rollout_ga() {
    let config = SurfaceRoutingConfig::default();
    let verdict = av(entitled_verdict("sec1"), "security", "shipped_fact");
    let surfaces = route_verdict_to_surfaces(&verdict, &config);
    assert_eq!(surfaces.len(), 3);
    assert!(surfaces.contains(&PublicationSurface::Docs));
    assert!(surfaces.contains(&PublicationSurface::Rollout));
    assert!(surfaces.contains(&PublicationSurface::Ga));
}

#[test]
fn route_rollout_only_to_rollout() {
    let config = SurfaceRoutingConfig::default();
    let verdict = av(entitled_verdict("ro1"), "rollout", "shipped_fact");
    let surfaces = route_verdict_to_surfaces(&verdict, &config);
    assert_eq!(surfaces.len(), 1);
    assert_eq!(surfaces[0], PublicationSurface::Rollout);
}

#[test]
fn route_ga_only_to_ga() {
    let config = SurfaceRoutingConfig::default();
    let verdict = av(entitled_verdict("ga1"), "ga", "shipped_fact");
    let surfaces = route_verdict_to_surfaces(&verdict, &config);
    assert_eq!(surfaces.len(), 1);
    assert_eq!(surfaces[0], PublicationSurface::Ga);
}

#[test]
fn route_docs_only_to_docs() {
    let config = SurfaceRoutingConfig::default();
    let verdict = av(entitled_verdict("doc1"), "docs", "shipped_fact");
    let surfaces = route_verdict_to_surfaces(&verdict, &config);
    assert_eq!(surfaces.len(), 1);
    assert_eq!(surfaces[0], PublicationSurface::Docs);
}

#[test]
fn route_unknown_domain_empty() {
    let config = SurfaceRoutingConfig::default();
    let verdict = av(entitled_verdict("x1"), "nonexistent", "shipped_fact");
    let surfaces = route_verdict_to_surfaces(&verdict, &config);
    assert!(surfaces.is_empty());
}

// ---------------------------------------------------------------------------
// Tier filtering
// ---------------------------------------------------------------------------

#[test]
fn shipped_fact_published_on_supremacy() {
    let verdicts = vec![av(entitled_verdict("s1"), "supremacy", "shipped_fact")];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let sup = eval.surface_claims.get("supremacy");
    assert!(sup.is_some_and(|c| !c.is_empty()));
}

#[test]
fn scoped_excluded_from_supremacy() {
    let verdicts = vec![av(entitled_verdict("s1"), "supremacy", "scoped_observed")];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let sup = eval.surface_claims.get("supremacy");
    assert!(sup.is_none() || sup.is_some_and(|c| c.is_empty()));
}

#[test]
fn frontier_excluded_from_ga() {
    let verdicts = vec![av(
        entitled_verdict("c1"),
        "compatibility",
        "frontier_ambition",
    )];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let ga = eval.surface_claims.get("ga");
    assert!(ga.is_none() || ga.is_some_and(|c| c.is_empty()));
}

#[test]
fn frontier_allowed_on_docs() {
    let verdicts = vec![av(
        entitled_verdict("c1"),
        "compatibility",
        "frontier_ambition",
    )];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let docs = eval.surface_claims.get("docs");
    assert!(docs.is_some_and(|c| !c.is_empty()));
}

#[test]
fn scoped_allowed_on_rollout() {
    let verdicts = vec![av(
        entitled_verdict("c1"),
        "compatibility",
        "scoped_observed",
    )];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let rollout = eval.surface_claims.get("rollout");
    assert!(rollout.is_some_and(|c| !c.is_empty()));
}

#[test]
fn unsupported_surface_tier_excluded_everywhere() {
    let verdicts = vec![av(
        entitled_verdict("u1"),
        "compatibility",
        "unsupported_surface",
    )];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    for claims in eval.surface_claims.values() {
        assert!(claims.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Gate decisions
// ---------------------------------------------------------------------------

#[test]
fn all_surfaces_have_decisions() {
    let verdicts = vec![av(entitled_verdict("c1"), "compatibility", "shipped_fact")];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 0)
        .expect("evaluate");
    for surface in &ALL_SURFACES {
        assert!(
            eval.gate_decisions.contains_key(&surface.to_string()),
            "missing decision for {surface}"
        );
    }
}

#[test]
fn entitled_only_surface_approved() {
    let verdicts = vec![av(entitled_verdict("c1"), "compatibility", "shipped_fact")];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let docs = eval.gate_decisions.get("docs").expect("docs");
    assert!(matches!(docs, GateDecision::Approved));
}

#[test]
fn counterexample_causes_rejection() {
    let verdicts = vec![av(
        counterexample_verdict("s1"),
        "supremacy",
        "shipped_fact",
    )];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let sup = eval.gate_decisions.get("supremacy").expect("supremacy");
    assert!(matches!(sup, GateDecision::Rejected { .. }));
}

#[test]
fn blocked_causes_warning_caveats() {
    let verdicts = vec![
        av(entitled_verdict("c1"), "compatibility", "shipped_fact"),
        av(blocked_verdict("c2"), "compatibility", "shipped_fact"),
    ];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let docs = eval.gate_decisions.get("docs").expect("docs");
    assert!(matches!(docs, GateDecision::ApprovedWithCaveats { .. }));
}

#[test]
fn no_claims_for_surface_rejected() {
    // Only supremacy claims → other surfaces without claims should be rejected
    let verdicts = vec![av(entitled_verdict("s1"), "supremacy", "shipped_fact")];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let rollout = eval.gate_decisions.get("rollout").expect("rollout");
    assert!(matches!(rollout, GateDecision::Rejected { .. }));
}

// ---------------------------------------------------------------------------
// Frontier gaps
// ---------------------------------------------------------------------------

#[test]
fn gap_blocking_ga_triggers_guidance() {
    let verdicts = vec![av(entitled_verdict("c1"), "compatibility", "shipped_fact")];
    let gaps = vec![gap("g1", "compat", vec![PublicationSurface::Ga])];
    let eval = evaluate_publication_gate(&verdicts, &gaps, &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let ga = eval.gate_decisions.get("ga").expect("ga");
    assert!(matches!(ga, GateDecision::RequireOperatorGuidance { .. }));
}

#[test]
fn gap_not_blocking_unrelated_surface() {
    let verdicts = vec![av(entitled_verdict("c1"), "compatibility", "shipped_fact")];
    let gaps = vec![gap("g1", "compat", vec![PublicationSurface::Supremacy])];
    let eval = evaluate_publication_gate(&verdicts, &gaps, &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let docs = eval.gate_decisions.get("docs").expect("docs");
    // Docs should still be approved (gap doesn't block docs)
    assert!(matches!(
        docs,
        GateDecision::Approved | GateDecision::ApprovedWithCaveats { .. }
    ));
}

#[test]
fn multiple_gaps_all_tracked() {
    let verdicts = vec![av(entitled_verdict("c1"), "compatibility", "shipped_fact")];
    let gaps = vec![
        gap("g1", "compat", vec![PublicationSurface::Ga]),
        gap("g2", "react", vec![PublicationSurface::React]),
        gap("g3", "supremacy", vec![PublicationSurface::Supremacy]),
    ];
    let eval = evaluate_publication_gate(&verdicts, &gaps, &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    assert_eq!(eval.frontier_gaps.len(), 3);
    assert_eq!(eval.summary.frontier_gap_count, 3);
}

// ---------------------------------------------------------------------------
// Staleness
// ---------------------------------------------------------------------------

#[test]
fn stale_supremacy_generates_warning() {
    let verdicts = vec![stale_av(
        entitled_verdict("s1"),
        "supremacy",
        "shipped_fact",
        100, // exceeds 72h limit
    )];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let stale_flags: Vec<_> = eval
        .risk_flags
        .iter()
        .filter(|f| f.description.contains("staleness"))
        .collect();
    assert!(!stale_flags.is_empty());
}

#[test]
fn fresh_evidence_no_staleness_warning() {
    let verdicts = vec![av(entitled_verdict("c1"), "compatibility", "shipped_fact")];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let stale_flags: Vec<_> = eval
        .risk_flags
        .iter()
        .filter(|f| f.description.contains("staleness"))
        .collect();
    assert!(stale_flags.is_empty());
}

#[test]
fn docs_has_double_staleness_limit() {
    let config = SurfaceRoutingConfig::default();
    let docs_limit = config.max_staleness_hours.get(&PublicationSurface::Docs);
    let ga_limit = config.max_staleness_hours.get(&PublicationSurface::Ga);
    assert!(docs_limit.is_some_and(|d| ga_limit.is_some_and(|g| *d > *g)));
}

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

#[test]
fn empty_verdicts_returns_error() {
    let result = evaluate_publication_gate(&[], &[], &SurfaceRoutingConfig::default(), 0);
    assert!(matches!(result, Err(PublicationGateError::EmptyVerdicts)));
}

// ---------------------------------------------------------------------------
// Risk flags
// ---------------------------------------------------------------------------

#[test]
fn counterexample_produces_critical_flag() {
    let verdicts = vec![av(
        counterexample_verdict("c1"),
        "compatibility",
        "shipped_fact",
    )];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let critical_flags: Vec<_> = eval
        .risk_flags
        .iter()
        .filter(|f| f.severity == RiskSeverity::Critical)
        .collect();
    assert!(!critical_flags.is_empty());
}

#[test]
fn blocked_produces_warning_flag() {
    let verdicts = vec![av(blocked_verdict("c1"), "compatibility", "shipped_fact")];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let warning_flags: Vec<_> = eval
        .risk_flags
        .iter()
        .filter(|f| f.severity == RiskSeverity::Warning)
        .collect();
    assert!(!warning_flags.is_empty());
}

#[test]
fn not_yet_proven_produces_info_flag() {
    let verdicts = vec![av(
        not_yet_proven_verdict("c1"),
        "compatibility",
        "shipped_fact",
    )];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let info_flags: Vec<_> = eval
        .risk_flags
        .iter()
        .filter(|f| f.severity == RiskSeverity::Info)
        .collect();
    assert!(!info_flags.is_empty());
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

#[test]
fn summary_counts_verdicts() {
    let verdicts = vec![
        av(entitled_verdict("c1"), "compatibility", "shipped_fact"),
        av(entitled_verdict("r1"), "react", "shipped_fact"),
        av(blocked_verdict("s1"), "supremacy", "shipped_fact"),
    ];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    assert_eq!(eval.summary.total_verdicts, 3);
}

#[test]
fn summary_counts_publishable_claims() {
    let verdicts = vec![
        av(entitled_verdict("c1"), "compatibility", "shipped_fact"),
        av(entitled_verdict("c2"), "compatibility", "shipped_fact"),
    ];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    // Each compat claim routes to 3 surfaces → 6 total publishable claims
    assert_eq!(eval.summary.total_publishable_claims, 6);
}

#[test]
fn render_summary_includes_epoch() {
    let verdicts = vec![av(entitled_verdict("c1"), "compatibility", "shipped_fact")];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 99)
        .expect("evaluate");
    let summary = render_publication_gate_summary(&eval);
    assert!(summary.contains("evaluated_epoch: 99"));
}

#[test]
fn render_summary_includes_surface_decisions() {
    let verdicts = vec![av(entitled_verdict("c1"), "compatibility", "shipped_fact")];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let summary = render_publication_gate_summary(&eval);
    assert!(summary.contains("Per-surface decisions"));
    assert!(summary.contains("docs:"));
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn full_evaluation_serde_round_trip() {
    let verdicts = vec![
        av(entitled_verdict("c1"), "compatibility", "shipped_fact"),
        av(blocked_verdict("c2"), "supremacy", "shipped_fact"),
    ];
    let gaps = vec![gap("g1", "compat", vec![PublicationSurface::Ga])];
    let eval = evaluate_publication_gate(&verdicts, &gaps, &SurfaceRoutingConfig::default(), 42)
        .expect("evaluate");
    let json = serde_json::to_string_pretty(&eval).expect("serialize");
    let deser: PublicationGateEvaluation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(eval, deser);
}

#[test]
fn config_serde_round_trip() {
    let config = SurfaceRoutingConfig::default();
    let json = serde_json::to_string(&config).expect("serialize");
    let deser: SurfaceRoutingConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, deser);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn evaluation_deterministic_across_runs() {
    let verdicts = vec![
        av(entitled_verdict("c1"), "compatibility", "shipped_fact"),
        av(entitled_verdict("r1"), "react", "shipped_fact"),
        av(blocked_verdict("s1"), "supremacy", "shipped_fact"),
    ];
    let gaps = vec![gap("g1", "compat", vec![PublicationSurface::Ga])];
    let config = SurfaceRoutingConfig::default();

    let eval1 = evaluate_publication_gate(&verdicts, &gaps, &config, 1).expect("eval1");
    let eval2 = evaluate_publication_gate(&verdicts, &gaps, &config, 1).expect("eval2");

    let json1 = serde_json::to_string(&eval1).expect("ser1");
    let json2 = serde_json::to_string(&eval2).expect("ser2");
    assert_eq!(json1, json2);
}

// ---------------------------------------------------------------------------
// Multi-domain scenarios
// ---------------------------------------------------------------------------

#[test]
fn full_board_coverage_scenario() {
    let verdicts = vec![
        av(
            entitled_verdict("compat-1"),
            "compatibility",
            "shipped_fact",
        ),
        av(
            entitled_verdict("ship-1"),
            "shipped_surface",
            "shipped_fact",
        ),
        av(entitled_verdict("react-1"), "react", "shipped_fact"),
        av(entitled_verdict("sup-1"), "supremacy", "shipped_fact"),
        av(entitled_verdict("roll-1"), "rollout", "scoped_observed"),
        av(entitled_verdict("ga-1"), "ga", "scoped_observed"),
        av(entitled_verdict("docs-1"), "docs", "frontier_ambition"),
        av(entitled_verdict("sec-1"), "security", "shipped_fact"),
    ];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    // All surfaces should have at least one claim
    for surface in &ALL_SURFACES {
        let claims = eval.surface_claims.get(&surface.to_string());
        assert!(
            claims.is_some_and(|c| !c.is_empty()),
            "no claims on {surface}"
        );
    }
    // All surfaces should be approved
    assert_eq!(eval.summary.approved_surfaces, 5);
    assert_eq!(eval.summary.rejected_surfaces, 0);
}

#[test]
fn mixed_verdicts_across_domains() {
    let verdicts = vec![
        av(entitled_verdict("c1"), "compatibility", "shipped_fact"),
        av(counterexample_verdict("s1"), "supremacy", "shipped_fact"),
        av(entitled_verdict("r1"), "react", "shipped_fact"),
    ];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");

    // Docs: approved (compat + supremacy counterexample → supremacy routed there but rejected)
    let docs = eval.gate_decisions.get("docs").expect("docs");
    // Docs gets both compat (entitled) and supremacy (counterexample)
    // counterexample on supremacy domain → critical flag on docs surface
    assert!(matches!(docs, GateDecision::Rejected { .. }));

    // Supremacy: rejected (counterexample)
    let sup = eval.gate_decisions.get("supremacy").expect("supremacy");
    assert!(matches!(sup, GateDecision::Rejected { .. }));

    // React: approved (react entitled)
    let react = eval.gate_decisions.get("react").expect("react");
    assert!(matches!(
        react,
        GateDecision::Approved | GateDecision::ApprovedWithCaveats { .. }
    ));
}

// ---------------------------------------------------------------------------
// Display trait coverage
// ---------------------------------------------------------------------------

#[test]
fn test_publication_surface_display_all_variants() {
    assert_eq!(PublicationSurface::Docs.to_string(), "docs");
    assert_eq!(PublicationSurface::Rollout.to_string(), "rollout");
    assert_eq!(PublicationSurface::Ga.to_string(), "ga");
    assert_eq!(PublicationSurface::React.to_string(), "react");
    assert_eq!(PublicationSurface::Supremacy.to_string(), "supremacy");
}

#[test]
fn test_gate_decision_display_approved() {
    let d = GateDecision::Approved;
    assert_eq!(d.to_string(), "approved");
}

#[test]
fn test_gate_decision_display_approved_with_caveats() {
    let d = GateDecision::ApprovedWithCaveats {
        caveat_ids: vec!["c1".to_string(), "c2".to_string()],
    };
    assert!(d.to_string().contains("approved_with_caveats(2)"));
}

#[test]
fn test_gate_decision_display_require_operator_guidance() {
    let d = GateDecision::RequireOperatorGuidance {
        reason: "gaps block ga".to_string(),
    };
    assert!(d.to_string().contains("require_operator_guidance"));
    assert!(d.to_string().contains("gaps block ga"));
}

#[test]
fn test_gate_decision_display_rejected() {
    let d = GateDecision::Rejected {
        reason: "no evidence".to_string(),
    };
    assert!(d.to_string().contains("rejected"));
    assert!(d.to_string().contains("no evidence"));
}

#[test]
fn test_risk_severity_display_all_variants() {
    assert_eq!(RiskSeverity::Info.to_string(), "info");
    assert_eq!(RiskSeverity::Warning.to_string(), "warning");
    assert_eq!(RiskSeverity::Critical.to_string(), "critical");
}

#[test]
fn test_publication_gate_error_display_empty_verdicts() {
    let e = PublicationGateError::EmptyVerdicts;
    assert!(e.to_string().contains("no verdicts"));
}

#[test]
fn test_publication_gate_error_display_unknown_domain() {
    let e = PublicationGateError::UnknownDomain {
        domain: "frobnicator".to_string(),
    };
    assert!(e.to_string().contains("frobnicator"));
    assert!(e.to_string().contains("unknown domain"));
}

#[test]
fn test_publication_gate_error_display_invalid_config() {
    let e = PublicationGateError::InvalidConfig {
        reason: "bad staleness".to_string(),
    };
    assert!(e.to_string().contains("bad staleness"));
}

#[test]
fn test_publication_gate_evaluation_display() {
    let verdicts = vec![av(entitled_verdict("c1"), "compatibility", "shipped_fact")];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 7)
        .expect("evaluate");
    let s = eval.to_string();
    assert!(s.contains("epoch=7"));
    assert!(s.contains("approved="));
    assert!(s.contains("flags="));
}

// ---------------------------------------------------------------------------
// Clone/Debug/PartialEq coverage
// ---------------------------------------------------------------------------

#[test]
fn test_publication_surface_clone_eq() {
    let s1 = PublicationSurface::Ga;
    let s2 = s1.clone();
    assert_eq!(s1, s2);
}

#[test]
fn test_risk_severity_ordering() {
    assert!(RiskSeverity::Info < RiskSeverity::Warning);
    assert!(RiskSeverity::Warning < RiskSeverity::Critical);
    assert!(RiskSeverity::Info < RiskSeverity::Critical);
}

#[test]
fn test_publication_surface_ordering() {
    // ALL_SURFACES defines canonical order; Ord must agree
    let mut surfaces = vec![
        PublicationSurface::Supremacy,
        PublicationSurface::Ga,
        PublicationSurface::Docs,
    ];
    surfaces.sort();
    // After sort, Docs < Ga < Supremacy (alphabetical serde snake_case backed by derive)
    // Just check the sort is stable and produces a consistent result
    let sorted_once = surfaces.clone();
    surfaces.sort();
    assert_eq!(sorted_once, surfaces);
}

#[test]
fn test_frontier_gap_disclosure_display() {
    let g = gap("gap-42", "compat", vec![PublicationSurface::Ga]);
    let s = g.to_string();
    assert!(s.contains("gap-42"));
    assert!(s.contains("compat"));
}

#[test]
fn test_risk_flag_display() {
    let f = RiskFlag {
        flag_id: "stale-1".to_string(),
        severity: RiskSeverity::Warning,
        surface: PublicationSurface::Ga,
        description: "staleness exceeded".to_string(),
    };
    let s = f.to_string();
    assert!(s.contains("stale-1"));
    assert!(s.contains("warning"));
    assert!(s.contains("ga"));
}

#[test]
fn test_publishable_claim_display() {
    let verdicts = vec![av(
        entitled_verdict("atom-7"),
        "compatibility",
        "shipped_fact",
    )];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let claims = eval.surface_claims.get("docs").expect("docs claims");
    let display = claims[0].to_string();
    assert!(display.contains("atom-7"));
    assert!(display.contains("docs"));
}

// ---------------------------------------------------------------------------
// Serde: individual struct round-trips
// ---------------------------------------------------------------------------

#[test]
fn test_gate_decision_serde_variants() {
    let variants = vec![
        GateDecision::Approved,
        GateDecision::ApprovedWithCaveats {
            caveat_ids: vec!["x".to_string()],
        },
        GateDecision::RequireOperatorGuidance {
            reason: "needs review".to_string(),
        },
        GateDecision::Rejected {
            reason: "failed".to_string(),
        },
    ];
    for d in &variants {
        let json = serde_json::to_string(d).expect("serialize");
        let back: GateDecision = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(d, &back);
    }
}

#[test]
fn test_risk_severity_serde_round_trip() {
    for sev in &[
        RiskSeverity::Info,
        RiskSeverity::Warning,
        RiskSeverity::Critical,
    ] {
        let json = serde_json::to_string(sev).expect("serialize");
        let back: RiskSeverity = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(sev, &back);
    }
}

#[test]
fn test_publication_surface_serde_round_trip() {
    for surface in &ALL_SURFACES {
        let json = serde_json::to_string(surface).expect("serialize");
        let back: PublicationSurface = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(surface, &back);
    }
}

#[test]
fn test_publication_gate_error_serde_round_trip() {
    let errors = vec![
        PublicationGateError::EmptyVerdicts,
        PublicationGateError::UnknownDomain {
            domain: "x".to_string(),
        },
        PublicationGateError::InvalidConfig {
            reason: "y".to_string(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).expect("serialize");
        let back: PublicationGateError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(e, &back);
    }
}

#[test]
fn test_annotated_verdict_serde_round_trip() {
    let v = av(entitled_verdict("at-99"), "react", "shipped_fact");
    let json = serde_json::to_string(&v).expect("serialize");
    let back: AnnotatedVerdict = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(v, back);
}

// ---------------------------------------------------------------------------
// Support_surface domain routing
// ---------------------------------------------------------------------------

#[test]
fn test_route_support_surface_to_docs_and_rollout() {
    let config = SurfaceRoutingConfig::default();
    let verdict = av(entitled_verdict("ss1"), "support_surface", "shipped_fact");
    let surfaces = route_verdict_to_surfaces(&verdict, &config);
    assert_eq!(surfaces.len(), 2);
    assert!(surfaces.contains(&PublicationSurface::Docs));
    assert!(surfaces.contains(&PublicationSurface::Rollout));
    assert!(!surfaces.contains(&PublicationSurface::Ga));
}

#[test]
fn test_shipped_surface_domain_routes_to_docs_rollout_ga() {
    let config = SurfaceRoutingConfig::default();
    let verdict = av(
        entitled_verdict("ship-x"),
        "shipped_surface",
        "shipped_fact",
    );
    let surfaces = route_verdict_to_surfaces(&verdict, &config);
    assert_eq!(surfaces.len(), 3);
    assert!(surfaces.contains(&PublicationSurface::Docs));
    assert!(surfaces.contains(&PublicationSurface::Rollout));
    assert!(surfaces.contains(&PublicationSurface::Ga));
}

// ---------------------------------------------------------------------------
// Tier boundary: React requires shipped_fact
// ---------------------------------------------------------------------------

#[test]
fn test_scoped_observed_excluded_from_react() {
    let verdicts = vec![av(entitled_verdict("r1"), "react", "scoped_observed")];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let react_claims = eval.surface_claims.get("react");
    assert!(react_claims.is_none() || react_claims.is_some_and(|c| c.is_empty()));
}

#[test]
fn test_frontier_ambition_excluded_from_react() {
    let verdicts = vec![av(entitled_verdict("r2"), "react", "frontier_ambition")];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let react_claims = eval.surface_claims.get("react");
    assert!(react_claims.is_none() || react_claims.is_some_and(|c| c.is_empty()));
}

// ---------------------------------------------------------------------------
// Staleness: exact boundary values
// ---------------------------------------------------------------------------

#[test]
fn test_exactly_at_supremacy_staleness_limit_passes() {
    // Supremacy limit is 72h; staleness == 72 should still pass (not exceed)
    let verdicts = vec![stale_av(
        entitled_verdict("s-boundary"),
        "supremacy",
        "shipped_fact",
        72,
    )];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let sup_claims = eval.surface_claims.get("supremacy");
    assert!(sup_claims.is_some_and(|c| !c.is_empty()));
}

#[test]
fn test_one_over_supremacy_staleness_limit_rejected() {
    // staleness == 73 should be rejected (exceeds 72h limit)
    let verdicts = vec![stale_av(
        entitled_verdict("s-over"),
        "supremacy",
        "shipped_fact",
        73,
    )];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let sup_claims = eval.surface_claims.get("supremacy");
    assert!(sup_claims.is_none() || sup_claims.is_some_and(|c| c.is_empty()));
    // Stale flag must exist
    let stale_flags: Vec<_> = eval
        .risk_flags
        .iter()
        .filter(|f| f.description.contains("staleness"))
        .collect();
    assert!(!stale_flags.is_empty());
}

// ---------------------------------------------------------------------------
// Summary: guidance_required_surfaces counter
// ---------------------------------------------------------------------------

#[test]
fn test_guidance_required_surfaces_counter() {
    let verdicts = vec![av(entitled_verdict("c1"), "compatibility", "shipped_fact")];
    let gaps = vec![
        gap("g1", "compat", vec![PublicationSurface::Ga]),
        gap("g2", "react", vec![PublicationSurface::React]),
    ];
    let eval = evaluate_publication_gate(&verdicts, &gaps, &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    assert!(eval.summary.guidance_required_surfaces >= 1);
}

// ---------------------------------------------------------------------------
// render_publication_gate_summary content coverage
// ---------------------------------------------------------------------------

#[test]
fn test_render_summary_contains_risk_flag_count() {
    let verdicts = vec![av(
        counterexample_verdict("c1"),
        "compatibility",
        "shipped_fact",
    )];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let summary = render_publication_gate_summary(&eval);
    assert!(summary.contains("risk_flags:"));
}

#[test]
fn test_render_summary_contains_schema_version() {
    let verdicts = vec![av(entitled_verdict("c1"), "compatibility", "shipped_fact")];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let summary = render_publication_gate_summary(&eval);
    assert!(summary.contains("schema_version:"));
    assert!(summary.contains("claim-publication-gate"));
}

// ---------------------------------------------------------------------------
// Multiple gaps blocking the same surface
// ---------------------------------------------------------------------------

#[test]
fn test_multiple_gaps_blocking_same_surface_all_tracked() {
    let verdicts = vec![av(entitled_verdict("c1"), "compatibility", "shipped_fact")];
    let gaps = vec![
        gap("g1", "compat", vec![PublicationSurface::Ga]),
        gap("g2", "compat", vec![PublicationSurface::Ga]),
    ];
    let eval = evaluate_publication_gate(&verdicts, &gaps, &SurfaceRoutingConfig::default(), 1)
        .expect("evaluate");
    let ga = eval.gate_decisions.get("ga").expect("ga");
    assert!(matches!(ga, GateDecision::RequireOperatorGuidance { .. }));
    assert_eq!(eval.summary.frontier_gap_count, 2);
}

// ---------------------------------------------------------------------------
// PublicationGateEvaluation bead/schema identity fields
// ---------------------------------------------------------------------------

#[test]
fn test_evaluation_schema_and_bead_fields() {
    let verdicts = vec![av(entitled_verdict("c1"), "compatibility", "shipped_fact")];
    let eval = evaluate_publication_gate(&verdicts, &[], &SurfaceRoutingConfig::default(), 5)
        .expect("evaluate");
    assert_eq!(eval.schema_version, CLAIM_PUBLICATION_GATE_SCHEMA_VERSION);
    assert_eq!(eval.bead_id, CLAIM_PUBLICATION_GATE_BEAD_ID);
    assert_eq!(eval.evaluated_epoch, 5);
}
