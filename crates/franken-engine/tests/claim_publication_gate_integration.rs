//! Integration tests for the claim publication gate module.
//!
//! Tests Layer 3 of the claim-entitlement system: wiring verdicts to
//! publication surfaces (docs, rollout, GA, React, supremacy).
//!
//! Bead: bd-1lsy.1.7.3 [RGC-017C]

use frankenengine_engine::claim_entitlement::{ClaimVerdict, ClaimVerdictState};
use frankenengine_engine::claim_publication_gate::{
    ALL_SURFACES, AnnotatedVerdict, CLAIM_PUBLICATION_GATE_BEAD_ID,
    CLAIM_PUBLICATION_GATE_SCHEMA_VERSION, FrontierGapDisclosure, GateDecision,
    MAX_PUBLISHABLE_STALENESS_HOURS, PublicationGateError, PublicationGateEvaluation,
    PublicationSurface, RiskSeverity, SurfaceRoutingConfig, evaluate_publication_gate,
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
