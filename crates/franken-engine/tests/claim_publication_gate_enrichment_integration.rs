#![forbid(unsafe_code)]

//! Enrichment integration tests for `claim_publication_gate` module.
//!
//! Covers: Display uniqueness for all enums, serde roundtrips for all types,
//! constant validation, surface routing, tier filtering, staleness gating,
//! gate decision logic, frontier gap interactions, risk flag generation,
//! summary counts, render output, and full evaluation lifecycle edge cases.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::claim_entitlement::{ClaimVerdict, ClaimVerdictState};
use frankenengine_engine::claim_publication_gate::*;

// ---------------------------------------------------------------------------
// Helpers
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

fn make_annotated(verdict: ClaimVerdict, domain: &str, tier: &str) -> AnnotatedVerdict {
    AnnotatedVerdict {
        statement: format!("Test claim {}", verdict.atom_id),
        verdict,
        domain: domain.to_string(),
        tier: tier.to_string(),
        staleness_hours: 0,
    }
}

fn make_stale_annotated(
    verdict: ClaimVerdict,
    domain: &str,
    tier: &str,
    staleness_hours: u64,
) -> AnnotatedVerdict {
    AnnotatedVerdict {
        statement: format!("Stale claim {}", verdict.atom_id),
        verdict,
        domain: domain.to_string(),
        tier: tier.to_string(),
        staleness_hours,
    }
}

fn make_gap(
    gap_id: &str,
    domain: &str,
    blocks: Vec<PublicationSurface>,
) -> FrontierGapDisclosure {
    FrontierGapDisclosure {
        gap_id: gap_id.to_string(),
        description: format!("Gap in {domain}"),
        domain: domain.to_string(),
        blocks_surfaces: blocks,
        remediation: format!("bd-{gap_id}"),
    }
}

fn default_config() -> SurfaceRoutingConfig {
    SurfaceRoutingConfig::default()
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_schema_version_constant_nonempty() {
    assert!(!CLAIM_PUBLICATION_GATE_SCHEMA_VERSION.is_empty());
    assert!(CLAIM_PUBLICATION_GATE_SCHEMA_VERSION.contains("claim-publication-gate"));
}

#[test]
fn enrichment_bead_id_constant_nonempty() {
    assert!(!CLAIM_PUBLICATION_GATE_BEAD_ID.is_empty());
    assert!(CLAIM_PUBLICATION_GATE_BEAD_ID.starts_with("bd-"));
}

#[test]
fn enrichment_max_staleness_hours_positive() {
    assert!(MAX_PUBLISHABLE_STALENESS_HOURS > 0);
    assert_eq!(MAX_PUBLISHABLE_STALENESS_HOURS, 168);
}

#[test]
fn enrichment_all_surfaces_has_five_entries() {
    assert_eq!(ALL_SURFACES.len(), 5);
}

#[test]
fn enrichment_all_surfaces_canonical_order() {
    assert_eq!(ALL_SURFACES[0], PublicationSurface::Docs);
    assert_eq!(ALL_SURFACES[1], PublicationSurface::Rollout);
    assert_eq!(ALL_SURFACES[2], PublicationSurface::Ga);
    assert_eq!(ALL_SURFACES[3], PublicationSurface::React);
    assert_eq!(ALL_SURFACES[4], PublicationSurface::Supremacy);
}

// ---------------------------------------------------------------------------
// PublicationSurface — Display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_publication_surface_display_all_unique() {
    let mut displays = BTreeSet::new();
    for s in &ALL_SURFACES {
        let d = s.to_string();
        assert!(!d.is_empty(), "surface display should not be empty");
        assert!(displays.insert(d.clone()), "duplicate display: {d}");
    }
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_publication_surface_display_docs() {
    assert_eq!(PublicationSurface::Docs.to_string(), "docs");
}

#[test]
fn enrichment_publication_surface_display_rollout() {
    assert_eq!(PublicationSurface::Rollout.to_string(), "rollout");
}

#[test]
fn enrichment_publication_surface_display_ga() {
    assert_eq!(PublicationSurface::Ga.to_string(), "ga");
}

#[test]
fn enrichment_publication_surface_display_react() {
    assert_eq!(PublicationSurface::React.to_string(), "react");
}

#[test]
fn enrichment_publication_surface_display_supremacy() {
    assert_eq!(PublicationSurface::Supremacy.to_string(), "supremacy");
}

// ---------------------------------------------------------------------------
// PublicationSurface — serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_publication_surface_serde_roundtrip_each() {
    for s in &ALL_SURFACES {
        let json = serde_json::to_string(s).expect("serialize");
        let back: PublicationSurface = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*s, back);
    }
}

#[test]
fn enrichment_publication_surface_serde_rename_snake_case() {
    let json = serde_json::to_string(&PublicationSurface::Docs).expect("serialize");
    assert_eq!(json, "\"docs\"");
    let json = serde_json::to_string(&PublicationSurface::Supremacy).expect("serialize");
    assert_eq!(json, "\"supremacy\"");
}

// ---------------------------------------------------------------------------
// GateDecision — Display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_decision_display_approved() {
    assert_eq!(GateDecision::Approved.to_string(), "approved");
}

#[test]
fn enrichment_gate_decision_display_approved_with_caveats_includes_count() {
    let d = GateDecision::ApprovedWithCaveats {
        caveat_ids: vec!["c1".into(), "c2".into(), "c3".into()],
    };
    let s = d.to_string();
    assert!(s.contains("approved_with_caveats"));
    assert!(s.contains("3"));
}

#[test]
fn enrichment_gate_decision_display_require_operator_guidance() {
    let d = GateDecision::RequireOperatorGuidance {
        reason: "frontier gap".into(),
    };
    let s = d.to_string();
    assert!(s.contains("require_operator_guidance"));
    assert!(s.contains("frontier gap"));
}

#[test]
fn enrichment_gate_decision_display_rejected_includes_reason() {
    let d = GateDecision::Rejected {
        reason: "missing evidence".into(),
    };
    let s = d.to_string();
    assert!(s.contains("rejected"));
    assert!(s.contains("missing evidence"));
}

#[test]
fn enrichment_gate_decision_display_all_unique() {
    let decisions = vec![
        GateDecision::Approved,
        GateDecision::ApprovedWithCaveats {
            caveat_ids: vec!["c1".into()],
        },
        GateDecision::RequireOperatorGuidance {
            reason: "test".into(),
        },
        GateDecision::Rejected {
            reason: "fail".into(),
        },
    ];
    let mut displays = BTreeSet::new();
    for d in &decisions {
        let s = d.to_string();
        assert!(displays.insert(s.clone()), "duplicate display: {s}");
    }
    assert_eq!(displays.len(), 4);
}

// ---------------------------------------------------------------------------
// GateDecision — serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_decision_serde_roundtrip_approved() {
    let d = GateDecision::Approved;
    let json = serde_json::to_string(&d).expect("serialize");
    let back: GateDecision = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(d, back);
}

#[test]
fn enrichment_gate_decision_serde_roundtrip_approved_with_caveats() {
    let d = GateDecision::ApprovedWithCaveats {
        caveat_ids: vec!["caveat-1".into(), "caveat-2".into()],
    };
    let json = serde_json::to_string(&d).expect("serialize");
    let back: GateDecision = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(d, back);
}

#[test]
fn enrichment_gate_decision_serde_roundtrip_require_guidance() {
    let d = GateDecision::RequireOperatorGuidance {
        reason: "gap in react".into(),
    };
    let json = serde_json::to_string(&d).expect("serialize");
    let back: GateDecision = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(d, back);
}

#[test]
fn enrichment_gate_decision_serde_roundtrip_rejected() {
    let d = GateDecision::Rejected {
        reason: "critical failure".into(),
    };
    let json = serde_json::to_string(&d).expect("serialize");
    let back: GateDecision = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(d, back);
}

#[test]
fn enrichment_gate_decision_approved_with_empty_caveats() {
    let d = GateDecision::ApprovedWithCaveats {
        caveat_ids: Vec::new(),
    };
    let s = d.to_string();
    assert!(s.contains("0"));
    let json = serde_json::to_string(&d).expect("serialize");
    let back: GateDecision = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(d, back);
}

// ---------------------------------------------------------------------------
// PublicationTier — Display + serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_publication_tier_display_shipped_fact() {
    assert_eq!(PublicationTier::ShippedFact.to_string(), "shipped_fact");
}

#[test]
fn enrichment_publication_tier_display_scoped_observed() {
    assert_eq!(
        PublicationTier::ScopedObserved.to_string(),
        "scoped_observed"
    );
}

#[test]
fn enrichment_publication_tier_display_frontier_ambition() {
    assert_eq!(
        PublicationTier::FrontierAmbition.to_string(),
        "frontier_ambition"
    );
}

#[test]
fn enrichment_publication_tier_display_all_unique() {
    let tiers = [
        PublicationTier::ShippedFact,
        PublicationTier::ScopedObserved,
        PublicationTier::FrontierAmbition,
    ];
    let mut displays = BTreeSet::new();
    for t in &tiers {
        assert!(displays.insert(t.to_string()));
    }
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_publication_tier_serde_roundtrip() {
    let tiers = [
        PublicationTier::ShippedFact,
        PublicationTier::ScopedObserved,
        PublicationTier::FrontierAmbition,
    ];
    for t in &tiers {
        let json = serde_json::to_string(t).expect("serialize");
        let back: PublicationTier = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*t, back);
    }
}

#[test]
fn enrichment_publication_tier_ord_shipped_highest() {
    // Derived Ord follows variant declaration order (ShippedFact first = smallest).
    // The tier_meets_minimum helper uses an internal rank function for semantic ordering.
    assert!(PublicationTier::ShippedFact < PublicationTier::ScopedObserved);
    assert!(PublicationTier::ScopedObserved < PublicationTier::FrontierAmbition);
    assert!(PublicationTier::ShippedFact < PublicationTier::FrontierAmbition);
}

// ---------------------------------------------------------------------------
// RiskSeverity — Display + serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_risk_severity_display_all() {
    assert_eq!(RiskSeverity::Info.to_string(), "info");
    assert_eq!(RiskSeverity::Warning.to_string(), "warning");
    assert_eq!(RiskSeverity::Critical.to_string(), "critical");
}

#[test]
fn enrichment_risk_severity_display_all_unique() {
    let sevs = [RiskSeverity::Info, RiskSeverity::Warning, RiskSeverity::Critical];
    let mut displays = BTreeSet::new();
    for s in &sevs {
        assert!(displays.insert(s.to_string()));
    }
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_risk_severity_serde_roundtrip() {
    let sevs = [RiskSeverity::Info, RiskSeverity::Warning, RiskSeverity::Critical];
    for s in &sevs {
        let json = serde_json::to_string(s).expect("serialize");
        let back: RiskSeverity = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*s, back);
    }
}

#[test]
fn enrichment_risk_severity_ord_critical_highest() {
    assert!(RiskSeverity::Critical > RiskSeverity::Warning);
    assert!(RiskSeverity::Warning > RiskSeverity::Info);
}

// ---------------------------------------------------------------------------
// PublishableClaim — construction + Display + serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_publishable_claim_construction_and_field_access() {
    let claim = PublishableClaim {
        atom_id: "atom-x".into(),
        surface: PublicationSurface::React,
        publication_tier: PublicationTier::ShippedFact,
        supporting_morphisms: vec!["m1".into(), "m2".into()],
        impossibility_certificates: vec!["cert-1".into()],
        domain: "react".into(),
        statement: "React SSR parity".into(),
    };
    assert_eq!(claim.atom_id, "atom-x");
    assert_eq!(claim.surface, PublicationSurface::React);
    assert_eq!(claim.publication_tier, PublicationTier::ShippedFact);
    assert_eq!(claim.supporting_morphisms.len(), 2);
    assert_eq!(claim.impossibility_certificates.len(), 1);
    assert_eq!(claim.domain, "react");
    assert_eq!(claim.statement, "React SSR parity");
}

#[test]
fn enrichment_publishable_claim_display_format() {
    let claim = PublishableClaim {
        atom_id: "claim-42".into(),
        surface: PublicationSurface::Supremacy,
        publication_tier: PublicationTier::ScopedObserved,
        supporting_morphisms: Vec::new(),
        impossibility_certificates: Vec::new(),
        domain: "supremacy".into(),
        statement: "perf claim".into(),
    };
    let display = claim.to_string();
    assert!(display.contains("claim-42"));
    assert!(display.contains("supremacy"));
    assert!(display.contains("scoped_observed"));
}

#[test]
fn enrichment_publishable_claim_serde_roundtrip() {
    let claim = PublishableClaim {
        atom_id: "a1".into(),
        surface: PublicationSurface::Ga,
        publication_tier: PublicationTier::ScopedObserved,
        supporting_morphisms: vec!["m1".into()],
        impossibility_certificates: Vec::new(),
        domain: "compatibility".into(),
        statement: "ES2024 arrow".into(),
    };
    let json = serde_json::to_string(&claim).expect("serialize");
    let back: PublishableClaim = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(claim, back);
}

#[test]
fn enrichment_publishable_claim_with_empty_morphisms_and_certs() {
    let claim = PublishableClaim {
        atom_id: "minimal".into(),
        surface: PublicationSurface::Docs,
        publication_tier: PublicationTier::FrontierAmbition,
        supporting_morphisms: Vec::new(),
        impossibility_certificates: Vec::new(),
        domain: "docs".into(),
        statement: "aspiration".into(),
    };
    assert!(claim.supporting_morphisms.is_empty());
    assert!(claim.impossibility_certificates.is_empty());
    let json = serde_json::to_string(&claim).expect("serialize");
    let back: PublishableClaim = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(claim, back);
}

// ---------------------------------------------------------------------------
// FrontierGapDisclosure — construction + Display + serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_frontier_gap_disclosure_construction_and_display() {
    let gap = make_gap("gap-gen", "compatibility", vec![PublicationSurface::Ga]);
    assert_eq!(gap.gap_id, "gap-gen");
    assert_eq!(gap.domain, "compatibility");
    assert_eq!(gap.blocks_surfaces.len(), 1);
    let display = gap.to_string();
    assert!(display.contains("gap-gen"));
    assert!(display.contains("compatibility"));
}

#[test]
fn enrichment_frontier_gap_disclosure_serde_roundtrip() {
    let gap = FrontierGapDisclosure {
        gap_id: "g1".into(),
        description: "Async iterators unsupported".into(),
        domain: "compatibility".into(),
        blocks_surfaces: vec![PublicationSurface::Ga, PublicationSurface::Rollout],
        remediation: "bd-1lsy.4.9".into(),
    };
    let json = serde_json::to_string(&gap).expect("serialize");
    let back: FrontierGapDisclosure = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(gap, back);
}

#[test]
fn enrichment_frontier_gap_no_blocking_surfaces() {
    let gap = FrontierGapDisclosure {
        gap_id: "gap-informational".into(),
        description: "Informational gap".into(),
        domain: "docs".into(),
        blocks_surfaces: Vec::new(),
        remediation: "none".into(),
    };
    assert!(gap.blocks_surfaces.is_empty());
    let display = gap.to_string();
    assert!(display.contains("gap-informational"));
}

#[test]
fn enrichment_frontier_gap_blocks_all_surfaces() {
    let gap = FrontierGapDisclosure {
        gap_id: "gap-total".into(),
        description: "Total blocker".into(),
        domain: "security".into(),
        blocks_surfaces: ALL_SURFACES.to_vec(),
        remediation: "bd-critical".into(),
    };
    assert_eq!(gap.blocks_surfaces.len(), 5);
}

// ---------------------------------------------------------------------------
// RiskFlag — construction + Display + serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_risk_flag_construction_and_display() {
    let flag = RiskFlag {
        flag_id: "rf-1".into(),
        severity: RiskSeverity::Critical,
        surface: PublicationSurface::Supremacy,
        description: "counterexample found".into(),
    };
    let display = flag.to_string();
    assert!(display.contains("rf-1"));
    assert!(display.contains("critical"));
    assert!(display.contains("supremacy"));
}

#[test]
fn enrichment_risk_flag_serde_roundtrip() {
    let flag = RiskFlag {
        flag_id: "rf-2".into(),
        severity: RiskSeverity::Info,
        surface: PublicationSurface::Docs,
        description: "informational note".into(),
    };
    let json = serde_json::to_string(&flag).expect("serialize");
    let back: RiskFlag = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(flag, back);
}

// ---------------------------------------------------------------------------
// SurfaceRoutingConfig — default + serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_surface_routing_config_default_has_all_expected_domains() {
    let config = default_config();
    let expected_domains = [
        "compatibility",
        "shipped_surface",
        "react",
        "supremacy",
        "rollout",
        "ga",
        "docs",
        "security",
        "support_surface",
    ];
    for domain in &expected_domains {
        assert!(
            config.domain_to_surfaces.contains_key(*domain),
            "missing domain: {domain}"
        );
    }
}

#[test]
fn enrichment_surface_routing_config_default_min_tiers() {
    let config = default_config();
    assert_eq!(
        config.min_tier_for_surface.get(&PublicationSurface::Supremacy),
        Some(&PublicationTier::ShippedFact)
    );
    assert_eq!(
        config.min_tier_for_surface.get(&PublicationSurface::Ga),
        Some(&PublicationTier::ScopedObserved)
    );
    assert_eq!(
        config.min_tier_for_surface.get(&PublicationSurface::Rollout),
        Some(&PublicationTier::ScopedObserved)
    );
    assert_eq!(
        config.min_tier_for_surface.get(&PublicationSurface::React),
        Some(&PublicationTier::ShippedFact)
    );
    assert_eq!(
        config.min_tier_for_surface.get(&PublicationSurface::Docs),
        Some(&PublicationTier::FrontierAmbition)
    );
}

#[test]
fn enrichment_surface_routing_config_default_max_staleness() {
    let config = default_config();
    assert_eq!(
        config.max_staleness_hours.get(&PublicationSurface::Supremacy),
        Some(&72)
    );
    assert_eq!(
        config.max_staleness_hours.get(&PublicationSurface::Ga),
        Some(&MAX_PUBLISHABLE_STALENESS_HOURS)
    );
    assert_eq!(
        config.max_staleness_hours.get(&PublicationSurface::Docs),
        Some(&(MAX_PUBLISHABLE_STALENESS_HOURS * 2))
    );
}

#[test]
fn enrichment_surface_routing_config_serde_roundtrip() {
    let config = default_config();
    let json = serde_json::to_string(&config).expect("serialize");
    let back: SurfaceRoutingConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, back);
}

#[test]
fn enrichment_surface_routing_config_custom_config_serde_roundtrip() {
    let mut domain_to_surfaces = BTreeMap::new();
    domain_to_surfaces.insert(
        "custom".to_string(),
        vec![PublicationSurface::Docs, PublicationSurface::Ga],
    );
    let mut min_tier_for_surface = BTreeMap::new();
    min_tier_for_surface.insert(PublicationSurface::Docs, PublicationTier::FrontierAmbition);
    let mut max_staleness_hours = BTreeMap::new();
    max_staleness_hours.insert(PublicationSurface::Docs, 24);
    let config = SurfaceRoutingConfig {
        domain_to_surfaces,
        min_tier_for_surface,
        max_staleness_hours,
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let back: SurfaceRoutingConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, back);
}

// ---------------------------------------------------------------------------
// AnnotatedVerdict — construction + serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_annotated_verdict_construction() {
    let av = make_annotated(entitled_verdict("a1"), "compatibility", "shipped_fact");
    assert_eq!(av.domain, "compatibility");
    assert_eq!(av.tier, "shipped_fact");
    assert_eq!(av.staleness_hours, 0);
    assert_eq!(av.verdict.atom_id, "a1");
    assert_eq!(av.verdict.state, ClaimVerdictState::Entitled);
}

#[test]
fn enrichment_annotated_verdict_serde_roundtrip() {
    let av = make_annotated(entitled_verdict("a1"), "react", "scoped_observed");
    let json = serde_json::to_string(&av).expect("serialize");
    let back: AnnotatedVerdict = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(av, back);
}

#[test]
fn enrichment_annotated_verdict_with_staleness() {
    let av = make_stale_annotated(
        blocked_verdict("stale1"),
        "supremacy",
        "shipped_fact",
        200,
    );
    assert_eq!(av.staleness_hours, 200);
    assert_eq!(av.verdict.state, ClaimVerdictState::BlockedByMissingEvidence);
}

// ---------------------------------------------------------------------------
// PublicationGateError — Display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_display_empty_verdicts() {
    let e = PublicationGateError::EmptyVerdicts;
    let s = e.to_string();
    assert!(s.contains("no verdicts"));
}

#[test]
fn enrichment_error_display_unknown_domain() {
    let e = PublicationGateError::UnknownDomain {
        domain: "phantom".into(),
    };
    let s = e.to_string();
    assert!(s.contains("phantom"));
    assert!(s.contains("unknown domain"));
}

#[test]
fn enrichment_error_display_invalid_config() {
    let e = PublicationGateError::InvalidConfig {
        reason: "empty surfaces".into(),
    };
    let s = e.to_string();
    assert!(s.contains("empty surfaces"));
    assert!(s.contains("invalid"));
}

#[test]
fn enrichment_error_display_all_unique() {
    let errors = vec![
        PublicationGateError::EmptyVerdicts,
        PublicationGateError::UnknownDomain {
            domain: "test".into(),
        },
        PublicationGateError::InvalidConfig {
            reason: "bad".into(),
        },
    ];
    let mut displays = BTreeSet::new();
    for e in &errors {
        let s = e.to_string();
        assert!(displays.insert(s.clone()), "duplicate display: {s}");
    }
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_error_serde_roundtrip_all_variants() {
    let errors = vec![
        PublicationGateError::EmptyVerdicts,
        PublicationGateError::UnknownDomain {
            domain: "dom".into(),
        },
        PublicationGateError::InvalidConfig {
            reason: "reason".into(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).expect("serialize");
        let back: PublicationGateError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*e, back);
    }
}

// ---------------------------------------------------------------------------
// PublicationGateSummary — construction + serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_publication_gate_summary_serde_roundtrip() {
    let summary = PublicationGateSummary {
        total_verdicts: 10,
        approved_surfaces: 3,
        rejected_surfaces: 1,
        guidance_required_surfaces: 1,
        total_publishable_claims: 7,
        frontier_gap_count: 2,
        risk_flag_count: 4,
    };
    let json = serde_json::to_string(&summary).expect("serialize");
    let back: PublicationGateSummary = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(summary, back);
}

#[test]
fn enrichment_publication_gate_summary_zero_values() {
    let summary = PublicationGateSummary {
        total_verdicts: 0,
        approved_surfaces: 0,
        rejected_surfaces: 0,
        guidance_required_surfaces: 0,
        total_publishable_claims: 0,
        frontier_gap_count: 0,
        risk_flag_count: 0,
    };
    let json = serde_json::to_string(&summary).expect("serialize");
    let back: PublicationGateSummary = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(summary, back);
}

// ---------------------------------------------------------------------------
// PublicationGateEvaluation — Display + serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evaluation_display_contains_key_fields() {
    let verdicts = vec![make_annotated(
        entitled_verdict("c1"),
        "compatibility",
        "shipped_fact",
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 99).expect("evaluate");
    let display = eval.to_string();
    assert!(display.contains("publication_gate"));
    assert!(display.contains("epoch=99"));
}

#[test]
fn enrichment_evaluation_serde_roundtrip_simple() {
    let verdicts = vec![make_annotated(
        entitled_verdict("s1"),
        "compatibility",
        "shipped_fact",
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 10).expect("evaluate");
    let json = serde_json::to_string(&eval).expect("serialize");
    let back: PublicationGateEvaluation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(eval, back);
}

#[test]
fn enrichment_evaluation_schema_version_matches_constant() {
    let verdicts = vec![make_annotated(
        entitled_verdict("sv"),
        "docs",
        "shipped_fact",
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    assert_eq!(eval.schema_version, CLAIM_PUBLICATION_GATE_SCHEMA_VERSION);
}

#[test]
fn enrichment_evaluation_bead_id_matches_constant() {
    let verdicts = vec![make_annotated(
        entitled_verdict("bid"),
        "docs",
        "shipped_fact",
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    assert_eq!(eval.bead_id, CLAIM_PUBLICATION_GATE_BEAD_ID);
}

#[test]
fn enrichment_evaluation_epoch_propagated() {
    let verdicts = vec![make_annotated(
        entitled_verdict("ep"),
        "docs",
        "shipped_fact",
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 777).expect("evaluate");
    assert_eq!(eval.evaluated_epoch, 777);
}

// ---------------------------------------------------------------------------
// evaluate_publication_gate — empty verdicts error
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evaluate_empty_verdicts_returns_error() {
    let result = evaluate_publication_gate(&[], &[], &default_config(), 0);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err, PublicationGateError::EmptyVerdicts);
}

// ---------------------------------------------------------------------------
// route_verdict_to_surfaces
// ---------------------------------------------------------------------------

#[test]
fn enrichment_route_compatibility_to_three_surfaces() {
    let config = default_config();
    let av = make_annotated(entitled_verdict("c"), "compatibility", "shipped_fact");
    let surfaces = route_verdict_to_surfaces(&av, &config);
    assert!(surfaces.contains(&PublicationSurface::Docs));
    assert!(surfaces.contains(&PublicationSurface::Rollout));
    assert!(surfaces.contains(&PublicationSurface::Ga));
    assert!(!surfaces.contains(&PublicationSurface::React));
    assert!(!surfaces.contains(&PublicationSurface::Supremacy));
}

#[test]
fn enrichment_route_react_domain_to_docs_react_ga() {
    let config = default_config();
    let av = make_annotated(entitled_verdict("r"), "react", "shipped_fact");
    let surfaces = route_verdict_to_surfaces(&av, &config);
    assert!(surfaces.contains(&PublicationSurface::Docs));
    assert!(surfaces.contains(&PublicationSurface::React));
    assert!(surfaces.contains(&PublicationSurface::Ga));
}

#[test]
fn enrichment_route_supremacy_to_supremacy_and_docs() {
    let config = default_config();
    let av = make_annotated(entitled_verdict("s"), "supremacy", "shipped_fact");
    let surfaces = route_verdict_to_surfaces(&av, &config);
    assert!(surfaces.contains(&PublicationSurface::Supremacy));
    assert!(surfaces.contains(&PublicationSurface::Docs));
    assert_eq!(surfaces.len(), 2);
}

#[test]
fn enrichment_route_rollout_domain_only_rollout() {
    let config = default_config();
    let av = make_annotated(entitled_verdict("ro"), "rollout", "shipped_fact");
    let surfaces = route_verdict_to_surfaces(&av, &config);
    assert_eq!(surfaces, vec![PublicationSurface::Rollout]);
}

#[test]
fn enrichment_route_ga_domain_only_ga() {
    let config = default_config();
    let av = make_annotated(entitled_verdict("ga"), "ga", "shipped_fact");
    let surfaces = route_verdict_to_surfaces(&av, &config);
    assert_eq!(surfaces, vec![PublicationSurface::Ga]);
}

#[test]
fn enrichment_route_docs_domain_only_docs() {
    let config = default_config();
    let av = make_annotated(entitled_verdict("d"), "docs", "shipped_fact");
    let surfaces = route_verdict_to_surfaces(&av, &config);
    assert_eq!(surfaces, vec![PublicationSurface::Docs]);
}

#[test]
fn enrichment_route_security_domain_to_docs_rollout_ga() {
    let config = default_config();
    let av = make_annotated(entitled_verdict("sec"), "security", "shipped_fact");
    let surfaces = route_verdict_to_surfaces(&av, &config);
    assert!(surfaces.contains(&PublicationSurface::Docs));
    assert!(surfaces.contains(&PublicationSurface::Rollout));
    assert!(surfaces.contains(&PublicationSurface::Ga));
}

#[test]
fn enrichment_route_support_surface_to_docs_rollout() {
    let config = default_config();
    let av = make_annotated(entitled_verdict("ss"), "support_surface", "shipped_fact");
    let surfaces = route_verdict_to_surfaces(&av, &config);
    assert!(surfaces.contains(&PublicationSurface::Docs));
    assert!(surfaces.contains(&PublicationSurface::Rollout));
    assert_eq!(surfaces.len(), 2);
}

#[test]
fn enrichment_route_unknown_domain_empty() {
    let config = default_config();
    let av = make_annotated(entitled_verdict("x"), "nonexistent_domain", "shipped_fact");
    let surfaces = route_verdict_to_surfaces(&av, &config);
    assert!(surfaces.is_empty());
}

#[test]
fn enrichment_route_custom_config_single_domain() {
    let mut domain_to_surfaces = BTreeMap::new();
    domain_to_surfaces.insert(
        "custom_domain".to_string(),
        vec![PublicationSurface::React],
    );
    let config = SurfaceRoutingConfig {
        domain_to_surfaces,
        min_tier_for_surface: BTreeMap::new(),
        max_staleness_hours: BTreeMap::new(),
    };
    let av = make_annotated(entitled_verdict("cd"), "custom_domain", "shipped_fact");
    let surfaces = route_verdict_to_surfaces(&av, &config);
    assert_eq!(surfaces, vec![PublicationSurface::React]);
}

// ---------------------------------------------------------------------------
// Tier filtering — scoped/frontier excluded from strict surfaces
// ---------------------------------------------------------------------------

#[test]
fn enrichment_frontier_tier_only_reaches_docs() {
    let verdicts = vec![make_annotated(
        entitled_verdict("ft"),
        "compatibility",
        "frontier_ambition",
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    // Frontier ambition meets docs min (frontier_ambition), but not rollout/ga (scoped_observed)
    let docs_claims = eval.surface_claims.get("docs");
    assert!(docs_claims.is_some_and(|c| !c.is_empty()));
    let rollout_claims = eval.surface_claims.get("rollout");
    assert!(rollout_claims.is_none() || rollout_claims.unwrap().is_empty());
    let ga_claims = eval.surface_claims.get("ga");
    assert!(ga_claims.is_none() || ga_claims.unwrap().is_empty());
}

#[test]
fn enrichment_scoped_observed_excluded_from_supremacy_and_react() {
    let verdicts = vec![
        make_annotated(entitled_verdict("so1"), "supremacy", "scoped_observed"),
        make_annotated(entitled_verdict("so2"), "react", "scoped_observed"),
    ];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    let sup = eval.surface_claims.get("supremacy");
    assert!(sup.is_none() || sup.unwrap().is_empty());
    let react = eval.surface_claims.get("react");
    assert!(react.is_none() || react.unwrap().is_empty());
}

#[test]
fn enrichment_shipped_fact_reaches_all_routed_surfaces() {
    let verdicts = vec![make_annotated(
        entitled_verdict("sf"),
        "compatibility",
        "shipped_fact",
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    // compatibility routes to docs, rollout, ga
    let docs = eval.surface_claims.get("docs");
    assert!(docs.is_some_and(|c| !c.is_empty()));
    let rollout = eval.surface_claims.get("rollout");
    assert!(rollout.is_some_and(|c| !c.is_empty()));
    let ga = eval.surface_claims.get("ga");
    assert!(ga.is_some_and(|c| !c.is_empty()));
}

#[test]
fn enrichment_invalid_tier_string_skips_verdict() {
    let verdicts = vec![make_annotated(
        entitled_verdict("bad_tier"),
        "compatibility",
        "unknown_tier",
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    // No claims should be produced because tier_from_str returns None
    let total = eval.summary.total_publishable_claims;
    assert_eq!(total, 0);
}

// ---------------------------------------------------------------------------
// Staleness gating
// ---------------------------------------------------------------------------

#[test]
fn enrichment_fresh_evidence_passes_staleness_check() {
    let verdicts = vec![make_stale_annotated(
        entitled_verdict("fresh"),
        "supremacy",
        "shipped_fact",
        0,
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    let sup_claims = eval.surface_claims.get("supremacy");
    assert!(sup_claims.is_some_and(|c| !c.is_empty()));
}

#[test]
fn enrichment_stale_supremacy_generates_warning_and_excluded() {
    let verdicts = vec![make_stale_annotated(
        entitled_verdict("stale"),
        "supremacy",
        "shipped_fact",
        100, // exceeds 72h supremacy limit
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    // Stale claim should not appear in supremacy claims
    let sup_claims = eval.surface_claims.get("supremacy");
    assert!(sup_claims.is_none() || sup_claims.unwrap().is_empty());
    // Risk flag should be generated
    let stale_flags: Vec<_> = eval
        .risk_flags
        .iter()
        .filter(|f| f.description.contains("staleness"))
        .collect();
    assert!(!stale_flags.is_empty());
}

#[test]
fn enrichment_staleness_at_exact_limit_passes() {
    // Supremacy max is 72h; at exactly 72h it should pass (not strictly greater)
    let verdicts = vec![make_stale_annotated(
        entitled_verdict("exact"),
        "supremacy",
        "shipped_fact",
        72,
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    let sup_claims = eval.surface_claims.get("supremacy");
    assert!(sup_claims.is_some_and(|c| !c.is_empty()));
}

#[test]
fn enrichment_staleness_one_over_limit_rejected() {
    let verdicts = vec![make_stale_annotated(
        entitled_verdict("over"),
        "supremacy",
        "shipped_fact",
        73,
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    let sup_claims = eval.surface_claims.get("supremacy");
    assert!(sup_claims.is_none() || sup_claims.unwrap().is_empty());
}

#[test]
fn enrichment_docs_staleness_limit_is_double_max() {
    // Docs max is MAX_PUBLISHABLE_STALENESS_HOURS * 2 = 336
    let verdicts = vec![make_stale_annotated(
        entitled_verdict("docs_stale"),
        "docs",
        "shipped_fact",
        336,
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    let docs_claims = eval.surface_claims.get("docs");
    assert!(docs_claims.is_some_and(|c| !c.is_empty()));
}

#[test]
fn enrichment_docs_over_double_max_excluded() {
    let verdicts = vec![make_stale_annotated(
        entitled_verdict("docs_very_stale"),
        "docs",
        "shipped_fact",
        337,
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    let docs_claims = eval.surface_claims.get("docs");
    assert!(docs_claims.is_none() || docs_claims.unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Verdict state handling — risk flag severity mapping
// ---------------------------------------------------------------------------

#[test]
fn enrichment_blocked_verdict_generates_warning_flag() {
    let verdicts = vec![make_annotated(
        blocked_verdict("blk"),
        "compatibility",
        "shipped_fact",
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    let warn_flags: Vec<_> = eval
        .risk_flags
        .iter()
        .filter(|f| f.severity == RiskSeverity::Warning)
        .collect();
    assert!(!warn_flags.is_empty());
}

#[test]
fn enrichment_not_yet_proven_verdict_generates_info_flag() {
    let verdicts = vec![make_annotated(
        not_yet_proven_verdict("nyp"),
        "compatibility",
        "shipped_fact",
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    let info_flags: Vec<_> = eval
        .risk_flags
        .iter()
        .filter(|f| f.severity == RiskSeverity::Info)
        .collect();
    assert!(!info_flags.is_empty());
}

#[test]
fn enrichment_counterexample_verdict_generates_critical_flag() {
    let verdicts = vec![make_annotated(
        counterexample_verdict("cex"),
        "supremacy",
        "shipped_fact",
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    let crit_flags: Vec<_> = eval
        .risk_flags
        .iter()
        .filter(|f| f.severity == RiskSeverity::Critical)
        .collect();
    assert!(!crit_flags.is_empty());
}

// ---------------------------------------------------------------------------
// Gate decision logic
// ---------------------------------------------------------------------------

#[test]
fn enrichment_all_entitled_single_domain_approved() {
    let verdicts = vec![make_annotated(
        entitled_verdict("ok1"),
        "docs",
        "shipped_fact",
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    let docs = eval.gate_decisions.get("docs").expect("docs");
    assert_eq!(*docs, GateDecision::Approved);
}

#[test]
fn enrichment_critical_flag_causes_rejection_even_with_claims() {
    // counterexample in supremacy generates critical flag -> rejected
    let verdicts = vec![
        make_annotated(entitled_verdict("ok"), "supremacy", "shipped_fact"),
        make_annotated(counterexample_verdict("cex"), "supremacy", "shipped_fact"),
    ];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    let sup = eval.gate_decisions.get("supremacy").expect("supremacy");
    assert!(matches!(sup, GateDecision::Rejected { .. }));
}

#[test]
fn enrichment_gap_blocking_surface_requires_guidance() {
    let verdicts = vec![make_annotated(
        entitled_verdict("ok"),
        "compatibility",
        "shipped_fact",
    )];
    let gaps = vec![make_gap("g1", "compatibility", vec![PublicationSurface::Ga])];
    let eval =
        evaluate_publication_gate(&verdicts, &gaps, &default_config(), 1).expect("evaluate");
    let ga = eval.gate_decisions.get("ga").expect("ga");
    assert!(matches!(ga, GateDecision::RequireOperatorGuidance { .. }));
}

#[test]
fn enrichment_no_claims_for_surface_rejected() {
    // Only docs-domain verdicts -> only docs surface gets claims
    let verdicts = vec![make_annotated(
        entitled_verdict("d1"),
        "docs",
        "shipped_fact",
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    let supremacy = eval.gate_decisions.get("supremacy").expect("supremacy");
    assert!(matches!(supremacy, GateDecision::Rejected { .. }));
}

#[test]
fn enrichment_mixed_entitled_and_blocked_shows_caveats_on_routed_surface() {
    let verdicts = vec![
        make_annotated(entitled_verdict("ok"), "compatibility", "shipped_fact"),
        make_annotated(blocked_verdict("blk"), "compatibility", "shipped_fact"),
    ];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    // Docs gets both entitled claims and warning flags -> ApprovedWithCaveats
    let docs = eval.gate_decisions.get("docs").expect("docs");
    assert!(matches!(docs, GateDecision::ApprovedWithCaveats { .. }));
}

#[test]
fn enrichment_all_surfaces_present_in_gate_decisions() {
    let verdicts = vec![make_annotated(
        entitled_verdict("x"),
        "compatibility",
        "shipped_fact",
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    for surface in &ALL_SURFACES {
        assert!(
            eval.gate_decisions.contains_key(&surface.to_string()),
            "missing gate decision for {surface}"
        );
    }
}

// ---------------------------------------------------------------------------
// Frontier gap interactions
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gap_with_no_blocking_surfaces_no_guidance() {
    let verdicts = vec![make_annotated(
        entitled_verdict("ok"),
        "docs",
        "shipped_fact",
    )];
    let gaps = vec![FrontierGapDisclosure {
        gap_id: "info-gap".into(),
        description: "informational".into(),
        domain: "docs".into(),
        blocks_surfaces: Vec::new(),
        remediation: "none".into(),
    }];
    let eval =
        evaluate_publication_gate(&verdicts, &gaps, &default_config(), 1).expect("evaluate");
    let docs = eval.gate_decisions.get("docs").expect("docs");
    // No blocking surfaces, so docs should be approved (gap is informational)
    assert_eq!(*docs, GateDecision::Approved);
    assert_eq!(eval.summary.frontier_gap_count, 1);
}

#[test]
fn enrichment_multiple_gaps_blocking_same_surface() {
    let verdicts = vec![make_annotated(
        entitled_verdict("ok"),
        "compatibility",
        "shipped_fact",
    )];
    let gaps = vec![
        make_gap("g1", "compat", vec![PublicationSurface::Rollout]),
        make_gap("g2", "compat", vec![PublicationSurface::Rollout]),
    ];
    let eval =
        evaluate_publication_gate(&verdicts, &gaps, &default_config(), 1).expect("evaluate");
    let rollout = eval.gate_decisions.get("rollout").expect("rollout");
    assert!(matches!(
        rollout,
        GateDecision::RequireOperatorGuidance { .. }
    ));
    assert_eq!(eval.summary.frontier_gap_count, 2);
}

#[test]
fn enrichment_gap_generates_warning_risk_flags_for_each_blocked_surface() {
    let verdicts = vec![make_annotated(
        entitled_verdict("ok"),
        "compatibility",
        "shipped_fact",
    )];
    let gaps = vec![make_gap(
        "multi-block",
        "compat",
        vec![PublicationSurface::Ga, PublicationSurface::Rollout],
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &gaps, &default_config(), 1).expect("evaluate");
    let gap_flags: Vec<_> = eval
        .risk_flags
        .iter()
        .filter(|f| f.flag_id.starts_with("gap-"))
        .collect();
    assert_eq!(gap_flags.len(), 2);
    for f in &gap_flags {
        assert_eq!(f.severity, RiskSeverity::Warning);
    }
}

// ---------------------------------------------------------------------------
// Summary counts validation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_summary_total_verdicts_matches_input() {
    let verdicts = vec![
        make_annotated(entitled_verdict("c1"), "compatibility", "shipped_fact"),
        make_annotated(entitled_verdict("c2"), "react", "shipped_fact"),
        make_annotated(blocked_verdict("c3"), "supremacy", "shipped_fact"),
    ];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    assert_eq!(eval.summary.total_verdicts, 3);
}

#[test]
fn enrichment_summary_approved_plus_rejected_plus_guidance_equals_five() {
    let verdicts = vec![make_annotated(
        entitled_verdict("c1"),
        "compatibility",
        "shipped_fact",
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    let total = eval.summary.approved_surfaces
        + eval.summary.rejected_surfaces
        + eval.summary.guidance_required_surfaces;
    assert_eq!(total, ALL_SURFACES.len());
}

#[test]
fn enrichment_summary_frontier_gap_count_matches() {
    let verdicts = vec![make_annotated(
        entitled_verdict("c1"),
        "compatibility",
        "shipped_fact",
    )];
    let gaps = vec![
        make_gap("g1", "compat", vec![PublicationSurface::Ga]),
        make_gap("g2", "compat", vec![PublicationSurface::Rollout]),
        make_gap("g3", "compat", vec![PublicationSurface::Supremacy]),
    ];
    let eval =
        evaluate_publication_gate(&verdicts, &gaps, &default_config(), 1).expect("evaluate");
    assert_eq!(eval.summary.frontier_gap_count, 3);
}

#[test]
fn enrichment_summary_risk_flag_count_nonzero_when_flags_present() {
    let verdicts = vec![make_annotated(
        blocked_verdict("b1"),
        "compatibility",
        "shipped_fact",
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    assert!(eval.summary.risk_flag_count > 0);
    assert_eq!(eval.summary.risk_flag_count, eval.risk_flags.len());
}

// ---------------------------------------------------------------------------
// render_publication_gate_summary
// ---------------------------------------------------------------------------

#[test]
fn enrichment_render_summary_contains_epoch() {
    let verdicts = vec![make_annotated(
        entitled_verdict("c1"),
        "compatibility",
        "shipped_fact",
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 42).expect("evaluate");
    let summary = render_publication_gate_summary(&eval);
    assert!(summary.contains("evaluated_epoch: 42"));
}

#[test]
fn enrichment_render_summary_contains_all_key_lines() {
    let verdicts = vec![
        make_annotated(entitled_verdict("c1"), "compatibility", "shipped_fact"),
        make_annotated(entitled_verdict("r1"), "react", "shipped_fact"),
    ];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 10).expect("evaluate");
    let summary = render_publication_gate_summary(&eval);
    assert!(summary.contains("schema_version:"));
    assert!(summary.contains("total_verdicts: 2"));
    assert!(summary.contains("approved_surfaces:"));
    assert!(summary.contains("rejected_surfaces:"));
    assert!(summary.contains("guidance_required:"));
    assert!(summary.contains("publishable_claims:"));
    assert!(summary.contains("frontier_gaps:"));
    assert!(summary.contains("risk_flags:"));
    assert!(summary.contains("Per-surface decisions"));
}

#[test]
fn enrichment_render_summary_per_surface_decisions_listed() {
    let verdicts = vec![make_annotated(
        entitled_verdict("d1"),
        "docs",
        "shipped_fact",
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    let summary = render_publication_gate_summary(&eval);
    // Each surface should appear in the per-surface section
    assert!(summary.contains("docs:"));
}

// ---------------------------------------------------------------------------
// Full lifecycle / multi-domain / multi-verdict scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrichment_multi_domain_all_entitled_mixed_surfaces() {
    let verdicts = vec![
        make_annotated(entitled_verdict("c1"), "compatibility", "shipped_fact"),
        make_annotated(entitled_verdict("r1"), "react", "shipped_fact"),
        make_annotated(entitled_verdict("s1"), "supremacy", "shipped_fact"),
        make_annotated(entitled_verdict("d1"), "docs", "shipped_fact"),
    ];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    // All surfaces should be approved
    for (surface_key, decision) in &eval.gate_decisions {
        assert!(
            matches!(decision, GateDecision::Approved),
            "expected Approved for {surface_key}, got {decision}"
        );
    }
}

#[test]
fn enrichment_single_verdict_unknown_domain_gets_no_surface_claims() {
    let verdicts = vec![make_annotated(
        entitled_verdict("unk"),
        "nonexistent",
        "shipped_fact",
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    // No claims produced for any surface
    assert_eq!(eval.summary.total_publishable_claims, 0);
    // All surfaces rejected for no claims
    for decision in eval.gate_decisions.values() {
        assert!(matches!(decision, GateDecision::Rejected { .. }));
    }
}

#[test]
fn enrichment_counterexample_overrides_entitled_on_same_surface() {
    let verdicts = vec![
        make_annotated(entitled_verdict("ok"), "supremacy", "shipped_fact"),
        make_annotated(counterexample_verdict("bad"), "supremacy", "shipped_fact"),
    ];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    // Critical flag from counterexample should cause rejection even though entitled claim exists
    let sup = eval.gate_decisions.get("supremacy").expect("supremacy");
    assert!(matches!(sup, GateDecision::Rejected { .. }));
}

#[test]
fn enrichment_gap_priority_over_warning_flags() {
    // Gap blocking should cause RequireOperatorGuidance, not just ApprovedWithCaveats
    let verdicts = vec![
        make_annotated(entitled_verdict("ok"), "compatibility", "shipped_fact"),
        make_annotated(blocked_verdict("blk"), "compatibility", "shipped_fact"),
    ];
    let gaps = vec![make_gap("g1", "compat", vec![PublicationSurface::Docs])];
    let eval =
        evaluate_publication_gate(&verdicts, &gaps, &default_config(), 1).expect("evaluate");
    let docs = eval.gate_decisions.get("docs").expect("docs");
    // Gap blocks docs -> RequireOperatorGuidance (gap takes priority over just warnings)
    assert!(matches!(
        docs,
        GateDecision::RequireOperatorGuidance { .. }
    ));
}

#[test]
fn enrichment_critical_takes_priority_over_gap() {
    // Critical flag should override gap -> Rejected, not RequireOperatorGuidance
    let verdicts = vec![make_annotated(
        counterexample_verdict("cex"),
        "compatibility",
        "shipped_fact",
    )];
    let gaps = vec![make_gap("g1", "compat", vec![PublicationSurface::Docs])];
    let eval =
        evaluate_publication_gate(&verdicts, &gaps, &default_config(), 1).expect("evaluate");
    let docs = eval.gate_decisions.get("docs").expect("docs");
    assert!(matches!(docs, GateDecision::Rejected { .. }));
}

#[test]
fn enrichment_publishable_claim_preserves_morphisms_and_certs() {
    let mut verdict = entitled_verdict("morph_test");
    verdict.supporting_morphism_ids = vec!["m1".into(), "m2".into(), "m3".into()];
    verdict.impossibility_certificate_ids = vec!["cert-x".into()];
    let verdicts = vec![make_annotated(verdict, "docs", "shipped_fact")];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    let docs_claims = eval.surface_claims.get("docs").expect("docs claims");
    assert_eq!(docs_claims.len(), 1);
    assert_eq!(docs_claims[0].supporting_morphisms.len(), 3);
    assert_eq!(docs_claims[0].impossibility_certificates.len(), 1);
}

#[test]
fn enrichment_evaluation_deterministic_across_calls() {
    let verdicts = vec![
        make_annotated(entitled_verdict("c1"), "compatibility", "shipped_fact"),
        make_annotated(entitled_verdict("r1"), "react", "shipped_fact"),
        make_annotated(blocked_verdict("b1"), "supremacy", "shipped_fact"),
    ];
    let gaps = vec![make_gap("g1", "compat", vec![PublicationSurface::Ga])];
    let eval1 =
        evaluate_publication_gate(&verdicts, &gaps, &default_config(), 1).expect("eval1");
    let eval2 =
        evaluate_publication_gate(&verdicts, &gaps, &default_config(), 1).expect("eval2");
    assert_eq!(eval1, eval2);
}

#[test]
fn enrichment_large_number_of_verdicts() {
    let verdicts: Vec<AnnotatedVerdict> = (0..50)
        .map(|i| {
            make_annotated(
                entitled_verdict(&format!("v{i}")),
                "compatibility",
                "shipped_fact",
            )
        })
        .collect();
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    assert_eq!(eval.summary.total_verdicts, 50);
    // Each verdict routes to docs/rollout/ga => 150 total claims
    assert_eq!(eval.summary.total_publishable_claims, 150);
}

#[test]
fn enrichment_serde_roundtrip_full_evaluation_with_gaps_and_flags() {
    let verdicts = vec![
        make_annotated(entitled_verdict("c1"), "compatibility", "shipped_fact"),
        make_annotated(blocked_verdict("b1"), "react", "shipped_fact"),
        make_annotated(counterexample_verdict("x1"), "supremacy", "shipped_fact"),
    ];
    let gaps = vec![make_gap("g1", "compat", vec![PublicationSurface::Ga])];
    let eval =
        evaluate_publication_gate(&verdicts, &gaps, &default_config(), 99).expect("evaluate");
    let json = serde_json::to_string(&eval).expect("serialize");
    let back: PublicationGateEvaluation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(eval, back);
}

#[test]
fn enrichment_shipped_surface_domain_routes_same_as_compatibility() {
    let config = default_config();
    let av = make_annotated(entitled_verdict("ss"), "shipped_surface", "shipped_fact");
    let surfaces = route_verdict_to_surfaces(&av, &config);
    assert!(surfaces.contains(&PublicationSurface::Docs));
    assert!(surfaces.contains(&PublicationSurface::Rollout));
    assert!(surfaces.contains(&PublicationSurface::Ga));
    assert_eq!(surfaces.len(), 3);
}

#[test]
fn enrichment_empty_config_all_surfaces_rejected() {
    let config = SurfaceRoutingConfig {
        domain_to_surfaces: BTreeMap::new(),
        min_tier_for_surface: BTreeMap::new(),
        max_staleness_hours: BTreeMap::new(),
    };
    let verdicts = vec![make_annotated(
        entitled_verdict("c1"),
        "compatibility",
        "shipped_fact",
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &config, 1).expect("evaluate");
    // No domain routing -> no claims -> all rejected
    for decision in eval.gate_decisions.values() {
        assert!(matches!(decision, GateDecision::Rejected { .. }));
    }
}

#[test]
fn enrichment_claim_domain_and_statement_preserved() {
    let verdicts = vec![AnnotatedVerdict {
        verdict: entitled_verdict("preserve"),
        domain: "react".into(),
        tier: "shipped_fact".into(),
        statement: "React hooks compile correctly".into(),
        staleness_hours: 0,
    }];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    let react_claims = eval.surface_claims.get("react").expect("react claims");
    assert_eq!(react_claims.len(), 1);
    assert_eq!(react_claims[0].domain, "react");
    assert_eq!(react_claims[0].statement, "React hooks compile correctly");
}

#[test]
fn enrichment_scoped_observed_allowed_on_rollout_and_ga() {
    let verdicts = vec![make_annotated(
        entitled_verdict("so"),
        "compatibility",
        "scoped_observed",
    )];
    let eval =
        evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
    let rollout_claims = eval.surface_claims.get("rollout");
    assert!(rollout_claims.is_some_and(|c| !c.is_empty()));
    let ga_claims = eval.surface_claims.get("ga");
    assert!(ga_claims.is_some_and(|c| !c.is_empty()));
}

#[test]
fn enrichment_evaluation_frontier_gaps_preserved_in_output() {
    let verdicts = vec![make_annotated(
        entitled_verdict("c1"),
        "compatibility",
        "shipped_fact",
    )];
    let gaps = vec![
        make_gap("g1", "dom1", vec![PublicationSurface::Docs]),
        make_gap("g2", "dom2", vec![PublicationSurface::Ga]),
    ];
    let eval =
        evaluate_publication_gate(&verdicts, &gaps, &default_config(), 1).expect("evaluate");
    assert_eq!(eval.frontier_gaps.len(), 2);
    assert_eq!(eval.frontier_gaps[0].gap_id, "g1");
    assert_eq!(eval.frontier_gaps[1].gap_id, "g2");
}

#[test]
fn enrichment_risk_flag_ids_unique() {
    let verdicts = vec![
        make_annotated(blocked_verdict("b1"), "compatibility", "shipped_fact"),
        make_annotated(blocked_verdict("b2"), "compatibility", "shipped_fact"),
        make_annotated(not_yet_proven_verdict("n1"), "react", "shipped_fact"),
    ];
    let gaps = vec![make_gap("g1", "compat", vec![PublicationSurface::Ga])];
    let eval =
        evaluate_publication_gate(&verdicts, &gaps, &default_config(), 1).expect("evaluate");
    let mut flag_ids = BTreeSet::new();
    for f in &eval.risk_flags {
        assert!(
            flag_ids.insert(f.flag_id.clone()),
            "duplicate flag_id: {}",
            f.flag_id
        );
    }
}
