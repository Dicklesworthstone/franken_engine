#![forbid(unsafe_code)]

//! Enrichment integration tests for milestone_release_test_evidence_integrator.

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

use frankenengine_engine::cut_line_automation::CutLine;
use frankenengine_engine::milestone_release_test_evidence_integrator::*;
use frankenengine_engine::release_checklist_gate::{
    ChecklistCategory, ChecklistItem, ChecklistItemStatus, ReleaseChecklist,
};

// ── Helpers ──────────────────────────────────────────────────────────────

fn signed_artifact(prefix: &str, now_ns: u64) -> EvidenceArtifactLink {
    EvidenceArtifactLink {
        artifact_id: format!("{prefix}-artifact"),
        path: format!("artifacts/{prefix}/run_manifest.json"),
        sha256: format!("{prefix}abcdef1234567890"),
        signature_status: SignatureStatus::Signed,
        signer: Some("maintainer@franken.engine".to_string()),
        signature_ref: Some(format!("sig:{prefix}")),
        generated_at_ns: now_ns.saturating_sub(100),
        schema_major: 1,
    }
}

fn baseline_signal(source: EvidenceSource, score: i64, now_ns: u64) -> EvidenceSignal {
    let mut metadata = BTreeMap::new();
    if source == EvidenceSource::FlakeQuarantineWorkflow {
        metadata.insert("flake_burden_millionths".to_string(), "90000".to_string());
    }
    EvidenceSignal {
        source,
        passed: true,
        score_millionths: score,
        collected_at_ns: now_ns.saturating_sub(100),
        schema_major: 1,
        evidence_refs: vec![format!("docs/{}.json", source.as_str())],
        artifact_links: vec![signed_artifact(source.as_str(), now_ns)],
        metadata,
    }
}

fn baseline_input(now_ns: u64) -> TestEvidenceIntegratorInput {
    TestEvidenceIntegratorInput {
        cut_line: CutLine::C4,
        release_tag: "v0.9.0-rc1".to_string(),
        now_ns,
        trace_id: "trace-enrich".to_string(),
        decision_id: "decision-enrich".to_string(),
        policy_id: "policy-enrich-v1".to_string(),
        signals: EvidenceSource::REQUIRED
            .iter()
            .map(|source| baseline_signal(*source, 980_000, now_ns))
            .collect(),
        previous_summary: None,
    }
}

fn empty_checklist() -> ReleaseChecklist {
    ReleaseChecklist {
        schema_version: "franken-engine.release-checklist.v1".to_string(),
        release_tag: "v0.9.0-rc1".to_string(),
        generated_at_utc: "2026-03-13T00:00:00Z".to_string(),
        trace_id: "trace-enrich".to_string(),
        decision_id: "decision-enrich".to_string(),
        policy_id: "policy-enrich-v1".to_string(),
        items: Vec::new(),
    }
}

// ===========================================================================
// 1. EvidenceSource — Ord, BTreeSet ordering, Copy
// ===========================================================================

#[test]
fn enrichment_evidence_source_ord_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for source in EvidenceSource::REQUIRED {
        assert!(
            set.insert(source),
            "duplicate in REQUIRED: {}",
            source.as_str()
        );
    }
    // Insert again — all should fail
    for source in EvidenceSource::REQUIRED {
        assert!(!set.insert(source));
    }
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_evidence_source_ord_deterministic_order() {
    let sorted: Vec<EvidenceSource> = {
        let mut v: Vec<EvidenceSource> = EvidenceSource::REQUIRED.to_vec();
        v.sort();
        v
    };
    let sorted2: Vec<EvidenceSource> = {
        let mut v: Vec<EvidenceSource> = EvidenceSource::REQUIRED.to_vec();
        v.sort();
        v
    };
    assert_eq!(sorted, sorted2);
}

#[test]
fn enrichment_evidence_source_copy_does_not_move() {
    let a = EvidenceSource::UnitDepthGate;
    let b = a;
    let c = a; // a still usable after copy
    assert_eq!(b, c);
    assert_eq!(a.as_str(), "unit_depth_gate");
}

// ===========================================================================
// 2. SignatureStatus — Ord implied by PartialOrd derive absence
// ===========================================================================

#[test]
fn enrichment_signature_status_copy_all() {
    for status in [
        SignatureStatus::Signed,
        SignatureStatus::Unsigned,
        SignatureStatus::Invalid,
    ] {
        let copied = status;
        let again = copied;
        assert_eq!(status, again);
    }
}

#[test]
fn enrichment_signature_status_debug_contains_variant_name() {
    assert!(format!("{:?}", SignatureStatus::Signed).contains("Signed"));
    assert!(format!("{:?}", SignatureStatus::Unsigned).contains("Unsigned"));
    assert!(format!("{:?}", SignatureStatus::Invalid).contains("Invalid"));
}

// ===========================================================================
// 3. EvidenceArtifactLink — Clone independence, Debug, serde
// ===========================================================================

#[test]
fn enrichment_evidence_artifact_link_clone_independence() {
    let original = signed_artifact("clone-test", 50_000);
    let mut cloned = original.clone();
    cloned.artifact_id = "mutated".to_string();
    cloned.sha256 = "deadbeef".to_string();
    cloned.signer = Some("hacker".to_string());
    assert_eq!(original.artifact_id, "clone-test-artifact");
    assert_ne!(original.artifact_id, cloned.artifact_id);
    assert_ne!(original.sha256, cloned.sha256);
    assert_ne!(original.signer, cloned.signer);
}

#[test]
fn enrichment_evidence_artifact_link_debug_contains_fields() {
    let link = signed_artifact("dbg", 10_000);
    let dbg = format!("{link:?}");
    assert!(dbg.contains("dbg-artifact"));
    assert!(dbg.contains("Signed"));
}

// ===========================================================================
// 4. EvidenceSignal — Clone independence, metadata isolation
// ===========================================================================

#[test]
fn enrichment_evidence_signal_clone_independence_metadata() {
    let original = baseline_signal(EvidenceSource::FlakeQuarantineWorkflow, 980_000, 50_000);
    let mut cloned = original.clone();
    cloned
        .metadata
        .insert("injected".to_string(), "evil".to_string());
    cloned.evidence_refs.push("extra".to_string());
    assert!(!original.metadata.contains_key("injected"));
    assert_eq!(original.evidence_refs.len(), 1);
    assert_eq!(cloned.evidence_refs.len(), 2);
}

#[test]
fn enrichment_evidence_signal_clone_artifact_links_independent() {
    let original = baseline_signal(EvidenceSource::UnitDepthGate, 980_000, 50_000);
    let mut cloned = original.clone();
    cloned.artifact_links[0].signature_status = SignatureStatus::Invalid;
    assert_eq!(
        original.artifact_links[0].signature_status,
        SignatureStatus::Signed
    );
}

// ===========================================================================
// 5. IntegratorPolicy — Clone, Default invariants
// ===========================================================================

#[test]
fn enrichment_integrator_policy_clone_threshold_independence() {
    let original = IntegratorPolicy::default();
    let mut cloned = original.clone();
    cloned
        .minimum_cut_line_scores_millionths
        .insert("C99".to_string(), 999_999);
    cloned.max_signal_age_ns = 1;
    assert!(
        !original
            .minimum_cut_line_scores_millionths
            .contains_key("C99")
    );
    assert_eq!(original.max_signal_age_ns, 3_600_000_000_000);
}

#[test]
fn enrichment_integrator_policy_default_thresholds_monotonically_increasing() {
    let policy = IntegratorPolicy::default();
    let mut prev = 0i64;
    for key in ["C0", "C1", "C2", "C3", "C4", "C5"] {
        let threshold = *policy.minimum_cut_line_scores_millionths.get(key).unwrap();
        assert!(
            threshold >= prev,
            "{key} threshold {threshold} < previous {prev}"
        );
        prev = threshold;
    }
}

#[test]
fn enrichment_integrator_policy_default_all_thresholds_in_valid_range() {
    let policy = IntegratorPolicy::default();
    for (key, &threshold) in &policy.minimum_cut_line_scores_millionths {
        assert!(threshold >= 0, "{key} threshold negative");
        assert!(threshold <= 1_000_000, "{key} threshold above 1M");
    }
}

// ===========================================================================
// 6. IntegrationFinding — Clone independence
// ===========================================================================

#[test]
fn enrichment_integration_finding_clone_independence() {
    let original = IntegrationFinding {
        source: Some(EvidenceSource::UnitDepthGate),
        error_code: "ERR-001".to_string(),
        message: "original msg".to_string(),
    };
    let mut cloned = original.clone();
    cloned.message = "mutated".to_string();
    cloned.source = None;
    assert_eq!(original.message, "original msg");
    assert_eq!(original.source, Some(EvidenceSource::UnitDepthGate));
}

// ===========================================================================
// 7. SignedEvidenceLink — Clone independence, Debug
// ===========================================================================

#[test]
fn enrichment_signed_evidence_link_clone_independence() {
    let original = SignedEvidenceLink {
        evidence_source: EvidenceSource::UnitDepthGate,
        gate_category: "compiler_correctness".to_string(),
        artifact_id: "art-001".to_string(),
        artifact_sha256: "abc123".to_string(),
        signer: "admin@test".to_string(),
        signature_ref: "sig:001".to_string(),
    };
    let mut cloned = original.clone();
    cloned.signer = "attacker@evil".to_string();
    assert_eq!(original.signer, "admin@test");
}

// ===========================================================================
// 8. MilestoneQualitySummary — Clone, serde field stability
// ===========================================================================

#[test]
fn enrichment_milestone_quality_summary_clone_delta_independence() {
    let mut deltas = BTreeMap::new();
    deltas.insert("aggregate".to_string(), 50_000i64);
    let original = MilestoneQualitySummary {
        cut_line: CutLine::C3,
        aggregate_score_millionths: 950_000,
        unit_depth_score_millionths: 980_000,
        e2e_stability_score_millionths: 970_000,
        logging_integrity_score_millionths: 960_000,
        flake_resilience_score_millionths: 940_000,
        artifact_integrity_score_millionths: 930_000,
        delta_from_previous_millionths: deltas,
    };
    let mut cloned = original.clone();
    cloned
        .delta_from_previous_millionths
        .insert("new_key".to_string(), 99);
    cloned.aggregate_score_millionths = 0;
    assert!(
        !original
            .delta_from_previous_millionths
            .contains_key("new_key")
    );
    assert_eq!(original.aggregate_score_millionths, 950_000);
}

// ===========================================================================
// 9. TestEvidenceIntegrationDecision — serde roundtrip, Clone
// ===========================================================================

#[test]
fn enrichment_decision_clone_blockers_independence() {
    let input = baseline_input(50_000);
    let mut input_deny = input.clone();
    input_deny
        .signals
        .retain(|s| s.source != EvidenceSource::UnitDepthGate);
    let decision =
        integrate_milestone_release_test_evidence(&input_deny, &IntegratorPolicy::default());
    let mut cloned = decision.clone();
    cloned.blockers.clear();
    assert!(!decision.blockers.is_empty());
    assert!(cloned.blockers.is_empty());
}

#[test]
fn enrichment_decision_clone_signed_links_independence() {
    let input = baseline_input(50_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let mut cloned = decision.clone();
    let orig_len = decision.signed_evidence_links.len();
    cloned.signed_evidence_links.clear();
    assert_eq!(decision.signed_evidence_links.len(), orig_len);
    assert!(cloned.signed_evidence_links.is_empty());
}

// ===========================================================================
// 10. TestEvidenceIntegratorEvent — Clone, Debug
// ===========================================================================

#[test]
fn enrichment_event_clone_independence() {
    let input = baseline_input(50_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let events = emit_integration_events(&decision);
    let mut cloned = events[0].clone();
    cloned.outcome = "mutated".to_string();
    assert_eq!(events[0].outcome, "allow");
    assert_eq!(cloned.outcome, "mutated");
}

// ===========================================================================
// 11. TestEvidenceIntegratorInput — Clone, serde
// ===========================================================================

#[test]
fn enrichment_input_clone_signals_independence() {
    let original = baseline_input(50_000);
    let mut cloned = original.clone();
    cloned.signals.clear();
    assert_eq!(original.signals.len(), 5);
    assert!(cloned.signals.is_empty());
}

#[test]
fn enrichment_input_clone_previous_summary_independence() {
    let mut original = baseline_input(50_000);
    original.previous_summary = Some(MilestoneQualitySummary {
        cut_line: CutLine::C2,
        aggregate_score_millionths: 900_000,
        unit_depth_score_millionths: 900_000,
        e2e_stability_score_millionths: 900_000,
        logging_integrity_score_millionths: 900_000,
        flake_resilience_score_millionths: 900_000,
        artifact_integrity_score_millionths: 900_000,
        delta_from_previous_millionths: BTreeMap::new(),
    });
    let mut cloned = original.clone();
    cloned.previous_summary = None;
    assert!(original.previous_summary.is_some());
    assert!(cloned.previous_summary.is_none());
}

// ===========================================================================
// 12. Determinism — 5-run integration proof
// ===========================================================================

#[test]
fn enrichment_integration_determinism_five_runs() {
    let input = baseline_input(50_000);
    let policy = IntegratorPolicy::default();
    let baseline = integrate_milestone_release_test_evidence(&input, &policy);
    let baseline_json = serde_json::to_string(&baseline).unwrap();
    for run in 1..=5 {
        let decision = integrate_milestone_release_test_evidence(&input, &policy);
        let json = serde_json::to_string(&decision).unwrap();
        assert_eq!(baseline_json, json, "run {run} diverged");
    }
}

#[test]
fn enrichment_gate_inputs_determinism_five_runs() {
    let input = baseline_input(50_000);
    let policy = IntegratorPolicy::default();
    let decision = integrate_milestone_release_test_evidence(&input, &policy);
    let baseline = to_cut_line_gate_inputs(&decision, &input.signals);
    let baseline_json = serde_json::to_string(&baseline).unwrap();
    for run in 1..=5 {
        let gate_inputs = to_cut_line_gate_inputs(&decision, &input.signals);
        let json = serde_json::to_string(&gate_inputs).unwrap();
        assert_eq!(baseline_json, json, "gate inputs run {run} diverged");
    }
}

#[test]
fn enrichment_emit_events_determinism_five_runs() {
    let input = baseline_input(50_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let baseline = emit_integration_events(&decision);
    let baseline_json = serde_json::to_string(&baseline).unwrap();
    for run in 1..=5 {
        let events = emit_integration_events(&decision);
        let json = serde_json::to_string(&events).unwrap();
        assert_eq!(baseline_json, json, "events run {run} diverged");
    }
}

// ===========================================================================
// 13. Cross-cutting: aggregate weighting invariants
// ===========================================================================

#[test]
fn enrichment_aggregate_weights_sum_to_100() {
    // Weights are 30+30+20+10+10 = 100. Verify: all scores at X → aggregate = X.
    let now_ns = 50_000u64;
    let mut input = baseline_input(now_ns);
    for signal in &mut input.signals {
        signal.score_millionths = 700_000;
    }
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    assert_eq!(decision.quality_summary.aggregate_score_millionths, 700_000);
}

#[test]
fn enrichment_each_source_contributes_correct_weight() {
    let now_ns = 50_000u64;
    let sources_and_weights: Vec<(EvidenceSource, i64)> = vec![
        (EvidenceSource::UnitDepthGate, 30),
        (EvidenceSource::EndToEndScenarioMatrix, 30),
        (EvidenceSource::TestLoggingSchema, 20),
        (EvidenceSource::FlakeQuarantineWorkflow, 10),
        (EvidenceSource::ProofCarryingArtifactGate, 10),
    ];
    for (target_source, expected_weight) in sources_and_weights {
        let mut input = baseline_input(now_ns);
        for signal in &mut input.signals {
            signal.score_millionths = 0;
        }
        input
            .signals
            .iter_mut()
            .find(|s| s.source == target_source)
            .unwrap()
            .score_millionths = 1_000_000;
        let decision =
            integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
        assert_eq!(
            decision.quality_summary.aggregate_score_millionths,
            expected_weight * 10_000,
            "wrong weight for {:?}",
            target_source
        );
    }
}

// ===========================================================================
// 14. Cross-cutting: queue_risk + aggregate = 1_000_000
// ===========================================================================

#[test]
fn enrichment_queue_risk_complement_invariant_multiple_scores() {
    let now_ns = 50_000u64;
    for score in [0, 100_000, 500_000, 800_000, 950_000, 1_000_000] {
        let mut input = baseline_input(now_ns);
        for signal in &mut input.signals {
            signal.score_millionths = score;
        }
        let decision =
            integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
        assert_eq!(
            decision.quality_summary.aggregate_score_millionths + decision.queue_risk_millionths,
            1_000_000,
            "invariant broken for score {score}"
        );
    }
}

// ===========================================================================
// 15. Cut-line threshold boundary for each cut line
// ===========================================================================

#[test]
fn enrichment_each_cut_line_boundary_exactly_at_threshold() {
    let now_ns = 50_000u64;
    let policy = IntegratorPolicy::default();
    let thresholds: Vec<(CutLine, i64)> = vec![
        (CutLine::C0, 900_000),
        (CutLine::C1, 930_000),
        (CutLine::C2, 940_000),
        (CutLine::C3, 950_000),
        (CutLine::C4, 965_000),
        (CutLine::C5, 975_000),
    ];
    for (cut_line, threshold) in thresholds {
        let mut input = baseline_input(now_ns);
        input.cut_line = cut_line;
        // Set all scores to threshold → aggregate = threshold
        for signal in &mut input.signals {
            signal.score_millionths = threshold;
        }
        let decision = integrate_milestone_release_test_evidence(&input, &policy);
        assert!(
            decision.allows_promotion(),
            "{cut_line:?}: aggregate {0} at threshold {threshold} should allow",
            decision.quality_summary.aggregate_score_millionths
        );
    }
}

#[test]
fn enrichment_each_cut_line_boundary_one_below_threshold() {
    let now_ns = 50_000u64;
    let policy = IntegratorPolicy::default();
    let thresholds: Vec<(CutLine, i64)> = vec![
        (CutLine::C0, 900_000),
        (CutLine::C1, 930_000),
        (CutLine::C2, 940_000),
        (CutLine::C3, 950_000),
        (CutLine::C4, 965_000),
        (CutLine::C5, 975_000),
    ];
    for (cut_line, threshold) in thresholds {
        let mut input = baseline_input(now_ns);
        input.cut_line = cut_line;
        // Set all scores to threshold-1 → aggregate = threshold-1
        for signal in &mut input.signals {
            signal.score_millionths = threshold - 1;
        }
        let decision = integrate_milestone_release_test_evidence(&input, &policy);
        // Due to integer division, verify the blocker message
        let agg = decision.quality_summary.aggregate_score_millionths;
        if agg < threshold {
            assert!(
                !decision.allows_promotion(),
                "{cut_line:?}: aggregate {agg} below threshold {threshold} should deny"
            );
        }
    }
}

// ===========================================================================
// 16. Gate inputs — evidence_refs dedup, evidence_hash
// ===========================================================================

#[test]
fn enrichment_gate_inputs_evidence_refs_sorted() {
    let input = baseline_input(50_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let gate_inputs = to_cut_line_gate_inputs(&decision, &input.signals);
    for gate in &gate_inputs {
        let mut sorted = gate.evidence_refs.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            gate.evidence_refs, sorted,
            "evidence_refs not sorted+deduped"
        );
    }
}

#[test]
fn enrichment_gate_inputs_score_clamped() {
    let now_ns = 50_000u64;
    let mut input = baseline_input(now_ns);
    // Set a score to max
    input.signals[0].score_millionths = 1_000_000;
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let gate_inputs = to_cut_line_gate_inputs(&decision, &input.signals);
    for gate in &gate_inputs {
        if let Some(score) = gate.score_millionths {
            assert!(
                (0..=1_000_000).contains(&score),
                "gate score out of range: {score}"
            );
        }
    }
}

#[test]
fn enrichment_gate_inputs_evidence_hash_nonempty() {
    let input = baseline_input(50_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let gate_inputs = to_cut_line_gate_inputs(&decision, &input.signals);
    for gate in &gate_inputs {
        assert!(!gate.evidence_hash.as_bytes().is_empty());
    }
}

// ===========================================================================
// 17. Checklist — idempotent apply
// ===========================================================================

#[test]
fn enrichment_checklist_apply_idempotent() {
    let input = baseline_input(50_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let mut checklist = empty_checklist();
    apply_to_release_checklist(&mut checklist, &decision, &input.signals);
    let first_json = serde_json::to_string(&checklist).unwrap();
    // Apply again
    apply_to_release_checklist(&mut checklist, &decision, &input.signals);
    let second_json = serde_json::to_string(&checklist).unwrap();
    // Item count should not grow (existing items updated, not duplicated)
    assert_eq!(
        first_json, second_json,
        "apply_to_release_checklist not idempotent"
    );
}

#[test]
fn enrichment_checklist_all_items_required() {
    let input = baseline_input(50_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let mut checklist = empty_checklist();
    apply_to_release_checklist(&mut checklist, &decision, &input.signals);
    for item in &checklist.items {
        assert!(item.required, "item {} should be required", item.item_id);
    }
}

#[test]
fn enrichment_checklist_no_waivers_on_passing() {
    let input = baseline_input(50_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let mut checklist = empty_checklist();
    apply_to_release_checklist(&mut checklist, &decision, &input.signals);
    for item in &checklist.items {
        assert!(
            item.waiver.is_none(),
            "item {} has unexpected waiver",
            item.item_id
        );
    }
}

#[test]
fn enrichment_checklist_item_categories_match_bindings() {
    let input = baseline_input(50_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let mut checklist = empty_checklist();
    apply_to_release_checklist(&mut checklist, &decision, &input.signals);
    for source in EvidenceSource::REQUIRED {
        let (item_id, expected_cat) = source.release_checklist_binding();
        let item = checklist
            .items
            .iter()
            .find(|i| i.item_id == item_id)
            .unwrap_or_else(|| panic!("missing checklist item {item_id}"));
        assert_eq!(
            item.category, expected_cat,
            "category mismatch for {item_id}"
        );
    }
}

// ===========================================================================
// 18. Signed evidence links — coverage and ordering
// ===========================================================================

#[test]
fn enrichment_signed_links_cover_all_gate_categories() {
    let input = baseline_input(50_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let link_cats: BTreeSet<&str> = decision
        .signed_evidence_links
        .iter()
        .map(|l| l.gate_category.as_str())
        .collect();
    // Expected categories from all 5 sources
    let expected = [
        "compiler_correctness",
        "runtime_parity",
        "deterministic_replay",
        "observability_integrity",
        "flake_burden",
        "governance_compliance",
        "handoff_readiness",
    ];
    for cat in expected {
        assert!(link_cats.contains(cat), "missing gate category: {cat}");
    }
}

#[test]
fn enrichment_signed_links_all_have_nonempty_signer() {
    let input = baseline_input(50_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    for link in &decision.signed_evidence_links {
        assert!(!link.signer.is_empty(), "signed link has empty signer");
        assert!(
            !link.artifact_id.is_empty(),
            "signed link has empty artifact_id"
        );
        assert!(
            !link.artifact_sha256.is_empty(),
            "signed link has empty sha256"
        );
    }
}

// ===========================================================================
// 19. Delta computation — sign and magnitude
// ===========================================================================

#[test]
fn enrichment_delta_negative_when_regression() {
    let now_ns = 50_000u64;
    let mut input = baseline_input(now_ns);
    // Previous scores were higher
    input.previous_summary = Some(MilestoneQualitySummary {
        cut_line: CutLine::C4,
        aggregate_score_millionths: 990_000,
        unit_depth_score_millionths: 990_000,
        e2e_stability_score_millionths: 990_000,
        logging_integrity_score_millionths: 990_000,
        flake_resilience_score_millionths: 990_000,
        artifact_integrity_score_millionths: 990_000,
        delta_from_previous_millionths: BTreeMap::new(),
    });
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let deltas = &decision.quality_summary.delta_from_previous_millionths;
    // Current scores are 980_000, previous 990_000 → deltas should be -10_000
    assert_eq!(deltas["unit_depth"], -10_000);
    assert_eq!(deltas["e2e_stability"], -10_000);
}

#[test]
fn enrichment_delta_zero_when_same() {
    let now_ns = 50_000u64;
    let mut input = baseline_input(now_ns);
    input.previous_summary = Some(MilestoneQualitySummary {
        cut_line: CutLine::C4,
        aggregate_score_millionths: 980_000,
        unit_depth_score_millionths: 980_000,
        e2e_stability_score_millionths: 980_000,
        logging_integrity_score_millionths: 980_000,
        flake_resilience_score_millionths: 980_000,
        artifact_integrity_score_millionths: 980_000,
        delta_from_previous_millionths: BTreeMap::new(),
    });
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let deltas = &decision.quality_summary.delta_from_previous_millionths;
    for (key, val) in deltas {
        assert_eq!(*val, 0, "delta for {key} should be 0");
    }
}

#[test]
fn enrichment_delta_has_exactly_six_keys() {
    let now_ns = 50_000u64;
    let mut input = baseline_input(now_ns);
    input.previous_summary = Some(MilestoneQualitySummary {
        cut_line: CutLine::C4,
        aggregate_score_millionths: 900_000,
        unit_depth_score_millionths: 900_000,
        e2e_stability_score_millionths: 900_000,
        logging_integrity_score_millionths: 900_000,
        flake_resilience_score_millionths: 900_000,
        artifact_integrity_score_millionths: 900_000,
        delta_from_previous_millionths: BTreeMap::new(),
    });
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let deltas = &decision.quality_summary.delta_from_previous_millionths;
    assert_eq!(deltas.len(), 6, "expected 6 delta keys: {deltas:?}");
    let expected_keys = [
        "aggregate",
        "unit_depth",
        "e2e_stability",
        "logging_integrity",
        "flake_resilience",
        "artifact_integrity",
    ];
    for key in expected_keys {
        assert!(deltas.contains_key(key), "missing delta key: {key}");
    }
}

// ===========================================================================
// 20. Multiple validation failures on single signal
// ===========================================================================

#[test]
fn enrichment_multiple_failures_on_one_signal() {
    let now_ns = 50_000u64;
    let mut input = baseline_input(now_ns);
    let signal = input
        .signals
        .iter_mut()
        .find(|s| s.source == EvidenceSource::UnitDepthGate)
        .unwrap();
    // Trigger multiple: out of range, empty refs, empty artifacts
    signal.score_millionths = -1;
    signal.evidence_refs.clear();
    signal.artifact_links.clear();
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    // Should have at least 3 blockers from this source
    let source_blockers: Vec<_> = decision
        .blockers
        .iter()
        .filter(|f| f.source == Some(EvidenceSource::UnitDepthGate))
        .collect();
    assert!(
        source_blockers.len() >= 3,
        "expected >=3 blockers, got {}",
        source_blockers.len()
    );
}

// ===========================================================================
// 21. Multiple artifacts per signal
// ===========================================================================

#[test]
fn enrichment_multiple_artifacts_first_signed_used_for_link() {
    let now_ns = 50_000u64;
    let mut input = baseline_input(now_ns);
    let signal = input
        .signals
        .iter_mut()
        .find(|s| s.source == EvidenceSource::UnitDepthGate)
        .unwrap();
    // Add an unsigned artifact before the signed one
    let unsigned = EvidenceArtifactLink {
        artifact_id: "unsigned-first".to_string(),
        path: "artifacts/unsigned/manifest.json".to_string(),
        sha256: "unsignedsha256".to_string(),
        signature_status: SignatureStatus::Unsigned,
        signer: None,
        signature_ref: None,
        generated_at_ns: now_ns - 100,
        schema_major: 1,
    };
    signal.artifact_links.insert(0, unsigned);

    // Need to allow unsigned artifacts in policy since we have an unsigned one
    let mut policy = IntegratorPolicy::default();
    policy.require_signed_artifacts = false;

    let decision = integrate_milestone_release_test_evidence(&input, &policy);
    // The signed evidence link should use the signed artifact, not the unsigned one
    let unit_link = decision
        .signed_evidence_links
        .iter()
        .find(|l| l.evidence_source == EvidenceSource::UnitDepthGate);
    if let Some(link) = unit_link {
        assert_ne!(
            link.artifact_id, "unsigned-first",
            "should prefer signed artifact"
        );
    }
}

// ===========================================================================
// 22. Empty signals vector
// ===========================================================================

#[test]
fn enrichment_empty_signals_all_missing_blockers() {
    let mut input = baseline_input(50_000);
    input.signals.clear();
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    assert!(!decision.allows_promotion());
    // Should have 5 "missing required signal" blockers
    let missing_count = decision
        .blockers
        .iter()
        .filter(|f| f.message.contains("missing required signal"))
        .count();
    assert_eq!(
        missing_count, 5,
        "expected 5 missing signal blockers, got {missing_count}"
    );
}

// ===========================================================================
// 23. Decision field consistency
// ===========================================================================

#[test]
fn enrichment_decision_trace_and_policy_ids_preserved() {
    let mut input = baseline_input(50_000);
    input.trace_id = "custom-trace-xyz".to_string();
    input.decision_id = "custom-decision-abc".to_string();
    input.policy_id = "custom-policy-v99".to_string();
    input.release_tag = "v99.0.0-beta".to_string();
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    assert_eq!(decision.trace_id, "custom-trace-xyz");
    assert_eq!(decision.decision_id, "custom-decision-abc");
    assert_eq!(decision.policy_id, "custom-policy-v99");
    assert_eq!(decision.release_tag, "v99.0.0-beta");
    assert_eq!(decision.evaluated_at_ns, 50_000);
}

#[test]
fn enrichment_decision_component_is_constant() {
    let input = baseline_input(50_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    assert_eq!(decision.component, TEST_EVIDENCE_INTEGRATOR_COMPONENT);
}

// ===========================================================================
// 24. Event inherits decision fields
// ===========================================================================

#[test]
fn enrichment_event_inherits_all_decision_ids() {
    let mut input = baseline_input(50_000);
    input.trace_id = "event-trace".to_string();
    input.decision_id = "event-decision".to_string();
    input.policy_id = "event-policy".to_string();
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let events = emit_integration_events(&decision);
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.trace_id, "event-trace");
    assert_eq!(event.decision_id, "event-decision");
    assert_eq!(event.policy_id, "event-policy");
    assert_eq!(event.component, TEST_EVIDENCE_INTEGRATOR_COMPONENT);
    assert_eq!(event.event, "integration_completed");
    assert_eq!(event.outcome, decision.outcome);
    assert_eq!(event.blocker_count, decision.blockers.len());
    assert_eq!(
        event.aggregate_score_millionths,
        decision.quality_summary.aggregate_score_millionths
    );
    assert_eq!(event.queue_risk_millionths, decision.queue_risk_millionths);
}

// ===========================================================================
// 25. Quality summary individual scores match signals
// ===========================================================================

#[test]
fn enrichment_quality_summary_individual_scores() {
    let now_ns = 50_000u64;
    let mut input = baseline_input(now_ns);
    // Set distinct scores for each source
    let scores: [(EvidenceSource, i64); 5] = [
        (EvidenceSource::UnitDepthGate, 960_000),
        (EvidenceSource::EndToEndScenarioMatrix, 970_000),
        (EvidenceSource::TestLoggingSchema, 980_000),
        (EvidenceSource::FlakeQuarantineWorkflow, 990_000),
        (EvidenceSource::ProofCarryingArtifactGate, 1_000_000),
    ];
    for (source, score) in &scores {
        input
            .signals
            .iter_mut()
            .find(|s| s.source == *source)
            .unwrap()
            .score_millionths = *score;
    }
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let qs = &decision.quality_summary;
    assert_eq!(qs.unit_depth_score_millionths, 960_000);
    assert_eq!(qs.e2e_stability_score_millionths, 970_000);
    assert_eq!(qs.logging_integrity_score_millionths, 980_000);
    assert_eq!(qs.flake_resilience_score_millionths, 990_000);
    assert_eq!(qs.artifact_integrity_score_millionths, 1_000_000);
    // aggregate = (960k*30 + 970k*30 + 980k*20 + 990k*10 + 1M*10) / 100
    let expected =
        (960_000 * 30 + 970_000 * 30 + 980_000 * 20 + 990_000 * 10 + 1_000_000 * 10) / 100;
    assert_eq!(qs.aggregate_score_millionths, expected);
}

// ===========================================================================
// 26. Checklist pre-existing items with different categories
// ===========================================================================

#[test]
fn enrichment_checklist_overwrites_wrong_category() {
    let input = baseline_input(50_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let mut checklist = empty_checklist();
    // Pre-populate with wrong category
    checklist.items.push(ChecklistItem {
        item_id: "security.conformance_suite".to_string(),
        category: ChecklistCategory::Reproducibility, // Wrong!
        required: false,
        status: ChecklistItemStatus::Fail,
        artifact_refs: vec![],
        waiver: None,
    });
    apply_to_release_checklist(&mut checklist, &decision, &input.signals);
    let item = checklist
        .items
        .iter()
        .find(|i| i.item_id == "security.conformance_suite")
        .unwrap();
    assert_eq!(item.category, ChecklistCategory::Security); // Corrected
    assert!(item.required);
    assert_eq!(item.status, ChecklistItemStatus::Pass);
}

// ===========================================================================
// 27. Gate categories expansion count
// ===========================================================================

#[test]
fn enrichment_gate_categories_total_count() {
    let mut total = 0usize;
    for source in EvidenceSource::REQUIRED {
        total += source.gate_categories().len();
    }
    // UnitDepth=1, E2E=2, Logging=1, Flake=1, Proof=2 = 7
    assert_eq!(total, 7, "total gate categories should be 7");
}

// ===========================================================================
// 28. Serde roundtrips on complex assembled types
// ===========================================================================

#[test]
fn enrichment_full_decision_with_blockers_serde_roundtrip() {
    let now_ns = 50_000u64;
    let mut input = baseline_input(now_ns);
    // Force blockers by removing a signal
    input
        .signals
        .retain(|s| s.source != EvidenceSource::TestLoggingSchema);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    assert!(!decision.blockers.is_empty());
    let json = serde_json::to_string(&decision).unwrap();
    let back: TestEvidenceIntegrationDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

#[test]
fn enrichment_full_decision_with_deltas_serde_roundtrip() {
    let now_ns = 50_000u64;
    let mut input = baseline_input(now_ns);
    input.previous_summary = Some(MilestoneQualitySummary {
        cut_line: CutLine::C3,
        aggregate_score_millionths: 900_000,
        unit_depth_score_millionths: 900_000,
        e2e_stability_score_millionths: 900_000,
        logging_integrity_score_millionths: 900_000,
        flake_resilience_score_millionths: 900_000,
        artifact_integrity_score_millionths: 900_000,
        delta_from_previous_millionths: BTreeMap::new(),
    });
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    assert!(
        !decision
            .quality_summary
            .delta_from_previous_millionths
            .is_empty()
    );
    let json = serde_json::to_string(&decision).unwrap();
    let back: TestEvidenceIntegrationDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

// ===========================================================================
// 29. Checklist artifact refs from signed links
// ===========================================================================

#[test]
fn enrichment_checklist_artifact_refs_nonempty_for_passing() {
    let input = baseline_input(50_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let mut checklist = empty_checklist();
    apply_to_release_checklist(&mut checklist, &decision, &input.signals);
    for item in &checklist.items {
        assert!(
            !item.artifact_refs.is_empty(),
            "item {} should have artifact refs when passing",
            item.item_id
        );
    }
}

// ===========================================================================
// 30. Flake burden boundary at exactly max
// ===========================================================================

#[test]
fn enrichment_flake_burden_at_exactly_max_no_blocker() {
    let now_ns = 50_000u64;
    let policy = IntegratorPolicy::default();
    let mut input = baseline_input(now_ns);
    input
        .signals
        .iter_mut()
        .find(|s| s.source == EvidenceSource::FlakeQuarantineWorkflow)
        .unwrap()
        .metadata
        .insert(
            "flake_burden_millionths".to_string(),
            policy.max_flake_burden_millionths.to_string(),
        );
    let decision = integrate_milestone_release_test_evidence(&input, &policy);
    let flake_blockers: Vec<_> = decision
        .blockers
        .iter()
        .filter(|f| f.message.contains("flake burden") && f.message.contains("exceeds"))
        .collect();
    assert!(
        flake_blockers.is_empty(),
        "flake burden at max should not block"
    );
}

#[test]
fn enrichment_flake_burden_one_above_max_blocks() {
    let now_ns = 50_000u64;
    let policy = IntegratorPolicy::default();
    let mut input = baseline_input(now_ns);
    input
        .signals
        .iter_mut()
        .find(|s| s.source == EvidenceSource::FlakeQuarantineWorkflow)
        .unwrap()
        .metadata
        .insert(
            "flake_burden_millionths".to_string(),
            (policy.max_flake_burden_millionths + 1).to_string(),
        );
    let decision = integrate_milestone_release_test_evidence(&input, &policy);
    let flake_blockers: Vec<_> = decision
        .blockers
        .iter()
        .filter(|f| f.message.contains("flake burden") && f.message.contains("exceeds"))
        .collect();
    assert!(
        !flake_blockers.is_empty(),
        "flake burden above max should block"
    );
}
