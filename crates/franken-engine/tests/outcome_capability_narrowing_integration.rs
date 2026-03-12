//! Integration tests for outcome_capability_narrowing module.

use std::collections::BTreeSet;

use frankenengine_engine::outcome_capability_narrowing::{
    BoundaryOutcome, BoundaryTransition, CapabilityGrant, CapabilityNarrowingValidator,
    CapabilityToken, NarrowingDirection, NarrowingReport, NarrowingViolation,
    OutcomePropagationRule,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// BoundaryOutcome integration
// ---------------------------------------------------------------------------

#[test]
fn integration_outcome_severity_total_ordering() {
    let outcomes = [
        BoundaryOutcome::Success,
        BoundaryOutcome::Failure,
        BoundaryOutcome::Timeout,
        BoundaryOutcome::Cancelled,
    ];
    for i in 0..outcomes.len() {
        for j in (i + 1)..outcomes.len() {
            assert!(
                outcomes[i].severity() < outcomes[j].severity(),
                "{:?} should have lower severity than {:?}",
                outcomes[i],
                outcomes[j]
            );
        }
    }
}

#[test]
fn integration_outcome_all_variants_distinct() {
    let outcomes = [
        BoundaryOutcome::Success,
        BoundaryOutcome::Failure,
        BoundaryOutcome::Timeout,
        BoundaryOutcome::Cancelled,
    ];
    let mut labels = BTreeSet::new();
    for o in outcomes {
        assert!(labels.insert(o.as_str()), "duplicate: {}", o.as_str());
    }
    assert_eq!(labels.len(), 4);
}

// ---------------------------------------------------------------------------
// OutcomePropagationRule integration
// ---------------------------------------------------------------------------

#[test]
fn integration_preserve_rule_is_identity() {
    let rule = OutcomePropagationRule::Preserve;
    for child in [
        BoundaryOutcome::Success,
        BoundaryOutcome::Failure,
        BoundaryOutcome::Timeout,
        BoundaryOutcome::Cancelled,
    ] {
        for parent in [
            BoundaryOutcome::Success,
            BoundaryOutcome::Failure,
            BoundaryOutcome::Timeout,
            BoundaryOutcome::Cancelled,
        ] {
            assert_eq!(
                rule.apply(child, parent),
                child,
                "preserve should return child"
            );
        }
    }
}

#[test]
fn integration_collapse_never_produces_timeout_or_cancelled() {
    let rule = OutcomePropagationRule::CollapseToFailure;
    for child in [
        BoundaryOutcome::Success,
        BoundaryOutcome::Failure,
        BoundaryOutcome::Timeout,
        BoundaryOutcome::Cancelled,
    ] {
        let result = rule.apply(child, BoundaryOutcome::Success);
        match result {
            BoundaryOutcome::Success | BoundaryOutcome::Failure => {}
            other => panic!("collapse produced {:?} from {:?}", other, child),
        }
    }
}

#[test]
fn integration_escalate_monotonically_increases_severity() {
    let rule = OutcomePropagationRule::EscalateToMostSevere;
    let mut current = BoundaryOutcome::Success;

    // Escalate through each level
    current = rule.apply(BoundaryOutcome::Failure, current);
    assert_eq!(current, BoundaryOutcome::Failure);

    current = rule.apply(BoundaryOutcome::Timeout, current);
    assert_eq!(current, BoundaryOutcome::Timeout);

    current = rule.apply(BoundaryOutcome::Cancelled, current);
    assert_eq!(current, BoundaryOutcome::Cancelled);

    // Can't go back down
    current = rule.apply(BoundaryOutcome::Success, current);
    assert_eq!(current, BoundaryOutcome::Cancelled);
}

#[test]
fn integration_severity_threshold_filters() {
    let rule = OutcomePropagationRule::SeverityThreshold { min_severity: 2 };

    // Below threshold: ignored
    let r1 = rule.apply(BoundaryOutcome::Success, BoundaryOutcome::Success);
    assert_eq!(r1, BoundaryOutcome::Success);

    let r2 = rule.apply(BoundaryOutcome::Failure, BoundaryOutcome::Success);
    assert_eq!(r2, BoundaryOutcome::Success); // severity 1 < 2

    // At threshold: propagated
    let r3 = rule.apply(BoundaryOutcome::Timeout, BoundaryOutcome::Success);
    assert_eq!(r3, BoundaryOutcome::Timeout);

    // Above threshold: propagated
    let r4 = rule.apply(BoundaryOutcome::Cancelled, BoundaryOutcome::Success);
    assert_eq!(r4, BoundaryOutcome::Cancelled);
}

// ---------------------------------------------------------------------------
// CapabilityGrant integration
// ---------------------------------------------------------------------------

#[test]
fn integration_capability_presets_correct_sizes() {
    assert_eq!(CapabilityGrant::none().len(), 0);
    assert_eq!(CapabilityGrant::compute_only().len(), 2);
    assert_eq!(CapabilityGrant::sandbox().len(), 4);
    assert_eq!(CapabilityGrant::full().len(), 12);
}

#[test]
fn integration_capability_subset_lattice() {
    let none = CapabilityGrant::none();
    let compute = CapabilityGrant::compute_only();
    let sandbox = CapabilityGrant::sandbox();
    let full = CapabilityGrant::full();

    // none ⊆ compute ⊆ sandbox ⊆ full
    assert!(none.is_subset_of(&compute));
    assert!(compute.is_subset_of(&sandbox));
    assert!(sandbox.is_subset_of(&full));

    // Not the reverse
    assert!(!full.is_subset_of(&sandbox));
    assert!(!sandbox.is_subset_of(&compute));
}

#[test]
fn integration_intersect_with_self_is_identity() {
    for grant in [
        CapabilityGrant::none(),
        CapabilityGrant::compute_only(),
        CapabilityGrant::sandbox(),
        CapabilityGrant::full(),
    ] {
        let intersected = grant.intersect(&grant);
        assert_eq!(intersected.tokens, grant.tokens);
    }
}

#[test]
fn integration_intersect_with_none_is_none() {
    let none = CapabilityGrant::none();
    for grant in [
        CapabilityGrant::compute_only(),
        CapabilityGrant::sandbox(),
        CapabilityGrant::full(),
    ] {
        let intersected = grant.intersect(&none);
        assert!(intersected.is_empty());
    }
}

#[test]
fn integration_difference_full_minus_sandbox() {
    let full = CapabilityGrant::full();
    let sandbox = CapabilityGrant::sandbox();
    let diff = full.difference(&sandbox);

    // Full has 12, sandbox has 4, difference should have 8
    assert_eq!(diff.len(), 8);
    // The difference should include things not in sandbox
    assert!(diff.contains(&CapabilityToken::NetworkAccess));
    assert!(diff.contains(&CapabilityToken::FileSystemWrite));
    assert!(diff.contains(&CapabilityToken::ProcessSpawn));
}

#[test]
fn integration_custom_capability_grant() {
    let mut grant = CapabilityGrant::none();
    grant.tokens.insert(CapabilityToken::FileSystemRead);
    grant.tokens.insert(CapabilityToken::TelemetryEmit);
    grant.label = "custom_readonly".to_owned();

    assert_eq!(grant.len(), 2);
    assert!(grant.has(CapabilityToken::FileSystemRead));
    assert!(grant.has(CapabilityToken::TelemetryEmit));
    assert!(!grant.has(CapabilityToken::FileSystemWrite));
}

// ---------------------------------------------------------------------------
// Validator integration
// ---------------------------------------------------------------------------

#[test]
fn integration_validator_clean_narrowing_chain() {
    let mut validator = CapabilityNarrowingValidator::with_defaults();

    // full → sandbox → compute → none
    let grants = [
        CapabilityGrant::full(),
        CapabilityGrant::sandbox(),
        CapabilityGrant::compute_only(),
        CapabilityGrant::none(),
    ];

    for i in 0..grants.len() - 1 {
        let dir = validator.validate_narrowing(
            &format!("trace-{}", i),
            &format!("trace-{}", i + 1),
            &format!("boundary-{}", i),
            &grants[i],
            &grants[i + 1],
        );
        assert_eq!(dir, NarrowingDirection::Narrowed);
    }

    assert!(!validator.has_violations());
    let report = validator.build_report();
    assert!(report.is_clean());
    assert_eq!(report.total_transitions, 3);
    assert_eq!(*report.direction_counts.get("narrowed").unwrap_or(&0), 3);
}

#[test]
fn integration_validator_widening_detected() {
    let mut validator = CapabilityNarrowingValidator::with_defaults();
    let parent = CapabilityGrant::compute_only();
    let child = CapabilityGrant::full();

    let dir = validator.validate_narrowing("p", "c", "bad_spawn", &parent, &child);
    assert_eq!(dir, NarrowingDirection::Widened);
    assert!(validator.has_violations());

    let report = validator.build_report();
    assert!(!report.is_clean());
    assert_eq!(*report.direction_counts.get("widened").unwrap_or(&0), 1);
}

#[test]
fn integration_validator_outcome_tracking() {
    let mut validator = CapabilityNarrowingValidator::with_defaults();

    // Record a narrowing
    validator.validate_narrowing(
        "parent",
        "child",
        "spawn",
        &CapabilityGrant::full(),
        &CapabilityGrant::sandbox(),
    );

    // Record outcome for the same boundary
    let propagated = validator.record_outcome_propagation(
        "spawn",
        BoundaryOutcome::Timeout,
        BoundaryOutcome::Success,
    );
    assert_eq!(propagated, BoundaryOutcome::Timeout);

    // Check transition was updated
    let last = validator.transitions().last().unwrap();
    assert_eq!(last.child_outcome, Some(BoundaryOutcome::Timeout));
    assert_eq!(last.propagated_outcome, Some(BoundaryOutcome::Timeout));
}

#[test]
fn integration_validator_outcome_upgrade_violation_detected() {
    let mut validator = CapabilityNarrowingValidator::new(
        OutcomePropagationRule::CollapseToFailure,
        SecurityEpoch::from_raw(1),
    );

    // CollapseToFailure maps Timeout(sev=2) → Failure(sev=1), which is an upgrade
    let _ = validator.record_outcome_propagation(
        "boundary",
        BoundaryOutcome::Timeout,
        BoundaryOutcome::Success,
    );

    assert!(validator.has_violations());
    match &validator.violations()[0] {
        NarrowingViolation::OutcomeUpgrade {
            child_outcome,
            propagated_outcome,
            ..
        } => {
            assert_eq!(*child_outcome, BoundaryOutcome::Timeout);
            assert_eq!(*propagated_outcome, BoundaryOutcome::Failure);
        }
        other => panic!("expected OutcomeUpgrade, got {:?}", other),
    }
}

#[test]
fn integration_validator_combined_cap_and_outcome() {
    let mut validator = CapabilityNarrowingValidator::new(
        OutcomePropagationRule::EscalateToMostSevere,
        SecurityEpoch::from_raw(1),
    );

    // Multiple boundary crossings
    for i in 0..5 {
        let parent = CapabilityGrant::full();
        let child = CapabilityGrant::sandbox();
        validator.validate_narrowing(
            &format!("p-{}", i),
            &format!("c-{}", i),
            &format!("b-{}", i),
            &parent,
            &child,
        );
    }

    // Record escalating outcomes
    let mut current = BoundaryOutcome::Success;
    for (i, outcome) in [
        BoundaryOutcome::Failure,
        BoundaryOutcome::Timeout,
        BoundaryOutcome::Cancelled,
    ]
    .iter()
    .enumerate()
    {
        current = validator.record_outcome_propagation(&format!("b-{}", i), *outcome, current);
    }

    assert_eq!(current, BoundaryOutcome::Cancelled);

    let report = validator.build_report();
    assert!(report.is_clean()); // no violations from narrowing
}

// ---------------------------------------------------------------------------
// Report integration
// ---------------------------------------------------------------------------

#[test]
fn integration_report_content_hash_deterministic() {
    let make_report = || {
        let mut v = CapabilityNarrowingValidator::with_defaults();
        v.validate_narrowing(
            "p",
            "c",
            "b",
            &CapabilityGrant::full(),
            &CapabilityGrant::sandbox(),
        );
        v.build_report()
    };

    let r1 = make_report();
    let r2 = make_report();
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn integration_report_json_roundtrip() {
    let mut v = CapabilityNarrowingValidator::with_defaults();
    v.validate_narrowing(
        "p",
        "c1",
        "b1",
        &CapabilityGrant::full(),
        &CapabilityGrant::sandbox(),
    );
    v.validate_narrowing(
        "p",
        "c2",
        "b2",
        &CapabilityGrant::sandbox(),
        &CapabilityGrant::compute_only(),
    );
    v.record_outcome_propagation("b1", BoundaryOutcome::Success, BoundaryOutcome::Success);
    v.record_outcome_propagation("b2", BoundaryOutcome::Failure, BoundaryOutcome::Success);

    let report = v.build_report();
    let json = serde_json::to_string_pretty(&report).unwrap();
    let round: NarrowingReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, round);
}

#[test]
fn integration_transition_json_roundtrip() {
    let mut v = CapabilityNarrowingValidator::with_defaults();
    v.validate_narrowing(
        "p",
        "c",
        "b",
        &CapabilityGrant::full(),
        &CapabilityGrant::sandbox(),
    );

    let transition = &v.transitions()[0];
    let json = serde_json::to_string(transition).unwrap();
    let round: BoundaryTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(*transition, round);
}

#[test]
fn integration_violation_json_roundtrip() {
    let violations = vec![
        NarrowingViolation::CapabilityWidening {
            boundary_label: "test".to_owned(),
            widened_tokens: {
                let mut s = BTreeSet::new();
                s.insert(CapabilityToken::NetworkAccess);
                s.insert(CapabilityToken::ProcessSpawn);
                s
            },
        },
        NarrowingViolation::OutcomeUpgrade {
            boundary_label: "test2".to_owned(),
            child_outcome: BoundaryOutcome::Timeout,
            propagated_outcome: BoundaryOutcome::Failure,
        },
        NarrowingViolation::UnknownOutcomeNotFailClosed {
            boundary_label: "test3".to_owned(),
        },
    ];

    for v in violations {
        let json = serde_json::to_string(&v).unwrap();
        let round: NarrowingViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(v, round);
    }
}

// ---------------------------------------------------------------------------
// CapabilityToken integration
// ---------------------------------------------------------------------------

#[test]
fn integration_all_tokens_have_unique_labels() {
    let tokens = CapabilityToken::all();
    let mut labels = BTreeSet::new();
    for token in tokens {
        assert!(
            labels.insert(token.as_str()),
            "duplicate: {}",
            token.as_str()
        );
    }
    assert_eq!(labels.len(), tokens.len());
}

#[test]
fn integration_token_serde_roundtrip() {
    for token in CapabilityToken::all() {
        let json = serde_json::to_string(token).unwrap();
        let round: CapabilityToken = serde_json::from_str(&json).unwrap();
        assert_eq!(*token, round);
    }
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn integration_empty_validator_report() {
    let validator = CapabilityNarrowingValidator::with_defaults();
    let report = validator.build_report();
    assert!(report.is_clean());
    assert_eq!(report.total_transitions, 0);
    assert!(report.direction_counts.is_empty());
    assert!(report.outcome_counts.is_empty());
}

#[test]
fn integration_narrowing_direction_serde_roundtrip() {
    for dir in [
        NarrowingDirection::Narrowed,
        NarrowingDirection::Preserved,
        NarrowingDirection::Widened,
    ] {
        let json = serde_json::to_string(&dir).unwrap();
        let round: NarrowingDirection = serde_json::from_str(&json).unwrap();
        assert_eq!(dir, round);
    }
}

#[test]
fn integration_high_volume_narrowing() {
    let mut validator = CapabilityNarrowingValidator::with_defaults();
    let parent = CapabilityGrant::full();
    let child = CapabilityGrant::sandbox();

    // 100 transitions
    for i in 0..100 {
        validator.validate_narrowing(
            &format!("p-{}", i),
            &format!("c-{}", i),
            &format!("b-{}", i),
            &parent,
            &child,
        );
    }

    assert!(!validator.has_violations());
    let report = validator.build_report();
    assert_eq!(report.total_transitions, 100);
}

#[test]
fn integration_outcome_budget_related_flag() {
    assert!(!BoundaryOutcome::Success.is_budget_related());
    assert!(!BoundaryOutcome::Failure.is_budget_related());
    assert!(BoundaryOutcome::Timeout.is_budget_related());
    assert!(!BoundaryOutcome::Cancelled.is_budget_related());
}

#[test]
fn integration_violation_display_messages() {
    let violations = vec![
        NarrowingViolation::CapabilityWidening {
            boundary_label: "ext_spawn".to_owned(),
            widened_tokens: {
                let mut s = BTreeSet::new();
                s.insert(CapabilityToken::NetworkAccess);
                s
            },
        },
        NarrowingViolation::OutcomeUpgrade {
            boundary_label: "cell_close".to_owned(),
            child_outcome: BoundaryOutcome::Timeout,
            propagated_outcome: BoundaryOutcome::Failure,
        },
        NarrowingViolation::UnknownOutcomeNotFailClosed {
            boundary_label: "unknown_boundary".to_owned(),
        },
    ];

    for v in violations {
        let msg = v.to_string();
        assert!(!msg.is_empty(), "violation display should not be empty");
    }
}

// ---------------------------------------------------------------------------
// Additional enrichment tests
// ---------------------------------------------------------------------------

#[test]
fn integration_outcome_as_str_all_variants() {
    assert_eq!(BoundaryOutcome::Success.as_str(), "success");
    assert_eq!(BoundaryOutcome::Failure.as_str(), "failure");
    assert_eq!(BoundaryOutcome::Timeout.as_str(), "timeout");
    assert_eq!(BoundaryOutcome::Cancelled.as_str(), "cancelled");
}

#[test]
fn integration_outcome_is_failure_class() {
    assert!(!BoundaryOutcome::Success.is_failure_class());
    assert!(BoundaryOutcome::Failure.is_failure_class());
    assert!(BoundaryOutcome::Timeout.is_failure_class());
    assert!(BoundaryOutcome::Cancelled.is_failure_class());
}

#[test]
fn integration_outcome_serde_roundtrip() {
    for outcome in [
        BoundaryOutcome::Success,
        BoundaryOutcome::Failure,
        BoundaryOutcome::Timeout,
        BoundaryOutcome::Cancelled,
    ] {
        let json = serde_json::to_string(&outcome).unwrap();
        let round: BoundaryOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, round);
    }
}

#[test]
fn integration_outcome_display() {
    for outcome in [
        BoundaryOutcome::Success,
        BoundaryOutcome::Failure,
        BoundaryOutcome::Timeout,
        BoundaryOutcome::Cancelled,
    ] {
        let display = format!("{outcome}");
        assert!(!display.is_empty());
    }
}

#[test]
fn integration_propagation_rule_serde_roundtrip() {
    let rules = [
        OutcomePropagationRule::Preserve,
        OutcomePropagationRule::CollapseToFailure,
        OutcomePropagationRule::EscalateToMostSevere,
        OutcomePropagationRule::SeverityThreshold { min_severity: 2 },
    ];
    for rule in &rules {
        let json = serde_json::to_string(rule).unwrap();
        let round: OutcomePropagationRule = serde_json::from_str(&json).unwrap();
        assert_eq!(*rule, round);
    }
}

#[test]
fn integration_capability_grant_is_empty() {
    assert!(CapabilityGrant::none().is_empty());
    assert!(!CapabilityGrant::compute_only().is_empty());
    assert!(!CapabilityGrant::sandbox().is_empty());
    assert!(!CapabilityGrant::full().is_empty());
}

#[test]
fn integration_capability_grant_compute_has_compute_and_telemetry() {
    let compute = CapabilityGrant::compute_only();
    assert!(compute.has(CapabilityToken::Compute));
    assert!(compute.has(CapabilityToken::TelemetryEmit));
    assert!(!compute.has(CapabilityToken::FileSystemRead));
    assert!(!compute.has(CapabilityToken::NetworkAccess));
}

#[test]
fn integration_capability_grant_sandbox_contains_compute() {
    let compute = CapabilityGrant::compute_only();
    let sandbox = CapabilityGrant::sandbox();
    assert!(compute.is_subset_of(&sandbox));
}

#[test]
fn integration_capability_grant_intersect_commutative() {
    let compute = CapabilityGrant::compute_only();
    let sandbox = CapabilityGrant::sandbox();
    let ab = compute.intersect(&sandbox);
    let ba = sandbox.intersect(&compute);
    assert_eq!(ab.tokens, ba.tokens);
}

#[test]
fn integration_capability_grant_difference_is_empty_for_subset() {
    let compute = CapabilityGrant::compute_only();
    let full = CapabilityGrant::full();
    let diff = compute.difference(&full);
    assert!(
        diff.is_empty(),
        "subset.difference(superset) should be empty"
    );
}

#[test]
fn integration_narrowing_direction_display() {
    for dir in [
        NarrowingDirection::Narrowed,
        NarrowingDirection::Preserved,
        NarrowingDirection::Widened,
    ] {
        let s = format!("{dir}");
        assert!(!s.is_empty());
    }
}

#[test]
fn integration_validator_preserved_direction() {
    let mut validator = CapabilityNarrowingValidator::with_defaults();
    let grant = CapabilityGrant::sandbox();
    let dir = validator.validate_narrowing("p", "c", "b", &grant, &grant);
    assert_eq!(dir, NarrowingDirection::Preserved);
    assert!(!validator.has_violations());
}

#[test]
fn integration_validator_widening_then_narrowing() {
    let mut validator = CapabilityNarrowingValidator::with_defaults();

    // First: widening (violation)
    let dir1 = validator.validate_narrowing(
        "p1",
        "c1",
        "b-widen",
        &CapabilityGrant::compute_only(),
        &CapabilityGrant::full(),
    );
    assert_eq!(dir1, NarrowingDirection::Widened);
    assert!(validator.has_violations());

    // Second: narrowing (ok)
    let dir2 = validator.validate_narrowing(
        "p2",
        "c2",
        "b-narrow",
        &CapabilityGrant::full(),
        &CapabilityGrant::sandbox(),
    );
    assert_eq!(dir2, NarrowingDirection::Narrowed);

    let report = validator.build_report();
    assert!(!report.is_clean());
    assert_eq!(report.total_transitions, 2);
}

#[test]
fn integration_report_hash_differs_for_different_inputs() {
    let make_report = |label: &str| {
        let mut v = CapabilityNarrowingValidator::with_defaults();
        v.validate_narrowing(
            label,
            "c",
            "b",
            &CapabilityGrant::full(),
            &CapabilityGrant::sandbox(),
        );
        v.build_report()
    };

    let r1 = make_report("parent_a");
    let r2 = make_report("parent_b");
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn integration_severity_threshold_zero_propagates_all() {
    let rule = OutcomePropagationRule::SeverityThreshold { min_severity: 0 };
    for outcome in [
        BoundaryOutcome::Success,
        BoundaryOutcome::Failure,
        BoundaryOutcome::Timeout,
        BoundaryOutcome::Cancelled,
    ] {
        let result = rule.apply(outcome, BoundaryOutcome::Success);
        assert_eq!(result, outcome, "threshold 0 should propagate {outcome:?}");
    }
}

#[test]
fn integration_capability_token_count() {
    let all = CapabilityToken::all();
    assert!(all.len() >= 12, "should have at least 12 capability tokens");
}

#[test]
fn integration_escalate_success_stays_success() {
    let rule = OutcomePropagationRule::EscalateToMostSevere;
    let result = rule.apply(BoundaryOutcome::Success, BoundaryOutcome::Success);
    assert_eq!(result, BoundaryOutcome::Success);
}

#[test]
fn integration_collapse_timeout_to_failure() {
    let rule = OutcomePropagationRule::CollapseToFailure;
    let result = rule.apply(BoundaryOutcome::Timeout, BoundaryOutcome::Success);
    assert_eq!(result, BoundaryOutcome::Failure);
}

#[test]
fn integration_collapse_cancelled_to_failure() {
    let rule = OutcomePropagationRule::CollapseToFailure;
    let result = rule.apply(BoundaryOutcome::Cancelled, BoundaryOutcome::Success);
    assert_eq!(result, BoundaryOutcome::Failure);
}
