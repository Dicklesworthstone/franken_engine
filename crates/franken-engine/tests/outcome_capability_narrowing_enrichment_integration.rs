//! Enrichment integration tests for outcome_capability_narrowing module.
//!
//! Covers serde roundtrips, Display uniqueness, struct construction,
//! lifecycle flows, arithmetic edge cases, and content hash determinism.

use std::collections::BTreeSet;

use frankenengine_engine::outcome_capability_narrowing::{
    BoundaryOutcome, BoundaryTransition, CapabilityGrant, CapabilityNarrowingValidator,
    CapabilityToken, NarrowingDirection, NarrowingReport, NarrowingViolation,
    OutcomePropagationRule,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Enum serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_boundary_outcome_snake_case_values() {
    let pairs = [
        (BoundaryOutcome::Success, "\"success\""),
        (BoundaryOutcome::Failure, "\"failure\""),
        (BoundaryOutcome::Timeout, "\"timeout\""),
        (BoundaryOutcome::Cancelled, "\"cancelled\""),
    ];
    for (variant, expected_json) in pairs {
        let json = serde_json::to_string(&variant).unwrap();
        assert_eq!(
            json, expected_json,
            "JSON encoding mismatch for {:?}",
            variant
        );
        let round: BoundaryOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(round, variant);
    }
}

#[test]
fn enrichment_serde_capability_token_all_variants_roundtrip() {
    for token in CapabilityToken::all() {
        let json = serde_json::to_string(token).unwrap();
        let round: CapabilityToken = serde_json::from_str(&json).unwrap();
        assert_eq!(*token, round);
        // Verify the JSON is a quoted snake_case string
        assert!(json.starts_with('"') && json.ends_with('"'));
    }
}

#[test]
fn enrichment_serde_narrowing_direction_all_variants() {
    let directions = [
        NarrowingDirection::Narrowed,
        NarrowingDirection::Preserved,
        NarrowingDirection::Widened,
    ];
    let mut seen_json = BTreeSet::new();
    for dir in directions {
        let json = serde_json::to_string(&dir).unwrap();
        assert!(
            seen_json.insert(json.clone()),
            "duplicate JSON for {:?}",
            dir
        );
        let round: NarrowingDirection = serde_json::from_str(&json).unwrap();
        assert_eq!(dir, round);
    }
}

#[test]
fn enrichment_serde_propagation_rule_severity_threshold_roundtrip() {
    for threshold in [0u8, 1, 2, 3, 127, 255] {
        let rule = OutcomePropagationRule::SeverityThreshold {
            min_severity: threshold,
        };
        let json = serde_json::to_string(&rule).unwrap();
        let round: OutcomePropagationRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, round, "roundtrip failed for threshold={}", threshold);
    }
}

#[test]
fn enrichment_serde_narrowing_violation_all_variants_roundtrip() {
    let mut tokens = BTreeSet::new();
    tokens.insert(CapabilityToken::FileSystemRead);
    tokens.insert(CapabilityToken::CryptoAccess);

    let violations = [
        NarrowingViolation::CapabilityWidening {
            boundary_label: "ext_spawn".to_owned(),
            widened_tokens: tokens,
        },
        NarrowingViolation::OutcomeUpgrade {
            boundary_label: "session_create".to_owned(),
            child_outcome: BoundaryOutcome::Cancelled,
            propagated_outcome: BoundaryOutcome::Success,
        },
        NarrowingViolation::UnknownOutcomeNotFailClosed {
            boundary_label: "external_api".to_owned(),
        },
    ];
    for v in &violations {
        let json = serde_json::to_string(v).unwrap();
        let round: NarrowingViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, round);
    }
}

#[test]
fn enrichment_serde_boundary_transition_with_none_outcomes() {
    let transition = BoundaryTransition {
        parent_trace_id: "trace-parent-001".to_owned(),
        child_trace_id: "trace-child-002".to_owned(),
        boundary_label: "sandbox_entry".to_owned(),
        parent_capabilities: CapabilityGrant::full(),
        child_capabilities: CapabilityGrant::compute_only(),
        narrowed_tokens: {
            let full = CapabilityGrant::full();
            let compute = CapabilityGrant::compute_only();
            full.difference(&compute)
        },
        direction: NarrowingDirection::Narrowed,
        child_outcome: None,
        propagated_outcome: None,
        sequence: 42,
    };
    let json = serde_json::to_string(&transition).unwrap();
    let round: BoundaryTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(transition, round);
    assert!(json.contains("null"));
}

#[test]
fn enrichment_serde_capability_grant_custom_tokens() {
    let mut tokens = BTreeSet::new();
    tokens.insert(CapabilityToken::NetworkAccess);
    tokens.insert(CapabilityToken::CryptoAccess);
    tokens.insert(CapabilityToken::SharedMemory);
    let grant = CapabilityGrant {
        tokens,
        label: "custom_network_crypto".to_owned(),
    };
    let json = serde_json::to_string(&grant).unwrap();
    let round: CapabilityGrant = serde_json::from_str(&json).unwrap();
    assert_eq!(grant, round);
    assert_eq!(round.len(), 3);
}

#[test]
fn enrichment_serde_narrowing_report_full_roundtrip() {
    let mut validator = CapabilityNarrowingValidator::new(
        OutcomePropagationRule::EscalateToMostSevere,
        SecurityEpoch::from_raw(99),
    );
    let parent = CapabilityGrant::full();
    let child = CapabilityGrant::sandbox();
    validator.validate_narrowing("p1", "c1", "b1", &parent, &child);
    validator.record_outcome_propagation("b1", BoundaryOutcome::Failure, BoundaryOutcome::Success);
    // Add a widening
    validator.validate_narrowing("c1", "c2", "b2", &child, &parent);

    let report = validator.build_report();
    let json = serde_json::to_string(&report).unwrap();
    let round: NarrowingReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, round);
    assert_eq!(round.total_transitions, 2);
    assert!(!round.is_clean());
}

// ---------------------------------------------------------------------------
// Display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_display_boundary_outcome_unique_strings() {
    let outcomes = [
        BoundaryOutcome::Success,
        BoundaryOutcome::Failure,
        BoundaryOutcome::Timeout,
        BoundaryOutcome::Cancelled,
    ];
    let mut displays = BTreeSet::new();
    for o in outcomes {
        let s = o.to_string();
        assert!(!s.is_empty());
        assert!(
            displays.insert(s.clone()),
            "duplicate Display for {:?}: {}",
            o,
            s
        );
    }
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_display_narrowing_direction_unique_strings() {
    let directions = [
        NarrowingDirection::Narrowed,
        NarrowingDirection::Preserved,
        NarrowingDirection::Widened,
    ];
    let mut displays = BTreeSet::new();
    for d in directions {
        let s = d.to_string();
        assert!(displays.insert(s.clone()), "duplicate Display for {:?}", d);
    }
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_display_capability_token_as_str_all_unique() {
    let all = CapabilityToken::all();
    let mut labels = BTreeSet::new();
    for t in all {
        let s = t.as_str();
        assert!(!s.is_empty());
        assert!(
            labels.insert(s.to_owned()),
            "duplicate as_str for {:?}: {}",
            t,
            s
        );
    }
    assert_eq!(labels.len(), all.len());
}

#[test]
fn enrichment_display_violation_widening_lists_tokens_sorted() {
    let mut widened = BTreeSet::new();
    widened.insert(CapabilityToken::ProcessSpawn);
    widened.insert(CapabilityToken::FileSystemWrite);
    widened.insert(CapabilityToken::NetworkAccess);
    let v = NarrowingViolation::CapabilityWidening {
        boundary_label: "spawn_v2".to_owned(),
        widened_tokens: widened,
    };
    let msg = v.to_string();
    // BTreeSet ordering: FileSystemWrite < NetworkAccess < ProcessSpawn
    let fs_pos = msg.find("fs_write").unwrap();
    let net_pos = msg.find("network").unwrap();
    let proc_pos = msg.find("process_spawn").unwrap();
    assert!(fs_pos < net_pos, "fs_write should appear before network");
    assert!(
        net_pos < proc_pos,
        "network should appear before process_spawn"
    );
}

#[test]
fn enrichment_display_violation_outcome_upgrade_contains_arrow() {
    let v = NarrowingViolation::OutcomeUpgrade {
        boundary_label: "test_boundary".to_owned(),
        child_outcome: BoundaryOutcome::Timeout,
        propagated_outcome: BoundaryOutcome::Success,
    };
    let msg = v.to_string();
    assert!(msg.contains("\u{2192}"), "should contain Unicode arrow");
    assert!(msg.contains("timeout"));
    assert!(msg.contains("success"));
}

// ---------------------------------------------------------------------------
// Struct construction
// ---------------------------------------------------------------------------

#[test]
fn enrichment_struct_capability_grant_none_has_label() {
    let grant = CapabilityGrant::none();
    assert_eq!(grant.label, "none");
    assert!(grant.is_empty());
    assert_eq!(grant.len(), 0);
}

#[test]
fn enrichment_struct_capability_grant_full_has_all_13_tokens() {
    let grant = CapabilityGrant::full();
    assert_eq!(grant.label, "full");
    assert_eq!(grant.len(), 13);
    for token in CapabilityToken::all() {
        assert!(grant.has(*token), "full grant missing {:?}", token);
    }
}

#[test]
fn enrichment_struct_capability_grant_compute_only_exact_tokens() {
    let grant = CapabilityGrant::compute_only();
    assert_eq!(grant.label, "compute_only");
    assert_eq!(grant.len(), 3);
    assert!(grant.has(CapabilityToken::Compute));
    assert!(grant.has(CapabilityToken::TelemetryEmit));
    assert!(grant.has(CapabilityToken::TimerAccess));
    // Must not have any others
    for token in CapabilityToken::all() {
        if !matches!(
            token,
            CapabilityToken::Compute
                | CapabilityToken::TelemetryEmit
                | CapabilityToken::TimerAccess
        ) {
            assert!(
                !grant.has(*token),
                "compute_only should not have {:?}",
                token
            );
        }
    }
}

#[test]
fn enrichment_struct_capability_grant_sandbox_exact_tokens() {
    let grant = CapabilityGrant::sandbox();
    assert_eq!(grant.label, "sandbox");
    assert_eq!(grant.len(), 5);
    let expected = [
        CapabilityToken::Compute,
        CapabilityToken::TelemetryEmit,
        CapabilityToken::TimerAccess,
        CapabilityToken::HostcallInvoke,
        CapabilityToken::ModuleLoad,
    ];
    for t in &expected {
        assert!(grant.has(*t), "sandbox missing {:?}", t);
    }
    for token in CapabilityToken::all() {
        if !expected.contains(token) {
            assert!(!grant.has(*token), "sandbox should not have {:?}", token);
        }
    }
}

#[test]
fn enrichment_struct_validator_with_defaults_epoch_one() {
    let validator = CapabilityNarrowingValidator::with_defaults();
    assert!(validator.transitions().is_empty());
    assert!(validator.violations().is_empty());
    assert!(!validator.has_violations());
    let report = validator.build_report();
    assert_eq!(report.epoch, SecurityEpoch::from_raw(1));
}

#[test]
fn enrichment_struct_validator_custom_epoch() {
    let validator = CapabilityNarrowingValidator::new(
        OutcomePropagationRule::Preserve,
        SecurityEpoch::from_raw(1000),
    );
    let report = validator.build_report();
    assert_eq!(report.epoch, SecurityEpoch::from_raw(1000));
}

// ---------------------------------------------------------------------------
// Lifecycle flows
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lifecycle_multi_level_narrowing_chain() {
    let mut validator = CapabilityNarrowingValidator::with_defaults();
    let full = CapabilityGrant::full();
    let sandbox = CapabilityGrant::sandbox();
    let compute = CapabilityGrant::compute_only();
    let none = CapabilityGrant::none();

    // full -> sandbox -> compute -> none: each step narrows
    let d1 = validator.validate_narrowing("root", "child1", "level_1", &full, &sandbox);
    assert_eq!(d1, NarrowingDirection::Narrowed);

    let d2 = validator.validate_narrowing("child1", "child2", "level_2", &sandbox, &compute);
    assert_eq!(d2, NarrowingDirection::Narrowed);

    let d3 = validator.validate_narrowing("child2", "child3", "level_3", &compute, &none);
    assert_eq!(d3, NarrowingDirection::Narrowed);

    assert!(!validator.has_violations());
    assert_eq!(validator.transitions().len(), 3);

    let report = validator.build_report();
    assert_eq!(*report.direction_counts.get("narrowed").unwrap(), 3);
    assert!(report.is_clean());
}

#[test]
fn enrichment_lifecycle_mixed_narrowing_and_widening() {
    let mut validator = CapabilityNarrowingValidator::with_defaults();
    let full = CapabilityGrant::full();
    let sandbox = CapabilityGrant::sandbox();

    // Valid narrowing
    validator.validate_narrowing("p1", "c1", "step1", &full, &sandbox);
    assert!(!validator.has_violations());

    // Invalid widening
    validator.validate_narrowing("c1", "c2", "step2", &sandbox, &full);
    assert!(validator.has_violations());
    assert_eq!(validator.violations().len(), 1);

    // Another valid narrowing
    validator.validate_narrowing("c2", "c3", "step3", &full, &sandbox);
    assert_eq!(validator.violations().len(), 1); // no new violation

    let report = validator.build_report();
    assert_eq!(report.total_transitions, 3);
    assert_eq!(*report.direction_counts.get("narrowed").unwrap(), 2);
    assert_eq!(*report.direction_counts.get("widened").unwrap(), 1);
    assert!(!report.is_clean());
}

#[test]
fn enrichment_lifecycle_outcome_propagation_across_multiple_boundaries() {
    let mut validator = CapabilityNarrowingValidator::new(
        OutcomePropagationRule::EscalateToMostSevere,
        SecurityEpoch::from_raw(5),
    );
    let parent = CapabilityGrant::full();
    let child = CapabilityGrant::sandbox();

    // Three transitions with outcomes
    validator.validate_narrowing("p1", "c1", "b1", &parent, &child);
    let o1 = validator.record_outcome_propagation(
        "b1",
        BoundaryOutcome::Success,
        BoundaryOutcome::Success,
    );
    assert_eq!(o1, BoundaryOutcome::Success);

    validator.validate_narrowing("p2", "c2", "b2", &parent, &child);
    let o2 = validator.record_outcome_propagation(
        "b2",
        BoundaryOutcome::Failure,
        BoundaryOutcome::Success,
    );
    assert_eq!(o2, BoundaryOutcome::Failure);

    validator.validate_narrowing("p3", "c3", "b3", &parent, &child);
    let o3 = validator.record_outcome_propagation(
        "b3",
        BoundaryOutcome::Cancelled,
        BoundaryOutcome::Failure,
    );
    assert_eq!(o3, BoundaryOutcome::Cancelled);

    let report = validator.build_report();
    assert_eq!(*report.outcome_counts.get("success").unwrap(), 1);
    assert_eq!(*report.outcome_counts.get("failure").unwrap(), 1);
    assert_eq!(*report.outcome_counts.get("cancelled").unwrap(), 1);
    assert!(report.is_clean());
}

#[test]
fn enrichment_lifecycle_collapse_rule_generates_upgrade_violations() {
    let mut validator = CapabilityNarrowingValidator::new(
        OutcomePropagationRule::CollapseToFailure,
        SecurityEpoch::from_raw(1),
    );

    // Timeout (severity 2) -> CollapseToFailure -> Failure (severity 1): upgrade violation
    let result = validator.record_outcome_propagation(
        "boundary_collapse",
        BoundaryOutcome::Timeout,
        BoundaryOutcome::Success,
    );
    assert_eq!(result, BoundaryOutcome::Failure);
    assert!(validator.has_violations());

    // Cancelled (severity 3) -> CollapseToFailure -> Failure (severity 1): upgrade violation
    let result2 = validator.record_outcome_propagation(
        "boundary_collapse_2",
        BoundaryOutcome::Cancelled,
        BoundaryOutcome::Success,
    );
    assert_eq!(result2, BoundaryOutcome::Failure);
    assert_eq!(validator.violations().len(), 2);

    // Failure (severity 1) -> CollapseToFailure -> Failure (severity 1): no upgrade
    let result3 = validator.record_outcome_propagation(
        "boundary_collapse_3",
        BoundaryOutcome::Failure,
        BoundaryOutcome::Success,
    );
    assert_eq!(result3, BoundaryOutcome::Failure);
    assert_eq!(validator.violations().len(), 2); // no new violation
}

#[test]
fn enrichment_lifecycle_severity_threshold_filters_low_severity() {
    let mut validator = CapabilityNarrowingValidator::new(
        OutcomePropagationRule::SeverityThreshold { min_severity: 2 },
        SecurityEpoch::from_raw(1),
    );

    // Success (0) below threshold -> keeps parent
    let r1 = validator.record_outcome_propagation(
        "threshold_test",
        BoundaryOutcome::Success,
        BoundaryOutcome::Failure,
    );
    assert_eq!(r1, BoundaryOutcome::Failure);

    // Failure (1) below threshold -> keeps parent
    let r2 = validator.record_outcome_propagation(
        "threshold_test",
        BoundaryOutcome::Failure,
        BoundaryOutcome::Success,
    );
    assert_eq!(r2, BoundaryOutcome::Success);

    // Timeout (2) meets threshold -> passes through
    let r3 = validator.record_outcome_propagation(
        "threshold_test",
        BoundaryOutcome::Timeout,
        BoundaryOutcome::Success,
    );
    assert_eq!(r3, BoundaryOutcome::Timeout);

    // Cancelled (3) exceeds threshold -> passes through
    let r4 = validator.record_outcome_propagation(
        "threshold_test",
        BoundaryOutcome::Cancelled,
        BoundaryOutcome::Success,
    );
    assert_eq!(r4, BoundaryOutcome::Cancelled);
}

// ---------------------------------------------------------------------------
// Arithmetic and edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_edge_outcome_severity_values_0_to_3() {
    assert_eq!(BoundaryOutcome::Success.severity(), 0);
    assert_eq!(BoundaryOutcome::Failure.severity(), 1);
    assert_eq!(BoundaryOutcome::Timeout.severity(), 2);
    assert_eq!(BoundaryOutcome::Cancelled.severity(), 3);
}

#[test]
fn enrichment_edge_is_failure_class_only_success_is_false() {
    let outcomes = [
        BoundaryOutcome::Success,
        BoundaryOutcome::Failure,
        BoundaryOutcome::Timeout,
        BoundaryOutcome::Cancelled,
    ];
    for o in outcomes {
        if matches!(o, BoundaryOutcome::Success) {
            assert!(!o.is_failure_class());
        } else {
            assert!(o.is_failure_class(), "{:?} should be failure class", o);
        }
    }
}

#[test]
fn enrichment_edge_is_budget_related_only_timeout() {
    let outcomes = [
        BoundaryOutcome::Success,
        BoundaryOutcome::Failure,
        BoundaryOutcome::Timeout,
        BoundaryOutcome::Cancelled,
    ];
    for o in outcomes {
        if matches!(o, BoundaryOutcome::Timeout) {
            assert!(o.is_budget_related());
        } else {
            assert!(
                !o.is_budget_related(),
                "{:?} should not be budget related",
                o
            );
        }
    }
}

#[test]
fn enrichment_edge_intersect_is_commutative_in_tokens() {
    let sandbox = CapabilityGrant::sandbox();
    let mut custom = CapabilityGrant::none();
    custom.tokens.insert(CapabilityToken::HostcallInvoke);
    custom.tokens.insert(CapabilityToken::NetworkAccess);
    custom.tokens.insert(CapabilityToken::Compute);
    custom.label = "custom".to_owned();

    let a_inter_b = sandbox.intersect(&custom);
    let b_inter_a = custom.intersect(&sandbox);

    // Tokens should be identical regardless of order
    assert_eq!(a_inter_b.tokens, b_inter_a.tokens);
    // But labels differ because composition order matters
    assert_eq!(a_inter_b.label, "sandbox\u{2229}custom");
    assert_eq!(b_inter_a.label, "custom\u{2229}sandbox");
}

#[test]
fn enrichment_edge_difference_full_minus_none_is_all() {
    let full = CapabilityGrant::full();
    let none = CapabilityGrant::none();
    let diff = full.difference(&none);
    assert_eq!(diff.len(), 13);
    for token in CapabilityToken::all() {
        assert!(diff.contains(token));
    }
}

#[test]
fn enrichment_edge_difference_none_minus_full_is_empty() {
    let full = CapabilityGrant::full();
    let none = CapabilityGrant::none();
    let diff = none.difference(&full);
    assert!(diff.is_empty());
}

#[test]
fn enrichment_edge_escalate_cancelled_always_wins() {
    let rule = OutcomePropagationRule::EscalateToMostSevere;
    let outcomes = [
        BoundaryOutcome::Success,
        BoundaryOutcome::Failure,
        BoundaryOutcome::Timeout,
        BoundaryOutcome::Cancelled,
    ];
    for parent in outcomes {
        let result = rule.apply(BoundaryOutcome::Cancelled, parent);
        assert_eq!(
            result,
            BoundaryOutcome::Cancelled,
            "Cancelled child should always win against {:?}",
            parent
        );
    }
}

#[test]
fn enrichment_edge_preserve_ignores_parent_current() {
    let rule = OutcomePropagationRule::Preserve;
    let outcomes = [
        BoundaryOutcome::Success,
        BoundaryOutcome::Failure,
        BoundaryOutcome::Timeout,
        BoundaryOutcome::Cancelled,
    ];
    for child in outcomes {
        for parent in outcomes {
            let result = rule.apply(child, parent);
            assert_eq!(
                result, child,
                "Preserve should always return child {:?}, got {:?}",
                child, result
            );
        }
    }
}

#[test]
fn enrichment_edge_validator_sequence_starts_at_one() {
    let mut validator = CapabilityNarrowingValidator::with_defaults();
    let caps = CapabilityGrant::sandbox();
    validator.validate_narrowing("p", "c", "first", &caps, &caps);
    assert_eq!(validator.transitions()[0].sequence, 1);
}

#[test]
fn enrichment_edge_validator_many_transitions_sequence_integrity() {
    let mut validator = CapabilityNarrowingValidator::with_defaults();
    let caps = CapabilityGrant::full();
    let child = CapabilityGrant::sandbox();

    for i in 0..20 {
        validator.validate_narrowing(
            &format!("p{}", i),
            &format!("c{}", i),
            &format!("b{}", i),
            &caps,
            &child,
        );
    }

    let sequences: Vec<u64> = validator.transitions().iter().map(|t| t.sequence).collect();
    for (i, seq) in sequences.iter().enumerate() {
        assert_eq!(*seq, (i + 1) as u64, "sequence mismatch at index {}", i);
    }
}

// ---------------------------------------------------------------------------
// Content hash determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_hash_empty_validator_deterministic() {
    let r1 = CapabilityNarrowingValidator::with_defaults().build_report();
    let r2 = CapabilityNarrowingValidator::with_defaults().build_report();
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_hash_same_operations_same_hash() {
    let build = || {
        let mut v = CapabilityNarrowingValidator::new(
            OutcomePropagationRule::EscalateToMostSevere,
            SecurityEpoch::from_raw(7),
        );
        let parent = CapabilityGrant::full();
        let child = CapabilityGrant::sandbox();
        v.validate_narrowing("p1", "c1", "b1", &parent, &child);
        v.record_outcome_propagation("b1", BoundaryOutcome::Timeout, BoundaryOutcome::Success);
        v.validate_narrowing("p2", "c2", "b2", &parent, &child);
        v.record_outcome_propagation("b2", BoundaryOutcome::Success, BoundaryOutcome::Success);
        v.build_report()
    };
    let r1 = build();
    let r2 = build();
    assert_eq!(r1.content_hash, r2.content_hash);
    assert_eq!(r1, r2);
}

#[test]
fn enrichment_hash_different_violation_count_different_hash() {
    let clean = {
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
    let dirty = {
        let mut v = CapabilityNarrowingValidator::with_defaults();
        v.validate_narrowing(
            "p",
            "c",
            "b",
            &CapabilityGrant::sandbox(),
            &CapabilityGrant::full(),
        );
        v.build_report()
    };
    assert_ne!(clean.content_hash, dirty.content_hash);
    assert!(clean.is_clean());
    assert!(!dirty.is_clean());
}

#[test]
fn enrichment_hash_different_transition_count_different_hash() {
    let one_transition = {
        let mut v = CapabilityNarrowingValidator::with_defaults();
        v.validate_narrowing(
            "p",
            "c",
            "b1",
            &CapabilityGrant::full(),
            &CapabilityGrant::sandbox(),
        );
        v.build_report()
    };
    let two_transitions = {
        let mut v = CapabilityNarrowingValidator::with_defaults();
        v.validate_narrowing(
            "p",
            "c",
            "b1",
            &CapabilityGrant::full(),
            &CapabilityGrant::sandbox(),
        );
        v.validate_narrowing(
            "p",
            "c",
            "b2",
            &CapabilityGrant::full(),
            &CapabilityGrant::sandbox(),
        );
        v.build_report()
    };
    assert_ne!(one_transition.content_hash, two_transitions.content_hash);
}

#[test]
fn enrichment_hash_report_rebuild_stable() {
    let mut v = CapabilityNarrowingValidator::new(
        OutcomePropagationRule::CollapseToFailure,
        SecurityEpoch::from_raw(42),
    );
    v.validate_narrowing(
        "p",
        "c",
        "test",
        &CapabilityGrant::full(),
        &CapabilityGrant::compute_only(),
    );
    v.record_outcome_propagation("test", BoundaryOutcome::Cancelled, BoundaryOutcome::Success);

    let r1 = v.build_report();
    let r2 = v.build_report();
    let r3 = v.build_report();
    assert_eq!(r1.content_hash, r2.content_hash);
    assert_eq!(r2.content_hash, r3.content_hash);
}

// ---------------------------------------------------------------------------
// Report structure
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_direction_counts_reflect_all_directions() {
    let mut v = CapabilityNarrowingValidator::with_defaults();
    let full = CapabilityGrant::full();
    let sandbox = CapabilityGrant::sandbox();

    // Narrowed
    v.validate_narrowing("p1", "c1", "narrow1", &full, &sandbox);
    v.validate_narrowing("p2", "c2", "narrow2", &full, &sandbox);
    // Preserved
    v.validate_narrowing("p3", "c3", "preserve1", &sandbox, &sandbox);
    // Widened
    v.validate_narrowing("p4", "c4", "widen1", &sandbox, &full);

    let report = v.build_report();
    assert_eq!(report.total_transitions, 4);
    assert_eq!(*report.direction_counts.get("narrowed").unwrap(), 2);
    assert_eq!(*report.direction_counts.get("preserved").unwrap(), 1);
    assert_eq!(*report.direction_counts.get("widened").unwrap(), 1);
}

#[test]
fn enrichment_report_outcome_counts_only_count_child_outcomes() {
    let mut v = CapabilityNarrowingValidator::with_defaults();
    let full = CapabilityGrant::full();
    let sandbox = CapabilityGrant::sandbox();

    // Transition with no outcome recorded
    v.validate_narrowing("p1", "c1", "no_outcome", &full, &sandbox);

    // Transition with outcome
    v.validate_narrowing("p2", "c2", "with_outcome", &full, &sandbox);
    v.record_outcome_propagation(
        "with_outcome",
        BoundaryOutcome::Timeout,
        BoundaryOutcome::Success,
    );

    let report = v.build_report();
    assert_eq!(report.total_transitions, 2);
    // Only one outcome was recorded
    let total_outcomes: u64 = report.outcome_counts.values().sum();
    assert_eq!(total_outcomes, 1);
    assert_eq!(*report.outcome_counts.get("timeout").unwrap(), 1);
}

// ---------------------------------------------------------------------------
// Capability subset lattice
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lattice_subset_reflexive() {
    let grants = [
        CapabilityGrant::none(),
        CapabilityGrant::compute_only(),
        CapabilityGrant::sandbox(),
        CapabilityGrant::full(),
    ];
    for grant in &grants {
        assert!(
            grant.is_subset_of(grant),
            "{} should be subset of itself",
            grant.label
        );
    }
}

#[test]
fn enrichment_lattice_subset_chain() {
    // none < compute_only < sandbox < full
    let none = CapabilityGrant::none();
    let compute = CapabilityGrant::compute_only();
    let sandbox = CapabilityGrant::sandbox();
    let full = CapabilityGrant::full();

    assert!(none.is_subset_of(&compute));
    assert!(compute.is_subset_of(&sandbox));
    assert!(sandbox.is_subset_of(&full));

    // Transitivity
    assert!(none.is_subset_of(&sandbox));
    assert!(none.is_subset_of(&full));
    assert!(compute.is_subset_of(&full));

    // Anti-symmetry (strict proper subsets)
    assert!(!compute.is_subset_of(&none));
    assert!(!sandbox.is_subset_of(&compute));
    assert!(!full.is_subset_of(&sandbox));
}

#[test]
fn enrichment_lattice_intersect_with_self_is_self_tokens() {
    let sandbox = CapabilityGrant::sandbox();
    let result = sandbox.intersect(&sandbox);
    assert_eq!(result.tokens, sandbox.tokens);
}
