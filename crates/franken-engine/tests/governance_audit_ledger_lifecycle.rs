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

use frankenengine_engine::moonshot_contract::MoonshotStage;
use frankenengine_engine::portfolio_governor::governance_audit_ledger::{
    GovernanceActor, GovernanceAuditLedger, GovernanceDecisionType, GovernanceLedgerConfig,
    GovernanceLedgerInput, GovernanceLedgerQuery, GovernanceRationale, ScorecardSnapshot,
};
use frankenengine_engine::portfolio_governor::{GovernorDecision, GovernorDecisionKind, Scorecard};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn sample_scorecard() -> Scorecard {
    Scorecard {
        moonshot_id: "moon-it-1".to_string(),
        ev_millionths: 900_000,
        confidence_millionths: 880_000,
        risk_of_harm_millionths: 140_000,
        implementation_friction_millionths: 110_000,
        cross_initiative_interference_millionths: 70_000,
        operational_burden_millionths: 220_000,
        computed_at_ns: 10,
        epoch: SecurityEpoch::from_raw(3),
    }
}

fn ledger() -> GovernanceAuditLedger {
    GovernanceAuditLedger::new(GovernanceLedgerConfig {
        checkpoint_interval: 2,
        signer_key: b"governance-it-key".to_vec(),
        policy_id: "moonshot-governor-policy-it".to_string(),
    })
    .expect("ledger should initialize")
}

#[test]
fn lifecycle_records_automatic_and_override_entries_with_query_and_report_support() {
    let mut ledger = ledger();

    let promote = GovernorDecision {
        decision_id: "auto-1".to_string(),
        moonshot_id: "moon-it-1".to_string(),
        kind: GovernorDecisionKind::Promote {
            from: MoonshotStage::Research,
            to: MoonshotStage::Shadow,
        },
        scorecard: sample_scorecard(),
        timestamp_ns: 100,
        epoch: SecurityEpoch::from_raw(3),
        rationale: "all gate criteria met".to_string(),
    };
    ledger
        .append_governor_decision(
            &promote,
            GovernanceActor::System("portfolio-governor".to_string()),
            vec!["artifact://scorecard/auto-1".to_string()],
            Some(10),
        )
        .expect("automatic append");

    ledger
        .append(GovernanceLedgerInput {
            decision_id: "ovr-1".to_string(),
            moonshot_id: "moon-it-1".to_string(),
            decision_type: GovernanceDecisionType::Override,
            actor: GovernanceActor::Human("operator-17".to_string()),
            rationale: GovernanceRationale {
                summary: "override hold due external incident context".to_string(),
                passed_criteria: vec!["artifact_obligations_met".to_string()],
                failed_criteria: vec!["risk_threshold".to_string()],
                confidence_millionths: 760_000,
                risk_of_harm_millionths: 260_000,
                bypassed_risk_criteria: vec!["risk_of_harm <= 200_000".to_string()],
                acknowledged_bypass: true,
            },
            scorecard_snapshot: ScorecardSnapshot::from(&sample_scorecard()),
            artifact_references: vec!["artifact://override/ovr-1".to_string()],
            timestamp_ns: 200,
            moonshot_started_at_ns: Some(10),
        })
        .expect("override append");

    ledger.verify_chain().expect("chain integrity");
    assert_eq!(ledger.entries().len(), 2);
    assert_eq!(ledger.checkpoints().len(), 1);

    let mut decision_types = BTreeSet::new();
    decision_types.insert(GovernanceDecisionType::Override);
    let rows = ledger.query(&GovernanceLedgerQuery {
        moonshot_id: Some("moon-it-1".to_string()),
        decision_types: Some(decision_types),
        actor_id: Some("operator-17".to_string()),
        start_time_ns: Some(150),
        end_time_ns: Some(220),
        override_only: Some(true),
    });
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].decision_id, "ovr-1");

    let report = ledger
        .governance_report(0, 1_000, 500)
        .expect("report generation");
    assert_eq!(report.total_decisions, 2);
    assert_eq!(report.override_count, 1);
    assert_eq!(report.override_frequency_millionths, 500_000);
    assert_eq!(report.mean_time_to_decision_ns, Some(140));
}

#[test]
fn append_failure_emits_stable_structured_event_fields() {
    let mut ledger = ledger();
    let err = ledger
        .append(GovernanceLedgerInput {
            decision_id: "ovr-bad".to_string(),
            moonshot_id: "moon-it-1".to_string(),
            decision_type: GovernanceDecisionType::Override,
            actor: GovernanceActor::Human("operator-17".to_string()),
            rationale: GovernanceRationale {
                summary: "bad override".to_string(),
                passed_criteria: Vec::new(),
                failed_criteria: Vec::new(),
                confidence_millionths: 700_000,
                risk_of_harm_millionths: 300_000,
                bypassed_risk_criteria: vec!["risk".to_string()],
                acknowledged_bypass: false,
            },
            scorecard_snapshot: ScorecardSnapshot::from(&sample_scorecard()),
            artifact_references: Vec::new(),
            timestamp_ns: 300,
            moonshot_started_at_ns: Some(10),
        })
        .expect_err("invalid override should fail");

    assert_eq!(err.code(), "FE-GOV-LED-0002");
    let event = ledger.events().last().expect("error event");
    assert_eq!(event.trace_id, "trace:ovr-bad");
    assert_eq!(event.decision_id, "ovr-bad");
    assert_eq!(event.policy_id, "moonshot-governor-policy-it");
    assert_eq!(event.component, "governance_audit_ledger");
    assert_eq!(event.event, "append_decision");
    assert_eq!(event.outcome, "rejected");
    assert_eq!(event.error_code.as_deref(), Some("FE-GOV-LED-0002"));
}

// ────────────────────────────────────────────────────────────
// Enrichment: query, report, chain integrity, serde, actors
// ────────────────────────────────────────────────────────────

#[test]
fn empty_ledger_has_no_entries_or_checkpoints() {
    let ledger = ledger();
    assert!(ledger.entries().is_empty());
    assert!(ledger.checkpoints().is_empty());
    assert!(ledger.events().is_empty());
    assert!(ledger.latest_entry().is_none());
    assert!(ledger.latest_checkpoint().is_none());
}

#[test]
fn empty_ledger_chain_verification_succeeds() {
    let ledger = ledger();
    ledger.verify_chain().expect("empty chain should verify");
}

#[test]
fn query_all_returns_all_entries() {
    let mut ledger = ledger();

    let promote = GovernorDecision {
        decision_id: "auto-q1".to_string(),
        moonshot_id: "moon-q1".to_string(),
        kind: GovernorDecisionKind::Promote {
            from: MoonshotStage::Research,
            to: MoonshotStage::Shadow,
        },
        scorecard: sample_scorecard(),
        timestamp_ns: 100,
        epoch: SecurityEpoch::from_raw(3),
        rationale: "gate met".to_string(),
    };
    ledger
        .append_governor_decision(
            &promote,
            GovernanceActor::System("portfolio-governor".to_string()),
            vec!["artifact://q1".to_string()],
            Some(10),
        )
        .expect("append");

    let all = ledger.query(&GovernanceLedgerQuery::all());
    assert_eq!(all.len(), 1);
}

#[test]
fn query_by_moonshot_id_filters_correctly() {
    let mut ledger = ledger();

    for (i, moonshot) in ["moon-a", "moon-b"].iter().enumerate() {
        let decision = GovernorDecision {
            decision_id: format!("auto-{i}"),
            moonshot_id: moonshot.to_string(),
            kind: GovernorDecisionKind::Promote {
                from: MoonshotStage::Research,
                to: MoonshotStage::Shadow,
            },
            scorecard: sample_scorecard(),
            timestamp_ns: (100 + i as u64) * 10,
            epoch: SecurityEpoch::from_raw(3),
            rationale: "gate met".to_string(),
        };
        ledger
            .append_governor_decision(
                &decision,
                GovernanceActor::System("gov".to_string()),
                vec![],
                Some(10),
            )
            .expect("append");
    }

    let query = GovernanceLedgerQuery {
        moonshot_id: Some("moon-b".to_string()),
        ..GovernanceLedgerQuery::all()
    };
    let results = ledger.query(&query);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].moonshot_id, "moon-b");
}

#[test]
fn governance_actor_is_human() {
    let human = GovernanceActor::Human("operator".to_string());
    assert!(human.is_human());
    assert_eq!(human.actor_id(), "operator");

    let system = GovernanceActor::System("portfolio-governor".to_string());
    assert!(!system.is_human());
    assert_eq!(system.actor_id(), "portfolio-governor");
}

#[test]
fn governance_decision_type_serde_round_trip() {
    for dtype in [
        GovernanceDecisionType::Promote,
        GovernanceDecisionType::Override,
    ] {
        let json = serde_json::to_string(&dtype).expect("serialize");
        let recovered: GovernanceDecisionType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(dtype, recovered);
    }
}

#[test]
fn governance_rationale_for_automatic_decision() {
    let rationale = GovernanceRationale::for_automatic_decision(
        "all criteria met",
        850_000,
        150_000,
        vec!["ev_threshold".to_string(), "confidence".to_string()],
        vec![],
    );
    assert_eq!(rationale.summary, "all criteria met");
    assert_eq!(rationale.passed_criteria.len(), 2);
    assert!(rationale.failed_criteria.is_empty());
    assert!(rationale.bypassed_risk_criteria.is_empty());
    assert!(!rationale.acknowledged_bypass);
}

#[test]
fn latest_entry_and_checkpoint_after_appends() {
    let mut ledger = ledger();

    // Append 3 entries; config has checkpoint_interval=2
    for i in 0..3 {
        let decision = GovernorDecision {
            decision_id: format!("d-{i}"),
            moonshot_id: "moon-latest".to_string(),
            kind: GovernorDecisionKind::Promote {
                from: MoonshotStage::Research,
                to: MoonshotStage::Shadow,
            },
            scorecard: sample_scorecard(),
            timestamp_ns: 100 + i * 100,
            epoch: SecurityEpoch::from_raw(3),
            rationale: "gate met".to_string(),
        };
        ledger
            .append_governor_decision(
                &decision,
                GovernanceActor::System("gov".to_string()),
                vec![],
                Some(10),
            )
            .expect("append");
    }

    let latest = ledger.latest_entry().expect("should have entries");
    assert_eq!(latest.decision_id, "d-2");

    // With checkpoint_interval=2 and 3 entries, at least 1 checkpoint
    assert!(!ledger.checkpoints().is_empty());
    assert!(ledger.latest_checkpoint().is_some());
}

#[test]
fn governance_report_on_empty_ledger() {
    let ledger = ledger();
    let report = ledger
        .governance_report(0, 1_000, 500)
        .expect("report on empty");
    assert_eq!(report.total_decisions, 0);
    assert_eq!(report.override_count, 0);
}

#[test]
fn scorecard_snapshot_from_scorecard() {
    let sc = sample_scorecard();
    let snap = ScorecardSnapshot::from(&sc);
    assert_eq!(snap.ev_millionths, sc.ev_millionths);
    assert_eq!(snap.confidence_millionths, sc.confidence_millionths);
    assert_eq!(snap.risk_of_harm_millionths, sc.risk_of_harm_millionths);
}

#[test]
fn governance_actor_serde_roundtrip() {
    for actor in [
        GovernanceActor::Human("operator-1".to_string()),
        GovernanceActor::System("portfolio-governor".to_string()),
    ] {
        let json = serde_json::to_string(&actor).expect("serialize");
        let recovered: GovernanceActor = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(actor.actor_id(), recovered.actor_id());
        assert_eq!(actor.is_human(), recovered.is_human());
    }
}

#[test]
fn governance_ledger_query_all_returns_default_none_fields() {
    let query = GovernanceLedgerQuery::all();
    assert!(query.moonshot_id.is_none());
    assert!(query.decision_types.is_none());
    assert!(query.actor_id.is_none());
    assert!(query.start_time_ns.is_none());
    assert!(query.end_time_ns.is_none());
    assert!(query.override_only.is_none());
}

#[test]
fn sample_scorecard_has_valid_field_ranges() {
    let sc = sample_scorecard();
    assert!(sc.ev_millionths <= 1_000_000);
    assert!(sc.confidence_millionths <= 1_000_000);
    assert!(sc.risk_of_harm_millionths <= 1_000_000);
    assert!(!sc.moonshot_id.is_empty());
}

#[test]
fn governance_decision_type_serde_extended_variants() {
    for dt in [
        GovernanceDecisionType::Pause,
        GovernanceDecisionType::Resume,
        GovernanceDecisionType::Override,
    ] {
        let json = serde_json::to_string(&dt).expect("serialize");
        let recovered: GovernanceDecisionType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(dt, recovered);
    }
}

#[test]
fn governance_actor_serde_round_trip() {
    let actor = GovernanceActor::System("sys-001".to_string());
    let json = serde_json::to_string(&actor).expect("serialize");
    let recovered: GovernanceActor = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(actor, recovered);
}

#[test]
fn governance_decision_type_display_is_non_empty() {
    for dt in [
        GovernanceDecisionType::Promote,
        GovernanceDecisionType::Hold,
        GovernanceDecisionType::Kill,
    ] {
        assert!(!dt.to_string().is_empty());
    }
}

#[test]
fn governance_ledger_config_default_is_valid() {
    let config = GovernanceLedgerConfig::default();
    assert!(config.checkpoint_interval > 0);
}

#[test]
fn scorecard_snapshot_serde_roundtrip() {
    let snapshot = ScorecardSnapshot::from(&sample_scorecard());
    let json = serde_json::to_string(&snapshot).expect("serialize");
    let recovered: ScorecardSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.ev_millionths, snapshot.ev_millionths);
}

#[test]
fn governance_rationale_serde_roundtrip() {
    let rationale = GovernanceRationale {
        summary: "test rationale".to_string(),
        passed_criteria: vec!["crit-1".to_string()],
        failed_criteria: vec![],
        confidence_millionths: 900_000,
        risk_of_harm_millionths: 100_000,
        bypassed_risk_criteria: vec![],
        acknowledged_bypass: false,
    };
    let json = serde_json::to_string(&rationale).expect("serialize");
    let recovered: GovernanceRationale = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.summary, "test rationale");
}

#[test]
fn governance_decision_type_debug_is_nonempty() {
    for dt in [
        GovernanceDecisionType::Promote,
        GovernanceDecisionType::Override,
        GovernanceDecisionType::Pause,
        GovernanceDecisionType::Resume,
        GovernanceDecisionType::Hold,
    ] {
        assert!(!format!("{dt:?}").is_empty());
    }
}

#[test]
fn governance_actor_debug_is_nonempty() {
    let actor = GovernanceActor::System("test-actor".to_string());
    assert!(!format!("{actor:?}").is_empty());
}

#[test]
fn governance_ledger_config_serde_roundtrip() {
    let config = GovernanceLedgerConfig::default();
    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: GovernanceLedgerConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(serde_json::to_string(&recovered).unwrap(), json);
}

// ────────────────────────────────────────────────────────────
// Enrichment: edge-case coverage for query, chain, report,
// duplicate rejection, serde, and bypass validation
// ────────────────────────────────────────────────────────────

#[test]
fn query_with_time_range_excluding_all_entries_returns_empty() {
    let mut ledger = ledger();

    // Append two entries at timestamps 500 and 600
    for (i, ts) in [500u64, 600].iter().enumerate() {
        let decision = GovernorDecision {
            decision_id: format!("tr-{i}"),
            moonshot_id: "moon-tr".to_string(),
            kind: GovernorDecisionKind::Promote {
                from: MoonshotStage::Research,
                to: MoonshotStage::Shadow,
            },
            scorecard: sample_scorecard(),
            timestamp_ns: *ts,
            epoch: SecurityEpoch::from_raw(3),
            rationale: "gate met".to_string(),
        };
        ledger
            .append_governor_decision(
                &decision,
                GovernanceActor::System("gov".to_string()),
                vec![],
                Some(10),
            )
            .expect("append");
    }
    assert_eq!(ledger.entries().len(), 2);

    // Query a time range that falls entirely before the entries
    let results_before = ledger.query(&GovernanceLedgerQuery {
        start_time_ns: Some(0),
        end_time_ns: Some(100),
        ..GovernanceLedgerQuery::all()
    });
    assert!(results_before.is_empty(), "no entries in [0,100]");

    // Query a time range that falls entirely after the entries
    let results_after = ledger.query(&GovernanceLedgerQuery {
        start_time_ns: Some(900),
        end_time_ns: Some(1_000),
        ..GovernanceLedgerQuery::all()
    });
    assert!(results_after.is_empty(), "no entries in [900,1000]");
}

#[test]
fn chain_verification_passes_after_multiple_appends_and_checkpoints() {
    // checkpoint_interval=2, so appending 6 entries produces 3 checkpoints
    let mut ledger = ledger();
    for i in 0u64..6 {
        let decision = GovernorDecision {
            decision_id: format!("chain-{i}"),
            moonshot_id: "moon-chain".to_string(),
            kind: GovernorDecisionKind::Promote {
                from: MoonshotStage::Research,
                to: MoonshotStage::Shadow,
            },
            scorecard: sample_scorecard(),
            timestamp_ns: 100 + i * 100,
            epoch: SecurityEpoch::from_raw(3),
            rationale: "gate met".to_string(),
        };
        ledger
            .append_governor_decision(
                &decision,
                GovernanceActor::System("gov".to_string()),
                vec![format!("artifact://chain/{i}")],
                Some(10),
            )
            .expect("append");
    }
    assert_eq!(ledger.entries().len(), 6);
    assert_eq!(
        ledger.checkpoints().len(),
        3,
        "6 entries / interval 2 = 3 checkpoints"
    );

    // Full chain verification: hashes, signatures, and checkpoint signatures
    ledger
        .verify_chain()
        .expect("chain with 3 checkpoints should verify");

    // Each entry's previous_hash links to the prior entry
    for (idx, entry) in ledger.entries().iter().enumerate() {
        if idx == 0 {
            assert!(entry.previous_hash.is_none());
        } else {
            assert_eq!(
                entry.previous_hash.as_deref(),
                Some(ledger.entries()[idx - 1].entry_hash.as_str())
            );
        }
    }
}

#[test]
fn governance_report_with_only_automatic_decisions_has_zero_override_count() {
    let mut ledger = ledger();

    // Append 3 automatic (non-override) decisions
    for i in 0u64..3 {
        let decision = GovernorDecision {
            decision_id: format!("auto-rpt-{i}"),
            moonshot_id: "moon-rpt".to_string(),
            kind: GovernorDecisionKind::Promote {
                from: MoonshotStage::Research,
                to: MoonshotStage::Shadow,
            },
            scorecard: sample_scorecard(),
            timestamp_ns: 100 + i * 100,
            epoch: SecurityEpoch::from_raw(3),
            rationale: "auto gate".to_string(),
        };
        ledger
            .append_governor_decision(
                &decision,
                GovernanceActor::System("gov".to_string()),
                vec![],
                Some(5),
            )
            .expect("append");
    }

    let report = ledger
        .governance_report(0, 1_000, 500)
        .expect("report generation");
    assert_eq!(report.total_decisions, 3);
    assert_eq!(report.override_count, 0);
    assert_eq!(report.override_frequency_millionths, 0);
    assert_eq!(report.kill_count, 0);
    assert_eq!(report.kill_rate_millionths, 0);
    // All decisions have moonshot_started_at_ns=Some(5), so mean latency is computable
    assert!(report.mean_time_to_decision_ns.is_some());
}

#[test]
fn duplicate_decision_id_append_fails_with_correct_error_code() {
    let mut ledger = ledger();

    let decision = GovernorDecision {
        decision_id: "dup-1".to_string(),
        moonshot_id: "moon-dup".to_string(),
        kind: GovernorDecisionKind::Hold {
            reason: "low signal".to_string(),
        },
        scorecard: sample_scorecard(),
        timestamp_ns: 100,
        epoch: SecurityEpoch::from_raw(3),
        rationale: "hold gate".to_string(),
    };
    ledger
        .append_governor_decision(
            &decision,
            GovernanceActor::System("gov".to_string()),
            vec![],
            Some(10),
        )
        .expect("first append should succeed");

    // Attempt second append with the same decision_id but later timestamp
    let duplicate = GovernorDecision {
        decision_id: "dup-1".to_string(),
        moonshot_id: "moon-dup".to_string(),
        kind: GovernorDecisionKind::Hold {
            reason: "low signal".to_string(),
        },
        scorecard: sample_scorecard(),
        timestamp_ns: 200,
        epoch: SecurityEpoch::from_raw(3),
        rationale: "hold gate again".to_string(),
    };
    let err = ledger
        .append_governor_decision(
            &duplicate,
            GovernanceActor::System("gov".to_string()),
            vec![],
            Some(10),
        )
        .expect_err("duplicate decision_id must be rejected");

    assert_eq!(err.code(), "FE-GOV-LED-0003");
    assert!(err.to_string().contains("dup-1"));
    // Only 1 entry should exist
    assert_eq!(ledger.entries().len(), 1);
}

#[test]
fn governance_ledger_query_serde_roundtrip() {
    let mut decision_types = BTreeSet::new();
    decision_types.insert(GovernanceDecisionType::Override);
    decision_types.insert(GovernanceDecisionType::Kill);

    let query = GovernanceLedgerQuery {
        moonshot_id: Some("moon-serde".to_string()),
        decision_types: Some(decision_types),
        actor_id: Some("operator-42".to_string()),
        start_time_ns: Some(100),
        end_time_ns: Some(999),
        override_only: Some(true),
    };

    let json = serde_json::to_string(&query).expect("serialize query");
    let recovered: GovernanceLedgerQuery = serde_json::from_str(&json).expect("deserialize query");

    assert_eq!(recovered.moonshot_id, query.moonshot_id);
    assert_eq!(recovered.decision_types, query.decision_types);
    assert_eq!(recovered.actor_id, query.actor_id);
    assert_eq!(recovered.start_time_ns, query.start_time_ns);
    assert_eq!(recovered.end_time_ns, query.end_time_ns);
    assert_eq!(recovered.override_only, query.override_only);

    // Also roundtrip the `all()` variant
    let all = GovernanceLedgerQuery::all();
    let all_json = serde_json::to_string(&all).expect("serialize all");
    let all_recovered: GovernanceLedgerQuery =
        serde_json::from_str(&all_json).expect("deserialize all");
    assert_eq!(all_recovered, all);
}

#[test]
fn override_with_bypassed_criteria_but_no_acknowledgment_is_rejected() {
    let mut ledger = ledger();

    // First append a valid automatic entry so the ledger is not empty
    let auto_decision = GovernorDecision {
        decision_id: "pre-auto".to_string(),
        moonshot_id: "moon-bypass".to_string(),
        kind: GovernorDecisionKind::Promote {
            from: MoonshotStage::Research,
            to: MoonshotStage::Shadow,
        },
        scorecard: sample_scorecard(),
        timestamp_ns: 50,
        epoch: SecurityEpoch::from_raw(3),
        rationale: "gate met".to_string(),
    };
    ledger
        .append_governor_decision(
            &auto_decision,
            GovernanceActor::System("gov".to_string()),
            vec![],
            Some(10),
        )
        .expect("auto append");

    // Attempt an override with bypassed_risk_criteria but acknowledged_bypass=false
    let err = ledger
        .append(GovernanceLedgerInput {
            decision_id: "ovr-noack".to_string(),
            moonshot_id: "moon-bypass".to_string(),
            decision_type: GovernanceDecisionType::Override,
            actor: GovernanceActor::Human("operator-99".to_string()),
            rationale: GovernanceRationale {
                summary: "override without acknowledgment".to_string(),
                passed_criteria: vec!["ev_threshold".to_string()],
                failed_criteria: vec!["risk_budget".to_string()],
                confidence_millionths: 750_000,
                risk_of_harm_millionths: 280_000,
                bypassed_risk_criteria: vec!["risk_of_harm <= 200_000".to_string()],
                acknowledged_bypass: false,
            },
            scorecard_snapshot: ScorecardSnapshot::from(&sample_scorecard()),
            artifact_references: vec!["artifact://override/noack".to_string()],
            timestamp_ns: 100,
            moonshot_started_at_ns: Some(10),
        })
        .expect_err("override without acknowledged_bypass must fail validation");

    // Error code FE-GOV-LED-0002 = InvalidInput
    assert_eq!(err.code(), "FE-GOV-LED-0002");
    assert!(
        err.to_string().contains("acknowledged_bypass")
            || err.to_string().contains("acknowledge bypass"),
        "error message should mention bypass acknowledgment, got: {err}"
    );

    // Ledger should still only have the automatic entry
    assert_eq!(ledger.entries().len(), 1);
    assert_eq!(ledger.entries()[0].decision_id, "pre-auto");
}

#[test]
fn governance_ledger_config_debug_is_nonempty() {
    let config = GovernanceLedgerConfig::default();
    assert!(!format!("{config:?}").is_empty());
}

#[test]
fn scorecard_snapshot_debug_is_nonempty() {
    let snapshot = ScorecardSnapshot::from(&sample_scorecard());
    assert!(!format!("{snapshot:?}").is_empty());
}

#[test]
fn governance_rationale_debug_is_nonempty() {
    let rationale = GovernanceRationale {
        summary: "test".to_string(),
        passed_criteria: vec!["c1".to_string()],
        failed_criteria: vec![],
        confidence_millionths: 500_000,
        risk_of_harm_millionths: 100_000,
        bypassed_risk_criteria: vec![],
        acknowledged_bypass: false,
    };
    assert!(!format!("{rationale:?}").is_empty());
}

// ────────────────────────────────────────────────────────────
// Enrichment: error variants, out-of-order timestamps,
// report serde, ledger serde, GovernanceLogEvent fields
// ────────────────────────────────────────────────────────────

#[test]
fn governance_ledger_error_all_codes_are_unique() {
    use frankenengine_engine::portfolio_governor::governance_audit_ledger::GovernanceLedgerError;
    let errors: Vec<GovernanceLedgerError> = vec![
        GovernanceLedgerError::InvalidConfig {
            reason: "test".into(),
        },
        GovernanceLedgerError::InvalidInput {
            field: "f".into(),
            reason: "r".into(),
        },
        GovernanceLedgerError::DuplicateDecisionId {
            decision_id: "d".into(),
        },
        GovernanceLedgerError::OutOfOrderTimestamp {
            previous_ns: 1,
            new_ns: 0,
        },
        GovernanceLedgerError::SerializationFailed { reason: "s".into() },
        GovernanceLedgerError::HashChainMismatch { sequence: 0 },
        GovernanceLedgerError::SignatureMismatch { sequence: 0 },
        GovernanceLedgerError::EntryHashMismatch { sequence: 0 },
        GovernanceLedgerError::EmptyLedger,
    ];

    let mut codes = BTreeSet::new();
    for err in &errors {
        let code = err.code();
        assert!(codes.insert(code), "duplicate error code: {code}");
        assert!(
            !err.to_string().is_empty(),
            "Display must be non-empty for {code}"
        );
    }
    assert_eq!(codes.len(), 9, "expected 9 unique error codes");
}

#[test]
fn governance_ledger_error_serde_roundtrip() {
    use frankenengine_engine::portfolio_governor::governance_audit_ledger::GovernanceLedgerError;
    let errors: Vec<GovernanceLedgerError> = vec![
        GovernanceLedgerError::InvalidConfig {
            reason: "bad config".into(),
        },
        GovernanceLedgerError::DuplicateDecisionId {
            decision_id: "dup-42".into(),
        },
        GovernanceLedgerError::EmptyLedger,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let recovered: GovernanceLedgerError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, recovered);
    }
}

#[test]
fn out_of_order_timestamp_append_fails() {
    let mut ledger = ledger();

    let d1 = GovernorDecision {
        decision_id: "ooo-1".to_string(),
        moonshot_id: "moon-ooo".to_string(),
        kind: GovernorDecisionKind::Promote {
            from: MoonshotStage::Research,
            to: MoonshotStage::Shadow,
        },
        scorecard: sample_scorecard(),
        timestamp_ns: 500,
        epoch: SecurityEpoch::from_raw(3),
        rationale: "gate met".to_string(),
    };
    ledger
        .append_governor_decision(
            &d1,
            GovernanceActor::System("gov".to_string()),
            vec![],
            Some(10),
        )
        .expect("first append");

    let d2 = GovernorDecision {
        decision_id: "ooo-2".to_string(),
        moonshot_id: "moon-ooo".to_string(),
        kind: GovernorDecisionKind::Hold {
            reason: "signal drop".to_string(),
        },
        scorecard: sample_scorecard(),
        timestamp_ns: 100,
        epoch: SecurityEpoch::from_raw(3),
        rationale: "hold".to_string(),
    };
    let err = ledger
        .append_governor_decision(
            &d2,
            GovernanceActor::System("gov".to_string()),
            vec![],
            Some(10),
        )
        .expect_err("out-of-order timestamp must fail");

    assert_eq!(err.code(), "FE-GOV-LED-0004");
    assert!(err.to_string().contains("500"));
    assert!(err.to_string().contains("100"));
}

#[test]
fn governance_report_serde_roundtrip() {
    let mut ledger = ledger();

    for i in 0u64..4 {
        let decision = GovernorDecision {
            decision_id: format!("rpt-serde-{i}"),
            moonshot_id: "moon-rpt-serde".to_string(),
            kind: GovernorDecisionKind::Promote {
                from: MoonshotStage::Research,
                to: MoonshotStage::Shadow,
            },
            scorecard: sample_scorecard(),
            timestamp_ns: 100 + i * 200,
            epoch: SecurityEpoch::from_raw(3),
            rationale: "gate met".to_string(),
        };
        ledger
            .append_governor_decision(
                &decision,
                GovernanceActor::System("gov".to_string()),
                vec![],
                Some(10),
            )
            .expect("append");
    }

    let report = ledger.governance_report(0, 1_000, 250).expect("report");
    let json = serde_json::to_string(&report).expect("serialize report");
    let recovered: frankenengine_engine::portfolio_governor::governance_audit_ledger::GovernanceReport =
        serde_json::from_str(&json).expect("deserialize report");
    assert_eq!(recovered.total_decisions, report.total_decisions);
    assert_eq!(recovered.override_count, report.override_count);
    assert_eq!(recovered.kill_count, report.kill_count);
}

#[test]
fn governance_log_event_fields_are_populated_on_success() {
    let mut ledger = ledger();

    let decision = GovernorDecision {
        decision_id: "evt-check".to_string(),
        moonshot_id: "moon-evt".to_string(),
        kind: GovernorDecisionKind::Promote {
            from: MoonshotStage::Research,
            to: MoonshotStage::Shadow,
        },
        scorecard: sample_scorecard(),
        timestamp_ns: 100,
        epoch: SecurityEpoch::from_raw(3),
        rationale: "gate met".to_string(),
    };
    ledger
        .append_governor_decision(
            &decision,
            GovernanceActor::System("gov".to_string()),
            vec!["artifact://evt".to_string()],
            Some(10),
        )
        .expect("append");

    let events = ledger.events();
    assert!(!events.is_empty());
    let event = &events[0];
    assert_eq!(event.component, "governance_audit_ledger");
    assert_eq!(event.event, "append_decision");
    assert_eq!(event.outcome, "accepted");
    assert!(event.error_code.is_none());
    assert_eq!(event.decision_id, "evt-check");
    assert!(!event.trace_id.is_empty());
    assert!(!event.policy_id.is_empty());
}

#[test]
fn governance_audit_ledger_serde_roundtrip() {
    let mut ledger = ledger();

    let decision = GovernorDecision {
        decision_id: "led-serde".to_string(),
        moonshot_id: "moon-led".to_string(),
        kind: GovernorDecisionKind::Promote {
            from: MoonshotStage::Research,
            to: MoonshotStage::Shadow,
        },
        scorecard: sample_scorecard(),
        timestamp_ns: 100,
        epoch: SecurityEpoch::from_raw(3),
        rationale: "gate met".to_string(),
    };
    ledger
        .append_governor_decision(
            &decision,
            GovernanceActor::System("gov".to_string()),
            vec![],
            Some(10),
        )
        .expect("append");

    let json = serde_json::to_string(&ledger).expect("serialize ledger");
    let recovered: GovernanceAuditLedger = serde_json::from_str(&json).expect("deserialize ledger");
    assert_eq!(recovered.entries().len(), 1);
    assert_eq!(recovered.entries()[0].decision_id, "led-serde");
    recovered
        .verify_chain()
        .expect("chain should verify after serde");
}

#[test]
fn governance_decision_type_all_variants_display_unique() {
    let variants = [
        GovernanceDecisionType::Promote,
        GovernanceDecisionType::Hold,
        GovernanceDecisionType::Kill,
        GovernanceDecisionType::Pause,
        GovernanceDecisionType::Resume,
        GovernanceDecisionType::Override,
    ];
    let mut display_strings = BTreeSet::new();
    for dt in &variants {
        let s = dt.to_string();
        assert!(!s.is_empty());
        assert!(
            display_strings.insert(s.clone()),
            "duplicate Display for {dt:?}"
        );
    }
    assert_eq!(display_strings.len(), 6);
}

#[test]
fn governance_ledger_entry_hash_and_signature_are_nonempty() {
    let mut ledger = ledger();

    let decision = GovernorDecision {
        decision_id: "hash-check".to_string(),
        moonshot_id: "moon-hash".to_string(),
        kind: GovernorDecisionKind::Promote {
            from: MoonshotStage::Research,
            to: MoonshotStage::Shadow,
        },
        scorecard: sample_scorecard(),
        timestamp_ns: 100,
        epoch: SecurityEpoch::from_raw(3),
        rationale: "gate met".to_string(),
    };
    ledger
        .append_governor_decision(
            &decision,
            GovernanceActor::System("gov".to_string()),
            vec![],
            Some(10),
        )
        .expect("append");

    let entry = ledger.latest_entry().expect("should have entry");
    assert!(!entry.entry_hash.is_empty());
    assert!(!entry.signature.is_empty());
    assert_eq!(entry.decision_id, "hash-check");
}

#[test]
fn governance_report_portfolio_health_trend_populated() {
    let mut ledger = ledger();

    for i in 0u64..4 {
        let decision = GovernorDecision {
            decision_id: format!("health-{i}"),
            moonshot_id: "moon-health".to_string(),
            kind: GovernorDecisionKind::Promote {
                from: MoonshotStage::Research,
                to: MoonshotStage::Shadow,
            },
            scorecard: sample_scorecard(),
            timestamp_ns: 100 + i * 200,
            epoch: SecurityEpoch::from_raw(3),
            rationale: "gate met".to_string(),
        };
        ledger
            .append_governor_decision(
                &decision,
                GovernanceActor::System("gov".to_string()),
                vec![],
                Some(10),
            )
            .expect("append");
    }

    let report = ledger.governance_report(0, 1_000, 200).expect("report");
    assert!(
        !report.portfolio_health_trend.is_empty(),
        "health trend should have entries"
    );
    for point in &report.portfolio_health_trend {
        assert!(point.window_end_ns > point.window_start_ns);
    }
}
