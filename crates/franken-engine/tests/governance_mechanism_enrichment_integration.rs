//! Enrichment integration tests for `governance_mechanism` module.
//!
//! Covers: Display uniqueness for all enums, serde roundtrips for all types,
//! method behavior, edge cases, deterministic hash behavior, full lifecycles,
//! and invariant validation.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::attack_surface_game_model::{
    ActionId, GameModelBuilder, LossDimension, LossEntry, Player, StrategicAction, Subsystem,
};
use frankenengine_engine::governance_mechanism::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ts(tick: u64) -> DeterministicTimestamp {
    DeterministicTimestamp(tick)
}

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn make_report(id: &str, package: &str, severity: i64) -> ExtensionReport {
    ExtensionReport {
        report_id: id.into(),
        package_id: package.into(),
        reporter_id: "reporter-1".into(),
        phase: ReportPhase::Submitted,
        evidence_refs: vec!["evidence-1".into()],
        loss_dimension: LossDimension::UserHarm,
        severity_millionths: severity,
        submitted_at: ts(1000),
        resolved_at: None,
    }
}

fn make_quarantine(id: &str, package: &str, report_id: &str) -> QuarantineRecord {
    QuarantineRecord {
        quarantine_id: id.into(),
        package_id: package.into(),
        status: QuarantineStatus::Active,
        trigger_report_id: report_id.into(),
        hard_constraints: vec!["no-network".into()],
        quarantined_at: ts(2000),
        lifted_at: None,
    }
}

fn make_challenge(ch_id: &str, report_id: &str) -> ChallengeRecord {
    ChallengeRecord {
        challenge_id: ch_id.into(),
        report_id: report_id.into(),
        challenger_id: "challenger-1".into(),
        outcome: None,
        rationale: "disagree with severity".into(),
        game_model_id: "model-1".into(),
        minimax_action: None,
        submitted_at: ts(3000),
        resolved_at: None,
    }
}

fn make_reinstate(req_id: &str, quarantine_id: &str) -> ReinstateRequest {
    ReinstateRequest {
        request_id: req_id.into(),
        quarantine_id: quarantine_id.into(),
        justification: "fixed vulnerability".into(),
        compliance_evidence_id: Some("evidence-fix".into()),
        submitted_at: ts(5000),
        approved: None,
    }
}

fn make_game_model(subsystem: Subsystem) -> frankenengine_engine::attack_surface_game_model::GameModel {
    let ep = epoch(100);
    let atk = StrategicAction {
        action_id: ActionId("atk_inject".into()),
        player: Player::Attacker,
        subsystem,
        description: "inject malicious payload".into(),
        admissible: true,
        constraints: vec![],
    };
    let def = StrategicAction {
        action_id: ActionId("def_quarantine".into()),
        player: Player::Defender,
        subsystem,
        description: "quarantine extension".into(),
        admissible: true,
        constraints: vec![],
    };
    let loss = LossEntry {
        attacker_action: ActionId("atk_inject".into()),
        defender_action: ActionId("def_quarantine".into()),
        dimension: LossDimension::UserHarm,
        loss_millionths: 500_000,
    };
    GameModelBuilder::new(subsystem, ep)
        .attacker_action(atk)
        .defender_action(def)
        .loss(loss)
        .build()
}

fn make_game_model_with_loss(subsystem: Subsystem, loss_value: i64) -> frankenengine_engine::attack_surface_game_model::GameModel {
    let ep = epoch(100);
    let atk = StrategicAction {
        action_id: ActionId("atk_probe".into()),
        player: Player::Attacker,
        subsystem,
        description: "probe attack surface".into(),
        admissible: true,
        constraints: vec![],
    };
    let def = StrategicAction {
        action_id: ActionId("def_block".into()),
        player: Player::Defender,
        subsystem,
        description: "block probe".into(),
        admissible: true,
        constraints: vec![],
    };
    let loss = LossEntry {
        attacker_action: ActionId("atk_probe".into()),
        defender_action: ActionId("def_block".into()),
        dimension: LossDimension::PerformanceCost,
        loss_millionths: loss_value,
    };
    GameModelBuilder::new(subsystem, ep)
        .attacker_action(atk)
        .defender_action(def)
        .loss(loss)
        .build()
}

// ---------------------------------------------------------------------------
// Display uniqueness tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_phase_display_uniqueness() {
    let phases = [
        ReportPhase::Submitted,
        ReportPhase::UnderReview,
        ReportPhase::Resolved,
        ReportPhase::Dismissed,
    ];
    let displays: BTreeSet<String> = phases.iter().map(|p| p.to_string()).collect();
    assert_eq!(displays.len(), 4, "all ReportPhase variants must have unique Display");
}

#[test]
fn enrichment_challenge_outcome_display_uniqueness() {
    let outcomes = [
        ChallengeOutcome::Upheld,
        ChallengeOutcome::Rejected,
        ChallengeOutcome::Escalated,
    ];
    let displays: BTreeSet<String> = outcomes.iter().map(|o| o.to_string()).collect();
    assert_eq!(displays.len(), 3, "all ChallengeOutcome variants must have unique Display");
}

#[test]
fn enrichment_quarantine_status_display_uniqueness() {
    let statuses = [
        QuarantineStatus::Active,
        QuarantineStatus::Lifted,
        QuarantineStatus::Expired,
    ];
    let displays: BTreeSet<String> = statuses.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), 3, "all QuarantineStatus variants must have unique Display");
}

#[test]
fn enrichment_incentive_compatibility_class_display_uniqueness() {
    let classes = [
        IncentiveCompatibilityClass::DominantStrategy,
        IncentiveCompatibilityClass::BayesNash,
        IncentiveCompatibilityClass::ExPostRational,
        IncentiveCompatibilityClass::NonCompliant,
    ];
    let displays: BTreeSet<String> = classes.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), 4, "all IncentiveCompatibilityClass variants must have unique Display");
}

#[test]
fn enrichment_mechanism_error_display_uniqueness_all_variants() {
    let errors = [
        MechanismError::InvalidInput {
            field: "alpha".into(),
            detail: "bad".into(),
        },
        MechanismError::GameModelMissing {
            subsystem: "beta".into(),
        },
        MechanismError::IncentiveViolation {
            reason: "gamma".into(),
        },
        MechanismError::QuarantineConstraintViolated {
            package_id: "delta".into(),
            reason: "dup".into(),
        },
        MechanismError::ReinstateNotAllowed {
            quarantine_id: "epsilon".into(),
            reason: "lifted".into(),
        },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), 5, "all 5 MechanismError variants must have unique Display");
}

// ---------------------------------------------------------------------------
// Serde roundtrip tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_phase_serde_roundtrip_all_variants() {
    let variants = [
        ReportPhase::Submitted,
        ReportPhase::UnderReview,
        ReportPhase::Resolved,
        ReportPhase::Dismissed,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: ReportPhase = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_challenge_outcome_serde_roundtrip_all_variants() {
    let variants = [
        ChallengeOutcome::Upheld,
        ChallengeOutcome::Rejected,
        ChallengeOutcome::Escalated,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: ChallengeOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_quarantine_status_serde_roundtrip_all_variants() {
    let variants = [
        QuarantineStatus::Active,
        QuarantineStatus::Lifted,
        QuarantineStatus::Expired,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: QuarantineStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_incentive_compatibility_class_serde_roundtrip_all() {
    let classes = [
        IncentiveCompatibilityClass::DominantStrategy,
        IncentiveCompatibilityClass::BayesNash,
        IncentiveCompatibilityClass::ExPostRational,
        IncentiveCompatibilityClass::NonCompliant,
    ];
    for c in &classes {
        let json = serde_json::to_string(c).unwrap();
        let back: IncentiveCompatibilityClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

#[test]
fn enrichment_mechanism_error_serde_roundtrip_all_variants() {
    let errors = vec![
        MechanismError::InvalidInput {
            field: "f".into(),
            detail: "d".into(),
        },
        MechanismError::GameModelMissing {
            subsystem: "s".into(),
        },
        MechanismError::IncentiveViolation {
            reason: "r".into(),
        },
        MechanismError::QuarantineConstraintViolated {
            package_id: "p".into(),
            reason: "q".into(),
        },
        MechanismError::ReinstateNotAllowed {
            quarantine_id: "qr".into(),
            reason: "not active".into(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: MechanismError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

#[test]
fn enrichment_extension_report_serde_roundtrip() {
    let report = make_report("r-serde", "pkg-serde@1.0", 750_000);
    let json = serde_json::to_string(&report).unwrap();
    let back: ExtensionReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn enrichment_extension_report_serde_with_resolved_at() {
    let mut report = make_report("r-res", "pkg-res@2.0", 600_000);
    report.phase = ReportPhase::Resolved;
    report.resolved_at = Some(ts(9999));
    let json = serde_json::to_string(&report).unwrap();
    let back: ExtensionReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
    assert_eq!(back.resolved_at, Some(ts(9999)));
}

#[test]
fn enrichment_challenge_record_serde_roundtrip_pending() {
    let ch = make_challenge("ch-pend", "r1");
    let json = serde_json::to_string(&ch).unwrap();
    let back: ChallengeRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(ch, back);
    assert!(back.outcome.is_none());
}

#[test]
fn enrichment_challenge_record_serde_roundtrip_resolved() {
    let mut ch = make_challenge("ch-res", "r1");
    ch.outcome = Some(ChallengeOutcome::Escalated);
    ch.resolved_at = Some(ts(8000));
    ch.minimax_action = Some("def_quarantine".into());
    let json = serde_json::to_string(&ch).unwrap();
    let back: ChallengeRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(ch, back);
}

#[test]
fn enrichment_quarantine_record_serde_roundtrip() {
    let q = make_quarantine("q-serde", "pkg-q", "r-q");
    let json = serde_json::to_string(&q).unwrap();
    let back: QuarantineRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(q, back);
}

#[test]
fn enrichment_quarantine_record_serde_lifted() {
    let mut q = make_quarantine("q-lifted", "pkg-l", "r-l");
    q.status = QuarantineStatus::Lifted;
    q.lifted_at = Some(ts(7777));
    let json = serde_json::to_string(&q).unwrap();
    let back: QuarantineRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(q, back);
    assert_eq!(back.lifted_at, Some(ts(7777)));
}

#[test]
fn enrichment_reinstate_request_serde_roundtrip() {
    let req = make_reinstate("req-serde", "q-serde");
    let json = serde_json::to_string(&req).unwrap();
    let back: ReinstateRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

#[test]
fn enrichment_reinstate_request_serde_approved() {
    let mut req = make_reinstate("req-approved", "q-a");
    req.approved = Some(true);
    let json = serde_json::to_string(&req).unwrap();
    let back: ReinstateRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
    assert_eq!(back.approved, Some(true));
}

#[test]
fn enrichment_reinstate_request_serde_denied() {
    let mut req = make_reinstate("req-denied", "q-d");
    req.approved = Some(false);
    req.compliance_evidence_id = None;
    let json = serde_json::to_string(&req).unwrap();
    let back: ReinstateRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
    assert_eq!(back.approved, Some(false));
    assert!(back.compliance_evidence_id.is_none());
}

#[test]
fn enrichment_mechanism_event_serde_roundtrip_with_attributes() {
    let mut attrs = BTreeMap::new();
    attrs.insert("key1".to_string(), "value1".to_string());
    attrs.insert("key2".to_string(), "value2".to_string());
    let event = MechanismEvent {
        kind: "test_event".into(),
        passed: false,
        summary: "a test event with attrs".into(),
        attributes: attrs,
        timestamp: ts(4242),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: MechanismEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
    assert_eq!(back.attributes.len(), 2);
}

#[test]
fn enrichment_mechanism_event_serde_empty_attributes() {
    let event = MechanismEvent {
        kind: "empty_attr_event".into(),
        passed: true,
        summary: "no attributes".into(),
        attributes: BTreeMap::new(),
        timestamp: ts(100),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: MechanismEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
    assert!(back.attributes.is_empty());
}

#[test]
fn enrichment_incentive_analysis_serde_roundtrip() {
    let mut mech = GovernanceMechanism::new(epoch(100));
    let model = make_game_model(Subsystem::ExtensionHost);
    let analysis = mech.analyze_incentive_compatibility(&model, ts(1000));
    let json = serde_json::to_string(&analysis).unwrap();
    let back: IncentiveAnalysis = serde_json::from_str(&json).unwrap();
    assert_eq!(analysis, back);
}

#[test]
fn enrichment_enforcement_policy_serde_roundtrip() {
    let mut mech = GovernanceMechanism::new(epoch(100));
    let model = make_game_model(Subsystem::Runtime);
    mech.analyze_incentive_compatibility(&model, ts(1000));
    let policy = mech
        .compile_enforcement_policy(Subsystem::Runtime, "pol-serde", ts(2000))
        .unwrap();
    let json = serde_json::to_string(&policy).unwrap();
    let back: EnforcementPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn enrichment_mechanism_report_serde_roundtrip() {
    let mut mech = GovernanceMechanism::new(epoch(200));
    mech.submit_report(make_report("r1", "pkg-a", 400_000))
        .unwrap();
    let report = mech.generate_report();
    let json = serde_json::to_string(&report).unwrap();
    let back: MechanismReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn enrichment_governance_mechanism_serde_roundtrip_full() {
    let mut mech = GovernanceMechanism::new(epoch(300));
    mech.submit_report(make_report("r1", "pkg-a", 500_000))
        .unwrap();
    mech.impose_quarantine(make_quarantine("q1", "pkg-a", "r1"))
        .unwrap();
    let model = make_game_model(Subsystem::Compiler);
    mech.analyze_incentive_compatibility(&model, ts(2000));
    mech.compile_enforcement_policy(Subsystem::Compiler, "pol-full", ts(3000))
        .unwrap();

    let json = serde_json::to_string(&mech).unwrap();
    let back: GovernanceMechanism = serde_json::from_str(&json).unwrap();
    assert_eq!(back.epoch(), epoch(300));
    assert_eq!(back.reports().len(), 1);
    assert_eq!(back.quarantines().len(), 1);
    assert_eq!(back.analyses().len(), 1);
    assert_eq!(back.policies().len(), 1);
}

// ---------------------------------------------------------------------------
// Schema version constant
// ---------------------------------------------------------------------------

#[test]
fn enrichment_schema_version_constant_value() {
    assert_eq!(SCHEMA_VERSION, "franken-engine.governance-mechanism.v1");
}

#[test]
fn enrichment_schema_version_in_generated_report() {
    let mech = GovernanceMechanism::new(epoch(1));
    let report = mech.generate_report();
    assert_eq!(report.schema_version, SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// Report submission edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_submit_report_empty_package_id_rejected() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    let mut report = make_report("r-empty", "pkg", 100_000);
    report.package_id = String::new();
    let err = mech.submit_report(report).unwrap_err();
    assert!(matches!(err, MechanismError::InvalidInput { field, .. } if field == "package_id"));
}

#[test]
fn enrichment_submit_report_severity_negative_rejected() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    let report = make_report("r-neg", "pkg-neg", -1);
    let err = mech.submit_report(report).unwrap_err();
    assert!(matches!(err, MechanismError::InvalidInput { field, .. } if field == "severity_millionths"));
}

#[test]
fn enrichment_submit_report_severity_exceeds_max_rejected() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    let report = make_report("r-max", "pkg-max", 1_000_001);
    let err = mech.submit_report(report).unwrap_err();
    assert!(matches!(err, MechanismError::InvalidInput { field, .. } if field == "severity_millionths"));
}

#[test]
fn enrichment_submit_report_severity_zero_accepted() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    let report = make_report("r-zero", "pkg-zero", 0);
    assert!(mech.submit_report(report).is_ok());
}

#[test]
fn enrichment_submit_report_severity_exact_max_accepted() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    let report = make_report("r-exact-max", "pkg-max", 1_000_000);
    assert!(mech.submit_report(report).is_ok());
}

#[test]
fn enrichment_submit_report_emits_event() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    mech.submit_report(make_report("r-ev", "pkg-ev", 500_000))
        .unwrap();
    assert_eq!(mech.events().len(), 1);
    assert_eq!(mech.events()[0].kind, "report_submitted");
    assert!(mech.events()[0].passed);
}

// ---------------------------------------------------------------------------
// Advance report
// ---------------------------------------------------------------------------

#[test]
fn enrichment_advance_report_all_phases() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    mech.submit_report(make_report("r-adv", "pkg-adv", 500_000))
        .unwrap();

    mech.advance_report("r-adv", ReportPhase::UnderReview, None)
        .unwrap();
    assert_eq!(mech.reports()[0].phase, ReportPhase::UnderReview);

    mech.advance_report("r-adv", ReportPhase::Resolved, Some(ts(9000)))
        .unwrap();
    assert_eq!(mech.reports()[0].phase, ReportPhase::Resolved);
    assert_eq!(mech.reports()[0].resolved_at, Some(ts(9000)));
}

#[test]
fn enrichment_advance_report_not_found_returns_error() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    let result = mech.advance_report("nonexistent", ReportPhase::Resolved, None);
    assert!(matches!(result, Err(MechanismError::InvalidInput { field, .. }) if field == "report_id"));
}

#[test]
fn enrichment_advance_report_emits_event() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    mech.submit_report(make_report("r-ev2", "pkg-ev2", 300_000))
        .unwrap();
    mech.advance_report("r-ev2", ReportPhase::Dismissed, None)
        .unwrap();
    // One event for submit + one for advance
    assert_eq!(mech.events().len(), 2);
    assert_eq!(mech.events()[1].kind, "report_advanced");
}

// ---------------------------------------------------------------------------
// Challenge lifecycle
// ---------------------------------------------------------------------------

#[test]
fn enrichment_submit_challenge_requires_existing_report() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    let ch = make_challenge("ch-orphan", "no-such-report");
    let result = mech.submit_challenge(ch);
    assert!(matches!(result, Err(MechanismError::InvalidInput { .. })));
}

#[test]
fn enrichment_submit_challenge_emits_event() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    mech.submit_report(make_report("r-ch", "pkg-ch", 500_000))
        .unwrap();
    mech.submit_challenge(make_challenge("ch-ev", "r-ch"))
        .unwrap();
    let challenge_events: Vec<_> = mech
        .events()
        .iter()
        .filter(|e| e.kind == "challenge_submitted")
        .collect();
    assert_eq!(challenge_events.len(), 1);
}

#[test]
fn enrichment_resolve_challenge_sets_outcome_and_timestamp() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    mech.submit_report(make_report("r-rc", "pkg-rc", 500_000))
        .unwrap();
    mech.submit_challenge(make_challenge("ch-rc", "r-rc"))
        .unwrap();
    mech.resolve_challenge("ch-rc", ChallengeOutcome::Rejected, ts(9000))
        .unwrap();
    assert_eq!(
        mech.challenges()[0].outcome,
        Some(ChallengeOutcome::Rejected)
    );
    assert_eq!(mech.challenges()[0].resolved_at, Some(ts(9000)));
}

#[test]
fn enrichment_resolve_challenge_not_found() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    let result = mech.resolve_challenge("ghost", ChallengeOutcome::Upheld, ts(1000));
    assert!(matches!(result, Err(MechanismError::InvalidInput { .. })));
}

#[test]
fn enrichment_resolve_challenge_all_outcomes() {
    for outcome in [
        ChallengeOutcome::Upheld,
        ChallengeOutcome::Rejected,
        ChallengeOutcome::Escalated,
    ] {
        let mut mech = GovernanceMechanism::new(epoch(10));
        mech.submit_report(make_report("r-out", "pkg-out", 500_000))
            .unwrap();
        mech.submit_challenge(make_challenge("ch-out", "r-out"))
            .unwrap();
        mech.resolve_challenge("ch-out", outcome, ts(5000)).unwrap();
        assert_eq!(mech.challenges()[0].outcome, Some(outcome));
    }
}

// ---------------------------------------------------------------------------
// Quarantine lifecycle
// ---------------------------------------------------------------------------

#[test]
fn enrichment_impose_quarantine_duplicate_same_package_fails() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    mech.submit_report(make_report("r-dup", "pkg-dup", 800_000))
        .unwrap();
    mech.impose_quarantine(make_quarantine("q-first", "pkg-dup", "r-dup"))
        .unwrap();
    let err = mech
        .impose_quarantine(make_quarantine("q-second", "pkg-dup", "r-dup"))
        .unwrap_err();
    assert!(matches!(
        err,
        MechanismError::QuarantineConstraintViolated { package_id, .. } if package_id == "pkg-dup"
    ));
}

#[test]
fn enrichment_impose_quarantine_different_packages_ok() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    mech.submit_report(make_report("r-a", "pkg-a", 800_000))
        .unwrap();
    mech.submit_report(make_report("r-b", "pkg-b", 700_000))
        .unwrap();
    mech.impose_quarantine(make_quarantine("q-a", "pkg-a", "r-a"))
        .unwrap();
    mech.impose_quarantine(make_quarantine("q-b", "pkg-b", "r-b"))
        .unwrap();
    assert_eq!(mech.active_quarantine_count(), 2);
}

#[test]
fn enrichment_impose_quarantine_after_lifted_same_package_ok() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    mech.submit_report(make_report("r-lift", "pkg-lift", 800_000))
        .unwrap();
    mech.impose_quarantine(make_quarantine("q-lift", "pkg-lift", "r-lift"))
        .unwrap();

    // Lift via reinstate
    let req = make_reinstate("req-lift", "q-lift");
    mech.request_reinstate(req).unwrap();
    mech.approve_reinstate("req-lift", ts(6000)).unwrap();

    // Now re-quarantine same package should succeed
    let mut q2 = make_quarantine("q-lift-2", "pkg-lift", "r-lift");
    q2.quarantined_at = ts(7000);
    assert!(mech.impose_quarantine(q2).is_ok());
    assert_eq!(mech.active_quarantine_count(), 1);
}

#[test]
fn enrichment_impose_quarantine_emits_event() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    mech.submit_report(make_report("r-qe", "pkg-qe", 800_000))
        .unwrap();
    mech.impose_quarantine(make_quarantine("q-ev", "pkg-qe", "r-qe"))
        .unwrap();
    let quarantine_events: Vec<_> = mech
        .events()
        .iter()
        .filter(|e| e.kind == "quarantine_imposed")
        .collect();
    assert_eq!(quarantine_events.len(), 1);
}

// ---------------------------------------------------------------------------
// Reinstatement lifecycle
// ---------------------------------------------------------------------------

#[test]
fn enrichment_request_reinstate_nonexistent_quarantine_fails() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    let req = make_reinstate("req-miss", "q-nonexistent");
    let err = mech.request_reinstate(req).unwrap_err();
    assert!(matches!(
        err,
        MechanismError::ReinstateNotAllowed { quarantine_id, .. } if quarantine_id == "q-nonexistent"
    ));
}

#[test]
fn enrichment_request_reinstate_on_lifted_quarantine_fails() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    mech.submit_report(make_report("r-rfl", "pkg-rfl", 800_000))
        .unwrap();
    mech.impose_quarantine(make_quarantine("q-rfl", "pkg-rfl", "r-rfl"))
        .unwrap();
    let req1 = make_reinstate("req-rfl1", "q-rfl");
    mech.request_reinstate(req1).unwrap();
    mech.approve_reinstate("req-rfl1", ts(6000)).unwrap();

    // Try to request reinstatement again on already-lifted quarantine
    let mut req2 = make_reinstate("req-rfl2", "q-rfl");
    req2.submitted_at = ts(7000);
    let err = mech.request_reinstate(req2).unwrap_err();
    assert!(matches!(err, MechanismError::ReinstateNotAllowed { .. }));
}

#[test]
fn enrichment_approve_reinstate_lifts_quarantine_and_sets_lifted_at() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    mech.submit_report(make_report("r-app", "pkg-app", 800_000))
        .unwrap();
    mech.impose_quarantine(make_quarantine("q-app", "pkg-app", "r-app"))
        .unwrap();
    let req = make_reinstate("req-app", "q-app");
    mech.request_reinstate(req).unwrap();
    mech.approve_reinstate("req-app", ts(6000)).unwrap();

    assert_eq!(mech.quarantines()[0].status, QuarantineStatus::Lifted);
    assert_eq!(mech.quarantines()[0].lifted_at, Some(ts(6000)));
    assert_eq!(mech.active_quarantine_count(), 0);
}

#[test]
fn enrichment_approve_reinstate_not_found_request_fails() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    let err = mech.approve_reinstate("no-such-req", ts(6000)).unwrap_err();
    assert!(matches!(err, MechanismError::ReinstateNotAllowed { .. }));
}

#[test]
fn enrichment_approve_reinstate_emits_event() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    mech.submit_report(make_report("r-rev", "pkg-rev", 800_000))
        .unwrap();
    mech.impose_quarantine(make_quarantine("q-rev", "pkg-rev", "r-rev"))
        .unwrap();
    let req = make_reinstate("req-rev", "q-rev");
    mech.request_reinstate(req).unwrap();
    mech.approve_reinstate("req-rev", ts(6000)).unwrap();

    let reinstate_events: Vec<_> = mech
        .events()
        .iter()
        .filter(|e| e.kind == "reinstate_approved")
        .collect();
    assert_eq!(reinstate_events.len(), 1);
}

// ---------------------------------------------------------------------------
// Incentive analysis
// ---------------------------------------------------------------------------

#[test]
fn enrichment_analyze_ic_returns_dominant_strategy_for_standard_game() {
    let mut mech = GovernanceMechanism::new(epoch(100));
    let model = make_game_model(Subsystem::Compiler);
    let analysis = mech.analyze_incentive_compatibility(&model, ts(1000));
    assert_eq!(
        analysis.ic_class,
        IncentiveCompatibilityClass::DominantStrategy
    );
    assert_eq!(analysis.ic_score_millionths, 1_000_000);
}

#[test]
fn enrichment_analyze_ic_populates_subsystem() {
    let mut mech = GovernanceMechanism::new(epoch(100));
    let model = make_game_model(Subsystem::EvidencePipeline);
    let analysis = mech.analyze_incentive_compatibility(&model, ts(1000));
    assert_eq!(analysis.subsystem, Subsystem::EvidencePipeline);
}

#[test]
fn enrichment_analyze_ic_populates_game_model_id() {
    let mut mech = GovernanceMechanism::new(epoch(100));
    let model = make_game_model(Subsystem::ControlPlane);
    let analysis = mech.analyze_incentive_compatibility(&model, ts(1000));
    assert_eq!(analysis.game_model_id, model.model_id);
}

#[test]
fn enrichment_analyze_ic_sets_minimax_defender_action() {
    let mut mech = GovernanceMechanism::new(epoch(100));
    let model = make_game_model(Subsystem::Runtime);
    let analysis = mech.analyze_incentive_compatibility(&model, ts(1000));
    assert!(analysis.minimax_defender_action.is_some());
}

#[test]
fn enrichment_analyze_ic_dominant_strategy_has_nonempty_dominant_actions() {
    let mut mech = GovernanceMechanism::new(epoch(100));
    let model = make_game_model(Subsystem::ExtensionHost);
    let analysis = mech.analyze_incentive_compatibility(&model, ts(1000));
    if analysis.ic_class == IncentiveCompatibilityClass::DominantStrategy {
        assert!(
            !analysis.dominant_strategy_actions.is_empty(),
            "dominant strategy must populate dominant_strategy_actions"
        );
    }
}

#[test]
fn enrichment_analyze_ic_emits_event() {
    let mut mech = GovernanceMechanism::new(epoch(100));
    let model = make_game_model(Subsystem::Compiler);
    mech.analyze_incentive_compatibility(&model, ts(1000));
    let ic_events: Vec<_> = mech
        .events()
        .iter()
        .filter(|e| e.kind == "incentive_analysis")
        .collect();
    assert_eq!(ic_events.len(), 1);
    assert!(ic_events[0].passed); // DominantStrategy => passed
}

#[test]
fn enrichment_analyze_ic_all_subsystems() {
    let mut mech = GovernanceMechanism::new(epoch(100));
    let subsystems = [
        Subsystem::Compiler,
        Subsystem::Runtime,
        Subsystem::ControlPlane,
        Subsystem::ExtensionHost,
        Subsystem::EvidencePipeline,
    ];
    for sub in &subsystems {
        let model = make_game_model(*sub);
        mech.analyze_incentive_compatibility(&model, ts(1000));
    }
    assert_eq!(mech.analyses().len(), 5);
    let analyzed_subsystems: BTreeSet<String> = mech
        .analyses()
        .iter()
        .map(|a| a.subsystem.to_string())
        .collect();
    assert_eq!(analyzed_subsystems.len(), 5);
}

#[test]
fn enrichment_analyze_ic_zero_loss_produces_zero_payoffs() {
    let mut mech = GovernanceMechanism::new(epoch(100));
    let model = make_game_model_with_loss(Subsystem::Compiler, 0);
    let analysis = mech.analyze_incentive_compatibility(&model, ts(1000));
    // Zero total loss => ExPostRational with false_report_loss=0, truthful_gain=0
    assert_eq!(analysis.false_report_loss_millionths, 0);
    assert_eq!(analysis.truthful_report_gain_millionths, 0);
    assert_eq!(
        analysis.ic_class,
        IncentiveCompatibilityClass::ExPostRational
    );
}

// ---------------------------------------------------------------------------
// Enforcement policy compilation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_compile_enforcement_policy_no_analysis_fails() {
    let mut mech = GovernanceMechanism::new(epoch(100));
    let err = mech
        .compile_enforcement_policy(Subsystem::ExtensionHost, "pol-noanalysis", ts(2000))
        .unwrap_err();
    assert!(matches!(err, MechanismError::GameModelMissing { .. }));
}

#[test]
fn enrichment_compile_enforcement_policy_uses_mechanism_epoch() {
    let ep = epoch(42);
    let mut mech = GovernanceMechanism::new(ep);
    let model = make_game_model(Subsystem::Runtime);
    mech.analyze_incentive_compatibility(&model, ts(1000));
    let policy = mech
        .compile_enforcement_policy(Subsystem::Runtime, "pol-ep", ts(2000))
        .unwrap();
    assert_eq!(policy.epoch, ep);
}

#[test]
fn enrichment_compile_enforcement_policy_emits_event() {
    let mut mech = GovernanceMechanism::new(epoch(100));
    let model = make_game_model(Subsystem::ControlPlane);
    mech.analyze_incentive_compatibility(&model, ts(1000));
    mech.compile_enforcement_policy(Subsystem::ControlPlane, "pol-ev", ts(2000))
        .unwrap();
    let policy_events: Vec<_> = mech
        .events()
        .iter()
        .filter(|e| e.kind == "policy_compiled")
        .collect();
    assert_eq!(policy_events.len(), 1);
    assert!(policy_events[0].passed);
}

// ---------------------------------------------------------------------------
// Deterministic hash behavior
// ---------------------------------------------------------------------------

#[test]
fn enrichment_enforcement_policy_hash_deterministic_same_inputs() {
    let mut m1 = GovernanceMechanism::new(epoch(100));
    let mut m2 = GovernanceMechanism::new(epoch(100));
    let model = make_game_model(Subsystem::ExtensionHost);

    m1.analyze_incentive_compatibility(&model, ts(1000));
    m2.analyze_incentive_compatibility(&model, ts(1000));

    let p1 = m1
        .compile_enforcement_policy(Subsystem::ExtensionHost, "pol-det", ts(2000))
        .unwrap();
    let p2 = m2
        .compile_enforcement_policy(Subsystem::ExtensionHost, "pol-det", ts(2000))
        .unwrap();
    assert_eq!(p1.content_hash, p2.content_hash);
}

#[test]
fn enrichment_enforcement_policy_hash_differs_with_different_policy_id() {
    let mut m1 = GovernanceMechanism::new(epoch(100));
    let mut m2 = GovernanceMechanism::new(epoch(100));
    let model = make_game_model(Subsystem::Compiler);

    m1.analyze_incentive_compatibility(&model, ts(1000));
    m2.analyze_incentive_compatibility(&model, ts(1000));

    let p1 = m1
        .compile_enforcement_policy(Subsystem::Compiler, "pol-alpha", ts(2000))
        .unwrap();
    let p2 = m2
        .compile_enforcement_policy(Subsystem::Compiler, "pol-beta", ts(2000))
        .unwrap();
    assert_ne!(p1.content_hash, p2.content_hash);
}

#[test]
fn enrichment_enforcement_policy_hash_differs_with_different_epoch() {
    let model = make_game_model(Subsystem::Runtime);

    let mut m1 = GovernanceMechanism::new(epoch(100));
    m1.analyze_incentive_compatibility(&model, ts(1000));
    let p1 = m1
        .compile_enforcement_policy(Subsystem::Runtime, "pol-ep", ts(2000))
        .unwrap();

    let mut m2 = GovernanceMechanism::new(epoch(200));
    m2.analyze_incentive_compatibility(&model, ts(1000));
    let p2 = m2
        .compile_enforcement_policy(Subsystem::Runtime, "pol-ep", ts(2000))
        .unwrap();

    assert_ne!(p1.content_hash, p2.content_hash);
}

#[test]
fn enrichment_mechanism_report_hash_deterministic_empty() {
    let m1 = GovernanceMechanism::new(epoch(100));
    let m2 = GovernanceMechanism::new(epoch(100));
    assert_eq!(
        m1.generate_report().report_hash,
        m2.generate_report().report_hash
    );
}

#[test]
fn enrichment_mechanism_report_hash_changes_with_reports() {
    let m1 = GovernanceMechanism::new(epoch(100));
    let mut m2 = GovernanceMechanism::new(epoch(100));
    m2.submit_report(make_report("r1", "pkg-a", 500_000))
        .unwrap();
    assert_ne!(
        m1.generate_report().report_hash,
        m2.generate_report().report_hash
    );
}

// ---------------------------------------------------------------------------
// Generate report
// ---------------------------------------------------------------------------

#[test]
fn enrichment_generate_report_empty_mechanism() {
    let mech = GovernanceMechanism::new(epoch(100));
    let report = mech.generate_report();
    assert_eq!(report.total_reports, 0);
    assert_eq!(report.active_quarantines, 0);
    assert_eq!(report.ic_compliant_count, 0);
    assert_eq!(report.ic_non_compliant_count, 0);
    assert_eq!(report.min_ic_score_millionths, 0);
    assert!(report.enforcement_policy_id.is_empty());
}

#[test]
fn enrichment_generate_report_with_multiple_analyses() {
    let mut mech = GovernanceMechanism::new(epoch(100));
    for sub in [Subsystem::Compiler, Subsystem::Runtime, Subsystem::ExtensionHost] {
        let model = make_game_model(sub);
        mech.analyze_incentive_compatibility(&model, ts(1000));
    }
    let report = mech.generate_report();
    assert_eq!(report.ic_compliant_count, 3);
    assert_eq!(report.ic_non_compliant_count, 0);
}

#[test]
fn enrichment_generate_report_enforcement_policy_id_tracks_latest() {
    let mut mech = GovernanceMechanism::new(epoch(100));
    let model = make_game_model(Subsystem::Compiler);
    mech.analyze_incentive_compatibility(&model, ts(1000));
    mech.compile_enforcement_policy(Subsystem::Compiler, "pol-first", ts(2000))
        .unwrap();
    mech.compile_enforcement_policy(Subsystem::Compiler, "pol-second", ts(3000))
        .unwrap();
    let report = mech.generate_report();
    assert_eq!(report.enforcement_policy_id, "pol-second");
}

// ---------------------------------------------------------------------------
// Accessor methods
// ---------------------------------------------------------------------------

#[test]
fn enrichment_epoch_accessor() {
    let mech = GovernanceMechanism::new(epoch(42));
    assert_eq!(mech.epoch(), epoch(42));
    assert_eq!(mech.epoch().as_u64(), 42);
}

#[test]
fn enrichment_all_accessors_empty_on_new() {
    let mech = GovernanceMechanism::new(epoch(1));
    assert!(mech.reports().is_empty());
    assert!(mech.challenges().is_empty());
    assert!(mech.quarantines().is_empty());
    assert!(mech.reinstate_requests().is_empty());
    assert!(mech.analyses().is_empty());
    assert!(mech.policies().is_empty());
    assert!(mech.events().is_empty());
}

// ---------------------------------------------------------------------------
// Full lifecycle integration
// ---------------------------------------------------------------------------

#[test]
fn enrichment_full_lifecycle_report_challenge_quarantine_reinstate() {
    let mut mech = GovernanceMechanism::new(epoch(50));

    // 1. Submit report
    mech.submit_report(make_report("r-full", "pkg-full@1.0", 800_000))
        .unwrap();
    assert_eq!(mech.reports().len(), 1);

    // 2. Advance to under review
    mech.advance_report("r-full", ReportPhase::UnderReview, None)
        .unwrap();

    // 3. Submit and resolve challenge (upheld)
    mech.submit_challenge(make_challenge("ch-full", "r-full"))
        .unwrap();
    mech.resolve_challenge("ch-full", ChallengeOutcome::Upheld, ts(4000))
        .unwrap();

    // 4. Impose quarantine
    mech.impose_quarantine(make_quarantine("q-full", "pkg-full@1.0", "r-full"))
        .unwrap();
    assert_eq!(mech.active_quarantine_count(), 1);

    // 5. Analyze IC
    let model = make_game_model(Subsystem::ExtensionHost);
    let analysis = mech.analyze_incentive_compatibility(&model, ts(5000));
    assert_eq!(
        analysis.ic_class,
        IncentiveCompatibilityClass::DominantStrategy
    );

    // 6. Compile enforcement policy
    let policy = mech
        .compile_enforcement_policy(Subsystem::ExtensionHost, "pol-full", ts(6000))
        .unwrap();
    assert!(!policy.action_set.is_empty());

    // 7. Request and approve reinstatement
    let req = make_reinstate("req-full", "q-full");
    mech.request_reinstate(req).unwrap();
    mech.approve_reinstate("req-full", ts(8000)).unwrap();
    assert_eq!(mech.active_quarantine_count(), 0);

    // 8. Resolve report
    mech.advance_report("r-full", ReportPhase::Resolved, Some(ts(9000)))
        .unwrap();

    // 9. Generate report
    let report = mech.generate_report();
    assert_eq!(report.total_reports, 1);
    assert_eq!(report.active_quarantines, 0);
    assert_eq!(report.ic_compliant_count, 1);
    assert_eq!(report.enforcement_policy_id, "pol-full");

    // 10. Verify event log completeness
    assert!(
        mech.events().len() >= 8,
        "should have at least 8 events from full lifecycle"
    );
}

#[test]
fn enrichment_full_lifecycle_multiple_packages() {
    let mut mech = GovernanceMechanism::new(epoch(60));

    // Reports on two different packages
    mech.submit_report(make_report("r-a", "pkg-a@1.0", 900_000))
        .unwrap();
    mech.submit_report(make_report("r-b", "pkg-b@2.0", 300_000))
        .unwrap();

    // Quarantine only pkg-a
    mech.impose_quarantine(make_quarantine("q-a", "pkg-a@1.0", "r-a"))
        .unwrap();
    assert_eq!(mech.active_quarantine_count(), 1);

    let report = mech.generate_report();
    assert_eq!(report.total_reports, 2);
    assert_eq!(report.active_quarantines, 1);
}

// ---------------------------------------------------------------------------
// Error Display format verification
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_display_invalid_input_format() {
    let e = MechanismError::InvalidInput {
        field: "package_id".into(),
        detail: "must not be empty".into(),
    };
    assert_eq!(e.to_string(), "invalid input: package_id: must not be empty");
}

#[test]
fn enrichment_error_display_game_model_missing_format() {
    let e = MechanismError::GameModelMissing {
        subsystem: "runtime".into(),
    };
    assert_eq!(e.to_string(), "game model missing for subsystem: runtime");
}

#[test]
fn enrichment_error_display_incentive_violation_format() {
    let e = MechanismError::IncentiveViolation {
        reason: "payoff structure invalid".into(),
    };
    assert_eq!(e.to_string(), "incentive violation: payoff structure invalid");
}

#[test]
fn enrichment_error_display_quarantine_constraint_format() {
    let e = MechanismError::QuarantineConstraintViolated {
        package_id: "pkg-x@1.0".into(),
        reason: "already active".into(),
    };
    assert_eq!(
        e.to_string(),
        "quarantine constraint for pkg-x@1.0: already active"
    );
}

#[test]
fn enrichment_error_display_reinstate_not_allowed_format() {
    let e = MechanismError::ReinstateNotAllowed {
        quarantine_id: "q-99".into(),
        reason: "quarantine status is lifted, not active".into(),
    };
    assert_eq!(
        e.to_string(),
        "reinstate not allowed for q-99: quarantine status is lifted, not active"
    );
}

// ---------------------------------------------------------------------------
// std::error::Error trait
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mechanism_error_implements_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(MechanismError::IncentiveViolation {
        reason: "test".into(),
    });
    assert!(!err.to_string().is_empty());
}

#[test]
fn enrichment_mechanism_error_source_is_none_all_variants() {
    use std::error::Error;
    let errors = vec![
        MechanismError::InvalidInput {
            field: "f".into(),
            detail: "d".into(),
        },
        MechanismError::GameModelMissing {
            subsystem: "s".into(),
        },
        MechanismError::IncentiveViolation {
            reason: "r".into(),
        },
        MechanismError::QuarantineConstraintViolated {
            package_id: "p".into(),
            reason: "d".into(),
        },
        MechanismError::ReinstateNotAllowed {
            quarantine_id: "q".into(),
            reason: "r".into(),
        },
    ];
    for e in &errors {
        assert!(e.source().is_none());
    }
}

// ---------------------------------------------------------------------------
// Ordering (Ord/PartialOrd)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_phase_ordering() {
    assert!(ReportPhase::Submitted < ReportPhase::UnderReview);
    assert!(ReportPhase::UnderReview < ReportPhase::Resolved);
    assert!(ReportPhase::Resolved < ReportPhase::Dismissed);
}

#[test]
fn enrichment_quarantine_status_ordering() {
    assert!(QuarantineStatus::Active < QuarantineStatus::Lifted);
    assert!(QuarantineStatus::Lifted < QuarantineStatus::Expired);
}

#[test]
fn enrichment_challenge_outcome_ordering() {
    assert!(ChallengeOutcome::Upheld < ChallengeOutcome::Rejected);
    assert!(ChallengeOutcome::Rejected < ChallengeOutcome::Escalated);
}

#[test]
fn enrichment_incentive_compatibility_class_ordering() {
    assert!(IncentiveCompatibilityClass::DominantStrategy < IncentiveCompatibilityClass::BayesNash);
    assert!(
        IncentiveCompatibilityClass::BayesNash
            < IncentiveCompatibilityClass::ExPostRational
    );
    assert!(
        IncentiveCompatibilityClass::ExPostRational
            < IncentiveCompatibilityClass::NonCompliant
    );
}

// ---------------------------------------------------------------------------
// Event log details
// ---------------------------------------------------------------------------

#[test]
fn enrichment_events_have_empty_attributes_from_mechanism() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    mech.submit_report(make_report("r-attr", "pkg-attr", 500_000))
        .unwrap();
    // Events emitted by GovernanceMechanism have empty attributes
    assert!(mech.events()[0].attributes.is_empty());
}

#[test]
fn enrichment_events_timestamp_matches_operation() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    let report = make_report("r-ts", "pkg-ts", 500_000);
    let expected_ts = report.submitted_at;
    mech.submit_report(report).unwrap();
    assert_eq!(mech.events()[0].timestamp, expected_ts);
}

#[test]
fn enrichment_event_count_accumulates_correctly() {
    let mut mech = GovernanceMechanism::new(epoch(10));

    // submit report => 1 event
    mech.submit_report(make_report("r-cnt", "pkg-cnt", 500_000))
        .unwrap();
    assert_eq!(mech.events().len(), 1);

    // advance report => 2 events
    mech.advance_report("r-cnt", ReportPhase::UnderReview, None)
        .unwrap();
    assert_eq!(mech.events().len(), 2);

    // impose quarantine => 3 events
    mech.impose_quarantine(make_quarantine("q-cnt", "pkg-cnt", "r-cnt"))
        .unwrap();
    assert_eq!(mech.events().len(), 3);

    // submit challenge => 4 events
    mech.submit_challenge(make_challenge("ch-cnt", "r-cnt"))
        .unwrap();
    assert_eq!(mech.events().len(), 4);

    // resolve challenge => 5 events
    mech.resolve_challenge("ch-cnt", ChallengeOutcome::Escalated, ts(4000))
        .unwrap();
    assert_eq!(mech.events().len(), 5);

    // request reinstate => 6 events
    let req = make_reinstate("req-cnt", "q-cnt");
    mech.request_reinstate(req).unwrap();
    assert_eq!(mech.events().len(), 6);

    // approve reinstate => 7 events
    mech.approve_reinstate("req-cnt", ts(8000)).unwrap();
    assert_eq!(mech.events().len(), 7);

    // IC analysis => 8 events
    let model = make_game_model(Subsystem::Compiler);
    mech.analyze_incentive_compatibility(&model, ts(9000));
    assert_eq!(mech.events().len(), 8);

    // compile policy => 9 events
    mech.compile_enforcement_policy(Subsystem::Compiler, "pol-cnt", ts(10000))
        .unwrap();
    assert_eq!(mech.events().len(), 9);
}

// ---------------------------------------------------------------------------
// ContentHash determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_content_hash_compute_deterministic() {
    let h1 = ContentHash::compute(b"governance-test-input");
    let h2 = ContentHash::compute(b"governance-test-input");
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_content_hash_compute_differs_for_different_input() {
    let h1 = ContentHash::compute(b"input-a");
    let h2 = ContentHash::compute(b"input-b");
    assert_ne!(h1, h2);
}

// ---------------------------------------------------------------------------
// Multiple report submissions
// ---------------------------------------------------------------------------

#[test]
fn enrichment_submit_multiple_reports_different_packages() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    for i in 0..10 {
        let report = make_report(
            &format!("r-{i}"),
            &format!("pkg-{i}@1.0"),
            (i as i64 + 1) * 100_000,
        );
        mech.submit_report(report).unwrap();
    }
    assert_eq!(mech.reports().len(), 10);
    assert_eq!(mech.events().len(), 10);
}

#[test]
fn enrichment_submit_multiple_reports_same_package_allowed() {
    let mut mech = GovernanceMechanism::new(epoch(10));
    // Multiple reports on the same package should be allowed
    mech.submit_report(make_report("r-1", "pkg-same", 500_000))
        .unwrap();
    mech.submit_report(make_report("r-2", "pkg-same", 600_000))
        .unwrap();
    assert_eq!(mech.reports().len(), 2);
}

// ---------------------------------------------------------------------------
// Edge: various loss dimensions
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_with_each_loss_dimension() {
    let dimensions = [
        LossDimension::UserHarm,
        LossDimension::PerformanceCost,
        LossDimension::FalsePositiveCost,
        LossDimension::AvailabilityCost,
        LossDimension::EvidenceIntegrityCost,
    ];
    for dim in &dimensions {
        let mut report = make_report("r-dim", "pkg-dim", 500_000);
        report.loss_dimension = *dim;
        let json = serde_json::to_string(&report).unwrap();
        let back: ExtensionReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.loss_dimension, *dim);
    }
}
