#![forbid(unsafe_code)]
//! Integration tests for the `governance_mechanism` module.
//!
//! Exercises GovernanceMechanism lifecycle: reports, challenges, quarantines,
//! reinstatement, incentive analysis, enforcement policy compilation, and
//! CI-readable report generation.

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

use frankenengine_engine::attack_surface_game_model::{
    ActionId, GameModelBuilder, LossDimension, LossEntry, Player, StrategicAction, Subsystem,
};
use frankenengine_engine::governance_mechanism::{
    ChallengeOutcome, ChallengeRecord, EnforcementPolicy, ExtensionReport, GovernanceMechanism,
    IncentiveCompatibilityClass, MechanismError, MechanismReport, QuarantineRecord,
    QuarantineStatus, ReinstateRequest, ReportPhase, SCHEMA_VERSION,
};
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(100)
}

fn ts(tick: u64) -> DeterministicTimestamp {
    DeterministicTimestamp(tick)
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

fn make_challenge(cid: &str, rid: &str) -> ChallengeRecord {
    ChallengeRecord {
        challenge_id: cid.into(),
        report_id: rid.into(),
        challenger_id: "challenger-1".into(),
        outcome: None,
        rationale: "false positive".into(),
        game_model_id: "gm-1".into(),
        minimax_action: None,
        submitted_at: ts(3000),
        resolved_at: None,
    }
}

fn make_reinstate_request(req_id: &str, quarantine_id: &str) -> ReinstateRequest {
    ReinstateRequest {
        request_id: req_id.into(),
        quarantine_id: quarantine_id.into(),
        justification: "patched and verified".into(),
        compliance_evidence_id: Some("ev-1".into()),
        submitted_at: ts(4000),
        approved: None,
    }
}

fn make_game_model(
    subsystem: Subsystem,
) -> frankenengine_engine::attack_surface_game_model::GameModel {
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
    GameModelBuilder::new(subsystem, epoch())
        .attacker_action(atk)
        .defender_action(def)
        .loss(loss)
        .build()
}

// ===========================================================================
// 1. Constants & enums
// ===========================================================================

#[test]
fn schema_version_nonempty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(SCHEMA_VERSION.contains("governance-mechanism"));
}

#[test]
fn report_phase_display() {
    assert_eq!(ReportPhase::Submitted.to_string(), "submitted");
    assert_eq!(ReportPhase::UnderReview.to_string(), "under_review");
    assert_eq!(ReportPhase::Resolved.to_string(), "resolved");
    assert_eq!(ReportPhase::Dismissed.to_string(), "dismissed");
}

#[test]
fn report_phase_serde() {
    for phase in [
        ReportPhase::Submitted,
        ReportPhase::UnderReview,
        ReportPhase::Resolved,
        ReportPhase::Dismissed,
    ] {
        let json = serde_json::to_string(&phase).unwrap();
        let back: ReportPhase = serde_json::from_str(&json).unwrap();
        assert_eq!(back, phase);
    }
}

#[test]
fn challenge_outcome_display() {
    assert_eq!(ChallengeOutcome::Upheld.to_string(), "upheld");
    assert_eq!(ChallengeOutcome::Rejected.to_string(), "rejected");
    assert_eq!(ChallengeOutcome::Escalated.to_string(), "escalated");
}

#[test]
fn challenge_outcome_serde() {
    for co in [
        ChallengeOutcome::Upheld,
        ChallengeOutcome::Rejected,
        ChallengeOutcome::Escalated,
    ] {
        let json = serde_json::to_string(&co).unwrap();
        let back: ChallengeOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(back, co);
    }
}

#[test]
fn quarantine_status_display() {
    assert_eq!(QuarantineStatus::Active.to_string(), "active");
    assert_eq!(QuarantineStatus::Lifted.to_string(), "lifted");
    assert_eq!(QuarantineStatus::Expired.to_string(), "expired");
}

#[test]
fn quarantine_status_serde() {
    for qs in [
        QuarantineStatus::Active,
        QuarantineStatus::Lifted,
        QuarantineStatus::Expired,
    ] {
        let json = serde_json::to_string(&qs).unwrap();
        let back: QuarantineStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, qs);
    }
}

#[test]
fn ic_class_display() {
    assert_eq!(
        IncentiveCompatibilityClass::DominantStrategy.to_string(),
        "dominant_strategy"
    );
    assert_eq!(
        IncentiveCompatibilityClass::BayesNash.to_string(),
        "bayes_nash"
    );
    assert_eq!(
        IncentiveCompatibilityClass::ExPostRational.to_string(),
        "ex_post_rational"
    );
    assert_eq!(
        IncentiveCompatibilityClass::NonCompliant.to_string(),
        "non_compliant"
    );
}

#[test]
fn ic_class_serde() {
    for ic in [
        IncentiveCompatibilityClass::DominantStrategy,
        IncentiveCompatibilityClass::BayesNash,
        IncentiveCompatibilityClass::ExPostRational,
        IncentiveCompatibilityClass::NonCompliant,
    ] {
        let json = serde_json::to_string(&ic).unwrap();
        let back: IncentiveCompatibilityClass = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ic);
    }
}

// ===========================================================================
// 2. MechanismError
// ===========================================================================

#[test]
fn error_display_invalid_input() {
    let e = MechanismError::InvalidInput {
        field: "f".into(),
        detail: "bad".into(),
    };
    let s = e.to_string();
    assert!(s.contains("invalid input"));
    assert!(s.contains("f"));
}

#[test]
fn error_display_game_model_missing() {
    let e = MechanismError::GameModelMissing {
        subsystem: "compiler".into(),
    };
    assert!(e.to_string().contains("game model missing"));
}

#[test]
fn error_display_incentive_violation() {
    let e = MechanismError::IncentiveViolation {
        reason: "bad".into(),
    };
    assert!(e.to_string().contains("incentive violation"));
}

#[test]
fn error_display_quarantine_constraint() {
    let e = MechanismError::QuarantineConstraintViolated {
        package_id: "pkg".into(),
        reason: "active".into(),
    };
    assert!(e.to_string().contains("quarantine constraint"));
}

#[test]
fn error_display_reinstate_not_allowed() {
    let e = MechanismError::ReinstateNotAllowed {
        quarantine_id: "q1".into(),
        reason: "not found".into(),
    };
    assert!(e.to_string().contains("reinstate not allowed"));
}

#[test]
fn error_serde() {
    let e = MechanismError::GameModelMissing {
        subsystem: "runtime".into(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: MechanismError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

// ===========================================================================
// 3. GovernanceMechanism — construction
// ===========================================================================

#[test]
fn mechanism_new() {
    let m = GovernanceMechanism::new(epoch());
    assert_eq!(m.epoch(), epoch());
    assert!(m.reports().is_empty());
    assert!(m.challenges().is_empty());
    assert!(m.quarantines().is_empty());
    assert!(m.reinstate_requests().is_empty());
    assert!(m.analyses().is_empty());
    assert!(m.policies().is_empty());
    assert!(m.events().is_empty());
}

#[test]
fn mechanism_serde() {
    let m = GovernanceMechanism::new(epoch());
    let json = serde_json::to_string(&m).unwrap();
    let back: GovernanceMechanism = serde_json::from_str(&json).unwrap();
    assert_eq!(back, m);
}

// ===========================================================================
// 4. Report lifecycle
// ===========================================================================

#[test]
fn submit_report_success() {
    let mut m = GovernanceMechanism::new(epoch());
    m.submit_report(make_report("r1", "pkg-a", 500_000))
        .unwrap();
    assert_eq!(m.reports().len(), 1);
    assert_eq!(m.reports()[0].phase, ReportPhase::Submitted);
    assert_eq!(m.events().len(), 1);
}

#[test]
fn submit_report_empty_package_fails() {
    let mut m = GovernanceMechanism::new(epoch());
    let mut r = make_report("r1", "pkg-a", 500_000);
    r.package_id = String::new();
    let err = m.submit_report(r).unwrap_err();
    assert!(matches!(err, MechanismError::InvalidInput { .. }));
}

#[test]
fn submit_report_severity_too_high_fails() {
    let mut m = GovernanceMechanism::new(epoch());
    let err = m
        .submit_report(make_report("r1", "pkg-a", 2_000_000))
        .unwrap_err();
    assert!(matches!(err, MechanismError::InvalidInput { .. }));
}

#[test]
fn submit_report_severity_negative_fails() {
    let mut m = GovernanceMechanism::new(epoch());
    let err = m.submit_report(make_report("r1", "pkg-a", -1)).unwrap_err();
    assert!(matches!(err, MechanismError::InvalidInput { .. }));
}

#[test]
fn advance_report_success() {
    let mut m = GovernanceMechanism::new(epoch());
    m.submit_report(make_report("r1", "pkg-a", 500_000))
        .unwrap();
    m.advance_report("r1", ReportPhase::UnderReview, None)
        .unwrap();
    assert_eq!(m.reports()[0].phase, ReportPhase::UnderReview);
}

#[test]
fn advance_report_resolved() {
    let mut m = GovernanceMechanism::new(epoch());
    m.submit_report(make_report("r1", "pkg-a", 500_000))
        .unwrap();
    m.advance_report("r1", ReportPhase::Resolved, Some(ts(5000)))
        .unwrap();
    assert_eq!(m.reports()[0].phase, ReportPhase::Resolved);
    assert_eq!(m.reports()[0].resolved_at, Some(ts(5000)));
}

#[test]
fn advance_report_not_found() {
    let mut m = GovernanceMechanism::new(epoch());
    let err = m
        .advance_report("nonexistent", ReportPhase::Resolved, None)
        .unwrap_err();
    assert!(matches!(err, MechanismError::InvalidInput { .. }));
}

// ===========================================================================
// 5. Challenge lifecycle
// ===========================================================================

#[test]
fn submit_challenge_success() {
    let mut m = GovernanceMechanism::new(epoch());
    m.submit_report(make_report("r1", "pkg-a", 500_000))
        .unwrap();
    m.submit_challenge(make_challenge("c1", "r1")).unwrap();
    assert_eq!(m.challenges().len(), 1);
    assert!(m.challenges()[0].outcome.is_none());
}

#[test]
fn submit_challenge_report_not_found() {
    let mut m = GovernanceMechanism::new(epoch());
    let err = m
        .submit_challenge(make_challenge("c1", "nonexistent"))
        .unwrap_err();
    assert!(matches!(err, MechanismError::InvalidInput { .. }));
}

#[test]
fn resolve_challenge_upheld() {
    let mut m = GovernanceMechanism::new(epoch());
    m.submit_report(make_report("r1", "pkg-a", 500_000))
        .unwrap();
    m.submit_challenge(make_challenge("c1", "r1")).unwrap();
    m.resolve_challenge("c1", ChallengeOutcome::Upheld, ts(5000))
        .unwrap();
    assert_eq!(m.challenges()[0].outcome, Some(ChallengeOutcome::Upheld));
    assert_eq!(m.challenges()[0].resolved_at, Some(ts(5000)));
}

#[test]
fn resolve_challenge_not_found() {
    let mut m = GovernanceMechanism::new(epoch());
    let err = m
        .resolve_challenge("nonexistent", ChallengeOutcome::Rejected, ts(5000))
        .unwrap_err();
    assert!(matches!(err, MechanismError::InvalidInput { .. }));
}

// ===========================================================================
// 6. Quarantine lifecycle
// ===========================================================================

#[test]
fn impose_quarantine_success() {
    let mut m = GovernanceMechanism::new(epoch());
    m.submit_report(make_report("r1", "pkg-a", 500_000))
        .unwrap();
    m.impose_quarantine(make_quarantine("q1", "pkg-a", "r1"))
        .unwrap();
    assert_eq!(m.quarantines().len(), 1);
    assert_eq!(m.active_quarantine_count(), 1);
}

#[test]
fn impose_quarantine_duplicate_active() {
    let mut m = GovernanceMechanism::new(epoch());
    m.submit_report(make_report("r1", "pkg-a", 500_000))
        .unwrap();
    m.impose_quarantine(make_quarantine("q1", "pkg-a", "r1"))
        .unwrap();
    let err = m
        .impose_quarantine(make_quarantine("q2", "pkg-a", "r1"))
        .unwrap_err();
    assert!(matches!(
        err,
        MechanismError::QuarantineConstraintViolated { .. }
    ));
}

// ===========================================================================
// 7. Reinstatement lifecycle
// ===========================================================================

#[test]
fn request_reinstate_success() {
    let mut m = GovernanceMechanism::new(epoch());
    m.submit_report(make_report("r1", "pkg-a", 500_000))
        .unwrap();
    m.impose_quarantine(make_quarantine("q1", "pkg-a", "r1"))
        .unwrap();
    m.request_reinstate(make_reinstate_request("req-1", "q1"))
        .unwrap();
    assert_eq!(m.reinstate_requests().len(), 1);
}

#[test]
fn request_reinstate_quarantine_not_found() {
    let mut m = GovernanceMechanism::new(epoch());
    let err = m
        .request_reinstate(make_reinstate_request("req-1", "nonexistent"))
        .unwrap_err();
    assert!(matches!(err, MechanismError::ReinstateNotAllowed { .. }));
}

#[test]
fn request_reinstate_quarantine_not_active() {
    let mut m = GovernanceMechanism::new(epoch());
    m.submit_report(make_report("r1", "pkg-a", 500_000))
        .unwrap();
    m.impose_quarantine(make_quarantine("q1", "pkg-a", "r1"))
        .unwrap();
    // Reinstate it first
    m.request_reinstate(make_reinstate_request("req-1", "q1"))
        .unwrap();
    m.approve_reinstate("req-1", ts(5000)).unwrap();
    // Now quarantine is lifted → second reinstatement should fail
    let err = m
        .request_reinstate(make_reinstate_request("req-2", "q1"))
        .unwrap_err();
    assert!(matches!(err, MechanismError::ReinstateNotAllowed { .. }));
}

#[test]
fn approve_reinstate_success() {
    let mut m = GovernanceMechanism::new(epoch());
    m.submit_report(make_report("r1", "pkg-a", 500_000))
        .unwrap();
    m.impose_quarantine(make_quarantine("q1", "pkg-a", "r1"))
        .unwrap();
    m.request_reinstate(make_reinstate_request("req-1", "q1"))
        .unwrap();
    m.approve_reinstate("req-1", ts(5000)).unwrap();

    // Quarantine should be lifted
    assert_eq!(m.quarantines()[0].status, QuarantineStatus::Lifted);
    assert_eq!(m.quarantines()[0].lifted_at, Some(ts(5000)));
    assert_eq!(m.active_quarantine_count(), 0);

    // Request should be approved
    assert_eq!(m.reinstate_requests()[0].approved, Some(true));
}

#[test]
fn approve_reinstate_not_found() {
    let mut m = GovernanceMechanism::new(epoch());
    let err = m.approve_reinstate("nonexistent", ts(5000)).unwrap_err();
    assert!(matches!(err, MechanismError::ReinstateNotAllowed { .. }));
}

// ===========================================================================
// 8. Incentive analysis
// ===========================================================================

#[test]
fn analyze_incentive_compatibility() {
    let mut m = GovernanceMechanism::new(epoch());
    let game = make_game_model(Subsystem::Compiler);
    let analysis = m.analyze_incentive_compatibility(&game, ts(6000));

    assert_eq!(analysis.subsystem, Subsystem::Compiler);
    assert_eq!(analysis.game_model_id, game.model_id);
    // With positive loss (500_000), the compute_ic_payoffs gives:
    // false_report_loss = -(500_000/3) < 0, truthful_gain = 500_000/2 > 0
    // → DominantStrategy
    assert_eq!(
        analysis.ic_class,
        IncentiveCompatibilityClass::DominantStrategy
    );
    assert!(analysis.ic_score_millionths > 0);
    assert!(!analysis.admissible_actions.is_empty());
    assert_eq!(m.analyses().len(), 1);
}

#[test]
fn analyze_multiple_subsystems() {
    let mut m = GovernanceMechanism::new(epoch());
    let g1 = make_game_model(Subsystem::Compiler);
    let g2 = make_game_model(Subsystem::Runtime);
    m.analyze_incentive_compatibility(&g1, ts(6000));
    m.analyze_incentive_compatibility(&g2, ts(6001));
    assert_eq!(m.analyses().len(), 2);
    assert_eq!(m.analyses()[0].subsystem, Subsystem::Compiler);
    assert_eq!(m.analyses()[1].subsystem, Subsystem::Runtime);
}

// ===========================================================================
// 9. Enforcement policy
// ===========================================================================

#[test]
fn compile_enforcement_policy_success() {
    let mut m = GovernanceMechanism::new(epoch());
    let game = make_game_model(Subsystem::Compiler);
    m.analyze_incentive_compatibility(&game, ts(6000));
    let policy = m
        .compile_enforcement_policy(Subsystem::Compiler, "pol-1", ts(7000))
        .unwrap();

    assert_eq!(policy.policy_id, "pol-1");
    assert_eq!(policy.epoch, epoch());
    assert_eq!(policy.analysis_subsystem, Subsystem::Compiler);
    assert!(!policy.action_set.is_empty());
    assert_eq!(m.policies().len(), 1);
}

#[test]
fn compile_enforcement_policy_no_analysis() {
    let mut m = GovernanceMechanism::new(epoch());
    let err = m
        .compile_enforcement_policy(Subsystem::Runtime, "pol-1", ts(7000))
        .unwrap_err();
    assert!(matches!(err, MechanismError::GameModelMissing { .. }));
}

#[test]
fn enforcement_policy_serde() {
    let mut m = GovernanceMechanism::new(epoch());
    let game = make_game_model(Subsystem::Compiler);
    m.analyze_incentive_compatibility(&game, ts(6000));
    let policy = m
        .compile_enforcement_policy(Subsystem::Compiler, "pol-1", ts(7000))
        .unwrap();
    let json = serde_json::to_string(&policy).unwrap();
    let back: EnforcementPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(back, policy);
}

// ===========================================================================
// 10. Report generation
// ===========================================================================

#[test]
fn generate_report_empty() {
    let m = GovernanceMechanism::new(epoch());
    let report = m.generate_report();
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.epoch, epoch());
    assert_eq!(report.total_reports, 0);
    assert_eq!(report.active_quarantines, 0);
}

#[test]
fn generate_report_with_data() {
    let mut m = GovernanceMechanism::new(epoch());
    m.submit_report(make_report("r1", "pkg-a", 500_000))
        .unwrap();
    m.submit_report(make_report("r2", "pkg-b", 300_000))
        .unwrap();
    m.impose_quarantine(make_quarantine("q1", "pkg-a", "r1"))
        .unwrap();

    let game = make_game_model(Subsystem::Compiler);
    m.analyze_incentive_compatibility(&game, ts(6000));
    m.compile_enforcement_policy(Subsystem::Compiler, "pol-1", ts(7000))
        .unwrap();

    let report = m.generate_report();
    assert_eq!(report.total_reports, 2);
    assert_eq!(report.active_quarantines, 1);
    assert_eq!(report.ic_compliant_count, 1);
    assert_eq!(report.ic_non_compliant_count, 0);
    assert!(report.min_ic_score_millionths > 0);
    assert_eq!(report.enforcement_policy_id, "pol-1");
}

#[test]
fn generate_report_serde() {
    let m = GovernanceMechanism::new(epoch());
    let report = m.generate_report();
    let json = serde_json::to_string(&report).unwrap();
    let back: MechanismReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, report);
}

#[test]
fn generate_report_deterministic() {
    let mut m1 = GovernanceMechanism::new(epoch());
    let mut m2 = GovernanceMechanism::new(epoch());
    m1.submit_report(make_report("r1", "pkg-a", 500_000))
        .unwrap();
    m2.submit_report(make_report("r1", "pkg-a", 500_000))
        .unwrap();
    assert_eq!(
        m1.generate_report().report_hash,
        m2.generate_report().report_hash
    );
}

// ===========================================================================
// 11. Audit events
// ===========================================================================

#[test]
fn events_accumulate() {
    let mut m = GovernanceMechanism::new(epoch());
    m.submit_report(make_report("r1", "pkg-a", 500_000))
        .unwrap();
    m.advance_report("r1", ReportPhase::UnderReview, None)
        .unwrap();
    // 2 events: report_submitted + report_advanced
    assert_eq!(m.events().len(), 2);
    assert_eq!(m.events()[0].kind, "report_submitted");
    assert_eq!(m.events()[1].kind, "report_advanced");
    assert!(m.events()[0].passed);
}

// ===========================================================================
// 12. Struct serde round-trips
// ===========================================================================

#[test]
fn extension_report_serde() {
    let r = make_report("r1", "pkg-a", 500_000);
    let json = serde_json::to_string(&r).unwrap();
    let back: ExtensionReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

#[test]
fn challenge_record_serde() {
    let c = make_challenge("c1", "r1");
    let json = serde_json::to_string(&c).unwrap();
    let back: ChallengeRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

#[test]
fn quarantine_record_serde() {
    let q = make_quarantine("q1", "pkg-a", "r1");
    let json = serde_json::to_string(&q).unwrap();
    let back: QuarantineRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back, q);
}

#[test]
fn reinstate_request_serde() {
    let r = make_reinstate_request("req-1", "q1");
    let json = serde_json::to_string(&r).unwrap();
    let back: ReinstateRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

// ===========================================================================
// 13. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_report_challenge_quarantine_reinstate() {
    let mut m = GovernanceMechanism::new(epoch());

    // 1. Submit report
    m.submit_report(make_report("r1", "pkg-a", 800_000))
        .unwrap();

    // 2. Review
    m.advance_report("r1", ReportPhase::UnderReview, None)
        .unwrap();

    // 3. Challenge
    m.submit_challenge(make_challenge("c1", "r1")).unwrap();
    m.resolve_challenge("c1", ChallengeOutcome::Upheld, ts(3500))
        .unwrap();

    // 4. Quarantine
    m.impose_quarantine(make_quarantine("q1", "pkg-a", "r1"))
        .unwrap();
    assert_eq!(m.active_quarantine_count(), 1);

    // 5. Resolve report
    m.advance_report("r1", ReportPhase::Resolved, Some(ts(4000)))
        .unwrap();

    // 6. Reinstate
    m.request_reinstate(make_reinstate_request("req-1", "q1"))
        .unwrap();
    m.approve_reinstate("req-1", ts(5000)).unwrap();
    assert_eq!(m.active_quarantine_count(), 0);

    // 7. Analyze + compile policy
    let game = make_game_model(Subsystem::ExtensionHost);
    m.analyze_incentive_compatibility(&game, ts(6000));
    m.compile_enforcement_policy(Subsystem::ExtensionHost, "pol-ext", ts(7000))
        .unwrap();

    // 8. Generate report
    let report = m.generate_report();
    assert_eq!(report.total_reports, 1);
    assert_eq!(report.active_quarantines, 0);
    assert_eq!(report.ic_compliant_count, 1);
    assert_eq!(report.enforcement_policy_id, "pol-ext");

    // 9. Events accumulated
    assert!(m.events().len() >= 8);

    // 10. Serde round-trip of full mechanism
    let json = serde_json::to_string(&m).unwrap();
    let back: GovernanceMechanism = serde_json::from_str(&json).unwrap();
    assert_eq!(back, m);
}
