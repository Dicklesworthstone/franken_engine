//! Integration tests for `capability_lease` (E10.T4, `bd-fqlfw.10.4`).
//!
//! Exercises the full risk-priced-lease lifecycle through the public API:
//! register → priced grants decrementing the windowed risk budget →
//! budget exhaustion → deterministic window reset → challenge under
//! elevated risk → revocation under hostile risk → content-hashed receipts
//! for every decision → deterministic internal report with recommendations.

use frankenengine_engine::bayesian_posterior::Posterior;
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::capability_lease::{
    CAPABILITY_LEASE_SCHEMA_VERSION, CapabilityLease, CapabilityLeaseStatus, DenialReason,
    LeaseDecision, LeaseManager, LeaseRecommendation, LeaseReport, MILLION,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn egress_lease(lease_id: &str, extension_id: &str) -> CapabilityLease {
    CapabilityLease {
        lease_id: lease_id.to_string(),
        extension_id: extension_id.to_string(),
        capability: RuntimeCapability::NetworkEgress,
        scope: "egress:api.partner.example".to_string(),
        max_expected_loss_millionths: 10 * MILLION,
        challenge_threshold_millionths: 200_000,
        revoke_threshold_millionths: 600_000,
        budget_window_ticks: 50,
        window_budget_millionths: 4 * MILLION,
        policy_epoch: SecurityEpoch::from_raw(11),
    }
}

fn benign() -> Posterior {
    Posterior::from_millionths(950_000, 30_000, 10_000, 10_000)
}

fn elevated() -> Posterior {
    Posterior::from_millionths(600_000, 100_000, 250_000, 50_000)
}

fn hostile() -> Posterior {
    Posterior::from_millionths(100_000, 100_000, 700_000, 100_000)
}

#[test]
fn full_lease_lifecycle_grants_exhausts_resets_challenges_revokes() {
    let mut manager = LeaseManager::balanced();
    manager
        .register_lease(egress_lease("net-1", "ext-alpha"))
        .expect("registration should succeed");

    let price = manager.risk_price_millionths(&benign());
    assert!(price > 0);
    let affordable = (4 * MILLION) / price;
    assert!(affordable >= 1);

    // Spend the window's budget.
    for tick in 0..affordable {
        let decision = manager
            .request_use(
                "net-1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &benign(),
                tick as u64,
            )
            .expect("request should succeed");
        assert!(matches!(decision, LeaseDecision::Granted { .. }));
    }
    let exhausted = manager
        .request_use(
            "net-1",
            "ext-alpha",
            RuntimeCapability::NetworkEgress,
            &benign(),
            10,
        )
        .expect("request should succeed");
    assert!(matches!(
        exhausted,
        LeaseDecision::Denied {
            reason: DenialReason::BudgetExhausted { .. }
        }
    ));

    // New window at tick 50: budget restored deterministically.
    let renewed = manager
        .request_use(
            "net-1",
            "ext-alpha",
            RuntimeCapability::NetworkEgress,
            &benign(),
            50,
        )
        .expect("request should succeed");
    assert!(matches!(renewed, LeaseDecision::Granted { .. }));

    // Elevated risk demands a challenge and spends nothing.
    let challenged = manager
        .request_use(
            "net-1",
            "ext-alpha",
            RuntimeCapability::NetworkEgress,
            &elevated(),
            51,
        )
        .expect("request should succeed");
    assert!(matches!(
        challenged,
        LeaseDecision::ChallengeRequired { .. }
    ));

    // Hostile risk revokes; the lease stays dead afterwards.
    let revoked = manager
        .request_use(
            "net-1",
            "ext-alpha",
            RuntimeCapability::NetworkEgress,
            &hostile(),
            52,
        )
        .expect("request should succeed");
    assert!(matches!(revoked, LeaseDecision::Revoked { .. }));
    assert_eq!(
        manager
            .lease_status("net-1")
            .expect("status should resolve"),
        CapabilityLeaseStatus::Revoked
    );
    let post_revoke = manager
        .request_use(
            "net-1",
            "ext-alpha",
            RuntimeCapability::NetworkEgress,
            &benign(),
            53,
        )
        .expect("request should succeed");
    assert!(matches!(
        post_revoke,
        LeaseDecision::Denied {
            reason: DenialReason::LeaseRevoked
        }
    ));

    // Every decision left a content-hashed receipt, in order.
    let receipts = manager.receipts();
    assert_eq!(receipts.len(), (affordable + 5) as usize);
    for (index, receipt) in receipts.iter().enumerate() {
        assert_eq!(receipt.receipt_id, format!("net-1#{}", index + 1));
        assert_eq!(receipt.policy_epoch, 11);
    }
    let kinds: Vec<&str> = receipts
        .iter()
        .map(|receipt| receipt.decision_kind.as_str())
        .collect();
    assert_eq!(
        kinds[kinds.len() - 4..].to_vec(),
        vec!["granted", "challenge_required", "revoked", "denied"]
    );

    // The report reflects the lifecycle and recommends review.
    let report = manager.report().expect("report should build");
    assert_eq!(report.schema_version, CAPABILITY_LEASE_SCHEMA_VERSION);
    let summary = &report.summaries[0];
    assert_eq!(summary.status, CapabilityLeaseStatus::Revoked);
    assert_eq!(summary.uses_granted, affordable as u64 + 1);
    assert_eq!(summary.challenges, 1);
    assert!(summary.denials >= 2);
    assert_eq!(
        summary.recommendation,
        LeaseRecommendation::ReviewBeforeRenewal
    );
    assert!(report.total_spend_millionths >= price * (affordable + 1));
}

#[test]
fn per_extension_spend_is_separated_in_the_report() {
    let mut manager = LeaseManager::balanced();
    manager
        .register_lease(egress_lease("net-alpha", "ext-alpha"))
        .expect("registration should succeed");
    manager
        .register_lease(egress_lease("net-beta", "ext-beta"))
        .expect("registration should succeed");

    manager
        .request_use(
            "net-alpha",
            "ext-alpha",
            RuntimeCapability::NetworkEgress,
            &benign(),
            1,
        )
        .expect("request should succeed");
    manager
        .request_use(
            "net-alpha",
            "ext-alpha",
            RuntimeCapability::NetworkEgress,
            &benign(),
            2,
        )
        .expect("request should succeed");
    manager
        .request_use(
            "net-beta",
            "ext-beta",
            RuntimeCapability::NetworkEgress,
            &benign(),
            1,
        )
        .expect("request should succeed");

    let report = manager.report().expect("report should build");
    let by_id = |id: &str| {
        report
            .summaries
            .iter()
            .find(|summary| summary.lease_id == id)
            .expect("summary should exist")
            .clone()
    };
    let alpha = by_id("net-alpha");
    let beta = by_id("net-beta");
    assert_eq!(alpha.extension_id, "ext-alpha");
    assert_eq!(beta.extension_id, "ext-beta");
    assert_eq!(alpha.uses_granted, 2);
    assert_eq!(beta.uses_granted, 1);
    assert_eq!(
        alpha.spend_total_millionths,
        2 * beta.spend_total_millionths
    );
    assert_eq!(
        report.total_spend_millionths,
        alpha.spend_total_millionths + beta.spend_total_millionths
    );
}

#[test]
fn authority_and_logical_clock_fail_closed_without_restoring_budget() {
    let mut constrained = egress_lease("net-1", "ext-alpha");
    constrained.window_budget_millionths = 2 * MILLION;
    constrained.budget_window_ticks = 10;
    let mut manager = LeaseManager::balanced();
    manager
        .register_lease(constrained)
        .expect("registration should succeed");

    let remaining_after_grant = match manager
        .request_use(
            "net-1",
            "ext-alpha",
            RuntimeCapability::NetworkEgress,
            &benign(),
            5,
        )
        .expect("authorized request should succeed")
    {
        LeaseDecision::Granted {
            remaining_budget_millionths,
            ..
        } => remaining_budget_millionths,
        other => panic!("expected grant, got {other:?}"),
    };

    let wrong_extension = manager
        .request_use(
            "net-1",
            "ext-other",
            RuntimeCapability::NetworkEgress,
            &benign(),
            10,
        )
        .expect("identity mismatch should produce a denial");
    assert!(matches!(
        wrong_extension,
        LeaseDecision::Denied {
            reason: DenialReason::ExtensionMismatch { .. }
        }
    ));

    let clock_regression = manager
        .request_use(
            "net-1",
            "ext-alpha",
            RuntimeCapability::NetworkEgress,
            &benign(),
            4,
        )
        .expect("clock regression should produce a denial");
    assert_eq!(
        clock_regression,
        LeaseDecision::Denied {
            reason: DenialReason::NonMonotonicTick {
                previous_tick: 5,
                requested_tick: 4,
            },
        }
    );

    assert!(
        manager
            .receipts()
            .iter()
            .all(|receipt| receipt.verify_content_hash())
    );
    assert_eq!(
        manager.receipts()[1].remaining_budget_millionths,
        remaining_after_grant
    );
    assert_eq!(
        manager.receipts()[2].remaining_budget_millionths,
        remaining_after_grant
    );

    let report = manager.report().expect("report should build");
    let summary = &report.summaries[0];
    assert_eq!(summary.extension_mismatches, 1);
    assert_eq!(summary.tick_regressions, 1);
    assert_eq!(summary.remaining_budget_millionths, remaining_after_grant);
    assert_eq!(
        summary.recommendation,
        LeaseRecommendation::ReviewExtensionMismatch,
        "identity misuse takes precedence over a clock repair recommendation"
    );
}

#[test]
fn report_and_receipts_are_deterministic_across_identical_runs() {
    let run = || -> (LeaseReport, usize) {
        let mut manager = LeaseManager::balanced();
        manager
            .register_lease(egress_lease("net-1", "ext-alpha"))
            .expect("registration should succeed");
        manager
            .request_use(
                "net-1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &benign(),
                1,
            )
            .expect("request should succeed");
        manager
            .request_use(
                "net-1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &elevated(),
                2,
            )
            .expect("request should succeed");
        (
            manager.report().expect("report should build"),
            manager.receipts().len(),
        )
    };
    let (first_report, first_receipts) = run();
    let (second_report, second_receipts) = run();
    assert_eq!(first_report, second_report);
    assert_eq!(first_receipts, second_receipts);
    assert_eq!(first_report.artifact_hash_hex.len(), 64);
}

#[test]
fn risk_pricing_is_monotone_in_posterior_hostility() {
    let manager = LeaseManager::balanced();
    let benign_price = manager.risk_price_millionths(&benign());
    let elevated_price = manager.risk_price_millionths(&elevated());
    let hostile_price = manager.risk_price_millionths(&hostile());
    assert!(benign_price < elevated_price);
    assert!(elevated_price < hostile_price);
}

#[test]
fn report_serde_round_trip() {
    let mut manager = LeaseManager::balanced();
    manager
        .register_lease(egress_lease("net-1", "ext-alpha"))
        .expect("registration should succeed");
    manager
        .request_use(
            "net-1",
            "ext-alpha",
            RuntimeCapability::NetworkEgress,
            &benign(),
            1,
        )
        .expect("request should succeed");
    let report = manager.report().expect("report should build");
    let json = serde_json::to_string(&report).expect("serialize should succeed");
    let decoded: LeaseReport = serde_json::from_str(&json).expect("deserialize should succeed");
    assert_eq!(decoded, report);
}
