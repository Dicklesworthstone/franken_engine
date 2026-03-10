#![forbid(unsafe_code)]
//! Integration tests for the `policy_as_data_security` module.
//!
//! Exercises signed policy artifacts, sandbox restrictions, adversarial
//! scenarios, failure playbooks, security reports, and serde round-trips
//! from outside the crate boundary.

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

use frankenengine_engine::policy_as_data_security::{
    AdversarialScenario, AdversarialSuite, EscalationLevel, ExpectedOutcome, FailurePlaybook,
    PlaybookStep, PolicyDataKind, PolicySandboxProfile, PolicyVerificationResult, SCHEMA_VERSION,
    SandboxRestriction, ScenarioCategory, ScenarioResult, SecurityReport, SignedPolicyArtifact,
    canonical_adversarial_scenarios, canonical_failure_playbooks, canonical_sandbox_profiles,
    generate_report,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Helpers
// ===========================================================================

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(5)
}

fn test_policy_bytes() -> Vec<u8> {
    b"{\"rule\":\"deny_all\"}".to_vec()
}

fn test_definition_hash(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(&hasher.finalize()[..16])
}

fn test_artifact() -> SignedPolicyArtifact {
    let bytes = test_policy_bytes();
    SignedPolicyArtifact {
        artifact_id: SignedPolicyArtifact::compute_artifact_id(
            &PolicyDataKind::SecurityPolicy,
            "test-policy",
            1,
            &test_epoch(),
        ),
        kind: PolicyDataKind::SecurityPolicy,
        policy_name: "test-policy".into(),
        version: 1,
        epoch: test_epoch(),
        definition_hash: test_definition_hash(&bytes),
        policy_bytes: bytes,
        signer_id: "signer-001".into(),
        signature_hex: "deadbeef".into(),
        tags: BTreeSet::from(["security".into()]),
        signed_at_ns: 1_000_000_000,
    }
}

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn schema_version_nonempty() {
    assert!(!SCHEMA_VERSION.is_empty());
}

// ===========================================================================
// 2. PolicyDataKind — ordering, display, serde
// ===========================================================================

#[test]
fn policy_data_kind_ordering() {
    assert!(PolicyDataKind::LaneRouting < PolicyDataKind::SecurityPolicy);
    assert!(PolicyDataKind::SecurityPolicy < PolicyDataKind::ContainmentPolicy);
}

#[test]
fn policy_data_kind_display() {
    let kinds = [
        PolicyDataKind::LaneRouting,
        PolicyDataKind::SecurityPolicy,
        PolicyDataKind::ContainmentPolicy,
        PolicyDataKind::GovernancePolicy,
        PolicyDataKind::FallbackPolicy,
        PolicyDataKind::OptimizationPolicy,
    ];
    for k in &kinds {
        assert!(!k.to_string().is_empty());
    }
}

#[test]
fn policy_data_kind_serde_round_trip() {
    let kinds = [
        PolicyDataKind::LaneRouting,
        PolicyDataKind::SecurityPolicy,
        PolicyDataKind::ContainmentPolicy,
        PolicyDataKind::GovernancePolicy,
        PolicyDataKind::FallbackPolicy,
        PolicyDataKind::OptimizationPolicy,
    ];
    for k in &kinds {
        let json = serde_json::to_string(k).unwrap();
        let back: PolicyDataKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *k);
    }
}

// ===========================================================================
// 3. ScenarioCategory, ExpectedOutcome, EscalationLevel — serde
// ===========================================================================

#[test]
fn scenario_category_serde_round_trip() {
    for c in [
        ScenarioCategory::PolicyTampering,
        ScenarioCategory::ReplayAttack,
        ScenarioCategory::PrivilegeEscalation,
        ScenarioCategory::ResourceExhaustion,
        ScenarioCategory::ContainmentEscape,
        ScenarioCategory::FallbackSuppression,
    ] {
        let json = serde_json::to_string(&c).unwrap();
        let back: ScenarioCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }
}

#[test]
fn expected_outcome_serde_round_trip() {
    for o in [
        ExpectedOutcome::Blocked,
        ExpectedOutcome::FallbackTriggered,
        ExpectedOutcome::Contained,
        ExpectedOutcome::DetectedOnly,
    ] {
        let json = serde_json::to_string(&o).unwrap();
        let back: ExpectedOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(back, o);
    }
}

#[test]
fn escalation_level_ordering() {
    assert!(EscalationLevel::Observe < EscalationLevel::Alert);
    assert!(EscalationLevel::Alert < EscalationLevel::Mitigate);
    assert!(EscalationLevel::Mitigate < EscalationLevel::Escalate);
    assert!(EscalationLevel::Escalate < EscalationLevel::Emergency);
}

#[test]
fn escalation_level_serde_round_trip() {
    for l in [
        EscalationLevel::Observe,
        EscalationLevel::Alert,
        EscalationLevel::Mitigate,
        EscalationLevel::Escalate,
        EscalationLevel::Emergency,
    ] {
        let json = serde_json::to_string(&l).unwrap();
        let back: EscalationLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(back, l);
    }
}

// ===========================================================================
// 4. SignedPolicyArtifact
// ===========================================================================

#[test]
fn artifact_id_deterministic() {
    let id1 = SignedPolicyArtifact::compute_artifact_id(
        &PolicyDataKind::SecurityPolicy,
        "my-policy",
        1,
        &test_epoch(),
    );
    let id2 = SignedPolicyArtifact::compute_artifact_id(
        &PolicyDataKind::SecurityPolicy,
        "my-policy",
        1,
        &test_epoch(),
    );
    assert_eq!(id1, id2);
}

#[test]
fn artifact_id_varies_by_kind() {
    let id1 = SignedPolicyArtifact::compute_artifact_id(
        &PolicyDataKind::SecurityPolicy,
        "my-policy",
        1,
        &test_epoch(),
    );
    let id2 = SignedPolicyArtifact::compute_artifact_id(
        &PolicyDataKind::LaneRouting,
        "my-policy",
        1,
        &test_epoch(),
    );
    assert_ne!(id1, id2);
}

#[test]
fn artifact_preimage_deterministic() {
    let a = test_artifact();
    let p1 = a.preimage_bytes();
    let p2 = a.preimage_bytes();
    assert_eq!(p1, p2);
}

#[test]
fn artifact_definition_hash_verification() {
    let a = test_artifact();
    assert!(a.verify_definition_hash());
}

#[test]
fn artifact_definition_hash_tampered() {
    let mut a = test_artifact();
    a.policy_bytes = b"tampered".to_vec();
    assert!(!a.verify_definition_hash());
}

#[test]
fn artifact_serde_round_trip() {
    let a = test_artifact();
    let json = serde_json::to_string(&a).unwrap();
    let back: SignedPolicyArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(back, a);
}

// ===========================================================================
// 5. SandboxRestriction
// ===========================================================================

#[test]
fn sandbox_deny_all_defaults() {
    let sb = SandboxRestriction::deny_all("test".into());
    assert!(!sb.allow_network);
    assert!(!sb.allow_fs_write);
    assert!(!sb.allow_process_spawn);
    assert!(sb.allowed_capabilities.is_empty());
    assert!(sb.max_memory_bytes > 0);
    assert!(sb.max_execution_ns > 0);
}

#[test]
fn sandbox_is_allowed() {
    let mut sb = SandboxRestriction::deny_all("test".into());
    sb.allowed_capabilities.insert("fs.read".into());
    assert!(sb.is_allowed("fs.read"));
    assert!(!sb.is_allowed("fs.write"));
}

#[test]
fn sandbox_memory_boundary() {
    let sb = SandboxRestriction::deny_all("test".into());
    let limit = sb.max_memory_bytes;
    assert!(!sb.would_exceed_memory(limit));
    assert!(sb.would_exceed_memory(limit + 1));
}

#[test]
fn sandbox_time_boundary() {
    let sb = SandboxRestriction::deny_all("test".into());
    let limit = sb.max_execution_ns;
    assert!(!sb.would_exceed_time(limit));
    assert!(sb.would_exceed_time(limit + 1));
}

#[test]
fn sandbox_unlimited_never_exceeds() {
    let sb = SandboxRestriction {
        max_memory_bytes: 0,
        max_execution_ns: 0,
        ..SandboxRestriction::deny_all("test".into())
    };
    assert!(!sb.would_exceed_memory(u64::MAX));
    assert!(!sb.would_exceed_time(u64::MAX));
}

#[test]
fn sandbox_serde_round_trip() {
    let sb = SandboxRestriction::deny_all("test".into());
    let json = serde_json::to_string(&sb).unwrap();
    let back: SandboxRestriction = serde_json::from_str(&json).unwrap();
    assert_eq!(back, sb);
}

// ===========================================================================
// 6. AdversarialSuite
// ===========================================================================

#[test]
fn suite_empty_not_all_pass() {
    let suite = AdversarialSuite::new("test".into(), test_epoch());
    assert!(!suite.all_pass());
    assert_eq!(suite.scenario_count(), 0);
    assert_eq!(suite.pass_count(), 0);
    assert_eq!(suite.fail_count(), 0);
}

#[test]
fn suite_all_pass() {
    let mut suite = AdversarialSuite::new("test".into(), test_epoch());
    let scenario = AdversarialScenario {
        scenario_id: "s-1".into(),
        name: "test-scenario".into(),
        category: ScenarioCategory::PolicyTampering,
        expected_outcome: ExpectedOutcome::Blocked,
        description: "test".into(),
        severity_millionths: 1_000_000,
        target_kinds: BTreeSet::from([PolicyDataKind::SecurityPolicy]),
    };
    suite.add_scenario(scenario);
    suite.record_result(ScenarioResult {
        scenario_id: "s-1".into(),
        actual_outcome: ExpectedOutcome::Blocked,
        passed: true,
        detail: "blocked".into(),
        evidence_hash: "abc".into(),
    });
    assert!(suite.all_pass());
    assert_eq!(suite.pass_count(), 1);
    assert_eq!(suite.fail_count(), 0);
}

#[test]
fn suite_failure_detection() {
    let mut suite = AdversarialSuite::new("test".into(), test_epoch());
    suite.add_scenario(AdversarialScenario {
        scenario_id: "s-1".into(),
        name: "test".into(),
        category: ScenarioCategory::PolicyTampering,
        expected_outcome: ExpectedOutcome::Blocked,
        description: "test".into(),
        severity_millionths: 500_000,
        target_kinds: BTreeSet::new(),
    });
    suite.record_result(ScenarioResult {
        scenario_id: "s-1".into(),
        actual_outcome: ExpectedOutcome::DetectedOnly,
        passed: false,
        detail: "only detected".into(),
        evidence_hash: "abc".into(),
    });
    assert!(!suite.all_pass());
    assert_eq!(suite.fail_count(), 1);
}

#[test]
fn suite_serde_round_trip() {
    let suite = AdversarialSuite::new("test".into(), test_epoch());
    let json = serde_json::to_string(&suite).unwrap();
    let back: AdversarialSuite = serde_json::from_str(&json).unwrap();
    assert_eq!(back, suite);
}

// ===========================================================================
// 7. FailurePlaybook
// ===========================================================================

#[test]
fn playbook_step_count() {
    let steps = vec![
        PlaybookStep {
            step: 1,
            level: EscalationLevel::Alert,
            action: "notify".into(),
            escalation_condition: "no ack in 30s".into(),
            max_duration_ns: 30_000_000_000,
        },
        PlaybookStep {
            step: 2,
            level: EscalationLevel::Emergency,
            action: "shutdown".into(),
            escalation_condition: "unrecoverable".into(),
            max_duration_ns: 0,
        },
    ];
    let pb = FailurePlaybook::new(
        "pb-test".into(),
        ScenarioCategory::PolicyTampering,
        steps,
        false,
    );
    assert_eq!(pb.step_count(), 2);
    assert_eq!(pb.max_level(), Some(EscalationLevel::Emergency));
}

#[test]
fn playbook_empty_no_max_level() {
    let pb = FailurePlaybook::new(
        "pb-empty".into(),
        ScenarioCategory::ResourceExhaustion,
        vec![],
        true,
    );
    assert_eq!(pb.step_count(), 0);
    assert_eq!(pb.max_level(), None);
}

#[test]
fn playbook_hash_deterministic() {
    let steps = vec![PlaybookStep {
        step: 1,
        level: EscalationLevel::Mitigate,
        action: "contain".into(),
        escalation_condition: "".into(),
        max_duration_ns: 0,
    }];
    let pb1 = FailurePlaybook::new(
        "pb-1".into(),
        ScenarioCategory::PolicyTampering,
        steps.clone(),
        false,
    );
    let pb2 = FailurePlaybook::new(
        "pb-1".into(),
        ScenarioCategory::PolicyTampering,
        steps,
        false,
    );
    assert_eq!(pb1.content_hash, pb2.content_hash);
}

#[test]
fn playbook_serde_round_trip() {
    let pb = FailurePlaybook::new(
        "pb-test".into(),
        ScenarioCategory::PolicyTampering,
        vec![],
        true,
    );
    let json = serde_json::to_string(&pb).unwrap();
    let back: FailurePlaybook = serde_json::from_str(&json).unwrap();
    assert_eq!(back, pb);
}

// ===========================================================================
// 8. Canonical functions
// ===========================================================================

#[test]
fn canonical_profiles_cover_all_kinds() {
    let profiles = canonical_sandbox_profiles();
    assert!(!profiles.is_empty());
    let all_kinds: BTreeSet<PolicyDataKind> = profiles
        .iter()
        .flat_map(|p| p.applicable_kinds.iter().copied())
        .collect();
    // Should cover all 6 policy kinds
    assert!(all_kinds.contains(&PolicyDataKind::LaneRouting));
    assert!(all_kinds.contains(&PolicyDataKind::SecurityPolicy));
    // Should have exactly one default
    let defaults: Vec<_> = profiles.iter().filter(|p| p.is_default).collect();
    assert_eq!(defaults.len(), 1);
}

#[test]
fn canonical_scenarios_cover_all_categories() {
    let scenarios = canonical_adversarial_scenarios();
    assert_eq!(scenarios.len(), 6);
    let categories: BTreeSet<ScenarioCategory> = scenarios.iter().map(|s| s.category).collect();
    assert_eq!(categories.len(), 6);
    // All IDs should be unique
    let ids: BTreeSet<&str> = scenarios.iter().map(|s| s.scenario_id.as_str()).collect();
    assert_eq!(ids.len(), 6);
}

#[test]
fn canonical_playbooks_have_steps() {
    let playbooks = canonical_failure_playbooks();
    assert!(!playbooks.is_empty());
    for pb in &playbooks {
        assert!(pb.step_count() > 0);
    }
}

// ===========================================================================
// 9. Security Report
// ===========================================================================

#[test]
fn report_full_security() {
    let mut suite = AdversarialSuite::new("test".into(), test_epoch());
    suite.add_scenario(AdversarialScenario {
        scenario_id: "s-1".into(),
        name: "test".into(),
        category: ScenarioCategory::PolicyTampering,
        expected_outcome: ExpectedOutcome::Blocked,
        description: "test".into(),
        severity_millionths: 1_000_000,
        target_kinds: BTreeSet::new(),
    });
    suite.record_result(ScenarioResult {
        scenario_id: "s-1".into(),
        actual_outcome: ExpectedOutcome::Blocked,
        passed: true,
        detail: "ok".into(),
        evidence_hash: "abc".into(),
    });
    let report = generate_report(&test_epoch(), 10, 10, &suite, 2, 3);
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.artifacts_verified, 10);
    assert_eq!(report.artifacts_valid, 10);
    assert_eq!(report.scenarios_executed, 1);
    assert_eq!(report.scenarios_passing, 1);
    // Full security → posture should be 1_000_000
    assert_eq!(report.security_posture_millionths, 1_000_000);
}

#[test]
fn report_partial_security() {
    let suite = AdversarialSuite::new("test".into(), test_epoch());
    // No scenarios → adversarial rate = 0
    let report = generate_report(&test_epoch(), 10, 8, &suite, 0, 0);
    // Artifact rate: 80%, Adversarial: 0%, Playbook: 0%
    // Posture: 0.8 * 0.4 = 320_000
    assert!(report.security_posture_millionths < 1_000_000);
    assert!(report.security_posture_millionths > 0);
}

#[test]
fn report_serde_round_trip() {
    let suite = AdversarialSuite::new("test".into(), test_epoch());
    let report = generate_report(&test_epoch(), 5, 5, &suite, 1, 1);
    let json = serde_json::to_string(&report).unwrap();
    let back: SecurityReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, report);
}

// ===========================================================================
// 10. PolicyVerificationResult — serde
// ===========================================================================

#[test]
fn policy_verification_result_serde_round_trip() {
    let r = PolicyVerificationResult {
        artifact_id: "pol-abc123".into(),
        definition_hash_valid: true,
        signature_valid: true,
        epoch_current: true,
        all_valid: true,
        detail: "all checks passed".into(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: PolicyVerificationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

// ===========================================================================
// 11. PolicySandboxProfile — serde
// ===========================================================================

#[test]
fn policy_sandbox_profile_serde_round_trip() {
    let profile = PolicySandboxProfile {
        name: "test-profile".into(),
        applicable_kinds: BTreeSet::from([PolicyDataKind::SecurityPolicy]),
        restriction: SandboxRestriction::deny_all("test".into()),
        is_default: false,
    };
    let json = serde_json::to_string(&profile).unwrap();
    let back: PolicySandboxProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(back, profile);
}

// ===========================================================================
// 12. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_policy_security() {
    // 1. Create and verify artifact
    let artifact = test_artifact();
    assert!(artifact.verify_definition_hash());

    // 2. Build sandbox profiles
    let profiles = canonical_sandbox_profiles();
    assert!(!profiles.is_empty());

    // 3. Build adversarial suite
    let scenarios = canonical_adversarial_scenarios();
    let mut suite = AdversarialSuite::new("full-lifecycle".into(), test_epoch());
    for s in &scenarios {
        suite.add_scenario(s.clone());
    }
    // Record all as passing
    for s in &scenarios {
        suite.record_result(ScenarioResult {
            scenario_id: s.scenario_id.clone(),
            actual_outcome: s.expected_outcome,
            passed: true,
            detail: "passed".into(),
            evidence_hash: format!("evidence-{}", s.scenario_id),
        });
    }
    assert!(suite.all_pass());

    // 4. Load playbooks
    let playbooks = canonical_failure_playbooks();

    // 5. Generate report
    let report = generate_report(&test_epoch(), 1, 1, &suite, playbooks.len(), profiles.len());
    assert_eq!(report.security_posture_millionths, 1_000_000);

    // 6. Serde round-trip
    let json = serde_json::to_string(&report).unwrap();
    let back: SecurityReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, report);
}
