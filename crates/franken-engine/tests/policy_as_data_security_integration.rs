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

// ===========================================================================
// 13. PolicyDataKind — Clone/Copy/Display/all variants
// ===========================================================================

#[test]
fn test_policy_data_kind_clone_copy() {
    let k = PolicyDataKind::GovernancePolicy;
    let k2 = k;
    let k3 = k.clone();
    assert_eq!(k, k2);
    assert_eq!(k, k3);
}

#[test]
fn test_policy_data_kind_debug_nonempty() {
    let kinds = [
        PolicyDataKind::LaneRouting,
        PolicyDataKind::SecurityPolicy,
        PolicyDataKind::ContainmentPolicy,
        PolicyDataKind::GovernancePolicy,
        PolicyDataKind::FallbackPolicy,
        PolicyDataKind::OptimizationPolicy,
    ];
    for k in &kinds {
        let dbg = format!("{k:?}");
        assert!(!dbg.is_empty());
    }
}

#[test]
fn test_policy_data_kind_display_exact_values() {
    assert_eq!(PolicyDataKind::LaneRouting.to_string(), "lane_routing");
    assert_eq!(
        PolicyDataKind::SecurityPolicy.to_string(),
        "security_policy"
    );
    assert_eq!(
        PolicyDataKind::ContainmentPolicy.to_string(),
        "containment_policy"
    );
    assert_eq!(
        PolicyDataKind::GovernancePolicy.to_string(),
        "governance_policy"
    );
    assert_eq!(
        PolicyDataKind::FallbackPolicy.to_string(),
        "fallback_policy"
    );
    assert_eq!(
        PolicyDataKind::OptimizationPolicy.to_string(),
        "optimization_policy"
    );
}

#[test]
fn test_policy_data_kind_full_ordering() {
    let mut kinds = vec![
        PolicyDataKind::OptimizationPolicy,
        PolicyDataKind::FallbackPolicy,
        PolicyDataKind::GovernancePolicy,
        PolicyDataKind::ContainmentPolicy,
        PolicyDataKind::SecurityPolicy,
        PolicyDataKind::LaneRouting,
    ];
    kinds.sort();
    assert_eq!(kinds[0], PolicyDataKind::LaneRouting);
    assert_eq!(kinds[5], PolicyDataKind::OptimizationPolicy);
}

// ===========================================================================
// 14. ScenarioCategory — Clone/Copy/Display/all variants
// ===========================================================================

#[test]
fn test_scenario_category_display_exact_values() {
    assert_eq!(
        ScenarioCategory::PolicyTampering.to_string(),
        "policy_tampering"
    );
    assert_eq!(ScenarioCategory::ReplayAttack.to_string(), "replay_attack");
    assert_eq!(
        ScenarioCategory::PrivilegeEscalation.to_string(),
        "privilege_escalation"
    );
    assert_eq!(
        ScenarioCategory::ResourceExhaustion.to_string(),
        "resource_exhaustion"
    );
    assert_eq!(
        ScenarioCategory::ContainmentEscape.to_string(),
        "containment_escape"
    );
    assert_eq!(
        ScenarioCategory::FallbackSuppression.to_string(),
        "fallback_suppression"
    );
}

#[test]
fn test_scenario_category_clone_copy() {
    let c = ScenarioCategory::ReplayAttack;
    let c2 = c;
    let c3 = c.clone();
    assert_eq!(c, c2);
    assert_eq!(c, c3);
}

#[test]
fn test_scenario_category_debug_nonempty() {
    let dbg = format!("{:?}", ScenarioCategory::ContainmentEscape);
    assert!(!dbg.is_empty());
}

#[test]
fn test_scenario_category_ordering() {
    assert!(ScenarioCategory::PolicyTampering < ScenarioCategory::ReplayAttack);
    assert!(ScenarioCategory::ReplayAttack < ScenarioCategory::PrivilegeEscalation);
    assert!(ScenarioCategory::PrivilegeEscalation < ScenarioCategory::ResourceExhaustion);
    assert!(ScenarioCategory::ResourceExhaustion < ScenarioCategory::ContainmentEscape);
    assert!(ScenarioCategory::ContainmentEscape < ScenarioCategory::FallbackSuppression);
}

// ===========================================================================
// 15. ExpectedOutcome — Clone/Copy/Display/all variants
// ===========================================================================

#[test]
fn test_expected_outcome_display_exact_values() {
    assert_eq!(ExpectedOutcome::Blocked.to_string(), "blocked");
    assert_eq!(
        ExpectedOutcome::FallbackTriggered.to_string(),
        "fallback_triggered"
    );
    assert_eq!(ExpectedOutcome::Contained.to_string(), "contained");
    assert_eq!(ExpectedOutcome::DetectedOnly.to_string(), "detected_only");
}

#[test]
fn test_expected_outcome_clone_copy() {
    let o = ExpectedOutcome::Contained;
    let o2 = o;
    let o3 = o.clone();
    assert_eq!(o, o2);
    assert_eq!(o, o3);
}

#[test]
fn test_expected_outcome_debug_nonempty() {
    let dbg = format!("{:?}", ExpectedOutcome::FallbackTriggered);
    assert!(!dbg.is_empty());
}

#[test]
fn test_expected_outcome_ordering() {
    assert!(ExpectedOutcome::Blocked < ExpectedOutcome::FallbackTriggered);
    assert!(ExpectedOutcome::FallbackTriggered < ExpectedOutcome::Contained);
    assert!(ExpectedOutcome::Contained < ExpectedOutcome::DetectedOnly);
}

// ===========================================================================
// 16. EscalationLevel — Clone/Copy/Display/all variants
// ===========================================================================

#[test]
fn test_escalation_level_display_exact_values() {
    assert_eq!(EscalationLevel::Observe.to_string(), "observe");
    assert_eq!(EscalationLevel::Alert.to_string(), "alert");
    assert_eq!(EscalationLevel::Mitigate.to_string(), "mitigate");
    assert_eq!(EscalationLevel::Escalate.to_string(), "escalate");
    assert_eq!(EscalationLevel::Emergency.to_string(), "emergency");
}

#[test]
fn test_escalation_level_clone_copy() {
    let l = EscalationLevel::Emergency;
    let l2 = l;
    let l3 = l.clone();
    assert_eq!(l, l2);
    assert_eq!(l, l3);
}

#[test]
fn test_escalation_level_debug_nonempty() {
    let dbg = format!("{:?}", EscalationLevel::Mitigate);
    assert!(!dbg.is_empty());
}

// ===========================================================================
// 17. SignedPolicyArtifact — edge cases
// ===========================================================================

#[test]
fn test_artifact_id_varies_by_name() {
    let id1 = SignedPolicyArtifact::compute_artifact_id(
        &PolicyDataKind::SecurityPolicy,
        "policy-a",
        1,
        &test_epoch(),
    );
    let id2 = SignedPolicyArtifact::compute_artifact_id(
        &PolicyDataKind::SecurityPolicy,
        "policy-b",
        1,
        &test_epoch(),
    );
    assert_ne!(id1, id2);
}

#[test]
fn test_artifact_id_varies_by_version() {
    let id1 = SignedPolicyArtifact::compute_artifact_id(
        &PolicyDataKind::SecurityPolicy,
        "my-policy",
        1,
        &test_epoch(),
    );
    let id2 = SignedPolicyArtifact::compute_artifact_id(
        &PolicyDataKind::SecurityPolicy,
        "my-policy",
        2,
        &test_epoch(),
    );
    assert_ne!(id1, id2);
}

#[test]
fn test_artifact_id_varies_by_epoch() {
    let epoch_a = SecurityEpoch::from_raw(1);
    let epoch_b = SecurityEpoch::from_raw(2);
    let id1 = SignedPolicyArtifact::compute_artifact_id(
        &PolicyDataKind::SecurityPolicy,
        "my-policy",
        1,
        &epoch_a,
    );
    let id2 = SignedPolicyArtifact::compute_artifact_id(
        &PolicyDataKind::SecurityPolicy,
        "my-policy",
        1,
        &epoch_b,
    );
    assert_ne!(id1, id2);
}

#[test]
fn test_artifact_id_has_pol_prefix() {
    let id = SignedPolicyArtifact::compute_artifact_id(
        &PolicyDataKind::LaneRouting,
        "lane-policy",
        5,
        &test_epoch(),
    );
    assert!(id.starts_with("pol-"));
}

#[test]
fn test_artifact_clone_eq() {
    let a = test_artifact();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn test_artifact_debug_nonempty() {
    let a = test_artifact();
    let dbg = format!("{a:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("SecurityPolicy"));
}

#[test]
fn test_artifact_preimage_nonempty() {
    let a = test_artifact();
    let p = a.preimage_bytes();
    assert!(!p.is_empty());
    // Should contain schema version bytes
    assert!(
        p.windows(frankenengine_engine::policy_as_data_security::SCHEMA_VERSION.len())
            .any(|w| w == frankenengine_engine::policy_as_data_security::SCHEMA_VERSION.as_bytes())
    );
}

#[test]
fn test_artifact_verify_empty_policy_bytes() {
    let empty_bytes: Vec<u8> = vec![];
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&empty_bytes);
    let hash = hex::encode(&hasher.finalize()[..16]);
    let a = SignedPolicyArtifact {
        artifact_id: "pol-test".into(),
        kind: PolicyDataKind::FallbackPolicy,
        policy_name: "empty-policy".into(),
        version: 0,
        epoch: test_epoch(),
        definition_hash: hash,
        policy_bytes: empty_bytes,
        signer_id: "signer-x".into(),
        signature_hex: "aabb".into(),
        tags: BTreeSet::new(),
        signed_at_ns: 0,
    };
    assert!(a.verify_definition_hash());
}

#[test]
fn test_artifact_version_zero() {
    let id = SignedPolicyArtifact::compute_artifact_id(
        &PolicyDataKind::OptimizationPolicy,
        "opt-policy",
        0,
        &test_epoch(),
    );
    assert!(!id.is_empty());
}

// ===========================================================================
// 18. PolicyVerificationResult — Clone/Debug
// ===========================================================================

#[test]
fn test_policy_verification_result_clone() {
    let r = PolicyVerificationResult {
        artifact_id: "pol-xyz".into(),
        definition_hash_valid: false,
        signature_valid: false,
        epoch_current: false,
        all_valid: false,
        detail: "hash mismatch".into(),
    };
    let r2 = r.clone();
    assert_eq!(r, r2);
}

#[test]
fn test_policy_verification_result_debug_nonempty() {
    let r = PolicyVerificationResult {
        artifact_id: "pol-xyz".into(),
        definition_hash_valid: true,
        signature_valid: true,
        epoch_current: true,
        all_valid: true,
        detail: "ok".into(),
    };
    let dbg = format!("{r:?}");
    assert!(dbg.contains("artifact_id"));
}

#[test]
fn test_policy_verification_result_all_false() {
    let r = PolicyVerificationResult {
        artifact_id: "pol-bad".into(),
        definition_hash_valid: false,
        signature_valid: false,
        epoch_current: false,
        all_valid: false,
        detail: "all checks failed".into(),
    };
    assert!(!r.all_valid);
    assert!(!r.definition_hash_valid);
    assert!(!r.signature_valid);
    assert!(!r.epoch_current);
    let json = serde_json::to_string(&r).unwrap();
    let back: PolicyVerificationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

// ===========================================================================
// 19. SandboxRestriction — additional edge cases
// ===========================================================================

#[test]
fn test_sandbox_restriction_clone_eq() {
    let sb = SandboxRestriction::deny_all("r-1".into());
    let sb2 = sb.clone();
    assert_eq!(sb, sb2);
}

#[test]
fn test_sandbox_restriction_debug_nonempty() {
    let sb = SandboxRestriction::deny_all("r-debug".into());
    let dbg = format!("{sb:?}");
    assert!(dbg.contains("restriction_id"));
}

#[test]
fn test_sandbox_multiple_capabilities_allowed() {
    let mut sb = SandboxRestriction::deny_all("multi-cap".into());
    sb.allowed_capabilities.insert("read".into());
    sb.allowed_capabilities.insert("write".into());
    sb.allowed_capabilities.insert("exec".into());
    assert!(sb.is_allowed("read"));
    assert!(sb.is_allowed("write"));
    assert!(sb.is_allowed("exec"));
    assert!(!sb.is_allowed("network"));
}

#[test]
fn test_sandbox_exact_memory_boundary() {
    let mut sb = SandboxRestriction::deny_all("mem-exact".into());
    sb.max_memory_bytes = 1024;
    assert!(!sb.would_exceed_memory(1024));
    assert!(!sb.would_exceed_memory(0));
    assert!(sb.would_exceed_memory(1025));
}

#[test]
fn test_sandbox_exact_time_boundary() {
    let mut sb = SandboxRestriction::deny_all("time-exact".into());
    sb.max_execution_ns = 5_000_000;
    assert!(!sb.would_exceed_time(5_000_000));
    assert!(!sb.would_exceed_time(0));
    assert!(sb.would_exceed_time(5_000_001));
}

#[test]
fn test_sandbox_allow_network_flag() {
    let mut sb = SandboxRestriction::deny_all("net-allowed".into());
    sb.allow_network = true;
    assert!(sb.allow_network);
    let json = serde_json::to_string(&sb).unwrap();
    let back: SandboxRestriction = serde_json::from_str(&json).unwrap();
    assert!(back.allow_network);
}

#[test]
fn test_sandbox_allow_fs_write_flag() {
    let mut sb = SandboxRestriction::deny_all("fs-write".into());
    sb.allow_fs_write = true;
    assert!(sb.allow_fs_write);
    let json = serde_json::to_string(&sb).unwrap();
    let back: SandboxRestriction = serde_json::from_str(&json).unwrap();
    assert!(back.allow_fs_write);
}

#[test]
fn test_sandbox_allow_process_spawn_flag() {
    let mut sb = SandboxRestriction::deny_all("spawn-ok".into());
    sb.allow_process_spawn = true;
    assert!(sb.allow_process_spawn);
    let json = serde_json::to_string(&sb).unwrap();
    let back: SandboxRestriction = serde_json::from_str(&json).unwrap();
    assert!(back.allow_process_spawn);
}

// ===========================================================================
// 20. PolicySandboxProfile — Clone/Debug/edge cases
// ===========================================================================

#[test]
fn test_policy_sandbox_profile_clone_eq() {
    let profile = PolicySandboxProfile {
        name: "clone-profile".into(),
        applicable_kinds: BTreeSet::from([PolicyDataKind::LaneRouting]),
        restriction: SandboxRestriction::deny_all("r-clone".into()),
        is_default: true,
    };
    let profile2 = profile.clone();
    assert_eq!(profile, profile2);
}

#[test]
fn test_policy_sandbox_profile_debug_nonempty() {
    let profile = PolicySandboxProfile {
        name: "debug-profile".into(),
        applicable_kinds: BTreeSet::new(),
        restriction: SandboxRestriction::deny_all("r-debug-p".into()),
        is_default: false,
    };
    let dbg = format!("{profile:?}");
    assert!(dbg.contains("name"));
}

#[test]
fn test_policy_sandbox_profile_multiple_kinds() {
    let profile = PolicySandboxProfile {
        name: "multi-kind".into(),
        applicable_kinds: BTreeSet::from([
            PolicyDataKind::LaneRouting,
            PolicyDataKind::FallbackPolicy,
            PolicyDataKind::ContainmentPolicy,
        ]),
        restriction: SandboxRestriction::deny_all("r-multi".into()),
        is_default: false,
    };
    assert_eq!(profile.applicable_kinds.len(), 3);
    assert!(
        profile
            .applicable_kinds
            .contains(&PolicyDataKind::LaneRouting)
    );
}

// ===========================================================================
// 21. AdversarialScenario — Clone/Debug/serde
// ===========================================================================

#[test]
fn test_adversarial_scenario_clone_eq() {
    let s = AdversarialScenario {
        scenario_id: "adv-clone".into(),
        name: "Clone Test".into(),
        category: ScenarioCategory::ReplayAttack,
        expected_outcome: ExpectedOutcome::Blocked,
        description: "Test clone".into(),
        severity_millionths: 500_000,
        target_kinds: BTreeSet::from([PolicyDataKind::GovernancePolicy]),
    };
    let s2 = s.clone();
    assert_eq!(s, s2);
}

#[test]
fn test_adversarial_scenario_debug_nonempty() {
    let s = AdversarialScenario {
        scenario_id: "adv-dbg".into(),
        name: "Debug Test".into(),
        category: ScenarioCategory::ContainmentEscape,
        expected_outcome: ExpectedOutcome::Contained,
        description: "Test debug".into(),
        severity_millionths: 1_000_000,
        target_kinds: BTreeSet::new(),
    };
    let dbg = format!("{s:?}");
    assert!(dbg.contains("scenario_id"));
}

#[test]
fn test_adversarial_scenario_serde_round_trip() {
    let s = AdversarialScenario {
        scenario_id: "adv-serde".into(),
        name: "Serde Test".into(),
        category: ScenarioCategory::FallbackSuppression,
        expected_outcome: ExpectedOutcome::FallbackTriggered,
        description: "Test serde".into(),
        severity_millionths: 700_000,
        target_kinds: BTreeSet::from([PolicyDataKind::FallbackPolicy]),
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: AdversarialScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
}

#[test]
fn test_adversarial_scenario_zero_severity() {
    let s = AdversarialScenario {
        scenario_id: "adv-zero".into(),
        name: "Zero Severity".into(),
        category: ScenarioCategory::ResourceExhaustion,
        expected_outcome: ExpectedOutcome::DetectedOnly,
        description: "Informational only".into(),
        severity_millionths: 0,
        target_kinds: BTreeSet::new(),
    };
    assert_eq!(s.severity_millionths, 0);
}

// ===========================================================================
// 22. ScenarioResult — Clone/Debug/serde
// ===========================================================================

#[test]
fn test_scenario_result_clone_eq() {
    let r = ScenarioResult {
        scenario_id: "s-clone".into(),
        actual_outcome: ExpectedOutcome::Blocked,
        passed: true,
        detail: "all good".into(),
        evidence_hash: "cafebabe".into(),
    };
    let r2 = r.clone();
    assert_eq!(r, r2);
}

#[test]
fn test_scenario_result_debug_nonempty() {
    let r = ScenarioResult {
        scenario_id: "s-dbg".into(),
        actual_outcome: ExpectedOutcome::Contained,
        passed: false,
        detail: "escaped".into(),
        evidence_hash: "deadbeef".into(),
    };
    let dbg = format!("{r:?}");
    assert!(dbg.contains("scenario_id"));
}

#[test]
fn test_scenario_result_serde_round_trip() {
    let r = ScenarioResult {
        scenario_id: "s-serde".into(),
        actual_outcome: ExpectedOutcome::FallbackTriggered,
        passed: true,
        detail: "fallback activated".into(),
        evidence_hash: "11223344".into(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: ScenarioResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

// ===========================================================================
// 23. AdversarialSuite — pass_rate_by_category and edge cases
// ===========================================================================

#[test]
fn test_suite_pass_rate_by_category_single_pass() {
    let mut suite = AdversarialSuite::new("rate-suite".into(), test_epoch());
    suite.add_scenario(AdversarialScenario {
        scenario_id: "r-1".into(),
        name: "rate test".into(),
        category: ScenarioCategory::PolicyTampering,
        expected_outcome: ExpectedOutcome::Blocked,
        description: "rate".into(),
        severity_millionths: 1_000_000,
        target_kinds: BTreeSet::new(),
    });
    suite.record_result(ScenarioResult {
        scenario_id: "r-1".into(),
        actual_outcome: ExpectedOutcome::Blocked,
        passed: true,
        detail: "ok".into(),
        evidence_hash: "ab".into(),
    });
    let rates = suite.pass_rate_by_category();
    let key = "policy_tampering";
    assert!(rates.contains_key(key));
    assert_eq!(rates[key], 1_000_000);
}

#[test]
fn test_suite_pass_rate_by_category_half_pass() {
    let mut suite = AdversarialSuite::new("half-suite".into(), test_epoch());
    for i in 1..=2 {
        suite.add_scenario(AdversarialScenario {
            scenario_id: format!("h-{i}"),
            name: format!("half {i}"),
            category: ScenarioCategory::ReplayAttack,
            expected_outcome: ExpectedOutcome::Blocked,
            description: "half".into(),
            severity_millionths: 500_000,
            target_kinds: BTreeSet::new(),
        });
    }
    suite.record_result(ScenarioResult {
        scenario_id: "h-1".into(),
        actual_outcome: ExpectedOutcome::Blocked,
        passed: true,
        detail: "pass".into(),
        evidence_hash: "aa".into(),
    });
    suite.record_result(ScenarioResult {
        scenario_id: "h-2".into(),
        actual_outcome: ExpectedOutcome::DetectedOnly,
        passed: false,
        detail: "fail".into(),
        evidence_hash: "bb".into(),
    });
    let rates = suite.pass_rate_by_category();
    let key = "replay_attack";
    assert!(rates.contains_key(key));
    assert_eq!(rates[key], 500_000); // 1/2 = 0.5 = 500_000
}

#[test]
fn test_suite_pass_rate_by_category_all_fail() {
    let mut suite = AdversarialSuite::new("fail-suite".into(), test_epoch());
    suite.add_scenario(AdversarialScenario {
        scenario_id: "f-1".into(),
        name: "fail test".into(),
        category: ScenarioCategory::PrivilegeEscalation,
        expected_outcome: ExpectedOutcome::Contained,
        description: "fail".into(),
        severity_millionths: 1_000_000,
        target_kinds: BTreeSet::new(),
    });
    suite.record_result(ScenarioResult {
        scenario_id: "f-1".into(),
        actual_outcome: ExpectedOutcome::DetectedOnly,
        passed: false,
        detail: "escaped".into(),
        evidence_hash: "cc".into(),
    });
    let rates = suite.pass_rate_by_category();
    let key = "privilege_escalation";
    assert_eq!(rates[key], 0);
}

#[test]
fn test_suite_pass_rate_empty_results_no_entries() {
    let suite = AdversarialSuite::new("empty-rate-suite".into(), test_epoch());
    let rates = suite.pass_rate_by_category();
    // No results recorded → no categories
    assert!(rates.is_empty());
}

#[test]
fn test_suite_multiple_categories_tracked_separately() {
    let mut suite = AdversarialSuite::new("multi-cat".into(), test_epoch());
    suite.add_scenario(AdversarialScenario {
        scenario_id: "mc-1".into(),
        name: "tamper".into(),
        category: ScenarioCategory::PolicyTampering,
        expected_outcome: ExpectedOutcome::Blocked,
        description: "t".into(),
        severity_millionths: 1_000_000,
        target_kinds: BTreeSet::new(),
    });
    suite.add_scenario(AdversarialScenario {
        scenario_id: "mc-2".into(),
        name: "exhaust".into(),
        category: ScenarioCategory::ResourceExhaustion,
        expected_outcome: ExpectedOutcome::Contained,
        description: "r".into(),
        severity_millionths: 600_000,
        target_kinds: BTreeSet::new(),
    });
    suite.record_result(ScenarioResult {
        scenario_id: "mc-1".into(),
        actual_outcome: ExpectedOutcome::Blocked,
        passed: true,
        detail: "ok".into(),
        evidence_hash: "e1".into(),
    });
    suite.record_result(ScenarioResult {
        scenario_id: "mc-2".into(),
        actual_outcome: ExpectedOutcome::DetectedOnly,
        passed: false,
        detail: "leaked".into(),
        evidence_hash: "e2".into(),
    });
    let rates = suite.pass_rate_by_category();
    assert_eq!(rates["policy_tampering"], 1_000_000);
    assert_eq!(rates["resource_exhaustion"], 0);
}

#[test]
fn test_suite_clone_eq() {
    let mut suite = AdversarialSuite::new("clone-suite".into(), test_epoch());
    suite.add_scenario(AdversarialScenario {
        scenario_id: "cs-1".into(),
        name: "test".into(),
        category: ScenarioCategory::PolicyTampering,
        expected_outcome: ExpectedOutcome::Blocked,
        description: "desc".into(),
        severity_millionths: 1_000_000,
        target_kinds: BTreeSet::new(),
    });
    let suite2 = suite.clone();
    assert_eq!(suite, suite2);
}

#[test]
fn test_suite_debug_nonempty() {
    let suite = AdversarialSuite::new("dbg-suite".into(), test_epoch());
    let dbg = format!("{suite:?}");
    assert!(dbg.contains("suite_name"));
}

// ===========================================================================
// 24. PlaybookStep — Clone/Debug/serde
// ===========================================================================

#[test]
fn test_playbook_step_clone_eq() {
    let step = PlaybookStep {
        step: 3,
        level: EscalationLevel::Emergency,
        action: "halt".into(),
        escalation_condition: "none".into(),
        max_duration_ns: 0,
    };
    let step2 = step.clone();
    assert_eq!(step, step2);
}

#[test]
fn test_playbook_step_debug_nonempty() {
    let step = PlaybookStep {
        step: 1,
        level: EscalationLevel::Alert,
        action: "notify".into(),
        escalation_condition: "timeout".into(),
        max_duration_ns: 30_000_000_000,
    };
    let dbg = format!("{step:?}");
    assert!(dbg.contains("step"));
}

#[test]
fn test_playbook_step_serde_round_trip() {
    let step = PlaybookStep {
        step: 2,
        level: EscalationLevel::Mitigate,
        action: "contain".into(),
        escalation_condition: "repeated".into(),
        max_duration_ns: 60_000_000_000,
    };
    let json = serde_json::to_string(&step).unwrap();
    let back: PlaybookStep = serde_json::from_str(&json).unwrap();
    assert_eq!(back, step);
}

// ===========================================================================
// 25. FailurePlaybook — additional edge cases
// ===========================================================================

#[test]
fn test_playbook_clone_eq() {
    let pb = FailurePlaybook::new(
        "pb-clone".into(),
        ScenarioCategory::ContainmentEscape,
        vec![PlaybookStep {
            step: 1,
            level: EscalationLevel::Observe,
            action: "watch".into(),
            escalation_condition: "detect".into(),
            max_duration_ns: 0,
        }],
        false,
    );
    let pb2 = pb.clone();
    assert_eq!(pb, pb2);
}

#[test]
fn test_playbook_debug_nonempty() {
    let pb = FailurePlaybook::new(
        "pb-dbg".into(),
        ScenarioCategory::ReplayAttack,
        vec![],
        true,
    );
    let dbg = format!("{pb:?}");
    assert!(dbg.contains("playbook_id"));
}

#[test]
fn test_playbook_content_hash_nonempty() {
    let pb = FailurePlaybook::new(
        "pb-hash".into(),
        ScenarioCategory::FallbackSuppression,
        vec![],
        false,
    );
    assert!(!pb.content_hash.is_empty());
}

#[test]
fn test_playbook_content_hash_differs_by_id() {
    let pb1 = FailurePlaybook::new(
        "pb-id-1".into(),
        ScenarioCategory::PolicyTampering,
        vec![],
        false,
    );
    let pb2 = FailurePlaybook::new(
        "pb-id-2".into(),
        ScenarioCategory::PolicyTampering,
        vec![],
        false,
    );
    assert_ne!(pb1.content_hash, pb2.content_hash);
}

#[test]
fn test_playbook_content_hash_differs_by_category() {
    let pb1 = FailurePlaybook::new(
        "pb-cat".into(),
        ScenarioCategory::PolicyTampering,
        vec![],
        false,
    );
    let pb2 = FailurePlaybook::new(
        "pb-cat".into(),
        ScenarioCategory::ReplayAttack,
        vec![],
        false,
    );
    assert_ne!(pb1.content_hash, pb2.content_hash);
}

#[test]
fn test_playbook_single_observe_max_level() {
    let pb = FailurePlaybook::new(
        "pb-observe".into(),
        ScenarioCategory::ResourceExhaustion,
        vec![PlaybookStep {
            step: 1,
            level: EscalationLevel::Observe,
            action: "log".into(),
            escalation_condition: "none".into(),
            max_duration_ns: 0,
        }],
        true,
    );
    assert_eq!(pb.max_level(), Some(EscalationLevel::Observe));
}

#[test]
fn test_playbook_allows_deescalation_preserved() {
    let pb_allow = FailurePlaybook::new(
        "pb-deesc-allow".into(),
        ScenarioCategory::PolicyTampering,
        vec![],
        true,
    );
    let pb_deny = FailurePlaybook::new(
        "pb-deesc-deny".into(),
        ScenarioCategory::PolicyTampering,
        vec![],
        false,
    );
    assert!(pb_allow.allows_deescalation);
    assert!(!pb_deny.allows_deescalation);
}

#[test]
fn test_playbook_serde_with_steps() {
    let pb = FailurePlaybook::new(
        "pb-full-serde".into(),
        ScenarioCategory::ContainmentEscape,
        vec![
            PlaybookStep {
                step: 1,
                level: EscalationLevel::Alert,
                action: "notify".into(),
                escalation_condition: "30s timeout".into(),
                max_duration_ns: 30_000_000_000,
            },
            PlaybookStep {
                step: 2,
                level: EscalationLevel::Emergency,
                action: "shutdown".into(),
                escalation_condition: "irrecoverable".into(),
                max_duration_ns: 0,
            },
        ],
        false,
    );
    let json = serde_json::to_string(&pb).unwrap();
    let back: FailurePlaybook = serde_json::from_str(&json).unwrap();
    assert_eq!(back, pb);
    assert_eq!(back.step_count(), 2);
}

// ===========================================================================
// 26. SecurityReport — Clone/Debug/edge cases
// ===========================================================================

#[test]
fn test_security_report_clone_eq() {
    let suite = AdversarialSuite::new("clone-report".into(), test_epoch());
    let report = generate_report(&test_epoch(), 5, 5, &suite, 2, 3);
    let report2 = report.clone();
    assert_eq!(report, report2);
}

#[test]
fn test_security_report_debug_nonempty() {
    let suite = AdversarialSuite::new("dbg-report".into(), test_epoch());
    let report = generate_report(&test_epoch(), 0, 0, &suite, 0, 0);
    let dbg = format!("{report:?}");
    assert!(dbg.contains("schema_version"));
}

#[test]
fn test_report_zero_artifacts_max_artifact_rate() {
    // With zero artifacts, artifact_rate = MILLION (no risk)
    let suite = AdversarialSuite::new("zero-art".into(), test_epoch());
    let report = generate_report(&test_epoch(), 0, 0, &suite, 1, 1);
    // artifact_rate=1_000_000 (40%), adversarial_rate=0 (40%), playbook_rate=1_000_000 (20%)
    // posture = (1_000_000*400_000 + 0 + 1_000_000*200_000) / 1_000_000 = 600_000
    assert_eq!(report.security_posture_millionths, 600_000);
}

#[test]
fn test_report_no_playbooks_reduces_posture() {
    let mut suite = AdversarialSuite::new("no-pb".into(), test_epoch());
    suite.add_scenario(AdversarialScenario {
        scenario_id: "np-1".into(),
        name: "test".into(),
        category: ScenarioCategory::PolicyTampering,
        expected_outcome: ExpectedOutcome::Blocked,
        description: "d".into(),
        severity_millionths: 1_000_000,
        target_kinds: BTreeSet::new(),
    });
    suite.record_result(ScenarioResult {
        scenario_id: "np-1".into(),
        actual_outcome: ExpectedOutcome::Blocked,
        passed: true,
        detail: "ok".into(),
        evidence_hash: "ev1".into(),
    });
    // No playbooks: playbook_rate = 0
    let report = generate_report(&test_epoch(), 1, 1, &suite, 0, 1);
    // artifact_rate=1_000_000 (40%), adversarial_rate=1_000_000 (40%), playbook_rate=0 (20%)
    // posture = (1_000_000*400_000 + 1_000_000*400_000 + 0) / 1_000_000 = 800_000
    assert_eq!(report.security_posture_millionths, 800_000);
}

#[test]
fn test_report_report_hash_nonempty() {
    let suite = AdversarialSuite::new("hash-report".into(), test_epoch());
    let report = generate_report(&test_epoch(), 3, 3, &suite, 1, 2);
    assert!(!report.report_hash.is_empty());
}

#[test]
fn test_report_report_hash_deterministic() {
    let suite1 = AdversarialSuite::new("det-suite".into(), test_epoch());
    let suite2 = AdversarialSuite::new("det-suite".into(), test_epoch());
    let r1 = generate_report(&test_epoch(), 5, 4, &suite1, 2, 3);
    let r2 = generate_report(&test_epoch(), 5, 4, &suite2, 2, 3);
    assert_eq!(r1.report_hash, r2.report_hash);
}

#[test]
fn test_report_category_pass_rates_in_report() {
    let mut suite = AdversarialSuite::new("cat-report".into(), test_epoch());
    suite.add_scenario(AdversarialScenario {
        scenario_id: "cr-1".into(),
        name: "tamper".into(),
        category: ScenarioCategory::PolicyTampering,
        expected_outcome: ExpectedOutcome::Blocked,
        description: "d".into(),
        severity_millionths: 1_000_000,
        target_kinds: BTreeSet::new(),
    });
    suite.record_result(ScenarioResult {
        scenario_id: "cr-1".into(),
        actual_outcome: ExpectedOutcome::Blocked,
        passed: true,
        detail: "ok".into(),
        evidence_hash: "ev".into(),
    });
    let report = generate_report(&test_epoch(), 1, 1, &suite, 1, 1);
    assert!(report.category_pass_rates.contains_key("policy_tampering"));
    assert_eq!(report.category_pass_rates["policy_tampering"], 1_000_000);
}

// ===========================================================================
// 27. Canonical functions — additional coverage
// ===========================================================================

#[test]
fn test_canonical_scenarios_all_nonempty_ids() {
    let scenarios = canonical_adversarial_scenarios();
    for s in &scenarios {
        assert!(!s.scenario_id.is_empty());
        assert!(!s.name.is_empty());
        assert!(!s.description.is_empty());
    }
}

#[test]
fn test_canonical_scenarios_positive_severity() {
    let scenarios = canonical_adversarial_scenarios();
    for s in &scenarios {
        assert!(
            s.severity_millionths > 0,
            "scenario {} has zero severity",
            s.scenario_id
        );
    }
}

#[test]
fn test_canonical_playbooks_cover_multiple_categories() {
    let playbooks = canonical_failure_playbooks();
    let cats: BTreeSet<ScenarioCategory> = playbooks.iter().map(|p| p.scenario_category).collect();
    assert!(cats.len() >= 2);
}

#[test]
fn test_canonical_playbooks_all_have_nonempty_hash() {
    let playbooks = canonical_failure_playbooks();
    for pb in &playbooks {
        assert!(
            !pb.content_hash.is_empty(),
            "playbook {} has empty hash",
            pb.playbook_id
        );
    }
}

#[test]
fn test_canonical_profiles_serde_round_trips() {
    let profiles = canonical_sandbox_profiles();
    for profile in &profiles {
        let json = serde_json::to_string(profile).unwrap();
        let back: PolicySandboxProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *profile);
    }
}

#[test]
fn test_canonical_scenarios_serde_round_trips() {
    let scenarios = canonical_adversarial_scenarios();
    for s in &scenarios {
        let json = serde_json::to_string(s).unwrap();
        let back: AdversarialScenario = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *s);
    }
}

#[test]
fn test_canonical_playbooks_serde_round_trips() {
    let playbooks = canonical_failure_playbooks();
    for pb in &playbooks {
        let json = serde_json::to_string(pb).unwrap();
        let back: FailurePlaybook = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *pb);
    }
}
