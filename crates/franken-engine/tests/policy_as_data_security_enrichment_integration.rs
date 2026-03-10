#![forbid(unsafe_code)]
//! Enrichment integration tests for `policy_as_data_security`.
//!
//! Adds Display exactness, Debug distinctness, serde exact tags,
//! JSON field-name stability, serde roundtrips, factory functions,
//! and edge-case validation beyond the existing 37 integration tests.

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
    PlaybookStep, PolicyDataKind, PolicyVerificationResult, SCHEMA_VERSION, SandboxRestriction,
    ScenarioCategory, ScenarioResult, SecurityReport, SignedPolicyArtifact,
    canonical_adversarial_scenarios, canonical_failure_playbooks, canonical_sandbox_profiles,
    generate_report,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// helpers
// ===========================================================================

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(5)
}

fn test_artifact() -> SignedPolicyArtifact {
    let bytes = b"{\"rule\":\"deny_all\"}".to_vec();
    let def_hash = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&bytes);
        hex::encode(&h.finalize()[..16])
    };
    let artifact_id = SignedPolicyArtifact::compute_artifact_id(
        &PolicyDataKind::SecurityPolicy,
        "test-policy",
        1,
        &test_epoch(),
    );
    SignedPolicyArtifact {
        artifact_id,
        kind: PolicyDataKind::SecurityPolicy,
        policy_name: "test-policy".into(),
        version: 1,
        epoch: test_epoch(),
        definition_hash: def_hash,
        policy_bytes: bytes,
        signer_id: "signer-001".into(),
        signature_hex: "deadbeef".into(),
        tags: BTreeSet::from(["security".into()]),
        signed_at_ns: 1_000_000_000,
    }
}

// ===========================================================================
// 1) SCHEMA_VERSION constant
// ===========================================================================

#[test]
fn schema_version_exact_value() {
    assert_eq!(SCHEMA_VERSION, "franken-engine.policy-as-data-security.v1");
}

// ===========================================================================
// 2) PolicyDataKind — Display exact values
// ===========================================================================

#[test]
fn policy_data_kind_display_lane_routing() {
    assert_eq!(PolicyDataKind::LaneRouting.to_string(), "lane_routing");
}

#[test]
fn policy_data_kind_display_security_policy() {
    assert_eq!(
        PolicyDataKind::SecurityPolicy.to_string(),
        "security_policy"
    );
}

#[test]
fn policy_data_kind_display_containment_policy() {
    assert_eq!(
        PolicyDataKind::ContainmentPolicy.to_string(),
        "containment_policy"
    );
}

#[test]
fn policy_data_kind_display_governance_policy() {
    assert_eq!(
        PolicyDataKind::GovernancePolicy.to_string(),
        "governance_policy"
    );
}

#[test]
fn policy_data_kind_display_fallback_policy() {
    assert_eq!(
        PolicyDataKind::FallbackPolicy.to_string(),
        "fallback_policy"
    );
}

#[test]
fn policy_data_kind_display_optimization_policy() {
    assert_eq!(
        PolicyDataKind::OptimizationPolicy.to_string(),
        "optimization_policy"
    );
}

// ===========================================================================
// 3) PolicyDataKind — serde exact tags (snake_case)
// ===========================================================================

#[test]
fn serde_exact_tags_policy_data_kind() {
    let kinds = [
        PolicyDataKind::LaneRouting,
        PolicyDataKind::SecurityPolicy,
        PolicyDataKind::ContainmentPolicy,
        PolicyDataKind::GovernancePolicy,
        PolicyDataKind::FallbackPolicy,
        PolicyDataKind::OptimizationPolicy,
    ];
    let expected = [
        "\"lane_routing\"",
        "\"security_policy\"",
        "\"containment_policy\"",
        "\"governance_policy\"",
        "\"fallback_policy\"",
        "\"optimization_policy\"",
    ];
    for (k, exp) in kinds.iter().zip(expected.iter()) {
        let json = serde_json::to_string(k).unwrap();
        assert_eq!(json, *exp, "PolicyDataKind tag mismatch for {k:?}");
    }
}

// ===========================================================================
// 4) PolicyDataKind — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_policy_data_kind() {
    let variants = [
        format!("{:?}", PolicyDataKind::LaneRouting),
        format!("{:?}", PolicyDataKind::SecurityPolicy),
        format!("{:?}", PolicyDataKind::ContainmentPolicy),
        format!("{:?}", PolicyDataKind::GovernancePolicy),
        format!("{:?}", PolicyDataKind::FallbackPolicy),
        format!("{:?}", PolicyDataKind::OptimizationPolicy),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 6);
}

// ===========================================================================
// 5) ScenarioCategory — Display exact values
// ===========================================================================

#[test]
fn scenario_category_display_policy_tampering() {
    assert_eq!(
        ScenarioCategory::PolicyTampering.to_string(),
        "policy_tampering"
    );
}

#[test]
fn scenario_category_display_replay_attack() {
    assert_eq!(ScenarioCategory::ReplayAttack.to_string(), "replay_attack");
}

#[test]
fn scenario_category_display_privilege_escalation() {
    assert_eq!(
        ScenarioCategory::PrivilegeEscalation.to_string(),
        "privilege_escalation"
    );
}

#[test]
fn scenario_category_display_resource_exhaustion() {
    assert_eq!(
        ScenarioCategory::ResourceExhaustion.to_string(),
        "resource_exhaustion"
    );
}

#[test]
fn scenario_category_display_containment_escape() {
    assert_eq!(
        ScenarioCategory::ContainmentEscape.to_string(),
        "containment_escape"
    );
}

#[test]
fn scenario_category_display_fallback_suppression() {
    assert_eq!(
        ScenarioCategory::FallbackSuppression.to_string(),
        "fallback_suppression"
    );
}

// ===========================================================================
// 6) ScenarioCategory — serde exact tags
// ===========================================================================

#[test]
fn serde_exact_tags_scenario_category() {
    let cats = [
        ScenarioCategory::PolicyTampering,
        ScenarioCategory::ReplayAttack,
        ScenarioCategory::PrivilegeEscalation,
        ScenarioCategory::ResourceExhaustion,
        ScenarioCategory::ContainmentEscape,
        ScenarioCategory::FallbackSuppression,
    ];
    let expected = [
        "\"policy_tampering\"",
        "\"replay_attack\"",
        "\"privilege_escalation\"",
        "\"resource_exhaustion\"",
        "\"containment_escape\"",
        "\"fallback_suppression\"",
    ];
    for (c, exp) in cats.iter().zip(expected.iter()) {
        let json = serde_json::to_string(c).unwrap();
        assert_eq!(json, *exp, "ScenarioCategory tag mismatch for {c:?}");
    }
}

// ===========================================================================
// 7) ScenarioCategory — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_scenario_category() {
    let variants = [
        format!("{:?}", ScenarioCategory::PolicyTampering),
        format!("{:?}", ScenarioCategory::ReplayAttack),
        format!("{:?}", ScenarioCategory::PrivilegeEscalation),
        format!("{:?}", ScenarioCategory::ResourceExhaustion),
        format!("{:?}", ScenarioCategory::ContainmentEscape),
        format!("{:?}", ScenarioCategory::FallbackSuppression),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 6);
}

// ===========================================================================
// 8) ExpectedOutcome — Display exact values
// ===========================================================================

#[test]
fn expected_outcome_display_blocked() {
    assert_eq!(ExpectedOutcome::Blocked.to_string(), "blocked");
}

#[test]
fn expected_outcome_display_fallback_triggered() {
    assert_eq!(
        ExpectedOutcome::FallbackTriggered.to_string(),
        "fallback_triggered"
    );
}

#[test]
fn expected_outcome_display_contained() {
    assert_eq!(ExpectedOutcome::Contained.to_string(), "contained");
}

#[test]
fn expected_outcome_display_detected_only() {
    assert_eq!(ExpectedOutcome::DetectedOnly.to_string(), "detected_only");
}

// ===========================================================================
// 9) ExpectedOutcome — serde exact tags
// ===========================================================================

#[test]
fn serde_exact_tags_expected_outcome() {
    let outcomes = [
        ExpectedOutcome::Blocked,
        ExpectedOutcome::FallbackTriggered,
        ExpectedOutcome::Contained,
        ExpectedOutcome::DetectedOnly,
    ];
    let expected = [
        "\"blocked\"",
        "\"fallback_triggered\"",
        "\"contained\"",
        "\"detected_only\"",
    ];
    for (o, exp) in outcomes.iter().zip(expected.iter()) {
        let json = serde_json::to_string(o).unwrap();
        assert_eq!(json, *exp, "ExpectedOutcome tag mismatch for {o:?}");
    }
}

// ===========================================================================
// 10) ExpectedOutcome — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_expected_outcome() {
    let variants = [
        format!("{:?}", ExpectedOutcome::Blocked),
        format!("{:?}", ExpectedOutcome::FallbackTriggered),
        format!("{:?}", ExpectedOutcome::Contained),
        format!("{:?}", ExpectedOutcome::DetectedOnly),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

// ===========================================================================
// 11) EscalationLevel — Display exact values
// ===========================================================================

#[test]
fn escalation_level_display_observe() {
    assert_eq!(EscalationLevel::Observe.to_string(), "observe");
}

#[test]
fn escalation_level_display_alert() {
    assert_eq!(EscalationLevel::Alert.to_string(), "alert");
}

#[test]
fn escalation_level_display_mitigate() {
    assert_eq!(EscalationLevel::Mitigate.to_string(), "mitigate");
}

#[test]
fn escalation_level_display_escalate() {
    assert_eq!(EscalationLevel::Escalate.to_string(), "escalate");
}

#[test]
fn escalation_level_display_emergency() {
    assert_eq!(EscalationLevel::Emergency.to_string(), "emergency");
}

// ===========================================================================
// 12) EscalationLevel — serde exact tags
// ===========================================================================

#[test]
fn serde_exact_tags_escalation_level() {
    let levels = [
        EscalationLevel::Observe,
        EscalationLevel::Alert,
        EscalationLevel::Mitigate,
        EscalationLevel::Escalate,
        EscalationLevel::Emergency,
    ];
    let expected = [
        "\"observe\"",
        "\"alert\"",
        "\"mitigate\"",
        "\"escalate\"",
        "\"emergency\"",
    ];
    for (l, exp) in levels.iter().zip(expected.iter()) {
        let json = serde_json::to_string(l).unwrap();
        assert_eq!(json, *exp, "EscalationLevel tag mismatch for {l:?}");
    }
}

// ===========================================================================
// 13) EscalationLevel — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_escalation_level() {
    let variants = [
        format!("{:?}", EscalationLevel::Observe),
        format!("{:?}", EscalationLevel::Alert),
        format!("{:?}", EscalationLevel::Mitigate),
        format!("{:?}", EscalationLevel::Escalate),
        format!("{:?}", EscalationLevel::Emergency),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 5);
}

// ===========================================================================
// 14) SandboxRestriction::deny_all — exact defaults
// ===========================================================================

#[test]
fn sandbox_deny_all_no_network() {
    let s = SandboxRestriction::deny_all("r1".into());
    assert!(!s.allow_network);
}

#[test]
fn sandbox_deny_all_no_fs_write() {
    let s = SandboxRestriction::deny_all("r1".into());
    assert!(!s.allow_fs_write);
}

#[test]
fn sandbox_deny_all_no_process_spawn() {
    let s = SandboxRestriction::deny_all("r1".into());
    assert!(!s.allow_process_spawn);
}

#[test]
fn sandbox_deny_all_max_memory_64mb() {
    let s = SandboxRestriction::deny_all("r1".into());
    assert_eq!(s.max_memory_bytes, 64 * 1024 * 1024);
}

#[test]
fn sandbox_deny_all_max_execution_5s() {
    let s = SandboxRestriction::deny_all("r1".into());
    assert_eq!(s.max_execution_ns, 5_000_000_000);
}

#[test]
fn sandbox_deny_all_empty_capabilities() {
    let s = SandboxRestriction::deny_all("r1".into());
    assert!(s.allowed_capabilities.is_empty());
}

// ===========================================================================
// 15) SandboxRestriction — is_allowed / would_exceed
// ===========================================================================

#[test]
fn sandbox_is_allowed_false_by_default() {
    let s = SandboxRestriction::deny_all("r1".into());
    assert!(!s.is_allowed("anything"));
}

#[test]
fn sandbox_would_exceed_memory_true() {
    let s = SandboxRestriction::deny_all("r1".into());
    assert!(s.would_exceed_memory(100 * 1024 * 1024));
}

#[test]
fn sandbox_would_exceed_memory_false() {
    let s = SandboxRestriction::deny_all("r1".into());
    assert!(!s.would_exceed_memory(32 * 1024 * 1024));
}

#[test]
fn sandbox_would_exceed_time_true() {
    let s = SandboxRestriction::deny_all("r1".into());
    assert!(s.would_exceed_time(10_000_000_000));
}

#[test]
fn sandbox_would_exceed_time_false() {
    let s = SandboxRestriction::deny_all("r1".into());
    assert!(!s.would_exceed_time(1_000_000_000));
}

// ===========================================================================
// 16) JSON field-name stability — SignedPolicyArtifact
// ===========================================================================

#[test]
fn json_fields_signed_policy_artifact() {
    let a = test_artifact();
    let v: serde_json::Value = serde_json::to_value(&a).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "artifact_id",
        "kind",
        "policy_name",
        "version",
        "epoch",
        "definition_hash",
        "policy_bytes",
        "signer_id",
        "signature_hex",
        "tags",
        "signed_at_ns",
    ] {
        assert!(
            obj.contains_key(key),
            "SignedPolicyArtifact missing field: {key}"
        );
    }
}

// ===========================================================================
// 17) JSON field-name stability — PolicyVerificationResult
// ===========================================================================

#[test]
fn json_fields_policy_verification_result() {
    let pvr = PolicyVerificationResult {
        artifact_id: "a".into(),
        definition_hash_valid: true,
        signature_valid: true,
        epoch_current: true,
        all_valid: true,
        detail: "ok".into(),
    };
    let v: serde_json::Value = serde_json::to_value(&pvr).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "artifact_id",
        "definition_hash_valid",
        "signature_valid",
        "epoch_current",
        "all_valid",
        "detail",
    ] {
        assert!(
            obj.contains_key(key),
            "PolicyVerificationResult missing field: {key}"
        );
    }
}

// ===========================================================================
// 18) JSON field-name stability — SandboxRestriction
// ===========================================================================

#[test]
fn json_fields_sandbox_restriction() {
    let s = SandboxRestriction::deny_all("test".into());
    let v: serde_json::Value = serde_json::to_value(&s).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "restriction_id",
        "description",
        "allowed_capabilities",
        "allow_network",
        "allow_fs_write",
        "max_memory_bytes",
        "max_execution_ns",
        "allow_process_spawn",
    ] {
        assert!(
            obj.contains_key(key),
            "SandboxRestriction missing field: {key}"
        );
    }
}

// ===========================================================================
// 19) JSON field-name stability — SecurityReport
// ===========================================================================

#[test]
fn json_fields_security_report() {
    let suite = AdversarialSuite::new("s".into(), test_epoch());
    let report = generate_report(&test_epoch(), 0, 0, &suite, 0, 0);
    let v: serde_json::Value = serde_json::to_value(&report).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "schema_version",
        "epoch",
        "artifacts_verified",
        "artifacts_valid",
        "scenarios_executed",
        "scenarios_passing",
        "category_pass_rates",
        "playbooks_loaded",
        "sandbox_profiles",
        "security_posture_millionths",
        "report_hash",
    ] {
        assert!(obj.contains_key(key), "SecurityReport missing field: {key}");
    }
}

// ===========================================================================
// 20) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_signed_policy_artifact() {
    let a = test_artifact();
    let json = serde_json::to_string(&a).unwrap();
    let rt: SignedPolicyArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(a, rt);
}

#[test]
fn serde_roundtrip_sandbox_restriction() {
    let s = SandboxRestriction::deny_all("sr".into());
    let json = serde_json::to_string(&s).unwrap();
    let rt: SandboxRestriction = serde_json::from_str(&json).unwrap();
    assert_eq!(s, rt);
}

#[test]
fn serde_roundtrip_policy_verification_result() {
    let pvr = PolicyVerificationResult {
        artifact_id: "a".into(),
        definition_hash_valid: true,
        signature_valid: false,
        epoch_current: true,
        all_valid: false,
        detail: "signature mismatch".into(),
    };
    let json = serde_json::to_string(&pvr).unwrap();
    let rt: PolicyVerificationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(pvr, rt);
}

#[test]
fn serde_roundtrip_scenario_result() {
    let sr = ScenarioResult {
        scenario_id: "adv-001".into(),
        actual_outcome: ExpectedOutcome::Blocked,
        passed: true,
        detail: "ok".into(),
        evidence_hash: "abc123".into(),
    };
    let json = serde_json::to_string(&sr).unwrap();
    let rt: ScenarioResult = serde_json::from_str(&json).unwrap();
    assert_eq!(sr, rt);
}

#[test]
fn serde_roundtrip_security_report() {
    let suite = AdversarialSuite::new("s".into(), test_epoch());
    let report = generate_report(&test_epoch(), 5, 4, &suite, 2, 3);
    let json = serde_json::to_string(&report).unwrap();
    let rt: SecurityReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, rt);
}

// ===========================================================================
// 21) canonical_sandbox_profiles — returns 3 profiles
// ===========================================================================

#[test]
fn canonical_sandbox_profiles_count() {
    let profiles = canonical_sandbox_profiles();
    assert_eq!(profiles.len(), 3);
}

#[test]
fn canonical_sandbox_profiles_has_default() {
    let profiles = canonical_sandbox_profiles();
    assert!(profiles.iter().any(|p| p.is_default));
}

#[test]
fn canonical_sandbox_profiles_names_unique() {
    let profiles = canonical_sandbox_profiles();
    let names: BTreeSet<_> = profiles.iter().map(|p| &p.name).collect();
    assert_eq!(names.len(), 3);
}

// ===========================================================================
// 22) canonical_adversarial_scenarios — returns 6 scenarios
// ===========================================================================

#[test]
fn canonical_adversarial_scenarios_count() {
    let scenarios = canonical_adversarial_scenarios();
    assert_eq!(scenarios.len(), 6);
}

#[test]
fn canonical_adversarial_scenarios_ids_unique() {
    let scenarios = canonical_adversarial_scenarios();
    let ids: BTreeSet<_> = scenarios.iter().map(|s| &s.scenario_id).collect();
    assert_eq!(ids.len(), 6);
}

#[test]
fn canonical_adversarial_scenarios_cover_all_categories() {
    let scenarios = canonical_adversarial_scenarios();
    let categories: BTreeSet<_> = scenarios.iter().map(|s| s.category).collect();
    assert_eq!(categories.len(), 6);
}

// ===========================================================================
// 23) canonical_failure_playbooks — returns 2 playbooks
// ===========================================================================

#[test]
fn canonical_failure_playbooks_count() {
    let playbooks = canonical_failure_playbooks();
    assert_eq!(playbooks.len(), 2);
}

#[test]
fn canonical_failure_playbooks_ids_unique() {
    let playbooks = canonical_failure_playbooks();
    let ids: BTreeSet<_> = playbooks.iter().map(|p| &p.playbook_id).collect();
    assert_eq!(ids.len(), 2);
}

#[test]
fn canonical_failure_playbooks_have_steps() {
    let playbooks = canonical_failure_playbooks();
    for pb in &playbooks {
        assert!(
            pb.step_count() > 0,
            "playbook {} has no steps",
            pb.playbook_id
        );
    }
}

// ===========================================================================
// 24) AdversarialSuite — initial state
// ===========================================================================

#[test]
fn adversarial_suite_initial_empty() {
    let suite = AdversarialSuite::new("test".into(), test_epoch());
    assert_eq!(suite.scenario_count(), 0);
    assert_eq!(suite.pass_count(), 0);
    assert_eq!(suite.fail_count(), 0);
    assert!(!suite.all_pass());
}

// ===========================================================================
// 25) AdversarialSuite — add/record/pass_count
// ===========================================================================

#[test]
fn adversarial_suite_add_and_record() {
    let mut suite = AdversarialSuite::new("test".into(), test_epoch());
    suite.add_scenario(AdversarialScenario {
        scenario_id: "s1".into(),
        name: "test".into(),
        category: ScenarioCategory::PolicyTampering,
        expected_outcome: ExpectedOutcome::Blocked,
        description: "d".into(),
        severity_millionths: 1_000_000,
        target_kinds: BTreeSet::from([PolicyDataKind::SecurityPolicy]),
    });
    assert_eq!(suite.scenario_count(), 1);

    suite.record_result(ScenarioResult {
        scenario_id: "s1".into(),
        actual_outcome: ExpectedOutcome::Blocked,
        passed: true,
        detail: "ok".into(),
        evidence_hash: "h".into(),
    });
    assert_eq!(suite.pass_count(), 1);
    assert_eq!(suite.fail_count(), 0);
    assert!(suite.all_pass());
}

// ===========================================================================
// 26) FailurePlaybook — max_level
// ===========================================================================

#[test]
fn failure_playbook_max_level() {
    let pb = FailurePlaybook::new(
        "pb".into(),
        ScenarioCategory::PolicyTampering,
        vec![
            PlaybookStep {
                step: 1,
                level: EscalationLevel::Alert,
                action: "a".into(),
                escalation_condition: "c".into(),
                max_duration_ns: 0,
            },
            PlaybookStep {
                step: 2,
                level: EscalationLevel::Emergency,
                action: "b".into(),
                escalation_condition: "c".into(),
                max_duration_ns: 0,
            },
        ],
        false,
    );
    assert_eq!(pb.max_level(), Some(EscalationLevel::Emergency));
}

// ===========================================================================
// 27) SignedPolicyArtifact — verify_definition_hash
// ===========================================================================

#[test]
fn artifact_verify_definition_hash_passes() {
    let a = test_artifact();
    assert!(a.verify_definition_hash());
}

#[test]
fn artifact_verify_definition_hash_fails_on_tamper() {
    let mut a = test_artifact();
    a.policy_bytes.push(0xFF);
    assert!(!a.verify_definition_hash());
}

// ===========================================================================
// 28) SignedPolicyArtifact::compute_artifact_id — starts with "pol-"
// ===========================================================================

#[test]
fn artifact_id_starts_with_pol() {
    let id = SignedPolicyArtifact::compute_artifact_id(
        &PolicyDataKind::LaneRouting,
        "test",
        1,
        &test_epoch(),
    );
    assert!(id.starts_with("pol-"), "artifact_id: {id}");
}

// ===========================================================================
// 29) generate_report — schema_version matches constant
// ===========================================================================

#[test]
fn generate_report_schema_version() {
    let suite = AdversarialSuite::new("s".into(), test_epoch());
    let report = generate_report(&test_epoch(), 0, 0, &suite, 0, 0);
    assert_eq!(report.schema_version, SCHEMA_VERSION);
}

#[test]
fn generate_report_counts_correct() {
    let suite = AdversarialSuite::new("s".into(), test_epoch());
    let report = generate_report(&test_epoch(), 10, 8, &suite, 2, 3);
    assert_eq!(report.artifacts_verified, 10);
    assert_eq!(report.artifacts_valid, 8);
    assert_eq!(report.playbooks_loaded, 2);
    assert_eq!(report.sandbox_profiles, 3);
}
