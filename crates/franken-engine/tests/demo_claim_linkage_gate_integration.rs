#![forbid(unsafe_code)]
//! Integration tests for the `demo_claim_linkage_gate` module.
//!
//! Exercises every public type, enum variant, method, error path,
//! Display/Debug impl, serde round-trip, and cross-concern scenario
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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::demo_claim_linkage_gate::{
    ClaimCategory, ClaimLinkageResult, DemoClaimLinkageGate, DemoSpecification, EvidenceKind,
    EvidenceLink, ExpectedOutput, LINKAGE_GATE_SCHEMA_VERSION, LinkageGateConfig,
    LinkageGateDecision, LinkageGateError, LinkageVerdict, MilestoneClaim, VerificationCommand,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

fn make_evidence(id: &str, kind: EvidenceKind) -> EvidenceLink {
    EvidenceLink {
        evidence_id: id.to_string(),
        kind,
        artifact_hash: ContentHash::compute(id.as_bytes()),
        description: format!("Evidence {}", id),
    }
}

fn make_evidence_default(id: &str) -> EvidenceLink {
    make_evidence(id, EvidenceKind::TestResult)
}

fn make_command(id: &str) -> VerificationCommand {
    VerificationCommand {
        command_id: id.to_string(),
        command: format!("cargo test {}", id),
        expected_exit_code: 0,
        timeout_ms: 60_000,
        deterministic: true,
    }
}

fn make_output(name: &str) -> ExpectedOutput {
    ExpectedOutput {
        name: name.to_string(),
        expected_hash: Some(ContentHash::compute(name.as_bytes())),
        exact_match: true,
        tolerance_millionths: 0,
    }
}

fn make_demo(id: &str, runnable: bool) -> DemoSpecification {
    let commands = if runnable {
        vec![make_command(&format!("cmd-{}", id))]
    } else {
        Vec::new()
    };
    let mut outputs = BTreeMap::new();
    if runnable {
        outputs.insert("out1".to_string(), make_output("out1"));
    }
    DemoSpecification {
        demo_id: id.to_string(),
        title: format!("Demo {}", id),
        description: format!("Demo {} description", id),
        milestone_id: "m1".to_string(),
        runnable,
        verification_commands: commands,
        expected_outputs: outputs,
        tags: BTreeSet::new(),
    }
}

fn make_claim(
    id: &str,
    category: ClaimCategory,
    demos: Vec<&str>,
    evidence: Vec<&str>,
) -> MilestoneClaim {
    MilestoneClaim {
        claim_id: id.to_string(),
        statement: format!("Claim {}", id),
        milestone_id: "m1".to_string(),
        category,
        evidence_links: evidence.into_iter().map(make_evidence_default).collect(),
        demos: demos.into_iter().map(String::from).collect(),
    }
}

fn default_gate() -> DemoClaimLinkageGate {
    DemoClaimLinkageGate::new(LinkageGateConfig::default()).unwrap()
}

fn gate_with_epoch(epoch: u64) -> DemoClaimLinkageGate {
    let config = LinkageGateConfig {
        epoch: SecurityEpoch::from_raw(epoch),
        ..Default::default()
    };
    DemoClaimLinkageGate::new(config).unwrap()
}

fn relaxed_gate() -> DemoClaimLinkageGate {
    let config = LinkageGateConfig {
        require_runnable_demo: false,
        require_evidence: false,
        require_expected_outputs: false,
        require_verification_commands: false,
        min_completeness_millionths: 0,
        ..Default::default()
    };
    DemoClaimLinkageGate::new(config).unwrap()
}

// ---------------------------------------------------------------------------
// Section 1: Schema version constant
// ---------------------------------------------------------------------------

#[test]
fn schema_version_is_well_formed() {
    assert!(LINKAGE_GATE_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(LINKAGE_GATE_SCHEMA_VERSION.contains("demo-claim-linkage-gate"));
    assert!(LINKAGE_GATE_SCHEMA_VERSION.ends_with(".v1"));
}

// ---------------------------------------------------------------------------
// Section 2: DemoSpecification
// ---------------------------------------------------------------------------

#[test]
fn demo_spec_is_complete_when_runnable_with_commands_and_outputs() {
    let demo = make_demo("d1", true);
    assert!(demo.is_complete());
    assert_eq!(demo.command_count(), 1);
}

#[test]
fn demo_spec_is_incomplete_when_not_runnable() {
    let demo = make_demo("d1", false);
    assert!(!demo.is_complete());
    assert_eq!(demo.command_count(), 0);
}

#[test]
fn demo_spec_is_incomplete_when_runnable_but_no_commands() {
    let demo = DemoSpecification {
        demo_id: "d-no-cmd".to_string(),
        title: "No Commands".to_string(),
        description: "Has no commands".to_string(),
        milestone_id: "m1".to_string(),
        runnable: true,
        verification_commands: Vec::new(),
        expected_outputs: {
            let mut m = BTreeMap::new();
            m.insert("out".to_string(), make_output("out"));
            m
        },
        tags: BTreeSet::new(),
    };
    assert!(!demo.is_complete());
}

#[test]
fn demo_spec_is_incomplete_when_runnable_but_no_outputs() {
    let demo = DemoSpecification {
        demo_id: "d-no-out".to_string(),
        title: "No Outputs".to_string(),
        description: "Has no outputs".to_string(),
        milestone_id: "m1".to_string(),
        runnable: true,
        verification_commands: vec![make_command("cmd1")],
        expected_outputs: BTreeMap::new(),
        tags: BTreeSet::new(),
    };
    assert!(!demo.is_complete());
}

#[test]
fn demo_spec_display_complete() {
    let demo = make_demo("alpha", true);
    let s = format!("{}", demo);
    assert!(s.contains("alpha"));
    assert!(s.contains("complete"));
    // "complete" not preceded by "in" => truly complete
    assert!(!s.contains("incomplete"));
}

#[test]
fn demo_spec_display_incomplete() {
    let demo = make_demo("beta", false);
    let s = format!("{}", demo);
    assert!(s.contains("beta"));
    assert!(s.contains("incomplete"));
}

#[test]
fn demo_spec_with_tags() {
    let mut demo = make_demo("tagged", true);
    demo.tags.insert("perf".to_string());
    demo.tags.insert("e2e".to_string());
    assert_eq!(demo.tags.len(), 2);
    assert!(demo.tags.contains("perf"));
}

#[test]
fn demo_spec_command_count_multiple() {
    let mut demo = make_demo("multi-cmd", true);
    demo.verification_commands.push(make_command("extra1"));
    demo.verification_commands.push(make_command("extra2"));
    assert_eq!(demo.command_count(), 3);
}

// ---------------------------------------------------------------------------
// Section 3: VerificationCommand
// ---------------------------------------------------------------------------

#[test]
fn verification_command_display() {
    let cmd = VerificationCommand {
        command_id: "lint-check".to_string(),
        command: "cargo clippy".to_string(),
        expected_exit_code: 2,
        timeout_ms: 30_000,
        deterministic: false,
    };
    let s = format!("{}", cmd);
    assert!(s.contains("lint-check"));
    assert!(s.contains("exit=2"));
}

#[test]
fn verification_command_debug() {
    let cmd = make_command("dbg-cmd");
    let dbg = format!("{:?}", cmd);
    assert!(dbg.contains("dbg-cmd"));
    assert!(dbg.contains("VerificationCommand"));
}

// ---------------------------------------------------------------------------
// Section 4: ExpectedOutput
// ---------------------------------------------------------------------------

#[test]
fn expected_output_with_hash_and_exact_match() {
    let out = make_output("result.json");
    assert!(out.exact_match);
    assert!(out.expected_hash.is_some());
    assert_eq!(out.tolerance_millionths, 0);
}

#[test]
fn expected_output_without_hash_and_tolerance() {
    let out = ExpectedOutput {
        name: "approx_metric".to_string(),
        expected_hash: None,
        exact_match: false,
        tolerance_millionths: 50_000, // 5%
    };
    assert!(!out.exact_match);
    assert!(out.expected_hash.is_none());
    assert_eq!(out.tolerance_millionths, 50_000);
}

// ---------------------------------------------------------------------------
// Section 5: ClaimCategory Display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn claim_category_display_all_variants() {
    assert_eq!(format!("{}", ClaimCategory::Performance), "performance");
    assert_eq!(format!("{}", ClaimCategory::Correctness), "correctness");
    assert_eq!(format!("{}", ClaimCategory::Security), "security");
    assert_eq!(format!("{}", ClaimCategory::Compatibility), "compatibility");
    assert_eq!(format!("{}", ClaimCategory::Reliability), "reliability");
    assert_eq!(
        format!("{}", ClaimCategory::DeveloperExperience),
        "developer-experience"
    );
}

#[test]
fn claim_category_display_values_are_unique() {
    let categories = [
        ClaimCategory::Performance,
        ClaimCategory::Correctness,
        ClaimCategory::Security,
        ClaimCategory::Compatibility,
        ClaimCategory::Reliability,
        ClaimCategory::DeveloperExperience,
    ];
    let displays: BTreeSet<String> = categories.iter().map(|c| format!("{}", c)).collect();
    assert_eq!(displays.len(), categories.len());
}

// ---------------------------------------------------------------------------
// Section 6: EvidenceKind Display
// ---------------------------------------------------------------------------

#[test]
fn evidence_kind_display_all_variants() {
    assert_eq!(format!("{}", EvidenceKind::TestResult), "test-result");
    assert_eq!(
        format!("{}", EvidenceKind::BenchmarkResult),
        "benchmark-result"
    );
    assert_eq!(format!("{}", EvidenceKind::SecurityAudit), "security-audit");
    assert_eq!(format!("{}", EvidenceKind::FormalProof), "formal-proof");
    assert_eq!(format!("{}", EvidenceKind::CodeReview), "code-review");
    assert_eq!(format!("{}", EvidenceKind::DemoReplay), "demo-replay");
    assert_eq!(
        format!("{}", EvidenceKind::ThirdPartyVerification),
        "third-party-verification"
    );
}

#[test]
fn evidence_kind_display_values_are_unique() {
    let kinds = [
        EvidenceKind::TestResult,
        EvidenceKind::BenchmarkResult,
        EvidenceKind::SecurityAudit,
        EvidenceKind::FormalProof,
        EvidenceKind::CodeReview,
        EvidenceKind::DemoReplay,
        EvidenceKind::ThirdPartyVerification,
    ];
    let displays: BTreeSet<String> = kinds.iter().map(|k| format!("{}", k)).collect();
    assert_eq!(displays.len(), kinds.len());
}

// ---------------------------------------------------------------------------
// Section 7: EvidenceLink Display
// ---------------------------------------------------------------------------

#[test]
fn evidence_link_display() {
    let ev = make_evidence("ev-42", EvidenceKind::SecurityAudit);
    let s = format!("{}", ev);
    assert!(s.contains("ev-42"));
    assert!(s.contains("security-audit"));
}

// ---------------------------------------------------------------------------
// Section 8: MilestoneClaim Display
// ---------------------------------------------------------------------------

#[test]
fn milestone_claim_display_shows_counts() {
    let claim = make_claim(
        "c-perf",
        ClaimCategory::Performance,
        vec!["d1", "d2"],
        vec!["e1"],
    );
    let s = format!("{}", claim);
    assert!(s.contains("c-perf"));
    assert!(s.contains("performance"));
    assert!(s.contains("evidence=1"));
    assert!(s.contains("demos=2"));
}

// ---------------------------------------------------------------------------
// Section 9: LinkageVerdict Display
// ---------------------------------------------------------------------------

#[test]
fn linkage_verdict_display_all_variants() {
    assert_eq!(format!("{}", LinkageVerdict::Pass), "pass");
    assert_eq!(format!("{}", LinkageVerdict::Fail), "fail");
    assert_eq!(format!("{}", LinkageVerdict::Empty), "empty");
}

// ---------------------------------------------------------------------------
// Section 10: LinkageGateConfig defaults
// ---------------------------------------------------------------------------

#[test]
fn config_default_values() {
    let config = LinkageGateConfig::default();
    assert_eq!(config.epoch, SecurityEpoch::from_raw(1));
    assert_eq!(config.min_completeness_millionths, MILLION);
    assert!(config.require_runnable_demo);
    assert!(config.require_evidence);
    assert!(config.require_expected_outputs);
    assert!(config.require_verification_commands);
}

// ---------------------------------------------------------------------------
// Section 11: DemoClaimLinkageGate constructor
// ---------------------------------------------------------------------------

#[test]
fn gate_new_with_default_config() {
    let gate = default_gate();
    assert_eq!(gate.evaluation_count(), 0);
    assert_eq!(gate.config().min_completeness_millionths, MILLION);
}

#[test]
fn gate_new_rejects_negative_completeness() {
    let config = LinkageGateConfig {
        min_completeness_millionths: -1,
        ..Default::default()
    };
    let result = DemoClaimLinkageGate::new(config);
    assert!(matches!(
        result,
        Err(LinkageGateError::InvalidConfig { .. })
    ));
}

#[test]
fn gate_new_rejects_over_million_completeness() {
    let config = LinkageGateConfig {
        min_completeness_millionths: MILLION + 1,
        ..Default::default()
    };
    let result = DemoClaimLinkageGate::new(config);
    assert!(matches!(
        result,
        Err(LinkageGateError::InvalidConfig { .. })
    ));
}

#[test]
fn gate_new_accepts_zero_completeness() {
    let config = LinkageGateConfig {
        min_completeness_millionths: 0,
        ..Default::default()
    };
    assert!(DemoClaimLinkageGate::new(config).is_ok());
}

#[test]
fn gate_new_accepts_exact_million_completeness() {
    let config = LinkageGateConfig {
        min_completeness_millionths: MILLION,
        ..Default::default()
    };
    assert!(DemoClaimLinkageGate::new(config).is_ok());
}

// ---------------------------------------------------------------------------
// Section 12: Evaluate — error paths
// ---------------------------------------------------------------------------

#[test]
fn evaluate_rejects_empty_claims() {
    let mut gate = default_gate();
    let err = gate.evaluate("m1", &[], &[]).unwrap_err();
    assert!(matches!(err, LinkageGateError::NoClaims));
}

#[test]
fn evaluate_rejects_too_many_claims() {
    let mut gate = default_gate();
    let demo = make_demo("d1", true);
    let claims: Vec<_> = (0..257)
        .map(|i| {
            make_claim(
                &format!("c{}", i),
                ClaimCategory::Performance,
                vec!["d1"],
                vec!["e1"],
            )
        })
        .collect();
    let err = gate.evaluate("m1", &claims, &[demo]).unwrap_err();
    assert!(matches!(
        err,
        LinkageGateError::TooManyClaims {
            count: 257,
            max: 256
        }
    ));
}

#[test]
fn evaluate_rejects_duplicate_claim_ids() {
    let mut gate = default_gate();
    let demo = make_demo("d1", true);
    let claims = vec![
        make_claim("dup-c", ClaimCategory::Performance, vec!["d1"], vec!["e1"]),
        make_claim("dup-c", ClaimCategory::Security, vec!["d1"], vec!["e2"]),
    ];
    let err = gate.evaluate("m1", &claims, &[demo]).unwrap_err();
    match err {
        LinkageGateError::DuplicateClaim { claim_id } => assert_eq!(claim_id, "dup-c"),
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn evaluate_rejects_duplicate_demo_ids() {
    let mut gate = default_gate();
    let demos = vec![make_demo("dup-d", true), make_demo("dup-d", false)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Correctness,
        vec!["dup-d"],
        vec!["e1"],
    )];
    let err = gate.evaluate("m1", &claims, &demos).unwrap_err();
    match err {
        LinkageGateError::DuplicateDemo { demo_id } => assert_eq!(demo_id, "dup-d"),
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn evaluate_rejects_unknown_demo_reference() {
    let mut gate = default_gate();
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Security,
        vec!["ghost"],
        vec!["e1"],
    )];
    let err = gate.evaluate("m1", &claims, &[]).unwrap_err();
    match err {
        LinkageGateError::UnknownDemo { claim_id, demo_id } => {
            assert_eq!(claim_id, "c1");
            assert_eq!(demo_id, "ghost");
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn evaluate_rejects_too_many_evidence_links() {
    let mut gate = default_gate();
    let demo = make_demo("d1", true);
    let evidence: Vec<EvidenceLink> = (0..65)
        .map(|i| make_evidence_default(&format!("ev{}", i)))
        .collect();
    let claim = MilestoneClaim {
        claim_id: "overloaded".to_string(),
        statement: "Too much evidence".to_string(),
        milestone_id: "m1".to_string(),
        category: ClaimCategory::Performance,
        evidence_links: evidence,
        demos: vec!["d1".to_string()],
    };
    let err = gate.evaluate("m1", &[claim], &[demo]).unwrap_err();
    match err {
        LinkageGateError::TooManyEvidenceLinks {
            claim_id,
            count,
            max,
        } => {
            assert_eq!(claim_id, "overloaded");
            assert_eq!(count, 65);
            assert_eq!(max, 64);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn evaluate_rejects_too_many_verification_commands() {
    let mut gate = default_gate();
    let mut demo = make_demo("big-demo", true);
    // Push until we exceed MAX_COMMANDS_PER_DEMO (32)
    for i in 0..33 {
        demo.verification_commands
            .push(make_command(&format!("extra-{}", i)));
    }
    // demo already has 1 from make_demo + 33 extra = 34
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Correctness,
        vec!["big-demo"],
        vec!["e1"],
    )];
    let err = gate.evaluate("m1", &claims, &[demo]).unwrap_err();
    match err {
        LinkageGateError::TooManyCommands {
            demo_id,
            count,
            max,
        } => {
            assert_eq!(demo_id, "big-demo");
            assert_eq!(count, 34); // 1 original + 33 extras
            assert_eq!(max, 32);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Section 13: Evaluate — happy path (fully linked)
// ---------------------------------------------------------------------------

#[test]
fn evaluate_single_fully_linked_claim_passes() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec!["e1"],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert!(decision.is_pass());
    assert_eq!(decision.verdict, LinkageVerdict::Pass);
    assert_eq!(decision.total_claims, 1);
    assert_eq!(decision.linked_claims, 1);
    assert_eq!(decision.unlinked_claims, 0);
    assert_eq!(decision.aggregate_completeness_millionths, MILLION);
    assert_eq!(decision.milestone_id, "m1");
}

#[test]
fn evaluate_multiple_fully_linked_claims_passes() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true), make_demo("d2", true)];
    let claims = vec![
        make_claim("c1", ClaimCategory::Performance, vec!["d1"], vec!["e1"]),
        make_claim("c2", ClaimCategory::Security, vec!["d2"], vec!["e2"]),
        make_claim(
            "c3",
            ClaimCategory::Correctness,
            vec!["d1", "d2"],
            vec!["e3"],
        ),
    ];
    let decision = gate.evaluate("milestone-alpha", &claims, &demos).unwrap();
    assert!(decision.is_pass());
    assert_eq!(decision.linked_claims, 3);
    assert_eq!(decision.total_claims, 3);
}

// ---------------------------------------------------------------------------
// Section 14: Evaluate — partial linkage (fail paths)
// ---------------------------------------------------------------------------

#[test]
fn evaluate_fails_when_missing_evidence() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec![],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert!(!decision.is_pass());
    assert_eq!(decision.verdict, LinkageVerdict::Fail);
}

#[test]
fn evaluate_fails_when_no_demo_references() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Reliability,
        vec![],
        vec!["e1"],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert_eq!(decision.verdict, LinkageVerdict::Fail);
}

#[test]
fn evaluate_fails_when_demo_not_runnable() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d-nr", false)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d-nr"],
        vec!["e1"],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert_eq!(decision.verdict, LinkageVerdict::Fail);
}

#[test]
fn evaluate_mixed_claims_some_linked_some_not() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![
        make_claim("c-ok", ClaimCategory::Performance, vec!["d1"], vec!["e1"]),
        make_claim("c-bad", ClaimCategory::Security, vec![], vec![]),
    ];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert_eq!(decision.verdict, LinkageVerdict::Fail);
    assert_eq!(decision.linked_claims, 1);
    assert_eq!(decision.unlinked_claims, 1);
    // Rationale mentions the unlinked claim
    assert!(decision.rationale.contains("c-bad"));
}

// ---------------------------------------------------------------------------
// Section 15: Completeness scoring
// ---------------------------------------------------------------------------

#[test]
fn fully_linked_claim_has_million_completeness() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec!["e1"],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert_eq!(decision.aggregate_completeness_millionths, MILLION);
    assert_eq!(decision.claim_results[0].completeness_millionths, MILLION);
}

#[test]
fn missing_one_of_four_requirements_gives_750k_completeness() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    // Missing evidence => 3/4 = 750_000
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec![],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert_eq!(decision.claim_results[0].completeness_millionths, 750_000);
}

#[test]
fn linkage_rate_millionths_half() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![
        make_claim("c1", ClaimCategory::Performance, vec!["d1"], vec!["e1"]),
        make_claim("c2", ClaimCategory::Security, vec![], vec![]),
    ];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert_eq!(decision.linkage_rate_millionths(), 500_000);
}

#[test]
fn linkage_rate_millionths_zero_total_claims() {
    let decision = LinkageGateDecision {
        decision_id: "test".to_string(),
        milestone_id: "m1".to_string(),
        epoch: SecurityEpoch::from_raw(1),
        verdict: LinkageVerdict::Empty,
        claim_results: Vec::new(),
        total_claims: 0,
        linked_claims: 0,
        unlinked_claims: 0,
        aggregate_completeness_millionths: 0,
        rationale: "empty".to_string(),
        artifact_hash: ContentHash::compute(b"test"),
    };
    assert_eq!(decision.linkage_rate_millionths(), 0);
}

// ---------------------------------------------------------------------------
// Section 16: Evaluation counter
// ---------------------------------------------------------------------------

#[test]
fn evaluation_count_increments() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec!["e1"],
    )];
    assert_eq!(gate.evaluation_count(), 0);
    let _ = gate.evaluate("m1", &claims, &demos);
    assert_eq!(gate.evaluation_count(), 1);
    let _ = gate.evaluate("m1", &claims, &demos);
    assert_eq!(gate.evaluation_count(), 2);
}

#[test]
fn evaluation_count_does_not_increment_on_error() {
    let mut gate = default_gate();
    // NoClaims error => count should not increment
    let _ = gate.evaluate("m1", &[], &[]);
    assert_eq!(gate.evaluation_count(), 0);
}

// ---------------------------------------------------------------------------
// Section 17: Decision ID format
// ---------------------------------------------------------------------------

#[test]
fn decision_id_contains_milestone_and_epoch_and_count() {
    let mut gate = gate_with_epoch(42);
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec!["e1"],
    )];
    let decision = gate.evaluate("ms-99", &claims, &demos).unwrap();
    assert!(decision.decision_id.contains("ms-99"));
    assert!(decision.decision_id.contains("42"));
    assert!(decision.decision_id.contains("1")); // evaluation_count=1
}

// ---------------------------------------------------------------------------
// Section 18: Relaxed configuration
// ---------------------------------------------------------------------------

#[test]
fn relaxed_gate_passes_with_no_evidence_no_demo() {
    let mut gate = relaxed_gate();
    let claims = vec![make_claim("c1", ClaimCategory::Reliability, vec![], vec![])];
    let decision = gate.evaluate("m1", &claims, &[]).unwrap();
    assert!(decision.is_pass());
    // With no requirements checked, max_score is 0, so completeness = MILLION
    assert_eq!(decision.aggregate_completeness_millionths, MILLION);
}

#[test]
fn gate_passes_without_evidence_when_not_required() {
    let config = LinkageGateConfig {
        require_evidence: false,
        ..Default::default()
    };
    let mut gate = DemoClaimLinkageGate::new(config).unwrap();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec![],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert!(decision.is_pass());
}

#[test]
fn gate_passes_without_runnable_demo_when_not_required() {
    let config = LinkageGateConfig {
        require_runnable_demo: false,
        require_expected_outputs: false,
        require_verification_commands: false,
        ..Default::default()
    };
    let mut gate = DemoClaimLinkageGate::new(config).unwrap();
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec![],
        vec!["e1"],
    )];
    let decision = gate.evaluate("m1", &claims, &[]).unwrap();
    assert!(decision.is_pass());
}

// ---------------------------------------------------------------------------
// Section 19: Artifact hash determinism
// ---------------------------------------------------------------------------

#[test]
fn artifact_hash_is_deterministic() {
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec!["e1"],
    )];

    let mut g1 = default_gate();
    let d1 = g1.evaluate("m1", &claims, &demos).unwrap();

    let mut g2 = default_gate();
    let d2 = g2.evaluate("m1", &claims, &demos).unwrap();

    assert_eq!(d1.artifact_hash, d2.artifact_hash);
}

#[test]
fn artifact_hash_changes_with_different_milestone() {
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec!["e1"],
    )];

    let mut g1 = default_gate();
    let d1 = g1.evaluate("milestone-A", &claims, &demos).unwrap();

    let mut g2 = default_gate();
    let d2 = g2.evaluate("milestone-B", &claims, &demos).unwrap();

    assert_ne!(d1.artifact_hash, d2.artifact_hash);
}

#[test]
fn artifact_hash_changes_with_different_epoch() {
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec!["e1"],
    )];

    let mut g1 = gate_with_epoch(1);
    let d1 = g1.evaluate("m1", &claims, &demos).unwrap();

    let mut g2 = gate_with_epoch(99);
    let d2 = g2.evaluate("m1", &claims, &demos).unwrap();

    assert_ne!(d1.artifact_hash, d2.artifact_hash);
}

// ---------------------------------------------------------------------------
// Section 20: Rationale content
// ---------------------------------------------------------------------------

#[test]
fn pass_rationale_mentions_all_claims() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec!["e1"],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert!(decision.rationale.contains("All"));
    assert!(decision.rationale.contains("1")); // total_claims
}

#[test]
fn fail_rationale_lists_unlinked_claim_ids() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![
        make_claim("c-ok", ClaimCategory::Performance, vec!["d1"], vec!["e1"]),
        make_claim("c-fail-a", ClaimCategory::Security, vec![], vec![]),
        make_claim("c-fail-b", ClaimCategory::Reliability, vec![], vec![]),
    ];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert!(decision.rationale.contains("c-fail-a"));
    assert!(decision.rationale.contains("c-fail-b"));
}

// ---------------------------------------------------------------------------
// Section 21: ClaimLinkageResult fields
// ---------------------------------------------------------------------------

#[test]
fn claim_linkage_result_fields_for_fully_linked() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec!["e1"],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    let r = &decision.claim_results[0];
    assert_eq!(r.claim_id, "c1");
    assert!(r.linked);
    assert!(r.has_runnable_demo);
    assert!(r.has_evidence);
    assert!(r.demos_have_outputs);
    assert!(r.demos_have_commands);
    assert!(r.missing.is_empty());
}

#[test]
fn claim_linkage_result_missing_items_for_empty_claim() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim("c1", ClaimCategory::Correctness, vec![], vec![])];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    let r = &decision.claim_results[0];
    assert!(!r.linked);
    assert!(!r.has_evidence);
    assert!(!r.has_runnable_demo);
    assert!(!r.missing.is_empty());
}

// ---------------------------------------------------------------------------
// Section 22: LinkageGateDecision Display
// ---------------------------------------------------------------------------

#[test]
fn decision_display_contains_key_info() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec!["e1"],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    let s = format!("{}", decision);
    assert!(s.contains("m1"));
    assert!(s.contains("pass"));
    assert!(s.contains("linked=1/1"));
}

#[test]
fn decision_display_shows_fail() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim("c-x", ClaimCategory::Security, vec![], vec![])];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    let s = format!("{}", decision);
    assert!(s.contains("fail"));
    assert!(s.contains("linked=0/1"));
}

// ---------------------------------------------------------------------------
// Section 23: LinkageGateError Display
// ---------------------------------------------------------------------------

#[test]
fn error_display_no_claims() {
    assert_eq!(
        format!("{}", LinkageGateError::NoClaims),
        "no claims provided"
    );
}

#[test]
fn error_display_too_many_claims() {
    let s = format!(
        "{}",
        LinkageGateError::TooManyClaims {
            count: 300,
            max: 256
        }
    );
    assert!(s.contains("300"));
    assert!(s.contains("256"));
}

#[test]
fn error_display_duplicate_claim() {
    let s = format!(
        "{}",
        LinkageGateError::DuplicateClaim {
            claim_id: "claim-x".to_string()
        }
    );
    assert!(s.contains("claim-x"));
}

#[test]
fn error_display_duplicate_demo() {
    let s = format!(
        "{}",
        LinkageGateError::DuplicateDemo {
            demo_id: "demo-y".to_string()
        }
    );
    assert!(s.contains("demo-y"));
}

#[test]
fn error_display_too_many_evidence() {
    let s = format!(
        "{}",
        LinkageGateError::TooManyEvidenceLinks {
            claim_id: "c1".to_string(),
            count: 100,
            max: 64,
        }
    );
    assert!(s.contains("c1"));
    assert!(s.contains("100"));
    assert!(s.contains("64"));
}

#[test]
fn error_display_too_many_commands() {
    let s = format!(
        "{}",
        LinkageGateError::TooManyCommands {
            demo_id: "d1".to_string(),
            count: 50,
            max: 32,
        }
    );
    assert!(s.contains("d1"));
    assert!(s.contains("50"));
    assert!(s.contains("32"));
}

#[test]
fn error_display_unknown_demo() {
    let s = format!(
        "{}",
        LinkageGateError::UnknownDemo {
            claim_id: "c1".to_string(),
            demo_id: "missing-d".to_string(),
        }
    );
    assert!(s.contains("c1"));
    assert!(s.contains("missing-d"));
}

#[test]
fn error_display_invalid_config() {
    let s = format!(
        "{}",
        LinkageGateError::InvalidConfig {
            detail: "bad value".to_string()
        }
    );
    assert!(s.contains("bad value"));
}

// ---------------------------------------------------------------------------
// Section 24: Error implements std::error::Error
// ---------------------------------------------------------------------------

#[test]
fn error_implements_std_error_trait() {
    let err = LinkageGateError::NoClaims;
    let _: &dyn std::error::Error = &err;
    assert!(std::error::Error::source(&err).is_none());
}

// ---------------------------------------------------------------------------
// Section 25: Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn serde_roundtrip_demo_specification() {
    let demo = make_demo("d-rt", true);
    let json = serde_json::to_string(&demo).unwrap();
    let back: DemoSpecification = serde_json::from_str(&json).unwrap();
    assert_eq!(demo, back);
}

#[test]
fn serde_roundtrip_verification_command() {
    let cmd = make_command("cmd-rt");
    let json = serde_json::to_string(&cmd).unwrap();
    let back: VerificationCommand = serde_json::from_str(&json).unwrap();
    assert_eq!(cmd, back);
}

#[test]
fn serde_roundtrip_expected_output() {
    let out = make_output("out-rt");
    let json = serde_json::to_string(&out).unwrap();
    let back: ExpectedOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(out, back);
}

#[test]
fn serde_roundtrip_milestone_claim() {
    let claim = make_claim("c-rt", ClaimCategory::Compatibility, vec!["d1"], vec!["e1"]);
    let json = serde_json::to_string(&claim).unwrap();
    let back: MilestoneClaim = serde_json::from_str(&json).unwrap();
    assert_eq!(claim, back);
}

#[test]
fn serde_roundtrip_linkage_gate_config() {
    let config = LinkageGateConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: LinkageGateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn serde_roundtrip_linkage_gate_decision() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec!["e1"],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    let json = serde_json::to_string(&decision).unwrap();
    let back: LinkageGateDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

#[test]
fn serde_roundtrip_linkage_gate_error() {
    let err = LinkageGateError::TooManyEvidenceLinks {
        claim_id: "c1".to_string(),
        count: 100,
        max: 64,
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: LinkageGateError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn serde_roundtrip_claim_linkage_result() {
    let result = ClaimLinkageResult {
        claim_id: "c-serde".to_string(),
        linked: false,
        has_runnable_demo: true,
        has_evidence: false,
        demos_have_outputs: true,
        demos_have_commands: false,
        missing: vec!["no evidence links".to_string()],
        completeness_millionths: 500_000,
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: ClaimLinkageResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn serde_roundtrip_evidence_link() {
    let ev = make_evidence("ev-serde", EvidenceKind::FormalProof);
    let json = serde_json::to_string(&ev).unwrap();
    let back: EvidenceLink = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn serde_roundtrip_all_claim_categories() {
    for cat in [
        ClaimCategory::Performance,
        ClaimCategory::Correctness,
        ClaimCategory::Security,
        ClaimCategory::Compatibility,
        ClaimCategory::Reliability,
        ClaimCategory::DeveloperExperience,
    ] {
        let json = serde_json::to_string(&cat).unwrap();
        let back: ClaimCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(cat, back);
    }
}

#[test]
fn serde_roundtrip_all_evidence_kinds() {
    for kind in [
        EvidenceKind::TestResult,
        EvidenceKind::BenchmarkResult,
        EvidenceKind::SecurityAudit,
        EvidenceKind::FormalProof,
        EvidenceKind::CodeReview,
        EvidenceKind::DemoReplay,
        EvidenceKind::ThirdPartyVerification,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: EvidenceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

#[test]
fn serde_roundtrip_all_verdicts() {
    for v in [
        LinkageVerdict::Pass,
        LinkageVerdict::Fail,
        LinkageVerdict::Empty,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: LinkageVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn serde_roundtrip_gate_itself() {
    let gate = default_gate();
    let json = serde_json::to_string(&gate).unwrap();
    let back: DemoClaimLinkageGate = serde_json::from_str(&json).unwrap();
    assert_eq!(back.evaluation_count(), 0);
    assert_eq!(
        back.config().min_completeness_millionths,
        gate.config().min_completeness_millionths
    );
}

// ---------------------------------------------------------------------------
// Section 26: JSON field presence
// ---------------------------------------------------------------------------

#[test]
fn json_fields_demo_specification() {
    let demo = make_demo("d1", true);
    let json = serde_json::to_string(&demo).unwrap();
    for field in [
        "demo_id",
        "title",
        "description",
        "milestone_id",
        "runnable",
        "verification_commands",
        "expected_outputs",
        "tags",
    ] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

#[test]
fn json_fields_linkage_gate_decision() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec!["e1"],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    let json = serde_json::to_string(&decision).unwrap();
    for field in [
        "decision_id",
        "milestone_id",
        "epoch",
        "verdict",
        "claim_results",
        "total_claims",
        "linked_claims",
        "unlinked_claims",
        "aggregate_completeness_millionths",
        "rationale",
        "artifact_hash",
    ] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

// ---------------------------------------------------------------------------
// Section 27: Clone equality
// ---------------------------------------------------------------------------

#[test]
fn clone_eq_demo_specification() {
    let demo = make_demo("d-clone", true);
    assert_eq!(demo, demo.clone());
}

#[test]
fn clone_eq_milestone_claim() {
    let claim = make_claim(
        "c-clone",
        ClaimCategory::Correctness,
        vec!["d1"],
        vec!["e1"],
    );
    assert_eq!(claim, claim.clone());
}

#[test]
fn clone_eq_linkage_gate_config() {
    let config = LinkageGateConfig::default();
    assert_eq!(config, config.clone());
}

// ---------------------------------------------------------------------------
// Section 28: Debug impls
// ---------------------------------------------------------------------------

#[test]
fn debug_impl_demo_specification() {
    let demo = make_demo("d-dbg", true);
    let s = format!("{:?}", demo);
    assert!(s.contains("DemoSpecification"));
    assert!(s.contains("d-dbg"));
}

#[test]
fn debug_impl_gate() {
    let gate = default_gate();
    let s = format!("{:?}", gate);
    assert!(s.contains("DemoClaimLinkageGate"));
}

#[test]
fn debug_impl_error() {
    let err = LinkageGateError::NoClaims;
    let s = format!("{:?}", err);
    assert!(s.contains("NoClaims"));
}

// ---------------------------------------------------------------------------
// Section 29: Edge cases — claim with multiple demos
// ---------------------------------------------------------------------------

#[test]
fn claim_with_multiple_demos_all_complete() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true), make_demo("d2", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1", "d2"],
        vec!["e1"],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert!(decision.is_pass());
}

#[test]
fn claim_with_one_non_runnable_demo_still_has_runnable() {
    // If one demo is runnable and one is not, has_runnable_demo is true
    // But demos_have_outputs and demos_have_commands require ALL demos to have them
    let mut gate = default_gate();
    let demos = vec![make_demo("d-run", true), make_demo("d-norun", false)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d-run", "d-norun"],
        vec!["e1"],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    let r = &decision.claim_results[0];
    // has_runnable_demo = true because at least one is runnable
    assert!(r.has_runnable_demo);
    // demos_have_outputs = false because d-norun has no outputs
    assert!(!r.demos_have_outputs);
    // demos_have_commands = false because d-norun has no commands
    assert!(!r.demos_have_commands);
}

// ---------------------------------------------------------------------------
// Section 30: Epoch propagation
// ---------------------------------------------------------------------------

#[test]
fn decision_epoch_matches_config() {
    let mut gate = gate_with_epoch(77);
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec!["e1"],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert_eq!(decision.epoch, SecurityEpoch::from_raw(77));
}

// ---------------------------------------------------------------------------
// Section 31: Multiple evaluations on the same gate
// ---------------------------------------------------------------------------

#[test]
fn multiple_evaluations_independent_results() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];

    let claims_ok = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec!["e1"],
    )];
    let d1 = gate.evaluate("m1", &claims_ok, &demos).unwrap();
    assert!(d1.is_pass());

    let claims_bad = vec![make_claim("c2", ClaimCategory::Security, vec![], vec![])];
    let d2 = gate.evaluate("m2", &claims_bad, &demos).unwrap();
    assert!(!d2.is_pass());

    assert_eq!(gate.evaluation_count(), 2);
    // Different decision IDs
    assert_ne!(d1.decision_id, d2.decision_id);
}

// ---------------------------------------------------------------------------
// Section 32: Config accessor
// ---------------------------------------------------------------------------

#[test]
fn config_accessor_returns_matching_config() {
    let config = LinkageGateConfig {
        epoch: SecurityEpoch::from_raw(5),
        min_completeness_millionths: 500_000,
        require_runnable_demo: false,
        require_evidence: true,
        require_expected_outputs: false,
        require_verification_commands: true,
    };
    let gate = DemoClaimLinkageGate::new(config.clone()).unwrap();
    assert_eq!(*gate.config(), config);
}

// ---------------------------------------------------------------------------
// Section 33: Boundary — exactly at limits
// ---------------------------------------------------------------------------

#[test]
fn exactly_256_claims_is_accepted() {
    let mut gate = default_gate();
    let demo = make_demo("d1", true);
    let claims: Vec<_> = (0..256)
        .map(|i| {
            make_claim(
                &format!("c{}", i),
                ClaimCategory::Performance,
                vec!["d1"],
                vec!["e1"],
            )
        })
        .collect();
    let result = gate.evaluate("m1", &claims, &[demo]);
    assert!(result.is_ok());
}

#[test]
fn exactly_64_evidence_links_is_accepted() {
    let mut gate = default_gate();
    let demo = make_demo("d1", true);
    let evidence: Vec<EvidenceLink> = (0..64)
        .map(|i| make_evidence_default(&format!("ev{}", i)))
        .collect();
    let claim = MilestoneClaim {
        claim_id: "c-max-ev".to_string(),
        statement: "Max evidence".to_string(),
        milestone_id: "m1".to_string(),
        category: ClaimCategory::Performance,
        evidence_links: evidence,
        demos: vec!["d1".to_string()],
    };
    let result = gate.evaluate("m1", &[claim], &[demo]);
    assert!(result.is_ok());
}

#[test]
fn exactly_32_verification_commands_is_accepted() {
    let mut gate = default_gate();
    let mut demo = DemoSpecification {
        demo_id: "d-max-cmd".to_string(),
        title: "Max Commands".to_string(),
        description: "Has 32 commands".to_string(),
        milestone_id: "m1".to_string(),
        runnable: true,
        verification_commands: (0..32)
            .map(|i| make_command(&format!("cmd{}", i)))
            .collect(),
        expected_outputs: {
            let mut m = BTreeMap::new();
            m.insert("out".to_string(), make_output("out"));
            m
        },
        tags: BTreeSet::new(),
    };
    let _ = &mut demo; // silence unused_mut
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Correctness,
        vec!["d-max-cmd"],
        vec!["e1"],
    )];
    let result = gate.evaluate("m1", &claims, &[demo]);
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Section 34: Evidence with different kinds
// ---------------------------------------------------------------------------

#[test]
fn evidence_link_with_each_kind() {
    let kinds = [
        EvidenceKind::TestResult,
        EvidenceKind::BenchmarkResult,
        EvidenceKind::SecurityAudit,
        EvidenceKind::FormalProof,
        EvidenceKind::CodeReview,
        EvidenceKind::DemoReplay,
        EvidenceKind::ThirdPartyVerification,
    ];
    for kind in kinds {
        let ev = make_evidence("ev-kind-test", kind);
        assert_eq!(ev.kind, kind);
        let json = serde_json::to_string(&ev).unwrap();
        let back: EvidenceLink = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }
}

// ---------------------------------------------------------------------------
// Section 35: Claim with all categories
// ---------------------------------------------------------------------------

#[test]
fn evaluate_with_all_claim_categories() {
    let mut gate = default_gate();
    let demos: Vec<_> = (0..6)
        .map(|i| make_demo(&format!("d{}", i), true))
        .collect();
    let categories = [
        ClaimCategory::Performance,
        ClaimCategory::Correctness,
        ClaimCategory::Security,
        ClaimCategory::Compatibility,
        ClaimCategory::Reliability,
        ClaimCategory::DeveloperExperience,
    ];
    let claims: Vec<_> = categories
        .iter()
        .enumerate()
        .map(|(i, cat)| {
            let demo_id = format!("d{}", i);
            MilestoneClaim {
                claim_id: format!("c-cat-{}", i),
                statement: format!("Claim for {:?}", cat),
                milestone_id: "m1".to_string(),
                category: *cat,
                evidence_links: vec![make_evidence_default("e1")],
                demos: vec![demo_id],
            }
        })
        .collect();
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert!(decision.is_pass());
    assert_eq!(decision.total_claims, 6);
}
