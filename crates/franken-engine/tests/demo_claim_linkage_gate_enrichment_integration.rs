//! Enrichment integration tests for the `demo_claim_linkage_gate` module.
//!
//! Covers Copy/Clone semantics, BTreeSet ordering, serde roundtrips, Display
//! coverage, Debug nonempty, Default, std::error::Error trait, gate lifecycle,
//! claim checking, completeness scoring, error paths, JSON field-name stability,
//! and determinism.
#![allow(clippy::useless_vec)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::demo_claim_linkage_gate::{
    ClaimCategory, ClaimLinkageResult, DemoClaimLinkageGate, DemoSpecification, EvidenceKind,
    EvidenceLink, ExpectedOutput, LINKAGE_GATE_SCHEMA_VERSION, LinkageGateConfig,
    LinkageGateDecision, LinkageGateError, LinkageVerdict, MilestoneClaim, VerificationCommand,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn make_evidence(id: &str) -> EvidenceLink {
    EvidenceLink {
        evidence_id: id.to_string(),
        kind: EvidenceKind::TestResult,
        artifact_hash: ContentHash::compute(id.as_bytes()),
        description: format!("Evidence {id}"),
    }
}

fn make_command(id: &str) -> VerificationCommand {
    VerificationCommand {
        command_id: id.to_string(),
        command: format!("cargo test {id}"),
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
        vec![make_command(&format!("cmd-{id}"))]
    } else {
        Vec::new()
    };
    let mut outputs = BTreeMap::new();
    if runnable {
        outputs.insert("out1".to_string(), make_output("out1"));
    }
    DemoSpecification {
        demo_id: id.to_string(),
        title: format!("Demo {id}"),
        description: format!("Demo {id} description"),
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
        statement: format!("Claim {id}"),
        milestone_id: "m1".to_string(),
        category,
        evidence_links: evidence.into_iter().map(make_evidence).collect(),
        demos: demos.into_iter().map(String::from).collect(),
    }
}

fn default_gate() -> DemoClaimLinkageGate {
    DemoClaimLinkageGate::new(LinkageGateConfig::default()).unwrap()
}

// -----------------------------------------------------------------------
// Copy semantics — ClaimCategory, EvidenceKind, LinkageVerdict
// -----------------------------------------------------------------------

#[test]
fn enrichment_claim_category_copy_semantics() {
    let original = ClaimCategory::Performance;
    let copied = original;
    assert_eq!(original, copied);
    assert_eq!(original, ClaimCategory::Performance);
}

#[test]
fn enrichment_evidence_kind_copy_semantics() {
    let original = EvidenceKind::SecurityAudit;
    let copied = original;
    assert_eq!(original, copied);
}

#[test]
fn enrichment_linkage_verdict_copy_semantics() {
    let original = LinkageVerdict::Pass;
    let copied = original;
    assert_eq!(original, copied);
}

#[test]
fn enrichment_claim_category_copy_all_variants() {
    for cat in [
        ClaimCategory::Performance,
        ClaimCategory::Correctness,
        ClaimCategory::Security,
        ClaimCategory::Compatibility,
        ClaimCategory::Reliability,
        ClaimCategory::DeveloperExperience,
    ] {
        let copied = cat;
        assert_eq!(cat, copied);
    }
}

// -----------------------------------------------------------------------
// Clone independence
// -----------------------------------------------------------------------

#[test]
fn enrichment_demo_spec_clone_independence() {
    let original = make_demo("d-orig", true);
    let mut cloned = original.clone();
    cloned.demo_id = "mutated".to_string();
    cloned.runnable = false;
    assert_eq!(original.demo_id, "d-orig");
    assert!(original.runnable);
}

#[test]
fn enrichment_milestone_claim_clone_independence() {
    let original = make_claim("c-orig", ClaimCategory::Performance, vec!["d1"], vec!["e1"]);
    let mut cloned = original.clone();
    cloned.claim_id = "mutated".to_string();
    cloned.demos.push("extra".to_string());
    assert_eq!(original.claim_id, "c-orig");
    assert_eq!(original.demos.len(), 1);
}

#[test]
fn enrichment_evidence_link_clone_independence() {
    let original = make_evidence("ev-orig");
    let mut cloned = original.clone();
    cloned.evidence_id = "mutated".to_string();
    cloned.kind = EvidenceKind::FormalProof;
    assert_eq!(original.evidence_id, "ev-orig");
    assert_eq!(original.kind, EvidenceKind::TestResult);
}

#[test]
fn enrichment_config_clone_independence() {
    let original = LinkageGateConfig::default();
    let cloned = original.clone();
    // Verify clone is equal but independent
    assert_eq!(original, cloned);
    assert!(original.require_evidence);
    assert_eq!(original.min_completeness_millionths, 1_000_000);
}

#[test]
fn enrichment_gate_clone_independence() {
    let original = default_gate();
    let cloned = original.clone();
    assert_eq!(original.evaluation_count(), cloned.evaluation_count());
}

// -----------------------------------------------------------------------
// Serde roundtrips
// -----------------------------------------------------------------------

#[test]
fn enrichment_claim_category_serde_all_variants() {
    for cat in [
        ClaimCategory::Performance,
        ClaimCategory::Correctness,
        ClaimCategory::Security,
        ClaimCategory::Compatibility,
        ClaimCategory::Reliability,
        ClaimCategory::DeveloperExperience,
    ] {
        let json = serde_json::to_string(&cat).unwrap();
        let restored: ClaimCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(cat, restored);
    }
}

#[test]
fn enrichment_evidence_kind_serde_all_variants() {
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
        let restored: EvidenceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, restored);
    }
}

#[test]
fn enrichment_linkage_verdict_serde_all_variants() {
    for verdict in [
        LinkageVerdict::Pass,
        LinkageVerdict::Fail,
        LinkageVerdict::Empty,
    ] {
        let json = serde_json::to_string(&verdict).unwrap();
        let restored: LinkageVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(verdict, restored);
    }
}

#[test]
fn enrichment_demo_spec_serde_roundtrip() {
    let demo = make_demo("d-serde", true);
    let json = serde_json::to_string(&demo).unwrap();
    let restored: DemoSpecification = serde_json::from_str(&json).unwrap();
    assert_eq!(demo, restored);
}

#[test]
fn enrichment_demo_spec_incomplete_serde_roundtrip() {
    let demo = make_demo("d-inc", false);
    let json = serde_json::to_string(&demo).unwrap();
    let restored: DemoSpecification = serde_json::from_str(&json).unwrap();
    assert_eq!(demo, restored);
}

#[test]
fn enrichment_verification_command_serde_roundtrip() {
    let cmd = make_command("cmd-serde");
    let json = serde_json::to_string(&cmd).unwrap();
    let restored: VerificationCommand = serde_json::from_str(&json).unwrap();
    assert_eq!(cmd, restored);
}

#[test]
fn enrichment_expected_output_serde_roundtrip() {
    let out = make_output("out-serde");
    let json = serde_json::to_string(&out).unwrap();
    let restored: ExpectedOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(out, restored);
}

#[test]
fn enrichment_expected_output_no_hash_serde_roundtrip() {
    let out = ExpectedOutput {
        name: "no-hash".to_string(),
        expected_hash: None,
        exact_match: false,
        tolerance_millionths: 50_000,
    };
    let json = serde_json::to_string(&out).unwrap();
    let restored: ExpectedOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(out, restored);
}

#[test]
fn enrichment_evidence_link_serde_roundtrip() {
    let ev = make_evidence("ev-serde");
    let json = serde_json::to_string(&ev).unwrap();
    let restored: EvidenceLink = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, restored);
}

#[test]
fn enrichment_milestone_claim_serde_roundtrip() {
    let claim = make_claim(
        "c-serde",
        ClaimCategory::Security,
        vec!["d1"],
        vec!["e1", "e2"],
    );
    let json = serde_json::to_string(&claim).unwrap();
    let restored: MilestoneClaim = serde_json::from_str(&json).unwrap();
    assert_eq!(claim, restored);
}

#[test]
fn enrichment_config_serde_roundtrip() {
    let config = LinkageGateConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let restored: LinkageGateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
}

#[test]
fn enrichment_claim_linkage_result_serde_roundtrip() {
    let result = ClaimLinkageResult {
        claim_id: "c1".to_string(),
        linked: true,
        has_runnable_demo: true,
        has_evidence: true,
        demos_have_outputs: true,
        demos_have_commands: true,
        missing: vec![],
        completeness_millionths: 1_000_000,
    };
    let json = serde_json::to_string(&result).unwrap();
    let restored: ClaimLinkageResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

#[test]
fn enrichment_gate_decision_serde_roundtrip() {
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
    let restored: LinkageGateDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, restored);
}

#[test]
fn enrichment_error_serde_all_variants() {
    let errors = vec![
        LinkageGateError::NoClaims,
        LinkageGateError::TooManyClaims {
            count: 300,
            max: 256,
        },
        LinkageGateError::DuplicateClaim {
            claim_id: "dup".to_string(),
        },
        LinkageGateError::DuplicateDemo {
            demo_id: "dup-demo".to_string(),
        },
        LinkageGateError::TooManyEvidenceLinks {
            claim_id: "c1".to_string(),
            count: 100,
            max: 64,
        },
        LinkageGateError::TooManyCommands {
            demo_id: "d1".to_string(),
            count: 50,
            max: 32,
        },
        LinkageGateError::UnknownDemo {
            claim_id: "c1".to_string(),
            demo_id: "x".to_string(),
        },
        LinkageGateError::InvalidConfig {
            detail: "bad".to_string(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let restored: LinkageGateError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, restored);
    }
}

#[test]
fn enrichment_gate_serde_roundtrip() {
    let gate = default_gate();
    let json = serde_json::to_string(&gate).unwrap();
    let restored: DemoClaimLinkageGate = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.evaluation_count(), 0);
}

// -----------------------------------------------------------------------
// Display coverage
// -----------------------------------------------------------------------

#[test]
fn enrichment_claim_category_display_all_unique() {
    let displays: BTreeSet<String> = [
        ClaimCategory::Performance,
        ClaimCategory::Correctness,
        ClaimCategory::Security,
        ClaimCategory::Compatibility,
        ClaimCategory::Reliability,
        ClaimCategory::DeveloperExperience,
    ]
    .iter()
    .map(|c| c.to_string())
    .collect();
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_claim_category_display_specific() {
    assert_eq!(ClaimCategory::Performance.to_string(), "performance");
    assert_eq!(ClaimCategory::Correctness.to_string(), "correctness");
    assert_eq!(ClaimCategory::Security.to_string(), "security");
    assert_eq!(ClaimCategory::Compatibility.to_string(), "compatibility");
    assert_eq!(ClaimCategory::Reliability.to_string(), "reliability");
    assert_eq!(
        ClaimCategory::DeveloperExperience.to_string(),
        "developer-experience"
    );
}

#[test]
fn enrichment_evidence_kind_display_all_unique() {
    let displays: BTreeSet<String> = [
        EvidenceKind::TestResult,
        EvidenceKind::BenchmarkResult,
        EvidenceKind::SecurityAudit,
        EvidenceKind::FormalProof,
        EvidenceKind::CodeReview,
        EvidenceKind::DemoReplay,
        EvidenceKind::ThirdPartyVerification,
    ]
    .iter()
    .map(|k| k.to_string())
    .collect();
    assert_eq!(displays.len(), 7);
}

#[test]
fn enrichment_evidence_kind_display_specific() {
    assert_eq!(EvidenceKind::TestResult.to_string(), "test-result");
    assert_eq!(
        EvidenceKind::BenchmarkResult.to_string(),
        "benchmark-result"
    );
    assert_eq!(EvidenceKind::SecurityAudit.to_string(), "security-audit");
    assert_eq!(EvidenceKind::FormalProof.to_string(), "formal-proof");
    assert_eq!(EvidenceKind::CodeReview.to_string(), "code-review");
    assert_eq!(EvidenceKind::DemoReplay.to_string(), "demo-replay");
    assert_eq!(
        EvidenceKind::ThirdPartyVerification.to_string(),
        "third-party-verification"
    );
}

#[test]
fn enrichment_linkage_verdict_display_all() {
    assert_eq!(LinkageVerdict::Pass.to_string(), "pass");
    assert_eq!(LinkageVerdict::Fail.to_string(), "fail");
    assert_eq!(LinkageVerdict::Empty.to_string(), "empty");
}

#[test]
fn enrichment_demo_spec_display_complete() {
    let demo = make_demo("d1", true);
    let display = demo.to_string();
    assert!(display.contains("d1"));
    assert!(display.contains("complete"));
}

#[test]
fn enrichment_demo_spec_display_incomplete() {
    let demo = make_demo("d1", false);
    let display = demo.to_string();
    assert!(display.contains("incomplete"));
}

#[test]
fn enrichment_claim_display_contains_id_and_category() {
    let claim = make_claim("c-disp", ClaimCategory::Security, vec!["d1"], vec!["e1"]);
    let display = claim.to_string();
    assert!(display.contains("c-disp"));
    assert!(display.contains("security"));
}

#[test]
fn enrichment_verification_command_display() {
    let cmd = make_command("cmd-disp");
    let display = cmd.to_string();
    assert!(display.contains("cmd-disp"));
    assert!(display.contains("exit=0"));
}

#[test]
fn enrichment_evidence_link_display() {
    let ev = make_evidence("ev-disp");
    let display = ev.to_string();
    assert!(display.contains("ev-disp"));
    assert!(display.contains("test-result"));
}

#[test]
fn enrichment_decision_display() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec!["e1"],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    let display = decision.to_string();
    assert!(display.contains("m1"));
    assert!(display.contains("pass"));
}

#[test]
fn enrichment_error_display_all_variants() {
    let errors = vec![
        LinkageGateError::NoClaims,
        LinkageGateError::TooManyClaims {
            count: 300,
            max: 256,
        },
        LinkageGateError::DuplicateClaim {
            claim_id: "dup".to_string(),
        },
        LinkageGateError::DuplicateDemo {
            demo_id: "dd".to_string(),
        },
        LinkageGateError::TooManyEvidenceLinks {
            claim_id: "c1".to_string(),
            count: 100,
            max: 64,
        },
        LinkageGateError::TooManyCommands {
            demo_id: "d1".to_string(),
            count: 50,
            max: 32,
        },
        LinkageGateError::UnknownDemo {
            claim_id: "c1".to_string(),
            demo_id: "x".to_string(),
        },
        LinkageGateError::InvalidConfig {
            detail: "bad".to_string(),
        },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), errors.len());
}

// -----------------------------------------------------------------------
// Debug nonempty
// -----------------------------------------------------------------------

#[test]
fn enrichment_demo_spec_debug() {
    let demo = make_demo("dbg", true);
    let dbg = format!("{demo:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("DemoSpecification"));
}

#[test]
fn enrichment_milestone_claim_debug() {
    let claim = make_claim("dbg", ClaimCategory::Correctness, vec![], vec![]);
    let dbg = format!("{claim:?}");
    assert!(dbg.contains("MilestoneClaim"));
}

#[test]
fn enrichment_config_debug() {
    let config = LinkageGateConfig::default();
    let dbg = format!("{config:?}");
    assert!(dbg.contains("LinkageGateConfig"));
}

#[test]
fn enrichment_gate_debug() {
    let gate = default_gate();
    let dbg = format!("{gate:?}");
    assert!(dbg.contains("DemoClaimLinkageGate"));
}

#[test]
fn enrichment_error_debug() {
    let err = LinkageGateError::NoClaims;
    let dbg = format!("{err:?}");
    assert!(dbg.contains("NoClaims"));
}

#[test]
fn enrichment_decision_debug() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec!["e1"],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    let dbg = format!("{decision:?}");
    assert!(dbg.contains("LinkageGateDecision"));
}

// -----------------------------------------------------------------------
// Default
// -----------------------------------------------------------------------

#[test]
fn enrichment_config_default() {
    let config = LinkageGateConfig::default();
    assert_eq!(config.min_completeness_millionths, 1_000_000);
    assert!(config.require_runnable_demo);
    assert!(config.require_evidence);
    assert!(config.require_expected_outputs);
    assert!(config.require_verification_commands);
    assert_eq!(config.epoch, SecurityEpoch::from_raw(1));
}

// -----------------------------------------------------------------------
// std::error::Error trait
// -----------------------------------------------------------------------

#[test]
fn enrichment_error_implements_std_error() {
    let err = LinkageGateError::NoClaims;
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
}

#[test]
fn enrichment_error_source_is_none() {
    use std::error::Error;
    let err = LinkageGateError::NoClaims;
    assert!(err.source().is_none());
}

// -----------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------

#[test]
fn enrichment_schema_version_nonempty() {
    assert!(!LINKAGE_GATE_SCHEMA_VERSION.is_empty());
    assert!(LINKAGE_GATE_SCHEMA_VERSION.contains("demo-claim-linkage-gate"));
}

// -----------------------------------------------------------------------
// DemoSpecification — is_complete, command_count
// -----------------------------------------------------------------------

#[test]
fn enrichment_demo_is_complete_runnable_with_both() {
    let demo = make_demo("d1", true);
    assert!(demo.is_complete());
    assert_eq!(demo.command_count(), 1);
}

#[test]
fn enrichment_demo_not_complete_when_not_runnable() {
    let demo = make_demo("d1", false);
    assert!(!demo.is_complete());
    assert_eq!(demo.command_count(), 0);
}

#[test]
fn enrichment_demo_not_complete_without_outputs() {
    let demo = DemoSpecification {
        demo_id: "d-no-out".to_string(),
        title: "No outputs".to_string(),
        description: "test".to_string(),
        milestone_id: "m1".to_string(),
        runnable: true,
        verification_commands: vec![make_command("cmd1")],
        expected_outputs: BTreeMap::new(),
        tags: BTreeSet::new(),
    };
    assert!(!demo.is_complete());
}

#[test]
fn enrichment_demo_not_complete_without_commands() {
    let mut outputs = BTreeMap::new();
    outputs.insert("o1".to_string(), make_output("o1"));
    let demo = DemoSpecification {
        demo_id: "d-no-cmd".to_string(),
        title: "No commands".to_string(),
        description: "test".to_string(),
        milestone_id: "m1".to_string(),
        runnable: true,
        verification_commands: vec![],
        expected_outputs: outputs,
        tags: BTreeSet::new(),
    };
    assert!(!demo.is_complete());
}

// -----------------------------------------------------------------------
// Gate lifecycle — constructor
// -----------------------------------------------------------------------

#[test]
fn enrichment_gate_new_valid_config() {
    let gate = default_gate();
    assert_eq!(gate.evaluation_count(), 0);
    assert_eq!(gate.config().min_completeness_millionths, 1_000_000);
}

#[test]
fn enrichment_gate_new_rejects_negative_completeness() {
    let config = LinkageGateConfig {
        min_completeness_millionths: -1,
        ..Default::default()
    };
    assert!(matches!(
        DemoClaimLinkageGate::new(config),
        Err(LinkageGateError::InvalidConfig { .. })
    ));
}

#[test]
fn enrichment_gate_new_rejects_over_million_completeness() {
    let config = LinkageGateConfig {
        min_completeness_millionths: 1_000_001,
        ..Default::default()
    };
    assert!(matches!(
        DemoClaimLinkageGate::new(config),
        Err(LinkageGateError::InvalidConfig { .. })
    ));
}

#[test]
fn enrichment_gate_new_accepts_zero_completeness() {
    let config = LinkageGateConfig {
        min_completeness_millionths: 0,
        ..Default::default()
    };
    assert!(DemoClaimLinkageGate::new(config).is_ok());
}

#[test]
fn enrichment_gate_new_accepts_million_completeness() {
    let config = LinkageGateConfig {
        min_completeness_millionths: 1_000_000,
        ..Default::default()
    };
    assert!(DemoClaimLinkageGate::new(config).is_ok());
}

// -----------------------------------------------------------------------
// Gate evaluate — error paths
// -----------------------------------------------------------------------

#[test]
fn enrichment_evaluate_no_claims_error() {
    let mut gate = default_gate();
    assert!(matches!(
        gate.evaluate("m1", &[], &[]),
        Err(LinkageGateError::NoClaims)
    ));
}

#[test]
fn enrichment_evaluate_duplicate_claim_error() {
    let mut gate = default_gate();
    let demo = make_demo("d1", true);
    let claims = vec![
        make_claim("dup", ClaimCategory::Performance, vec!["d1"], vec!["e1"]),
        make_claim("dup", ClaimCategory::Security, vec!["d1"], vec!["e2"]),
    ];
    assert!(matches!(
        gate.evaluate("m1", &claims, &[demo]),
        Err(LinkageGateError::DuplicateClaim { .. })
    ));
}

#[test]
fn enrichment_evaluate_duplicate_demo_error() {
    let mut gate = default_gate();
    let demos = vec![make_demo("dup-d", true), make_demo("dup-d", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["dup-d"],
        vec!["e1"],
    )];
    assert!(matches!(
        gate.evaluate("m1", &claims, &demos),
        Err(LinkageGateError::DuplicateDemo { .. })
    ));
}

#[test]
fn enrichment_evaluate_unknown_demo_error() {
    let mut gate = default_gate();
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["nonexistent"],
        vec!["e1"],
    )];
    assert!(matches!(
        gate.evaluate("m1", &claims, &[]),
        Err(LinkageGateError::UnknownDemo { .. })
    ));
}

// -----------------------------------------------------------------------
// Gate evaluate — pass/fail lifecycle
// -----------------------------------------------------------------------

#[test]
fn enrichment_evaluate_fully_linked_passes() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec!["e1"],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert_eq!(decision.verdict, LinkageVerdict::Pass);
    assert!(decision.is_pass());
    assert_eq!(decision.linked_claims, 1);
    assert_eq!(decision.unlinked_claims, 0);
    assert_eq!(decision.total_claims, 1);
}

#[test]
fn enrichment_evaluate_missing_evidence_fails() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec![],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert_eq!(decision.verdict, LinkageVerdict::Fail);
    assert!(!decision.is_pass());
}

#[test]
fn enrichment_evaluate_missing_demo_refs_fails() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec![],
        vec!["e1"],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert_eq!(decision.verdict, LinkageVerdict::Fail);
}

#[test]
fn enrichment_evaluate_non_runnable_demo_fails() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", false)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec!["e1"],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert_eq!(decision.verdict, LinkageVerdict::Fail);
}

#[test]
fn enrichment_evaluate_increments_count() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec!["e1"],
    )];
    let _ = gate.evaluate("m1", &claims, &demos);
    assert_eq!(gate.evaluation_count(), 1);
    let _ = gate.evaluate("m1", &claims, &demos);
    assert_eq!(gate.evaluation_count(), 2);
}

// -----------------------------------------------------------------------
// Multiple claims
// -----------------------------------------------------------------------

#[test]
fn enrichment_multiple_claims_all_linked() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true), make_demo("d2", true)];
    let claims = vec![
        make_claim("c1", ClaimCategory::Performance, vec!["d1"], vec!["e1"]),
        make_claim("c2", ClaimCategory::Security, vec!["d2"], vec!["e2"]),
    ];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert_eq!(decision.verdict, LinkageVerdict::Pass);
    assert_eq!(decision.linked_claims, 2);
}

#[test]
fn enrichment_mixed_linked_unlinked_fails() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![
        make_claim("c1", ClaimCategory::Performance, vec!["d1"], vec!["e1"]),
        make_claim("c2", ClaimCategory::Security, vec![], vec![]),
    ];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert_eq!(decision.verdict, LinkageVerdict::Fail);
    assert_eq!(decision.linked_claims, 1);
    assert_eq!(decision.unlinked_claims, 1);
}

// -----------------------------------------------------------------------
// Completeness scoring
// -----------------------------------------------------------------------

#[test]
fn enrichment_fully_linked_million_completeness() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec!["e1"],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert_eq!(decision.aggregate_completeness_millionths, 1_000_000);
}

#[test]
fn enrichment_partial_linkage_partial_completeness() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec![],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert!(decision.aggregate_completeness_millionths > 0);
    assert!(decision.aggregate_completeness_millionths < 1_000_000);
}

#[test]
fn enrichment_linkage_rate_half() {
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
fn enrichment_linkage_rate_zero_claims_returns_zero() {
    // Test the method directly on a constructed decision
    let decision = LinkageGateDecision {
        decision_id: "test".to_string(),
        milestone_id: "m1".to_string(),
        epoch: SecurityEpoch::from_raw(1),
        verdict: LinkageVerdict::Empty,
        claim_results: vec![],
        total_claims: 0,
        linked_claims: 0,
        unlinked_claims: 0,
        aggregate_completeness_millionths: 0,
        rationale: "empty".to_string(),
        artifact_hash: ContentHash::compute(b"empty"),
    };
    assert_eq!(decision.linkage_rate_millionths(), 0);
}

// -----------------------------------------------------------------------
// Relaxed configuration
// -----------------------------------------------------------------------

#[test]
fn enrichment_relaxed_no_evidence_required() {
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
    assert_eq!(decision.verdict, LinkageVerdict::Pass);
}

#[test]
fn enrichment_relaxed_no_runnable_demo_required() {
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
    assert_eq!(decision.verdict, LinkageVerdict::Pass);
}

// -----------------------------------------------------------------------
// Artifact hash determinism
// -----------------------------------------------------------------------

#[test]
fn enrichment_artifact_hash_deterministic() {
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
fn enrichment_artifact_hash_differs_on_different_input() {
    let demos = vec![make_demo("d1", true)];
    let claims1 = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec!["e1"],
    )];
    let claims2 = vec![make_claim(
        "c2",
        ClaimCategory::Security,
        vec!["d1"],
        vec!["e2"],
    )];
    let mut g1 = default_gate();
    let d1 = g1.evaluate("m1", &claims1, &demos).unwrap();
    let mut g2 = default_gate();
    let d2 = g2.evaluate("m1", &claims2, &demos).unwrap();
    assert_ne!(d1.artifact_hash, d2.artifact_hash);
}

// -----------------------------------------------------------------------
// JSON field-name stability
// -----------------------------------------------------------------------

#[test]
fn enrichment_demo_spec_json_field_names() {
    let demo = make_demo("d-json", true);
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
        assert!(json.contains(field), "JSON missing field: {field}");
    }
}

#[test]
fn enrichment_claim_json_field_names() {
    let claim = make_claim("c-json", ClaimCategory::Performance, vec!["d1"], vec!["e1"]);
    let json = serde_json::to_string(&claim).unwrap();
    for field in [
        "claim_id",
        "statement",
        "milestone_id",
        "category",
        "evidence_links",
        "demos",
    ] {
        assert!(json.contains(field), "JSON missing field: {field}");
    }
}

#[test]
fn enrichment_decision_json_field_names() {
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
        assert!(json.contains(field), "JSON missing field: {field}");
    }
}

#[test]
fn enrichment_config_json_field_names() {
    let config = LinkageGateConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    for field in [
        "epoch",
        "min_completeness_millionths",
        "require_runnable_demo",
        "require_evidence",
        "require_expected_outputs",
        "require_verification_commands",
    ] {
        assert!(json.contains(field), "JSON missing field: {field}");
    }
}

#[test]
fn enrichment_claim_linkage_result_json_field_names() {
    let result = ClaimLinkageResult {
        claim_id: "c1".to_string(),
        linked: true,
        has_runnable_demo: true,
        has_evidence: true,
        demos_have_outputs: true,
        demos_have_commands: true,
        missing: vec![],
        completeness_millionths: 1_000_000,
    };
    let json = serde_json::to_string(&result).unwrap();
    for field in [
        "claim_id",
        "linked",
        "has_runnable_demo",
        "has_evidence",
        "demos_have_outputs",
        "demos_have_commands",
        "missing",
        "completeness_millionths",
    ] {
        assert!(json.contains(field), "JSON missing field: {field}");
    }
}

// -----------------------------------------------------------------------
// Claim category coverage
// -----------------------------------------------------------------------

#[test]
fn enrichment_all_claim_categories_evaluate() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    for cat in [
        ClaimCategory::Performance,
        ClaimCategory::Correctness,
        ClaimCategory::Security,
        ClaimCategory::Compatibility,
        ClaimCategory::Reliability,
        ClaimCategory::DeveloperExperience,
    ] {
        let claims = vec![make_claim("c1", cat, vec!["d1"], vec!["e1"])];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert_eq!(decision.verdict, LinkageVerdict::Pass);
    }
}

// -----------------------------------------------------------------------
// Evidence kind coverage in links
// -----------------------------------------------------------------------

#[test]
fn enrichment_all_evidence_kinds_in_links() {
    let kinds = [
        EvidenceKind::TestResult,
        EvidenceKind::BenchmarkResult,
        EvidenceKind::SecurityAudit,
        EvidenceKind::FormalProof,
        EvidenceKind::CodeReview,
        EvidenceKind::DemoReplay,
        EvidenceKind::ThirdPartyVerification,
    ];
    for kind in &kinds {
        let link = EvidenceLink {
            evidence_id: "ev1".to_string(),
            kind: *kind,
            artifact_hash: ContentHash::compute(b"test"),
            description: "test evidence".to_string(),
        };
        let json = serde_json::to_string(&link).unwrap();
        let restored: EvidenceLink = serde_json::from_str(&json).unwrap();
        assert_eq!(link, restored);
    }
}

// -----------------------------------------------------------------------
// Demo with tags
// -----------------------------------------------------------------------

#[test]
fn enrichment_demo_with_tags_serde() {
    let mut tags = BTreeSet::new();
    tags.insert("integration".to_string());
    tags.insert("smoke".to_string());
    let demo = DemoSpecification {
        demo_id: "d-tags".to_string(),
        title: "Tagged".to_string(),
        description: "test".to_string(),
        milestone_id: "m1".to_string(),
        runnable: true,
        verification_commands: vec![make_command("cmd1")],
        expected_outputs: {
            let mut m = BTreeMap::new();
            m.insert("o1".to_string(), make_output("o1"));
            m
        },
        tags,
    };
    let json = serde_json::to_string(&demo).unwrap();
    let restored: DemoSpecification = serde_json::from_str(&json).unwrap();
    assert_eq!(demo, restored);
    assert_eq!(restored.tags.len(), 2);
}

// -----------------------------------------------------------------------
// Decision rationale content
// -----------------------------------------------------------------------

#[test]
fn enrichment_pass_rationale_mentions_all_linked() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec!["e1"],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert!(decision.rationale.contains("fully linked"));
}

#[test]
fn enrichment_fail_rationale_mentions_unlinked() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![
        make_claim("c1", ClaimCategory::Performance, vec!["d1"], vec!["e1"]),
        make_claim("c2", ClaimCategory::Security, vec![], vec![]),
    ];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert!(decision.rationale.contains("unlinked"));
    assert!(decision.rationale.contains("c2"));
}

// -----------------------------------------------------------------------
// Decision ID format
// -----------------------------------------------------------------------

#[test]
fn enrichment_decision_id_contains_milestone() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec!["e1"],
    )];
    let decision = gate.evaluate("my-milestone", &claims, &demos).unwrap();
    assert!(decision.decision_id.contains("my-milestone"));
}

// -----------------------------------------------------------------------
// Multiple demos per claim
// -----------------------------------------------------------------------

#[test]
fn enrichment_claim_with_multiple_demos() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true), make_demo("d2", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1", "d2"],
        vec!["e1"],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert_eq!(decision.verdict, LinkageVerdict::Pass);
}

// -----------------------------------------------------------------------
// Claim result details
// -----------------------------------------------------------------------

#[test]
fn enrichment_claim_result_fully_linked() {
    let mut gate = default_gate();
    let demos = vec![make_demo("d1", true)];
    let claims = vec![make_claim(
        "c1",
        ClaimCategory::Performance,
        vec!["d1"],
        vec!["e1"],
    )];
    let decision = gate.evaluate("m1", &claims, &demos).unwrap();
    assert_eq!(decision.claim_results.len(), 1);
    let r = &decision.claim_results[0];
    assert!(r.linked);
    assert!(r.has_runnable_demo);
    assert!(r.has_evidence);
    assert!(r.demos_have_outputs);
    assert!(r.demos_have_commands);
    assert!(r.missing.is_empty());
    assert_eq!(r.completeness_millionths, 1_000_000);
}

#[test]
fn enrichment_claim_result_missing_items() {
    let mut gate = default_gate();
    let claims = vec![make_claim("c1", ClaimCategory::Performance, vec![], vec![])];
    // Need at least one demo to avoid unknown demo error
    let decision = gate.evaluate("m1", &claims, &[]).unwrap();
    let r = &decision.claim_results[0];
    assert!(!r.linked);
    assert!(!r.missing.is_empty());
    assert!(r.completeness_millionths < 1_000_000);
}
