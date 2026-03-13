#![forbid(unsafe_code)]
//! Enrichment integration tests for `rgc_test_harness` module.
//!
//! Covers: HarnessLane, BaselineScenarioDomain, BaselineScenarioOutcome,
//! DeterministicTestContext, EventInput, HarnessLogEvent, HarnessRunManifest,
//! HarnessArtifactTriad, BaselineE2eScenario, ArtifactValidationErrorCode,
//! ArtifactValidationFinding, ArtifactValidationReport,
//! ArtifactBundleValidationErrorCode, ArtifactBundleValidationFinding,
//! ArtifactBundleCorrelationSignature, ArtifactBundleValidationReport,
//! FixtureLoadError, ArtifactWriteError, load_json_fixture, write_artifact_triad,
//! validate_artifact_triad, validate_artifact_bundle,
//! baseline_e2e_scenario_registry, select_baseline_e2e_scenarios,
//! schema version constants -- serde roundtrips, Display uniqueness,
//! deterministic ID derivation, multi-lane correlation, path traversal
//! protection, artifact lifecycle, and cross-cutting integration scenarios.

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
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::rgc_test_harness::*;
use serde::{Deserialize, Serialize};

// ── helpers ──────────────────────────────────────────────────────────────

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be monotonic")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "franken_engine_enrichment_{label}_{nanos}_{}",
        std::process::id()
    ))
}

fn make_ctx(
    scenario: &str,
    fixture: &str,
    lane: HarnessLane,
    seed: u64,
) -> DeterministicTestContext {
    DeterministicTestContext::new(scenario, fixture, lane, seed)
}

fn make_event(ctx: &DeterministicTestContext, seq: u64) -> HarnessLogEvent {
    ctx.event(EventInput {
        sequence: seq,
        component: "enrichment_test",
        event: "step",
        outcome: "pass",
        error_code: None,
        timing_us: 10 + seq,
        timestamp_unix_ms: 1_700_000_000_000 + seq,
    })
}

fn make_manifest(
    ctx: &DeterministicTestContext,
    event_count: usize,
    command_count: usize,
) -> HarnessRunManifest {
    HarnessRunManifest::from_context(
        ctx,
        ctx.default_run_id(),
        event_count,
        command_count,
        "./replay.sh ci",
        1_700_500_000_000,
    )
}

fn write_lane_triad(
    bundle_dir: &std::path::Path,
    scenario_id: &str,
    fixture_id: &str,
    lane: HarnessLane,
    seed: u64,
) -> HarnessArtifactTriad {
    let ctx = make_ctx(scenario_id, fixture_id, lane, seed);
    let events = vec![make_event(&ctx, 0)];
    let commands = vec!["cargo test".to_string()];
    let manifest = make_manifest(&ctx, 1, 1);
    write_artifact_triad(bundle_dir, &manifest, &events, &commands)
        .expect("lane triad should write")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TestFixture {
    name: String,
    value: u64,
}

// ── HarnessLane Display uniqueness ───────────────────────────────────────

#[test]
fn enrichment_harness_lane_display_values_are_all_unique() {
    let lanes = [
        HarnessLane::Parser,
        HarnessLane::Runtime,
        HarnessLane::Security,
        HarnessLane::Governance,
        HarnessLane::E2e,
    ];
    let display_set: BTreeSet<String> = lanes.iter().map(|l| l.to_string()).collect();
    assert_eq!(display_set.len(), lanes.len());
}

#[test]
fn enrichment_harness_lane_as_str_matches_display_for_all_variants() {
    for lane in [
        HarnessLane::Parser,
        HarnessLane::Runtime,
        HarnessLane::Security,
        HarnessLane::Governance,
        HarnessLane::E2e,
    ] {
        assert_eq!(lane.to_string(), lane.as_str());
    }
}

#[test]
fn enrichment_harness_lane_serde_roundtrip_all_variants() {
    for lane in [
        HarnessLane::Parser,
        HarnessLane::Runtime,
        HarnessLane::Security,
        HarnessLane::Governance,
        HarnessLane::E2e,
    ] {
        let json = serde_json::to_string(&lane).unwrap();
        let back: HarnessLane = serde_json::from_str(&json).unwrap();
        assert_eq!(lane, back);
    }
}

#[test]
fn enrichment_harness_lane_as_str_values_are_snake_case() {
    for lane in [
        HarnessLane::Parser,
        HarnessLane::Runtime,
        HarnessLane::Security,
        HarnessLane::Governance,
        HarnessLane::E2e,
    ] {
        let s = lane.as_str();
        assert_eq!(s, s.to_lowercase(), "as_str value must be lowercase");
        assert!(!s.contains(' '), "as_str value must not contain spaces");
    }
}

#[test]
fn enrichment_harness_lane_ord_is_stable_across_runs() {
    let mut lanes_a = vec![
        HarnessLane::E2e,
        HarnessLane::Governance,
        HarnessLane::Security,
        HarnessLane::Runtime,
        HarnessLane::Parser,
    ];
    let mut lanes_b = lanes_a.clone();
    lanes_a.sort();
    lanes_b.sort();
    assert_eq!(lanes_a, lanes_b);
}

// ── BaselineScenarioDomain Display/serde ─────────────────────────────────

#[test]
fn enrichment_baseline_scenario_domain_display_unique() {
    let domains = [
        BaselineScenarioDomain::Runtime,
        BaselineScenarioDomain::Module,
        BaselineScenarioDomain::Security,
    ];
    let display_set: BTreeSet<String> = domains.iter().map(|d| d.to_string()).collect();
    assert_eq!(display_set.len(), domains.len());
}

#[test]
fn enrichment_baseline_scenario_domain_as_str_matches_display() {
    for domain in [
        BaselineScenarioDomain::Runtime,
        BaselineScenarioDomain::Module,
        BaselineScenarioDomain::Security,
    ] {
        assert_eq!(domain.to_string(), domain.as_str());
    }
}

#[test]
fn enrichment_baseline_scenario_domain_serde_roundtrip() {
    for domain in [
        BaselineScenarioDomain::Runtime,
        BaselineScenarioDomain::Module,
        BaselineScenarioDomain::Security,
    ] {
        let json = serde_json::to_string(&domain).unwrap();
        let back: BaselineScenarioDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(domain, back);
    }
}

// ── BaselineScenarioOutcome serde ────────────────────────────────────────

#[test]
fn enrichment_baseline_scenario_outcome_serde_roundtrip() {
    for outcome in [
        BaselineScenarioOutcome::HappyPath,
        BaselineScenarioOutcome::CanonicalFailure,
    ] {
        let json = serde_json::to_string(&outcome).unwrap();
        let back: BaselineScenarioOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, back);
    }
}

// ── DeterministicTestContext ─────────────────────────────────────────────

#[test]
fn enrichment_context_trace_id_prefix_format() {
    let ctx = make_ctx("scen-1", "fix-1", HarnessLane::Runtime, 42);
    assert!(ctx.trace_id.starts_with("trace-rgc-"));
    assert!(ctx.trace_id.len() > "trace-rgc-".len());
}

#[test]
fn enrichment_context_decision_id_prefix_format() {
    let ctx = make_ctx("scen-1", "fix-1", HarnessLane::Runtime, 42);
    assert!(ctx.decision_id.starts_with("decision-rgc-"));
    assert!(ctx.decision_id.len() > "decision-rgc-".len());
}

#[test]
fn enrichment_context_policy_id_embeds_lane_name() {
    for lane in [
        HarnessLane::Parser,
        HarnessLane::Runtime,
        HarnessLane::Security,
        HarnessLane::Governance,
        HarnessLane::E2e,
    ] {
        let ctx = make_ctx("s", "f", lane, 1);
        assert!(
            ctx.policy_id.contains(lane.as_str()),
            "policy_id `{}` should contain lane `{}`",
            ctx.policy_id,
            lane.as_str()
        );
    }
}

#[test]
fn enrichment_context_deterministic_same_inputs_same_ids() {
    let a = make_ctx("scenario-X", "fixture-Y", HarnessLane::Security, 999);
    let b = make_ctx("scenario-X", "fixture-Y", HarnessLane::Security, 999);
    assert_eq!(a.trace_id, b.trace_id);
    assert_eq!(a.decision_id, b.decision_id);
    assert_eq!(a.policy_id, b.policy_id);
}

#[test]
fn enrichment_context_different_scenario_different_trace() {
    let a = make_ctx("alpha", "fix", HarnessLane::Runtime, 1);
    let b = make_ctx("beta", "fix", HarnessLane::Runtime, 1);
    assert_ne!(a.trace_id, b.trace_id);
}

#[test]
fn enrichment_context_different_fixture_different_trace() {
    let a = make_ctx("sc", "fix-a", HarnessLane::Runtime, 1);
    let b = make_ctx("sc", "fix-b", HarnessLane::Runtime, 1);
    assert_ne!(a.trace_id, b.trace_id);
}

#[test]
fn enrichment_context_different_lane_different_trace() {
    let a = make_ctx("sc", "fix", HarnessLane::Parser, 1);
    let b = make_ctx("sc", "fix", HarnessLane::Governance, 1);
    assert_ne!(a.trace_id, b.trace_id);
    assert_ne!(a.policy_id, b.policy_id);
}

#[test]
fn enrichment_context_different_seed_different_trace() {
    let a = make_ctx("sc", "fix", HarnessLane::Runtime, 0);
    let b = make_ctx("sc", "fix", HarnessLane::Runtime, 1);
    assert_ne!(a.trace_id, b.trace_id);
}

#[test]
fn enrichment_context_trace_and_decision_share_suffix() {
    let ctx = make_ctx("sc", "fix", HarnessLane::Runtime, 42);
    let trace_suffix = &ctx.trace_id["trace-rgc-".len()..];
    let decision_suffix = &ctx.decision_id["decision-rgc-".len()..];
    assert_eq!(trace_suffix, decision_suffix);
}

#[test]
fn enrichment_context_serde_roundtrip() {
    let ctx = make_ctx("sc-serde", "fix-serde", HarnessLane::E2e, 7);
    let json = serde_json::to_string(&ctx).unwrap();
    let back: DeterministicTestContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, back);
}

#[test]
fn enrichment_context_default_run_id_starts_with_run_prefix() {
    let ctx = make_ctx("rgc-100", "fix-1", HarnessLane::Runtime, 42);
    let run_id = ctx.default_run_id();
    assert!(run_id.starts_with("run-"));
}

#[test]
fn enrichment_context_default_run_id_contains_sanitized_scenario() {
    let ctx = make_ctx("rgc-100", "fix-1", HarnessLane::Runtime, 42);
    let run_id = ctx.default_run_id();
    assert!(run_id.contains("rgc-100"));
}

#[test]
fn enrichment_context_default_run_id_deterministic() {
    let a = make_ctx("sc", "fix", HarnessLane::Runtime, 42);
    let b = make_ctx("sc", "fix", HarnessLane::Runtime, 42);
    assert_eq!(a.default_run_id(), b.default_run_id());
}

#[test]
fn enrichment_context_seed_zero_produces_valid_ids() {
    let ctx = make_ctx("sc", "fix", HarnessLane::Runtime, 0);
    assert!(!ctx.trace_id.is_empty());
    assert!(!ctx.decision_id.is_empty());
    assert!(!ctx.policy_id.is_empty());
}

#[test]
fn enrichment_context_seed_max_produces_valid_ids() {
    let ctx = make_ctx("sc", "fix", HarnessLane::Runtime, u64::MAX);
    assert!(!ctx.trace_id.is_empty());
    assert!(ctx.trace_id.starts_with("trace-rgc-"));
}

// ── EventInput / HarnessLogEvent ─────────────────────────────────────────

#[test]
fn enrichment_event_populates_schema_version_from_constant() {
    let ctx = make_ctx("sc", "fix", HarnessLane::Runtime, 1);
    let event = make_event(&ctx, 0);
    assert_eq!(event.schema_version, RGC_TEST_HARNESS_EVENT_SCHEMA_VERSION);
}

#[test]
fn enrichment_event_inherits_all_context_fields() {
    let ctx = make_ctx("scenario-ev", "fixture-ev", HarnessLane::Security, 42);
    let event = ctx.event(EventInput {
        sequence: 7,
        component: "comp-a",
        event: "evt-b",
        outcome: "pass",
        error_code: Some("FE-ERR-001"),
        timing_us: 999,
        timestamp_unix_ms: 1_700_000_000_123,
    });
    assert_eq!(event.scenario_id, ctx.scenario_id);
    assert_eq!(event.fixture_id, ctx.fixture_id);
    assert_eq!(event.trace_id, ctx.trace_id);
    assert_eq!(event.decision_id, ctx.decision_id);
    assert_eq!(event.policy_id, ctx.policy_id);
    assert_eq!(event.lane, ctx.lane);
    assert_eq!(event.seed, ctx.seed);
    assert_eq!(event.sequence, 7);
    assert_eq!(event.component, "comp-a");
    assert_eq!(event.event, "evt-b");
    assert_eq!(event.outcome, "pass");
    assert_eq!(event.error_code.as_deref(), Some("FE-ERR-001"));
    assert_eq!(event.timing_us, 999);
    assert_eq!(event.timestamp_unix_ms, 1_700_000_000_123);
}

#[test]
fn enrichment_event_without_error_code_has_none() {
    let ctx = make_ctx("sc", "fix", HarnessLane::Runtime, 1);
    let event = make_event(&ctx, 0);
    assert!(event.error_code.is_none());
}

#[test]
fn enrichment_event_serde_roundtrip_with_error_code() {
    let ctx = make_ctx("sc", "fix", HarnessLane::Runtime, 1);
    let event = ctx.event(EventInput {
        sequence: 0,
        component: "c",
        event: "e",
        outcome: "fail",
        error_code: Some("FE-PARSE-0001"),
        timing_us: 50,
        timestamp_unix_ms: 1_700_000_000_000,
    });
    let json = serde_json::to_string(&event).unwrap();
    let back: HarnessLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrichment_event_serde_roundtrip_without_error_code() {
    let ctx = make_ctx("sc", "fix", HarnessLane::Parser, 2);
    let event = make_event(&ctx, 3);
    let json = serde_json::to_string(&event).unwrap();
    let back: HarnessLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ── HarnessRunManifest ───────────────────────────────────────────────────

#[test]
fn enrichment_manifest_from_context_populates_schema_versions() {
    let ctx = make_ctx("sc", "fix", HarnessLane::E2e, 53);
    let manifest = make_manifest(&ctx, 2, 1);
    assert_eq!(
        manifest.schema_version,
        RGC_TEST_HARNESS_MANIFEST_SCHEMA_VERSION
    );
    assert_eq!(
        manifest.harness_schema_version,
        RGC_TEST_HARNESS_SCHEMA_VERSION
    );
}

#[test]
fn enrichment_manifest_from_context_inherits_context_fields() {
    let ctx = make_ctx("manifest-sc", "manifest-fix", HarnessLane::Governance, 88);
    let manifest = make_manifest(&ctx, 3, 2);
    assert_eq!(manifest.scenario_id, ctx.scenario_id);
    assert_eq!(manifest.fixture_id, ctx.fixture_id);
    assert_eq!(manifest.lane, ctx.lane);
    assert_eq!(manifest.seed, ctx.seed);
    assert_eq!(manifest.trace_id, ctx.trace_id);
    assert_eq!(manifest.decision_id, ctx.decision_id);
    assert_eq!(manifest.policy_id, ctx.policy_id);
}

#[test]
fn enrichment_manifest_env_fingerprint_deterministic_same_inputs() {
    let ctx = make_ctx("sc", "fix", HarnessLane::E2e, 53);
    let m1 = HarnessRunManifest::from_context(&ctx, "run-1", 2, 1, "replay.sh", 1_000);
    let m2 = HarnessRunManifest::from_context(&ctx, "run-1", 2, 1, "replay.sh", 2_000);
    assert_eq!(m1.env_fingerprint, m2.env_fingerprint);
}

#[test]
fn enrichment_manifest_env_fingerprint_changes_with_replay_command() {
    let ctx = make_ctx("sc", "fix", HarnessLane::E2e, 53);
    let m1 = HarnessRunManifest::from_context(&ctx, "run-1", 2, 1, "replay-a.sh", 1_000);
    let m2 = HarnessRunManifest::from_context(&ctx, "run-1", 2, 1, "replay-b.sh", 1_000);
    assert_ne!(m1.env_fingerprint, m2.env_fingerprint);
}

#[test]
fn enrichment_manifest_env_fingerprint_changes_with_seed() {
    let ctx_a = make_ctx("sc", "fix", HarnessLane::E2e, 1);
    let ctx_b = make_ctx("sc", "fix", HarnessLane::E2e, 2);
    let m1 = HarnessRunManifest::from_context(&ctx_a, "run-1", 2, 1, "replay.sh", 1_000);
    let m2 = HarnessRunManifest::from_context(&ctx_b, "run-1", 2, 1, "replay.sh", 1_000);
    assert_ne!(m1.env_fingerprint, m2.env_fingerprint);
}

#[test]
fn enrichment_manifest_env_fingerprint_is_hex_string() {
    let ctx = make_ctx("sc", "fix", HarnessLane::E2e, 53);
    let manifest = make_manifest(&ctx, 1, 1);
    assert!(!manifest.env_fingerprint.is_empty());
    assert!(
        manifest
            .env_fingerprint
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    );
}

#[test]
fn enrichment_manifest_serde_roundtrip() {
    let ctx = make_ctx("sc", "fix", HarnessLane::Security, 7);
    let manifest = make_manifest(&ctx, 5, 3);
    let json = serde_json::to_string(&manifest).unwrap();
    let back: HarnessRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

// ── FixtureLoadError ─────────────────────────────────────────────────────

#[test]
fn enrichment_fixture_load_error_display_unique_across_variants() {
    let errors = [
        FixtureLoadError::InvalidRelativePath {
            relative_path: "../escape".to_string(),
        },
        FixtureLoadError::IoRead {
            path: "/tmp/missing.json".to_string(),
            message: "not found".to_string(),
        },
        FixtureLoadError::JsonParse {
            path: "/tmp/bad.json".to_string(),
            message: "unexpected token".to_string(),
        },
    ];
    let display_set: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(display_set.len(), errors.len());
}

#[test]
fn enrichment_fixture_load_error_is_std_error() {
    let err = FixtureLoadError::InvalidRelativePath {
        relative_path: "..".to_string(),
    };
    let _: &dyn std::error::Error = &err;
}

#[test]
fn enrichment_fixture_load_error_invalid_path_display_contains_path() {
    let err = FixtureLoadError::InvalidRelativePath {
        relative_path: "../etc/passwd".to_string(),
    };
    assert!(err.to_string().contains("../etc/passwd"));
}

#[test]
fn enrichment_fixture_load_error_io_display_contains_path_and_message() {
    let err = FixtureLoadError::IoRead {
        path: "/data/fixtures/missing.json".to_string(),
        message: "permission denied".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("/data/fixtures/missing.json"));
    assert!(display.contains("permission denied"));
}

#[test]
fn enrichment_fixture_load_error_json_parse_display_contains_details() {
    let err = FixtureLoadError::JsonParse {
        path: "/data/fixtures/bad.json".to_string(),
        message: "expected `{`".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("/data/fixtures/bad.json"));
    assert!(display.contains("expected `{`"));
}

// ── ArtifactWriteError ───────────────────────────────────────────────────

#[test]
fn enrichment_artifact_write_error_display_unique() {
    let errors = [
        ArtifactWriteError::Io {
            path: "/a".to_string(),
            message: "io err".to_string(),
        },
        ArtifactWriteError::Json {
            path: "/b".to_string(),
            message: "json err".to_string(),
        },
    ];
    let display_set: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(display_set.len(), errors.len());
}

#[test]
fn enrichment_artifact_write_error_is_std_error() {
    let err = ArtifactWriteError::Io {
        path: "test".to_string(),
        message: "fail".to_string(),
    };
    let _: &dyn std::error::Error = &err;
}

#[test]
fn enrichment_artifact_write_error_io_display() {
    let err = ArtifactWriteError::Io {
        path: "/tmp/out.json".to_string(),
        message: "disk full".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("/tmp/out.json"));
    assert!(display.contains("disk full"));
}

#[test]
fn enrichment_artifact_write_error_json_display() {
    let err = ArtifactWriteError::Json {
        path: "/tmp/data.json".to_string(),
        message: "recursive".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("/tmp/data.json"));
    assert!(display.contains("recursive"));
}

// ── ArtifactValidationErrorCode serde ────────────────────────────────────

#[test]
fn enrichment_artifact_validation_error_code_serde_roundtrip_all() {
    for code in [
        ArtifactValidationErrorCode::MissingArtifact,
        ArtifactValidationErrorCode::InvalidManifestJson,
        ArtifactValidationErrorCode::InvalidEventJson,
        ArtifactValidationErrorCode::MissingRequiredField,
        ArtifactValidationErrorCode::CorrelationMismatch,
        ArtifactValidationErrorCode::CountMismatch,
        ArtifactValidationErrorCode::EmptyCommands,
    ] {
        let json = serde_json::to_string(&code).unwrap();
        let back: ArtifactValidationErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(code, back);
    }
}

// ── ArtifactBundleValidationErrorCode serde ──────────────────────────────

#[test]
fn enrichment_artifact_bundle_validation_error_code_serde_roundtrip_all() {
    for code in [
        ArtifactBundleValidationErrorCode::MissingBundleDirectory,
        ArtifactBundleValidationErrorCode::MissingRunDirectory,
        ArtifactBundleValidationErrorCode::InvalidManifest,
        ArtifactBundleValidationErrorCode::InvalidTriad,
        ArtifactBundleValidationErrorCode::DuplicateLane,
        ArtifactBundleValidationErrorCode::DuplicateRunId,
        ArtifactBundleValidationErrorCode::MissingRequiredLane,
        ArtifactBundleValidationErrorCode::CorrelationMismatch,
    ] {
        let json = serde_json::to_string(&code).unwrap();
        let back: ArtifactBundleValidationErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(code, back);
    }
}

// ── ArtifactValidationFinding serde ──────────────────────────────────────

#[test]
fn enrichment_artifact_validation_finding_serde_roundtrip() {
    let finding = ArtifactValidationFinding {
        component: "validator".to_string(),
        event: "validate".to_string(),
        outcome: "fail".to_string(),
        error_code: ArtifactValidationErrorCode::CountMismatch,
        message: "expected 5 got 3".to_string(),
    };
    let json = serde_json::to_string(&finding).unwrap();
    let back: ArtifactValidationFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding, back);
}

// ── ArtifactBundleValidationFinding serde ────────────────────────────────

#[test]
fn enrichment_artifact_bundle_validation_finding_serde_roundtrip() {
    let finding = ArtifactBundleValidationFinding {
        component: "bundle_validator".to_string(),
        event: "validate_bundle".to_string(),
        outcome: "fail".to_string(),
        error_code: ArtifactBundleValidationErrorCode::DuplicateLane,
        message: "dup".to_string(),
        owner_hint: "owner".to_string(),
        remediation_hint: "fix it".to_string(),
        repro_command: "cargo test".to_string(),
    };
    let json = serde_json::to_string(&finding).unwrap();
    let back: ArtifactBundleValidationFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding, back);
}

// ── ArtifactBundleCorrelationSignature serde ─────────────────────────────

#[test]
fn enrichment_artifact_bundle_correlation_signature_serde_roundtrip() {
    let sig = ArtifactBundleCorrelationSignature {
        scenario_id: "sig-test".to_string(),
        seed: 100,
        lanes: vec![
            HarnessLane::Parser,
            HarnessLane::Runtime,
            HarnessLane::Security,
        ],
    };
    let json = serde_json::to_string(&sig).unwrap();
    let back: ArtifactBundleCorrelationSignature = serde_json::from_str(&json).unwrap();
    assert_eq!(sig, back);
}

// ── ArtifactValidationReport serde ───────────────────────────────────────

#[test]
fn enrichment_artifact_validation_report_serde_roundtrip_valid() {
    let report = ArtifactValidationReport {
        schema_version: RGC_ARTIFACT_VALIDATOR_SCHEMA_VERSION.to_string(),
        component: "validator".to_string(),
        event: "validate".to_string(),
        outcome: "pass".to_string(),
        valid: true,
        run_id: Some("run-001".to_string()),
        trace_id: Some("trace-001".to_string()),
        decision_id: Some("dec-001".to_string()),
        policy_id: Some("pol-001".to_string()),
        findings: Vec::new(),
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: ArtifactValidationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn enrichment_artifact_validation_report_serde_roundtrip_with_findings() {
    let report = ArtifactValidationReport {
        schema_version: RGC_ARTIFACT_VALIDATOR_SCHEMA_VERSION.to_string(),
        component: "validator".to_string(),
        event: "validate".to_string(),
        outcome: "fail".to_string(),
        valid: false,
        run_id: None,
        trace_id: None,
        decision_id: None,
        policy_id: None,
        findings: vec![ArtifactValidationFinding {
            component: "validator".to_string(),
            event: "validate".to_string(),
            outcome: "fail".to_string(),
            error_code: ArtifactValidationErrorCode::MissingArtifact,
            message: "missing manifest".to_string(),
        }],
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: ArtifactValidationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ── ArtifactBundleValidationReport serde ─────────────────────────────────

#[test]
fn enrichment_artifact_bundle_validation_report_serde_roundtrip() {
    let report = ArtifactBundleValidationReport {
        schema_version: RGC_ARTIFACT_BUNDLE_VALIDATOR_SCHEMA_VERSION.to_string(),
        component: "bundle_validator".to_string(),
        event: "validate_bundle".to_string(),
        outcome: "pass".to_string(),
        valid: true,
        bundle_dir: "/tmp/bundle".to_string(),
        correlation_signature: Some(ArtifactBundleCorrelationSignature {
            scenario_id: "sc".to_string(),
            seed: 42,
            lanes: vec![HarnessLane::Runtime],
        }),
        run_dirs: vec!["/tmp/bundle/run-1".to_string()],
        lane_reports: Vec::new(),
        findings: Vec::new(),
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: ArtifactBundleValidationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ── BaselineE2eScenario & registry ───────────────────────────────────────

#[test]
fn enrichment_baseline_registry_contains_six_scenarios() {
    let registry = baseline_e2e_scenario_registry();
    assert_eq!(registry.len(), 6);
}

#[test]
fn enrichment_baseline_registry_all_use_e2e_lane() {
    let registry = baseline_e2e_scenario_registry();
    for scenario in &registry {
        assert_eq!(scenario.lane, HarnessLane::E2e);
    }
}

#[test]
fn enrichment_baseline_registry_sorted_by_scenario_id() {
    let registry = baseline_e2e_scenario_registry();
    let ids: Vec<&str> = registry.iter().map(|s| s.scenario_id.as_str()).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);
}

#[test]
fn enrichment_baseline_registry_failure_scenarios_have_error_codes() {
    let registry = baseline_e2e_scenario_registry();
    for scenario in &registry {
        if scenario.outcome == BaselineScenarioOutcome::CanonicalFailure {
            assert!(
                scenario.error_code.is_some(),
                "failure scenario {} must have an error_code",
                scenario.scenario_id
            );
        }
    }
}

#[test]
fn enrichment_baseline_registry_happy_scenarios_lack_error_codes() {
    let registry = baseline_e2e_scenario_registry();
    for scenario in &registry {
        if scenario.outcome == BaselineScenarioOutcome::HappyPath {
            assert!(
                scenario.error_code.is_none(),
                "happy scenario {} must not have an error_code",
                scenario.scenario_id
            );
        }
    }
}

#[test]
fn enrichment_baseline_registry_covers_all_three_domains() {
    let registry = baseline_e2e_scenario_registry();
    let domains: BTreeSet<BaselineScenarioDomain> = registry.iter().map(|s| s.domain).collect();
    assert!(domains.contains(&BaselineScenarioDomain::Runtime));
    assert!(domains.contains(&BaselineScenarioDomain::Module));
    assert!(domains.contains(&BaselineScenarioDomain::Security));
}

#[test]
fn enrichment_baseline_registry_each_domain_has_happy_and_failure() {
    let registry = baseline_e2e_scenario_registry();
    for domain in [
        BaselineScenarioDomain::Runtime,
        BaselineScenarioDomain::Module,
        BaselineScenarioDomain::Security,
    ] {
        let happy = registry
            .iter()
            .filter(|s| s.domain == domain && s.outcome == BaselineScenarioOutcome::HappyPath)
            .count();
        let fail = registry
            .iter()
            .filter(|s| {
                s.domain == domain && s.outcome == BaselineScenarioOutcome::CanonicalFailure
            })
            .count();
        assert_eq!(
            happy, 1,
            "domain {} should have exactly 1 happy path",
            domain
        );
        assert_eq!(
            fail, 1,
            "domain {} should have exactly 1 canonical failure",
            domain
        );
    }
}

#[test]
fn enrichment_baseline_e2e_scenario_serde_roundtrip_happy() {
    let registry = baseline_e2e_scenario_registry();
    let happy = registry
        .iter()
        .find(|s| s.outcome == BaselineScenarioOutcome::HappyPath)
        .unwrap();
    let json = serde_json::to_string(happy).unwrap();
    let back: BaselineE2eScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(*happy, back);
}

#[test]
fn enrichment_baseline_e2e_scenario_serde_roundtrip_failure() {
    let registry = baseline_e2e_scenario_registry();
    let fail = registry
        .iter()
        .find(|s| s.outcome == BaselineScenarioOutcome::CanonicalFailure)
        .unwrap();
    let json = serde_json::to_string(fail).unwrap();
    let back: BaselineE2eScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(*fail, back);
}

// ── select_baseline_e2e_scenarios ────────────────────────────────────────

#[test]
fn enrichment_select_scenarios_empty_domains_includes_all() {
    let all = select_baseline_e2e_scenarios(&[], true);
    assert_eq!(all.len(), 6);
}

#[test]
fn enrichment_select_scenarios_empty_domains_happy_only() {
    let happy = select_baseline_e2e_scenarios(&[], false);
    assert_eq!(happy.len(), 3);
    for s in &happy {
        assert_eq!(s.outcome, BaselineScenarioOutcome::HappyPath);
    }
}

#[test]
fn enrichment_select_scenarios_single_domain_with_failures() {
    let selected = select_baseline_e2e_scenarios(&[BaselineScenarioDomain::Module], true);
    assert_eq!(selected.len(), 2);
    for s in &selected {
        assert_eq!(s.domain, BaselineScenarioDomain::Module);
    }
}

#[test]
fn enrichment_select_scenarios_single_domain_happy_only() {
    let selected = select_baseline_e2e_scenarios(&[BaselineScenarioDomain::Security], false);
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].domain, BaselineScenarioDomain::Security);
    assert_eq!(selected[0].outcome, BaselineScenarioOutcome::HappyPath);
}

#[test]
fn enrichment_select_scenarios_is_deterministic() {
    let a = select_baseline_e2e_scenarios(
        &[
            BaselineScenarioDomain::Runtime,
            BaselineScenarioDomain::Security,
        ],
        true,
    );
    let b = select_baseline_e2e_scenarios(
        &[
            BaselineScenarioDomain::Runtime,
            BaselineScenarioDomain::Security,
        ],
        true,
    );
    assert_eq!(a, b);
}

#[test]
fn enrichment_select_scenarios_sorted_by_scenario_id() {
    let selected = select_baseline_e2e_scenarios(&[], true);
    let ids: Vec<&str> = selected.iter().map(|s| s.scenario_id.as_str()).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);
}

// ── load_json_fixture path traversal protection ──────────────────────────

#[test]
fn enrichment_load_fixture_rejects_parent_traversal() {
    let root = PathBuf::from("/tmp");
    let result = load_json_fixture::<TestFixture>(&root, "../escape.json");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, FixtureLoadError::InvalidRelativePath { .. }));
}

#[test]
fn enrichment_load_fixture_rejects_absolute_path() {
    let root = PathBuf::from("/tmp");
    let result = load_json_fixture::<TestFixture>(&root, "/etc/passwd");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, FixtureLoadError::InvalidRelativePath { .. }));
}

#[test]
fn enrichment_load_fixture_rejects_empty_path() {
    let root = PathBuf::from("/tmp");
    let result = load_json_fixture::<TestFixture>(&root, "");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, FixtureLoadError::InvalidRelativePath { .. }));
}

#[test]
fn enrichment_load_fixture_rejects_whitespace_only_path() {
    let root = PathBuf::from("/tmp");
    let result = load_json_fixture::<TestFixture>(&root, "   ");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, FixtureLoadError::InvalidRelativePath { .. }));
}

#[test]
fn enrichment_load_fixture_returns_io_error_for_missing_file() {
    let root = temp_dir("load_fixture_missing");
    fs::create_dir_all(&root).expect("create temp dir");
    let result = load_json_fixture::<TestFixture>(&root, "nonexistent.json");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, FixtureLoadError::IoRead { .. }));
}

#[test]
fn enrichment_load_fixture_returns_parse_error_for_invalid_json() {
    let root = temp_dir("load_fixture_bad_json");
    fs::create_dir_all(&root).expect("create temp dir");
    fs::write(root.join("bad.json"), "not-valid-json").expect("write bad fixture");
    let result = load_json_fixture::<TestFixture>(&root, "bad.json");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, FixtureLoadError::JsonParse { .. }));
}

#[test]
fn enrichment_load_fixture_succeeds_for_valid_json() {
    let root = temp_dir("load_fixture_valid");
    fs::create_dir_all(&root).expect("create temp dir");
    let fixture = TestFixture {
        name: "test".to_string(),
        value: 42,
    };
    fs::write(
        root.join("valid.json"),
        serde_json::to_string(&fixture).unwrap(),
    )
    .expect("write fixture");
    let loaded: TestFixture = load_json_fixture(&root, "valid.json").unwrap();
    assert_eq!(loaded, fixture);
}

// ── write_artifact_triad ─────────────────────────────────────────────────

#[test]
fn enrichment_write_triad_creates_three_files() {
    let root = temp_dir("write_triad_three_files");
    let ctx = make_ctx("write-test", "fix-1", HarnessLane::Parser, 9);
    let events = vec![make_event(&ctx, 0), make_event(&ctx, 1)];
    let commands = vec!["cargo check".to_string(), "cargo test".to_string()];
    let manifest = make_manifest(&ctx, 2, 2);
    let triad = write_artifact_triad(&root, &manifest, &events, &commands).unwrap();
    assert!(triad.manifest_path.exists());
    assert!(triad.events_path.exists());
    assert!(triad.commands_path.exists());
    assert!(triad.run_dir.is_dir());
}

#[test]
fn enrichment_write_triad_manifest_is_valid_json() {
    let root = temp_dir("write_triad_manifest_json");
    let ctx = make_ctx("json-check", "fix-1", HarnessLane::Runtime, 1);
    let events = vec![make_event(&ctx, 0)];
    let commands = vec!["cargo test".to_string()];
    let manifest = make_manifest(&ctx, 1, 1);
    let triad = write_artifact_triad(&root, &manifest, &events, &commands).unwrap();
    let raw = fs::read_to_string(&triad.manifest_path).unwrap();
    let parsed: HarnessRunManifest = serde_json::from_str(&raw).unwrap();
    assert_eq!(parsed, manifest);
}

#[test]
fn enrichment_write_triad_events_are_jsonl() {
    let root = temp_dir("write_triad_events_jsonl");
    let ctx = make_ctx("jsonl-check", "fix-1", HarnessLane::Security, 2);
    let events = vec![
        make_event(&ctx, 0),
        make_event(&ctx, 1),
        make_event(&ctx, 2),
    ];
    let commands = vec!["cargo test".to_string()];
    let manifest = make_manifest(&ctx, 3, 1);
    let triad = write_artifact_triad(&root, &manifest, &events, &commands).unwrap();
    let raw = fs::read_to_string(&triad.events_path).unwrap();
    let lines: Vec<&str> = raw.lines().collect();
    assert_eq!(lines.len(), 3);
    for (i, line) in lines.iter().enumerate() {
        let parsed: HarnessLogEvent = serde_json::from_str(line).unwrap();
        assert_eq!(parsed, events[i]);
    }
}

#[test]
fn enrichment_write_triad_commands_file_line_count_matches() {
    let root = temp_dir("write_triad_cmds_count");
    let ctx = make_ctx("cmd-count", "fix-1", HarnessLane::Governance, 3);
    let events = vec![make_event(&ctx, 0)];
    let commands = vec![
        "cargo check".to_string(),
        "cargo clippy".to_string(),
        "cargo test".to_string(),
    ];
    let manifest = make_manifest(&ctx, 1, 3);
    let triad = write_artifact_triad(&root, &manifest, &events, &commands).unwrap();
    let raw = fs::read_to_string(&triad.commands_path).unwrap();
    let non_empty_lines = raw.lines().filter(|l| !l.trim().is_empty()).count();
    assert_eq!(non_empty_lines, 3);
}

#[test]
fn enrichment_write_triad_zero_events_creates_empty_events_file() {
    let root = temp_dir("write_triad_zero_events");
    let ctx = make_ctx("zero-ev", "fix-1", HarnessLane::Parser, 1);
    let events: Vec<HarnessLogEvent> = Vec::new();
    let commands = vec!["cargo test".to_string()];
    let manifest = make_manifest(&ctx, 0, 1);
    let triad = write_artifact_triad(&root, &manifest, &events, &commands).unwrap();
    let raw = fs::read_to_string(&triad.events_path).unwrap();
    assert!(raw.trim().is_empty());
}

// ── validate_artifact_triad ──────────────────────────────────────────────

#[test]
fn enrichment_validate_triad_valid_roundtrip() {
    let root = temp_dir("validate_triad_ok");
    let ctx = make_ctx("validate-ok", "fix-1", HarnessLane::Runtime, 10);
    let events = vec![make_event(&ctx, 0)];
    let commands = vec!["cargo test".to_string()];
    let manifest = make_manifest(&ctx, 1, 1);
    let triad = write_artifact_triad(&root, &manifest, &events, &commands).unwrap();
    let report = validate_artifact_triad(&triad.run_dir);
    assert!(report.valid, "findings: {:?}", report.findings);
    assert!(report.findings.is_empty());
    assert_eq!(report.run_id.as_deref(), Some(manifest.run_id.as_str()));
    assert_eq!(report.trace_id.as_deref(), Some(manifest.trace_id.as_str()));
}

#[test]
fn enrichment_validate_triad_missing_all_three_files() {
    let root = temp_dir("validate_triad_empty");
    fs::create_dir_all(&root).expect("create dir");
    let report = validate_artifact_triad(&root);
    assert!(!report.valid);
    let missing: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.error_code == ArtifactValidationErrorCode::MissingArtifact)
        .collect();
    assert_eq!(missing.len(), 3);
}

#[test]
fn enrichment_validate_triad_event_count_mismatch() {
    let root = temp_dir("validate_triad_ev_mismatch");
    let ctx = make_ctx("ev-mm", "fix-1", HarnessLane::Runtime, 1);
    let events = vec![make_event(&ctx, 0)];
    let commands = vec!["cargo test".to_string()];
    // Manifest claims 5 events but only 1 written
    let manifest = HarnessRunManifest::from_context(
        &ctx,
        ctx.default_run_id(),
        5,
        1,
        "./replay.sh",
        1_700_500_000_000,
    );
    let triad = write_artifact_triad(&root, &manifest, &events, &commands).unwrap();
    let report = validate_artifact_triad(&triad.run_dir);
    assert!(!report.valid);
    assert!(
        report
            .findings
            .iter()
            .any(|f| { f.error_code == ArtifactValidationErrorCode::CountMismatch })
    );
}

#[test]
fn enrichment_validate_triad_command_count_mismatch() {
    let root = temp_dir("validate_triad_cmd_mismatch");
    let ctx = make_ctx("cmd-mm", "fix-1", HarnessLane::Runtime, 1);
    let events = vec![make_event(&ctx, 0)];
    let commands = vec!["cargo test".to_string()];
    // Manifest claims 10 commands but only 1 written
    let manifest = HarnessRunManifest::from_context(
        &ctx,
        ctx.default_run_id(),
        1,
        10,
        "./replay.sh",
        1_700_500_000_000,
    );
    let triad = write_artifact_triad(&root, &manifest, &events, &commands).unwrap();
    let report = validate_artifact_triad(&triad.run_dir);
    assert!(!report.valid);
    assert!(report.findings.iter().any(|f| {
        f.error_code == ArtifactValidationErrorCode::CountMismatch
            && f.message.contains("command count")
    }));
}

#[test]
fn enrichment_validate_triad_detects_trace_id_correlation_mismatch() {
    let root = temp_dir("validate_triad_corr_trace");
    let ctx = make_ctx("corr-test", "fix-1", HarnessLane::Runtime, 77);
    let mut event = make_event(&ctx, 0);
    event.trace_id = "trace-rgc-WRONG".to_string();
    let events = vec![event];
    let commands = vec!["cargo test".to_string()];
    let manifest = make_manifest(&ctx, 1, 1);
    let triad = write_artifact_triad(&root, &manifest, &events, &commands).unwrap();
    let report = validate_artifact_triad(&triad.run_dir);
    assert!(!report.valid);
    assert!(report.findings.iter().any(|f| {
        f.error_code == ArtifactValidationErrorCode::CorrelationMismatch
            && f.message.contains("trace_id mismatch")
    }));
}

#[test]
fn enrichment_validate_triad_detects_decision_id_correlation_mismatch() {
    let root = temp_dir("validate_triad_corr_decision");
    let ctx = make_ctx("corr-dec", "fix-1", HarnessLane::Runtime, 77);
    let mut event = make_event(&ctx, 0);
    event.decision_id = "decision-rgc-WRONG".to_string();
    let events = vec![event];
    let commands = vec!["cargo test".to_string()];
    let manifest = make_manifest(&ctx, 1, 1);
    let triad = write_artifact_triad(&root, &manifest, &events, &commands).unwrap();
    let report = validate_artifact_triad(&triad.run_dir);
    assert!(!report.valid);
    assert!(report.findings.iter().any(|f| {
        f.error_code == ArtifactValidationErrorCode::CorrelationMismatch
            && f.message.contains("decision_id mismatch")
    }));
}

#[test]
fn enrichment_validate_triad_detects_policy_id_correlation_mismatch() {
    let root = temp_dir("validate_triad_corr_policy");
    let ctx = make_ctx("corr-pol", "fix-1", HarnessLane::Runtime, 77);
    let mut event = make_event(&ctx, 0);
    event.policy_id = "policy-rgc-WRONG".to_string();
    let events = vec![event];
    let commands = vec!["cargo test".to_string()];
    let manifest = make_manifest(&ctx, 1, 1);
    let triad = write_artifact_triad(&root, &manifest, &events, &commands).unwrap();
    let report = validate_artifact_triad(&triad.run_dir);
    assert!(!report.valid);
    assert!(report.findings.iter().any(|f| {
        f.error_code == ArtifactValidationErrorCode::CorrelationMismatch
            && f.message.contains("policy_id mismatch")
    }));
}

#[test]
fn enrichment_validate_triad_detects_seed_correlation_mismatch() {
    let root = temp_dir("validate_triad_corr_seed");
    let ctx = make_ctx("corr-seed", "fix-1", HarnessLane::Runtime, 77);
    let mut event = make_event(&ctx, 0);
    event.seed = 999;
    let events = vec![event];
    let commands = vec!["cargo test".to_string()];
    let manifest = make_manifest(&ctx, 1, 1);
    let triad = write_artifact_triad(&root, &manifest, &events, &commands).unwrap();
    let report = validate_artifact_triad(&triad.run_dir);
    assert!(!report.valid);
    assert!(report.findings.iter().any(|f| {
        f.error_code == ArtifactValidationErrorCode::CorrelationMismatch
            && f.message.contains("seed mismatch")
    }));
}

#[test]
fn enrichment_validate_triad_empty_commands_detected() {
    let root = temp_dir("validate_triad_empty_cmds");
    let ctx = make_ctx("empty-cmd", "fix-1", HarnessLane::Runtime, 1);
    let events = vec![make_event(&ctx, 0)];
    let manifest = make_manifest(&ctx, 1, 0);
    // Manually write triad with empty commands
    let run_dir = root.join(&manifest.run_id);
    fs::create_dir_all(&run_dir).expect("create run dir");
    let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();
    fs::write(run_dir.join("run_manifest.json"), &manifest_json).unwrap();
    let event_line = serde_json::to_string(&events[0]).unwrap();
    fs::write(run_dir.join("events.jsonl"), format!("{event_line}\n")).unwrap();
    fs::write(run_dir.join("commands.txt"), "\n").unwrap();

    let report = validate_artifact_triad(&run_dir);
    assert!(!report.valid);
    assert!(
        report
            .findings
            .iter()
            .any(|f| { f.error_code == ArtifactValidationErrorCode::EmptyCommands })
    );
}

#[test]
fn enrichment_validate_triad_invalid_event_json() {
    let root = temp_dir("validate_triad_bad_event");
    let ctx = make_ctx("bad-event", "fix-1", HarnessLane::Runtime, 1);
    let manifest = make_manifest(&ctx, 1, 1);
    let run_dir = root.join(&manifest.run_id);
    fs::create_dir_all(&run_dir).expect("create run dir");
    let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();
    fs::write(run_dir.join("run_manifest.json"), &manifest_json).unwrap();
    fs::write(run_dir.join("events.jsonl"), "{not-valid-json}\n").unwrap();
    fs::write(run_dir.join("commands.txt"), "cargo test\n").unwrap();

    let report = validate_artifact_triad(&run_dir);
    assert!(!report.valid);
    assert!(
        report
            .findings
            .iter()
            .any(|f| { f.error_code == ArtifactValidationErrorCode::InvalidEventJson })
    );
}

// ── validate_artifact_bundle ─────────────────────────────────────────────

#[test]
fn enrichment_validate_bundle_valid_multi_lane() {
    let root = temp_dir("validate_bundle_valid_multi");
    let bundle_dir = root.join("bundle");
    fs::create_dir_all(&bundle_dir).expect("create bundle dir");
    for lane in [
        HarnessLane::Runtime,
        HarnessLane::Security,
        HarnessLane::E2e,
    ] {
        write_lane_triad(&bundle_dir, "rgc-enrich-happy", "fixture-shared", lane, 42);
    }
    let report = validate_artifact_bundle(
        &bundle_dir,
        &[
            HarnessLane::Runtime,
            HarnessLane::Security,
            HarnessLane::E2e,
        ],
    );
    assert!(report.valid, "findings: {:?}", report.findings);
    assert_eq!(report.lane_reports.len(), 3);
    let sig = report.correlation_signature.expect("should have signature");
    assert_eq!(sig.scenario_id, "rgc-enrich-happy");
    assert_eq!(sig.seed, 42);
    assert_eq!(sig.lanes.len(), 3);
}

#[test]
fn enrichment_validate_bundle_nonexistent_directory() {
    let report = validate_artifact_bundle(
        "/tmp/franken_engine_nonexistent_dir_enrichment_test",
        &[HarnessLane::Runtime],
    );
    assert!(!report.valid);
    assert!(
        report
            .findings
            .iter()
            .any(|f| { f.error_code == ArtifactBundleValidationErrorCode::MissingBundleDirectory })
    );
}

#[test]
fn enrichment_validate_bundle_empty_directory() {
    let root = temp_dir("validate_bundle_empty");
    fs::create_dir_all(&root).expect("create dir");
    let report = validate_artifact_bundle(&root, &[HarnessLane::Runtime]);
    assert!(!report.valid);
    assert!(
        report
            .findings
            .iter()
            .any(|f| { f.error_code == ArtifactBundleValidationErrorCode::MissingRunDirectory })
    );
}

#[test]
fn enrichment_validate_bundle_missing_required_lane() {
    let root = temp_dir("validate_bundle_missing_lane");
    let bundle_dir = root.join("bundle");
    fs::create_dir_all(&bundle_dir).expect("create bundle dir");
    write_lane_triad(
        &bundle_dir,
        "rgc-missing-lane",
        "fixture-shared",
        HarnessLane::Runtime,
        1,
    );
    let report =
        validate_artifact_bundle(&bundle_dir, &[HarnessLane::Runtime, HarnessLane::Security]);
    assert!(!report.valid);
    assert!(
        report
            .findings
            .iter()
            .any(|f| { f.error_code == ArtifactBundleValidationErrorCode::MissingRequiredLane })
    );
}

#[test]
fn enrichment_validate_bundle_duplicate_lane() {
    let root = temp_dir("validate_bundle_dup_lane");
    let bundle_dir = root.join("bundle");
    fs::create_dir_all(&bundle_dir).expect("create bundle dir");
    write_lane_triad(
        &bundle_dir,
        "rgc-dup-lane",
        "fix-a",
        HarnessLane::Runtime,
        1,
    );
    write_lane_triad(
        &bundle_dir,
        "rgc-dup-lane",
        "fix-b",
        HarnessLane::Runtime,
        1,
    );
    let report = validate_artifact_bundle(&bundle_dir, &[HarnessLane::Runtime]);
    assert!(!report.valid);
    assert!(
        report
            .findings
            .iter()
            .any(|f| { f.error_code == ArtifactBundleValidationErrorCode::DuplicateLane })
    );
}

#[test]
fn enrichment_validate_bundle_cross_lane_seed_mismatch() {
    let root = temp_dir("validate_bundle_seed_mm");
    let bundle_dir = root.join("bundle");
    fs::create_dir_all(&bundle_dir).expect("create bundle dir");
    write_lane_triad(&bundle_dir, "rgc-seed-mm", "fix", HarnessLane::Runtime, 100);
    write_lane_triad(
        &bundle_dir,
        "rgc-seed-mm",
        "fix",
        HarnessLane::Security,
        200,
    );
    let report =
        validate_artifact_bundle(&bundle_dir, &[HarnessLane::Runtime, HarnessLane::Security]);
    assert!(!report.valid);
    assert!(report.findings.iter().any(|f| {
        f.error_code == ArtifactBundleValidationErrorCode::CorrelationMismatch
            && f.message.contains("seed mismatch")
    }));
}

#[test]
fn enrichment_validate_bundle_cross_lane_scenario_mismatch() {
    let root = temp_dir("validate_bundle_scenario_mm");
    let bundle_dir = root.join("bundle");
    fs::create_dir_all(&bundle_dir).expect("create bundle dir");
    write_lane_triad(
        &bundle_dir,
        "scenario-alpha",
        "fix",
        HarnessLane::Runtime,
        42,
    );
    write_lane_triad(
        &bundle_dir,
        "scenario-beta",
        "fix",
        HarnessLane::Security,
        42,
    );
    let report =
        validate_artifact_bundle(&bundle_dir, &[HarnessLane::Runtime, HarnessLane::Security]);
    assert!(!report.valid);
    assert!(report.findings.iter().any(|f| {
        f.error_code == ArtifactBundleValidationErrorCode::CorrelationMismatch
            && f.message.contains("scenario mismatch")
    }));
}

#[test]
fn enrichment_validate_bundle_no_required_lanes_accepts_any() {
    let root = temp_dir("validate_bundle_no_req");
    let bundle_dir = root.join("bundle");
    fs::create_dir_all(&bundle_dir).expect("create bundle dir");
    write_lane_triad(&bundle_dir, "rgc-no-req", "fix", HarnessLane::Parser, 1);
    let report = validate_artifact_bundle(&bundle_dir, &[]);
    assert!(report.valid, "findings: {:?}", report.findings);
}

#[test]
fn enrichment_validate_bundle_path_is_file_not_directory() {
    let root = temp_dir("validate_bundle_file_path");
    fs::create_dir_all(&root).expect("create dir");
    let file_path = root.join("not_a_dir");
    fs::write(&file_path, "data").expect("write file");
    let report = validate_artifact_bundle(&file_path, &[]);
    assert!(!report.valid);
    assert!(
        report
            .findings
            .iter()
            .any(|f| { f.error_code == ArtifactBundleValidationErrorCode::MissingBundleDirectory })
    );
}

#[test]
fn enrichment_validate_bundle_report_schema_version() {
    let root = temp_dir("validate_bundle_schema_ver");
    let bundle_dir = root.join("bundle");
    fs::create_dir_all(&bundle_dir).expect("create bundle dir");
    write_lane_triad(&bundle_dir, "rgc-schema", "fix", HarnessLane::Runtime, 1);
    let report = validate_artifact_bundle(&bundle_dir, &[]);
    assert_eq!(
        report.schema_version,
        RGC_ARTIFACT_BUNDLE_VALIDATOR_SCHEMA_VERSION
    );
    assert_eq!(report.component, "rgc_artifact_bundle_validator");
    assert_eq!(report.event, "validate_artifact_bundle");
}

// ── cross-cutting: end-to-end write->validate->bundle lifecycle ──────────

#[test]
fn enrichment_full_lifecycle_write_validate_triad_then_bundle() {
    let root = temp_dir("lifecycle_full");
    let bundle_dir = root.join("bundle");
    fs::create_dir_all(&bundle_dir).expect("create bundle dir");

    for lane in [
        HarnessLane::Parser,
        HarnessLane::Runtime,
        HarnessLane::Security,
    ] {
        let ctx = make_ctx("rgc-lifecycle", "fixture-lifecycle", lane, 777);
        let events: Vec<HarnessLogEvent> = (0..3).map(|i| make_event(&ctx, i)).collect();
        let commands = vec!["cargo check".to_string(), "cargo test".to_string()];
        let manifest = make_manifest(&ctx, 3, 2);
        let triad = write_artifact_triad(&bundle_dir, &manifest, &events, &commands).unwrap();

        // Validate each triad individually
        let triad_report = validate_artifact_triad(&triad.run_dir);
        assert!(
            triad_report.valid,
            "triad for lane {} failed: {:?}",
            lane, triad_report.findings
        );
    }

    // Now validate the bundle
    let bundle_report = validate_artifact_bundle(
        &bundle_dir,
        &[
            HarnessLane::Parser,
            HarnessLane::Runtime,
            HarnessLane::Security,
        ],
    );
    assert!(
        bundle_report.valid,
        "bundle validation failed: {:?}",
        bundle_report.findings
    );
    assert_eq!(bundle_report.lane_reports.len(), 3);
    let sig = bundle_report.correlation_signature.unwrap();
    assert_eq!(sig.scenario_id, "rgc-lifecycle");
    assert_eq!(sig.seed, 777);
    assert_eq!(sig.lanes.len(), 3);
}

#[test]
fn enrichment_triad_validator_report_schema_version_correct() {
    let root = temp_dir("triad_report_schema");
    let ctx = make_ctx("schema-check", "fix-1", HarnessLane::Runtime, 1);
    let events = vec![make_event(&ctx, 0)];
    let commands = vec!["cargo test".to_string()];
    let manifest = make_manifest(&ctx, 1, 1);
    let triad = write_artifact_triad(&root, &manifest, &events, &commands).unwrap();
    let report = validate_artifact_triad(&triad.run_dir);
    assert_eq!(report.schema_version, RGC_ARTIFACT_VALIDATOR_SCHEMA_VERSION);
    assert_eq!(report.component, "rgc_artifact_validator");
    assert_eq!(report.event, "validate_artifact_triad");
}

#[test]
fn enrichment_triad_validator_valid_report_has_pass_outcome() {
    let root = temp_dir("triad_pass_outcome");
    let ctx = make_ctx("pass-outcome", "fix-1", HarnessLane::Runtime, 1);
    let events = vec![make_event(&ctx, 0)];
    let commands = vec!["cargo test".to_string()];
    let manifest = make_manifest(&ctx, 1, 1);
    let triad = write_artifact_triad(&root, &manifest, &events, &commands).unwrap();
    let report = validate_artifact_triad(&triad.run_dir);
    assert!(report.valid);
    assert_eq!(report.outcome, "pass");
}

#[test]
fn enrichment_triad_validator_invalid_report_has_fail_outcome() {
    let root = temp_dir("triad_fail_outcome");
    fs::create_dir_all(&root).expect("create dir");
    let report = validate_artifact_triad(&root);
    assert!(!report.valid);
    assert_eq!(report.outcome, "fail");
}

// ── cross-cutting: corrupted manifest in bundle ──────────────────────────

#[test]
fn enrichment_bundle_with_corrupted_trace_id_fails_correlation() {
    let root = temp_dir("bundle_corrupt_trace");
    let bundle_dir = root.join("bundle");
    fs::create_dir_all(&bundle_dir).expect("create bundle dir");

    let triad_ok = write_lane_triad(&bundle_dir, "rgc-corrupt", "fix", HarnessLane::Runtime, 50);
    let triad_bad = write_lane_triad(&bundle_dir, "rgc-corrupt", "fix", HarnessLane::Security, 50);

    // Corrupt the security manifest's trace_id
    let manifest_path = triad_bad.run_dir.join("run_manifest.json");
    let raw = fs::read_to_string(&manifest_path).unwrap();
    let mut manifest: HarnessRunManifest = serde_json::from_str(&raw).unwrap();
    manifest.trace_id = "trace-rgc-corrupted".to_string();
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    // Also update events to match corrupted trace (so triad-level stays consistent)
    let events_path = triad_bad.run_dir.join("events.jsonl");
    let events_raw = fs::read_to_string(&events_path).unwrap();
    let mut rewritten = String::new();
    for line in events_raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut event: HarnessLogEvent = serde_json::from_str(line).unwrap();
        event.trace_id = "trace-rgc-corrupted".to_string();
        rewritten.push_str(&serde_json::to_string(&event).unwrap());
        rewritten.push('\n');
    }
    fs::write(&events_path, rewritten).unwrap();

    let report =
        validate_artifact_bundle(&bundle_dir, &[HarnessLane::Runtime, HarnessLane::Security]);
    assert!(!report.valid);
    // Individual triads should still be self-consistent
    assert!(report.lane_reports.iter().all(|r| r.valid));
    // But bundle-level correlation should detect the mismatch
    assert!(report.findings.iter().any(|f| {
        f.error_code == ArtifactBundleValidationErrorCode::CorrelationMismatch
            && f.message.contains("non-deterministic trace_id")
    }));

    // Verify the ok triad was not affected
    let ok_report = validate_artifact_triad(&triad_ok.run_dir);
    assert!(ok_report.valid);
}

// ── schema version constants ─────────────────────────────────────────────

#[test]
fn enrichment_schema_version_constants_are_non_empty() {
    assert!(!RGC_TEST_HARNESS_SCHEMA_VERSION.is_empty());
    assert!(!RGC_TEST_HARNESS_EVENT_SCHEMA_VERSION.is_empty());
    assert!(!RGC_TEST_HARNESS_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(!RGC_BASELINE_E2E_SCENARIO_SCHEMA_VERSION.is_empty());
    assert!(!RGC_ARTIFACT_VALIDATOR_SCHEMA_VERSION.is_empty());
    assert!(!RGC_ARTIFACT_BUNDLE_VALIDATOR_SCHEMA_VERSION.is_empty());
}

#[test]
fn enrichment_schema_version_constants_are_all_unique() {
    let versions: BTreeSet<&str> = [
        RGC_TEST_HARNESS_SCHEMA_VERSION,
        RGC_TEST_HARNESS_EVENT_SCHEMA_VERSION,
        RGC_TEST_HARNESS_MANIFEST_SCHEMA_VERSION,
        RGC_BASELINE_E2E_SCENARIO_SCHEMA_VERSION,
        RGC_ARTIFACT_VALIDATOR_SCHEMA_VERSION,
        RGC_ARTIFACT_BUNDLE_VALIDATOR_SCHEMA_VERSION,
    ]
    .into_iter()
    .collect();
    assert_eq!(versions.len(), 6);
}

#[test]
fn enrichment_schema_version_constants_contain_franken_engine_prefix() {
    for version in [
        RGC_TEST_HARNESS_SCHEMA_VERSION,
        RGC_TEST_HARNESS_EVENT_SCHEMA_VERSION,
        RGC_TEST_HARNESS_MANIFEST_SCHEMA_VERSION,
        RGC_BASELINE_E2E_SCENARIO_SCHEMA_VERSION,
        RGC_ARTIFACT_VALIDATOR_SCHEMA_VERSION,
        RGC_ARTIFACT_BUNDLE_VALIDATOR_SCHEMA_VERSION,
    ] {
        assert!(
            version.starts_with("franken-engine."),
            "schema version `{version}` must start with `franken-engine.`"
        );
    }
}

// ── cross-cutting: multiple events maintain correlation ──────────────────

#[test]
fn enrichment_multiple_events_all_share_context_correlation_ids() {
    let ctx = make_ctx("multi-ev", "fix-multi", HarnessLane::Security, 99);
    let events: Vec<HarnessLogEvent> = (0..10)
        .map(|i| {
            ctx.event(EventInput {
                sequence: i,
                component: &format!("comp-{i}"),
                event: &format!("evt-{i}"),
                outcome: if i % 2 == 0 { "pass" } else { "fail" },
                error_code: if i % 3 == 0 { Some("FE-ERR") } else { None },
                timing_us: i * 100,
                timestamp_unix_ms: 1_700_000_000_000 + i,
            })
        })
        .collect();

    for event in &events {
        assert_eq!(event.trace_id, ctx.trace_id);
        assert_eq!(event.decision_id, ctx.decision_id);
        assert_eq!(event.policy_id, ctx.policy_id);
        assert_eq!(event.seed, ctx.seed);
        assert_eq!(event.lane, ctx.lane);
    }
}

#[test]
fn enrichment_events_sequence_numbers_are_independent() {
    let ctx = make_ctx("seq-test", "fix", HarnessLane::Parser, 1);
    let e0 = make_event(&ctx, 0);
    let e99 = make_event(&ctx, 99);
    assert_eq!(e0.sequence, 0);
    assert_eq!(e99.sequence, 99);
}

// ── cross-cutting: five-lane bundle with all harness lanes ───────────────

#[test]
fn enrichment_five_lane_bundle_validates_with_all_lanes_required() {
    let root = temp_dir("five_lane_bundle");
    let bundle_dir = root.join("bundle");
    fs::create_dir_all(&bundle_dir).expect("create bundle dir");

    for lane in [
        HarnessLane::Parser,
        HarnessLane::Runtime,
        HarnessLane::Security,
        HarnessLane::Governance,
        HarnessLane::E2e,
    ] {
        write_lane_triad(&bundle_dir, "rgc-five-lane", "fixture-all", lane, 555);
    }

    let report = validate_artifact_bundle(
        &bundle_dir,
        &[
            HarnessLane::Parser,
            HarnessLane::Runtime,
            HarnessLane::Security,
            HarnessLane::Governance,
            HarnessLane::E2e,
        ],
    );
    assert!(report.valid, "findings: {:?}", report.findings);
    assert_eq!(report.lane_reports.len(), 5);
    let sig = report.correlation_signature.unwrap();
    assert_eq!(sig.lanes.len(), 5);
    assert_eq!(sig.seed, 555);
}

// ── cross-cutting: manifest generated_at_unix_ms does not affect fingerprint ──

#[test]
fn enrichment_manifest_generated_at_does_not_affect_fingerprint() {
    let ctx = make_ctx("fp-test", "fix", HarnessLane::E2e, 1);
    let m1 = HarnessRunManifest::from_context(&ctx, "run-1", 1, 1, "replay.sh", 1_000_000);
    let m2 = HarnessRunManifest::from_context(&ctx, "run-1", 1, 1, "replay.sh", 9_999_999);
    assert_eq!(m1.env_fingerprint, m2.env_fingerprint);
    assert_eq!(m1.generated_at_unix_ms, 1_000_000);
    assert_eq!(m2.generated_at_unix_ms, 9_999_999);
}

// ── cross-cutting: write then validate bundle with varying event counts ──

#[test]
fn enrichment_lanes_with_varying_event_counts_validate() {
    let root = temp_dir("varying_event_counts");
    let bundle_dir = root.join("bundle");
    fs::create_dir_all(&bundle_dir).expect("create bundle dir");

    for (lane, event_count) in [
        (HarnessLane::Parser, 0_usize),
        (HarnessLane::Runtime, 5),
        (HarnessLane::Security, 1),
    ] {
        let ctx = make_ctx("rgc-vary", "fix-vary", lane, 42);
        let events: Vec<HarnessLogEvent> = (0..event_count as u64)
            .map(|i| make_event(&ctx, i))
            .collect();
        let commands = vec!["cargo test".to_string()];
        let manifest = HarnessRunManifest::from_context(
            &ctx,
            ctx.default_run_id(),
            event_count,
            1,
            "./replay.sh",
            1_700_500_000_000,
        );
        write_artifact_triad(&bundle_dir, &manifest, &events, &commands).unwrap();
    }

    let report = validate_artifact_bundle(
        &bundle_dir,
        &[
            HarnessLane::Parser,
            HarnessLane::Runtime,
            HarnessLane::Security,
        ],
    );
    assert!(report.valid, "findings: {:?}", report.findings);
}
