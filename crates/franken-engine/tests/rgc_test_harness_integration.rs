#![forbid(unsafe_code)]
//! Integration tests for shared deterministic RGC test harness utilities.

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

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::rgc_test_harness::{
    ArtifactBundleCorrelationSignature, ArtifactBundleValidationErrorCode,
    ArtifactBundleValidationFinding, ArtifactBundleValidationReport, ArtifactValidationErrorCode,
    ArtifactValidationFinding, ArtifactValidationReport, ArtifactWriteError, BaselineE2eScenario,
    BaselineScenarioDomain, BaselineScenarioOutcome, DeterministicTestContext, EventInput,
    FixtureLoadError, HarnessLane, HarnessLogEvent, HarnessRunManifest,
    RGC_ARTIFACT_BUNDLE_VALIDATOR_SCHEMA_VERSION, RGC_ARTIFACT_VALIDATOR_SCHEMA_VERSION,
    RGC_BASELINE_E2E_SCENARIO_SCHEMA_VERSION, RGC_TEST_HARNESS_EVENT_SCHEMA_VERSION,
    RGC_TEST_HARNESS_MANIFEST_SCHEMA_VERSION, RGC_TEST_HARNESS_SCHEMA_VERSION,
    baseline_e2e_scenario_registry, load_json_fixture, select_baseline_e2e_scenarios,
    validate_artifact_bundle, validate_artifact_triad, write_artifact_triad,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DemoFixture {
    scenario_id: String,
    expected_lane: String,
}

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock drift")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "franken_engine_{label}_{nanos}_{}",
        std::process::id()
    ))
}

#[test]
fn rgc_harness_event_contains_required_correlation_keys() {
    let context = DeterministicTestContext::new(
        "rgc-052-runtime-smoke",
        "fixture-runtime-smoke",
        HarnessLane::Runtime,
        77,
    );
    let event = context.event(EventInput {
        sequence: 3,
        component: "runtime_lane",
        event: "execute",
        outcome: "pass",
        error_code: None,
        timing_us: 105,
        timestamp_unix_ms: 1_700_000_100_123,
    });

    assert_eq!(
        event.schema_version, RGC_TEST_HARNESS_EVENT_SCHEMA_VERSION,
        "event schema must stay stable for downstream validators"
    );
    assert_eq!(event.scenario_id, "rgc-052-runtime-smoke");
    assert_eq!(event.fixture_id, "fixture-runtime-smoke");
    assert_eq!(event.trace_id, context.trace_id);
    assert_eq!(event.decision_id, context.decision_id);
    assert_eq!(event.policy_id, context.policy_id);
    assert_eq!(event.seed, 77);
}

#[test]
fn rgc_harness_fixture_load_and_artifact_triad_round_trip() {
    let root = temp_dir("rgc_harness_roundtrip");
    let fixtures_root = root.join("fixtures");
    fs::create_dir_all(&fixtures_root).expect("create fixture root");

    let fixture_path = fixtures_root.join("runtime_smoke.json");
    fs::write(
        &fixture_path,
        r#"{"scenario_id":"rgc-052-runtime-smoke","expected_lane":"runtime"}"#,
    )
    .expect("write fixture");

    let fixture: DemoFixture = load_json_fixture(&fixtures_root, "runtime_smoke.json")
        .expect("fixture loader should parse deterministic JSON fixture");
    assert_eq!(fixture.scenario_id, "rgc-052-runtime-smoke");
    assert_eq!(fixture.expected_lane, "runtime");

    let context = DeterministicTestContext::new(
        fixture.scenario_id.clone(),
        "runtime_smoke",
        HarnessLane::Runtime,
        7,
    );
    let run_id = context.default_run_id();

    let events = vec![
        context.event(EventInput {
            sequence: 0,
            component: "fixture_loader",
            event: "fixture_loaded",
            outcome: "pass",
            error_code: None,
            timing_us: 40,
            timestamp_unix_ms: 1_700_000_200_010,
        }),
        context.event(EventInput {
            sequence: 1,
            component: "runtime_lane",
            event: "semantic_assertions_complete",
            outcome: "pass",
            error_code: None,
            timing_us: 90,
            timestamp_unix_ms: 1_700_000_200_100,
        }),
    ];
    let commands = vec![
        "cargo check -p frankenengine-engine --test rgc_test_harness_integration".to_string(),
        "cargo test -p frankenengine-engine --test rgc_test_harness_integration".to_string(),
    ];
    let manifest = HarnessRunManifest::from_context(
        &context,
        run_id,
        events.len(),
        commands.len(),
        "./scripts/e2e/rgc_test_harness_replay.sh ci",
        1_700_000_200_500,
    );

    let artifacts_root = root.join("artifacts");
    let triad = write_artifact_triad(&artifacts_root, &manifest, &events, &commands)
        .expect("artifact triad should be emitted");
    assert!(triad.manifest_path.exists());
    assert!(triad.events_path.exists());
    assert!(triad.commands_path.exists());

    let saved_manifest: HarnessRunManifest = serde_json::from_str(
        &fs::read_to_string(&triad.manifest_path).expect("read saved manifest"),
    )
    .expect("parse saved manifest");
    assert_eq!(
        saved_manifest.schema_version,
        RGC_TEST_HARNESS_MANIFEST_SCHEMA_VERSION
    );
    assert_eq!(saved_manifest.event_count, 2);
    assert_eq!(saved_manifest.command_count, 2);
}

#[test]
fn rgc_harness_fixture_loader_rejects_escape_paths() {
    let fixtures_root = temp_dir("rgc_harness_escape");
    fs::create_dir_all(&fixtures_root).expect("create fixture root");

    let error = load_json_fixture::<DemoFixture>(&fixtures_root, "../secrets.json")
        .expect_err("escape path must fail");
    let message = error.to_string();
    assert!(
        message.contains("must not escape root"),
        "unexpected error message: {message}"
    );
}

#[test]
fn rgc_baseline_registry_selection_and_validator_cover_representative_lanes() {
    let registry = baseline_e2e_scenario_registry();
    assert_eq!(
        registry.len(),
        6,
        "expected runtime/module/security happy+failure"
    );
    assert!(registry.iter().any(|scenario| {
        scenario.domain == BaselineScenarioDomain::Runtime
            && scenario.outcome == BaselineScenarioOutcome::CanonicalFailure
    }));
    assert!(registry.iter().any(|scenario| {
        scenario.domain == BaselineScenarioDomain::Module
            && scenario.outcome == BaselineScenarioOutcome::HappyPath
    }));
    assert!(registry.iter().any(|scenario| {
        scenario.domain == BaselineScenarioDomain::Security
            && scenario.outcome == BaselineScenarioOutcome::CanonicalFailure
    }));

    let selected = select_baseline_e2e_scenarios(
        &[
            BaselineScenarioDomain::Runtime,
            BaselineScenarioDomain::Security,
        ],
        true,
    );
    assert_eq!(selected.len(), 4);
    let selected_repeat = select_baseline_e2e_scenarios(
        &[
            BaselineScenarioDomain::Runtime,
            BaselineScenarioDomain::Security,
        ],
        true,
    );
    assert_eq!(
        selected, selected_repeat,
        "selection order must be deterministic"
    );

    let root = temp_dir("rgc_baseline_validator");
    for (lane, scenario_id, fixture_id, component, event, error_code) in [
        (
            HarnessLane::Runtime,
            "rgc-053a-runtime-happy",
            "runtime-smoke-happy",
            "runtime_lane",
            "execute_runtime_smoke",
            None,
        ),
        (
            HarnessLane::Security,
            "rgc-053a-security-failure",
            "security-smoke-failure",
            "security_guardplane",
            "containment_triggered",
            Some("FE-RGC-053A-SECURITY-0001"),
        ),
        (
            HarnessLane::E2e,
            "rgc-053a-module-happy",
            "module-smoke-happy",
            "module_loader",
            "resolve_graph",
            None,
        ),
    ] {
        let context = DeterministicTestContext::new(scenario_id, fixture_id, lane, 53);
        let run_id = context.default_run_id();
        let events = vec![context.event(EventInput {
            sequence: 0,
            component,
            event,
            outcome: if error_code.is_some() { "fail" } else { "pass" },
            error_code,
            timing_us: 77,
            timestamp_unix_ms: 1_700_100_200_000,
        })];
        let commands = vec![
            "cargo test -p frankenengine-engine --test rgc_test_harness_integration".to_string(),
        ];
        let manifest = HarnessRunManifest::from_context(
            &context,
            run_id,
            events.len(),
            commands.len(),
            "./scripts/e2e/rgc_test_harness_replay.sh ci",
            1_700_100_200_100,
        );

        let triad = write_artifact_triad(&root, &manifest, &events, &commands)
            .expect("artifact triad should be emitted");
        let validation = validate_artifact_triad(&triad.run_dir);
        assert!(
            validation.valid,
            "expected valid triad for lane {lane}, findings: {:?}",
            validation.findings
        );
    }
}

#[test]
fn rgc_bundle_validator_detects_cross_lane_drift_even_when_lane_triads_pass() {
    let root = temp_dir("rgc_bundle_validator");
    let artifacts_root = root.join("artifacts");
    fs::create_dir_all(&artifacts_root).expect("create artifacts root");

    let scenario_id = "rgc-062b-integration";
    let fixture_id = "fixture-shared";
    let seed = 6207;
    for lane in [HarnessLane::Runtime, HarnessLane::Security] {
        let context = DeterministicTestContext::new(scenario_id, fixture_id, lane, seed);
        let run_id = context.default_run_id();
        let events = vec![context.event(EventInput {
            sequence: 0,
            component: "rgc_bundle_validator_integration",
            event: "lane_done",
            outcome: "pass",
            error_code: None,
            timing_us: 99,
            timestamp_unix_ms: 1_700_400_000_100,
        })];
        let commands = vec![
            "cargo test -p frankenengine-engine --test rgc_test_harness_integration".to_string(),
        ];
        let manifest = HarnessRunManifest::from_context(
            &context,
            run_id,
            events.len(),
            commands.len(),
            "./scripts/e2e/rgc_artifact_validator_phase_b_replay.sh ci",
            1_700_400_000_200,
        );
        write_artifact_triad(&artifacts_root, &manifest, &events, &commands)
            .expect("write integration triad");
    }

    let security_context =
        DeterministicTestContext::new(scenario_id, fixture_id, HarnessLane::Security, seed);
    let security_run_dir = artifacts_root.join(security_context.default_run_id());
    let manifest_path = security_run_dir.join("run_manifest.json");
    let mut manifest: HarnessRunManifest =
        serde_json::from_str(&fs::read_to_string(&manifest_path).expect("read security manifest"))
            .expect("parse security manifest");
    manifest.trace_id = "trace-rgc-corrupted-integration".to_string();
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("serialize security manifest"),
    )
    .expect("rewrite security manifest");

    let events_path = security_run_dir.join("events.jsonl");
    let mut rewritten = String::new();
    for line in fs::read_to_string(&events_path)
        .expect("read security events")
        .lines()
    {
        if line.trim().is_empty() {
            continue;
        }
        let mut event =
            serde_json::from_str::<frankenengine_engine::rgc_test_harness::HarnessLogEvent>(line)
                .expect("parse event");
        event.trace_id = "trace-rgc-corrupted-integration".to_string();
        rewritten.push_str(&serde_json::to_string(&event).expect("serialize event"));
        rewritten.push('\n');
    }
    fs::write(&events_path, rewritten).expect("rewrite security events");

    let report = validate_artifact_bundle(
        &artifacts_root,
        &[HarnessLane::Runtime, HarnessLane::Security],
    );
    assert!(!report.valid);
    assert!(
        report.lane_reports.iter().all(|lane| lane.valid),
        "lane triads should remain valid after synchronized corruption"
    );
    assert!(report.findings.iter().any(|finding| {
        finding.error_code == ArtifactBundleValidationErrorCode::CorrelationMismatch
            && finding.message.contains("non-deterministic trace_id")
    }));
}

// ────────────────────────────────────────────────────────────
// Enrichment: serde, display, defaults, edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn harness_lane_serde_round_trip_all_variants() {
    for lane in [
        HarnessLane::Parser,
        HarnessLane::Runtime,
        HarnessLane::Security,
        HarnessLane::Governance,
        HarnessLane::E2e,
    ] {
        let json = serde_json::to_string(&lane).expect("serialize");
        let recovered: HarnessLane = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(lane, recovered);
    }
}

#[test]
fn harness_lane_display_and_as_str_are_consistent() {
    for lane in [
        HarnessLane::Parser,
        HarnessLane::Runtime,
        HarnessLane::Security,
        HarnessLane::Governance,
        HarnessLane::E2e,
    ] {
        assert_eq!(lane.to_string(), lane.as_str());
        assert!(!lane.as_str().is_empty());
    }
}

#[test]
fn baseline_scenario_domain_serde_round_trip_all_variants() {
    for domain in [
        BaselineScenarioDomain::Runtime,
        BaselineScenarioDomain::Module,
        BaselineScenarioDomain::Security,
    ] {
        let json = serde_json::to_string(&domain).expect("serialize");
        let recovered: BaselineScenarioDomain = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(domain, recovered);
    }
}

#[test]
fn baseline_scenario_domain_display_and_as_str_are_consistent() {
    for domain in [
        BaselineScenarioDomain::Runtime,
        BaselineScenarioDomain::Module,
        BaselineScenarioDomain::Security,
    ] {
        assert_eq!(domain.to_string(), domain.as_str());
        assert!(!domain.as_str().is_empty());
    }
}

#[test]
fn baseline_scenario_outcome_serde_round_trip() {
    for outcome in [
        BaselineScenarioOutcome::HappyPath,
        BaselineScenarioOutcome::CanonicalFailure,
    ] {
        let json = serde_json::to_string(&outcome).expect("serialize");
        let recovered: BaselineScenarioOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(outcome, recovered);
    }
}

#[test]
fn artifact_bundle_validation_error_code_serde_round_trip() {
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
        let json = serde_json::to_string(&code).expect("serialize");
        let recovered: ArtifactBundleValidationErrorCode =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(code, recovered);
    }
}

#[test]
fn deterministic_test_context_same_inputs_produce_identical_trace_ids() {
    let a = DeterministicTestContext::new("scenario-a", "fixture-a", HarnessLane::Runtime, 42);
    let b = DeterministicTestContext::new("scenario-a", "fixture-a", HarnessLane::Runtime, 42);
    assert_eq!(a.trace_id, b.trace_id);
    assert_eq!(a.decision_id, b.decision_id);
    assert_eq!(a.policy_id, b.policy_id);
}

#[test]
fn harness_run_manifest_serde_round_trip() {
    let context = DeterministicTestContext::new("serde-test", "fixture-serde", HarnessLane::E2e, 1);
    let manifest = HarnessRunManifest::from_context(
        &context,
        context.default_run_id(),
        2,
        1,
        "./scripts/replay.sh ci",
        1_700_000_000_000,
    );
    let json = serde_json::to_string(&manifest).expect("serialize");
    let recovered: HarnessRunManifest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(manifest, recovered);
}

// ────────────────────────────────────────────────────────────
// Enrichment: schema constants stability
// ────────────────────────────────────────────────────────────

#[test]
fn rgc_schema_version_constants_are_stable_across_invocations() {
    assert_eq!(
        RGC_TEST_HARNESS_SCHEMA_VERSION,
        "franken-engine.rgc-test-harness.v1"
    );
    assert_eq!(
        RGC_TEST_HARNESS_EVENT_SCHEMA_VERSION,
        "franken-engine.rgc-test-event.v1"
    );
    assert_eq!(
        RGC_TEST_HARNESS_MANIFEST_SCHEMA_VERSION,
        "franken-engine.rgc-test-harness.run-manifest.v1"
    );
    assert_eq!(
        RGC_BASELINE_E2E_SCENARIO_SCHEMA_VERSION,
        "franken-engine.rgc-baseline-e2e-scenario.v1"
    );
    assert_eq!(
        RGC_ARTIFACT_VALIDATOR_SCHEMA_VERSION,
        "franken-engine.rgc-artifact-validator.v1"
    );
    assert_eq!(
        RGC_ARTIFACT_BUNDLE_VALIDATOR_SCHEMA_VERSION,
        "franken-engine.rgc-artifact-bundle-validator.v1"
    );
}

// ────────────────────────────────────────────────────────────
// Enrichment: DeterministicTestContext ID variation
// ────────────────────────────────────────────────────────────

#[test]
fn context_ids_change_when_seed_differs() {
    let a = DeterministicTestContext::new("sc-a", "fix-a", HarnessLane::Runtime, 1);
    let b = DeterministicTestContext::new("sc-a", "fix-a", HarnessLane::Runtime, 2);
    assert_ne!(a.trace_id, b.trace_id);
    assert_ne!(a.decision_id, b.decision_id);
}

#[test]
fn context_ids_change_when_scenario_differs() {
    let a = DeterministicTestContext::new("alpha", "fix-a", HarnessLane::Runtime, 42);
    let b = DeterministicTestContext::new("beta", "fix-a", HarnessLane::Runtime, 42);
    assert_ne!(a.trace_id, b.trace_id);
    assert_ne!(a.decision_id, b.decision_id);
}

#[test]
fn context_ids_change_when_fixture_differs() {
    let a = DeterministicTestContext::new("sc-a", "fix-a", HarnessLane::Runtime, 42);
    let b = DeterministicTestContext::new("sc-a", "fix-b", HarnessLane::Runtime, 42);
    assert_ne!(a.trace_id, b.trace_id);
    assert_ne!(a.decision_id, b.decision_id);
}

#[test]
fn context_ids_change_when_lane_differs() {
    let a = DeterministicTestContext::new("sc-a", "fix-a", HarnessLane::Parser, 42);
    let b = DeterministicTestContext::new("sc-a", "fix-a", HarnessLane::Security, 42);
    assert_ne!(a.trace_id, b.trace_id);
    assert_ne!(a.policy_id, b.policy_id);
}

#[test]
fn context_default_run_id_starts_with_run_prefix() {
    let ctx = DeterministicTestContext::new("rgc-052", "fixture-a", HarnessLane::Runtime, 42);
    let run_id = ctx.default_run_id();
    assert!(
        run_id.starts_with("run-rgc-052-"),
        "run_id should start with 'run-<sanitized_scenario>-': {run_id}"
    );
    assert!(run_id.len() > "run-rgc-052-".len());
}

#[test]
fn context_policy_id_includes_lane_name_for_all_lanes() {
    for lane in [
        HarnessLane::Parser,
        HarnessLane::Runtime,
        HarnessLane::Security,
        HarnessLane::Governance,
        HarnessLane::E2e,
    ] {
        let ctx = DeterministicTestContext::new("sc", "fix", lane, 1);
        assert!(
            ctx.policy_id.contains(lane.as_str()),
            "policy_id {} should contain {}",
            ctx.policy_id,
            lane.as_str()
        );
    }
}

#[test]
fn context_with_seed_zero_and_max_both_produce_valid_ids() {
    let zero = DeterministicTestContext::new("sc", "fix", HarnessLane::Runtime, 0);
    assert!(zero.trace_id.starts_with("trace-rgc-"));
    assert_eq!(zero.seed, 0);

    let max = DeterministicTestContext::new("sc", "fix", HarnessLane::Runtime, u64::MAX);
    assert!(max.trace_id.starts_with("trace-rgc-"));
    assert_eq!(max.seed, u64::MAX);
    assert_ne!(zero.trace_id, max.trace_id);
}

// ────────────────────────────────────────────────────────────
// Enrichment: DeterministicTestContext serde
// ────────────────────────────────────────────────────────────

#[test]
fn context_serde_round_trip() {
    let ctx = DeterministicTestContext::new("rgc-052", "fixture-a", HarnessLane::Security, 7);
    let json = serde_json::to_string(&ctx).expect("serialize");
    let restored: DeterministicTestContext = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ctx, restored);
}

// ────────────────────────────────────────────────────────────
// Enrichment: HarnessLogEvent construction and serde
// ────────────────────────────────────────────────────────────

#[test]
fn event_populates_all_fields_from_context() {
    let ctx = DeterministicTestContext::new("sc-42", "fix-7", HarnessLane::Parser, 99);
    let event = ctx.event(EventInput {
        sequence: 3,
        component: "parser",
        event: "parse",
        outcome: "pass",
        error_code: Some("FE-001"),
        timing_us: 500,
        timestamp_unix_ms: 1_700_000_000_000,
    });
    assert_eq!(event.schema_version, RGC_TEST_HARNESS_EVENT_SCHEMA_VERSION);
    assert_eq!(event.scenario_id, "sc-42");
    assert_eq!(event.fixture_id, "fix-7");
    assert_eq!(event.trace_id, ctx.trace_id);
    assert_eq!(event.decision_id, ctx.decision_id);
    assert_eq!(event.policy_id, ctx.policy_id);
    assert_eq!(event.lane, HarnessLane::Parser);
    assert_eq!(event.seed, 99);
    assert_eq!(event.sequence, 3);
    assert_eq!(event.component, "parser");
    assert_eq!(event.event, "parse");
    assert_eq!(event.outcome, "pass");
    assert_eq!(event.error_code.as_deref(), Some("FE-001"));
    assert_eq!(event.timing_us, 500);
    assert_eq!(event.timestamp_unix_ms, 1_700_000_000_000);
}

#[test]
fn event_with_error_code_serde_round_trip() {
    let ctx = DeterministicTestContext::new("scenario-err", "fix-1", HarnessLane::Security, 1);
    let event = ctx.event(EventInput {
        sequence: 0,
        component: "guardplane",
        event: "containment_triggered",
        outcome: "fail",
        error_code: Some("FE-SEC-0001"),
        timing_us: 50,
        timestamp_unix_ms: 1_700_000_000_100,
    });
    assert_eq!(event.error_code.as_deref(), Some("FE-SEC-0001"));
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: HarnessLogEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, restored);
}

#[test]
fn event_without_error_code_serde_round_trip() {
    let ctx = DeterministicTestContext::new("scenario-ok", "fix-1", HarnessLane::Runtime, 99);
    let event = ctx.event(EventInput {
        sequence: 0,
        component: "runtime",
        event: "execute",
        outcome: "pass",
        error_code: None,
        timing_us: 123,
        timestamp_unix_ms: 1_700_000_000_000,
    });
    assert!(event.error_code.is_none());
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: HarnessLogEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, restored);
}

// ────────────────────────────────────────────────────────────
// Enrichment: HarnessRunManifest env_fingerprint
// ────────────────────────────────────────────────────────────

#[test]
fn manifest_env_fingerprint_is_deterministic_across_calls() {
    let ctx = DeterministicTestContext::new("rgc-052", "fix-a", HarnessLane::E2e, 53);
    let m1 = HarnessRunManifest::from_context(&ctx, "run-1", 3, 2, "replay.sh", 1_700_000_000_000);
    let m2 = HarnessRunManifest::from_context(&ctx, "run-1", 3, 2, "replay.sh", 1_700_000_000_001);
    assert_eq!(
        m1.env_fingerprint, m2.env_fingerprint,
        "fingerprint must not depend on timestamp"
    );
}

#[test]
fn manifest_env_fingerprint_changes_with_different_replay_command() {
    let ctx = DeterministicTestContext::new("rgc-052", "fix-a", HarnessLane::E2e, 53);
    let m1 =
        HarnessRunManifest::from_context(&ctx, "run-1", 3, 2, "replay-a.sh", 1_700_000_000_000);
    let m2 =
        HarnessRunManifest::from_context(&ctx, "run-1", 3, 2, "replay-b.sh", 1_700_000_000_000);
    assert_ne!(m1.env_fingerprint, m2.env_fingerprint);
}

// ────────────────────────────────────────────────────────────
// Enrichment: fixture loader security and edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn fixture_loader_rejects_empty_path() {
    let root = temp_dir("fixture_reject_empty");
    fs::create_dir_all(&root).expect("create dir");
    let error = load_json_fixture::<DemoFixture>(&root, "").expect_err("empty path must fail");
    assert!(matches!(
        error,
        FixtureLoadError::InvalidRelativePath { .. }
    ));
}

#[test]
fn fixture_loader_rejects_absolute_path() {
    let root = temp_dir("fixture_reject_abs");
    fs::create_dir_all(&root).expect("create dir");
    let error = load_json_fixture::<DemoFixture>(&root, "/etc/passwd")
        .expect_err("absolute path must fail");
    assert!(matches!(
        error,
        FixtureLoadError::InvalidRelativePath { .. }
    ));
}

#[test]
fn fixture_loader_rejects_whitespace_only_path() {
    let root = temp_dir("fixture_reject_ws");
    fs::create_dir_all(&root).expect("create dir");
    let error =
        load_json_fixture::<DemoFixture>(&root, "   ").expect_err("whitespace path must fail");
    assert!(matches!(
        error,
        FixtureLoadError::InvalidRelativePath { .. }
    ));
}

#[test]
fn fixture_loader_missing_file_returns_io_error() {
    let root = temp_dir("fixture_missing_file");
    fs::create_dir_all(&root).expect("create dir");
    let error = load_json_fixture::<DemoFixture>(&root, "nonexistent.json")
        .expect_err("missing file must fail");
    assert!(matches!(error, FixtureLoadError::IoRead { .. }));
}

#[test]
fn fixture_loader_invalid_json_returns_parse_error() {
    let root = temp_dir("fixture_bad_json");
    fs::create_dir_all(&root).expect("create dir");
    fs::write(root.join("bad.json"), "not-json").expect("write bad fixture");
    let error =
        load_json_fixture::<DemoFixture>(&root, "bad.json").expect_err("bad JSON must fail");
    assert!(matches!(error, FixtureLoadError::JsonParse { .. }));
}

// ────────────────────────────────────────────────────────────
// Enrichment: triad validation edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn validate_triad_missing_all_three_files_reports_missing_artifact() {
    let root = temp_dir("validate_triad_all_missing");
    fs::create_dir_all(&root).expect("create dir");
    let report = validate_artifact_triad(&root);
    assert!(!report.valid);
    assert!(report.findings.iter().any(|f| {
        f.error_code == ArtifactValidationErrorCode::MissingArtifact
            && f.message.contains("run_manifest.json")
    }));
    assert!(report.findings.iter().any(|f| {
        f.error_code == ArtifactValidationErrorCode::MissingArtifact
            && f.message.contains("events.jsonl")
    }));
    assert!(report.findings.iter().any(|f| {
        f.error_code == ArtifactValidationErrorCode::MissingArtifact
            && f.message.contains("commands.txt")
    }));
}

#[test]
fn validate_triad_event_count_mismatch() {
    let root = temp_dir("validate_triad_event_count");
    let ctx = DeterministicTestContext::new("count-test", "fix-1", HarnessLane::Runtime, 1);
    let run_id = ctx.default_run_id();
    let events = vec![ctx.event(EventInput {
        sequence: 0,
        component: "test",
        event: "step",
        outcome: "pass",
        error_code: None,
        timing_us: 10,
        timestamp_unix_ms: 1_700_100_000_000,
    })];
    let commands = vec!["cargo test".to_string()];
    // Manifest says 5 events but only 1 written
    let manifest =
        HarnessRunManifest::from_context(&ctx, run_id, 5, 1, "replay.sh", 1_700_100_000_100);
    let triad =
        write_artifact_triad(&root, &manifest, &events, &commands).expect("write should succeed");
    let report = validate_artifact_triad(&triad.run_dir);
    assert!(!report.valid);
    assert!(report.findings.iter().any(|f| {
        f.error_code == ArtifactValidationErrorCode::CountMismatch
            && f.message.contains("event count")
    }));
}

#[test]
fn validate_triad_command_count_mismatch() {
    let root = temp_dir("validate_triad_cmd_count");
    let ctx = DeterministicTestContext::new("cmd-count-test", "fix-1", HarnessLane::Runtime, 1);
    let run_id = ctx.default_run_id();
    let events = vec![ctx.event(EventInput {
        sequence: 0,
        component: "test",
        event: "step",
        outcome: "pass",
        error_code: None,
        timing_us: 10,
        timestamp_unix_ms: 1_700_100_000_000,
    })];
    let commands = vec!["cargo test".to_string()];
    // Manifest says 3 commands but only 1 written
    let manifest =
        HarnessRunManifest::from_context(&ctx, run_id, 1, 3, "replay.sh", 1_700_100_000_100);
    let triad =
        write_artifact_triad(&root, &manifest, &events, &commands).expect("write should succeed");
    let report = validate_artifact_triad(&triad.run_dir);
    assert!(!report.valid);
    assert!(report.findings.iter().any(|f| {
        f.error_code == ArtifactValidationErrorCode::CountMismatch
            && f.message.contains("command count")
    }));
}

#[test]
fn validate_triad_event_correlation_mismatch_detected() {
    let root = temp_dir("validate_triad_corr_mismatch");
    let ctx = DeterministicTestContext::new("corr-test", "fix-1", HarnessLane::Runtime, 77);
    let run_id = ctx.default_run_id();
    let mut event = ctx.event(EventInput {
        sequence: 0,
        component: "test",
        event: "step",
        outcome: "pass",
        error_code: None,
        timing_us: 10,
        timestamp_unix_ms: 1_700_100_000_000,
    });
    event.trace_id = "trace-rgc-corrupted".to_string();
    let events = vec![event];
    let commands = vec!["cargo test".to_string()];
    let manifest =
        HarnessRunManifest::from_context(&ctx, run_id, 1, 1, "replay.sh", 1_700_100_000_100);
    let triad =
        write_artifact_triad(&root, &manifest, &events, &commands).expect("write should succeed");
    let report = validate_artifact_triad(&triad.run_dir);
    assert!(!report.valid);
    assert!(report.findings.iter().any(|f| {
        f.error_code == ArtifactValidationErrorCode::CorrelationMismatch
            && f.message.contains("trace_id mismatch")
    }));
}

#[test]
fn validate_triad_zero_events_is_valid_when_manifest_says_zero() {
    let root = temp_dir("validate_triad_zero_events");
    let ctx = DeterministicTestContext::new("zero-events", "fix-1", HarnessLane::Parser, 1);
    let run_id = ctx.default_run_id();
    let events: Vec<HarnessLogEvent> = Vec::new();
    let commands = vec!["cargo test".to_string()];
    let manifest =
        HarnessRunManifest::from_context(&ctx, run_id, 0, 1, "replay.sh", 1_700_100_000_100);
    let triad =
        write_artifact_triad(&root, &manifest, &events, &commands).expect("write should succeed");
    let report = validate_artifact_triad(&triad.run_dir);
    assert!(
        report.valid,
        "zero events when manifest says 0 should be valid: {:?}",
        report.findings
    );
}

#[test]
fn validate_triad_malformed_manifest_and_events_reports_all_issues() {
    let root = temp_dir("validate_triad_malformed");
    let run_dir = root.join("broken-run");
    fs::create_dir_all(&run_dir).expect("create run dir");
    fs::write(
        run_dir.join("run_manifest.json"),
        r#"{"schema_version":"wrong","run_id":"","seed":"not-a-number"}"#,
    )
    .expect("write malformed manifest");
    fs::write(run_dir.join("events.jsonl"), "{not-json}\n").expect("write malformed events");
    fs::write(run_dir.join("commands.txt"), "\n").expect("write empty commands");

    let report = validate_artifact_triad(&run_dir);
    assert!(!report.valid);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.error_code == ArtifactValidationErrorCode::MissingRequiredField)
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.error_code == ArtifactValidationErrorCode::InvalidEventJson)
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.error_code == ArtifactValidationErrorCode::EmptyCommands)
    );
}

// ────────────────────────────────────────────────────────────
// Enrichment: bundle validation edge cases
// ────────────────────────────────────────────────────────────

fn write_lane_triad(
    bundle_dir: &std::path::Path,
    scenario_id: &str,
    fixture_id: &str,
    lane: HarnessLane,
    seed: u64,
) {
    let context = DeterministicTestContext::new(scenario_id, fixture_id, lane, seed);
    let run_id = context.default_run_id();
    let events = vec![context.event(EventInput {
        sequence: 0,
        component: "rgc_integration",
        event: "lane_complete",
        outcome: "pass",
        error_code: None,
        timing_us: 25,
        timestamp_unix_ms: 1_700_300_000_000,
    })];
    let commands =
        vec!["cargo test -p frankenengine-engine --test rgc_test_harness_integration".to_string()];
    let manifest = HarnessRunManifest::from_context(
        &context,
        run_id,
        events.len(),
        commands.len(),
        "./scripts/e2e/rgc_test_harness_replay.sh ci",
        1_700_300_000_100,
    );
    write_artifact_triad(bundle_dir, &manifest, &events, &commands).expect("write lane triad");
}

#[test]
fn bundle_validator_rejects_nonexistent_directory() {
    let root = PathBuf::from("/tmp/franken_engine_nonexistent_bundle_integration");
    let report = validate_artifact_bundle(&root, &[HarnessLane::Runtime]);
    assert!(!report.valid);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.error_code == ArtifactBundleValidationErrorCode::MissingBundleDirectory)
    );
}

#[test]
fn bundle_validator_rejects_empty_directory() {
    let root = temp_dir("bundle_empty_dir");
    fs::create_dir_all(&root).expect("create dir");
    let report = validate_artifact_bundle(&root, &[HarnessLane::Runtime]);
    assert!(!report.valid);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.error_code == ArtifactBundleValidationErrorCode::MissingRunDirectory)
    );
}

#[test]
fn bundle_validator_rejects_file_path_instead_of_directory() {
    let root = temp_dir("bundle_file_not_dir");
    fs::create_dir_all(&root).expect("create dir");
    let file_path = root.join("not_a_dir");
    fs::write(&file_path, "data").expect("write file");
    let report = validate_artifact_bundle(&file_path, &[]);
    assert!(!report.valid);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.error_code == ArtifactBundleValidationErrorCode::MissingBundleDirectory)
    );
}

#[test]
fn bundle_validator_detects_cross_lane_seed_mismatch() {
    let root = temp_dir("bundle_seed_mismatch");
    let bundle_dir = root.join("bundle");
    fs::create_dir_all(&bundle_dir).expect("create dir");
    write_lane_triad(
        &bundle_dir,
        "rgc-seed-test",
        "fix-shared",
        HarnessLane::Runtime,
        100,
    );
    write_lane_triad(
        &bundle_dir,
        "rgc-seed-test",
        "fix-shared",
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
fn bundle_validator_detects_cross_lane_scenario_mismatch() {
    let root = temp_dir("bundle_scenario_mismatch");
    let bundle_dir = root.join("bundle");
    fs::create_dir_all(&bundle_dir).expect("create dir");
    write_lane_triad(
        &bundle_dir,
        "scenario-alpha",
        "fix-shared",
        HarnessLane::Runtime,
        42,
    );
    write_lane_triad(
        &bundle_dir,
        "scenario-beta",
        "fix-shared",
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
fn bundle_validator_accepts_valid_multi_lane_bundle() {
    let root = temp_dir("bundle_valid_multi_lane");
    let bundle_dir = root.join("bundle");
    fs::create_dir_all(&bundle_dir).expect("create dir");
    for lane in [
        HarnessLane::Runtime,
        HarnessLane::Security,
        HarnessLane::E2e,
    ] {
        write_lane_triad(&bundle_dir, "rgc-happy", "fix-shared", lane, 6202);
    }
    let report = validate_artifact_bundle(
        &bundle_dir,
        &[
            HarnessLane::Runtime,
            HarnessLane::Security,
            HarnessLane::E2e,
        ],
    );
    assert!(
        report.valid,
        "expected valid bundle, findings: {:?}",
        report.findings
    );
    assert_eq!(report.lane_reports.len(), 3);
    let sig = report
        .correlation_signature
        .expect("signature should be present");
    assert_eq!(sig.scenario_id, "rgc-happy");
    assert_eq!(sig.seed, 6202);
    assert_eq!(sig.lanes.len(), 3);
}

#[test]
fn bundle_validator_no_required_lanes_accepts_any_present() {
    let root = temp_dir("bundle_no_req_lanes");
    let bundle_dir = root.join("bundle");
    fs::create_dir_all(&bundle_dir).expect("create dir");
    write_lane_triad(
        &bundle_dir,
        "rgc-no-req",
        "fix-shared",
        HarnessLane::Runtime,
        1,
    );
    let report = validate_artifact_bundle(&bundle_dir, &[]);
    assert!(
        report.valid,
        "no required lanes means any present lane is fine: {:?}",
        report.findings
    );
}

// ────────────────────────────────────────────────────────────
// Enrichment: baseline registry properties
// ────────────────────────────────────────────────────────────

#[test]
fn baseline_registry_scenario_ids_are_sorted() {
    let registry = baseline_e2e_scenario_registry();
    let ids: Vec<&str> = registry.iter().map(|s| s.scenario_id.as_str()).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted, "scenario IDs must be sorted");
}

#[test]
fn baseline_registry_all_scenarios_use_e2e_lane() {
    let registry = baseline_e2e_scenario_registry();
    for scenario in &registry {
        assert_eq!(scenario.lane, HarnessLane::E2e);
    }
}

#[test]
fn baseline_registry_failure_scenarios_have_error_codes() {
    let registry = baseline_e2e_scenario_registry();
    for scenario in &registry {
        if scenario.outcome == BaselineScenarioOutcome::CanonicalFailure {
            assert!(
                scenario.error_code.is_some(),
                "failure scenario {} must have error_code",
                scenario.scenario_id
            );
        }
    }
}

#[test]
fn baseline_registry_happy_scenarios_have_no_error_codes() {
    let registry = baseline_e2e_scenario_registry();
    for scenario in &registry {
        if scenario.outcome == BaselineScenarioOutcome::HappyPath {
            assert!(
                scenario.error_code.is_none(),
                "happy scenario {} must not have error_code",
                scenario.scenario_id
            );
        }
    }
}

#[test]
fn baseline_registry_covers_all_three_domains_with_both_outcomes() {
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
        let failure = registry
            .iter()
            .filter(|s| {
                s.domain == domain && s.outcome == BaselineScenarioOutcome::CanonicalFailure
            })
            .count();
        assert_eq!(happy, 1, "missing happy-path for {domain}");
        assert_eq!(failure, 1, "missing canonical-failure for {domain}");
    }
}

// ────────────────────────────────────────────────────────────
// Enrichment: selection edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn select_single_domain_with_failures() {
    let selected = select_baseline_e2e_scenarios(&[BaselineScenarioDomain::Security], true);
    assert_eq!(selected.len(), 2, "security: 1 happy + 1 failure");
    assert!(
        selected
            .iter()
            .all(|s| s.domain == BaselineScenarioDomain::Security)
    );
}

#[test]
fn select_single_domain_happy_only() {
    let selected = select_baseline_e2e_scenarios(&[BaselineScenarioDomain::Module], false);
    assert_eq!(selected.len(), 1, "module happy-only should return 1");
    assert_eq!(selected[0].outcome, BaselineScenarioOutcome::HappyPath);
    assert_eq!(selected[0].domain, BaselineScenarioDomain::Module);
}

#[test]
fn select_all_domains_with_failures() {
    let selected = select_baseline_e2e_scenarios(&[], true);
    assert_eq!(selected.len(), 6, "3 domains x 2 outcomes = 6");
}

// ────────────────────────────────────────────────────────────
// Enrichment: serde round trips for remaining public types
// ────────────────────────────────────────────────────────────

#[test]
fn baseline_e2e_scenario_happy_serde_round_trip() {
    let registry = baseline_e2e_scenario_registry();
    let happy = registry
        .iter()
        .find(|s| s.outcome == BaselineScenarioOutcome::HappyPath)
        .expect("at least one happy scenario");
    let json = serde_json::to_string(happy).expect("serialize");
    let restored: BaselineE2eScenario = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(*happy, restored);
    assert!(restored.error_code.is_none());
}

#[test]
fn baseline_e2e_scenario_failure_serde_round_trip() {
    let registry = baseline_e2e_scenario_registry();
    let failure = registry
        .iter()
        .find(|s| s.outcome == BaselineScenarioOutcome::CanonicalFailure)
        .expect("at least one failure scenario");
    let json = serde_json::to_string(failure).expect("serialize");
    let restored: BaselineE2eScenario = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(*failure, restored);
    assert!(restored.error_code.is_some());
}

#[test]
fn artifact_validation_error_code_serde_round_trip_all_variants() {
    for code in [
        ArtifactValidationErrorCode::MissingArtifact,
        ArtifactValidationErrorCode::InvalidManifestJson,
        ArtifactValidationErrorCode::InvalidEventJson,
        ArtifactValidationErrorCode::MissingRequiredField,
        ArtifactValidationErrorCode::CorrelationMismatch,
        ArtifactValidationErrorCode::CountMismatch,
        ArtifactValidationErrorCode::EmptyCommands,
    ] {
        let json = serde_json::to_string(&code).expect("serialize");
        let restored: ArtifactValidationErrorCode =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(code, restored);
    }
}

#[test]
fn artifact_validation_finding_serde_round_trip() {
    let finding = ArtifactValidationFinding {
        component: "test".to_string(),
        event: "validate".to_string(),
        outcome: "fail".to_string(),
        error_code: ArtifactValidationErrorCode::CountMismatch,
        message: "mismatch detected".to_string(),
    };
    let json = serde_json::to_string(&finding).expect("serialize");
    let restored: ArtifactValidationFinding = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(finding, restored);
}

#[test]
fn artifact_validation_report_serde_round_trip() {
    let report = ArtifactValidationReport {
        schema_version: RGC_ARTIFACT_VALIDATOR_SCHEMA_VERSION.to_string(),
        component: "test".to_string(),
        event: "validate".to_string(),
        outcome: "pass".to_string(),
        valid: true,
        run_id: Some("run-001".to_string()),
        trace_id: Some("trace-001".to_string()),
        decision_id: Some("decision-001".to_string()),
        policy_id: Some("policy-001".to_string()),
        findings: Vec::new(),
    };
    let json = serde_json::to_string(&report).expect("serialize");
    let restored: ArtifactValidationReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(report, restored);
}

#[test]
fn artifact_bundle_validation_finding_serde_round_trip() {
    let finding = ArtifactBundleValidationFinding {
        component: "test".to_string(),
        event: "validate_bundle".to_string(),
        outcome: "fail".to_string(),
        error_code: ArtifactBundleValidationErrorCode::DuplicateLane,
        message: "dup".to_string(),
        owner_hint: "owner".to_string(),
        remediation_hint: "fix it".to_string(),
        repro_command: "cargo test".to_string(),
    };
    let json = serde_json::to_string(&finding).expect("serialize");
    let restored: ArtifactBundleValidationFinding =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(finding, restored);
}

#[test]
fn artifact_bundle_correlation_signature_serde_round_trip() {
    let sig = ArtifactBundleCorrelationSignature {
        scenario_id: "test-corr".to_string(),
        seed: 42,
        lanes: vec![HarnessLane::Parser, HarnessLane::Runtime],
    };
    let json = serde_json::to_string(&sig).expect("serialize");
    let restored: ArtifactBundleCorrelationSignature =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(sig, restored);
}

#[test]
fn artifact_bundle_validation_report_serde_round_trip() {
    let report = ArtifactBundleValidationReport {
        schema_version: RGC_ARTIFACT_BUNDLE_VALIDATOR_SCHEMA_VERSION.to_string(),
        component: "test".to_string(),
        event: "validate_bundle".to_string(),
        outcome: "pass".to_string(),
        valid: true,
        bundle_dir: "/tmp/test".to_string(),
        correlation_signature: Some(ArtifactBundleCorrelationSignature {
            scenario_id: "test-scenario".to_string(),
            seed: 42,
            lanes: vec![HarnessLane::Runtime, HarnessLane::Security],
        }),
        run_dirs: vec!["/tmp/test/run-1".to_string()],
        lane_reports: Vec::new(),
        findings: Vec::new(),
    };
    let json = serde_json::to_string(&report).expect("serialize");
    let restored: ArtifactBundleValidationReport =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(report, restored);
}

// ────────────────────────────────────────────────────────────
// Enrichment: error Display and Error trait
// ────────────────────────────────────────────────────────────

#[test]
fn fixture_load_error_display_invalid_relative_path() {
    let err = FixtureLoadError::InvalidRelativePath {
        relative_path: "../escape".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("../escape"));
    assert!(msg.contains("must not escape"));
}

#[test]
fn fixture_load_error_display_io_read() {
    let err = FixtureLoadError::IoRead {
        path: "/tmp/missing.json".to_string(),
        message: "not found".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("/tmp/missing.json"));
    assert!(msg.contains("not found"));
}

#[test]
fn fixture_load_error_display_json_parse() {
    let err = FixtureLoadError::JsonParse {
        path: "/tmp/bad.json".to_string(),
        message: "unexpected token".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("/tmp/bad.json"));
    assert!(msg.contains("unexpected token"));
}

#[test]
fn fixture_load_error_implements_std_error() {
    let err = FixtureLoadError::InvalidRelativePath {
        relative_path: "..".to_string(),
    };
    let _: &dyn std::error::Error = &err;
}

#[test]
fn artifact_write_error_display_io() {
    let err = ArtifactWriteError::Io {
        path: "/tmp/out.json".to_string(),
        message: "permission denied".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("/tmp/out.json"));
    assert!(msg.contains("permission denied"));
}

#[test]
fn artifact_write_error_display_json() {
    let err = ArtifactWriteError::Json {
        path: "/tmp/data.json".to_string(),
        message: "recursive structure".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("/tmp/data.json"));
    assert!(msg.contains("recursive structure"));
}

#[test]
fn artifact_write_error_implements_std_error() {
    let err = ArtifactWriteError::Io {
        path: "test".to_string(),
        message: "fail".to_string(),
    };
    let _: &dyn std::error::Error = &err;
}

// ────────────────────────────────────────────────────────────
// Enrichment: ordering determinism
// ────────────────────────────────────────────────────────────

#[test]
fn harness_lane_ord_is_deterministic() {
    let mut lanes = vec![
        HarnessLane::E2e,
        HarnessLane::Security,
        HarnessLane::Parser,
        HarnessLane::Governance,
        HarnessLane::Runtime,
    ];
    let mut lanes2 = lanes.clone();
    lanes.sort();
    lanes2.sort();
    assert_eq!(lanes, lanes2, "sorting must be deterministic");
}

#[test]
fn baseline_scenario_domain_ord_is_deterministic() {
    let mut domains = vec![
        BaselineScenarioDomain::Security,
        BaselineScenarioDomain::Runtime,
        BaselineScenarioDomain::Module,
    ];
    let mut domains2 = domains.clone();
    domains.sort();
    domains2.sort();
    assert_eq!(domains, domains2);
}
