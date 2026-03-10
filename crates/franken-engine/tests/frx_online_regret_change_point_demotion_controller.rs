#![forbid(unsafe_code)]
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

use std::{collections::BTreeMap, fs, path::PathBuf};

use frankenengine_engine::hybrid_lane_router::{
    ChangePointConfig, ChangePointMonitor, ConformalConfig, ConformalState, DemotionReason,
    HybridLaneRouter, LaneChoice, LaneObservation, RiskBudget, RouterConfig, RoutingPolicy,
};
use frankenengine_engine::runtime_decision_core::{
    FallbackReason, LaneId, RegimeEstimate, RoutingDecisionInput, RuntimeDecisionCore,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn default_risk_posteriors() -> BTreeMap<String, i64> {
    let mut risk = BTreeMap::new();
    risk.insert("compatibility".to_string(), 100_000);
    risk.insert("latency".to_string(), 100_000);
    risk.insert("memory".to_string(), 100_000);
    risk.insert("incident_severity".to_string(), 100_000);
    risk
}

fn make_input(
    observed_latency_us: u64,
    calibration_covered: bool,
    timestamp_ns: u64,
) -> RoutingDecisionInput {
    RoutingDecisionInput {
        observed_latency_us,
        risk_posteriors: default_risk_posteriors(),
        regime: RegimeEstimate::Normal,
        confidence_millionths: 950_000,
        is_adverse: false,
        nonconformity_score_millionths: 100_000,
        calibration_covered,
        compute_ms: 1,
        memory_mb: 32,
        epoch: SecurityEpoch::from_raw(1),
        timestamp_ns,
    }
}

fn neutral_observation(lane: LaneChoice) -> LaneObservation {
    LaneObservation {
        lane,
        latency_us: 1_000,
        success: true,
        dom_ops: 10,
        signals_evaluated: 10,
        safe_mode_entered: false,
        compatibility_errors: 0,
    }
}

#[test]
fn frx_15_3_doc_contains_required_sections() {
    let path = repo_root().join("docs/FRX_ONLINE_REGRET_CHANGE_POINT_DEMOTION_CONTROLLER_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Online Regret + Change-Point Demotion Controller v1",
        "## Scope",
        "## Inputs",
        "## Deterministic Threshold Policy",
        "## Demotion Semantics",
        "## Structured Event Contract",
        "## Incident Artifact Requirements",
        "## Gate Commands",
        "## Failure Policy",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "missing FRX-15.3 contract section: {section}"
        );
    }

    for clause in [
        "Fail-closed",
        "CVaR",
        "Calibration",
        "change-point",
        "regret",
    ] {
        assert!(
            doc.contains(clause),
            "missing FRX-15.3 contract clause: {clause}"
        );
    }
}

#[test]
fn frx_15_3_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_online_regret_change_point_demotion_controller_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.online-regret-change-point-demotion-controller.v1")
    );
    assert_eq!(value["generated_by"].as_str(), Some("bd-mjh3.15.3"));
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.15.3"));
    assert_eq!(
        value["demotion_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
    assert_eq!(
        value["integration"]["runtime_decision_core"]["requires_cvar_gate"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["integration"]["runtime_decision_core"]["requires_calibration_gate"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["artifacts"]["suite_script"].as_str(),
        Some("scripts/run_frx_online_regret_change_point_demotion_controller_suite.sh")
    );
    assert_eq!(
        value["artifacts"]["replay_script"].as_str(),
        Some("scripts/e2e/frx_online_regret_change_point_demotion_controller_replay.sh")
    );

    let fields = value["logging"]["required_fields"]
        .as_array()
        .expect("logging.required_fields must be an array");
    for required in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(
            fields.iter().any(|entry| entry.as_str() == Some(required)),
            "missing required structured log field: {required}"
        );
    }
}

#[test]
fn frx_15_3_readme_registers_gate_commands() {
    let readme_path = repo_root().join("README.md");
    let readme = fs::read_to_string(&readme_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", readme_path.display()));

    assert!(readme.contains("## FRX Online Regret + Change-Point Demotion Controller Gate"));
    assert!(
        readme.contains(
            "./scripts/run_frx_online_regret_change_point_demotion_controller_suite.sh ci"
        )
    );
    assert!(
        readme.contains(
            "./scripts/e2e/frx_online_regret_change_point_demotion_controller_replay.sh ci"
        )
    );
    assert!(readme.contains(
        "artifacts/frx_online_regret_change_point_demotion_controller/<timestamp>/run_manifest.json"
    ));
}

#[test]
fn frx_15_3_runtime_core_integrates_tail_risk_and_calibration_fallbacks() {
    let lanes = vec![LaneId::quickjs_native(), LaneId::v8_native()];
    let mut cvar_core = RuntimeDecisionCore::new(
        "frx-15-3-cvar",
        lanes.clone(),
        LaneId::quickjs_native(),
        SecurityEpoch::from_raw(1),
    )
    .expect("runtime decision core should construct");

    cvar_core.cvar_constraint.max_cvar_us = 500;
    let cvar_out = cvar_core
        .decide(&make_input(20_000, true, 1))
        .expect("cvar decision should execute");
    assert!(cvar_out.fallback_triggered);
    assert!(matches!(
        cvar_out.fallback_reason,
        Some(FallbackReason::CVaRViolation { .. })
    ));

    let mut calibration_core = RuntimeDecisionCore::new(
        "frx-15-3-calibration",
        lanes,
        LaneId::quickjs_native(),
        SecurityEpoch::from_raw(1),
    )
    .expect("runtime decision core should construct");

    calibration_core.cvar_constraint.max_cvar_us = u64::MAX;

    let mut last = None;
    for idx in 0..24u64 {
        let out = calibration_core
            .decide(&make_input(100, false, idx + 10))
            .expect("calibration decision should execute");
        last = Some(out);
    }

    let last = last.expect("at least one decision output expected");
    assert!(last.fallback_triggered);
    assert!(matches!(
        last.fallback_reason,
        Some(FallbackReason::CalibrationUndercoverage { .. })
    ));
    assert!(
        !calibration_core.fallback_events.is_empty(),
        "fallback events must record calibration-triggered demotion"
    );
}

#[test]
fn frx_15_3_hybrid_router_regret_budget_breach_demotes_deterministically() {
    let mut config = RouterConfig::default_config();
    config.risk_budget = RiskBudget {
        tail_latency_budget_us: u64::MAX,
        compatibility_error_budget: u64::MAX,
        // Force deterministic regret gate activation on first observation.
        regret_budget_millionths: -1,
    };
    config.change_point = ChangePointConfig {
        threshold_millionths: i64::MAX,
        drift_millionths: 50_000,
        min_observations: u64::MAX,
    };
    config.conformal = ConformalConfig {
        target_coverage_millionths: 0,
        min_observations: u64::MAX,
        window_size: 1,
    };

    let mut router = HybridLaneRouter::new(config);
    router.conformal = ConformalState::new(router.config.conformal.clone());
    router.change_point = ChangePointMonitor::new(router.config.change_point.clone());
    router
        .promote_to_adaptive()
        .expect("router should promote to adaptive");
    assert_eq!(
        router.policy,
        RoutingPolicy::Adaptive,
        "router must be adaptive before evaluating change-point trigger"
    );

    let trace = router.observe(
        LaneChoice::Js,
        &neutral_observation(LaneChoice::Js),
        Some(42_000),
    );

    assert!(matches!(
        trace.demotion_reason,
        Some(DemotionReason::RegretExceeded { .. })
    ));
    assert_eq!(router.policy, RoutingPolicy::Conservative);
}

#[test]
fn frx_15_3_hybrid_router_change_point_breach_demotes_deterministically() {
    let mut config = RouterConfig::default_config();
    config.risk_budget = RiskBudget {
        tail_latency_budget_us: u64::MAX,
        compatibility_error_budget: u64::MAX,
        regret_budget_millionths: i64::MAX,
    };
    config.change_point = ChangePointConfig {
        // Threshold below zero makes the first observation deterministically trigger.
        threshold_millionths: -1,
        drift_millionths: 0,
        min_observations: 1,
    };
    config.conformal = ConformalConfig {
        target_coverage_millionths: 0,
        min_observations: u64::MAX,
        window_size: 1,
    };

    let mut router = HybridLaneRouter::new(config);
    router.conformal = ConformalState::new(router.config.conformal.clone());
    router.change_point = ChangePointMonitor::new(router.config.change_point.clone());
    router
        .promote_to_adaptive()
        .expect("router should promote to adaptive");

    let trace = router.observe(
        LaneChoice::Wasm,
        &neutral_observation(LaneChoice::Wasm),
        Some(99_000),
    );

    assert!(
        matches!(
            trace.demotion_reason,
            Some(DemotionReason::ChangePointDetected { .. })
        ),
        "expected change-point demotion, got {:?}; policy={:?}; observation_count={}; cusum_upper={}; cusum_lower={}; threshold={}; min_observations={}",
        trace.demotion_reason,
        router.policy,
        router.change_point.observation_count,
        router.change_point.cusum_upper_millionths,
        router.change_point.cusum_lower_millionths,
        router.change_point.config.threshold_millionths,
        router.change_point.config.min_observations
    );
    assert_eq!(router.policy, RoutingPolicy::Conservative);
}

#[test]
fn frx_15_3_deterministic_sequence_replays_identically() {
    fn run_sequence() -> Vec<Option<DemotionReason>> {
        let mut config = RouterConfig::default_config();
        config.risk_budget = RiskBudget {
            tail_latency_budget_us: u64::MAX,
            compatibility_error_budget: u64::MAX,
            regret_budget_millionths: 20,
        };
        config.change_point = ChangePointConfig {
            threshold_millionths: i64::MAX,
            drift_millionths: 50_000,
            min_observations: u64::MAX,
        };
        config.conformal = ConformalConfig {
            target_coverage_millionths: 0,
            min_observations: u64::MAX,
            window_size: 1,
        };

        let mut router = HybridLaneRouter::new(config);
        router.conformal = ConformalState::new(router.config.conformal.clone());
        router.change_point = ChangePointMonitor::new(router.config.change_point.clone());
        router
            .promote_to_adaptive()
            .expect("router should promote to adaptive");

        let mut traces = Vec::new();

        // Round 0: no breach
        traces.push(
            router
                .observe(
                    LaneChoice::Js,
                    &neutral_observation(LaneChoice::Js),
                    Some(10_000),
                )
                .demotion_reason,
        );

        // Round 1: deterministic regret breach
        router.risk.cumulative_regret_millionths = 25;
        traces.push(
            router
                .observe(
                    LaneChoice::Js,
                    &neutral_observation(LaneChoice::Js),
                    Some(20_000),
                )
                .demotion_reason,
        );

        traces
    }

    let a = run_sequence();
    let b = run_sequence();

    assert_eq!(
        a, b,
        "deterministic replay must produce identical demotion traces"
    );
}

// ---------- default_risk_posteriors ----------

#[test]
fn default_risk_posteriors_has_four_keys() {
    let posteriors = default_risk_posteriors();
    assert_eq!(posteriors.len(), 4);
    assert!(posteriors.contains_key("compatibility"));
    assert!(posteriors.contains_key("latency"));
    assert!(posteriors.contains_key("memory"));
    assert!(posteriors.contains_key("incident_severity"));
}

// ---------- make_input ----------

#[test]
fn make_input_sets_correct_fields() {
    let input = make_input(500, true, 42_000);
    assert_eq!(input.observed_latency_us, 500);
    assert!(input.calibration_covered);
    assert_eq!(input.timestamp_ns, 42_000);
    assert_eq!(input.confidence_millionths, 950_000);
    assert!(!input.is_adverse);
    assert_eq!(input.epoch, SecurityEpoch::from_raw(1));
}

// ---------- neutral_observation ----------

#[test]
fn neutral_observation_is_successful() {
    let obs = neutral_observation(LaneChoice::Js);
    assert_eq!(obs.lane, LaneChoice::Js);
    assert!(obs.success);
    assert_eq!(obs.latency_us, 1_000);
    assert_eq!(obs.compatibility_errors, 0);
    assert!(!obs.safe_mode_entered);
}

#[test]
fn neutral_observation_wasm_sets_lane() {
    let obs = neutral_observation(LaneChoice::Wasm);
    assert_eq!(obs.lane, LaneChoice::Wasm);
}

// ---------- LaneChoice ----------

#[test]
fn lane_choice_serde_roundtrip() {
    for lane in [LaneChoice::Js, LaneChoice::Wasm] {
        let json = serde_json::to_string(&lane).expect("serialize");
        let recovered: LaneChoice = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, lane);
    }
}

// ---------- RoutingPolicy ----------

#[test]
fn routing_policy_serde_roundtrip() {
    for policy in [RoutingPolicy::Conservative, RoutingPolicy::Adaptive] {
        let json = serde_json::to_string(&policy).expect("serialize");
        let recovered: RoutingPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, policy);
    }
}

// ---------- DemotionReason ----------

#[test]
fn demotion_reason_regret_serde_roundtrip() {
    let reason = DemotionReason::RegretExceeded {
        realized_millionths: 100,
        bound_millionths: 50,
    };
    let json = serde_json::to_string(&reason).expect("serialize");
    let recovered: DemotionReason = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, reason);
}

#[test]
fn demotion_reason_change_point_serde_roundtrip() {
    let reason = DemotionReason::ChangePointDetected {
        cusum_stat_millionths: 200,
        threshold_millionths: 100,
    };
    let json = serde_json::to_string(&reason).expect("serialize");
    let recovered: DemotionReason = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, reason);
}

// ---------- RouterConfig ----------

#[test]
fn router_config_default_is_conservative() {
    let config = RouterConfig::default_config();
    assert!(config.risk_budget.tail_latency_budget_us > 0);
    assert!(config.risk_budget.compatibility_error_budget > 0);
}

// ---------- HybridLaneRouter ----------

#[test]
fn hybrid_lane_router_starts_conservative() {
    let router = HybridLaneRouter::new(RouterConfig::default_config());
    assert_eq!(router.policy, RoutingPolicy::Conservative);
}

#[test]
fn hybrid_lane_router_summary_reflects_initial_state() {
    let router = HybridLaneRouter::new(RouterConfig::default_config());
    let summary = router.summary();
    assert_eq!(summary.policy, RoutingPolicy::Conservative);
    assert_eq!(summary.round, 0);
    assert_eq!(summary.total_js_routes, 0);
    assert_eq!(summary.total_wasm_routes, 0);
}

#[test]
fn hybrid_lane_router_promote_then_observe_tracks_round() {
    let mut config = RouterConfig::default_config();
    config.risk_budget = RiskBudget {
        tail_latency_budget_us: u64::MAX,
        compatibility_error_budget: u64::MAX,
        regret_budget_millionths: i64::MAX,
    };
    config.change_point = ChangePointConfig {
        threshold_millionths: i64::MAX,
        drift_millionths: 50_000,
        min_observations: u64::MAX,
    };
    config.conformal = ConformalConfig {
        target_coverage_millionths: 0,
        min_observations: u64::MAX,
        window_size: 1,
    };

    let mut router = HybridLaneRouter::new(config);
    router.conformal = ConformalState::new(router.config.conformal.clone());
    router.change_point = ChangePointMonitor::new(router.config.change_point.clone());
    router.promote_to_adaptive().expect("promote");

    let trace = router.observe(
        LaneChoice::Js,
        &neutral_observation(LaneChoice::Js),
        Some(10_000),
    );
    assert_eq!(trace.round, 0);
    assert_eq!(trace.policy, RoutingPolicy::Adaptive);
    assert!(trace.demotion_reason.is_none());
}

// ---------- ChangePointMonitor ----------

#[test]
fn change_point_monitor_serde_roundtrip() {
    let monitor = ChangePointMonitor::new(ChangePointConfig {
        threshold_millionths: 500_000,
        drift_millionths: 50_000,
        min_observations: 10,
    });
    let json = serde_json::to_string(&monitor).expect("serialize");
    let recovered: ChangePointMonitor = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.observation_count, 0);
}

// ---------- ConformalState ----------

#[test]
fn conformal_state_serde_roundtrip() {
    let state = ConformalState::new(ConformalConfig {
        target_coverage_millionths: 900_000,
        min_observations: 50,
        window_size: 100,
    });
    let json = serde_json::to_string(&state).expect("serialize");
    let recovered: ConformalState = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.config.target_coverage_millionths, 900_000);
}

// ---------- RiskBudget ----------

#[test]
fn risk_budget_serde_roundtrip() {
    let budget = RiskBudget {
        tail_latency_budget_us: 5_000,
        compatibility_error_budget: 10,
        regret_budget_millionths: 100_000,
    };
    let json = serde_json::to_string(&budget).expect("serialize");
    let recovered: RiskBudget = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.tail_latency_budget_us, 5_000);
    assert_eq!(recovered.regret_budget_millionths, 100_000);
}

// ---------- RoutingDecisionInput ----------

#[test]
fn routing_decision_input_serde_roundtrip() {
    let input = make_input(1_000, true, 99);
    let json = serde_json::to_string(&input).expect("serialize");
    let recovered: RoutingDecisionInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.observed_latency_us, 1_000);
    assert_eq!(recovered.timestamp_ns, 99);
}

// ---------- LaneObservation ----------

#[test]
fn lane_observation_serde_roundtrip() {
    let obs = neutral_observation(LaneChoice::Wasm);
    let json = serde_json::to_string(&obs).expect("serialize");
    let recovered: LaneObservation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.lane, LaneChoice::Wasm);
    assert!(recovered.success);
}

// ---------- JSON contract field completeness ----------

#[test]
fn frx_15_3_json_contract_demotion_policy_has_required_subfields() {
    let path = repo_root().join("docs/frx_online_regret_change_point_demotion_controller_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let dp = &value["demotion_policy"];
    assert!(dp.is_object(), "demotion_policy must be an object");
    assert!(
        dp["mode"].as_str().is_some_and(|s| !s.is_empty()),
        "demotion_policy.mode must be non-empty string"
    );
}

#[test]
fn frx_15_3_json_contract_integration_section_has_runtime_decision_core() {
    let path = repo_root().join("docs/frx_online_regret_change_point_demotion_controller_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["integration"].is_object());
    assert!(value["integration"]["runtime_decision_core"].is_object());
}

// ---------- make_input edge cases ----------

#[test]
fn make_input_zero_latency_and_zero_timestamp() {
    let input = make_input(0, false, 0);
    assert_eq!(input.observed_latency_us, 0);
    assert!(!input.calibration_covered);
    assert_eq!(input.timestamp_ns, 0);
    assert_eq!(input.risk_posteriors.len(), 4);
}

// ---------- HybridLaneRouter manual_demote ----------

#[test]
fn hybrid_lane_router_manual_demote_on_conservative_is_noop_or_error() {
    let mut router = HybridLaneRouter::new(RouterConfig::default_config());
    assert_eq!(router.policy, RoutingPolicy::Conservative);
    // manual_demote on already-conservative router should return an error
    let result = router.manual_demote();
    assert!(result.is_err());
}

// ---------- ChangePointConfig serde roundtrip ----------

#[test]
fn change_point_config_serde_roundtrip() {
    let config = ChangePointConfig {
        threshold_millionths: 750_000,
        drift_millionths: 25_000,
        min_observations: 42,
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: ChangePointConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.threshold_millionths, 750_000);
    assert_eq!(recovered.drift_millionths, 25_000);
    assert_eq!(recovered.min_observations, 42);
}

// ---------- ConformalConfig serde roundtrip ----------

#[test]
fn conformal_config_serde_roundtrip() {
    let config = ConformalConfig {
        target_coverage_millionths: 800_000,
        min_observations: 100,
        window_size: 50,
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: ConformalConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.target_coverage_millionths, 800_000);
    assert_eq!(recovered.min_observations, 100);
    assert_eq!(recovered.window_size, 50);
}

// ---------- RouterConfig serde roundtrip ----------

#[test]
fn router_config_default_serde_roundtrip() {
    let config = RouterConfig::default_config();
    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: RouterConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        recovered.risk_budget.tail_latency_budget_us,
        config.risk_budget.tail_latency_budget_us
    );
    assert_eq!(
        recovered.change_point.threshold_millionths,
        config.change_point.threshold_millionths
    );
}
