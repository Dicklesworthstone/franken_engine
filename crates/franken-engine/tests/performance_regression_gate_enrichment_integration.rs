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

use std::collections::BTreeSet;

use frankenengine_engine::performance_regression_gate::{
    CulpritCandidate, PERFORMANCE_REGRESSION_GATE_COMPONENT,
    PERFORMANCE_REGRESSION_GATE_SCHEMA_VERSION, RegressionFinding, RegressionGateError,
    RegressionGateInput, RegressionGateLogEvent, RegressionGatePolicy, RegressionObservation,
    RegressionSeverity, RegressionStatus, RegressionWaiver, evaluate_performance_regression_gate,
    write_regression_report,
};

fn default_policy() -> RegressionGatePolicy {
    RegressionGatePolicy {
        warning_regression_millionths: 20_000,
        fail_regression_millionths: 40_000,
        critical_regression_millionths: 90_000,
        max_p_value_millionths: 50_000,
        max_culprits: 5,
    }
}

fn mk_obs(workload: &str, baseline: u64, observed: u64, p_value: u32) -> RegressionObservation {
    RegressionObservation::new(
        workload,
        "scenario",
        "sha256:meta",
        baseline,
        observed,
        p_value,
        Some(format!("commit-{workload}")),
    )
}

fn mk_input(
    observations: Vec<RegressionObservation>,
    waivers: Vec<RegressionWaiver>,
) -> RegressionGateInput {
    RegressionGateInput::new(
        "trace-test",
        "decision-test",
        "policy-test",
        1_700_000_000,
        observations,
        waivers,
    )
}

// =========================================================================
// A. BTreeSet ordering and dedup for RegressionSeverity (Ord + Hash)
// =========================================================================

#[test]
fn enrichment_severity_btreeset_ordering_dedup() {
    let mut set = BTreeSet::new();
    set.insert(RegressionSeverity::None);
    set.insert(RegressionSeverity::Warning);
    set.insert(RegressionSeverity::High);
    set.insert(RegressionSeverity::Critical);
    set.insert(RegressionSeverity::None); // duplicate
    set.insert(RegressionSeverity::Critical); // duplicate
    assert_eq!(set.len(), 4);
    let ordered: Vec<_> = set.into_iter().collect();
    for i in 1..ordered.len() {
        assert!(ordered[i - 1] < ordered[i]);
    }
}

// =========================================================================
// B. Hash consistency for RegressionSeverity
// =========================================================================

#[test]
fn enrichment_severity_hash_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let hash_of = |s: RegressionSeverity| {
        let mut hasher = DefaultHasher::new();
        s.hash(&mut hasher);
        hasher.finish()
    };
    // Same values hash identically
    assert_eq!(
        hash_of(RegressionSeverity::Critical),
        hash_of(RegressionSeverity::Critical)
    );
    assert_eq!(
        hash_of(RegressionSeverity::None),
        hash_of(RegressionSeverity::None)
    );
    // Different values (very likely) hash differently
    assert_ne!(
        hash_of(RegressionSeverity::None),
        hash_of(RegressionSeverity::Critical)
    );
}

// =========================================================================
// C. Default impls
// =========================================================================

#[test]
fn enrichment_severity_default_is_none() {
    assert_eq!(RegressionSeverity::default(), RegressionSeverity::None);
}

#[test]
fn enrichment_status_default_is_active() {
    assert_eq!(RegressionStatus::default(), RegressionStatus::Active);
}

// =========================================================================
// D. Display for all enum variants via fmt::Display
// =========================================================================

#[test]
fn enrichment_severity_display_all_variants() {
    assert_eq!(format!("{}", RegressionSeverity::None), "none");
    assert_eq!(format!("{}", RegressionSeverity::Warning), "warning");
    assert_eq!(format!("{}", RegressionSeverity::High), "high");
    assert_eq!(format!("{}", RegressionSeverity::Critical), "critical");
}

#[test]
fn enrichment_status_display_all_variants() {
    assert_eq!(format!("{}", RegressionStatus::Active), "active");
    assert_eq!(format!("{}", RegressionStatus::Waived), "waived");
}

#[test]
fn enrichment_severity_display_values_distinct() {
    let displays: BTreeSet<String> = [
        RegressionSeverity::None,
        RegressionSeverity::Warning,
        RegressionSeverity::High,
        RegressionSeverity::Critical,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(displays.len(), 4);
}

// =========================================================================
// E. Debug nonempty for all types
// =========================================================================

#[test]
fn enrichment_debug_nonempty_enums() {
    assert!(!format!("{:?}", RegressionSeverity::None).is_empty());
    assert!(!format!("{:?}", RegressionSeverity::Warning).is_empty());
    assert!(!format!("{:?}", RegressionSeverity::High).is_empty());
    assert!(!format!("{:?}", RegressionSeverity::Critical).is_empty());
    assert!(!format!("{:?}", RegressionStatus::Active).is_empty());
    assert!(!format!("{:?}", RegressionStatus::Waived).is_empty());
}

#[test]
fn enrichment_debug_nonempty_structs() {
    let obs = mk_obs("w-a", 100_000, 200_000, 5_000);
    assert!(!format!("{obs:?}").is_empty());
    let waiver = RegressionWaiver::new("w-1", "w-a", "oncall", 1_800_000_000, "test");
    assert!(!format!("{waiver:?}").is_empty());
    let policy = default_policy();
    assert!(!format!("{policy:?}").is_empty());
    let input = mk_input(vec![obs], vec![waiver]);
    assert!(!format!("{input:?}").is_empty());
    let report = evaluate_performance_regression_gate(&input, &policy);
    assert!(!format!("{report:?}").is_empty());
}

#[test]
fn enrichment_debug_nonempty_error() {
    let err = RegressionGateError::Serialization("test".into());
    assert!(!format!("{err:?}").is_empty());
    let err = RegressionGateError::ReportWrite {
        path: "/tmp/test".to_string(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
    };
    assert!(!format!("{err:?}").is_empty());
}

// =========================================================================
// F. Clone independence
// =========================================================================

#[test]
fn enrichment_clone_independence_report() {
    let input = mk_input(vec![mk_obs("w-a", 100_000, 200_000, 5_000)], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());
    let mut cloned = report.clone();
    cloned.trace_id = "modified".to_string();
    cloned.regressions[0].workload_id = "changed".to_string();
    assert_eq!(report.trace_id, "trace-test");
    assert_eq!(report.regressions[0].workload_id, "w-a");
}

#[test]
fn enrichment_clone_independence_input() {
    let input = mk_input(
        vec![mk_obs("w-a", 100_000, 200_000, 5_000)],
        vec![RegressionWaiver::new(
            "w-1",
            "w-a",
            "oncall",
            1_800_000_000,
            "test",
        )],
    );
    let mut cloned = input.clone();
    cloned.trace_id = "modified".to_string();
    cloned.observations[0].workload_id = "changed".to_string();
    cloned.waivers[0].waiver_id = "changed".to_string();
    assert_eq!(input.trace_id, "trace-test");
    assert_eq!(input.observations[0].workload_id, "w-a");
    assert_eq!(input.waivers[0].waiver_id, "w-1");
}

// =========================================================================
// G. Finding with ALL optional fields populated serde roundtrip
// =========================================================================

#[test]
fn enrichment_finding_all_optional_fields_serde() {
    let finding = RegressionFinding {
        workload_id: "w-a".to_string(),
        scenario_id: "scenario".to_string(),
        severity: RegressionSeverity::High,
        status: RegressionStatus::Waived,
        regression_millionths: 60_000,
        p_value_millionths: 10_000,
        error_code: "FE-RGC-703-REGRESSION-0005".to_string(),
        message: "regression (waived by waiver-1)".to_string(),
        waiver_id: Some("waiver-1".to_string()),
        waiver_owner: Some("oncall".to_string()),
        waiver_expires_at_unix_seconds: Some(1_800_000_000),
        commit_id: Some("commit-a".to_string()),
    };
    let json = serde_json::to_string(&finding).unwrap();
    let back: RegressionFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding, back);
    // Verify optional fields survived roundtrip
    assert_eq!(back.waiver_id, Some("waiver-1".to_string()));
    assert_eq!(back.waiver_owner, Some("oncall".to_string()));
    assert_eq!(back.waiver_expires_at_unix_seconds, Some(1_800_000_000));
    assert_eq!(back.commit_id, Some("commit-a".to_string()));
}

// =========================================================================
// H. Observation without commit_id (skip_serializing_if)
// =========================================================================

#[test]
fn enrichment_observation_no_commit_id_serde() {
    let obs = RegressionObservation::new(
        "w-a",
        "scenario",
        "sha256:meta",
        100_000,
        200_000,
        5_000,
        None,
    );
    let json = serde_json::to_string(&obs).unwrap();
    assert!(!json.contains("commit_id")); // skip_serializing_if
    let back: RegressionObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(back.commit_id, None);
    assert_eq!(obs, back);
}

// =========================================================================
// I. CulpritCandidate with empty error_codes (skip_serializing_if)
// =========================================================================

#[test]
fn enrichment_culprit_empty_error_codes_serde() {
    let candidate = CulpritCandidate {
        rank: 1,
        workload_id: "w-a".to_string(),
        severity: RegressionSeverity::High,
        score: 2_060_000_000,
        regression_millionths: 60_000,
        p_value_millionths: 10_000,
        error_codes: vec![],
        commit_id: None,
    };
    let json = serde_json::to_string(&candidate).unwrap();
    assert!(!json.contains("error_codes")); // skip_serializing_if
    let back: CulpritCandidate = serde_json::from_str(&json).unwrap();
    assert!(back.error_codes.is_empty());
}

// =========================================================================
// J. Multiple waivers for same workload: latest expiry wins
// =========================================================================

#[test]
fn enrichment_multiple_waivers_latest_expiry_wins() {
    let old_waiver = RegressionWaiver::new("waiver-old", "w-a", "oncall", 1_600_000_000, "old");
    let new_waiver = RegressionWaiver::new("waiver-new", "w-a", "oncall", 1_900_000_000, "new");
    // 60% regression (Critical)
    let input = mk_input(
        vec![mk_obs("w-a", 100_000, 160_000, 10_000)],
        vec![old_waiver, new_waiver],
    );
    let report = evaluate_performance_regression_gate(&input, &default_policy());
    // new waiver is valid (expires 1.9B > now 1.7B), should suppress blocking
    assert!(!report.blocking);
    assert_eq!(report.regressions[0].status, RegressionStatus::Waived);
    assert_eq!(
        report.regressions[0].waiver_id.as_deref(),
        Some("waiver-new")
    );
}

// =========================================================================
// K. Boundary conditions: exactly at thresholds
// =========================================================================

#[test]
fn enrichment_regression_exactly_at_warning_threshold() {
    // 2% = 20_000 millionths = exactly at warning threshold
    let input = mk_input(vec![mk_obs("w-a", 100_000, 102_000, 10_000)], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());
    // At threshold → warning finding
    assert_eq!(report.regressions.len(), 1);
    assert_eq!(report.regressions[0].severity, RegressionSeverity::Warning);
    assert!(!report.blocking);
}

#[test]
fn enrichment_regression_just_below_warning_threshold() {
    // 1.9% ≈ 19_000 millionths < warning 20_000 → no finding
    let input = mk_input(vec![mk_obs("w-a", 100_000, 101_900, 10_000)], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());
    assert!(report.regressions.is_empty());
}

#[test]
fn enrichment_regression_exactly_at_fail_threshold() {
    // 4% = 40_000 millionths = exactly at fail threshold
    let input = mk_input(vec![mk_obs("w-a", 100_000, 104_000, 10_000)], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());
    assert_eq!(report.regressions[0].severity, RegressionSeverity::High);
    assert!(report.blocking);
}

#[test]
fn enrichment_regression_exactly_at_critical_threshold() {
    // 9% = 90_000 millionths = exactly at critical threshold
    let input = mk_input(vec![mk_obs("w-a", 100_000, 109_000, 10_000)], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());
    assert_eq!(report.regressions[0].severity, RegressionSeverity::Critical);
    assert!(report.blocking);
}

// =========================================================================
// L. p_value boundary: exactly at max_p_value
// =========================================================================

#[test]
fn enrichment_p_value_exactly_at_max() {
    // p_value = 50_000 = exactly max → still significant (not >) → normal classification
    let input = mk_input(vec![mk_obs("w-a", 100_000, 103_000, 50_000)], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());
    assert_eq!(report.regressions.len(), 1);
    assert_eq!(report.regressions[0].severity, RegressionSeverity::Warning);
}

#[test]
fn enrichment_p_value_just_above_max() {
    // p_value = 50_001 > max 50_000 → low confidence → High severity
    let input = mk_input(vec![mk_obs("w-a", 100_000, 103_000, 50_001)], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());
    assert_eq!(report.regressions.len(), 1);
    assert_eq!(report.regressions[0].severity, RegressionSeverity::High);
    assert!(report.regressions[0].error_code.contains("SIGNIFICANCE"));
}

// =========================================================================
// M. Log events for regression findings
// =========================================================================

#[test]
fn enrichment_log_events_for_each_finding() {
    let input = mk_input(
        vec![
            mk_obs("w-a", 100_000, 200_000, 5_000),
            mk_obs("w-b", 100_000, 103_000, 10_000),
        ],
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &default_policy());
    let finding_logs: Vec<_> = report
        .logs
        .iter()
        .filter(|l| l.event == "regression_finding")
        .collect();
    // One log per finding
    assert_eq!(finding_logs.len(), report.regressions.len());
    // Each finding log has workload_id
    for log in &finding_logs {
        assert!(log.workload_id.is_some());
    }
}

// =========================================================================
// N. Report fields blocking == is_blocking
// =========================================================================

#[test]
fn enrichment_blocking_and_is_blocking_are_equal() {
    // Non-blocking case
    let input1 = mk_input(vec![mk_obs("w-a", 100_000, 100_000, 5_000)], Vec::new());
    let report1 = evaluate_performance_regression_gate(&input1, &default_policy());
    assert_eq!(report1.blocking, report1.is_blocking);

    // Blocking case
    let input2 = mk_input(vec![mk_obs("w-a", 100_000, 200_000, 5_000)], Vec::new());
    let report2 = evaluate_performance_regression_gate(&input2, &default_policy());
    assert_eq!(report2.blocking, report2.is_blocking);
}

#[test]
fn enrichment_highest_severity_equals_severity() {
    let input = mk_input(vec![mk_obs("w-a", 100_000, 200_000, 5_000)], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());
    assert_eq!(report.highest_severity, report.severity);
}

// =========================================================================
// O. Write report then read back JSON structure
// =========================================================================

#[test]
fn enrichment_write_report_produces_valid_json() {
    let input = mk_input(vec![mk_obs("w-a", 100_000, 200_000, 5_000)], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());
    let path = std::env::temp_dir().join("prg_enrichment_report.json");
    write_regression_report(&report, &path).unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert!(parsed.is_object());
    assert_eq!(
        parsed["schema_version"].as_str().unwrap(),
        PERFORMANCE_REGRESSION_GATE_SCHEMA_VERSION
    );
    assert_eq!(parsed["blocking"].as_bool(), Some(true));
    assert!(parsed["regressions"].as_array().unwrap().len() > 0);
    assert!(parsed["culprit_ranking"].as_array().unwrap().len() > 0);

    let _ = std::fs::remove_file(&path);
}

// =========================================================================
// P. Error Display includes relevant info
// =========================================================================

#[test]
fn enrichment_error_display_messages_distinct() {
    let err1 = RegressionGateError::Serialization("bad json".into());
    let err2 = RegressionGateError::ReportWrite {
        path: "/tmp/x".to_string(),
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
    };
    let d1 = err1.to_string();
    let d2 = err2.to_string();
    assert_ne!(d1, d2);
    assert!(d1.contains("bad json"));
    assert!(d2.contains("/tmp/x"));
}

// =========================================================================
// Q. Copy semantics for enums
// =========================================================================

#[test]
fn enrichment_enum_copy_semantics() {
    let sev = RegressionSeverity::Critical;
    let copy = sev;
    assert_eq!(sev, copy); // original still valid after copy

    let status = RegressionStatus::Waived;
    let copy = status;
    assert_eq!(status, copy);
}

// =========================================================================
// R. Waiver expiry boundary: exactly at now
// =========================================================================

#[test]
fn enrichment_waiver_expires_exactly_at_now_is_valid() {
    // expires_at = now → not expired (> check, not >=)
    let waiver = RegressionWaiver::new("w-1", "w-a", "oncall", 1_700_000_000, "at boundary");
    let input = mk_input(vec![mk_obs("w-a", 100_000, 160_000, 10_000)], vec![waiver]);
    let report = evaluate_performance_regression_gate(&input, &default_policy());
    assert!(!report.blocking);
    assert_eq!(report.regressions[0].status, RegressionStatus::Waived);
}

// =========================================================================
// S. Culprit ranking tracks min p_value across findings
// =========================================================================

#[test]
fn enrichment_culprit_min_p_value_across_findings() {
    let obs1 = RegressionObservation::new(
        "w-a",
        "s1",
        "sha256:m1",
        100_000,
        200_000,
        20_000,
        Some("c1".into()),
    );
    let obs2 = RegressionObservation::new(
        "w-a",
        "s2",
        "sha256:m2",
        100_000,
        160_000,
        5_000,
        Some("c1".into()),
    );
    let input = mk_input(vec![obs1, obs2], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());
    assert_eq!(report.culprit_ranking.len(), 1);
    // Min p_value across the two findings
    assert_eq!(report.culprit_ranking[0].p_value_millionths, 5_000);
}

// =========================================================================
// T. Log event serde with optional fields
// =========================================================================

#[test]
fn enrichment_log_event_with_all_fields_serde() {
    let event = RegressionGateLogEvent {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: PERFORMANCE_REGRESSION_GATE_COMPONENT.to_string(),
        event: "regression_finding".to_string(),
        outcome: "active".to_string(),
        error_code: Some("FE-RGC-703-REGRESSION-0004".to_string()),
        workload_id: Some("w-a".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: RegressionGateLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
    assert_eq!(
        back.error_code,
        Some("FE-RGC-703-REGRESSION-0004".to_string())
    );
    assert_eq!(back.workload_id, Some("w-a".to_string()));
}

// =========================================================================
// U. Large regression saturates to u32::MAX
// =========================================================================

#[test]
fn enrichment_huge_regression_does_not_overflow() {
    // Observed is astronomically larger than baseline
    let obs = RegressionObservation::new(
        "w-huge",
        "scenario",
        "sha256:meta",
        1,
        u64::MAX / 2,
        5_000,
        Some("commit-huge".into()),
    );
    let input = mk_input(vec![obs], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());
    // Should produce a finding without panicking
    assert!(report.blocking);
    assert!(!report.regressions.is_empty());
}

// =========================================================================
// V. Default policy serde roundtrip
// =========================================================================

#[test]
fn enrichment_default_policy_serde_roundtrip() {
    let policy = RegressionGatePolicy::default();
    let json = serde_json::to_string(&policy).unwrap();
    let back: RegressionGatePolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

// =========================================================================
// W. Zero baseline triggers Critical with BASELINE error code
// =========================================================================

#[test]
fn enrichment_zero_baseline_yields_critical_baseline_error() {
    let obs = RegressionObservation::new(
        "w-zero",
        "scenario",
        "sha256:meta",
        0,
        500_000,
        5_000,
        Some("c1".into()),
    );
    let input = mk_input(vec![obs], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());
    assert!(report.blocking);
    assert_eq!(report.highest_severity, RegressionSeverity::Critical);
    assert_eq!(report.regressions.len(), 1);
    assert!(report.regressions[0].error_code.contains("BASELINE"));
    assert_eq!(report.regressions[0].severity, RegressionSeverity::Critical);
    assert_eq!(report.regressions[0].status, RegressionStatus::Active);
}

// =========================================================================
// X. Missing metadata hash triggers High with INTEGRITY error code
// =========================================================================

#[test]
fn enrichment_empty_metadata_hash_yields_high_integrity_error() {
    let obs = RegressionObservation::new("w-meta", "scenario", "", 100_000, 130_000, 10_000, None);
    let input = mk_input(vec![obs], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());
    assert!(report.blocking);
    assert_eq!(report.regressions.len(), 1);
    assert!(report.regressions[0].error_code.contains("INTEGRITY"));
    assert_eq!(report.regressions[0].severity, RegressionSeverity::High);
}

#[test]
fn enrichment_whitespace_only_metadata_hash_yields_integrity_error() {
    let obs = RegressionObservation::new(
        "w-ws", "scenario", "   \t  ", 100_000, 130_000, 10_000, None,
    );
    let input = mk_input(vec![obs], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());
    assert!(report.blocking);
    assert!(report.regressions[0].error_code.contains("INTEGRITY"));
}

// =========================================================================
// Y. Expired waiver on blocking regression emits WAIVER error
// =========================================================================

#[test]
fn enrichment_expired_waiver_on_blocking_regression_emits_waiver_error() {
    // 6% regression (High) with expired waiver → blocking + WAIVER error finding
    let waiver = RegressionWaiver::new("w-exp", "w-a", "oncall", 1_600_000_000, "expired");
    let input = mk_input(vec![mk_obs("w-a", 100_000, 106_000, 10_000)], vec![waiver]);
    let report = evaluate_performance_regression_gate(&input, &default_policy());
    assert!(report.blocking);
    // Should have 2 findings: original + waiver-expired
    assert_eq!(report.regressions.len(), 2);
    let waiver_finding = report
        .regressions
        .iter()
        .find(|f| f.error_code.contains("WAIVER"));
    assert!(waiver_finding.is_some());
    let wf = waiver_finding.unwrap();
    assert_eq!(wf.status, RegressionStatus::Active);
    assert_eq!(wf.waiver_id.as_deref(), Some("w-exp"));
    assert_eq!(wf.waiver_owner.as_deref(), Some("oncall"));
    assert_eq!(wf.waiver_expires_at_unix_seconds, Some(1_600_000_000));
}

// =========================================================================
// Z. Expired waiver on non-blocking warning: no WAIVER error emitted
// =========================================================================

#[test]
fn enrichment_expired_waiver_on_warning_does_not_emit_waiver_error() {
    // 3% regression (Warning, non-blocking) with expired waiver
    // The is_blocking() check means WAIVER error is only emitted for High/Critical
    let waiver = RegressionWaiver::new("w-exp", "w-a", "oncall", 1_600_000_000, "expired");
    let input = mk_input(vec![mk_obs("w-a", 100_000, 103_000, 10_000)], vec![waiver]);
    let report = evaluate_performance_regression_gate(&input, &default_policy());
    // Warning is NOT blocking, so expired waiver is treated as waived
    assert!(!report.blocking);
    assert_eq!(report.regressions.len(), 1);
    assert_eq!(report.regressions[0].status, RegressionStatus::Waived);
    assert!(!report.regressions[0].error_code.contains("WAIVER"));
}

// =========================================================================
// AA. max_culprits = 0 yields empty culprit ranking
// =========================================================================

#[test]
fn enrichment_max_culprits_zero_yields_empty_ranking() {
    let policy = RegressionGatePolicy {
        max_culprits: 0,
        ..default_policy()
    };
    let input = mk_input(vec![mk_obs("w-a", 100_000, 200_000, 5_000)], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &policy);
    assert!(report.blocking);
    assert!(!report.regressions.is_empty());
    assert!(report.culprit_ranking.is_empty());
}

// =========================================================================
// AB. Culprit ranking capped at max_culprits
// =========================================================================

#[test]
fn enrichment_culprit_ranking_capped_at_max() {
    let policy = RegressionGatePolicy {
        max_culprits: 2,
        ..default_policy()
    };
    let input = mk_input(
        vec![
            mk_obs("w-a", 100_000, 200_000, 5_000),
            mk_obs("w-b", 100_000, 150_000, 10_000),
            mk_obs("w-c", 100_000, 140_000, 15_000),
        ],
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &policy);
    assert_eq!(report.culprit_ranking.len(), 2);
    assert_eq!(report.culprit_ranking[0].rank, 1);
    assert_eq!(report.culprit_ranking[1].rank, 2);
}

// =========================================================================
// AC. Full RegressionGateReport serde roundtrip
// =========================================================================

#[test]
fn enrichment_full_report_serde_roundtrip() {
    let input = mk_input(
        vec![
            mk_obs("w-a", 100_000, 200_000, 5_000),
            mk_obs("w-b", 100_000, 103_000, 10_000),
        ],
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &default_policy());
    let json = serde_json::to_string(&report).unwrap();
    let back: frankenengine_engine::performance_regression_gate::RegressionGateReport =
        serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// =========================================================================
// AD. RegressionGateInput serde roundtrip with waivers default
// =========================================================================

#[test]
fn enrichment_input_serde_roundtrip_with_waivers() {
    let input = mk_input(
        vec![mk_obs("w-a", 100_000, 200_000, 5_000)],
        vec![RegressionWaiver::new(
            "w-1",
            "w-a",
            "oncall",
            1_800_000_000,
            "test",
        )],
    );
    let json = serde_json::to_string(&input).unwrap();
    let back: RegressionGateInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

#[test]
fn enrichment_input_serde_roundtrip_no_waivers_default() {
    // Without waivers in JSON, serde(default) should produce empty vec
    let input = mk_input(vec![mk_obs("w-a", 100_000, 100_000, 5_000)], Vec::new());
    let json = serde_json::to_string(&input).unwrap();
    // Remove waivers from JSON to test default behavior
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();
    let mut map = val.as_object().unwrap().clone();
    map.remove("waivers");
    let stripped = serde_json::to_string(&map).unwrap();
    let back: RegressionGateInput = serde_json::from_str(&stripped).unwrap();
    assert!(back.waivers.is_empty());
    assert_eq!(back.trace_id, "trace-test");
}

// =========================================================================
// AE. RegressionWaiver serde roundtrip
// =========================================================================

#[test]
fn enrichment_waiver_serde_roundtrip() {
    let waiver = RegressionWaiver::new("w-42", "wl-alpha", "sre-team", 1_800_000_000, "noisy host");
    let json = serde_json::to_string(&waiver).unwrap();
    let back: RegressionWaiver = serde_json::from_str(&json).unwrap();
    assert_eq!(waiver, back);
}

// =========================================================================
// AF. RegressionGateError stable_code returns expected codes
// =========================================================================

#[test]
fn enrichment_error_stable_code_serialization() {
    let err = RegressionGateError::Serialization("boom".into());
    assert!(err.stable_code().contains("SERIALIZATION"));
}

#[test]
fn enrichment_error_stable_code_report_write() {
    let err = RegressionGateError::ReportWrite {
        path: "/tmp/x".to_string(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
    };
    assert!(err.stable_code().contains("REPORT"));
}

// =========================================================================
// AG. Gate decision log is always the last log entry
// =========================================================================

#[test]
fn enrichment_gate_decision_log_is_last_entry() {
    // Non-blocking case
    let input1 = mk_input(vec![mk_obs("w-a", 100_000, 100_000, 5_000)], Vec::new());
    let report1 = evaluate_performance_regression_gate(&input1, &default_policy());
    let last1 = report1.logs.last().unwrap();
    assert_eq!(last1.event, "gate_decision");
    assert_eq!(last1.outcome, "promote");

    // Blocking case
    let input2 = mk_input(vec![mk_obs("w-a", 100_000, 200_000, 5_000)], Vec::new());
    let report2 = evaluate_performance_regression_gate(&input2, &default_policy());
    let last2 = report2.logs.last().unwrap();
    assert_eq!(last2.event, "gate_decision");
    assert_eq!(last2.outcome, "hold");
}

// =========================================================================
// AH. Determinism: same input permutation produces identical output
// =========================================================================

#[test]
fn enrichment_determinism_under_observation_permutation() {
    let policy = default_policy();
    let obs_a = mk_obs("w-c", 100_000, 140_000, 12_000);
    let obs_b = mk_obs("w-a", 100_000, 130_000, 10_000);
    let obs_c = mk_obs("w-b", 100_000, 111_000, 20_000);
    let input_forward = mk_input(
        vec![obs_a.clone(), obs_b.clone(), obs_c.clone()],
        Vec::new(),
    );
    let input_reversed = mk_input(vec![obs_c, obs_b, obs_a], Vec::new());
    let report_f = evaluate_performance_regression_gate(&input_forward, &policy);
    let report_r = evaluate_performance_regression_gate(&input_reversed, &policy);
    assert_eq!(report_f.regressions, report_r.regressions);
    assert_eq!(report_f.culprit_ranking, report_r.culprit_ranking);
    assert_eq!(report_f.blocking, report_r.blocking);
    assert_eq!(report_f.highest_severity, report_r.highest_severity);
}

// =========================================================================
// AI. Mixed severities: highest active determines report severity
// =========================================================================

#[test]
fn enrichment_mixed_severities_highest_active_wins() {
    let input = mk_input(
        vec![
            mk_obs("w-warn", 100_000, 103_000, 10_000), // Warning (3%)
            mk_obs("w-high", 100_000, 106_000, 10_000), // High (6%)
            mk_obs("w-crit", 100_000, 200_000, 10_000), // Critical (100%)
        ],
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &default_policy());
    assert!(report.blocking);
    assert_eq!(report.highest_severity, RegressionSeverity::Critical);
    assert_eq!(report.severity, RegressionSeverity::Critical);
    assert_eq!(report.regressions.len(), 3);
}

// =========================================================================
// AJ. CulpritCandidate full serde roundtrip with all fields populated
// =========================================================================

#[test]
fn enrichment_culprit_candidate_full_serde_roundtrip() {
    let candidate = CulpritCandidate {
        rank: 3,
        workload_id: "w-full".to_string(),
        severity: RegressionSeverity::Critical,
        score: 3_100_995_000,
        regression_millionths: 100_000,
        p_value_millionths: 5_000,
        error_codes: vec!["FE-RGC-703-REGRESSION-0004".to_string()],
        commit_id: Some("abc123".to_string()),
    };
    let json = serde_json::to_string(&candidate).unwrap();
    let back: CulpritCandidate = serde_json::from_str(&json).unwrap();
    assert_eq!(candidate, back);
    assert!(json.contains("error_codes")); // non-empty, should be serialized
    assert!(json.contains("commit_id"));
}

// =========================================================================
// AK. Observation improvement (observed < baseline) produces no finding
// =========================================================================

#[test]
fn enrichment_improvement_no_finding() {
    let obs = RegressionObservation::new(
        "w-fast",
        "scenario",
        "sha256:meta",
        100_000,
        90_000, // improvement: 10% faster
        5_000,
        Some("c1".into()),
    );
    let input = mk_input(vec![obs], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());
    assert!(!report.blocking);
    assert!(report.regressions.is_empty());
    assert!(report.culprit_ranking.is_empty());
    assert_eq!(report.highest_severity, RegressionSeverity::None);
}

// =========================================================================
// AL. Report component and schema_version are correct
// =========================================================================

#[test]
fn enrichment_report_component_and_schema_version() {
    let input = mk_input(vec![mk_obs("w-a", 100_000, 100_000, 5_000)], Vec::new());
    let report = evaluate_performance_regression_gate(&input, &default_policy());
    assert_eq!(report.component, PERFORMANCE_REGRESSION_GATE_COMPONENT);
    assert_eq!(
        report.schema_version,
        PERFORMANCE_REGRESSION_GATE_SCHEMA_VERSION
    );
    assert_eq!(report.trace_id, "trace-test");
    assert_eq!(report.decision_id, "decision-test");
    assert_eq!(report.policy_id, "policy-test");
}
