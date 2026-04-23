#![no_main]

use frankenengine_engine::performance_regression_gate::{
    PERFORMANCE_REGRESSION_GATE_COMPONENT, PERFORMANCE_REGRESSION_GATE_SCHEMA_VERSION,
    RegressionGateInput, RegressionGatePolicy, RegressionObservation, RegressionSeverity,
    RegressionStatus, RegressionWaiver, evaluate_performance_regression_gate,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 2048;
const MAX_OBSERVATIONS: usize = 12;
const MAX_WAIVERS: usize = 8;
const MAX_NANOS: u64 = 10_000_000_000;
const MAX_NOW: u64 = 4_000_000_000;
const MILLION: u32 = 1_000_000;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT_BYTES {
        return;
    }

    let policy = policy_from_bytes(data);
    let input = input_from_bytes(data);
    let report = evaluate_performance_regression_gate(&input, &policy);

    assert_eq!(
        report.schema_version,
        PERFORMANCE_REGRESSION_GATE_SCHEMA_VERSION
    );
    assert_eq!(report.component, PERFORMANCE_REGRESSION_GATE_COMPONENT);
    assert_eq!(report.trace_id, input.trace_id);
    assert_eq!(report.decision_id, input.decision_id);
    assert_eq!(report.policy_id, input.policy_id);

    let repeated = evaluate_performance_regression_gate(&input, &policy);
    assert_eq!(report, repeated);

    let mut permuted = input.clone();
    permuted.observations.reverse();
    permuted.waivers.reverse();
    let permuted_report = evaluate_performance_regression_gate(&permuted, &policy);
    assert_eq!(report, permuted_report);

    assert_report_invariants(&report, &policy);

    let json = serde_json::to_string(&report).expect("regression report serializes");
    let restored = serde_json::from_str(&json).expect("regression report deserializes");
    assert_eq!(report, restored);
});

fn policy_from_bytes(data: &[u8]) -> RegressionGatePolicy {
    let warning = read_u32(data, 0) % 200_001;
    let fail = warning.saturating_add(read_u32(data, 4) % 300_001);
    let critical = fail.saturating_add(read_u32(data, 8) % 500_001);

    RegressionGatePolicy {
        warning_regression_millionths: warning,
        fail_regression_millionths: fail,
        critical_regression_millionths: critical,
        max_p_value_millionths: read_u32(data, 12) % (MILLION + 1),
        max_culprits: read_usize(data, 16) % (MAX_OBSERVATIONS + 1),
    }
}

fn input_from_bytes(data: &[u8]) -> RegressionGateInput {
    let now = read_u64(data, 24) % MAX_NOW;
    RegressionGateInput::new(
        "trace-benchmark-regression-fuzz",
        "decision-benchmark-regression-fuzz",
        "policy-rgc-703-fuzz",
        now,
        observations_from_bytes(data),
        waivers_from_bytes(data, now),
    )
}

fn observations_from_bytes(data: &[u8]) -> Vec<RegressionObservation> {
    let count = byte(data, 32) as usize % (MAX_OBSERVATIONS + 1);
    let mut observations = Vec::new();

    for index in 0..count {
        let base = 40 + index * 40;
        let workload = format!("workload-{:02}", byte(data, base) % 8);
        let scenario = format!("scenario-{:02}", byte(data, base + 1) % 4);
        let baseline_ns = baseline_nanos(data, base + 8);
        let observed_ns = observed_nanos(data, base + 16, baseline_ns);
        let metadata_hash = if byte(data, base + 2) & 0b0000_0001 == 0 {
            format!("sha256:meta-{index:02x}-{:02x}", byte(data, base + 3))
        } else {
            String::new()
        };
        let commit_id = if byte(data, base + 2) & 0b0000_0010 == 0 {
            Some(format!("commit-{:02x}", byte(data, base + 4)))
        } else {
            None
        };

        observations.push(RegressionObservation::new(
            workload,
            scenario,
            metadata_hash,
            baseline_ns,
            observed_ns,
            read_u32(data, base + 24) % (MILLION + 1),
            commit_id,
        ));
    }

    observations
}

fn waivers_from_bytes(data: &[u8], now: u64) -> Vec<RegressionWaiver> {
    let count = byte(data, 33) as usize % (MAX_WAIVERS + 1);
    let mut waivers = Vec::new();

    for index in 0..count {
        let base = 544 + index * 24;
        let workload = format!("workload-{:02}", byte(data, base) % 8);
        let expiry = if byte(data, base + 1) & 1 == 0 {
            now.saturating_add(read_u64(data, base + 8) % 10_000)
        } else {
            now.saturating_sub(1 + read_u64(data, base + 8) % 10_000)
        };

        waivers.push(RegressionWaiver::new(
            format!("waiver-{index:02x}-{:02x}", byte(data, base + 2)),
            workload,
            format!("owner-{:02x}", byte(data, base + 3)),
            expiry,
            "fuzz-generated waiver",
        ));
    }

    waivers
}

fn assert_report_invariants(
    report: &frankenengine_engine::performance_regression_gate::RegressionGateReport,
    policy: &RegressionGatePolicy,
) {
    let highest_active = report
        .regressions
        .iter()
        .filter(|finding| finding.status == RegressionStatus::Active)
        .map(|finding| finding.severity)
        .max()
        .unwrap_or(RegressionSeverity::None);
    assert_eq!(report.highest_severity, highest_active);
    assert_eq!(report.severity, highest_active);

    let expected_blocking = report.regressions.iter().any(|finding| {
        finding.status == RegressionStatus::Active
            && matches!(
                finding.severity,
                RegressionSeverity::High | RegressionSeverity::Critical
            )
    });
    assert_eq!(report.blocking, expected_blocking);
    assert_eq!(report.is_blocking, expected_blocking);

    assert!(report.culprit_ranking.len() <= policy.max_culprits);
    for (index, candidate) in report.culprit_ranking.iter().enumerate() {
        assert_eq!(candidate.rank, index + 1);
        assert_ne!(candidate.severity, RegressionSeverity::None);
        if index > 0 {
            let previous = &report.culprit_ranking[index - 1];
            assert!(
                previous.score >= candidate.score,
                "culprit ranking must be descending by score"
            );
        }
    }

    assert!(
        report
            .logs
            .iter()
            .any(|event| event.event == "gate_decision")
    );
    for event in &report.logs {
        assert_eq!(event.trace_id, report.trace_id);
        assert_eq!(event.decision_id, report.decision_id);
        assert_eq!(event.policy_id, report.policy_id);
        assert_eq!(event.component, PERFORMANCE_REGRESSION_GATE_COMPONENT);
    }
}

fn baseline_nanos(data: &[u8], offset: usize) -> u64 {
    if byte(data, offset) & 0b1000_0000 == 0 {
        1 + read_u64(data, offset) % MAX_NANOS
    } else {
        0
    }
}

fn observed_nanos(data: &[u8], offset: usize, baseline: u64) -> u64 {
    match byte(data, offset) % 5 {
        0 => baseline,
        1 => baseline.saturating_add(baseline / 100),
        2 => baseline.saturating_add(baseline / 20),
        3 => baseline.saturating_add(baseline / 5),
        _ => read_u64(data, offset) % MAX_NANOS,
    }
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0_u8; 8];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = byte(data, offset.saturating_add(index));
    }
    u64::from_le_bytes(bytes)
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    let mut bytes = [0_u8; 4];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = byte(data, offset.saturating_add(index));
    }
    u32::from_le_bytes(bytes)
}

fn read_usize(data: &[u8], offset: usize) -> usize {
    read_u64(data, offset) as usize
}

fn byte(data: &[u8], offset: usize) -> u8 {
    data.get(offset % data.len()).copied().unwrap_or(0)
}
