#![no_main]

use frankenengine_engine::cold_start_aot_governance::{
    BenchmarkVerdict, ColdStartEvidence, GovernanceConfig, GovernanceError, GovernanceVerdict,
    ParityCheckKind, ParityResult, RollbackTrigger, StartupPathKind, evaluate_cold_start_at_epoch,
    produce_receipt, validate_config, validate_evidence_freshness,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 2048;
const MAX_EVIDENCE: usize = 8;
const MAX_PARITY: usize = 8;
const MAX_NANOS: u64 = 10_000_000_000;
const MAX_SAMPLES: u64 = 256;
const MAX_EPOCH: u64 = 512;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT_BYTES {
        return;
    }

    let config = config_from_bytes(data);
    validate_config(&config).expect("fuzz config stays within documented bounds");

    let decision_epoch = SecurityEpoch::from_raw(read_u64(data, 32) % MAX_EPOCH);
    let evidence = evidence_from_bytes(data);
    let parity = parity_from_bytes(data);

    let verdict = evaluate_cold_start_at_epoch(decision_epoch, &evidence, &parity, &config);
    assert_deterministic(decision_epoch, &evidence, &parity, &config, &verdict);
    assert_error_precedence(decision_epoch, &evidence, &config, &verdict);

    if let Ok(verdict) = verdict {
        assert_verdict_invariants(&verdict, &evidence, &config);
        let receipt = produce_receipt(decision_epoch, &evidence, &parity, &verdict);
        let receipt_again = produce_receipt(decision_epoch, &evidence, &parity, &verdict);
        assert_eq!(receipt, receipt_again);

        let verdict_json = serde_json::to_string(&verdict).expect("verdict serializes");
        let restored_verdict: GovernanceVerdict =
            serde_json::from_str(&verdict_json).expect("verdict deserializes");
        assert_eq!(verdict, restored_verdict);

        let receipt_json = serde_json::to_string(&receipt).expect("receipt serializes");
        let restored_receipt = serde_json::from_str(&receipt_json).expect("receipt deserializes");
        assert_eq!(receipt, restored_receipt);
    }
});

fn config_from_bytes(data: &[u8]) -> GovernanceConfig {
    GovernanceConfig {
        min_benchmark_samples: 1 + read_u64(data, 0) % MAX_SAMPLES,
        max_regression_millionths: read_u64(data, 8) % 1_000_001,
        require_semantic_parity: byte(data, 16) & 1 != 0,
        require_observability_proof: byte(data, 16) & 2 != 0,
        max_staleness_epochs: 1 + read_u64(data, 24) % 64,
        min_speedup_threshold: read_u64(data, 40) % 1_000_001,
        max_divergence: read_u64(data, 48) % 1_000_001,
    }
}

fn evidence_from_bytes(data: &[u8]) -> Vec<ColdStartEvidence> {
    let count = (byte(data, 56) as usize % (MAX_EVIDENCE + 1)).min(data.len());
    let mut evidence = Vec::new();

    for index in 0..count {
        let base = 64 + index * 40;
        let baseline_nanos = 1 + read_u64(data, base) % MAX_NANOS;
        let candidate_nanos = 1 + read_u64(data, base + 8) % MAX_NANOS;
        let sample_count = read_u64(data, base + 16) % MAX_SAMPLES;
        let epoch = SecurityEpoch::from_raw(read_u64(data, base + 24) % MAX_EPOCH);
        evidence.push(ColdStartEvidence::new(
            startup_path(byte(data, base + 32)),
            baseline_nanos,
            candidate_nanos,
            sample_count,
            epoch,
        ));
    }

    evidence
}

fn parity_from_bytes(data: &[u8]) -> Vec<ParityResult> {
    let count = byte(data, 57) as usize % (MAX_PARITY + 1);
    let mut parity = Vec::new();

    for index in 0..count {
        let base = 384 + index * 24;
        parity.push(ParityResult::new(
            parity_kind(byte(data, base)),
            byte(data, base + 1) & 1 != 0,
            read_u64(data, base + 8) % 1_000_001,
            evidence_slice(data, base + 16),
        ));
    }

    parity
}

fn assert_deterministic(
    decision_epoch: SecurityEpoch,
    evidence: &[ColdStartEvidence],
    parity: &[ParityResult],
    config: &GovernanceConfig,
    verdict: &Result<GovernanceVerdict, GovernanceError>,
) {
    let repeated = evaluate_cold_start_at_epoch(decision_epoch, evidence, parity, config);
    assert_eq!(verdict, &repeated);
}

fn assert_error_precedence(
    decision_epoch: SecurityEpoch,
    evidence: &[ColdStartEvidence],
    config: &GovernanceConfig,
    verdict: &Result<GovernanceVerdict, GovernanceError>,
) {
    if evidence.is_empty() {
        assert_eq!(verdict, &Err(GovernanceError::EmptyEvidence));
        return;
    }

    if let Err(stale) = validate_evidence_freshness(decision_epoch, evidence, config) {
        assert_eq!(verdict, &Err(stale));
        return;
    }

    let total_samples = evidence
        .iter()
        .map(|entry| entry.sample_count)
        .fold(0_u64, u64::saturating_add);
    if total_samples < config.min_benchmark_samples {
        assert_eq!(
            verdict,
            &Err(GovernanceError::InsufficientSamples {
                have: total_samples,
                need: config.min_benchmark_samples,
            })
        );
    }
}

fn assert_verdict_invariants(
    verdict: &GovernanceVerdict,
    evidence: &[ColdStartEvidence],
    config: &GovernanceConfig,
) {
    match verdict {
        GovernanceVerdict::Approved => {
            assert!(verdict.allows_publication());
            assert!(!verdict.requires_rollback());
            assert!(
                evidence
                    .iter()
                    .any(|entry| entry.verdict(config) == BenchmarkVerdict::Faster)
            );
            assert!(
                evidence
                    .iter()
                    .all(|entry| entry.verdict(config) != BenchmarkVerdict::Slower)
            );
        }
        GovernanceVerdict::Blocked { reasons } => {
            assert!(!reasons.is_empty());
            assert!(!verdict.allows_publication());
            assert!(!verdict.requires_rollback());
        }
        GovernanceVerdict::Rollback { triggers } => {
            assert!(!triggers.is_empty());
            assert!(!verdict.allows_publication());
            assert!(verdict.requires_rollback());
            assert_expected_rollback_triggers(triggers, evidence, config);
        }
    }
}

fn assert_expected_rollback_triggers(
    triggers: &[RollbackTrigger],
    evidence: &[ColdStartEvidence],
    config: &GovernanceConfig,
) {
    let performance_regression = evidence.iter().any(|entry| {
        entry.speedup_millionths < 0
            && entry.speedup_millionths.unsigned_abs() > config.max_regression_millionths
    });
    if performance_regression {
        assert!(triggers.contains(&RollbackTrigger::PerformanceRegression));
    }

    let observability_mismatch = config.require_observability_proof
        && evidence
            .iter()
            .any(|entry| entry.path_kind.is_optimised() && entry.sample_count == 0);
    if observability_mismatch {
        assert!(triggers.contains(&RollbackTrigger::ObservabilityMismatch));
    }
}

fn startup_path(value: u8) -> StartupPathKind {
    StartupPathKind::ALL[value as usize % StartupPathKind::ALL.len()]
}

fn parity_kind(value: u8) -> ParityCheckKind {
    ParityCheckKind::ALL[value as usize % ParityCheckKind::ALL.len()]
}

fn evidence_slice(data: &[u8], offset: usize) -> &[u8] {
    if offset >= data.len() {
        return b"governance-verdict-fuzz";
    }
    let end = offset.saturating_add(8).min(data.len());
    &data[offset..end]
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0_u8; 8];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = byte(data, offset.saturating_add(index));
    }
    u64::from_le_bytes(bytes)
}

fn byte(data: &[u8], offset: usize) -> u8 {
    data.get(offset).copied().unwrap_or(0)
}
