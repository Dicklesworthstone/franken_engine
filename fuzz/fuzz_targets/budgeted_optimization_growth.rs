#![no_main]

use std::collections::BTreeSet;

use frankenengine_engine::budgeted_optimization::{
    BudgetedOptimizationStack, CampaignStatus, EGraphSnapshot, EGraphSnapshotParts,
    ExtractionPolicy, ExtractionResult, OptimizationCampaign, OptimizationError,
    OptimizationEventKind, RewriteFamily, SaturationOutcome,
};
use frankenengine_engine::hash_tiers::ContentHash;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 1024;
const PATHOLOGICAL_THRESHOLD: u64 = 10_000;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT_BYTES {
        return;
    }

    let baseline = baseline_snapshot(data);
    let candidate = candidate_snapshot(data, &baseline);
    let expected_pathological = candidate.is_pathological_growth(&baseline);
    let expected_failure = !candidate.outcome.is_successful() || expected_pathological;

    let mut stack = BudgetedOptimizationStack::new();
    stack
        .register_campaign(OptimizationCampaign::new(
            "growth-campaign",
            "pathological growth fuzz campaign",
            ContentHash::compute(data),
        ))
        .expect("fresh campaign id should register");

    stack
        .record_saturation("growth-campaign", baseline.clone())
        .expect("registered campaign should accept baseline saturation");
    assert_eq!(
        stack
            .get_campaign("growth-campaign")
            .expect("campaign exists")
            .status,
        CampaignStatus::Extracting
    );

    stack
        .record_saturation("growth-campaign", candidate.clone())
        .expect("registered campaign should accept candidate saturation");

    let campaign = stack
        .get_campaign("growth-campaign")
        .expect("campaign exists after candidate saturation");

    if expected_failure {
        assert_eq!(campaign.status, CampaignStatus::Failed);
        assert!(campaign.extraction_result.is_none());
        assert_failure_event(&stack, &candidate, expected_pathological);

        let err = stack
            .record_extraction("growth-campaign", extraction_result(data))
            .expect_err("failed campaigns must not proceed to extraction");
        assert!(matches!(
            err,
            OptimizationError::InvalidCampaignState { .. }
        ));
    } else {
        assert_eq!(campaign.status, CampaignStatus::Extracting);
        stack
            .record_extraction("growth-campaign", extraction_result(data))
            .expect("non-pathological saturated candidates may extract");
        assert_eq!(
            stack
                .get_campaign("growth-campaign")
                .expect("campaign exists after extraction")
                .status,
            CampaignStatus::Completed
        );
    }

    assert_event_sequence_is_contiguous(&stack);
    let serialized = serde_json::to_string(&stack).expect("stack serializes");
    let restored: BudgetedOptimizationStack =
        serde_json::from_str(&serialized).expect("stack deserializes");
    assert_eq!(stack, restored);
});

fn baseline_snapshot(data: &[u8]) -> EGraphSnapshot {
    let iteration_count = read_u64(data, 8) % 32;
    EGraphSnapshot::new(EGraphSnapshotParts {
        class_count: 1 + (read_u64(data, 16) % 256),
        node_count: read_u64(data, 24) % 50_000,
        iteration_count,
        rewrite_count: read_u64(data, 32) % 4_096,
        outcome: SaturationOutcome::Saturated,
        state_hash: state_hash(data, 0, b"baseline"),
        elapsed_ms: read_u64(data, 40) % 60_000,
        peak_memory_bytes: read_u64(data, 48),
    })
}

fn candidate_snapshot(data: &[u8], baseline: &EGraphSnapshot) -> EGraphSnapshot {
    let iteration_delta = 1 + (read_u64(data, 56) % 32);
    let same_iteration_count = byte(data, 1) & 0b1000_0000 != 0;
    let iteration_count = if same_iteration_count {
        baseline.iteration_count
    } else {
        baseline.iteration_count.saturating_add(iteration_delta)
    };

    let node_delta = match byte(data, 0) % 6 {
        0 => read_u64(data, 64) % 1_000,
        1 => iteration_delta.saturating_mul(PATHOLOGICAL_THRESHOLD),
        2 => iteration_delta.saturating_mul(PATHOLOGICAL_THRESHOLD.saturating_add(1)),
        3 => iteration_delta.saturating_mul(
            PATHOLOGICAL_THRESHOLD
                .saturating_add(1)
                .saturating_add(read_u64(data, 72) % 4_096),
        ),
        4 => u64::MAX,
        _ => read_u64(data, 64),
    };

    let node_count = if byte(data, 1) & 0b0100_0000 != 0 {
        baseline.node_count.saturating_sub(node_delta)
    } else {
        baseline.node_count.saturating_add(node_delta)
    };

    EGraphSnapshot::new(EGraphSnapshotParts {
        class_count: 1 + (read_u64(data, 80) % 65_536),
        node_count,
        iteration_count,
        rewrite_count: read_u64(data, 88),
        outcome: outcome_from_byte(byte(data, 2)),
        state_hash: state_hash(data, 16, b"candidate"),
        elapsed_ms: read_u64(data, 96),
        peak_memory_bytes: read_u64(data, 104),
    })
}

fn outcome_from_byte(value: u8) -> SaturationOutcome {
    match value % 4 {
        0 => SaturationOutcome::Saturated,
        1 => SaturationOutcome::NodeLimitReached,
        2 => SaturationOutcome::TimeLimitReached,
        _ => SaturationOutcome::MemoryLimitReached,
    }
}

fn extraction_result(data: &[u8]) -> ExtractionResult {
    let mut families_used = BTreeSet::new();
    families_used.insert(match byte(data, 3) % 4 {
        0 => RewriteFamily::AlgebraicSimplification,
        1 => RewriteFamily::DeadCodeElimination,
        2 => RewriteFamily::PartialEvaluation,
        _ => RewriteFamily::Incrementalization,
    });

    ExtractionResult {
        policy: match byte(data, 4) % 3 {
            0 => ExtractionPolicy::MinCost,
            1 => ExtractionPolicy::MinSize,
            _ => ExtractionPolicy::ProofAware {
                proof_weight_millionths: (read_u64(data, 112) % 1_000_001) as i64,
            },
        },
        total_cost_millionths: read_i64(data, 120),
        extracted_node_count: read_u64(data, 128),
        proven_rewrite_count: read_u64(data, 136),
        output_hash: state_hash(data, 32, b"output"),
        families_used,
    }
}

fn assert_failure_event(
    stack: &BudgetedOptimizationStack,
    candidate: &EGraphSnapshot,
    expected_pathological: bool,
) {
    let failure = stack
        .events()
        .iter()
        .rev()
        .find(|event| event.kind == OptimizationEventKind::CampaignFailed)
        .expect("failed saturation must emit CampaignFailed");

    if !candidate.outcome.is_successful() {
        assert!(
            failure
                .detail
                .contains(&format!("outcome={}", candidate.outcome))
        );
    } else if expected_pathological {
        assert!(failure.detail.contains("pathological_growth"));
        assert!(failure.detail.contains("node_growth_rate="));
    }
}

fn assert_event_sequence_is_contiguous(stack: &BudgetedOptimizationStack) {
    for (expected, event) in stack.events().iter().enumerate() {
        assert_eq!(event.seq, expected as u64);
    }
}

fn state_hash(data: &[u8], offset: usize, fallback: &[u8]) -> ContentHash {
    if offset < data.len() {
        let end = offset.saturating_add(32).min(data.len());
        ContentHash::compute(&data[offset..end])
    } else {
        ContentHash::compute(fallback)
    }
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0_u8; 8];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = byte(data, offset.saturating_add(index));
    }
    u64::from_le_bytes(bytes)
}

fn read_i64(data: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(read_u64(data, offset).to_le_bytes())
}

fn byte(data: &[u8], index: usize) -> u8 {
    data.get(index % data.len()).copied().unwrap_or(0)
}
