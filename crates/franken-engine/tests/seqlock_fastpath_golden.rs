#![forbid(unsafe_code)]

use frankenengine_engine::seqlock_fastpath::{RetryBudgetPolicy, SnapshotFastPath};
use serde::Serialize;

// bd-ub6x8.6.3: migrated from tests/golden_vectors/ to tests/golden/wire_vectors/.
const EXPECTED: &str = include_str!("golden/wire_vectors/seqlock_fastpath_recovery_surface.json");

#[derive(Debug, Serialize)]
struct SeqlockFastPathSnapshot<T> {
    coverage_gap: &'static str,
    policy: RetryBudgetPolicy,
    seeded_first: bool,
    seeded_again: bool,
    initial_read: frankenengine_engine::seqlock_fastpath::FastPathReadResult<T>,
    after_publish: frankenengine_engine::seqlock_fastpath::FastPathReadResult<T>,
    telemetry: frankenengine_engine::seqlock_fastpath::FastPathTelemetry,
}

#[test]
fn seqlock_fastpath_recovery_surface_matches_golden() {
    let policy = RetryBudgetPolicy::new(4, 2);
    let fast_path = SnapshotFastPath::new(policy);

    let seeded_first = fast_path.seed_if_uninitialized(17_u64);
    let seeded_again = fast_path.seed_if_uninitialized(19_u64);
    let initial_read = fast_path.read_clone_or_else(|| 0);

    fast_path.publish(23_u64);
    let after_publish = fast_path.read_clone_or_else(|| 0);

    let snapshot = SeqlockFastPathSnapshot {
        coverage_gap: "seqlock_fastpath recovery and telemetry surface",
        policy,
        seeded_first,
        seeded_again,
        initial_read,
        after_publish,
        telemetry: fast_path.telemetry(),
    };

    let actual = format!("{}\n", serde_json::to_string_pretty(&snapshot).unwrap());
    assert_eq!(actual, EXPECTED);
}
