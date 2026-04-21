use frankenengine_engine::cold_start_aot_governance::{
    ColdStartEvidence, StartupPathKind, aggregate_speedup, compute_speedup,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use proptest::prelude::*;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

proptest! {
    #[test]
    fn compute_speedup_returns_zero_for_zero_baseline(candidate in any::<u64>()) {
        prop_assert_eq!(compute_speedup(0, candidate), 0);
    }

    #[test]
    fn compute_speedup_returns_zero_for_equal_latencies(baseline in 1u64..) {
        prop_assert_eq!(compute_speedup(baseline, baseline), 0);
    }

    #[test]
    fn compute_speedup_sign_matches_latency_order(
        baseline in 1u64..,
        candidate in any::<u64>(),
    ) {
        let speedup = compute_speedup(baseline, candidate);
        if candidate < baseline {
            prop_assert!(speedup > 0);
        } else if candidate > baseline {
            prop_assert!(speedup < 0);
        } else {
            prop_assert_eq!(speedup, 0);
        }
    }

    #[test]
    fn aggregate_speedup_matches_singleton_evidence(
        baseline in 1u64..1_000_000,
        candidate in 0u64..1_000_000,
        sample_count in 1u64..1_000,
    ) {
        let evidence = ColdStartEvidence::new(
            StartupPathKind::ColdStart,
            baseline,
            candidate,
            sample_count,
            epoch(),
        );

        prop_assert_eq!(
            aggregate_speedup(std::slice::from_ref(&evidence)),
            evidence.speedup_millionths
        );
    }

    #[test]
    fn aggregate_speedup_stays_within_input_speedup_bounds(
        baseline_a in 1u64..1_000_000,
        candidate_a in 0u64..1_000_000,
        sample_count_a in 1u64..1_000,
        baseline_b in 1u64..1_000_000,
        candidate_b in 0u64..1_000_000,
        sample_count_b in 1u64..1_000,
    ) {
        let evidence_a = ColdStartEvidence::new(
            StartupPathKind::ColdStart,
            baseline_a,
            candidate_a,
            sample_count_a,
            epoch(),
        );
        let evidence_b = ColdStartEvidence::new(
            StartupPathKind::WarmCache,
            baseline_b,
            candidate_b,
            sample_count_b,
            epoch(),
        );

        let aggregate = aggregate_speedup(&[evidence_a.clone(), evidence_b.clone()]);
        let lower = evidence_a.speedup_millionths.min(evidence_b.speedup_millionths);
        let upper = evidence_a.speedup_millionths.max(evidence_b.speedup_millionths);

        prop_assert!(aggregate >= lower);
        prop_assert!(aggregate <= upper);
    }
}
