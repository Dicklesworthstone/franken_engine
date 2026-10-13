//! Countdown sampling must preserve the externally observable sample schedule.

use super::*;

#[test]
fn countdown_matches_modulo_schedule_for_every_profiling_mode() {
    for instructions in [false, true] {
        for hotspots in [false, true] {
            for interval in [0, 1, 2, 3, 7, 31, 1000, 65537, u64::MAX] {
                let mut profiler = Profiler::new(ProfilingConfig {
                    enable_instruction_profiling: instructions,
                    enable_hotspot_profiling: hotspots,
                    hotspot_sampling_interval: interval,
                    ..Default::default()
                });
                let initial_time = profiler.last_sample_time();
                let operation = Ir3Instruction::LoadInt { dst: 0, value: 7 };
                for executed in 1..=4097_u64 {
                    let before = profiler.last_sample_time();
                    let previous_samples = profiler.sample_count();
                    profiler.record_instruction(&operation);
                    let expected = if instructions && hotspots && interval != 0 {
                        executed / interval
                    } else {
                        0
                    };
                    assert_eq!(profiler.sample_count(), expected);
                    if expected == previous_samples {
                        assert_eq!(profiler.last_sample_time(), before);
                    }
                }
                if profiler.sample_count() == 0 {
                    assert_eq!(profiler.last_sample_time(), initial_time);
                }
                let report = profiler.generate_report("sampling-countdown".to_string());
                if instructions {
                    assert_eq!(report.instruction_stats["LoadInt"].count, 4097);
                } else {
                    assert!(report.instruction_stats.is_empty());
                }
            }
        }
    }
}

#[test]
fn maximum_interval_rearms_without_overflow() {
    let mut profiler = Profiler::new(ProfilingConfig {
        hotspot_sampling_interval: u64::MAX,
        ..Default::default()
    });
    let operation = Ir3Instruction::LoadInt { dst: 0, value: 1 };
    assert_eq!(profiler.instructions_until_sample, u64::MAX);
    profiler.record_instruction(&operation);
    assert_eq!(profiler.instructions_until_sample, u64::MAX - 1);
    assert_eq!(profiler.sample_count(), 0);
    // Reach the final step without spending u64::MAX instructions in a test.
    profiler.instructions_until_sample = 1;
    profiler.record_instruction(&operation);
    assert_eq!(profiler.instructions_until_sample, u64::MAX);
    assert_eq!(profiler.sample_count(), 1);
    profiler.record_instruction(&operation);
    assert_eq!(profiler.instructions_until_sample, u64::MAX - 1);
    assert_eq!(profiler.sample_count(), 1);
}

#[test]
fn timing_only_observations_do_not_advance_instruction_sampling() {
    let mut profiler = Profiler::new(ProfilingConfig {
        hotspot_sampling_interval: 3,
        ..Default::default()
    });
    let operation = Ir3Instruction::LoadInt { dst: 0, value: 1 };
    let before = profiler.last_sample_time();
    for _ in 0..10 {
        profiler.record_instruction_time(&operation, Duration::from_nanos(7));
    }
    assert_eq!(profiler.instructions_until_sample, 3);
    assert_eq!(profiler.sample_count(), 0);
    assert_eq!(profiler.last_sample_time(), before);
    let report = profiler.generate_report("timing-only".to_string());
    assert!(report.instruction_stats.is_empty());
    assert_eq!(report.hotspots.len(), 1);
    assert_eq!(report.hotspots[0].hit_count, 0);
    for _ in 0..3 {
        profiler.record_instruction(&operation);
    }
    assert_eq!(profiler.sample_count(), 1);
    assert_eq!(profiler.instructions_until_sample, 3);
    let report = profiler.generate_report("counted".to_string());
    assert_eq!(report.instruction_stats["LoadInt"].count, 3);
    assert_eq!(report.instruction_stats["LoadInt"].total_time_ns, 70);
}

#[test]
fn sample_count_still_saturates_at_the_reporting_limit() {
    let mut profiler = Profiler::new(ProfilingConfig {
        hotspot_sampling_interval: 1,
        ..Default::default()
    });
    profiler.sample_count = u64::MAX;
    profiler.record_instruction(&Ir3Instruction::LoadInt { dst: 0, value: 1 });
    assert_eq!(profiler.sample_count(), u64::MAX);
    assert_eq!(profiler.instructions_until_sample, 1);
}
