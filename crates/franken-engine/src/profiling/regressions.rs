//! Report-equivalence checks for dense opcode profiling.

use super::*;
use crate::ir_contract::{CapabilityTag, RegRange};

fn instructions() -> Vec<Ir3Instruction> {
    vec![
        Ir3Instruction::LoadInt {
            dst: 0,
            value: -1,
        },
        Ir3Instruction::LoadFloat {
            dst: 1,
            bits: (-0.0_f64).to_bits(),
        },
        Ir3Instruction::LoadBool {
            dst: 2,
            value: true,
        },
        Ir3Instruction::Add {
            dst: 3,
            lhs: 0,
            rhs: 1,
        },
        Ir3Instruction::HostCall {
            capability: CapabilityTag("large operand that must not be formatted".repeat(4096)),
            args: RegRange { start: 0, count: 4 },
            dst: 4,
        },
        Ir3Instruction::LoadBigInt {
            dst: 5,
            value: "9".repeat(4096),
        },
        Ir3Instruction::SetPropertySloppy {
            obj: 0,
            key: 1,
            val: 2,
        },
        Ir3Instruction::CreateDataProperty {
            obj: 0,
            key: 1,
            val: 2,
        },
        Ir3Instruction::CreateArrowClosure {
            dst: 0,
            function_index: 1,
            capture_count: 2,
        },
        Ir3Instruction::CreateAsyncArrowClosure {
            dst: 0,
            function_index: 1,
            capture_count: 2,
        },
        Ir3Instruction::LoadName {
            dst: 0,
            name_pool_index: 1,
            allow_missing: true,
        },
        Ir3Instruction::ResolveNameStatus {
            dst: 0,
            name_pool_index: 1,
        },
        Ir3Instruction::DeleteName {
            dst: 0,
            name_pool_index: 1,
        },
        Ir3Instruction::PutName {
            src: 0,
            name_pool_index: 1,
            strict: true,
        },
        Ir3Instruction::PutNameWithStatus {
            src: 0,
            status: 2,
            name_pool_index: 1,
            strict: false,
        },
        Ir3Instruction::CreatePerIterationBinding {
            name_pool_index: 1,
            kind: 1,
            preserve_state: true,
        },
        Ir3Instruction::ModuleAwaitValue {
            promise_reg: 0,
        },
        Ir3Instruction::Inc {
            dst: 0,
            src: 1,
        },
        Ir3Instruction::Dec {
            dst: 0,
            src: 1,
        },
        Ir3Instruction::Halt,
        Ir3Instruction::EndTry,
        Ir3Instruction::EnterFinally,
        Ir3Instruction::EndFinally,
        Ir3Instruction::DiscardAbruptCompletion,
        Ir3Instruction::PushScope,
        Ir3Instruction::PopScope,
    ]
}

fn legacy_name(instruction: &Ir3Instruction) -> String {
    let debug = format!("{instruction:?}");
    debug
        .split(" {")
        .next()
        .unwrap()
        .split('(')
        .next()
        .unwrap()
        .into()
}

#[test]
fn names_and_dense_indices_preserve_debug_variant_names() {
    let mut names = std::collections::BTreeSet::new();
    for &name in opcode::NAMES {
        assert!(names.insert(name), "duplicate opcode name: {name}");
    }
    for instruction in instructions() {
        assert_eq!(instruction_name(&instruction), legacy_name(&instruction));
        assert!(opcode::index(&instruction) < opcode::NAMES.len());
    }
}

#[test]
fn reports_match_legacy_maps_for_every_counting_and_timing_configuration() {
    let instructions = instructions();
    for counting in [false, true] {
        for timing in [false, true] {
            for interval in [0, 1, 4, 1000] {
                let mut profiler = Profiler::new(ProfilingConfig {
                    enable_instruction_profiling: counting,
                    enable_hotspot_profiling: timing,
                    hotspot_sampling_interval: interval,
                    ..Default::default()
                });
                let mut counts = BTreeMap::<String, u64>::new();
                let mut times = BTreeMap::<String, Duration>::new();
                // Reverse visits make insertion order disagree with name order.
                for round in 0..7 {
                    for (index, instruction) in instructions.iter().enumerate().rev() {
                        let name = legacy_name(instruction);
                        profiler.record_instruction(instruction);
                        if counting {
                            *counts.entry(name.clone()).or_default() += 1;
                        }
                        // Leave some opcodes untimed and explicitly time others
                        // at zero. Equal totals exercise deterministic tie order.
                        if (index + round) % 3 != 0 {
                            let duration = Duration::from_nanos((index % 3) as u64);
                            profiler.record_instruction_time(instruction, duration);
                            if timing {
                                *times.entry(name).or_default() += duration;
                            }
                        }
                    }
                }
                let report = profiler.generate_report("equivalence".into());
                assert_eq!(report.instruction_stats.len(), counts.len());
                for (name, count) in &counts {
                    let actual = &report.instruction_stats[name];
                    let ns = times.get(name).copied().unwrap_or_default().as_nanos() as u64;
                    assert_eq!(actual.count, *count);
                    assert_eq!(actual.total_time_ns, ns);
                    assert_eq!(actual.average_time_ns, ns / count);
                }
                let mut expected: Vec<_> = times.iter().collect();
                expected.sort_by(|a, b| b.1.cmp(a.1));
                expected.truncate(10);
                assert_eq!(report.hotspots.len(), expected.len());
                for (actual, (name, duration)) in report.hotspots.iter().zip(expected) {
                    let count = counts.get(name).copied().unwrap_or(0);
                    assert_eq!(actual.name, *name);
                    assert_eq!(actual.hit_count, count);
                    assert_eq!(
                        actual.average_time_ns,
                        (duration.as_nanos() as u64).checked_div(count).unwrap_or(0)
                    );
                }
                let expected_samples = if counting && timing && interval > 0 {
                    (7 * instructions.len()) as u64 / interval
                } else {
                    0
                };
                assert_eq!(profiler.sample_count(), expected_samples);
            }
        }
    }
}

#[test]
fn timing_only_zero_sample_is_not_lost_or_reported_as_a_counted_instruction() {
    let mut profiler = Profiler::new(ProfilingConfig {
        enable_instruction_profiling: false,
        ..Default::default()
    });
    profiler.record_instruction_time(&Ir3Instruction::Halt, Duration::ZERO);
    let report = profiler.generate_report("timing-only".into());
    assert!(report.instruction_stats.is_empty());
    assert_eq!(report.hotspots.len(), 1);
    assert_eq!(report.hotspots[0].name, "Halt");
    assert_eq!(report.hotspots[0].hit_count, 0);
    assert_eq!(report.hotspots[0].average_time_ns, 0);
}

#[test]
fn operand_changes_share_the_same_counter_without_changing_storage() {
    let mut profiler = Profiler::new(ProfilingConfig {
        enable_hotspot_profiling: false,
        ..Default::default()
    });
    let storage = std::ptr::from_ref(profiler.opcodes.as_ref());
    for value in 0..10_000 {
        profiler.record_instruction(&Ir3Instruction::LoadInt { dst: 0, value });
    }
    assert_eq!(std::ptr::from_ref(profiler.opcodes.as_ref()), storage);
    let report = profiler.generate_report("operands".into());
    assert_eq!(report.instruction_stats.len(), 1);
    assert_eq!(report.instruction_stats["LoadInt"].count, 10_000);
}
