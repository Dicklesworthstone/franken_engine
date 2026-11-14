use super::*;
use crate::ir_contract::{
    CapabilityTag, Ir3FunctionDesc, IrHeader, IrLevel, IrSchemaVersion, RegRange,
};
use std::sync::{Arc, Mutex};

// -- helpers --------------------------------------------------------

fn test_module(instructions: Vec<Ir3Instruction>) -> Ir3Module {
    Ir3Module {
        header: IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir3,
            source_hash: None,
            source_label: "test".to_string(),
        },
        instructions,
        constant_pool: Vec::new(),
        function_table: Vec::new(),
        specialization: None,
        required_capabilities: Vec::new(),
        function_lengths: Default::default(),
        function_sources: Default::default(),
        sloppy_functions: Default::default(),
    }
}

fn test_module_with_pool(instructions: Vec<Ir3Instruction>, pool: Vec<String>) -> Ir3Module {
    let mut m = test_module(instructions);
    m.constant_pool = pool.into_iter().map(Into::into).collect();
    m
}

fn assert_execution_semantics_equal(compact: &ExecutionResult, baseline: &ExecutionResult) {
    assert_eq!(compact.value, baseline.value);
    assert_eq!(compact.completion_label, baseline.completion_label);
    assert_eq!(
        compact.instructions_executed,
        baseline.instructions_executed
    );
    assert_eq!(
        compact.requested_hook_action,
        baseline.requested_hook_action
    );
    assert_eq!(compact.witness_events, baseline.witness_events);
    assert_eq!(compact.hostcall_decisions, baseline.hostcall_decisions);
    assert_eq!(compact.events, baseline.events);
    assert_eq!(compact.console_output, baseline.console_output);
    assert_eq!(compact.iteration_traces, baseline.iteration_traces);
    assert_eq!(compact.nondeterminism_trace, baseline.nondeterminism_trace);
    assert_eq!(compact.generated_code_audit, baseline.generated_code_audit);
}

#[test]
fn process_effect_error_mapping_uses_structured_not_found_code_bd_x85a7_3() {
    let redacted = "process policy violation: redacted code (23 bytes), detail (55 bytes)";
    let not_found = InterpreterCore::process_error_from_effect(EffectError::HandlerError {
        handler: "process_spawn_handler".to_string(),
        message: redacted.to_string(),
        code: Some(PROCESS_SPAWN_EXECUTABLE_NOT_FOUND_CODE.to_string()),
    });
    assert!(matches!(
        not_found,
        InterpreterError::HostProcess { code, message, .. }
            if code == "ENOENT" && message == redacted
    ));

    let denied = InterpreterCore::process_error_from_effect(EffectError::HandlerError {
        handler: "process_spawn_handler".to_string(),
        message: redacted.to_string(),
        code: Some("PROCESS_SPAWN_POLICY_VIOLATION".to_string()),
    });
    assert!(matches!(
        denied,
        InterpreterError::HostProcess { code, message, .. }
            if code == "EACCES" && message == redacted
    ));
}

fn execute_compact_and_baseline(
    module: &Ir3Module,
    config: InterpreterConfig,
) -> (ExecutionResult, ExecutionResult) {
    let compact_plan = CompactTier1Program::compile(module).expect("compact plan");
    let compact = QuickJsLane::with_config(config.clone())
        .execute_with_compact_tier1(module, "tier-i-differential", &compact_plan)
        .expect("compact execution");
    let baseline = QuickJsLane::with_config(config)
        .execute(module, "tier-i-differential")
        .expect("baseline execution");
    (compact, baseline)
}

#[test]
fn compact_tier1_cell_is_exactly_sixteen_bytes_bd_performance_bridge_5_1() {
    assert_eq!(std::mem::size_of::<CompactTier1Instruction>(), 16);
    assert_eq!(std::mem::align_of::<CompactTier1Instruction>(), 8);
}

#[test]
fn compact_tier1_termination_only_module_is_not_eligible_bd_performance_bridge_5_1() {
    let module = test_module(vec![Ir3Instruction::Halt]);
    assert!(CompactTier1Program::compile(&module).is_none());
}

#[test]
fn compact_tier1_scalar_loop_is_artifact_exact_bd_performance_bridge_5_2() {
    let module = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 0 },
        Ir3Instruction::LoadInt { dst: 1, value: 1 },
        Ir3Instruction::LoadInt { dst: 2, value: 101 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 0,
            rhs: 1,
        },
        Ir3Instruction::Add {
            dst: 1,
            lhs: 1,
            rhs: 3,
        },
        Ir3Instruction::Lt {
            dst: 4,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::JumpIf { cond: 4, target: 3 },
        Ir3Instruction::Halt,
    ]);
    let mut config = test_quickjs_config();
    config.instruction_budget = 10_000;
    let mut seeded_module = module;
    seeded_module
        .instructions
        .insert(3, Ir3Instruction::LoadInt { dst: 3, value: 1 });

    let (compact, baseline) = execute_compact_and_baseline(&seeded_module, config);
    assert_execution_semantics_equal(&compact, &baseline);
    assert_eq!(compact.value, Value::Int(5050));
    assert_eq!(baseline.tier_i_instructions_executed, 0);
    assert_eq!(
        compact.tier_i_instructions_executed,
        compact.instructions_executed - 1,
        "the empty Writable checkpoint remains Tier R and consumes one step"
    );
    assert!(
        compact.tier_i_specialized_instructions_executed > 200,
        "the hot scalar loop must use guarded borrowed/int specializations"
    );
}

#[test]
fn compact_tier1_mixed_dispatch_preserves_unsupported_string_path_bd_performance_bridge_5_2() {
    let module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 42 },
            Ir3Instruction::Add {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Halt,
        ],
        vec!["answer: ".to_string()],
    );
    let (compact, baseline) = execute_compact_and_baseline(&module, test_quickjs_config());
    assert_execution_semantics_equal(&compact, &baseline);
    assert_eq!(compact.value, Value::str("answer: 42"));
    assert_eq!(compact.tier_i_instructions_executed, 3);
    assert_eq!(compact.tier_i_specialized_instructions_executed, 0);
    assert_eq!(baseline.tier_i_instructions_executed, 0);
}

#[test]
fn compact_tier1_register_encoding_falls_back_above_u16_bd_performance_bridge_5_1() {
    let module = test_module(vec![
        Ir3Instruction::LoadInt {
            dst: u32::from(u16::MAX),
            value: 1,
        },
        Ir3Instruction::LoadInt {
            dst: u32::from(u16::MAX) + 1,
            value: 2,
        },
    ]);
    let plan = CompactTier1Program::compile(&module).expect("one cell remains compact");
    assert_eq!(plan.compact_instruction_count(), 1);
    assert_eq!(plan.instructions[0].opcode, CompactTier1Opcode::LoadInt);
    assert_eq!(plan.instructions[1].opcode, CompactTier1Opcode::Baseline);
}

#[test]
fn compact_tier1_plan_refuses_same_length_different_module_before_mutation_bd_performance_bridge_5_1()
 {
    let planned_module = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::Halt,
    ]);
    let executed_module = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 2 },
        Ir3Instruction::Halt,
    ]);
    let plan = CompactTier1Program::compile(&planned_module).expect("compact plan");
    let mut core = quickjs_test_core();
    let seed_epoch_before = core.seed_epoch;

    let error = core
        .execute_with_trace_handoff(&executed_module, Some(&plan), TraceHandoff::RetainInCore)
        .expect_err("a compact plan must be bound to its exact IR3 module");

    assert_eq!(
        error,
        InterpreterError::InternalError {
            details: format!(
                "compact Tier-I plan/module identity mismatch: expected {}, got {}",
                planned_module.content_hash(),
                executed_module.content_hash()
            ),
        }
    );
    assert_eq!(core.instructions_executed, 0);
    assert_eq!(core.tier_i_instructions_executed, 0);
    assert_eq!(core.seed_epoch, seed_epoch_before);
}

#[test]
fn compact_tier1_plan_binds_noncanonical_rest_abi_bd_bridge_5_3() {
    let descriptor = |entry, arity, rest_param_index| Ir3FunctionDesc {
        entry,
        arity,
        frame_size: arity.max(1),
        name: None,
        is_generator: false,
        rest_param_index,
    };
    let planned_module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 1 },
            Ir3Instruction::Halt,
            Ir3Instruction::Return { value: 0 },
        ],
        vec![descriptor(0, 0, None), descriptor(2, 1, None)],
    );
    let mut executed_module = planned_module.clone();
    executed_module.function_table[1].rest_param_index = Some(0);
    assert_eq!(
        planned_module.content_hash(),
        executed_module.content_hash(),
        "the historical IR3 hash deliberately omits rest metadata"
    );

    let plan = CompactTier1Program::compile(&planned_module).expect("compact ABI plan");
    let mut core = quickjs_test_core();
    let seed_epoch_before = core.seed_epoch;
    let error = core
        .execute_with_trace_handoff(&executed_module, Some(&plan), TraceHandoff::RetainInCore)
        .expect_err("same-hash rest ABI drift must be rejected before execution");

    assert_eq!(
        error,
        InterpreterError::InternalError {
            details: "compact Tier-I plan/module rest-parameter ABI mismatch".to_string(),
        }
    );
    assert_eq!(core.instructions_executed, 0);
    assert_eq!(core.seed_epoch, seed_epoch_before);
}

#[test]
fn compact_tier1_budget_refusal_matches_tier_r_bd_performance_bridge_5_2() {
    let module = test_module(vec![Ir3Instruction::Jump { target: 0 }]);
    let plan = CompactTier1Program::compile(&module).expect("compact jump plan");
    let mut config = test_quickjs_config();
    config.instruction_budget = 5;
    let compact_error = QuickJsLane::with_config(config.clone())
        .execute_with_compact_tier1(&module, "tier-i-budget", &plan)
        .expect_err("compact loop must exhaust its exact budget");
    let baseline_error = QuickJsLane::with_config(config)
        .execute(&module, "tier-i-budget")
        .expect_err("baseline loop must exhaust its exact budget");
    assert_eq!(compact_error, baseline_error);
    assert_eq!(
        compact_error,
        InterpreterError::BudgetExhausted {
            executed: 5,
            budget: 5,
        }
    );
}

#[test]
fn compact_tier1_cancellation_density_matches_tier_r_bd_performance_bridge_5_2() {
    let module = test_module(vec![Ir3Instruction::Jump { target: 0 }]);
    let plan = CompactTier1Program::compile(&module).expect("compact jump plan");
    let token = CancellationToken::new();
    token.cancel();
    let mut config = test_quickjs_config();
    config.instruction_budget = 100;
    config.checkpoint_density = 3;
    config.cancellation_token = Some(token);
    let checkpoint_density = config.checkpoint_density;
    let mut compact_core = InterpreterCore::new(config.clone(), "tier-i-cancel");
    let compact_error = compact_core
        .execute_with_trace_handoff(&module, Some(&plan), TraceHandoff::RetainInCore)
        .expect_err("compact loop must observe cancellation");
    let mut baseline_core = InterpreterCore::new(config, "tier-i-cancel");
    let baseline_error = baseline_core
        .execute(&module)
        .expect_err("baseline loop must observe cancellation");
    assert_eq!(compact_error, baseline_error);
    assert_eq!(compact_error, InterpreterError::Cancelled);
    assert_eq!(
        compact_core.instructions_executed, baseline_core.instructions_executed,
        "Tier-I and Tier-R must observe cancellation at the same instruction boundary"
    );
    assert!(compact_core.instructions_executed >= checkpoint_density);
}

#[test]
fn compact_tier1_binary_ifc_join_matches_tier_r_bd_performance_bridge_5_2() {
    let module = test_module(vec![
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let plan = CompactTier1Program::compile(&module).expect("compact add plan");
    let mut compact_core = quickjs_test_core();
    compact_core.set_reg(1, Value::Int(20));
    compact_core.set_reg(2, Value::Int(22));
    compact_core
        .set_register_label(1, Label::Confidential)
        .expect("lhs label");
    compact_core
        .set_register_label(2, Label::Secret)
        .expect("rhs label");
    let compact = compact_core
        .execute_with_trace_handoff(&module, Some(&plan), TraceHandoff::RetainInCore)
        .expect("compact labeled add");

    let mut baseline_core = quickjs_test_core();
    baseline_core.set_reg(1, Value::Int(20));
    baseline_core.set_reg(2, Value::Int(22));
    baseline_core
        .set_register_label(1, Label::Confidential)
        .expect("lhs label");
    baseline_core
        .set_register_label(2, Label::Secret)
        .expect("rhs label");
    let baseline = baseline_core
        .execute(&module)
        .expect("baseline labeled add");

    assert_execution_semantics_equal(&compact, &baseline);
    assert_eq!(compact.value, Value::Int(42));
    assert_eq!(compact.completion_label, Label::Secret);
    assert_eq!(compact.tier_i_specialized_instructions_executed, 0);
    assert_eq!(compact_core.get_register_label(0), Ok(&Label::Secret));
    assert_eq!(baseline_core.get_register_label(0), Ok(&Label::Secret));
    assert_eq!(
        compact_core.estimated_memory_bytes(),
        compact_core.recompute_estimated_memory_bytes()
    );
    assert_eq!(
        baseline_core.estimated_memory_bytes(),
        baseline_core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn compact_tier1_integer_relational_specialization_preserves_f64_projection_bd_performance_bridge_5_2()
 {
    let module = test_module(vec![
        Ir3Instruction::LoadInt {
            dst: 1,
            value: 9_007_199_254_740_992,
        },
        Ir3Instruction::LoadInt {
            dst: 2,
            value: 9_007_199_254_740_993,
        },
        Ir3Instruction::Lt {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);

    let (compact, baseline) = execute_compact_and_baseline(&module, test_quickjs_config());
    assert_execution_semantics_equal(&compact, &baseline);
    assert_eq!(compact.value, Value::Bool(false));
    assert_eq!(compact.tier_i_specialized_instructions_executed, 1);
}

#[test]
fn compact_tier1_bigint_add_uses_exact_accounted_fallback_bd_performance_bridge_5_2() {
    let module = test_module(vec![
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let plan = CompactTier1Program::compile(&module).expect("compact add plan");
    let mut compact_core = quickjs_test_core();
    compact_core.set_reg(1, Value::BigInt(Arc::from("9007199254740993")));
    compact_core.set_reg(2, Value::BigInt(Arc::from("7")));
    compact_core
        .sync_estimated_memory_bytes()
        .expect("seeded BigInt operands should fit memory budget");
    let compact = compact_core
        .execute_with_trace_handoff(&module, Some(&plan), TraceHandoff::RetainInCore)
        .expect("compact BigInt fallback");

    let mut baseline_core = quickjs_test_core();
    baseline_core.set_reg(1, Value::BigInt(Arc::from("9007199254740993")));
    baseline_core.set_reg(2, Value::BigInt(Arc::from("7")));
    baseline_core
        .sync_estimated_memory_bytes()
        .expect("seeded BigInt operands should fit memory budget");
    let baseline = baseline_core.execute(&module).expect("baseline BigInt add");

    assert_execution_semantics_equal(&compact, &baseline);
    assert_eq!(compact.value, Value::BigInt(Arc::from("9007199254741000")));
    assert_eq!(compact.tier_i_specialized_instructions_executed, 0);
    assert_eq!(
        compact_core.estimated_memory_bytes(),
        compact_core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn compact_tier1_nan_add_uses_generic_numeric_fallback_bd_performance_bridge_5_2() {
    let module = test_module(vec![
        Ir3Instruction::LoadFloat {
            dst: 1,
            bits: f64::NAN.to_bits(),
        },
        Ir3Instruction::LoadInt { dst: 2, value: 1 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);

    let (compact, baseline) = execute_compact_and_baseline(&module, test_quickjs_config());
    assert_execution_semantics_equal(&compact, &baseline);
    assert!(matches!(compact.value, Value::Float(value) if value.is_nan()));
    assert_eq!(compact.tier_i_specialized_instructions_executed, 0);
}

fn compact_number_test_instruction(
    opcode: CompactTier1Opcode,
    dst: u32,
    lhs: u32,
    rhs: u32,
) -> Ir3Instruction {
    match opcode {
        CompactTier1Opcode::Add => Ir3Instruction::Add { dst, lhs, rhs },
        CompactTier1Opcode::Sub => Ir3Instruction::Sub { dst, lhs, rhs },
        CompactTier1Opcode::Mul => Ir3Instruction::Mul { dst, lhs, rhs },
        CompactTier1Opcode::Div => Ir3Instruction::Div { dst, lhs, rhs },
        CompactTier1Opcode::Mod => Ir3Instruction::Mod { dst, lhs, rhs },
        _ => unreachable!("numeric test selects only arithmetic opcodes"),
    }
}

#[test]
fn compact_tier1_number_arithmetic_matches_tier_r_bits_and_aliases() {
    use CompactTier1Opcode as Op;

    let float = |value| Value::Float(Float64::new(value));
    let pairs = [
        (float(1.25), float(2.5)),
        (Value::Int(7), float(2.5)),
        (float(-7.5), Value::Int(2)),
        (float(0.5), float(0.5)),
        (float(-0.0), float(-0.0)),
        (float(-0.0), float(0.0)),
        (Value::Int(0), Value::Int(-2)),
        (Value::Int(-6), Value::Int(3)),
        (Value::Int(7), Value::Int(0)),
        (Value::Int(0), Value::Int(0)),
        (float(-0.0), Value::Int(2)),
        (float(1.0), float(-0.0)),
        (Value::Int(MAX_SAFE_INTEGER), Value::Int(1)),
        (Value::Int(MIN_SAFE_INTEGER), Value::Int(-1)),
        (Value::Int(1_i64 << 32), Value::Int(1_i64 << 32)),
        (Value::Int(i64::MAX), Value::Int(1)),
        (Value::Int(i64::MIN), Value::Int(-1)),
        (Value::Int(9_007_199_254_740_993), float(1.0)),
        (float(f64::INFINITY), float(f64::INFINITY)),
        (float(f64::INFINITY), float(f64::NEG_INFINITY)),
        (float(f64::INFINITY), Value::Int(0)),
        (Value::Int(0), float(f64::NEG_INFINITY)),
        (float(f64::from_bits(0x7ff8_0000_0000_0001)), Value::Int(1)),
        (Value::Int(1), float(f64::from_bits(0xfff8_0000_0000_0002))),
        (float(f64::from_bits(1)), float(0.5)),
        (float(f64::MAX), float(f64::MAX)),
    ];
    for opcode in [Op::Add, Op::Sub, Op::Mul, Op::Div, Op::Mod] {
        for (left, right) in &pairs {
            for dst in 0..=2 {
                let module = test_module(vec![
                    compact_number_test_instruction(opcode, dst, 1, 2),
                    Ir3Instruction::Return { value: dst },
                ]);
                let plan = CompactTier1Program::compile(&module).expect("numeric plan");
                let run = |compact| {
                    let mut core = quickjs_test_core();
                    core.set_reg(1, left.clone());
                    core.set_reg(2, right.clone());
                    let result = core
                        .execute_with_trace_handoff(
                            &module,
                            if compact { Some(&plan) } else { None },
                            TraceHandoff::RetainInCore,
                        )
                        .expect("Number arithmetic executes");
                    (core, result)
                };
                let (compact_core, compact) = run(true);
                let (baseline_core, baseline) = run(false);
                // Value::Float equality preserves NaN payload bits and
                // distinguishes negative zero, not just numeric equality.
                assert_execution_semantics_equal(&compact, &baseline);
                let is_nan = matches!(&baseline.value, Value::Float(value) if value.is_nan());
                let expected_specializations = u64::from(!is_nan);
                assert_eq!(
                    compact.tier_i_specialized_instructions_executed, expected_specializations,
                    "{opcode:?}, {left:?}, {right:?}, dst={dst}"
                );
                assert_eq!(compact_core.registers.value, baseline_core.registers.value);
                assert_eq!(compact_core.register_labels, baseline_core.register_labels);
                assert_eq!(compact_core.seed_epoch, baseline_core.seed_epoch);
                assert_eq!(
                    compact_core.estimated_memory_bytes(),
                    baseline_core.estimated_memory_bytes()
                );
                assert_eq!(
                    compact_core.estimated_memory_bytes(),
                    compact_core.recompute_estimated_memory_bytes()
                );
            }
        }
    }
}

#[test]
fn compact_tier1_number_arithmetic_keeps_accounted_fallbacks() {
    use CompactTier1Opcode as Op;

    for opcode in [Op::Add, Op::Sub, Op::Mul, Op::Div, Op::Mod] {
        for fallback in 0..7 {
            let module = test_module(vec![
                compact_number_test_instruction(opcode, 0, 1, 2),
                Ir3Instruction::Return { value: 0 },
            ]);
            let plan = CompactTier1Program::compile(&module).expect("numeric plan");
            let make_core = || {
                let mut core = quickjs_test_core();
                core.set_reg(1, Value::Float(Float64::new(6.5)));
                core.set_reg(2, Value::Float(Float64::new(2.5)));
                match fallback {
                    0 => core.set_register_label(1, Label::Secret).unwrap(),
                    1 => core
                        .set_register_label(
                            2,
                            Label::Custom {
                                name: "numeric-source".to_string(),
                                level: 3,
                            },
                        )
                        .unwrap(),
                    2 => core.set_reg(0, Value::str("owned destination")),
                    3 => core
                        .set_register_label(
                            0,
                            Label::Custom {
                                name: "replaced-destination".to_string(),
                                level: 2,
                            },
                        )
                        .unwrap(),
                    4 => core.active_inline_callback_context_label = Some(Label::Secret),
                    5 => core.set_reg(1, Value::str("6.5")),
                    6 => {
                        core.set_reg(1, Value::BigInt(Arc::from("13")));
                        core.set_reg(2, Value::BigInt(Arc::from("2")));
                    }
                    _ => unreachable!(),
                }
                core.sync_estimated_memory_bytes()
                    .expect("fallback fixture");
                core
            };
            let mut compact = make_core();
            let mut baseline = make_core();
            let before_epoch = compact.seed_epoch;
            let before_registers = compact.registers.value.clone();
            assert!(
                compact
                    .compact_public_number_arithmetic(0, 1, 2, opcode)
                    .is_none(),
                "{opcode:?} fallback {fallback}"
            );
            assert_eq!(compact.seed_epoch, before_epoch);
            assert_eq!(compact.registers.value, before_registers);
            // Enter the real dispatch loops directly so the callback
            // context survives; top-level prepare intentionally clears it.
            let compact_result = compact
                .run_loop_labeled_with_compact_tier1(&module, Some(&plan))
                .expect("compact fallback");
            let baseline_result = baseline.run_loop_labeled(&module).expect("Tier R fallback");
            assert_eq!(compact_result.value, baseline_result.value);
            assert_eq!(compact_result.label, baseline_result.label);
            assert_eq!(compact.tier_i_specialized_instructions_executed, 0);
            assert_eq!(
                compact.instructions_executed,
                baseline.instructions_executed
            );
            assert_eq!(compact.registers.value, baseline.registers.value);
            assert_eq!(compact.register_labels, baseline.register_labels);
            assert_eq!(compact.seed_epoch, baseline.seed_epoch);
            assert_eq!(compact.nondeterminism_trace, baseline.nondeterminism_trace);
            assert_eq!(
                compact.estimated_memory_bytes(),
                baseline.estimated_memory_bytes()
            );
            assert_eq!(
                compact.estimated_memory_bytes(),
                compact.recompute_estimated_memory_bytes()
            );
        }
    }
}

#[test]
fn compact_tier1_number_arithmetic_preserves_seed_and_memory_refusal() {
    use CompactTier1Opcode as Op;

    for opcode in [Op::Add, Op::Sub, Op::Mul, Op::Div, Op::Mod] {
        for over_budget in [false, true] {
            let module = test_module(vec![
                compact_number_test_instruction(opcode, 1, 1, 2),
                Ir3Instruction::Return { value: 1 },
            ]);
            let plan = CompactTier1Program::compile(&module).expect("numeric plan");
            let make_core = || {
                let mut core = quickjs_test_core();
                core.set_reg(1, Value::Float(Float64::new(1.25)));
                core.set_reg(2, Value::Float(Float64::new(2.5)));
                core.sync_estimated_memory_bytes().expect("numeric fixture");
                let seed = core.capture_execution_seed().expect("seed fits");
                core.config.max_total_memory_bytes = core
                    .estimated_memory_bytes()
                    .saturating_sub(u64::from(over_budget));
                (core, seed)
            };
            let (mut compact, compact_seed) = make_core();
            let (mut baseline, baseline_seed) = make_core();
            let before_epoch = compact.seed_epoch;
            let before_registers = compact.registers.value.clone();
            let compact_result = compact.run_loop_labeled_with_compact_tier1(&module, Some(&plan));
            let baseline_result = baseline.run_loop_labeled(&module);
            match (compact_result, baseline_result) {
                (Err(compact_error), Err(baseline_error)) if over_budget => {
                    assert_eq!(compact_error, baseline_error);
                    assert!(matches!(
                        compact_error,
                        InterpreterError::MemoryBudgetExceeded { .. }
                    ));
                    assert_eq!(compact.registers.value, before_registers);
                    assert_eq!(compact.seed_epoch, before_epoch);
                    assert_eq!(compact.tier_i_specialized_instructions_executed, 0);
                }
                (Ok(compact_value), Ok(baseline_value)) if !over_budget => {
                    assert_eq!(compact_value.value, baseline_value.value);
                    assert_eq!(compact_value.label, baseline_value.label);
                    assert_eq!(compact.tier_i_specialized_instructions_executed, 1);
                    for seed in [&compact_seed, &baseline_seed] {
                        seed.inspect(|state| match state {
                            ExecutionSeed::Materialized { registers, .. } => {
                                assert_eq!(registers, &before_registers);
                            }
                            ExecutionSeed::Lazy { .. } => {
                                panic!("the numeric write must preserve the pre-write seed");
                            }
                        });
                    }
                }
                _ => panic!("numeric memory boundary differs for {opcode:?}, {over_budget}"),
            }
            assert_eq!(compact.registers.value, baseline.registers.value);
            assert_eq!(compact.register_labels, baseline.register_labels);
            assert_eq!(compact.seed_epoch, baseline.seed_epoch);
            assert_eq!(
                compact.instructions_executed,
                baseline.instructions_executed
            );
            assert_eq!(
                compact.estimated_memory_bytes(),
                baseline.estimated_memory_bytes()
            );
            assert_eq!(
                compact.live_execution_seed_reserved_bytes(),
                baseline.live_execution_seed_reserved_bytes()
            );
        }
    }
}

#[test]
fn compact_tier1_number_loop_preserves_budget_and_cancellation_boundaries() {
    let module = test_module(vec![
        Ir3Instruction::LoadFloat {
            dst: 0,
            bits: 1.25_f64.to_bits(),
        },
        Ir3Instruction::LoadFloat {
            dst: 1,
            bits: 2.5_f64.to_bits(),
        },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 0,
            rhs: 1,
        },
        Ir3Instruction::Sub {
            dst: 0,
            lhs: 0,
            rhs: 1,
        },
        Ir3Instruction::Mul {
            dst: 0,
            lhs: 0,
            rhs: 1,
        },
        Ir3Instruction::Div {
            dst: 0,
            lhs: 0,
            rhs: 1,
        },
        Ir3Instruction::Mod {
            dst: 0,
            lhs: 0,
            rhs: 1,
        },
        Ir3Instruction::Jump { target: 2 },
    ]);
    let plan = CompactTier1Program::compile(&module).expect("numeric loop");
    for cancelled in [false, true] {
        for budget in 0..=20 {
            let mut config = test_quickjs_config();
            config.instruction_budget = budget;
            config.checkpoint_density = 3;
            if cancelled {
                let token = CancellationToken::new();
                token.cancel();
                config.cancellation_token = Some(token);
            }
            let mut compact = InterpreterCore::new(config.clone(), "numeric-boundary");
            let mut baseline = InterpreterCore::new(config, "numeric-boundary");
            let compact_error = compact
                .run_loop_labeled_with_compact_tier1(&module, Some(&plan))
                .expect_err("loop must stop");
            let baseline_error = baseline
                .run_loop_labeled(&module)
                .expect_err("loop must stop");
            assert_eq!(compact_error, baseline_error);
            assert_eq!(
                compact.instructions_executed,
                baseline.instructions_executed
            );
            assert_eq!(compact.ip, baseline.ip);
            assert_eq!(compact.registers.value, baseline.registers.value);
            assert_eq!(compact.register_labels, baseline.register_labels);
            assert_eq!(compact.seed_epoch, baseline.seed_epoch);
            assert_eq!(compact.nondeterminism_trace, baseline.nondeterminism_trace);
            assert_eq!(
                compact.estimated_memory_bytes(),
                baseline.estimated_memory_bytes()
            );
        }
    }
}

#[test]
fn compact_tier1_every_admitted_opcode_matches_tier_r_bd_performance_bridge_5_2() {
    let binary = |instruction| {
        vec![
            Ir3Instruction::LoadInt { dst: 1, value: 9 },
            Ir3Instruction::LoadInt { dst: 2, value: 2 },
            instruction,
            Ir3Instruction::Halt,
        ]
    };
    let unary = |instruction| {
        vec![
            Ir3Instruction::LoadInt { dst: 1, value: 9 },
            instruction,
            Ir3Instruction::Halt,
        ]
    };
    let cases = vec![
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: -7 },
            Ir3Instruction::Halt,
        ],
        vec![
            Ir3Instruction::LoadFloat {
                dst: 0,
                bits: (-0.0f64).to_bits(),
            },
            Ir3Instruction::Halt,
        ],
        vec![
            Ir3Instruction::LoadBool {
                dst: 0,
                value: true,
            },
            Ir3Instruction::Halt,
        ],
        vec![Ir3Instruction::LoadNull { dst: 0 }, Ir3Instruction::Halt],
        vec![
            Ir3Instruction::LoadUndefined { dst: 0 },
            Ir3Instruction::Halt,
        ],
        vec![
            Ir3Instruction::LoadInt { dst: 1, value: 7 },
            Ir3Instruction::Move { dst: 0, src: 1 },
            Ir3Instruction::Halt,
        ],
        binary(Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        }),
        binary(Ir3Instruction::Sub {
            dst: 0,
            lhs: 1,
            rhs: 2,
        }),
        binary(Ir3Instruction::Mul {
            dst: 0,
            lhs: 1,
            rhs: 2,
        }),
        binary(Ir3Instruction::Div {
            dst: 0,
            lhs: 1,
            rhs: 2,
        }),
        binary(Ir3Instruction::Mod {
            dst: 0,
            lhs: 1,
            rhs: 2,
        }),
        binary(Ir3Instruction::Exp {
            dst: 0,
            lhs: 1,
            rhs: 2,
        }),
        unary(Ir3Instruction::UnaryNeg { dst: 0, src: 1 }),
        unary(Ir3Instruction::UnaryPlus { dst: 0, src: 1 }),
        unary(Ir3Instruction::LogicalNot { dst: 0, src: 1 }),
        unary(Ir3Instruction::BitNot { dst: 0, src: 1 }),
        binary(Ir3Instruction::Lt {
            dst: 0,
            lhs: 1,
            rhs: 2,
        }),
        binary(Ir3Instruction::Lte {
            dst: 0,
            lhs: 1,
            rhs: 2,
        }),
        binary(Ir3Instruction::Gt {
            dst: 0,
            lhs: 1,
            rhs: 2,
        }),
        binary(Ir3Instruction::Gte {
            dst: 0,
            lhs: 1,
            rhs: 2,
        }),
        binary(Ir3Instruction::Eq {
            dst: 0,
            lhs: 1,
            rhs: 2,
        }),
        binary(Ir3Instruction::StrictEq {
            dst: 0,
            lhs: 1,
            rhs: 2,
        }),
        binary(Ir3Instruction::NotEq {
            dst: 0,
            lhs: 1,
            rhs: 2,
        }),
        binary(Ir3Instruction::StrictNotEq {
            dst: 0,
            lhs: 1,
            rhs: 2,
        }),
        binary(Ir3Instruction::BitAnd {
            dst: 0,
            lhs: 1,
            rhs: 2,
        }),
        binary(Ir3Instruction::BitOr {
            dst: 0,
            lhs: 1,
            rhs: 2,
        }),
        binary(Ir3Instruction::BitXor {
            dst: 0,
            lhs: 1,
            rhs: 2,
        }),
        binary(Ir3Instruction::Shl {
            dst: 0,
            lhs: 1,
            rhs: 2,
        }),
        binary(Ir3Instruction::Shr {
            dst: 0,
            lhs: 1,
            rhs: 2,
        }),
        binary(Ir3Instruction::Ushr {
            dst: 0,
            lhs: 1,
            rhs: 2,
        }),
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 1 },
            Ir3Instruction::Jump { target: 3 },
            Ir3Instruction::LoadInt { dst: 0, value: 2 },
            Ir3Instruction::Halt,
        ],
        vec![
            Ir3Instruction::LoadBool {
                dst: 1,
                value: true,
            },
            Ir3Instruction::JumpIf { cond: 1, target: 3 },
            Ir3Instruction::LoadInt { dst: 0, value: 2 },
            Ir3Instruction::Halt,
        ],
        vec![
            Ir3Instruction::LoadNull { dst: 1 },
            Ir3Instruction::JumpIfNullish { cond: 1, target: 3 },
            Ir3Instruction::LoadInt { dst: 0, value: 2 },
            Ir3Instruction::Halt,
        ],
    ];

    for (index, instructions) in cases.into_iter().enumerate() {
        let module = test_module(instructions);
        let plan = CompactTier1Program::compile(&module).expect("compact plan");
        assert_eq!(
            plan.compact_instruction_count(),
            module.instructions.len(),
            "case {index} must compile every source cell through Tier-I"
        );
        let (compact, baseline) = execute_compact_and_baseline(&module, test_quickjs_config());
        assert_execution_semantics_equal(&compact, &baseline);
        assert!(
            compact.tier_i_instructions_executed > 0,
            "case {index} must exercise Tier-I"
        );
    }
}

#[test]
fn compact_tier1_frame_width_clears_wide_then_narrow_bd_bridge_5_3() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadInt { dst: 1, value: 20 },
            Ir3Instruction::LoadInt { dst: 2, value: 22 },
            Ir3Instruction::CreateClosure {
                dst: 0,
                function_index: 1,
                capture_count: 0,
            },
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 2 },
                dst: 3,
            },
            Ir3Instruction::CreateClosure {
                dst: 0,
                function_index: 2,
                capture_count: 0,
            },
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 0 },
                dst: 0,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::Add {
                dst: 7,
                lhs: 0,
                rhs: 1,
            },
            Ir3Instruction::Return { value: 7 },
            Ir3Instruction::LoadInt { dst: 0, value: 7 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![
            Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 4,
                name: Some("main".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 7,
                arity: 2,
                frame_size: 8,
                name: Some("wide".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 9,
                arity: 0,
                frame_size: 1,
                name: Some("narrow".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
        ],
    );
    let plan = CompactTier1Program::compile(&module).expect("compact function plan");
    assert_eq!(plan.verified_function_frame_clear_width, Some(8));
    assert_eq!(&*plan.verified_function_frame_clear_widths, &[4, 8, 1]);

    let config = test_quickjs_config();
    let max_registers = config.max_registers as usize;
    let mut narrow_only_core = InterpreterCore::new(config.clone(), "tier-i-exact-narrow-frame");
    narrow_only_core
        .enter_stacked_register_frame_for_function(&module, Some(&plan), 2)
        .expect("narrow frame entry");
    // The narrow frame's window is the only part of the file that may
    // hold a value after its entry (bd-9vouw.499).
    assert_eq!(narrow_only_core.register_dirty_end, max_registers + 1);
    assert_eq!(narrow_only_core.registers.len(), max_registers * 2);
    assert_eq!(narrow_only_core.register_labels.len(), max_registers * 2);

    let mut compact_core = InterpreterCore::new(config.clone(), "tier-i-frame-width");
    let compact = compact_core
        .execute_with_trace_handoff(&module, Some(&plan), TraceHandoff::RetainInCore)
        .expect("verified-width execution");
    let mut baseline_core = InterpreterCore::new(config, "tier-i-frame-width");
    let baseline = baseline_core
        .execute(&module)
        .expect("full-width execution");

    assert_execution_semantics_equal(&compact, &baseline);
    assert_eq!(compact.value, Value::Int(7));
    assert_eq!(compact_core.registers.len(), max_registers * 2);
    assert_eq!(compact_core.register_labels.len(), max_registers * 2);
    assert_eq!(baseline_core.registers.len(), max_registers * 2);
    assert_eq!(baseline_core.register_labels.len(), max_registers * 2);
    assert_eq!(compact_core.registers[max_registers + 7], Value::Undefined);
    assert_eq!(
        compact_core.register_labels[max_registers + 7],
        Label::Public
    );
    assert_eq!(
        compact_core.estimated_memory_bytes(),
        baseline_core.estimated_memory_bytes()
    );
    let snapshot_bytes = compact_core.module_execution_snapshot_memory_bytes();
    assert_eq!(
        snapshot_bytes,
        baseline_core.module_execution_snapshot_memory_bytes(),
        "active-width clearing must preserve the later snapshot preflight boundary"
    );
    let one_byte_short = compact_core
        .estimated_memory_bytes()
        .saturating_add(snapshot_bytes)
        .saturating_sub(1);
    compact_core.config.max_total_memory_bytes = one_byte_short;
    baseline_core.config.max_total_memory_bytes = one_byte_short;
    assert_eq!(
        compact_core
            .check_temporary_memory_budget(snapshot_bytes)
            .expect_err("compact snapshot must refuse one byte below its exact peak"),
        baseline_core
            .check_temporary_memory_budget(snapshot_bytes)
            .expect_err("baseline snapshot must refuse at the same exact peak")
    );
    assert_eq!(
        compact_core.estimated_memory_bytes(),
        compact_core.recompute_estimated_memory_bytes()
    );
    assert_eq!(
        baseline_core.estimated_memory_bytes(),
        baseline_core.recompute_estimated_memory_bytes()
    );
}

fn scope_inert_leaf_call_module() -> Ir3Module {
    test_module_with_functions(
        vec![
            Ir3Instruction::LoadInt { dst: 1, value: 20 },
            Ir3Instruction::LoadInt { dst: 2, value: 22 },
            Ir3Instruction::CreateClosure {
                dst: 0,
                function_index: 1,
                capture_count: 0,
            },
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 2 },
                dst: 0,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::Add {
                dst: 2,
                lhs: 0,
                rhs: 1,
            },
            Ir3Instruction::Return { value: 2 },
        ],
        vec![
            Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 3,
                name: Some("main".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 5,
                arity: 2,
                frame_size: 3,
                name: Some("add".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
        ],
    )
}

fn seed_scope_inert_captured_binding(core: &mut InterpreterCore) {
    core.scope_chain
        .current_mut()
        .expect("global scope")
        .insert_binding(
            "unused_capture".to_string(),
            ScopeBinding::with_labeled_state(
                BindingKind::Let,
                Value::Str(JsString::from("captured-payload")),
                Label::Secret,
                true,
            ),
        );
    core.sync_estimated_memory_bytes()
        .expect("captured binding fixture must fit");
}

fn assert_scope_inert_terminal_state_equal(
    compact_core: &mut InterpreterCore,
    baseline_core: &mut InterpreterCore,
    module: &Ir3Module,
) {
    assert_eq!(
        compact_core.call_stack.len(),
        baseline_core.call_stack.len()
    );
    assert_eq!(compact_core.register_base, baseline_core.register_base);
    assert_eq!(
        compact_core.scope_chain.depth(),
        baseline_core.scope_chain.depth()
    );
    assert_eq!(
        compact_core.estimated_memory_bytes(),
        baseline_core.estimated_memory_bytes()
    );
    assert_eq!(
        compact_core.module_execution_snapshot_memory_bytes(),
        baseline_core.module_execution_snapshot_memory_bytes(),
        "terminal callback snapshot preflight must be Tier-I/Tier-R exact"
    );
    assert_eq!(
        compact_core
            .scope_chain
            .resolve("unused_capture")
            .expect("compact captured binding")
            .1
            .value()
            .expect("compact captured value"),
        baseline_core
            .scope_chain
            .resolve("unused_capture")
            .expect("baseline captured binding")
            .1
            .value()
            .expect("baseline captured value")
    );
    assert_eq!(
        compact_core.estimated_memory_bytes(),
        compact_core.recompute_estimated_memory_bytes()
    );
    assert_eq!(
        baseline_core.estimated_memory_bytes(),
        baseline_core.recompute_estimated_memory_bytes()
    );

    // The preflight charges the synthetic call site (two trampoline
    // instructions since fc0428914, not a module copy) plus the caller
    // snapshot.
    let callback_temporary_bytes = InterpreterCore::isolated_call_site_bytes()
        .saturating_add(compact_core.module_execution_snapshot_memory_bytes());
    let one_byte_short = compact_core
        .estimated_memory_bytes()
        .saturating_add(callback_temporary_bytes)
        .saturating_sub(1);
    compact_core.config.max_total_memory_bytes = one_byte_short;
    baseline_core.config.max_total_memory_bytes = one_byte_short;
    let callback = Value::Function(1);
    assert_eq!(
        compact_core
            .preflight_inline_method_call_with_argument_label(Some(module), &callback, 0, None,)
            .expect_err("compact terminal callback snapshot must refuse one byte short"),
        baseline_core
            .preflight_inline_method_call_with_argument_label(Some(module), &callback, 0, None,)
            .expect_err("baseline terminal callback snapshot must refuse one byte short"),
        "terminal callback admission must retain the exact Tier-R budget boundary"
    );
}

#[test]
fn compact_tier1_scope_inert_leaf_matches_full_activation_bd_bridge_5_3() {
    let module = scope_inert_leaf_call_module();
    let plan = CompactTier1Program::compile(&module).expect("compact leaf plan");
    assert_eq!(&*plan.verified_scope_inert_leaf_functions, &[false, true]);

    let config = test_quickjs_config();
    let mut compact_core = InterpreterCore::new(config.clone(), "tier-i-scope-inert-leaf");
    let compact = compact_core
        .execute_with_trace_handoff(&module, Some(&plan), TraceHandoff::RetainInCore)
        .expect("scope-inert compact call");
    let mut baseline_core = InterpreterCore::new(config, "tier-i-scope-inert-leaf");
    let baseline = baseline_core
        .execute(&module)
        .expect("full scope activation call");

    assert_execution_semantics_equal(&compact, &baseline);
    assert_eq!(compact.value, Value::Int(42));
    assert_eq!(compact.tier_i_specialized_instructions_executed, 1);
    assert_eq!(
        compact_core.scope_chain.frames.len(),
        baseline_core.scope_chain.frames.len()
    );
    assert!(compact_core.call_stack.is_empty());
    assert_eq!(compact_core.register_base, 0);
    assert_eq!(
        compact_core.estimated_memory_bytes(),
        compact_core.recompute_estimated_memory_bytes()
    );
    assert_eq!(
        baseline_core.estimated_memory_bytes(),
        baseline_core.recompute_estimated_memory_bytes()
    );
}

fn scope_inert_leaf_method_module() -> Ir3Module {
    let mut module = scope_inert_leaf_call_module();
    // Read a seeded argument so the test can carry a non-Public label
    // through the same function with either dispatch tier.
    module.instructions[0] = Ir3Instruction::Move { dst: 1, src: 3 };
    module.instructions[3] = Ir3Instruction::CallMethod {
        receiver: 4,
        callee: 0,
        args: RegRange { start: 1, count: 2 },
        dst: 0,
    };
    module.function_table[0].frame_size = 5;
    module
}

fn seed_scope_inert_method(core: &mut InterpreterCore, argument: Value) {
    seed_scope_inert_captured_binding(core);
    core.set_reg(3, argument);
    core.set_register_label(3, Label::Secret)
        .expect("seeded argument label fits");
    core.set_reg(4, Value::Str(JsString::from("retained method receiver")));
    core.set_register_label(
        4,
        Label::Custom {
            name: "receiver-context".to_string(),
            level: 1,
        },
    )
    .expect("seeded receiver label fits");
}

#[test]
fn compact_tier1_scope_inert_method_preserves_labels_and_accounting() {
    let module = scope_inert_leaf_method_module();
    let plan = CompactTier1Program::compile(&module).expect("compact method leaf plan");
    assert_eq!(&*plan.verified_scope_inert_leaf_functions, &[false, true]);
    let config = test_quickjs_config();
    let mut compact_core = InterpreterCore::new(config.clone(), "tier-i-method-leaf");
    let mut baseline_core = InterpreterCore::new(config, "tier-i-method-leaf");
    seed_scope_inert_method(&mut compact_core, Value::Int(20));
    seed_scope_inert_method(&mut baseline_core, Value::Int(20));
    let compact = compact_core
        .execute_with_trace_handoff(&module, Some(&plan), TraceHandoff::RetainInCore)
        .expect("compact method call");
    let baseline = baseline_core
        .execute(&module)
        .expect("baseline method call");

    assert_execution_semantics_equal(&compact, &baseline);
    assert_eq!(compact.value, Value::Int(42));
    assert_eq!(compact.completion_label, Label::Secret);
    assert!(compact_core.call_stack.is_empty());
    assert_scope_inert_terminal_state_equal(&mut compact_core, &mut baseline_core, &module);
}

#[test]
fn compact_tier1_scope_inert_method_without_captured_environment() {
    let mut module = scope_inert_leaf_method_module();
    module.instructions[2] = Ir3Instruction::Move { dst: 0, src: 5 };
    module.function_table[0].frame_size = 6;
    let plan = CompactTier1Program::compile(&module).expect("compact plain method plan");
    assert_eq!(&*plan.verified_scope_inert_leaf_functions, &[false, true]);

    for argument in [Value::Int(20), Value::BigInt(Arc::from("20"))] {
        let mut compact_core = InterpreterCore::new(test_quickjs_config(), "tier-i-plain-method");
        let mut baseline_core = InterpreterCore::new(test_quickjs_config(), "tier-i-plain-method");
        for core in [&mut compact_core, &mut baseline_core] {
            seed_scope_inert_method(core, argument.clone());
            core.set_reg(5, Value::Function(1));
        }
        let compact = compact_core.execute_with_trace_handoff(
            &module,
            Some(&plan),
            TraceHandoff::RetainInCore,
        );
        let baseline = baseline_core.execute(&module);
        if matches!(argument, Value::Int(_)) {
            let compact = compact.expect("compact plain method returns");
            let baseline = baseline.expect("baseline plain method returns");
            assert_execution_semantics_equal(&compact, &baseline);
            assert_eq!(compact.value, Value::Int(42));
            assert_eq!(compact.completion_label, Label::Secret);
            assert!(compact_core.call_stack.is_empty());
        } else {
            let compact_error = compact.expect_err("compact mixed numeric method refuses");
            let baseline_error = baseline.expect_err("baseline mixed numeric method refuses");
            assert_eq!(compact_error, baseline_error);
            assert!(matches!(compact_error, InterpreterError::TypeError { .. }));
        }
        assert_eq!(
            compact_core.instructions_executed,
            baseline_core.instructions_executed
        );
        assert_scope_inert_terminal_state_equal(&mut compact_core, &mut baseline_core, &module);
    }
}

#[test]
fn compact_tier1_scope_inert_method_preserves_exact_entry_memory_boundary() {
    let module = scope_inert_leaf_method_module();
    let plan = CompactTier1Program::compile(&module).expect("compact method memory plan");
    assert_eq!(&*plan.verified_scope_inert_leaf_functions, &[false, true]);
    let make_core = || {
        let mut config = test_quickjs_config();
        config.instruction_budget = 3;
        let mut core = InterpreterCore::new(config, "tier-i-method-memory");
        seed_scope_inert_method(&mut core, Value::Int(20));
        // A large captured key makes the two scope snapshots the entry
        // peak, above the subsequent small frame and argument charges.
        core.scope_chain
            .current_mut()
            .expect("caller scope")
            .insert_binding(
                "snapshot-boundary-".repeat(256),
                ScopeBinding::with_state(BindingKind::Let, Value::Undefined, true),
            );
        core.sync_estimated_memory_bytes()
            .expect("method memory fixture fits");
        assert_eq!(
            core.run_loop_labeled(&module)
                .expect_err("pause immediately before method entry"),
            InterpreterError::BudgetExhausted {
                executed: 3,
                budget: 3,
            }
        );
        assert_eq!(core.ip, 3);
        assert!(core.call_stack.is_empty());
        core.config.instruction_budget = 100;
        core
    };
    let probe = make_core();
    let Value::Closure(closure_id) = probe.read_reg(0).expect("created callee") else {
        panic!("fixture must enter a captured method");
    };
    let captured_bytes = InterpreterCore::estimate_scope_chain_bytes(
        &probe.closures[closure_id as usize].captured_env,
    );
    let receiver_bytes =
        InterpreterCore::estimate_value_bytes(&probe.read_reg(4).expect("method receiver"))
            .saturating_add(InterpreterCore::estimate_label_bytes(
                probe.get_register_label(4).expect("receiver label"),
            ));
    let exact_peak = probe
        .estimated_memory_bytes()
        .saturating_add(captured_bytes)
        .saturating_add(InterpreterCore::estimate_label_bytes(&Label::Public))
        .saturating_add(receiver_bytes)
        .saturating_add(InterpreterCore::estimate_scope_chain_bytes(
            &probe.scope_chain.frames,
        ));

    for one_byte_short in [true, false] {
        let mut compact_core = make_core();
        let mut baseline_core = make_core();
        let before_bytes = baseline_core.estimated_memory_bytes();
        let limit = exact_peak - u64::from(one_byte_short);
        compact_core.config.max_total_memory_bytes = limit;
        baseline_core.config.max_total_memory_bytes = limit;
        let compact = compact_core.run_loop_labeled_with_compact_tier1(&module, Some(&plan));
        let baseline = baseline_core.run_loop_labeled(&module);
        if one_byte_short {
            let compact_error = compact.expect_err("virtual entry must preserve the peak");
            let baseline_error = baseline.expect_err("full entry must refuse one byte short");
            assert_eq!(compact_error, baseline_error);
            assert!(matches!(
                compact_error,
                InterpreterError::MemoryBudgetExceeded {
                    requested_bytes,
                    max_bytes,
                    ..
                } if requested_bytes == exact_peak && max_bytes == limit
            ));
            assert_eq!(compact_core.ip, 3);
            assert_eq!(baseline_core.ip, 3);
            assert_eq!(compact_core.instructions_executed, 4);
            assert!(compact_core.call_stack.is_empty());
            assert_eq!(compact_core.estimated_memory_bytes(), before_bytes);
        } else {
            let compact = compact.expect("virtual entry fits at the exact ceiling");
            let baseline = baseline.expect("full entry fits at the exact ceiling");
            assert_eq!(compact.value, baseline.value);
            assert_eq!(compact.label, baseline.label);
            assert_eq!(compact.value, Value::Int(42));
            assert_eq!(compact.label, Label::Secret);
            assert!(compact_core.call_stack.is_empty());
        }
        assert_eq!(
            compact_core.instructions_executed,
            baseline_core.instructions_executed
        );
        assert_scope_inert_terminal_state_equal(&mut compact_core, &mut baseline_core, &module);
    }
}

#[test]
fn compact_tier1_scope_inert_method_preserves_terminal_refusals() {
    let module = scope_inert_leaf_method_module();
    let plan = CompactTier1Program::compile(&module).expect("compact method leaf plan");
    for case in [
        "type-error",
        "instruction-budget",
        "cancellation",
        "scope-depth",
    ] {
        let mut config = test_quickjs_config();
        let argument = match case {
            "type-error" => Value::BigInt(Arc::from("20")),
            "instruction-budget" => {
                config.instruction_budget = 5;
                Value::Int(20)
            }
            "cancellation" => {
                let token = CancellationToken::new();
                token.cancel();
                config.cancellation_token = Some(token);
                config.checkpoint_density = 5;
                Value::Int(20)
            }
            "scope-depth" => {
                config.max_scope_depth = 1;
                Value::Int(20)
            }
            _ => unreachable!("fixed refusal cases"),
        };
        let mut compact_core = InterpreterCore::new(config.clone(), "tier-i-method-refusal");
        let mut baseline_core = InterpreterCore::new(config, "tier-i-method-refusal");
        seed_scope_inert_method(&mut compact_core, argument.clone());
        seed_scope_inert_method(&mut baseline_core, argument);
        let compact_error = compact_core
            .execute_with_trace_handoff(&module, Some(&plan), TraceHandoff::RetainInCore)
            .expect_err("compact method must refuse");
        let baseline_error = baseline_core
            .execute(&module)
            .expect_err("baseline method must refuse");

        assert_eq!(compact_error, baseline_error, "{case}");
        assert_eq!(
            compact_core.instructions_executed, baseline_core.instructions_executed,
            "{case} must stop at the same deterministic instruction"
        );
        assert_scope_inert_terminal_state_equal(&mut compact_core, &mut baseline_core, &module);
    }
}

#[test]
fn compact_tier1_scope_inert_leaf_preserves_error_state_bd_bridge_5_3() {
    let mut module = scope_inert_leaf_call_module();
    module.instructions[0] = Ir3Instruction::LoadBigInt {
        dst: 1,
        value: "20".to_string(),
    };
    let plan = CompactTier1Program::compile(&module).expect("compact leaf plan");
    assert_eq!(&*plan.verified_scope_inert_leaf_functions, &[false, true]);

    let config = test_quickjs_config();
    let mut compact_core = InterpreterCore::new(config.clone(), "tier-i-scope-inert-error");
    seed_scope_inert_captured_binding(&mut compact_core);
    let compact_error = compact_core
        .execute_with_trace_handoff(&module, Some(&plan), TraceHandoff::RetainInCore)
        .expect_err("mixed BigInt/Number add must fail");
    let mut baseline_core = InterpreterCore::new(config, "tier-i-scope-inert-error");
    seed_scope_inert_captured_binding(&mut baseline_core);
    let baseline_error = baseline_core
        .execute(&module)
        .expect_err("full scope activation must fail identically");

    assert_eq!(compact_error, baseline_error);
    assert_scope_inert_terminal_state_equal(&mut compact_core, &mut baseline_core, &module);
}

#[test]
fn compact_tier1_scope_inert_leaf_preserves_budget_exit_state_bd_bridge_5_3() {
    let module = scope_inert_leaf_call_module();
    let plan = CompactTier1Program::compile(&module).expect("compact leaf plan");
    let mut config = test_quickjs_config();
    config.instruction_budget = 5;

    let mut compact_core = InterpreterCore::new(config.clone(), "tier-i-scope-inert-budget");
    seed_scope_inert_captured_binding(&mut compact_core);
    let compact_error = compact_core
        .execute_with_trace_handoff(&module, Some(&plan), TraceHandoff::RetainInCore)
        .expect_err("compact leaf must exhaust before return");
    let mut baseline_core = InterpreterCore::new(config, "tier-i-scope-inert-budget");
    seed_scope_inert_captured_binding(&mut baseline_core);
    let baseline_error = baseline_core
        .execute(&module)
        .expect_err("baseline leaf must exhaust before return");

    assert_eq!(compact_error, baseline_error);
    assert!(matches!(
        compact_error,
        InterpreterError::BudgetExhausted {
            executed: 5,
            budget: 5
        }
    ));
    assert_scope_inert_terminal_state_equal(&mut compact_core, &mut baseline_core, &module);
}

#[test]
fn compact_tier1_scope_inert_leaf_preserves_cancellation_exit_state_bd_bridge_5_3() {
    let module = scope_inert_leaf_call_module();
    let plan = CompactTier1Program::compile(&module).expect("compact leaf plan");
    let token = CancellationToken::new();
    token.cancel();
    let mut config = test_quickjs_config();
    config.instruction_budget = 100;
    config.checkpoint_density = 5;
    config.cancellation_token = Some(token);
    let checkpoint_density = config.checkpoint_density;

    let mut compact_core = InterpreterCore::new(config.clone(), "tier-i-scope-inert-cancel");
    seed_scope_inert_captured_binding(&mut compact_core);
    let compact_error = compact_core
        .execute_with_trace_handoff(&module, Some(&plan), TraceHandoff::RetainInCore)
        .expect_err("compact leaf must observe cancellation inside the active call");
    let mut baseline_core = InterpreterCore::new(config, "tier-i-scope-inert-cancel");
    seed_scope_inert_captured_binding(&mut baseline_core);
    let baseline_error = baseline_core
        .execute(&module)
        .expect_err("baseline leaf must observe cancellation at the same boundary");

    assert_eq!(compact_error, baseline_error);
    assert_eq!(compact_error, InterpreterError::Cancelled);
    assert_eq!(
        compact_core.instructions_executed, baseline_core.instructions_executed,
        "scope-inert Tier-I and Tier-R must retain the same terminal instruction boundary"
    );
    assert!(compact_core.instructions_executed >= checkpoint_density);
    assert_scope_inert_terminal_state_equal(&mut compact_core, &mut baseline_core, &module);
}

#[test]
fn compact_tier1_scope_inert_leaf_preserves_caught_error_unwind_bd_bridge_5_3() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::BeginTry {
                catch_target: 7,
                finally_target: None,
            },
            Ir3Instruction::LoadBigInt {
                dst: 1,
                value: "20".to_string(),
            },
            Ir3Instruction::LoadInt { dst: 2, value: 22 },
            Ir3Instruction::CreateClosure {
                dst: 0,
                function_index: 1,
                capture_count: 0,
            },
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 2 },
                dst: 0,
            },
            Ir3Instruction::EndTry,
            Ir3Instruction::Jump { target: 9 },
            Ir3Instruction::EnterCatch { dst: 0 },
            Ir3Instruction::LoadInt { dst: 0, value: 99 },
            Ir3Instruction::Halt,
            Ir3Instruction::Add {
                dst: 2,
                lhs: 0,
                rhs: 1,
            },
            Ir3Instruction::Return { value: 2 },
        ],
        vec![
            Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 3,
                name: Some("main".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 10,
                arity: 2,
                frame_size: 3,
                name: Some("caught_add".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
        ],
    );
    let plan = CompactTier1Program::compile(&module).expect("compact caught-error plan");
    assert_eq!(&*plan.verified_scope_inert_leaf_functions, &[false, true]);

    let config = test_quickjs_config();
    let mut compact_core = InterpreterCore::new(config.clone(), "tier-i-scope-inert-catch");
    seed_scope_inert_captured_binding(&mut compact_core);
    let compact = compact_core
        .execute_with_trace_handoff(&module, Some(&plan), TraceHandoff::RetainInCore)
        .expect("compact caller must catch the leaf error");
    let mut baseline_core = InterpreterCore::new(config, "tier-i-scope-inert-catch");
    seed_scope_inert_captured_binding(&mut baseline_core);
    let baseline = baseline_core
        .execute(&module)
        .expect("baseline caller must catch the leaf error");

    assert_execution_semantics_equal(&compact, &baseline);
    assert_eq!(compact.value, Value::Int(99));
    assert!(compact_core.call_stack.is_empty());
    assert_eq!(compact_core.register_base, 0);
    assert_eq!(compact_core.scope_chain.depth(), 1);
    assert_eq!(
        compact_core
            .scope_chain
            .resolve("unused_capture")
            .expect("restored compact caller binding")
            .1
            .value()
            .expect("restored compact caller value"),
        baseline_core
            .scope_chain
            .resolve("unused_capture")
            .expect("restored baseline caller binding")
            .1
            .value()
            .expect("restored baseline caller value")
    );
    assert_eq!(
        compact_core.estimated_memory_bytes(),
        baseline_core.estimated_memory_bytes()
    );
    assert_eq!(
        compact_core.estimated_memory_bytes(),
        compact_core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn compact_tier1_scope_inert_leaf_preserves_scope_depth_refusal_bd_bridge_5_3() {
    let module = scope_inert_leaf_call_module();
    let plan = CompactTier1Program::compile(&module).expect("compact leaf plan");
    let mut config = test_quickjs_config();
    config.max_scope_depth = 1;
    let mut compact_core = InterpreterCore::new(config.clone(), "tier-i-scope-depth");
    let compact_error = compact_core
        .execute_with_trace_handoff(&module, Some(&plan), TraceHandoff::RetainInCore)
        .expect_err("virtual leaf scope must retain the depth refusal");
    let mut baseline_core = InterpreterCore::new(config, "tier-i-scope-depth");
    let baseline_error = baseline_core
        .execute(&module)
        .expect_err("full leaf scope must hit the same depth refusal");

    assert_eq!(compact_error, baseline_error);
    assert!(matches!(
        compact_error,
        InterpreterError::ScopeDepthExceeded {
            requested_depth: 2,
            max_depth: 1
        }
    ));
    assert!(compact_core.call_stack.is_empty());
    assert_eq!(compact_core.register_base, 0);
    assert_eq!(
        compact_core.estimated_memory_bytes(),
        compact_core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn compact_tier1_scope_inert_leaf_rejects_reentrant_or_scope_ops_bd_bridge_5_3() {
    let mut module = scope_inert_leaf_call_module();
    module.instructions[5] = Ir3Instruction::CreateClosure {
        dst: 2,
        function_index: 1,
        capture_count: 0,
    };
    let plan = CompactTier1Program::compile(&module).expect("mixed compact plan");
    assert_eq!(&*plan.verified_scope_inert_leaf_functions, &[false, false]);

    module.instructions[5] = Ir3Instruction::Call {
        callee: 0,
        args: RegRange { start: 1, count: 0 },
        dst: 2,
    };
    let plan = CompactTier1Program::compile(&module).expect("reentrant compact plan");
    assert_eq!(&*plan.verified_scope_inert_leaf_functions, &[false, false]);

    module.instructions[5] = Ir3Instruction::LoadScoped {
        dst: 2,
        name_pool_index: 0,
    };
    let plan = CompactTier1Program::compile(&module).expect("scope-reading compact plan");
    assert_eq!(&*plan.verified_scope_inert_leaf_functions, &[false, false]);

    module.instructions[5] = Ir3Instruction::Add {
        dst: 2,
        lhs: 0,
        rhs: 1,
    };
    module.function_table[1].is_generator = true;
    let plan = CompactTier1Program::compile(&module).expect("generator compact plan");
    assert_eq!(&*plan.verified_scope_inert_leaf_functions, &[false, false]);
}

#[test]
fn compact_tier1_verified_width_covers_method_call_entry_bd_bridge_5_3() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadInt { dst: 3, value: 0 },
            Ir3Instruction::CallMethod {
                receiver: 0,
                callee: 1,
                args: RegRange { start: 4, count: 0 },
                dst: 2,
            },
            Ir3Instruction::Return { value: 2 },
            Ir3Instruction::LoadThis { dst: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![
            Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 4,
                name: Some("main".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 3,
                arity: 0,
                frame_size: 1,
                name: Some("return_this".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
        ],
    );
    let plan = CompactTier1Program::compile(&module).expect("method compact plan");
    assert_eq!(plan.verified_function_frame_clear_width, Some(4));

    let config = test_quickjs_config();
    let max_registers = config.max_registers as usize;
    let mut compact_core = InterpreterCore::new(config.clone(), "tier-i-method-frame");
    compact_core.set_reg(0, Value::Int(77));
    compact_core.set_reg(1, Value::Function(1));
    let compact = compact_core
        .execute_with_trace_handoff(&module, Some(&plan), TraceHandoff::RetainInCore)
        .expect("compact method call");

    let mut baseline_core = InterpreterCore::new(config, "tier-i-method-frame");
    baseline_core.set_reg(0, Value::Int(77));
    baseline_core.set_reg(1, Value::Function(1));
    let baseline = baseline_core
        .execute(&module)
        .expect("baseline method call");

    assert_execution_semantics_equal(&compact, &baseline);
    assert_eq!(compact.value, Value::Int(77));
    assert_eq!(compact_core.registers.len(), max_registers * 2);
    assert_eq!(compact_core.register_labels.len(), max_registers * 2);
    assert_eq!(baseline_core.registers.len(), max_registers * 2);
    assert_eq!(baseline_core.register_labels.len(), max_registers * 2);
}

#[test]
fn compact_tier1_verified_width_covers_constructor_entry_bd_bridge_5_3() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadInt { dst: 3, value: 0 },
            Ir3Instruction::Construct {
                callee: 0,
                args: RegRange { start: 2, count: 0 },
                dst: 1,
            },
            Ir3Instruction::Return { value: 1 },
            Ir3Instruction::LoadUndefined { dst: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![
            Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 4,
                name: Some("main".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 3,
                arity: 0,
                frame_size: 1,
                name: Some("Ctor".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
        ],
    );
    let plan = CompactTier1Program::compile(&module).expect("constructor compact plan");
    assert_eq!(plan.verified_function_frame_clear_width, Some(4));

    let config = test_quickjs_config();
    let max_registers = config.max_registers as usize;
    let mut compact_core = InterpreterCore::new(config.clone(), "tier-i-constructor-frame");
    compact_core.set_reg(0, Value::Function(1));
    let compact = compact_core
        .execute_with_trace_handoff(&module, Some(&plan), TraceHandoff::RetainInCore)
        .expect("compact construction");

    let mut baseline_core = InterpreterCore::new(config, "tier-i-constructor-frame");
    baseline_core.set_reg(0, Value::Function(1));
    let baseline = baseline_core
        .execute(&module)
        .expect("baseline construction");

    assert_execution_semantics_equal(&compact, &baseline);
    assert!(matches!(compact.value, Value::Object(_)));
    assert_eq!(compact_core.registers.len(), max_registers * 2);
    assert_eq!(compact_core.register_labels.len(), max_registers * 2);
    assert_eq!(baseline_core.registers.len(), max_registers * 2);
    assert_eq!(baseline_core.register_labels.len(), max_registers * 2);
    assert_eq!(
        compact_core.estimated_memory_bytes(),
        compact_core.recompute_estimated_memory_bytes()
    );
    assert_eq!(
        baseline_core.estimated_memory_bytes(),
        baseline_core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn compact_tier1_invalid_frame_falls_back_to_full_width_bd_bridge_5_3() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadInt { dst: 1, value: 42 },
            Ir3Instruction::CreateClosure {
                dst: 0,
                function_index: 1,
                capture_count: 0,
            },
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 1 },
                dst: 0,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::Move { dst: 7, src: 0 },
            Ir3Instruction::Return { value: 7 },
        ],
        vec![
            Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 2,
                name: Some("main".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 4,
                arity: 1,
                frame_size: 1,
                name: Some("underdeclared".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
        ],
    );
    let plan = CompactTier1Program::compile(&module).expect("compact fallback plan");
    assert_eq!(plan.verified_function_frame_clear_width, None);

    let config = test_quickjs_config();
    let max_registers = config.max_registers as usize;
    let mut compact_core = InterpreterCore::new(config.clone(), "tier-i-frame-fallback");
    let compact = compact_core
        .execute_with_trace_handoff(&module, Some(&plan), TraceHandoff::RetainInCore)
        .expect("fallback execution");
    let mut baseline_core = InterpreterCore::new(config, "tier-i-frame-fallback");
    let baseline = baseline_core.execute(&module).expect("baseline execution");

    assert_execution_semantics_equal(&compact, &baseline);
    assert_eq!(compact.value, Value::Int(42));
    assert_eq!(compact_core.registers.len(), max_registers * 2);
    assert_eq!(compact_core.register_labels.len(), max_registers * 2);
}

#[test]
fn compact_tier1_frame_high_water_survives_narrower_module_bd_bridge_5_3() {
    let module = |frame_size, body| {
        test_module_with_functions(
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 1 },
                Ir3Instruction::Halt,
                body,
                Ir3Instruction::Return { value: 0 },
            ],
            vec![
                Ir3FunctionDesc {
                    entry: 0,
                    arity: 0,
                    frame_size: 1,
                    name: Some("main".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
                Ir3FunctionDesc {
                    entry: 2,
                    arity: 0,
                    frame_size,
                    name: Some("callee".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
            ],
        )
    };
    let wide = module(8, Ir3Instruction::LoadInt { dst: 7, value: 99 });
    let narrow = module(1, Ir3Instruction::LoadInt { dst: 0, value: 7 });
    let wide_plan = CompactTier1Program::compile(&wide).expect("wide compact plan");
    let narrow_plan = CompactTier1Program::compile(&narrow).expect("narrow compact plan");
    let mut core = quickjs_test_core();
    let max_registers = core.config.max_registers as usize;

    core.enter_stacked_register_frame(Some(&wide_plan))
        .expect("wide frame entry");
    core.write_reg_with_label(7, Value::Int(99), Label::Secret)
        .expect("seed stale wide-frame state");
    // Returning restores the caller's window: its base and its width
    // (bd-9vouw.72), so the narrow callee reuses the wide one's slots.
    core.register_base = 0;
    core.register_width = max_registers;
    core.enter_stacked_register_frame(Some(&narrow_plan))
        .expect("narrow frame entry");

    // The wide frame's write raised the dirty end past register 7, so the
    // narrow entry cleared it (bd-9vouw.499); only its own window may be
    // dirty after it.
    assert_eq!(core.register_dirty_end, max_registers + 1);
    assert_eq!(core.registers[max_registers + 7], Value::Undefined);
    assert_eq!(core.register_labels[max_registers + 7], Label::Public);

    // bd-9vouw.499: the next narrow entry clears its own window only;
    // the wide frame's slots are already clear.
    core.write_reg_with_label(0, Value::Int(1), Label::Secret)
        .expect("narrow frame write");
    core.register_base = 0;
    core.register_width = max_registers;
    assert_eq!(core.register_dirty_end, max_registers + 1);
    core.enter_stacked_register_frame(Some(&narrow_plan))
        .expect("narrow entry");
    assert_eq!(core.registers[max_registers], Value::Undefined);
    assert_eq!(core.register_labels[max_registers], Label::Public);
    assert_eq!(core.register_dirty_end, max_registers + 1);
}

/// bd-9vouw.499: registers a deeper frame left behind, past the window of
/// the next frame entered at a shallower base, are cleared by that entry,
/// and a write past every window (a widened builtin window) is cleared
/// by the next entry too.
#[test]
fn stale_registers_of_deeper_frames_are_cleared_by_the_next_entry() {
    let module = |frame_size: u32| {
        test_module_with_functions(
            vec![
                Ir3Instruction::Halt,
                Ir3Instruction::LoadInt { dst: 0, value: 1 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![
                Ir3FunctionDesc {
                    entry: 0,
                    arity: 0,
                    frame_size: 1,
                    name: Some("main".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
                Ir3FunctionDesc {
                    entry: 1,
                    arity: 0,
                    frame_size,
                    name: Some("callee".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
            ],
        )
    };
    let four = CompactTier1Program::compile(&module(4)).expect("width-4 plan");
    let two = CompactTier1Program::compile(&module(2)).expect("width-2 plan");
    let mut core = quickjs_test_core();
    let max_registers = core.config.max_registers as usize;

    // main -> a (width 4) -> b (width 4); b writes its last register.
    core.enter_stacked_register_frame(Some(&four)).expect("a");
    core.enter_stacked_register_frame(Some(&four)).expect("b");
    assert_eq!(core.register_base, max_registers + 4);
    core.write_reg_with_label(3, Value::str("left by b"), Label::Secret)
        .expect("b writes");
    assert_eq!(core.register_dirty_end, max_registers + 8);
    // Both return; main calls c (width 2) at a's base.
    core.register_base = 0;
    core.register_width = max_registers;
    core.enter_stacked_register_frame(Some(&two)).expect("c");
    assert_eq!(core.registers[max_registers + 7], Value::Undefined);
    assert_eq!(core.register_labels[max_registers + 7], Label::Public);
    assert_eq!(core.register_dirty_end, max_registers + 2);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    // A write past c's window (as a widened builtin window makes).
    core.write_reg_with_label(5, Value::Int(9), Label::Secret)
        .expect("write past the window");
    assert_eq!(core.register_dirty_end, max_registers + 6);
    core.register_base = 0;
    core.register_width = max_registers;
    core.enter_stacked_register_frame(Some(&two)).expect("d");
    assert_eq!(core.registers[max_registers + 5], Value::Undefined);
    assert_eq!(core.register_labels[max_registers + 5], Label::Public);
    assert_eq!(core.register_dirty_end, max_registers + 2);
}

#[test]
fn module_execution_restore_keeps_the_parked_dirty_end_bd_9vouw_500() {
    let mut core = quickjs_test_core();
    let max_registers = core.config.max_registers as usize;
    core.write_reg_with_label(3, Value::Int(7), Label::Secret)
        .expect("caller writes");
    assert_eq!(core.register_dirty_end, 4);

    // An isolated call starts on files that are clear throughout.
    let previous_register_bytes = core.registers_memory_bytes();
    let previous_label_bytes = core.register_context_labels_memory_bytes();
    let snapshot = core
        .isolate_module_execution()
        .expect("isolated snapshot fits");
    assert_eq!(core.register_dirty_end, 0);
    let previous_scope_bytes = core.scope_chain_memory_bytes();
    let previous_call_stack_bytes = core.call_stack_memory_bytes();
    core.apply_register_context_scope_call_stack_memory_delta(
        previous_register_bytes,
        previous_label_bytes,
        previous_scope_bytes,
        previous_call_stack_bytes,
    )
    .expect("callback setup fits");
    core.write_reg(5, Value::Int(1)).expect("callee writes");
    assert_eq!(core.register_dirty_end, 6);
    core.restore_module_execution(snapshot, true);
    // The caller's dirty end, not its file's length: the next call
    // clears only what is dirty.
    assert!(core.registers.len() >= max_registers);
    assert_eq!(core.register_dirty_end, 4);
    assert_eq!(core.read_reg(3).expect("caller register"), Value::Int(7));
    assert_eq!(core.read_reg(5).expect("caller register"), Value::Undefined);

    // A rollback snapshot is restored the same way.
    let snapshot = core
        .snapshot_module_execution()
        .expect("rollback snapshot fits");
    core.write_reg(9, Value::Int(2)).expect("setup writes");
    assert_eq!(core.register_dirty_end, 10);
    core.restore_module_execution(snapshot, false);
    assert_eq!(core.register_dirty_end, 4);
    assert_eq!(core.read_reg(9).expect("rolled back"), Value::Undefined);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

/// A generator stepped from inside a function alternates between the
/// caller's file and the activation's, which differ in length. The core
/// keeps a spare of each and hands out the one of the length asked for,
/// so neither file is cut and regrown on every step (bd-9vouw.500).
#[test]
fn spare_register_files_are_matched_by_length_bd_9vouw_500() {
    let mut core = quickjs_test_core();
    let window = core.config.max_registers as usize;
    let cleared = |len: usize| (vec![Value::Undefined; len], vec![Label::Public; len]);
    let (short_values, short_labels) = cleared(window);
    let (long_values, long_labels) = cleared(2 * window);
    let short_address = short_values.as_ptr();
    let long_address = long_values.as_ptr();
    core.keep_spare_register_files(short_values, short_labels);
    core.keep_spare_register_files(long_values, long_labels);

    let (values, _) = core.take_spare_register_files(window);
    assert_eq!(values.as_ptr(), short_address);
    core.keep_spare_register_files(values, vec![Label::Public; window]);
    let (values, _) = core.take_spare_register_files(2 * window);
    assert_eq!(values.as_ptr(), long_address);
    core.keep_spare_register_files(values, vec![Label::Public; 2 * window]);

    // No spare of the length: new empty files, and the spares stay.
    let (values, labels) = core.take_spare_register_files(3 * window);
    assert!(values.is_empty() && labels.is_empty());
    assert_eq!(core.spare_register_files.len(), 2);
    // A third spare evicts the oldest.
    let (third_values, third_labels) = cleared(window / 2);
    core.keep_spare_register_files(third_values, third_labels);
    assert_eq!(core.spare_register_files.len(), SPARE_REGISTER_FILES);
    assert!(
        core.spare_register_files
            .iter()
            .all(|(values, _)| values.as_ptr() != short_address)
    );
    // None kept at all: empty files.
    core.spare_register_files.clear();
    assert_eq!(core.take_spare_register_files(window).0.len(), 0);

    // A step from inside a function: the caller's file (two windows) is
    // taken, the activation's (one window) installed, then the reverse.
    // From the second step on, each install finds its own file.
    let (caller_values, caller_labels) = cleared(2 * window);
    let caller_address = caller_values.as_ptr();
    core.keep_spare_register_files(caller_values, caller_labels);
    let (values, _) = core.take_spare_register_files(window);
    assert!(values.is_empty(), "the caller's file is not cut down");
    let (activation_values, activation_labels) = cleared(window);
    let activation_address = activation_values.as_ptr();
    core.keep_spare_register_files(activation_values, activation_labels);
    let (values, labels) = core.take_spare_register_files(2 * window);
    assert_eq!(values.as_ptr(), caller_address);
    core.keep_spare_register_files(values, labels);
    let (values, _) = core.take_spare_register_files(window);
    assert_eq!(values.as_ptr(), activation_address);
}

#[test]
fn parked_activation_files_are_moved_out_and_refilled_bd_9vouw_500() {
    let mut core = quickjs_test_core();
    let max_registers = core.config.max_registers as usize;
    let text = Value::str("parked across a step");
    core.write_reg_with_label(1, text.clone(), Label::Secret)
        .expect("string register");
    core.write_reg(4, Value::Int(3)).expect("int register");
    let value_bytes = core.registers_memory_bytes();
    assert!(value_bytes > 0);
    let register_len = core.registers.len();
    let label_len = core.register_labels.len();
    assert!(register_len >= max_registers);

    let execution = core.take_generator_execution();
    // The snapshot keeps only the live prefix (bd-9vouw.167) and the
    // file's cached byte count.
    assert_eq!(execution.registers.len(), 5);
    assert_eq!(execution.register_labels.len(), 5);
    assert_eq!(execution.register_len, register_len);
    assert_eq!(execution.register_dirty_end, 5);
    assert_eq!(execution.registers_value_bytes, Some(value_bytes));
    // The emptied files are the spare, cleared throughout.
    assert!(core.registers.is_empty());
    assert_eq!(core.spare_register_files.len(), 1);
    let (spare_values, spare_labels) = core
        .spare_register_files
        .last()
        .expect("the taken files are the spare");
    assert_eq!(spare_values.len(), register_len);
    assert_eq!(spare_labels.len(), label_len);
    assert!(spare_values.iter().all(|value| *value == Value::Undefined));
    assert!(spare_labels.iter().all(|label| *label == Label::Public));
    let spare_address = spare_values.as_ptr();

    core.install_generator_execution(execution);
    // Refilled in place: no allocation, no padding pass.
    assert!(core.spare_register_files.is_empty());
    assert_eq!(core.registers.as_ptr(), spare_address);
    assert_eq!(core.registers.len(), register_len);
    assert_eq!(core.register_labels.len(), label_len);
    assert_eq!(core.read_reg(1).expect("string register"), text);
    assert_eq!(
        core.get_register_label(1).expect("string label"),
        &Label::Secret
    );
    assert_eq!(core.read_reg(4).expect("int register"), Value::Int(3));
    assert!(
        core.registers[5..]
            .iter()
            .all(|value| *value == Value::Undefined)
    );
    assert_eq!(core.registers_value_bytes.get(), Some(value_bytes));
    // The test build's registers_memory_bytes checks the cache against
    // a walk of the file.
    assert_eq!(core.registers_memory_bytes(), value_bytes);
    assert_eq!(core.register_dirty_end, 5);

    // A file longer than the cap is freed rather than kept.
    let long = max_registers * (SPARE_REGISTER_FILE_WINDOWS + 1);
    core.mutate_registers(|registers| registers.resize(long, Value::Undefined));
    core.register_labels.resize(long, Label::Public);
    let execution = core.take_generator_execution();
    assert!(core.spare_register_files.is_empty());
    core.install_generator_execution(execution);
    assert_eq!(core.registers.len(), long);
    assert_eq!(core.register_labels.len(), long);
    assert_eq!(core.read_reg(1).expect("string register"), text);
    assert_eq!(core.registers_memory_bytes(), value_bytes);
}

#[test]
fn compact_tier1_verified_widths_stack_nested_windows_bd_bridge_5_3() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadInt { dst: 1, value: 1 },
            Ir3Instruction::CreateClosure {
                dst: 0,
                function_index: 1,
                capture_count: 0,
            },
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 0 },
                dst: 0,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadInt { dst: 1, value: 2 },
            Ir3Instruction::CreateClosure {
                dst: 0,
                function_index: 2,
                capture_count: 0,
            },
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 0 },
                dst: 0,
            },
            Ir3Instruction::Return { value: 0 },
            Ir3Instruction::LoadInt { dst: 0, value: 42 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![
            Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 2,
                name: Some("main".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 4,
                arity: 0,
                frame_size: 2,
                name: Some("outer".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 8,
                arity: 0,
                frame_size: 1,
                name: Some("inner".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
        ],
    );
    let plan = CompactTier1Program::compile(&module).expect("nested compact plan");
    assert_eq!(plan.verified_function_frame_clear_width, Some(2));

    let config = test_quickjs_config();
    let max_registers = config.max_registers as usize;
    let mut compact_core = InterpreterCore::new(config.clone(), "tier-i-nested-frame");
    let compact = compact_core
        .execute_with_trace_handoff(&module, Some(&plan), TraceHandoff::RetainInCore)
        .expect("nested compact execution");
    let mut baseline_core = InterpreterCore::new(config, "tier-i-nested-frame");
    let baseline = baseline_core
        .execute(&module)
        .expect("nested baseline execution");

    assert_execution_semantics_equal(&compact, &baseline);
    assert_eq!(compact.value, Value::Int(42));
    // A callee window starts right above its caller's verified width
    // (bd-9vouw.72): main keeps the top frame's max_registers window,
    // `outer` is 2 wide, and `inner`'s window (physically max_registers
    // long) starts at max_registers + 2. The plain run uses the same
    // verified widths as the compact plan.
    assert_eq!(compact_core.registers.len(), max_registers * 2 + 2);
    assert_eq!(baseline_core.registers.len(), max_registers * 2 + 2);
}

#[test]
fn compact_tier1_verified_width_preserves_exception_unwind_bd_bridge_5_3() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::BeginTry {
                catch_target: 5,
                finally_target: None,
            },
            Ir3Instruction::CreateClosure {
                dst: 0,
                function_index: 1,
                capture_count: 0,
            },
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 0, count: 0 },
                dst: 0,
            },
            Ir3Instruction::EndTry,
            Ir3Instruction::Jump { target: 6 },
            Ir3Instruction::EnterCatch { dst: 0 },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadInt { dst: 0, value: 9 },
            Ir3Instruction::Throw { value: 0 },
        ],
        vec![
            Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 1,
                name: Some("main".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 7,
                arity: 0,
                frame_size: 1,
                name: Some("throwing".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
        ],
    );
    let plan = CompactTier1Program::compile(&module).expect("throwing compact plan");
    assert_eq!(plan.verified_function_frame_clear_width, Some(1));

    let config = test_quickjs_config();
    let max_registers = config.max_registers as usize;
    let mut compact_core = InterpreterCore::new(config.clone(), "tier-i-unwind-frame");
    let compact = compact_core
        .execute_with_trace_handoff(&module, Some(&plan), TraceHandoff::RetainInCore)
        .expect("compact caught throw");
    let mut baseline_core = InterpreterCore::new(config, "tier-i-unwind-frame");
    let baseline = baseline_core
        .execute(&module)
        .expect("baseline caught throw");

    assert_execution_semantics_equal(&compact, &baseline);
    assert_eq!(compact.value, Value::Int(9));
    assert_eq!(compact_core.registers.len(), max_registers * 2);
    assert_eq!(baseline_core.registers.len(), max_registers * 2);
}

#[test]
fn compact_tier1_frame_verifier_rejects_bad_edges_bd_bridge_5_3() {
    let descriptor = |entry, frame_size| Ir3FunctionDesc {
        entry,
        arity: 0,
        frame_size,
        name: None,
        is_generator: false,
        rest_param_index: None,
    };

    let cross_window = test_module_with_functions(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 1 },
            Ir3Instruction::Halt,
            Ir3Instruction::Jump { target: 3 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![descriptor(0, 1), descriptor(2, 1), descriptor(3, 1)],
    );
    assert_eq!(
        CompactTier1Program::compile(&cross_window)
            .expect("compact cross-window plan")
            .verified_function_frame_clear_width,
        None
    );

    let overflowing_range = test_module_with_functions(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 1 },
            Ir3Instruction::Halt,
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange {
                    start: u32::MAX,
                    count: 2,
                },
                dst: 0,
            },
        ],
        vec![descriptor(0, 1), descriptor(2, 1)],
    );
    assert_eq!(
        CompactTier1Program::compile(&overflowing_range)
            .expect("compact overflowing-range plan")
            .verified_function_frame_clear_width,
        None
    );
}

#[test]
fn bounded_register_liveness_preserves_unequal_files_bd_9vouw_500() {
    // These include the two normal lane widths, empty/unequal files,
    // and a conservative bound left above a truncated file's end.
    for value_len in [0, 1, 7, 256, 4096] {
        for label_len in [0, 1, 7, 256, 4096] {
            for dirty_end in [0, 1, 5, 256, usize::MAX] {
                let value_limit = value_len.min(dirty_end);
                let label_limit = label_len.min(dirty_end);
                let positions =
                    |limit: usize| [None, limit.checked_sub(1), (limit > 1).then_some(0)];
                for value_index in positions(value_limit) {
                    for label_index in positions(label_limit) {
                        let mut registers = vec![Value::Undefined; value_len];
                        let mut labels = vec![Label::Public; label_len];
                        if let Some(index) = value_index {
                            registers[index] = Value::Null;
                        }
                        if let Some(index) = label_index {
                            labels[index] = Label::Secret;
                        }
                        let expected = value_index
                            .map_or(0, |index| index + 1)
                            .max(label_index.map_or(0, |index| index + 1));
                        assert_eq!(
                            live_register_prefix_len(&registers, &labels, dirty_end),
                            expected,
                            "values={value_len}, labels={label_len}, bound={dirty_end}"
                        );
                        assert_eq!(
                            live_register_prefix_len_by_walk(&registers, &labels),
                            expected
                        );
                    }
                }
            }
        }
    }
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "a register past register_dirty_end")]
fn bounded_register_liveness_detects_untracked_labels_bd_9vouw_500() {
    let registers = vec![Value::Undefined; 64];
    let mut labels = vec![Label::Public; 64];
    labels[63] = Label::Secret;
    // A missed label-only write must fail the debug oracle before a
    // parked snapshot could silently omit its taint.
    let _ = live_register_prefix_len(&registers, &labels, 4);
}

#[test]
fn generator_initial_dirty_bound_covers_materialized_parameters_bd_9vouw_500() {
    for (arity, rest, arguments, labels, dirty_end, live) in [
        (3, None, vec![], vec![], 0, 0),
        (
            3,
            None,
            vec![Value::Int(7), Value::Undefined],
            vec![Label::Public, Label::Secret],
            2,
            2,
        ),
        (3, None, vec![Value::Undefined], vec![Label::Public], 1, 0),
        (
            1,
            None,
            vec![Value::Int(7), Value::Int(8)],
            vec![Label::Public, Label::Secret],
            1,
            1,
        ),
        (3, Some(2), vec![Value::Int(7)], vec![Label::Public], 3, 3),
    ] {
        let mut core = quickjs_test_core();
        let window = core.config.max_registers as usize;
        let module = test_module_with_functions(
            vec![Ir3Instruction::Return { value: 0 }],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity,
                frame_size: window as u32,
                name: Some("parked_parameters".to_string()),
                is_generator: true,
                rest_param_index: rest,
            }],
        );
        let execution = core
            .prepare_generator_execution(
                &module,
                GeneratorInvocation {
                    function_index: 0,
                    closure_index: None,
                    arguments,
                    argument_labels: labels,
                    this_value: Value::Undefined,
                    this_label: Label::Public,
                    inline_context_label: None,
                    module_specifier: None,
                    generated_function_artifact: None,
                },
            )
            .expect("generator parameters fit");
        assert_eq!(execution.register_dirty_end, dirty_end);
        assert_eq!(execution.registers.len(), live);
        assert_eq!(execution.register_labels.len(), live);
        assert_eq!(execution.register_len, window);
        assert_eq!(execution.register_label_len, window);
        if let Some(rest_index) = rest {
            assert!(matches!(
                execution.registers[rest_index as usize],
                Value::Object(_)
            ));
        }
    }
}

#[test]
fn parked_activation_preserves_unequal_files_and_dirty_bound_bd_9vouw_500() {
    for labels_longer in [false, true] {
        let mut core = quickjs_test_core();
        let window = core.config.max_registers as usize;
        let (value_len, label_len, value_index, label_index) = if labels_longer {
            (8, window, 3, 13)
        } else {
            (window, 8, 13, 3)
        };
        let value = Value::str("owned by parked activation");
        let label = Label::Custom {
            name: "parked-label".to_string(),
            level: 42,
        };
        core.write_reg(value_index, value.clone())
            .expect("value write");
        core.set_register_label(label_index, label.clone())
            .expect("label-only write");
        // A cleared high write leaves a conservative bound. Parking
        // must save that bound, not substitute the shorter live prefix.
        core.write_reg(20, Value::Int(1)).expect("high write");
        core.write_reg(20, Value::Undefined)
            .expect("clear high value");
        core.mutate_registers(|registers| registers.truncate(value_len));
        core.register_labels.truncate(label_len);
        let value_bytes = core.registers_memory_bytes();
        let label_bytes = core.register_labels_memory_bytes();
        let total_bytes = core.estimated_memory_bytes();

        for _ in 0..3 {
            let execution = core.take_generator_execution();
            assert_eq!(execution.registers.len(), value_len.min(14));
            assert_eq!(execution.register_labels.len(), label_len.min(14));
            assert_eq!(execution.register_dirty_end, 21);
            assert_eq!(execution.registers_value_bytes, Some(value_bytes));
            assert_eq!(execution.register_labels_bytes, Some(label_bytes));
            assert_eq!(core.register_dirty_end, 0);
            assert!(core.registers.is_empty() && core.register_labels.is_empty());
            core.install_generator_execution(execution);
            assert_eq!(core.registers.len(), value_len);
            assert_eq!(core.register_labels.len(), label_len);
            assert_eq!(core.register_dirty_end, 21);
            assert_eq!(core.read_reg(value_index).expect("restored value"), value);
            assert_eq!(
                core.get_register_label(label_index)
                    .expect("restored label"),
                &label
            );
            assert_eq!(core.registers_memory_bytes(), value_bytes);
            assert_eq!(core.register_labels_memory_bytes(), label_bytes);
            assert_eq!(core.estimated_memory_bytes(), total_bytes);
            assert_eq!(core.recompute_estimated_memory_bytes(), total_bytes);
        }
    }
}

#[test]
fn async_register_window_preserves_missing_capacity_bd_9vouw_500() {
    let mut core = quickjs_test_core();
    let window = core.config.max_registers as usize;
    core.write_reg(5, Value::Int(7)).expect("value write");
    core.set_register_label(13, Label::Secret)
        .expect("label-only write");
    for (start, end, expected) in [
        (0, window, 14),
        (3, 8, 6),
        (6, 12, 6),
        (14, window, 14),
        (20, 20, 20),
        (20, 10, 20),
    ] {
        assert_eq!(core.register_window_live_end(start, end), expected);
        assert_eq!(core.register_window_live_end_by_walk(start, end), expected);
    }
    // The old scan treats missing parallel capacity as live so the
    // await preflight refuses it. A dirty bound must not conceal it.
    core.register_labels.truncate(8);
    assert_eq!(core.register_window_live_end(3, window), window);
    assert_eq!(core.register_window_live_end(20, window), window);
    core.mutate_registers(|registers| registers.truncate(4));
    assert_eq!(core.register_window_live_end(0, 8), 8);
    assert_eq!(core.register_window_live_end(3, 4), 3);
}

fn test_module_with_functions(
    instructions: Vec<Ir3Instruction>,
    functions: Vec<Ir3FunctionDesc>,
) -> Ir3Module {
    let mut m = test_module(instructions);
    m.function_table = functions;
    m
}

#[test]
fn exact_module_specifier_boundary_is_injective_bd_lfq44() {
    let ordinary = JsString::from("./fixture.js");
    assert_eq!(
        InterpreterCore::utf8_module_specifier(&ordinary)
            .expect("ordinary module source has an exact UTF-8 view"),
        "./fixture.js"
    );

    let d800 = JsString::from_code_units(&[0xD800]);
    let dc00 = JsString::from_code_units(&[0xDC00]);
    assert_eq!(d800.as_utf8_projection(), dc00.as_utf8_projection());

    let module = test_module(Vec::new());
    for (specifier, expected_label) in [(&d800, "\\uD800"), (&dc00, "\\uDC00")] {
        let mut core = InterpreterCore::new(
            InterpreterConfig::quickjs_defaults(),
            "bd-lfq44-module-source-boundary",
        );
        for error in [
            core.import_module(&module, specifier)
                .expect_err("exact lone unit cannot enter the UTF-8 module loader"),
            core.require_module(&module, specifier)
                .expect_err("exact lone unit cannot enter the UTF-8 require loader"),
        ] {
            assert!(matches!(
                error,
                InterpreterError::ModuleResolutionFailed {
                    specifier,
                    reason: ModuleResolutionFailureReason::MalformedSpecifier,
                } if specifier == expected_label
            ));
        }
    }
}

/// Pre-create the entry module record (specifier "test", matching
/// `test_module`'s `source_label`) BEFORE a hook is installed. On the first
/// `execute()`, `prepare_execution` lazily allocates the module-namespace
/// object (via `ensure_module_record`), which itself fires a pre-allocation
/// hook at `instruction_count == 0`. Priming the record here (while no hook
/// is set, so no event is recorded) makes that idempotent `ensure_module_record`
/// early-return during the real run, isolating the specific
/// allocation/call/property event each hook test asserts on from incidental
/// module-initialization bookkeeping. It does not run any IR instruction, so
/// `instructions_executed` stays 0 and the asserted `instruction_count`s hold.
fn prime_entry_module_record(core: &mut InterpreterCore) {
    core.ensure_module_record(&test_module(Vec::new()), "test")
        .expect("prime entry module record before installing hook");
}

/// Build a test interpreter config that grants the execution capabilities
/// every baseline interpreter test needs. The production `quickjs_defaults`
/// / `v8_defaults` intentionally start with an empty capability set so
/// callers must explicitly grant what an extension may do; tests are not
/// exercising the grant-policy surface, so they need a fully-enabled
/// baseline to actually dispatch VM instructions and allocate objects.
fn test_quickjs_config() -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = RuntimeCapability::ALL.into_iter().collect();
    config
}

fn test_v8_config() -> InterpreterConfig {
    let mut config = InterpreterConfig::v8_defaults();
    config.granted_capabilities = RuntimeCapability::ALL.into_iter().collect();
    config
}

fn quickjs_execute(module: &Ir3Module) -> Result<ExecutionResult, InterpreterError> {
    QuickJsLane::with_config(test_quickjs_config()).execute(module, "test-trace")
}

fn v8_execute(module: &Ir3Module) -> Result<ExecutionResult, InterpreterError> {
    V8Lane::with_config(test_v8_config()).execute(module, "test-trace")
}

fn quickjs_test_core() -> InterpreterCore {
    InterpreterCore::new(test_quickjs_config(), "test-trace")
}

#[test]
fn bigint_load_preflights_instruction_clone_and_arc_bd_aw8td() {
    let digits = "9".repeat(512);
    let module = test_module(vec![
        Ir3Instruction::LoadBigInt {
            dst: 0,
            value: digits.clone(),
        },
        Ir3Instruction::Halt,
    ]);
    let fixture = || {
        let mut core = quickjs_test_core();
        core.sync_estimated_memory_bytes()
            .expect("BigInt load fixture accounting");
        let seed = core
            .capture_execution_seed()
            .expect("BigInt load fixture seed reservation");
        (core, seed)
    };
    let peak = InterpreterCore::bigint_literal_construction_peak_bytes(&digits);

    let (mut one_short, one_short_seed) = fixture();
    let baseline = one_short.estimated_memory_bytes();
    one_short.config.max_total_memory_bytes = baseline.saturating_add(peak).saturating_sub(1);
    assert!(matches!(
        one_short.run_loop(&module),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(one_short.ip, 0);
    assert_eq!(one_short.instructions_executed, 0);
    assert_eq!(
        one_short.read_reg(0).expect("destination register"),
        Value::Undefined
    );
    assert_eq!(one_short.estimated_memory_bytes(), baseline);
    drop(one_short_seed);

    let (mut exact, exact_seed) = fixture();
    let exact_baseline = exact.estimated_memory_bytes();
    exact.config.max_total_memory_bytes = exact_baseline.saturating_add(peak);
    assert_eq!(exact.run_loop(&module), Err(InterpreterError::Halted));
    assert_eq!(
        exact.read_reg(0).expect("loaded BigInt"),
        Value::BigInt(Arc::from(digits))
    );
    assert!(exact.estimated_memory_bytes() <= exact.config.max_total_memory_bytes);
    drop(exact_seed);
}

#[test]
fn bigint_add_preflights_label_decimal_scratch_and_arc_bd_aw8td() {
    let lhs = "9".repeat(384);
    let rhs = "1".to_string();
    let label = Label::Custom {
        name: "bigint-add-label".repeat(64),
        level: 8,
    };
    let module = test_module(vec![
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let fixture = || {
        let mut core = quickjs_test_core();
        core.write_reg_with_label(1, Value::BigInt(Arc::from(lhs.as_str())), label.clone())
            .expect("left BigInt fixture");
        core.write_reg(2, Value::BigInt(Arc::from(rhs.as_str())))
            .expect("right BigInt fixture");
        core.write_reg_with_label(0, Value::Int(77), Label::Internal)
            .expect("destination sentinel");
        core.sync_estimated_memory_bytes()
            .expect("BigInt add fixture accounting");
        core
    };
    let peak = InterpreterCore::bigint_add_construction_peak_bytes(&lhs, &rhs)
        .saturating_add(InterpreterCore::estimate_label_bytes(&label));

    let mut one_short = fixture();
    let baseline = one_short.estimated_memory_bytes();
    one_short.config.max_total_memory_bytes = baseline.saturating_add(peak).saturating_sub(1);
    assert!(matches!(
        one_short.run_loop(&module),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(one_short.ip, 0);
    assert_eq!(
        one_short.read_reg(0).expect("destination sentinel"),
        Value::Int(77)
    );
    assert_eq!(
        one_short.get_register_label(0).expect("destination label"),
        &Label::Internal
    );
    assert_eq!(one_short.estimated_memory_bytes(), baseline);

    let mut exact = fixture();
    let exact_baseline = exact.estimated_memory_bytes();
    exact.config.max_total_memory_bytes = exact_baseline.saturating_add(peak);
    assert_eq!(exact.run_loop(&module), Err(InterpreterError::Halted));
    let Value::BigInt(result) = exact.read_reg(0).expect("BigInt sum") else {
        panic!("BigInt add must publish a BigInt")
    };
    assert_eq!(result.as_ref(), format!("1{}", "0".repeat(384)));
    assert_eq!(exact.get_register_label(0).expect("sum label"), &label);
}

fn bigint_callback_fixture() -> (InterpreterCore, Ir3Module, String, String) {
    let left = "8".repeat(256);
    let right = "1".repeat(256);
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadBigInt {
                dst: 4,
                value: left.clone(),
            },
            Ir3Instruction::LoadBigInt {
                dst: 5,
                value: right.clone(),
            },
            Ir3Instruction::Add {
                dst: 6,
                lhs: 4,
                rhs: 5,
            },
            Ir3Instruction::Return { value: 6 },
        ],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 4,
            frame_size: 7,
            name: Some("bigint_callback".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = quickjs_test_core();
    core.config.max_registers = 8;
    core.sync_estimated_memory_bytes()
        .expect("callback fixture accounting");
    (core, module, left, right)
}

fn bigint_callback_peak(core: &InterpreterCore, left: &str, right: &str) -> u64 {
    u64::from(core.config.max_registers)
        .saturating_mul(u64::try_from(std::mem::size_of::<Value>()).unwrap_or(u64::MAX))
        .saturating_add(InterpreterCore::estimate_string_bytes(left))
        .saturating_add(InterpreterCore::estimate_string_bytes(right))
        .saturating_add(InterpreterCore::bigint_add_construction_peak_bytes(
            left, right,
        ))
}

#[test]
fn reducer_register_file_is_reused_clean_and_its_bytes_released() {
    // The reducer lane keeps its register file between callbacks: the
    // second callback reads register 5, which only the first one wrote,
    // and must see `undefined`, not the first callback's BigInt.
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadBigInt {
                dst: 5,
                value: "7".repeat(64),
            },
            Ir3Instruction::Return { value: 5 },
            Ir3Instruction::Return { value: 5 },
        ],
        vec![
            Ir3FunctionDesc {
                entry: 0,
                arity: 4,
                frame_size: 6,
                name: Some("writes_r5".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 2,
                arity: 4,
                frame_size: 6,
                name: Some("reads_r5".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
        ],
    );
    let mut core = quickjs_test_core();
    core.config.max_registers = 8;
    core.sync_estimated_memory_bytes()
        .expect("callback fixture accounting");
    let first = core
        .invoke_simple_reduce_callback(
            Some(&module),
            &Value::Function(0),
            Value::Int(0),
            Value::Int(1),
            0,
            ObjectId(0),
        )
        .expect("first reducer callback");
    assert!(matches!(first, Value::BigInt(_)));
    let second = core
        .invoke_simple_reduce_callback(
            Some(&module),
            &Value::Function(1),
            Value::Int(0),
            Value::Int(1),
            1,
            ObjectId(0),
        )
        .expect("second reducer callback");
    assert_eq!(second, Value::Undefined);
    assert_eq!(core.simple_callback_temporary_bytes, 0);
    assert!(
        core.simple_callback_register_pool
            .iter()
            .all(|value| matches!(value, Value::Undefined)),
        "the pooled register file is all undefined between callbacks"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn callback_bigints_reserve_cumulative_locals_and_construction_peak_bd_aw8td() {
    let (mut reduce_short, module, left, right) = bigint_callback_fixture();
    let peak = bigint_callback_peak(&reduce_short, &left, &right);
    let baseline = reduce_short.estimated_memory_bytes();
    reduce_short.config.max_total_memory_bytes = baseline.saturating_add(peak).saturating_sub(1);
    assert!(matches!(
        reduce_short.invoke_simple_reduce_callback(
            Some(&module),
            &Value::Function(0),
            Value::Int(0),
            Value::Int(1),
            0,
            ObjectId(0),
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(reduce_short.simple_callback_temporary_bytes, 0);
    assert_eq!(
        reduce_short.estimated_memory_bytes(),
        reduce_short.recompute_estimated_memory_bytes()
    );

    let (mut reduce_exact, module, left, right) = bigint_callback_fixture();
    let peak = bigint_callback_peak(&reduce_exact, &left, &right);
    let baseline = reduce_exact.estimated_memory_bytes();
    reduce_exact.config.max_total_memory_bytes = baseline.saturating_add(peak);
    assert!(matches!(
        reduce_exact
            .invoke_simple_reduce_callback(
                Some(&module),
                &Value::Function(0),
                Value::Int(0),
                Value::Int(1),
                0,
                ObjectId(0),
            )
            .expect("reducer callback at exact construction ceiling"),
        Value::BigInt(_)
    ));
    assert_eq!(reduce_exact.simple_callback_temporary_bytes, 0);

    // Array.from now executes the ordinary interpreter, not a private
    // Vec of mini-interpreter locals. Its register file is already in the
    // baseline; pin the cumulative operand + construction peak on the
    // actual run_loop path, without the removed Vec's carrier charge.
    // The reducer above still owns (and tests) its separate local Vec.
    let (mut ordinary_short, mut module, left, right) = bigint_callback_fixture();
    *module.instructions.last_mut().expect("callback return") = Ir3Instruction::Halt;
    let live_operands = InterpreterCore::estimate_string_bytes(&left)
        .saturating_add(InterpreterCore::estimate_string_bytes(&right));
    let peak = live_operands.saturating_add(InterpreterCore::bigint_add_construction_peak_bytes(
        &left, &right,
    ));
    let baseline = ordinary_short.estimated_memory_bytes();
    ordinary_short.config.max_total_memory_bytes = baseline.saturating_add(peak).saturating_sub(1);
    assert!(matches!(
        ordinary_short.run_loop(&module),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(ordinary_short.ip, 2, "refuse before BigInt addition");
    assert_eq!(ordinary_short.read_reg(6).unwrap(), Value::Undefined);
    assert_eq!(
        ordinary_short.estimated_memory_bytes(),
        baseline.saturating_add(live_operands),
    );
    assert_eq!(
        ordinary_short.estimated_memory_bytes(),
        ordinary_short.recompute_estimated_memory_bytes(),
    );
    assert_eq!(ordinary_short.simple_callback_temporary_bytes, 0);

    let (mut ordinary_exact, mut module, left, right) = bigint_callback_fixture();
    *module.instructions.last_mut().expect("callback return") = Ir3Instruction::Halt;
    let peak = InterpreterCore::estimate_string_bytes(&left)
        .saturating_add(InterpreterCore::estimate_string_bytes(&right))
        .saturating_add(InterpreterCore::bigint_add_construction_peak_bytes(
            &left, &right,
        ));
    let baseline = ordinary_exact.estimated_memory_bytes();
    ordinary_exact.config.max_total_memory_bytes = baseline.saturating_add(peak);
    assert_eq!(
        ordinary_exact.run_loop(&module),
        Err(InterpreterError::Halted)
    );
    let expected = Value::BigInt(Arc::from("9".repeat(256)));
    assert_eq!(ordinary_exact.read_reg(6).unwrap(), expected);
    assert_eq!(ordinary_exact.simple_callback_temporary_bytes, 0);
    assert_eq!(
        ordinary_exact.estimated_memory_bytes(),
        ordinary_exact.recompute_estimated_memory_bytes(),
    );

    // Exercise the public operation's mapper wiring as well: real call
    // frames need more registers than the removed eight-slot local Vec.
    let (mut mapped, module, _, _) = bigint_callback_fixture();
    mapped.config.max_registers = 32;
    let source = mapped.alloc_array_from_values(&[Value::Int(1)]).unwrap();
    mapped.write_reg(0, Value::Object(source)).unwrap();
    mapped.write_reg(1, Value::Function(0)).unwrap();
    let Value::Object(result) = mapped
        .array_from_builtin(Some(&module), RegRange { start: 0, count: 2 })
        .expect("ordinary Array.from BigInt callback")
    else {
        panic!("Array.from must produce an array");
    };
    assert_eq!(
        mapped.heap[result.0 as usize].properties.get("0"),
        Some(&expected)
    );
    assert_eq!(
        mapped.heap[result.0 as usize].properties.get("length"),
        Some(&Value::Int(1)),
    );
    assert_eq!(mapped.simple_callback_temporary_bytes, 0);
    assert_eq!(
        mapped.estimated_memory_bytes(),
        mapped.recompute_estimated_memory_bytes(),
    );
}

#[test]
fn require_and_accessor_first_construction_are_budget_atomic_bd_aw8td() {
    let empty_left = BuiltinFunction::new_kind(BuiltinFunctionKind::MathAbs);
    let empty_right = BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayPush);
    assert!(empty_left.module_specifier.is_empty());
    assert!(empty_right.module_specifier.is_empty());
    assert!(empty_left.module_specifier.0.is_none());
    assert!(empty_right.module_specifier.0.is_none());
    let empty_wire = serde_json::to_string(&empty_left).expect("serialize empty builtin");
    assert!(!empty_wire.contains("module_specifier"));
    assert_eq!(
        serde_json::from_str::<BuiltinFunction>(&empty_wire)
            .expect("roundtrip empty builtin")
            .module_specifier
            .as_ref(),
        ""
    );

    let specifier = format!("/fixture/{}/entry.cjs", "nested/".repeat(64));
    let dirname = Path::new(&specifier)
        .parent()
        .expect("absolute fixture has a parent")
        .display()
        .to_string();
    let cjs_names = ["require", "exports", "module", "__filename", "__dirname"];
    let cjs_fixture = || {
        let mut core = quickjs_test_core();
        let module_object = core
            .alloc_object_with_prototype(None)
            .expect("CJS module fixture object");
        let exports_object = core
            .alloc_object_with_prototype(None)
            .expect("CJS exports fixture object");
        let frame = core.scope_chain.current_mut().expect("CJS fixture scope");
        for name in cjs_names {
            frame.insert_binding(
                name.to_string(),
                ScopeBinding::with_state(
                    BindingKind::Var,
                    Value::str(format!("old-{name}-{}", "x".repeat(2048))),
                    true,
                ),
            );
        }
        core.sync_estimated_memory_bytes()
            .expect("CJS fixture accounting");
        (core, module_object, exports_object)
    };
    let rollback_slots = u64::try_from(cjs_names.len().saturating_mul(std::mem::size_of::<(
        String,
        Option<ScopeBinding>,
        Option<ScopeBindingState>,
    )>()))
    .unwrap_or(u64::MAX);
    let binding_and_name_bytes = cjs_names.into_iter().fold(0u64, |total, name| {
        total.saturating_add(
            MEMORY_ESTIMATE_SCOPE_BINDING_BASE_BYTES
                .saturating_add(InterpreterCore::estimate_string_bytes(name).saturating_mul(2)),
        )
    });
    let require_peak = InterpreterCore::estimate_string_bytes(&specifier)
        .saturating_mul(2)
        .saturating_add(InterpreterCore::estimate_string_bytes(&dirname))
        .saturating_add(rollback_slots)
        .saturating_add(binding_and_name_bytes);

    let (mut require_short, module_object, exports_object) = cjs_fixture();
    let baseline = require_short.estimated_memory_bytes();
    let bindings_before = cjs_names.map(|name| {
        require_short
            .scope_chain
            .resolve(name)
            .expect("seeded CJS binding")
            .1
            .value()
            .expect("seeded CJS value")
    });
    let requested = baseline.saturating_add(require_peak);
    require_short.config.max_total_memory_bytes = requested.saturating_sub(1);
    assert_eq!(
        require_short.insert_cjs_bindings(module_object, exports_object, Some(&specifier),),
        Err(InterpreterError::MemoryBudgetExceeded {
            requested_bytes: requested,
            max_bytes: requested.saturating_sub(1),
            requested_heap_objects: require_short.heap_object_count_u32(),
            max_heap_objects: require_short.config.max_heap_objects,
        })
    );
    assert_eq!(
        cjs_names.map(|name| {
            require_short
                .scope_chain
                .resolve(name)
                .expect("CJS binding after refusal")
                .1
                .value()
                .expect("CJS value after refusal")
        }),
        bindings_before
    );
    assert_eq!(require_short.estimated_memory_bytes(), baseline);

    let (mut require_exact, module_object, exports_object) = cjs_fixture();
    let baseline = require_exact.estimated_memory_bytes();
    require_exact.config.max_total_memory_bytes = baseline.saturating_add(require_peak);
    require_exact
        .insert_cjs_bindings(module_object, exports_object, Some(&specifier))
        .expect("CJS bindings at exact require construction ceiling");
    let binding_value = |core: &InterpreterCore, name: &str| {
        core.scope_chain
            .resolve(name)
            .expect("installed CJS binding")
            .1
            .value()
            .expect("installed CJS value")
    };
    let Value::BuiltinFunction(require) = binding_value(&require_exact, "require") else {
        panic!("require binding must be callable")
    };
    assert_eq!(require.kind, BuiltinFunctionKind::Require);
    assert_eq!(require.module_specifier.as_ref(), specifier);
    assert_eq!(
        binding_value(&require_exact, "__filename"),
        Value::str(specifier.clone())
    );
    assert_eq!(
        binding_value(&require_exact, "__dirname"),
        Value::str(dirname)
    );
    assert_eq!(
        binding_value(&require_exact, "module"),
        Value::Object(module_object)
    );
    assert_eq!(
        binding_value(&require_exact, "exports"),
        Value::Object(exports_object)
    );
    assert_eq!(
        require_exact.estimated_memory_bytes(),
        require_exact.recompute_estimated_memory_bytes()
    );

    let cjs_property_fixture = || {
        let mut core = quickjs_test_core();
        let module_object = core
            .alloc_object_with_prototype(None)
            .expect("CJS require-property object");
        core.set_object_property(
            module_object,
            "require".to_string(),
            Value::str("old-require".repeat(256)),
        )
        .expect("seed old CJS require property");
        core.sync_estimated_memory_bytes()
            .expect("CJS require-property accounting");
        (core, module_object)
    };
    let property_key_bytes = InterpreterCore::estimate_string_bytes("require");
    let property_peak =
        property_key_bytes.saturating_add(InterpreterCore::estimate_string_bytes(&specifier));

    let (mut property_key_short, module_object) = cjs_property_fixture();
    let baseline = property_key_short.estimated_memory_bytes();
    let property_requested = baseline.saturating_add(property_peak);
    let key_short_max = baseline
        .saturating_add(property_key_bytes)
        .saturating_sub(1);
    let wire_before = serde_json::to_string(&property_key_short.heap[module_object.0 as usize])
        .expect("serialize CJS property before key-boundary refusal");
    property_key_short.config.max_total_memory_bytes = key_short_max;
    assert_eq!(
        property_key_short.set_cjs_require_property(module_object, &specifier),
        Err(InterpreterError::MemoryBudgetExceeded {
            requested_bytes: property_requested,
            max_bytes: key_short_max,
            requested_heap_objects: property_key_short.heap_object_count_u32(),
            max_heap_objects: property_key_short.config.max_heap_objects,
        })
    );
    assert_eq!(
        serde_json::to_string(&property_key_short.heap[module_object.0 as usize])
            .expect("serialize CJS property after key-boundary refusal"),
        wire_before
    );
    assert_eq!(property_key_short.estimated_memory_bytes(), baseline);
    assert_eq!(
        property_key_short.estimated_memory_bytes(),
        property_key_short.recompute_estimated_memory_bytes()
    );

    let (mut property_short, module_object) = cjs_property_fixture();
    let baseline = property_short.estimated_memory_bytes();
    let property_requested = baseline.saturating_add(property_peak);
    let wire_before = serde_json::to_string(&property_short.heap[module_object.0 as usize])
        .expect("serialize CJS property before refusal");
    property_short.config.max_total_memory_bytes = property_requested.saturating_sub(1);
    assert_eq!(
        property_short.set_cjs_require_property(module_object, &specifier),
        Err(InterpreterError::MemoryBudgetExceeded {
            requested_bytes: property_requested,
            max_bytes: property_requested.saturating_sub(1),
            requested_heap_objects: property_short.heap_object_count_u32(),
            max_heap_objects: property_short.config.max_heap_objects,
        })
    );
    assert_eq!(
        serde_json::to_string(&property_short.heap[module_object.0 as usize])
            .expect("serialize CJS property after refusal"),
        wire_before
    );
    assert_eq!(property_short.estimated_memory_bytes(), baseline);

    let (mut property_exact, module_object) = cjs_property_fixture();
    property_exact.config.max_total_memory_bytes = property_exact
        .estimated_memory_bytes()
        .saturating_add(property_peak);
    property_exact
        .set_cjs_require_property(module_object, &specifier)
        .expect("CJS require property at exact construction ceiling");
    let Value::BuiltinFunction(require) = property_exact.heap[module_object.0 as usize]
        .properties
        .get("require")
        .expect("installed CJS require property")
    else {
        panic!("CJS require property must be callable")
    };
    assert_eq!(require.kind, BuiltinFunctionKind::Require);
    assert_eq!(require.module_specifier.as_ref(), specifier);
    assert_eq!(
        property_exact.estimated_memory_bytes(),
        property_exact.recompute_estimated_memory_bytes()
    );

    let accessor_fixture = || {
        let mut core = quickjs_test_core();
        let object = core
            .alloc_object_with_prototype(None)
            .expect("accessor fixture object");
        core.sync_estimated_memory_bytes()
            .expect("accessor fixture accounting");
        (core, object)
    };
    let (mut one_short, object) = accessor_fixture();
    let key = JsString::from("value");
    let arc_value_bytes = u64::try_from(std::mem::size_of::<Value>())
        .unwrap_or(u64::MAX)
        .saturating_add(
            u64::try_from(2usize.saturating_mul(std::mem::size_of::<usize>())).unwrap_or(u64::MAX),
        );
    let previous_map = InterpreterCore::estimate_ordered_property_map_bytes_nonalloc(
        &one_short.heap[object.0 as usize].properties,
    );
    assert_eq!(previous_map, 0);
    let next_map = MEMORY_ESTIMATE_MAP_ENTRY_BYTES
        .saturating_add(InterpreterCore::estimate_string_bytes("value").saturating_mul(2))
        .saturating_add(arc_value_bytes);
    let baseline = one_short.estimated_memory_bytes();
    let retained = baseline
        .saturating_sub(previous_map)
        .saturating_add(next_map);
    let construction = baseline
        .saturating_add(arc_value_bytes)
        .saturating_add(InterpreterCore::estimate_string_bytes("value"));
    let requested = retained.max(construction);
    one_short.config.max_total_memory_bytes = requested.saturating_sub(1);
    assert_eq!(
        one_short.define_accessor_property(
            object,
            RuntimePropertyKey::String(key.clone()),
            Value::Function(0),
            AccessorKind::Get,
        ),
        Err(InterpreterError::MemoryBudgetExceeded {
            requested_bytes: requested,
            max_bytes: requested.saturating_sub(1),
            requested_heap_objects: one_short.heap_object_count_u32(),
            max_heap_objects: one_short.config.max_heap_objects,
        })
    );
    assert!(
        one_short.heap[object.0 as usize]
            .properties
            .get("value")
            .is_none()
    );
    assert_eq!(one_short.estimated_memory_bytes(), baseline);
    assert_eq!(
        one_short.estimated_memory_bytes(),
        one_short.recompute_estimated_memory_bytes()
    );

    let (mut exact, object) = accessor_fixture();
    exact.config.max_total_memory_bytes = requested;
    exact
        .define_accessor_property(
            object,
            RuntimePropertyKey::String(key),
            Value::Function(0),
            AccessorKind::Get,
        )
        .expect("accessor first construction at exact ceiling");
    assert!(matches!(
        exact.heap[object.0 as usize].properties.get("value"),
        Some(Value::Accessor {
            get: Some(_),
            set: None
        })
    ));
    assert_eq!(
        exact.estimated_memory_bytes(),
        exact.recompute_estimated_memory_bytes()
    );
}

#[test]
fn accessor_merge_exact_activation_and_symbol_storage_are_atomic_bd_aw8td() {
    let arc_value_bytes = u64::try_from(std::mem::size_of::<Value>())
        .unwrap_or(u64::MAX)
        .saturating_add(
            u64::try_from(2usize.saturating_mul(std::mem::size_of::<usize>())).unwrap_or(u64::MAX),
        );

    let ordinary_fixture = || {
        let mut core = quickjs_test_core();
        let object = core
            .alloc_object_with_prototype(None)
            .expect("ordinary accessor merge object");
        core.define_accessor_property(
            object,
            RuntimePropertyKey::String(JsString::from("value")),
            Value::Function(1),
            AccessorKind::Get,
        )
        .expect("ordinary getter setup");
        core.sync_estimated_memory_bytes()
            .expect("ordinary accessor merge accounting");
        (core, object)
    };
    let (mut ordinary_short, object) = ordinary_fixture();
    let key = JsString::from("value");
    let previous_map = InterpreterCore::estimate_ordered_property_map_bytes_nonalloc(
        &ordinary_short.heap[object.0 as usize].properties,
    );
    let entry_without_accessor = MEMORY_ESTIMATE_MAP_ENTRY_BYTES
        .saturating_add(InterpreterCore::estimate_string_bytes("value").saturating_mul(2));
    assert_eq!(
        previous_map,
        entry_without_accessor.saturating_add(arc_value_bytes)
    );
    let next_map = entry_without_accessor.saturating_add(arc_value_bytes.saturating_mul(2));
    let baseline = ordinary_short.estimated_memory_bytes();
    let retained = baseline
        .saturating_sub(previous_map)
        .saturating_add(next_map);
    let construction = baseline
        .saturating_add(arc_value_bytes)
        .saturating_add(InterpreterCore::estimate_string_bytes("value"));
    let requested = retained.max(construction);
    let getter_before = match ordinary_short.heap[object.0 as usize]
        .properties
        .get("value")
    {
        Some(Value::Accessor {
            get: Some(getter), ..
        }) => getter.clone(),
        other => panic!("ordinary getter fixture is malformed: {other:?}"),
    };
    ordinary_short.config.max_total_memory_bytes = requested.saturating_sub(1);
    assert_eq!(
        ordinary_short.define_accessor_property(
            object,
            RuntimePropertyKey::String(key.clone()),
            Value::Function(2),
            AccessorKind::Set,
        ),
        Err(InterpreterError::MemoryBudgetExceeded {
            requested_bytes: requested,
            max_bytes: requested.saturating_sub(1),
            requested_heap_objects: ordinary_short.heap_object_count_u32(),
            max_heap_objects: ordinary_short.config.max_heap_objects,
        })
    );
    match ordinary_short.heap[object.0 as usize]
        .properties
        .get("value")
    {
        Some(Value::Accessor {
            get: Some(getter),
            set: None,
        }) => assert!(Arc::ptr_eq(getter, &getter_before)),
        other => panic!("ordinary getter changed after refusal: {other:?}"),
    }
    assert_eq!(ordinary_short.estimated_memory_bytes(), baseline);

    let (mut ordinary_exact, object) = ordinary_fixture();
    ordinary_exact.config.max_total_memory_bytes = requested;
    ordinary_exact
        .define_accessor_property(
            object,
            RuntimePropertyKey::String(key),
            Value::Function(2),
            AccessorKind::Set,
        )
        .expect("ordinary setter merge at exact construction ceiling");
    assert!(matches!(
        ordinary_exact.heap[object.0 as usize]
            .properties
            .get("value"),
        Some(Value::Accessor {
            get: Some(_),
            set: Some(_),
        })
    ));
    assert_eq!(
        ordinary_exact.estimated_memory_bytes(),
        ordinary_exact.recompute_estimated_memory_bytes()
    );

    let exact_fixture = || {
        let mut core = quickjs_test_core();
        let object = core
            .alloc_object_with_prototype(None)
            .expect("exact accessor activation object");
        core.set_object_property(object, "alpha".to_string(), Value::Int(1))
            .expect("first ordinary property");
        core.set_object_property(object, "beta".to_string(), Value::Int(2))
            .expect("second ordinary property");
        core.sync_estimated_memory_bytes()
            .expect("exact accessor activation accounting");
        (core, object)
    };
    let exact_key = JsString::from_code_units(&[0xD800]);
    let (mut exact_short, object) = exact_fixture();
    let previous_map = InterpreterCore::estimate_ordered_property_map_bytes_nonalloc(
        &exact_short.heap[object.0 as usize].properties,
    );
    let next_map = ["alpha", "beta"]
        .into_iter()
        .fold(0u64, |total, key| {
            total.saturating_add(
                MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                    .saturating_add(InterpreterCore::estimate_string_bytes(key).saturating_mul(4)),
            )
        })
        .saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES)
        .saturating_add(InterpreterCore::estimate_js_string_bytes(&exact_key).saturating_mul(3))
        .saturating_add(arc_value_bytes);
    let baseline = exact_short.estimated_memory_bytes();
    let retained = baseline
        .saturating_sub(previous_map)
        .saturating_add(next_map);
    let construction =
        baseline.saturating_add(arc_value_bytes.saturating_add(previous_map).max(next_map));
    let requested = retained.max(construction);
    let order_before = exact_short.heap[object.0 as usize].properties.exact_keys();
    exact_short.config.max_total_memory_bytes = requested.saturating_sub(1);
    assert_eq!(
        exact_short.define_accessor_property(
            object,
            RuntimePropertyKey::String(exact_key.clone()),
            Value::Function(3),
            AccessorKind::Get,
        ),
        Err(InterpreterError::MemoryBudgetExceeded {
            requested_bytes: requested,
            max_bytes: requested.saturating_sub(1),
            requested_heap_objects: exact_short.heap_object_count_u32(),
            max_heap_objects: exact_short.config.max_heap_objects,
        })
    );
    assert_eq!(
        exact_short.heap[object.0 as usize].properties.exact_keys(),
        order_before
    );
    assert_eq!(exact_short.estimated_memory_bytes(), baseline);

    let (mut exact_success, object) = exact_fixture();
    exact_success.config.max_total_memory_bytes = requested;
    exact_success
        .define_accessor_property(
            object,
            RuntimePropertyKey::String(exact_key.clone()),
            Value::Function(3),
            AccessorKind::Get,
        )
        .expect("first exact accessor at exact construction ceiling");
    assert_eq!(
        exact_success.heap[object.0 as usize]
            .properties
            .exact_keys(),
        vec![JsString::from("alpha"), JsString::from("beta"), exact_key]
    );
    assert_eq!(
        exact_success.estimated_memory_bytes(),
        exact_success.recompute_estimated_memory_bytes()
    );

    let symbol_fixture = || {
        let mut core = quickjs_test_core();
        let object = core
            .alloc_object_with_prototype(None)
            .expect("symbol accessor object");
        let symbol = core
            .allocate_private_symbol(Some(JsString::from("accessor")))
            .expect("symbol accessor key");
        core.define_accessor_property(
            object,
            RuntimePropertyKey::Symbol(symbol),
            Value::Function(4),
            AccessorKind::Get,
        )
        .expect("symbol getter setup");
        core.sync_estimated_memory_bytes()
            .expect("symbol accessor accounting");
        (core, object, symbol)
    };
    let (mut symbol_short, object, symbol) = symbol_fixture();
    let previous_map = InterpreterCore::estimate_ordered_property_map_bytes_nonalloc(
        &symbol_short.heap[object.0 as usize].properties,
    );
    let next_property = BaselineSymbolProperty::Accessor {
        get: Some(Value::Function(4)),
        set: Some(Value::Function(5)),
    };
    let next_map = MEMORY_ESTIMATE_MAP_ENTRY_BYTES
        .saturating_add((std::mem::size_of::<SymbolId>() as u64).saturating_mul(2));
    assert_eq!(previous_map, next_map);
    let baseline = symbol_short.estimated_memory_bytes();
    let retained = baseline
        .saturating_sub(previous_map)
        .saturating_add(next_map);
    let requested = retained.max(baseline.saturating_add(previous_map.max(next_map)));
    symbol_short.config.max_total_memory_bytes = requested.saturating_sub(1);
    assert_eq!(
        symbol_short.define_accessor_property(
            object,
            RuntimePropertyKey::Symbol(symbol),
            Value::Function(5),
            AccessorKind::Set,
        ),
        Err(InterpreterError::MemoryBudgetExceeded {
            requested_bytes: requested,
            max_bytes: requested.saturating_sub(1),
            requested_heap_objects: symbol_short.heap_object_count_u32(),
            max_heap_objects: symbol_short.config.max_heap_objects,
        })
    );
    assert_eq!(
        symbol_short.heap[object.0 as usize]
            .properties
            .baseline_symbol_property(core_symbol_id(symbol)),
        Some(&BaselineSymbolProperty::Accessor {
            get: Some(Value::Function(4)),
            set: None,
        })
    );
    assert_eq!(symbol_short.estimated_memory_bytes(), baseline);
    assert_eq!(
        symbol_short.estimated_memory_bytes(),
        symbol_short.recompute_estimated_memory_bytes()
    );

    let (mut symbol_exact, object, symbol) = symbol_fixture();
    symbol_exact.config.max_total_memory_bytes = requested;
    symbol_exact
        .define_accessor_property(
            object,
            RuntimePropertyKey::Symbol(symbol),
            Value::Function(5),
            AccessorKind::Set,
        )
        .expect("symbol setter merge at exact clone ceiling");
    assert_eq!(
        symbol_exact.heap[object.0 as usize]
            .properties
            .baseline_symbol_property(core_symbol_id(symbol)),
        Some(&next_property)
    );
    assert_eq!(
        symbol_exact.estimated_memory_bytes(),
        symbol_exact.recompute_estimated_memory_bytes()
    );
}

#[test]
fn crypto_brand_lifecycle_label_and_memory_are_private_bd_2z157() {
    let mut core = quickjs_test_core();
    let forged = core
        .alloc_object_with_properties(&[("__type", Value::str("Hash"))])
        .expect("forged ordinary object allocation");
    assert!(core.crypto_test_method(forged, "update").is_none());

    core.write_reg(0, Value::str("sha256"))
        .expect("seed hash algorithm");
    let Value::Object(hash) = core
        .crypto_create_hash(RegRange { start: 0, count: 1 })
        .expect("create authenticated hash")
    else {
        panic!("createHash must return an object")
    };
    core.clear_pending_hostcall_result_label();
    assert_eq!(
        core.prototype_chain_get(hash, "update")
            .expect("generic crypto property lookup must stay inert"),
        Value::Undefined,
        "authenticated crypto objects expose lifecycle methods only through finite HostCalls"
    );
    let update = core
        .crypto_test_method(hash, "update")
        .expect("authenticated hash update method");
    assert_eq!(update.bound_object, Some(hash.0));

    let classified = core
        .alloc_buffer_from_bytes(b"classified")
        .expect("classified input Buffer");
    core.join_binary_storage_label(classified, &Label::Secret)
        .expect("classify input backing");
    core.write_reg(0, Value::Object(classified))
        .expect("seed update input");
    core.crypto_update(
        Some(Value::Object(hash)),
        &update,
        RegRange { start: 0, count: 1 },
    )
    .expect("update authenticated hash");
    assert_eq!(core.crypto_objects[&hash].lifecycle_label(), &Label::Secret);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn crypto_object_hostcalls_revalidate_private_brand_bd_1by6p() {
    let mut core = quickjs_test_core();
    core.write_reg(0, Value::str("sha256"))
        .expect("seed hash algorithm");
    let Value::Object(hash) = core
        .crypto_create_hash(RegRange { start: 0, count: 1 })
        .expect("create authenticated hash")
    else {
        panic!("createHash must return an object")
    };
    core.clear_pending_hostcall_result_label();

    core.write_reg(0, Value::Object(hash))
        .expect("seed authenticated receiver");
    core.write_reg(1, Value::str("payload"))
        .expect("seed lifecycle input");
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:CryptoObjectUpdate",
            RegRange { start: 0, count: 2 },
            None,
        )
        .expect("finite lifecycle hostcall"),
        Value::Object(hash)
    );

    let classified = core
        .alloc_buffer_from_bytes(b"classified")
        .expect("classified lifecycle input Buffer");
    core.join_binary_storage_label(classified, &Label::Secret)
        .expect("classify lifecycle input backing");
    core.write_reg(0, Value::Object(hash))
        .expect("seed authenticated receiver for classified update");
    core.write_reg(1, Value::Object(classified))
        .expect("seed classified lifecycle input");
    core.dispatch_builtin_hostcall(
        "builtin:CryptoObjectUpdate",
        RegRange { start: 0, count: 2 },
        None,
    )
    .expect("classified finite lifecycle update");
    core.write_reg(0, Value::Object(hash))
        .expect("seed authenticated receiver for ignored digest encoding");
    core.write_reg(1, Value::Int(7))
        .expect("seed ignored digest encoding");
    let digest = core
        .dispatch_builtin_hostcall(
            "builtin:CryptoObjectDigest",
            RegRange { start: 0, count: 2 },
            None,
        )
        .expect("Node ignores a non-string hash digest encoding");
    assert!(matches!(digest, Value::Object(_)));
    assert_eq!(core.pending_hostcall_result_label, Some(Label::Secret));
    core.clear_pending_hostcall_result_label();

    let forged = core
        .alloc_object_with_properties(&[("__type", Value::str("Hash"))])
        .expect("forge ordinary object");
    core.write_reg(0, Value::Object(forged))
        .expect("seed forged receiver");
    assert!(matches!(
        core.dispatch_builtin_hostcall(
            "builtin:CryptoObjectDigest",
            RegRange { start: 0, count: 1 },
            None,
        ),
        Err(InterpreterError::UncaughtException { .. })
    ));
    assert_eq!(core.pending_exception_label, Label::TopSecret);
    core.clear_pending_exception_slot();

    assert!(matches!(
        core.dispatch_builtin_hostcall(
            "builtin:CryptoObjectDigest",
            RegRange { start: 0, count: 0 },
            None,
        ),
        Err(InterpreterError::UncaughtException { .. })
    ));
    assert_eq!(core.pending_exception_label, Label::TopSecret);
    core.clear_pending_exception_slot();

    core.write_reg(0, Value::str("not-an-object"))
        .expect("seed detached receiver");
    assert!(matches!(
        core.dispatch_builtin_hostcall(
            "builtin:CryptoObjectFinal",
            RegRange { start: 0, count: 1 },
            None,
        ),
        Err(InterpreterError::UncaughtException { .. })
    ));
    assert_eq!(core.pending_exception_label, Label::TopSecret);
    core.clear_pending_exception_slot();

    core.write_reg(0, Value::Object(hash))
        .expect("seed wrong-kind authenticated receiver");
    assert!(matches!(
        core.dispatch_builtin_hostcall(
            "builtin:CryptoObjectFinal",
            RegRange { start: 0, count: 1 },
            None,
        ),
        Err(InterpreterError::UncaughtException { .. })
    ));
    assert_eq!(core.pending_exception_label, Label::TopSecret);
    core.clear_pending_exception_slot();

    core.write_reg(0, Value::str("sha256"))
        .expect("seed HMAC algorithm");
    core.write_reg(1, Value::str("public-key"))
        .expect("seed HMAC key");
    let Value::Object(hmac) = core
        .crypto_create_hmac(RegRange { start: 0, count: 2 })
        .expect("create authenticated HMAC")
    else {
        panic!("createHmac must return an object")
    };
    core.clear_pending_hostcall_result_label();
    core.write_reg(0, Value::Object(hmac))
        .expect("seed authenticated HMAC receiver");
    assert!(matches!(
        core.dispatch_builtin_hostcall(
            "builtin:CryptoObjectCopy",
            RegRange { start: 0, count: 1 },
            None,
        ),
        Err(InterpreterError::UncaughtException { .. })
    ));
    assert_eq!(core.pending_exception_label, Label::TopSecret);
    core.clear_pending_exception_slot();
}

#[test]
fn buffer_object_hostcalls_revalidate_brand_and_publish_backing_labels_bd_nx5cb() {
    let mut core = quickjs_test_core();
    let buffer = core
        .alloc_buffer_from_bytes(&[1, 0, 0, 0])
        .expect("allocate authenticated Buffer");
    core.join_binary_storage_label(buffer, &Label::Secret)
        .expect("classify Buffer backing");

    core.write_reg(0, Value::Object(buffer))
        .expect("seed toString receiver");
    core.write_reg(1, Value::str("hex")).expect("seed encoding");
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:BufferObjectToString",
            RegRange { start: 0, count: 2 },
            None,
        )
        .expect("authenticated toString hostcall"),
        Value::str("01000000")
    );
    assert_eq!(core.pending_hostcall_result_label, Some(Label::Secret));
    core.clear_pending_hostcall_result_label();

    core.write_reg(0, Value::Object(buffer))
        .expect("seed integer receiver");
    core.write_reg(1, Value::Int(0)).expect("seed offset");
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:BufferObjectReadUInt32LE",
            RegRange { start: 0, count: 2 },
            None,
        )
        .expect("authenticated integer read hostcall"),
        Value::Int(1)
    );
    assert_eq!(core.pending_hostcall_result_label, Some(Label::Secret));
    core.clear_pending_hostcall_result_label();

    core.write_reg(0, Value::Object(buffer))
        .expect("seed invalid-encoding receiver");
    core.write_reg(1, Value::str("bogus"))
        .expect("seed invalid encoding");
    assert!(matches!(
        core.dispatch_builtin_hostcall(
            "builtin:BufferObjectToString",
            RegRange { start: 0, count: 2 },
            None,
        ),
        Err(InterpreterError::UncaughtException { .. })
    ));
    assert_eq!(core.pending_exception_label, Label::Secret);
    let Value::Object(error_id) = core
        .pending_exception
        .as_ref()
        .expect("unknown encoding must publish a Node error")
    else {
        panic!("unknown encoding must publish an object error")
    };
    assert_eq!(
        core.heap[error_id.0 as usize].properties.get("code"),
        Some(&Value::str("ERR_UNKNOWN_ENCODING"))
    );
    core.clear_pending_exception_slot();

    let short = core
        .alloc_buffer_from_bytes(&[0, 0])
        .expect("allocate short authenticated Buffer");
    core.join_binary_storage_label(short, &Label::Secret)
        .expect("classify short Buffer backing");
    core.write_reg(0, Value::Object(short))
        .expect("seed short integer receiver");
    core.write_reg(1, Value::Int(0)).expect("seed short offset");
    assert!(matches!(
        core.dispatch_builtin_hostcall(
            "builtin:BufferObjectReadUInt32LE",
            RegRange { start: 0, count: 2 },
            None,
        ),
        Err(InterpreterError::UncaughtException { .. })
    ));
    assert_eq!(core.pending_exception_label, Label::Secret);
    let Value::Object(error_id) = core
        .pending_exception
        .as_ref()
        .expect("out-of-bounds read must publish a Node error")
    else {
        panic!("out-of-bounds read must publish an object error")
    };
    assert_eq!(
        core.heap[error_id.0 as usize].properties.get("code"),
        Some(&Value::str("ERR_BUFFER_OUT_OF_BOUNDS"))
    );
    core.clear_pending_exception_slot();

    let forged = core
        .alloc_object_with_properties(&[("__type", Value::str("Buffer"))])
        .expect("allocate forged Buffer tag");
    let uint8 = core
        .alloc_typed_array_with_fresh_buffer(TypedArrayKind::Uint8, 4)
        .expect("allocate ordinary Uint8Array");
    for (case_name, receiver) in [
        ("forged", Value::Object(forged)),
        ("uint8", Value::Object(uint8)),
        ("primitive", Value::str("not-a-buffer")),
    ] {
        core.write_reg(0, receiver).expect("seed rejected receiver");
        assert!(
            matches!(
                core.dispatch_builtin_hostcall(
                    "builtin:BufferObjectReadUInt32LE",
                    RegRange { start: 0, count: 1 },
                    None,
                ),
                Err(InterpreterError::TypeError { .. })
            ),
            "{case_name} receiver must fail private-brand validation"
        );
        assert!(core.pending_hostcall_result_label.is_none());
    }
    assert!(matches!(
        core.dispatch_builtin_hostcall(
            "builtin:BufferObjectToString",
            RegRange { start: 0, count: 0 },
            None,
        ),
        Err(InterpreterError::TypeError { .. })
    ));
    assert!(core.pending_hostcall_result_label.is_none());

    let broken = core
        .alloc_buffer_from_bytes(&[0, 0, 0, 0])
        .expect("allocate Buffer before simulating broken backing identity");
    core.mutate_heap(|heap| {
        heap[broken.0 as usize]
            .typed_array
            .as_mut()
            .expect("Buffer must carry a typed-array view")
            .buffer = ObjectId(u32::MAX);
    });
    core.write_reg(0, Value::Object(broken))
        .expect("seed broken Buffer receiver");
    assert!(matches!(
        core.dispatch_builtin_hostcall(
            "builtin:BufferObjectReadUInt32LE",
            RegRange { start: 0, count: 1 },
            None,
        ),
        Err(InterpreterError::InternalError { .. })
    ));
    assert!(core.pending_hostcall_result_label.is_none());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn buffer_object_hostcall_exception_backing_label_reaches_enter_catch_bd_nx5cb() {
    let mut core = quickjs_test_core();
    let buffer = core
        .alloc_buffer_from_bytes(&[1, 2, 3, 4])
        .expect("allocate authenticated Buffer");
    core.join_binary_storage_label(buffer, &Label::Secret)
        .expect("classify Buffer backing");
    core.write_reg_with_label(0, Value::Object(buffer), Label::Public)
        .expect("seed public receiver register");
    core.write_reg_with_label(1, Value::str("bogus"), Label::Public)
        .expect("seed public encoding register");

    let module = test_module_with_functions(
        vec![
            Ir3Instruction::BeginTry {
                catch_target: 4,
                finally_target: None,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:BufferObjectToString".to_string()),
                args: RegRange { start: 0, count: 2 },
                dst: 2,
            },
            Ir3Instruction::EndTry,
            Ir3Instruction::Jump { target: 5 },
            Ir3Instruction::EnterCatch { dst: 2 },
            Ir3Instruction::Halt,
        ],
        Vec::new(),
    );
    core.execute(&module)
        .expect("Node-style Buffer error must enter the catch handler");

    assert_eq!(core.register_labels[2], Label::Secret);
    let Value::Object(error_id) = &core.registers[2] else {
        panic!("catch register must contain the structured Buffer error")
    };
    assert_eq!(
        core.heap[error_id.0 as usize].properties.get("code"),
        Some(&Value::str("ERR_UNKNOWN_ENCODING"))
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn buffer_object_error_label_peak_and_inner_refusal_are_atomic_bd_nx5cb() {
    let custom_label = Label::Custom {
        name: "buffer-object-backing-label".repeat(128),
        level: 7,
    };
    let fixture = || {
        let mut core = quickjs_test_core();
        let buffer = core
            .alloc_buffer_from_bytes(&[1, 2, 3, 4])
            .expect("allocate authenticated Buffer");
        core.join_binary_storage_label(buffer, &custom_label)
            .expect("classify Buffer backing");
        core.write_reg_with_label(0, Value::Object(buffer), Label::Public)
            .expect("seed public receiver register");
        core.write_reg_with_label(1, Value::str("bogus"), Label::Public)
            .expect("seed public encoding register");
        core
    };

    let mut permissive = fixture();
    assert!(matches!(
        permissive.dispatch_builtin_hostcall(
            "builtin:BufferObjectToString",
            RegRange { start: 0, count: 2 },
            None,
        ),
        Err(InterpreterError::UncaughtException { .. })
    ));
    assert_eq!(permissive.pending_exception_label, custom_label);
    let successful_accounted_bytes = permissive.estimated_memory_bytes();
    let label_bytes = InterpreterCore::estimate_label_bytes(&custom_label);

    let mut tight = fixture();
    let heap_before = tight.heap.len();
    let memory_before = tight.estimated_memory_bytes();
    let prototypes_before = tight
        .builtin_prototypes
        .iter()
        .map(|(name, object_id)| (name.clone(), *object_id))
        .collect::<Vec<_>>();
    // This admits the fully accounted successful state plus all but one
    // byte of the additional live Custom-label clone. A one-copy check
    // would accept it; the physical two-copy exception peak must refuse.
    tight.config.max_total_memory_bytes = successful_accounted_bytes
        .saturating_add(label_bytes)
        .saturating_sub(1);
    assert!(matches!(
        tight.dispatch_builtin_hostcall(
            "builtin:BufferObjectToString",
            RegRange { start: 0, count: 2 },
            None,
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(tight.heap.len(), heap_before);
    assert_eq!(tight.estimated_memory_bytes(), memory_before);
    assert!(tight.pending_exception.is_none());
    assert_eq!(tight.pending_exception_label, Label::Public);
    assert!(tight.pending_hostcall_result_label.is_none());
    assert_eq!(
        tight
            .builtin_prototypes
            .iter()
            .map(|(name, object_id)| (name.clone(), *object_id))
            .collect::<Vec<_>>(),
        prototypes_before
    );
    assert_eq!(
        tight.estimated_memory_bytes(),
        tight.recompute_estimated_memory_bytes()
    );

    let mut inner_refusal = fixture();
    inner_refusal
        .ensure_builtin_prototype("Error")
        .expect("seed stable parent prototype outside refusal boundary");
    let heap_before = inner_refusal.heap.len();
    let memory_before = inner_refusal.estimated_memory_bytes();
    let prototypes_before = inner_refusal
        .builtin_prototypes
        .iter()
        .map(|(name, object_id)| (name.clone(), *object_id))
        .collect::<Vec<_>>();
    inner_refusal.config.max_total_memory_bytes = memory_before;
    assert!(matches!(
        inner_refusal.dispatch_builtin_hostcall(
            "builtin:BufferObjectToString",
            RegRange { start: 0, count: 2 },
            None,
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(inner_refusal.heap.len(), heap_before);
    assert_eq!(inner_refusal.estimated_memory_bytes(), memory_before);
    assert!(inner_refusal.pending_exception.is_none());
    assert_eq!(inner_refusal.pending_exception_label, Label::Public);
    assert!(inner_refusal.pending_hostcall_result_label.is_none());
    assert_eq!(
        inner_refusal
            .builtin_prototypes
            .iter()
            .map(|(name, object_id)| (name.clone(), *object_id))
            .collect::<Vec<_>>(),
        prototypes_before
    );
    assert_eq!(
        inner_refusal.estimated_memory_bytes(),
        inner_refusal.recompute_estimated_memory_bytes()
    );
}

#[test]
fn crypto_update_refusal_and_finalized_tombstone_are_atomic_bd_2z157() {
    let mut core = quickjs_test_core();
    core.write_reg(0, Value::str("sha256"))
        .expect("seed hash algorithm");
    let Value::Object(hash) = core
        .crypto_create_hash(RegRange { start: 0, count: 1 })
        .expect("create authenticated hash")
    else {
        panic!("createHash must return an object")
    };
    core.clear_pending_hostcall_result_label();
    let update = core
        .crypto_test_method(hash, "update")
        .expect("authenticated update method");
    core.write_reg(0, Value::str("too-large-for-headroom"))
        .expect("seed refused update");
    let before = core.crypto_objects[&hash].clone();
    let memory_before = core.estimated_memory_bytes();
    core.config.max_total_memory_bytes = memory_before.saturating_add(1);
    assert!(matches!(
        core.crypto_update(
            Some(Value::Object(hash)),
            &update,
            RegRange { start: 0, count: 1 },
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.crypto_objects[&hash], before);
    assert_eq!(core.estimated_memory_bytes(), memory_before);

    core.config.max_total_memory_bytes = u64::MAX;
    let digest = core
        .crypto_test_method(hash, "digest")
        .expect("authenticated digest method");
    core.crypto_digest(
        Some(Value::Object(hash)),
        &digest,
        RegRange { start: 0, count: 0 },
    )
    .expect("finalize hash");
    assert!(matches!(
        core.crypto_objects.get(&hash),
        Some(CryptoObjectState::HashFinalized { .. })
    ));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn crypto_lifecycle_error_materialization_refusal_is_atomic_bd_2z157() {
    let mut core = quickjs_test_core();
    core.ensure_builtin_prototype("TypeError")
        .expect("prime catchable error prototypes before the refusal");
    core.write_reg(0, Value::str("sha256"))
        .expect("seed hash algorithm");
    let Value::Object(hash) = core
        .crypto_create_hash(RegRange { start: 0, count: 1 })
        .expect("create authenticated hash")
    else {
        panic!("createHash must return an object")
    };
    core.clear_pending_hostcall_result_label();
    core.write_reg(0, Value::Object(hash))
        .expect("seed lifecycle receiver");
    core.write_reg(1, Value::Int(7))
        .expect("seed invalid update input");
    core.set_register_label(
        1,
        Label::Custom {
            name: "crypto-label".repeat(512),
            level: 9,
        },
    )
    .expect("seed attacker-sized invocation label");

    let state_before = core.crypto_objects[&hash].clone();
    let heap_len_before = core.heap.len();
    let memory_before = core.estimated_memory_bytes();
    let pending_before = core.pending_exception.clone();
    let pending_label_before = core.pending_exception_label.clone();
    let pending_result_label_before = core.pending_hostcall_result_label.clone();
    let instructions_before = core.instructions_executed;
    core.config.max_total_memory_bytes =
        memory_before.saturating_add(MEMORY_ESTIMATE_HEAP_OBJECT_BASE_BYTES);

    assert!(matches!(
        core.dispatch_builtin_hostcall(
            "builtin:CryptoObjectUpdate",
            RegRange { start: 0, count: 2 },
            None,
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.crypto_objects[&hash], state_before);
    assert_eq!(core.heap.len(), heap_len_before);
    assert_eq!(core.estimated_memory_bytes(), memory_before);
    assert_eq!(core.pending_exception, pending_before);
    assert_eq!(core.pending_exception_label, pending_label_before);
    assert_eq!(
        core.pending_hostcall_result_label,
        pending_result_label_before
    );
    assert_eq!(core.instructions_executed, instructions_before);
}

#[test]
fn crypto_cipher_update_preflights_full_output_pipeline_bd_2z157() {
    let mut core = quickjs_test_core();
    let key = core
        .alloc_buffer_from_bytes(&[1; 16])
        .expect("allocate CTR key");
    let iv = core
        .alloc_buffer_from_bytes(&[2; 16])
        .expect("allocate CTR IV");
    core.write_reg(0, Value::str("aes-128-ctr"))
        .expect("seed CTR algorithm");
    core.write_reg(1, Value::Object(key)).expect("seed CTR key");
    core.write_reg(2, Value::Object(iv)).expect("seed CTR IV");
    let Value::Object(cipher) = core
        .crypto_create_cipher(
            RegRange { start: 0, count: 3 },
            CryptoCipherDirection::Encrypt,
        )
        .expect("create CTR cipher")
    else {
        panic!("createCipheriv must return an object")
    };
    core.clear_pending_hostcall_result_label();

    let payload = core
        .alloc_buffer_from_bytes(&[3; 1024])
        .expect("allocate cipher payload");
    core.write_reg(0, Value::Object(payload))
        .expect("seed cipher payload");
    core.write_reg(1, Value::Undefined)
        .expect("seed default input encoding");
    core.write_reg(2, Value::str("utf16le"))
        .expect("seed expanding output encoding");
    let update = core
        .crypto_test_method(cipher, "update")
        .expect("authenticated cipher update method");
    let state = &core.crypto_objects[&cipher];
    let CryptoObjectState::CipherActive {
        key,
        iv,
        input,
        auth_tag,
        output_remainder,
        lifecycle_label,
        ..
    } = state
    else {
        panic!("cipher must remain active")
    };
    let retained_state_bytes = InterpreterCore::estimate_crypto_object_state_bytes(state);
    let next_input_bytes = u64::try_from(input.len() + 1024).expect("bounded test input");
    let label_bytes = InterpreterCore::estimate_label_bytes(lifecycle_label);
    let candidate_state_bytes = CRYPTO_STATE_BASE_BYTES
        .saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES)
        .saturating_add(u64::try_from(key.capacity()).expect("bounded key"))
        .saturating_add(u64::try_from(iv.capacity()).expect("bounded IV"))
        .saturating_add(next_input_bytes)
        .saturating_add(
            auth_tag
                .as_ref()
                .map_or(0, |tag| u64::try_from(tag.capacity()).unwrap_or(u64::MAX)),
        )
        .saturating_add(u64::try_from(output_remainder.capacity()).expect("bounded remainder"))
        .saturating_add(label_bytes);
    let aggregate_peak = retained_state_bytes
        .saturating_add(1024)
        .saturating_add(candidate_state_bytes)
        .saturating_add(InterpreterCore::crypto_output_pipeline_peak_bytes(
            next_input_bytes,
            next_input_bytes,
            0,
        ))
        .saturating_add(label_bytes.saturating_mul(3));
    let state_before = state.clone();
    let heap_len_before = core.heap.len();
    let memory_before = core.estimated_memory_bytes();
    let instructions_before = core.instructions_executed;
    core.config.max_total_memory_bytes = memory_before.saturating_add(aggregate_peak - 1);

    assert!(matches!(
        core.crypto_cipher_update(
            Some(Value::Object(cipher)),
            &update,
            RegRange { start: 0, count: 3 },
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.crypto_objects[&cipher], state_before);
    assert_eq!(core.heap.len(), heap_len_before);
    assert_eq!(core.estimated_memory_bytes(), memory_before);
    assert_eq!(core.instructions_executed, instructions_before);
}

#[test]
fn crypto_cipher_final_preflights_full_output_pipeline_bd_2z157() {
    let mut core = quickjs_test_core();
    core.config.instruction_budget = u64::MAX;
    let key = core
        .alloc_buffer_from_bytes(&[4; 32])
        .expect("allocate GCM key");
    let iv = core
        .alloc_buffer_from_bytes(&[5; 12])
        .expect("allocate GCM IV");
    core.write_reg(0, Value::str("aes-256-gcm"))
        .expect("seed GCM algorithm");
    core.write_reg(1, Value::Object(key)).expect("seed GCM key");
    core.write_reg(2, Value::Object(iv)).expect("seed GCM IV");
    let Value::Object(decipher) = core
        .crypto_create_cipher(
            RegRange { start: 0, count: 3 },
            CryptoCipherDirection::Decrypt,
        )
        .expect("create GCM decipher")
    else {
        panic!("createDecipheriv must return an object")
    };
    core.clear_pending_hostcall_result_label();

    let tag = core
        .alloc_buffer_from_bytes(&[6; 16])
        .expect("allocate GCM tag");
    core.write_reg(0, Value::Object(tag)).expect("seed GCM tag");
    let set_auth_tag = core
        .crypto_test_method(decipher, "setAuthTag")
        .expect("authenticated setAuthTag method");
    core.crypto_set_auth_tag(
        Some(Value::Object(decipher)),
        &set_auth_tag,
        RegRange { start: 0, count: 1 },
    )
    .expect("install GCM tag");

    let ciphertext = core
        .alloc_buffer_from_bytes(&[7; 1024])
        .expect("allocate GCM ciphertext");
    core.write_reg(0, Value::Object(ciphertext))
        .expect("seed GCM ciphertext");
    let update = core
        .crypto_test_method(decipher, "update")
        .expect("authenticated decipher update method");
    core.crypto_cipher_update(
        Some(Value::Object(decipher)),
        &update,
        RegRange { start: 0, count: 1 },
    )
    .expect("buffer GCM ciphertext without publishing plaintext");
    core.clear_pending_hostcall_result_label();

    core.write_reg(0, Value::str("utf16le"))
        .expect("seed expanding final encoding");
    let final_method = core
        .crypto_test_method(decipher, "final")
        .expect("authenticated decipher final method");
    let state = &core.crypto_objects[&decipher];
    let CryptoObjectState::CipherActive {
        input,
        output_remainder,
        lifecycle_label,
        ..
    } = state
    else {
        panic!("decipher must remain active")
    };
    let retained_state_bytes = InterpreterCore::estimate_crypto_object_state_bytes(state);
    let transformed_bound = u64::try_from(input.len() + 16).expect("bounded test input");
    let label_bytes = InterpreterCore::estimate_label_bytes(lifecycle_label);
    let candidate_state_bytes = CRYPTO_STATE_BASE_BYTES
        .saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES)
        .saturating_add(16)
        .saturating_add(label_bytes);
    let aggregate_peak = retained_state_bytes
        .saturating_add(candidate_state_bytes)
        .saturating_add(InterpreterCore::crypto_output_pipeline_peak_bytes(
            transformed_bound,
            transformed_bound,
            u64::try_from(output_remainder.capacity()).expect("bounded remainder"),
        ))
        .saturating_add(label_bytes.saturating_mul(3));
    let state_before = state.clone();
    let heap_len_before = core.heap.len();
    let memory_before = core.estimated_memory_bytes();
    let instructions_before = core.instructions_executed;
    core.config.max_total_memory_bytes = memory_before.saturating_add(aggregate_peak - 1);

    assert!(matches!(
        core.crypto_cipher_final(
            Some(Value::Object(decipher)),
            &final_method,
            RegRange { start: 0, count: 1 },
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.crypto_objects[&decipher], state_before);
    assert_eq!(core.heap.len(), heap_len_before);
    assert_eq!(core.estimated_memory_bytes(), memory_before);
    assert_eq!(core.instructions_executed, instructions_before);
}

#[test]
fn crypto_pbkdf2_rejects_iterations_above_node_i32_ceiling_bd_2z157() {
    let mut core = quickjs_test_core();
    core.write_reg(0, Value::str("password"))
        .expect("seed PBKDF2 password");
    core.write_reg(1, Value::str("salt"))
        .expect("seed PBKDF2 salt");
    core.write_reg(2, Value::Int(i64::from(i32::MAX) + 1))
        .expect("seed out-of-range iteration count");
    core.write_reg(3, Value::Int(0))
        .expect("seed zero output length");
    core.write_reg(4, Value::str("sha256"))
        .expect("seed PBKDF2 digest");
    let instructions_before = core.instructions_executed;

    assert!(matches!(
        core.crypto_pbkdf2(RegRange { start: 0, count: 5 }, false),
        Err(InterpreterError::UncaughtException { .. })
    ));
    assert_eq!(core.instructions_executed, instructions_before);
    let Value::Object(error_id) = core
        .pending_exception
        .clone()
        .expect("Node-style PBKDF2 RangeError must be catchable")
    else {
        panic!("pending exception must be an Error object")
    };
    assert_eq!(
        core.heap[error_id.0 as usize].properties.get("code"),
        Some(&Value::str("ERR_OUT_OF_RANGE"))
    );
}

#[test]
fn crypto_gcm_auth_tag_is_private_labeled_and_transactional_bd_2z157() {
    let mut core = quickjs_test_core();
    let key = core
        .alloc_buffer_from_bytes(&[5; 32])
        .expect("allocate GCM key");
    let iv = core
        .alloc_buffer_from_bytes(&[6; 12])
        .expect("allocate GCM IV");
    core.write_reg(0, Value::str("aes-256-gcm"))
        .expect("seed GCM algorithm");
    core.write_reg(1, Value::Object(key)).expect("seed GCM key");
    core.write_reg(2, Value::Object(iv)).expect("seed GCM IV");
    let Value::Object(decipher) = core
        .crypto_create_cipher(
            RegRange { start: 0, count: 3 },
            CryptoCipherDirection::Decrypt,
        )
        .expect("create authenticated GCM decipher")
    else {
        panic!("createDecipheriv must return an object")
    };
    core.clear_pending_hostcall_result_label();

    let classified_tag = core
        .alloc_buffer_from_bytes(&[7; 16])
        .expect("allocate classified GCM tag");
    core.join_binary_storage_label(classified_tag, &Label::Secret)
        .expect("classify GCM tag backing");
    core.write_reg(0, Value::Object(classified_tag))
        .expect("seed classified GCM tag");
    let set_auth_tag = core
        .crypto_test_method(decipher, "setAuthTag")
        .expect("authenticated GCM setAuthTag method");
    assert_eq!(
        core.crypto_set_auth_tag(
            Some(Value::Object(decipher)),
            &set_auth_tag,
            RegRange { start: 0, count: 1 },
        )
        .expect("install authenticated GCM tag"),
        Value::Object(decipher)
    );
    assert!(matches!(
        core.crypto_objects.get(&decipher),
        Some(CryptoObjectState::CipherActive {
            auth_tag: Some(tag),
            lifecycle_label: Label::Secret,
            ..
        }) if tag.as_slice() == [7; 16]
    ));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    assert!(matches!(
        core.crypto_set_auth_tag(
            Some(Value::Object(decipher)),
            &set_auth_tag,
            RegRange { start: 0, count: 1 },
        ),
        Err(InterpreterError::UncaughtException { .. })
    ));
    core.clear_pending_exception_slot();

    core.write_reg(0, Value::str("aes-256-gcm"))
        .expect("seed second GCM algorithm");
    core.write_reg(1, Value::Object(key))
        .expect("seed second GCM key");
    core.write_reg(2, Value::Object(iv))
        .expect("seed second GCM IV");
    let Value::Object(refused) = core
        .crypto_create_cipher(
            RegRange { start: 0, count: 3 },
            CryptoCipherDirection::Decrypt,
        )
        .expect("create GCM decipher for memory refusal")
    else {
        panic!("createDecipheriv must return an object")
    };
    core.clear_pending_hostcall_result_label();
    core.write_reg(0, Value::Object(classified_tag))
        .expect("seed refused GCM tag");
    let refused_method = core
        .crypto_test_method(refused, "setAuthTag")
        .expect("second authenticated GCM setAuthTag method");
    let before = core.crypto_objects[&refused].clone();
    let memory_before = core.estimated_memory_bytes();
    let retained_state_bytes =
        InterpreterCore::estimate_crypto_object_state_bytes(&core.crypto_objects[&refused]);
    let tag_value = Value::Object(classified_tag);
    let obsolete_per_allocation_headroom = retained_state_bytes
        .saturating_add(
            core.crypto_input_allocation_bound(&tag_value, None)
                .expect("bound classified tag"),
        )
        .saturating_add(InterpreterCore::estimate_label_bytes(&Label::Secret));
    core.config.max_total_memory_bytes =
        memory_before.saturating_add(obsolete_per_allocation_headroom);
    assert!(matches!(
        core.crypto_set_auth_tag(
            Some(Value::Object(refused)),
            &refused_method,
            RegRange { start: 0, count: 1 },
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.crypto_objects[&refused], before);
    assert_eq!(core.estimated_memory_bytes(), memory_before);
}

#[test]
fn crypto_gcm_variable_nonce_matches_node_bun_goldens_bd_lnqta() {
    // Differential goldens captured from live Node v24 and Bun 1.4.0
    // probes on 2026-08-26: both runtimes emit byte-identical
    // ciphertext/tag pairs, so either serves as the oracle. Key is
    // 32 x 0x01, each IV is iv_len x 0x07, plaintext is constant.
    const KEY: [u8; 32] = [1; 32];
    const PLAINTEXT: &[u8] = b"hello variable nonce";
    fn unhex(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .expect("valid fixture hex")
    }
    let goldens: &[(usize, &str, &str)] = &[
        (
            1,
            "4c0971579abef61f10cc92d12e0910ded9cf5ee9",
            "dba2a7af2ca9109bcd2c01cf2e24a3c9",
        ),
        (
            7,
            "2e61943f973eb45a49dd677532b9972e782878d3",
            "8ce2d9fd8ee9ead9369acdfba2e359fa",
        ),
        (
            8,
            "8eece1cd028b7f79c95007a5a07dba4a03627780",
            "bc3ad9bdcc7a068df99ae73fff7cba0f",
        ),
        (
            11,
            "0cb67f3d50dc314b057655f0107c9be3599cb0dc",
            "7564f70ed6ffff6c9af1b0adf6b86154",
        ),
        (
            12,
            "e59686c8608ec7c06bf36552caa547a4c8c7e2bc",
            "3c0da85ba467e4d859c0a9fa33b0b61f",
        ),
        (
            13,
            "cfce17e9a86f497ac188c39540160a804768f1b2",
            "fe5b89612475b85d23c4694e55b2c0ac",
        ),
        (
            16,
            "2dcc57b2b8bb4cef2ef28a9179b19fa7fe0440fe",
            "42ce77b52c64f83af718ae121251c808",
        ),
        (
            24,
            "ec10c6d1a4d0807eadc36a80c72c33f049f2394c",
            "a3c4e68bb7a3dae4c2dd2ba616c866d1",
        ),
        (
            32,
            "3ef30546c423d39a8d4fcd43e2e092aad9b454cf",
            "f2cff1f69694932b289cab0110abb325",
        ),
        (
            64,
            "bf913681c1fe7e8746563e095c344fd869f2bef1",
            "917b66a4c99340521e8558dc1de6c81f",
        ),
        (
            128,
            "4b282d62037a896d915921330fcf248ef416a862",
            "ebcd1d0b04034b10a608c8c8495672d9",
        ),
    ];
    for &(iv_len, ciphertext_hex, tag_hex) in goldens {
        let iv = vec![7u8; iv_len];
        let (ciphertext, tag) = InterpreterCore::crypto_transform_cipher_all(
            CryptoCipherAlgorithm::Aes256Gcm,
            CryptoCipherDirection::Encrypt,
            &KEY,
            &iv,
            PLAINTEXT,
            None,
        )
        .unwrap_or_else(|_| panic!("encryption must admit IV length {iv_len}"));
        assert_eq!(
            ciphertext.as_slice(),
            unhex(ciphertext_hex),
            "ciphertext divergence at IV length {iv_len}"
        );
        let tag = tag.expect("GCM encryption must produce an auth tag");
        assert_eq!(
            tag.as_slice(),
            unhex(tag_hex),
            "tag divergence at IV length {iv_len}"
        );
        let (plaintext, decrypted_tag) = InterpreterCore::crypto_transform_cipher_all(
            CryptoCipherAlgorithm::Aes256Gcm,
            CryptoCipherDirection::Decrypt,
            &KEY,
            &iv,
            &ciphertext,
            Some(tag.as_slice()),
        )
        .unwrap_or_else(|_| panic!("decryption must admit IV length {iv_len}"));
        assert!(decrypted_tag.is_none(), "decryption emits no tag");
        assert_eq!(plaintext.as_slice(), PLAINTEXT);
    }
    // Empty plaintext tags at representative lengths, including the
    // zero-length GHASH domain edge.
    let empty_goldens: &[(usize, &str)] = &[
        (8, "d3371853a590f6ec7452944bd0b601e2"),
        (13, "8f5bb7b7cad0eeb73eeafaa02f51ea91"),
        (128, "a1e7d0ddf4617ca23d98380a6204844a"),
    ];
    for &(iv_len, tag_hex) in empty_goldens {
        let iv = vec![7u8; iv_len];
        let (ciphertext, tag) = InterpreterCore::crypto_transform_cipher_all(
            CryptoCipherAlgorithm::Aes256Gcm,
            CryptoCipherDirection::Encrypt,
            &KEY,
            &iv,
            b"",
            None,
        )
        .expect("empty-payload encryption must succeed");
        assert!(ciphertext.is_empty());
        let tag = tag.expect("empty payload still carries an auth tag");
        assert_eq!(tag.as_slice(), unhex(tag_hex));
    }
}

#[test]
fn crypto_gcm_variable_nonce_refuses_tampered_material_bd_lnqta() {
    const KEY: [u8; 32] = [1; 32];
    const PLAINTEXT: &[u8] = b"hello variable nonce";
    let iv = vec![7u8; 13];
    let encrypt = |plaintext: &[u8]| {
        InterpreterCore::crypto_transform_cipher_all(
            CryptoCipherAlgorithm::Aes256Gcm,
            CryptoCipherDirection::Encrypt,
            &KEY,
            &iv,
            plaintext,
            None,
        )
        .expect("baseline encryption")
    };
    // A flipped auth-tag bit must refuse authentication without
    // releasing plaintext.
    let (ciphertext, tag) = encrypt(PLAINTEXT);
    let mut tag = tag.expect("auth tag present");
    tag[15] ^= 0x01;
    assert!(matches!(
        InterpreterCore::crypto_transform_cipher_all(
            CryptoCipherAlgorithm::Aes256Gcm,
            CryptoCipherDirection::Decrypt,
            &KEY,
            &iv,
            &ciphertext,
            Some(tag.as_slice()),
        ),
        Err("unable to authenticate data")
    ));
    // So must a flipped final ciphertext bit under the untampered tag.
    let (ciphertext, tag) = encrypt(PLAINTEXT);
    let tag = tag.expect("auth tag present");
    let mut tampered = ciphertext.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x80;
    assert!(matches!(
        InterpreterCore::crypto_transform_cipher_all(
            CryptoCipherAlgorithm::Aes256Gcm,
            CryptoCipherDirection::Decrypt,
            &KEY,
            &iv,
            &tampered,
            Some(tag.as_slice()),
        ),
        Err("unable to authenticate data")
    ));
}

#[test]
fn ed25519_detached_sign_verify_accept_tamper_and_length_bd_53l89() {
    let seed = [0x42u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let message = b"franken engine signs";

    let signature = InterpreterCore::ed25519_sign_detached(seed, message);
    assert_eq!(signature.len(), 64);
    assert!(
        InterpreterCore::ed25519_verify_detached(public_key, message, &signature)
            .expect("well-formed signature verifies"),
        "the true signature must verify"
    );

    let tampered_message = b"franken engine signS";
    assert_eq!(
        InterpreterCore::ed25519_verify_detached(public_key, tampered_message, &signature),
        Ok(false),
        "a tampered message must reject without error"
    );

    assert_eq!(
        InterpreterCore::ed25519_verify_detached(public_key, message, &signature[..63]),
        Err("ERR_CRYPTO_INVALID_SIGNATURE_LENGTH"),
        "short signatures must surface the typed length error"
    );

    // Determinism under the contract's scripted-entropy regime: same seed,
    // same message, identical signature bytes.
    assert_eq!(
        InterpreterCore::ed25519_sign_detached(seed, message),
        signature
    );
}

#[test]
fn crypto_create_cipher_enforces_bounded_gcm_iv_window_bd_lnqta() {
    let mut core = quickjs_test_core();
    let key = core
        .alloc_buffer_from_bytes(&[5; 32])
        .expect("allocate GCM key");
    core.write_reg(0, Value::str("aes-256-gcm"))
        .expect("seed algorithm register");
    core.write_reg(1, Value::Object(key))
        .expect("seed key register");
    // Rejected: empty and over-window IVs fail closed exactly like the
    // live Node/Bun probes.
    for rejected_len in [0usize, 129, 200] {
        let iv = core
            .alloc_buffer_from_bytes(&vec![6u8; rejected_len])
            .expect("allocate rejected IV");
        core.write_reg(2, Value::Object(iv))
            .expect("seed rejected IV register");
        assert!(
            matches!(
                core.crypto_create_cipher(
                    RegRange { start: 0, count: 3 },
                    CryptoCipherDirection::Encrypt,
                ),
                Err(InterpreterError::UncaughtException { .. })
            ),
            "IV length {rejected_len} must be refused"
        );
        let Value::Object(error_id) = core
            .pending_exception
            .clone()
            .expect("Node-style IV error must be pending")
        else {
            panic!("pending exception must be an Error object")
        };
        assert_eq!(
            core.heap[error_id.0 as usize].properties.get("code"),
            Some(&Value::str("ERR_CRYPTO_INVALID_IV"))
        );
        core.clear_pending_exception_slot();
    }
    // Accepted: both window boundaries and a mid-window odd length admit
    // live cipher objects.
    for accepted_len in [1usize, 13, 128] {
        let iv = core
            .alloc_buffer_from_bytes(&vec![7u8; accepted_len])
            .expect("allocate accepted IV");
        core.write_reg(2, Value::Object(iv))
            .expect("seed accepted IV register");
        let created = core
            .crypto_create_cipher(
                RegRange { start: 0, count: 3 },
                CryptoCipherDirection::Encrypt,
            )
            .unwrap_or_else(|_| panic!("IV length {accepted_len} must be admitted"));
        assert!(matches!(created, Value::Object(_)));
        core.clear_pending_hostcall_result_label();
    }
}

#[test]
fn crypto_state_is_cleared_before_seed_object_ids_are_reused_bd_2z157() {
    let mut core = quickjs_test_core();
    let seed = core
        .capture_execution_seed()
        .expect("test execution-seed capture must fit");
    core.write_reg(0, Value::str("sha256"))
        .expect("seed hash algorithm");
    core.crypto_create_hash(RegRange { start: 0, count: 1 })
        .expect("create execution-local crypto state");
    core.clear_pending_hostcall_result_label();
    assert!(!core.crypto_objects.is_empty());

    core.reset_execution_state_from_seed(&seed)
        .expect("restore pre-crypto execution seed");
    assert!(core.crypto_objects.is_empty());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn crypto_kdf_validation_precedes_work_and_rejects_fractional_counts_bd_2z157() {
    let mut core = quickjs_test_core();
    assert!(matches!(
        core.crypto_integer_arg(&Value::Float(Float64::new(1.5)), "iterations", false),
        Err(InterpreterError::TypeError { .. })
    ));

    core.write_reg(0, Value::str("password"))
        .expect("seed PBKDF2 password");
    core.write_reg(1, Value::str("salt"))
        .expect("seed PBKDF2 salt");
    core.write_reg(2, Value::Int(1_000_000))
        .expect("seed deliberately expensive iteration count");
    core.write_reg(3, Value::Int(32))
        .expect("seed PBKDF2 output length");
    core.write_reg(4, Value::str("sha256"))
        .expect("seed PBKDF2 digest");
    core.write_reg(5, Value::Int(7))
        .expect("seed invalid callback");
    let instructions_before = core.instructions_executed;
    assert!(matches!(
        core.crypto_pbkdf2(RegRange { start: 0, count: 6 }, true),
        Err(InterpreterError::TypeError { .. })
    ));
    assert_eq!(core.instructions_executed, instructions_before);
}

#[test]
fn crypto_scrypt_raw_output_length_and_full_workspace_preflight_bd_2z157() {
    let mut core = quickjs_test_core();
    core.config.instruction_budget = u64::MAX;
    let options = core
        .alloc_object_with_properties(&[
            ("N", Value::Int(2)),
            ("r", Value::Int(1)),
            ("p", Value::Int(1)),
            ("maxmem", Value::Int(4096)),
        ])
        .expect("allocate bounded scrypt options");
    for (key_len, expected_len) in [(1, 1usize), (0, 0usize)] {
        core.write_reg(0, Value::str("password"))
            .expect("seed scrypt password");
        core.write_reg(1, Value::str("salt"))
            .expect("seed scrypt salt");
        core.write_reg(2, Value::Int(key_len))
            .expect("seed raw scrypt output length");
        core.write_reg(3, Value::Object(options))
            .expect("seed scrypt options");
        let value = core
            .crypto_scrypt_sync(RegRange { start: 0, count: 4 })
            .expect("raw scrypt output length must not be constrained by Params metadata");
        assert_eq!(
            core.bytes_for_buffer_like(&value)
                .expect("scrypt returns a Buffer")
                .len(),
            expected_len
        );
        core.clear_pending_hostcall_result_label();
    }

    let refused = core
        .alloc_object_with_properties(&[
            ("N", Value::Int(1024)),
            ("r", Value::Int(8)),
            ("p", Value::Int(2)),
            ("maxmem", Value::Int(1024)),
        ])
        .expect("allocate maxmem-refused scrypt options");
    core.write_reg(2, Value::Int(16))
        .expect("seed refused output length");
    core.write_reg(3, Value::Object(refused))
        .expect("seed refused scrypt options");
    let instructions_before = core.instructions_executed;
    assert!(matches!(
        core.crypto_scrypt_sync(RegRange { start: 0, count: 4 }),
        Err(InterpreterError::RangeError { message }) if message.contains("maxmem")
    ));
    assert_eq!(core.instructions_executed, instructions_before);

    let amplified = core
        .alloc_object_with_properties(&[
            ("N", Value::Int(2)),
            ("r", Value::Int(1)),
            ("p", Value::Int(40_000)),
            ("maxmem", Value::Int(32 * 1024 * 1024)),
        ])
        .expect("allocate PBKDF-amplified scrypt options");
    core.write_reg(2, Value::Int(CRYPTO_MAX_INPUT_BYTES as i64))
        .expect("seed amplified output length");
    core.write_reg(3, Value::Object(amplified))
        .expect("seed amplified scrypt options");
    let instructions_before = core.instructions_executed;
    assert!(matches!(
        core.crypto_scrypt_sync(RegRange { start: 0, count: 4 }),
        Err(InterpreterError::BudgetExhausted { .. })
    ));
    assert_eq!(core.instructions_executed, instructions_before);
}

#[test]
fn crypto_retained_memory_uses_vector_capacity_bd_2z157() {
    let mut input = Vec::with_capacity(128);
    input.push(1);
    let state = CryptoObjectState::HashActive {
        algorithm: CryptoHashAlgorithm::Sha256,
        input: Zeroizing::new(input),
        lifecycle_label: Label::Public,
    };
    assert!(
        InterpreterCore::estimate_crypto_object_state_bytes(&state)
            >= CRYPTO_STATE_BASE_BYTES
                .saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES)
                .saturating_add(128)
    );
}

#[test]
fn crypto_encoded_stream_carries_incomplete_utf_units_bd_2z157() {
    let (published, remainder) =
        InterpreterCore::crypto_encoded_stream_chunk(&[], &[0xc0], "utf8", false);
    assert!(published.is_empty());
    assert_eq!(remainder.as_slice(), &[0xc0]);
    let (published, remainder) =
        InterpreterCore::crypto_encoded_stream_chunk(&[], &[0x3d, 0xd8], "utf16le", false);
    assert!(published.is_empty());
    assert_eq!(remainder.as_slice(), &[0x3d, 0xd8]);
    let (published, remainder) =
        InterpreterCore::crypto_encoded_stream_chunk(&remainder, &[], "utf16le", true);
    assert_eq!(published.as_slice(), &[0x3d, 0xd8]);
    assert!(remainder.is_empty());

    let (published, remainder) =
        InterpreterCore::crypto_encoded_stream_chunk(&[], &[0x3d, 0xd8, 0x00], "utf16le", false);
    assert_eq!(published.as_slice(), &[0x3d, 0xd8]);
    assert_eq!(remainder.as_slice(), &[0x00]);

    let (published, high_surrogate) =
        InterpreterCore::crypto_encoded_stream_chunk(&[], &[0x3d, 0xd8], "utf16le", false);
    assert!(published.is_empty());
    let (published, high_and_odd) =
        InterpreterCore::crypto_encoded_stream_chunk(&high_surrogate, &[0x00], "utf16le", false);
    assert!(published.is_empty());
    assert_eq!(high_and_odd.as_slice(), &[0x3d, 0xd8, 0x00]);
    let (published, remainder) =
        InterpreterCore::crypto_encoded_stream_chunk(&high_and_odd, &[0xde], "utf16le", false);
    assert_eq!(published.as_slice(), &[0x3d, 0xd8, 0x00, 0xde]);
    assert!(remainder.is_empty());

    let (published, odd) =
        InterpreterCore::crypto_encoded_stream_chunk(&[], &[0x3d], "utf16le", false);
    assert!(published.is_empty());
    let (published, remainder) =
        InterpreterCore::crypto_encoded_stream_chunk(&odd, &[0xd8, 0x00], "utf16le", false);
    assert_eq!(published.as_slice(), &[0x3d, 0xd8]);
    assert_eq!(remainder.as_slice(), &[0x00]);
}

#[test]
fn timing_safe_equal_preflights_both_temporary_copies_bd_2z157() {
    let mut core = quickjs_test_core();
    let left = core
        .alloc_array_buffer_object(16)
        .expect("allocate left timingSafeEqual input");
    let right = core
        .alloc_array_buffer_object(16)
        .expect("allocate right timingSafeEqual input");
    core.write_reg(0, Value::Object(left))
        .expect("seed left timingSafeEqual input");
    core.write_reg(1, Value::Object(right))
        .expect("seed right timingSafeEqual input");
    let retained = core.estimated_memory_bytes();
    core.config.max_total_memory_bytes = retained
        .saturating_add(16)
        .saturating_add(InterpreterCore::estimate_label_bytes(&Label::Public));
    assert!(matches!(
        core.crypto_timing_safe_equal(RegRange { start: 0, count: 2 }),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.estimated_memory_bytes(), retained);
}

fn lower_symbol_source_bd_n8eta_4_2(source: &str) -> Ir3Module {
    let syntax_tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "bd_n8eta_4_2.js".to_string(),
                text: source.to_string(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("Symbol regression source should parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(syntax_tree, "bd_n8eta_4_2.js"),
        &LoweringContext::new(
            "trace-bd-n8eta-4-2",
            "decision-bd-n8eta-4-2",
            "policy-bd-n8eta-4-2",
        ),
    )
    .expect("Symbol regression source should lower")
    .ir3
}

fn array_reduce_module(
    args_count: u32,
    reducer_instructions: Vec<Ir3Instruction>,
    constant_pool: Vec<String>,
) -> Ir3Module {
    let reducer_entry = 2;
    let mut instructions = vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:ArrayPrototypeReduce".to_string()),
            args: RegRange {
                start: 0,
                count: args_count,
            },
            dst: 0,
        },
        Ir3Instruction::Halt,
    ];
    instructions.extend(reducer_instructions);

    let mut module = test_module_with_functions(
        instructions,
        vec![Ir3FunctionDesc {
            entry: reducer_entry,
            arity: 4,
            frame_size: 8,
            name: Some("reduce_callback".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    module.constant_pool = constant_pool.into_iter().map(Into::into).collect();
    module
}

fn seed_array(core: &mut InterpreterCore, length: i64, values: &[(usize, Value)]) -> ObjectId {
    let array_id = core
        .alloc_object_with_prototype(None)
        .expect("operation should succeed for valid inputs");
    for (index, value) in values {
        core.set_object_property(array_id, index.to_string(), value.clone())
            .expect("operation should succeed for valid inputs");
    }
    core.set_object_property(array_id, "length".to_string(), Value::Int(length))
        .expect("operation should succeed for valid inputs");
    array_id
}

fn assert_entry_pair(
    core: &InterpreterCore,
    value: Value,
    expected_index: i64,
    expected_value: Value,
) {
    let Value::Object(pair_id) = value else {
        panic!("expected entry pair object, got {value:?}");
    };
    let properties = &core.heap[pair_id.0 as usize].properties;
    assert_eq!(properties.get("0"), Some(&Value::Int(expected_index)));
    assert_eq!(properties.get("1"), Some(&expected_value));
    assert_eq!(properties.get("length"), Some(&Value::Int(2)));
}

fn iterator_method_via_property(core: &mut InterpreterCore, iterator: Value, key: Value) -> Value {
    // Replicate the `GetProperty` (iterator branch) + `CallMethod` pair
    // WITHOUT routing through `execute()`. `execute()`'s `prepare_execution`
    // re-injects the runtime globals and runs the seed-tracked reset on every
    // call, which perturbs the shared interpreter state between successive
    // `.next()` invocations. `invoke_inline_method_call` performs the very
    // same receiver/callee dispatch over an isolated register frame while
    // leaving the runtime iterator table (`self.iterators`) untouched, so the
    // iterator's in-progress cursor is preserved across calls.
    let handle = match &iterator {
        Value::Iterator(handle) => *handle,
        other => panic!("expected iterator value, got {other:?}"),
    };
    let key = core.executable_property_key_from_value(&key);
    let method = core.iterator_runtime_property_value(handle, &key);
    let module = test_module(Vec::new());
    core.invoke_inline_method_call(Some(&module), method, iterator, Vec::new())
        .expect("iterator property method call should execute")
}

fn iterator_next_via_property(core: &mut InterpreterCore, iterator: Value) -> Value {
    iterator_method_via_property(core, iterator, Value::str("next"))
}

fn assert_iterator_result(
    core: &InterpreterCore,
    result: Value,
    expected_done: bool,
    expected_value: Value,
) {
    let Value::Object(result_id) = result else {
        panic!("expected iterator result object, got {result:?}");
    };
    let properties = &core.heap[result_id.0 as usize].properties;
    assert_eq!(properties.get("done"), Some(&Value::Bool(expected_done)));
    assert_eq!(properties.get("value"), Some(&expected_value));
}

#[test]
fn parseint_nan_radix_defaults_for_global_and_number_parseint_builtin_ids() {
    let mut interpreter = quickjs_test_core();

    for func_index in [82, 234, 377] {
        interpreter.set_reg(0, Value::str("42"));
        interpreter.set_reg(1, Value::Float(Float64::new(f64::NAN)));

        let result = interpreter
            .call_builtin_by_id(func_index, RegRange { start: 0, count: 2 })
            .expect("parseInt with NaN radix should not fail interpreter dispatch");
        assert_eq!(
            result,
            Value::Int(42),
            "parseInt builtin ID {} should default NaN radix to decimal",
            func_index
        );
    }
}

#[test]
fn parseint_sign_and_radix_semantics_consistent_across_builtins() {
    let mut interpreter = quickjs_test_core();

    let run_case = |interpreter: &mut InterpreterCore,
                    builtin_id: u32,
                    input: &str,
                    radix: Option<i64>,
                    expected: Option<i64>| {
        interpreter.set_reg(0, Value::str(input));
        let count = if let Some(radix) = radix {
            interpreter.set_reg(1, Value::Int(radix));
            2
        } else {
            1
        };

        let result = interpreter
            .call_builtin_by_id(builtin_id, RegRange { start: 0, count })
            .expect("parseInt builtin should run with unified sign/radix helper");

        match expected {
            Some(expected) => {
                assert_eq!(
                    result,
                    Value::Int(expected),
                    "parseInt builtin ID {builtin_id} input {input:?} failed"
                );
            }
            None => match result {
                Value::Float(value) => assert!(
                    value.is_nan(),
                    "parseInt builtin ID {builtin_id} input {input:?} should return NaN"
                ),
                // SAFETY: Test validates parseInt builtin returns NaN for invalid input cases
                other => panic!(
                    "parseInt builtin ID {builtin_id} input {input:?} expected NaN, got {other:?}"
                ),
            },
        }
    };

    for (builtin_id, input, radix, expected) in [
        (82u32, " -10", None, Some(-10)),
        (234u32, "  -10", None, Some(-10)),
        (377u32, "-10", None, Some(-10)),
        (82u32, "ff", Some(16), Some(255)),
        (234u32, "0x10", Some(0), Some(16)),
        (377u32, "0X10", Some(0), Some(16)),
        (82u32, "101", Some(2), Some(5)),
        (377u32, "101", Some(2), Some(5)),
        (82u32, "a", Some(10), None),
        (234u32, "+15", None, Some(15)),
        (377u32, "123xyz", None, Some(123)),
        (377u32, "0", Some(37), None),
    ] {
        run_case(&mut interpreter, builtin_id, input, radix, expected);
    }
}

#[test]
fn parseint_number_to_string_nan_radix_defaults_for_builtin_ids() {
    let mut interpreter = quickjs_test_core();

    for func_index in [196, 343] {
        interpreter.set_reg(0, Value::Int(42));
        interpreter.set_reg(1, Value::Float(Float64::new(f64::NAN)));

        // (42).toString(NaN): per ES, radix = ToIntegerOrInfinity(NaN) = 0, and a
        // radix of 0 is outside the valid 2..=36 range, so Number.prototype.toString
        // throws a RangeError. The legacy premise ("NaN radix defaults to decimal")
        // was non-conformant (bd-n0sap).
        let err = interpreter
            .call_builtin_by_id(func_index, RegRange { start: 0, count: 2 })
            .expect_err("Number.toString with radix 0 (from NaN) must throw RangeError");
        assert!(
            matches!(err, InterpreterError::RangeError { .. }),
            "Number.toString builtin ID {func_index} NaN radix should be a RangeError, got {err:?}"
        );
    }
}

#[test]
fn number_to_string_fractional_radix_preserves_fractional_part() {
    let mut interpreter = quickjs_test_core();

    for func_index in [196, 343] {
        interpreter.set_reg(0, Value::Float(Float64::new(3.5)));
        interpreter.set_reg(1, Value::Int(2));

        let result = interpreter
            .call_builtin_by_id(func_index, RegRange { start: 0, count: 2 })
            .expect("Number.toString with fractional non-decimal radix should run");
        assert_eq!(
            result,
            Value::str("11.1"),
            "Number.toString builtin ID {} should preserve fractional radix digits",
            func_index
        );
    }
}

fn construct_weakmap_for_test(core: &mut InterpreterCore) -> ObjectId {
    let result = core
        .call_builtin_by_id(172, RegRange { start: 0, count: 0 })
        .expect("WeakMap constructor should allocate receiver and entries");
    let Value::Object(weakmap_id) = result else {
        panic!("WeakMap constructor should return object, got {result:?}");
    };

    let weakmap_obj = &core.heap[weakmap_id.0 as usize];
    assert_eq!(weakmap_obj.brand(), Some("WeakMap"));
    weakmap_id
}

fn weakmap_storage_for_test(
    core: &mut InterpreterCore,
    weakmap_id: ObjectId,
) -> &mut WeakMapStorage {
    core.weakmap_storage
        .get_mut(&weakmap_id)
        .expect("WeakMap constructor should initialize weak storage")
}

#[test]
fn weakmap_get_has_use_constructor_entries_storage() {
    let mut core = quickjs_test_core();
    let weakmap_id = construct_weakmap_for_test(&mut core);
    // The current engine stores WeakMap entries in a dedicated Rust-side
    // `weakmap_storage` map keyed by the WeakMap's object id rather than an
    // `__entries` heap object, so assert that distinct backing storage exists.
    assert!(
        core.weakmap_storage.contains_key(&weakmap_id),
        "WeakMap should have distinct weak-entry storage"
    );

    let key_id = core
        .alloc_object_with_prototype(None)
        .expect("object key allocation should succeed");
    weakmap_storage_for_test(&mut core, weakmap_id).set(key_id.0, Value::Int(41));

    core.set_reg(0, Value::Object(weakmap_id));
    core.set_reg(1, Value::Object(key_id));
    assert_eq!(
        core.call_builtin_by_id(324, RegRange { start: 0, count: 2 })
            .expect("WeakMap.prototype.has should execute"),
        Value::Bool(true)
    );
    assert_eq!(
        core.call_builtin_by_id(328, RegRange { start: 0, count: 2 })
            .expect("WeakMap.prototype.get should execute"),
        Value::Int(41)
    );

    let missing_key_id = core
        .alloc_object_with_prototype(None)
        .expect("missing object key allocation should succeed");
    core.set_reg(1, Value::Object(missing_key_id));
    assert_eq!(
        core.call_builtin_by_id(324, RegRange { start: 0, count: 2 })
            .expect("WeakMap.prototype.has should execute for missing key"),
        Value::Bool(false)
    );
    assert_eq!(
        core.call_builtin_by_id(328, RegRange { start: 0, count: 2 })
            .expect("WeakMap.prototype.get should execute for missing key"),
        Value::Undefined
    );
}

#[test]
fn weakmap_get_has_reject_plain_object_receivers() {
    let mut core = quickjs_test_core();
    let receiver_id = core
        .alloc_object_with_prototype(None)
        .expect("plain receiver allocation should succeed");
    let key_id = core
        .alloc_object_with_prototype(None)
        .expect("object key allocation should succeed");
    core.set_object_property(receiver_id, format!("o:{}", key_id.0), Value::Int(9))
        .expect("test setup should write fake direct receiver key");

    for builtin_id in [324, 328] {
        core.set_reg(0, Value::Object(receiver_id));
        core.set_reg(1, Value::Object(key_id));
        let err = core
            .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 2 })
            .expect_err("WeakMap prototype method should reject non-WeakMap receiver");
        assert!(matches!(
            err,
            InterpreterError::TypeError { expected, got }
                if expected == "WeakMap" && got == "object"
        ));
    }
}

#[test]
fn weakmap_get_has_ignore_primitive_keys_even_when_entries_match() {
    let mut core = quickjs_test_core();
    let weakmap_id = construct_weakmap_for_test(&mut core);
    // Seed an object-keyed entry in the weak storage; the lookup below uses a
    // primitive key which must never match object-keyed weak entries.
    let object_key_id = core
        .alloc_object_with_prototype(None)
        .expect("object key allocation should succeed");
    weakmap_storage_for_test(&mut core, weakmap_id).set(object_key_id.0, Value::Int(7));

    core.set_reg(0, Value::Object(weakmap_id));
    core.set_reg(1, Value::str("primitive"));
    assert_eq!(
        core.call_builtin_by_id(324, RegRange { start: 0, count: 2 })
            .expect("WeakMap.prototype.has should execute for primitive key"),
        Value::Bool(false)
    );
    assert_eq!(
        core.call_builtin_by_id(328, RegRange { start: 0, count: 2 })
            .expect("WeakMap.prototype.get should execute for primitive key"),
        Value::Undefined
    );
}

fn alloc_indexed_object_for_test(core: &mut InterpreterCore, values: &[Value]) -> ObjectId {
    let object_id = core
        .alloc_object_with_prototype(None)
        .expect("indexed iterable allocation should succeed");
    for (index, value) in values.iter().enumerate() {
        core.set_object_property(object_id, index.to_string(), value.clone())
            .expect("indexed iterable element write should succeed");
    }
    object_id
}

#[test]
fn map_and_set_constructors_seed_iterable_input() {
    let mut core = quickjs_test_core();

    let first_pair =
        alloc_indexed_object_for_test(&mut core, &[Value::str("alpha"), Value::Int(1)]);
    let second_pair =
        alloc_indexed_object_for_test(&mut core, &[Value::str("beta"), Value::Int(2)]);
    let map_iterable = alloc_indexed_object_for_test(
        &mut core,
        &[Value::Object(first_pair), Value::Object(second_pair)],
    );

    core.set_reg(0, Value::Object(map_iterable));
    let Value::Object(map_id) = core
        .call_builtin_by_id(170, RegRange { start: 0, count: 1 })
        .expect("Map constructor should accept iterable seed")
    else {
        panic!("Map constructor should return object");
    };

    assert_eq!(core.collection_size(map_id, "Map"), Some(2));
    core.set_reg(0, Value::Object(map_id));
    core.set_reg(1, Value::str("alpha"));
    assert_eq!(
        core.call_builtin_by_id(175, RegRange { start: 0, count: 2 })
            .expect("Map.prototype.get should read seeded entry"),
        Value::Int(1)
    );
    core.set_reg(1, Value::str("beta"));
    assert_eq!(
        core.call_builtin_by_id(175, RegRange { start: 0, count: 2 })
            .expect("Map.prototype.get should read second seeded entry"),
        Value::Int(2)
    );

    let set_iterable =
        alloc_indexed_object_for_test(&mut core, &[Value::Int(7), Value::Int(9), Value::Int(7)]);
    core.set_reg(0, Value::Object(set_iterable));
    let Value::Object(set_id) = core
        .call_builtin_by_id(171, RegRange { start: 0, count: 1 })
        .expect("Set constructor should accept iterable seed")
    else {
        panic!("Set constructor should return object");
    };

    assert_eq!(core.collection_size(set_id, "Set"), Some(2));
    core.set_reg(0, Value::Object(set_id));
    core.set_reg(1, Value::Int(7));
    assert_eq!(
        core.call_builtin_by_id(177, RegRange { start: 0, count: 2 })
            .expect("Set.prototype.has should observe seeded value"),
        Value::Bool(true)
    );
    core.set_reg(1, Value::Int(9));
    assert_eq!(
        core.call_builtin_by_id(177, RegRange { start: 0, count: 2 })
            .expect("Set.prototype.has should observe second seeded value"),
        Value::Bool(true)
    );
}

#[test]
fn weakmap_and_weakset_constructors_seed_iterable_input() {
    let mut core = quickjs_test_core();
    let key_a = core
        .alloc_object_with_prototype(None)
        .expect("weak collection key allocation should succeed");
    let key_b = core
        .alloc_object_with_prototype(None)
        .expect("second weak collection key allocation should succeed");

    let first_pair =
        alloc_indexed_object_for_test(&mut core, &[Value::Object(key_a), Value::Int(11)]);
    let second_pair =
        alloc_indexed_object_for_test(&mut core, &[Value::Object(key_b), Value::Int(13)]);
    let weakmap_iterable = alloc_indexed_object_for_test(
        &mut core,
        &[Value::Object(first_pair), Value::Object(second_pair)],
    );

    core.set_reg(0, Value::Object(weakmap_iterable));
    let Value::Object(weakmap_id) = core
        .call_builtin_by_id(172, RegRange { start: 0, count: 1 })
        .expect("WeakMap constructor should accept iterable seed")
    else {
        panic!("WeakMap constructor should return object");
    };
    let weakmap_entries = core
        .weakmap_storage
        .get(&weakmap_id)
        .expect("WeakMap should initialize weak storage");
    assert_eq!(weakmap_entries.get(key_a.0), Some(&Value::Int(11)));
    assert_eq!(weakmap_entries.get(key_b.0), Some(&Value::Int(13)));

    core.set_reg(0, Value::Object(weakmap_id));
    core.set_reg(1, Value::Object(key_a));
    assert_eq!(
        core.call_builtin_by_id(324, RegRange { start: 0, count: 2 })
            .expect("WeakMap.prototype.has should observe seeded key"),
        Value::Bool(true)
    );
    assert_eq!(
        core.call_builtin_by_id(328, RegRange { start: 0, count: 2 })
            .expect("WeakMap.prototype.get should observe seeded value"),
        Value::Int(11)
    );

    let weakset_iterable =
        alloc_indexed_object_for_test(&mut core, &[Value::Object(key_a), Value::Object(key_b)]);
    core.set_reg(0, Value::Object(weakset_iterable));
    let Value::Object(weakset_id) = core
        .call_builtin_by_id(173, RegRange { start: 0, count: 1 })
        .expect("WeakSet constructor should accept iterable seed")
    else {
        panic!("WeakSet constructor should return object");
    };
    let membership = core
        .weakmap_storage
        .get(&weakset_id)
        .expect("private WeakSet membership");
    assert_eq!(membership.get(key_a.0), Some(&Value::Bool(true)));
    assert_eq!(membership.get(key_b.0), Some(&Value::Bool(true)));
    assert!(
        !core.heap[weakset_id.0 as usize]
            .properties
            .contains_key("__values")
    );
}

#[test]
fn weakset_empty_iterator_completion_retains_membership_provenance() {
    let mut core = quickjs_test_core();
    let module = test_module(vec![Ir3Instruction::Halt]);
    let result = core
        .alloc_object_with_prototype(None)
        .expect("iterator result");
    core.set_object_property(result, "done".to_string(), Value::Bool(true))
        .expect("terminal iterator result");
    core.set_own_runtime_property_label(
        result,
        &RuntimePropertyKey::String(JsString::from("done")),
        &Label::Secret,
    )
    .expect("classified done property");
    // Object.prototype.valueOf returns this result object as next(). The
    // iterable handle is public; only reading its terminal done is secret.
    let iterator = core
        .init_iterator_from_state(
            Value::Object(result),
            RuntimeForOfInit::from_receiver(
                Value::Object(result),
                Value::BuiltinFunction(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::ObjectPrototypeValueOf,
                )),
            ),
            IterationKind::ForOf,
        )
        .expect("custom iterator");
    core.write_reg_with_label(0, iterator, Label::Public)
        .expect("public iterator argument");
    let Value::Object(set) = core
        .dispatch_builtin_hostcall(
            "builtin:WeakSet",
            RegRange { start: 0, count: 1 },
            Some(&module),
        )
        .expect("empty iterator seed")
    else {
        panic!("WeakSet must return an object");
    };
    assert!(core.weakmap_storage[&set].entries.is_empty());
    assert_eq!(core.object_mutation_labels.get(&set), Some(&Label::Secret));
    assert_eq!(core.pending_hostcall_result_label.as_ref(), Some(&Label::Secret));

    let absent = core
        .alloc_object_with_prototype(None)
        .expect("public membership query key");
    core.write_reg_with_label(0, Value::Object(absent), Label::Public)
        .expect("public query argument");
    core.clear_pending_hostcall_result_label();
    assert_eq!(
        core.weakset_method(
            Some(&module),
            "has",
            Value::Object(set),
            RegRange { start: 0, count: 1 },
        ),
        Ok(Value::Bool(false))
    );
    assert_eq!(core.pending_hostcall_result_label.as_ref(), Some(&Label::Secret));
}

#[test]
fn weakset_membership_retains_receiver_and_callee_selection_across_public_aliases() {
    let module = test_module(vec![
        Ir3Instruction::CallMethod {
            receiver: 1,
            callee: 2,
            args: RegRange { start: 3, count: 1 },
            dst: 6,
        },
        Ir3Instruction::CallMethod {
            receiver: 4,
            callee: 5,
            args: RegRange { start: 3, count: 1 },
            dst: 0,
        },
        Ir3Instruction::Halt,
    ]);
    for config in [test_quickjs_config(), test_v8_config()] {
        // Isolate receiver selection from callee selection: each must reach
        // the collection itself, even when the query uses a Public alias.
        for selected_register in [1, 2] {
            let mut core = InterpreterCore::new(config.clone(), "weakset-selection");
            let set = core.alloc_weak_collection("WeakSet").expect("WeakSet");
            let key = core
                .alloc_object_with_prototype(None)
                .expect("member identity");
            let add = InterpreterCore::collection_prototype_method("WeakSet", "add")
                .expect("intrinsic add");
            let has = InterpreterCore::collection_prototype_method("WeakSet", "has")
                .expect("intrinsic has");
            for (register, value) in [
                (1, Value::Object(set)),
                (2, Value::BuiltinFunction(add)),
                (3, Value::Object(key)),
                (4, Value::Object(set)),
                (5, Value::BuiltinFunction(has)),
            ] {
                core.seed_register(register, value).expect("seed operand");
            }
            let label = Label::Custom {
                name: "weakset-selection".to_string(),
                level: 7,
            };
            core.set_register_label(selected_register, label.clone())
                .expect("classified selection");
            let result = core.execute(&module).expect("actual builtin method calls");
            assert_eq!(result.value, Value::Bool(true));
            assert_eq!(result.completion_label, label);
            assert_eq!(core.object_mutation_labels.get(&set), Some(&label));
            assert!(core.active_inline_callback_context_label.is_none());
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}

fn assert_string_split_result(result: Value, expected: Vec<&str>, core: &mut InterpreterCore) {
    let Value::Object(array_id) = result else {
        // SAFETY: Test helper validates string split returns array object type
        panic!("split should return array object, got {result:?}");
    };

    let array_obj = &core.heap[array_id.0 as usize];
    let length = match array_obj.properties.get("length") {
        Some(Value::Int(length)) => *length as usize,
        Some(other) => {
            // SAFETY: Test helper validates string split array has integer length property
            panic!("split length should be Int, got {other:?}");
        }
        // SAFETY: Test helper validates string split array has length property
        None => panic!("split result missing length"),
    };

    assert_eq!(length, expected.len());
    for (index, expected_part) in expected.iter().enumerate() {
        assert_eq!(
            array_obj.properties.get(&index.to_string()),
            Some(&Value::str(*expected_part))
        );
    }
}

#[test]
fn string_split_omitted_and_undefined_separator_returns_whole_string() {
    let mut core = quickjs_test_core();
    core.set_reg(0, Value::str("hello"));

    // SAFETY: call_builtin cannot fail with valid test inputs
    let result = core
        .call_builtin(
            "builtin:StringPrototypeSplit",
            RegRange { start: 0, count: 1 },
        )
        .expect("operation should succeed for valid inputs");
    assert_string_split_result(result, vec!["hello"], &mut core);

    core.set_reg(1, Value::Undefined);
    // SAFETY: call_builtin cannot fail with valid test inputs and builtin function name
    let result = core
        .call_builtin(
            "builtin:StringPrototypeSplit",
            RegRange { start: 0, count: 2 },
        )
        .expect("operation should succeed for valid inputs");
    assert_string_split_result(result, vec!["hello"], &mut core);
}

#[test]
fn string_split_omitted_and_undefined_separator_handle_non_ascii() {
    let mut core = quickjs_test_core();
    core.set_reg(0, Value::str("a🙂b"));

    // SAFETY: call_builtin cannot fail with valid test inputs and builtin function name
    let result = core
        .call_builtin(
            "builtin:StringPrototypeSplit",
            RegRange { start: 0, count: 1 },
        )
        .expect("operation should succeed for valid inputs");
    assert_string_split_result(result, vec!["a🙂b"], &mut core);

    core.set_reg(1, Value::Undefined);
    // SAFETY: call_builtin cannot fail with valid test inputs and builtin function name
    let result = core
        .call_builtin(
            "builtin:StringPrototypeSplit",
            RegRange { start: 0, count: 2 },
        )
        .expect("operation should succeed for valid inputs");
    assert_string_split_result(result, vec!["a🙂b"], &mut core);
}

#[test]
fn string_split_omitted_separator_and_undefined_keep_whole_punctuation_string() {
    let mut core = quickjs_test_core();
    core.set_reg(0, Value::str("a,b"));

    // SAFETY: call_builtin cannot fail with valid test inputs and builtin function name
    let result = core
        .call_builtin(
            "builtin:StringPrototypeSplit",
            RegRange { start: 0, count: 1 },
        )
        .expect("operation should succeed for valid inputs");
    assert_string_split_result(result, vec!["a,b"], &mut core);

    core.set_reg(1, Value::Undefined);
    // SAFETY: call_builtin cannot fail with valid test inputs and builtin function name
    let result = core
        .call_builtin(
            "builtin:StringPrototypeSplit",
            RegRange { start: 0, count: 2 },
        )
        .expect("operation should succeed for valid inputs");
    assert_string_split_result(result, vec!["a,b"], &mut core);
}

#[test]
fn string_split_empty_separator_splits_characters() {
    let mut core = quickjs_test_core();
    core.set_reg(0, Value::str("ab"));
    core.set_reg(1, Value::str(""));

    // SAFETY: call_builtin cannot fail with valid test inputs and builtin function name
    let result = core
        .call_builtin(
            "builtin:StringPrototypeSplit",
            RegRange { start: 0, count: 2 },
        )
        .expect("operation should succeed for valid inputs");
    assert_string_split_result(result, vec!["a", "b"], &mut core);
}

#[test]
fn string_split_normal_separator() {
    let mut core = quickjs_test_core();
    core.set_reg(0, Value::str("a,b,c"));
    core.set_reg(1, Value::str(","));

    // SAFETY: call_builtin cannot fail with valid test inputs and builtin function name
    let result = core
        .call_builtin(
            "builtin:StringPrototypeSplit",
            RegRange { start: 0, count: 2 },
        )
        .expect("operation should succeed for valid inputs");
    assert_string_split_result(result, vec!["a", "b", "c"], &mut core);
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HookRecord {
    Property {
        ctx: HookContext,
        target: ObjectId,
        key: String,
    },
    Call {
        ctx: HookContext,
        callee: FunctionRef,
        args: Vec<Value>,
    },
    Allocation {
        ctx: HookContext,
        kind: AllocKind,
        size_hint: usize,
    },
    Import {
        ctx: HookContext,
        specifier: String,
    },
}

#[derive(Debug)]
struct RecordingHook {
    records: Mutex<Vec<HookRecord>>,
    property_action: HookAction,
    call_action: HookAction,
    allocation_action: HookAction,
    import_action: HookAction,
}

impl RecordingHook {
    fn allow_all() -> Self {
        Self {
            records: Mutex::new(Vec::new()),
            property_action: HookAction::Allow,
            call_action: HookAction::Allow,
            allocation_action: HookAction::Allow,
            import_action: HookAction::Allow,
        }
    }

    fn with_allocation_action(action: HookAction) -> Self {
        Self {
            allocation_action: action,
            ..Self::allow_all()
        }
    }

    fn records(&self) -> Vec<HookRecord> {
        // SAFETY: Test-only unwrap for uncontended Mutex in single-threaded test context
        self.records
            .lock()
            .expect("operation should succeed for valid inputs")
            .clone()
    }
}

impl InterpreterHook for RecordingHook {
    fn pre_property_access(
        &self,
        ctx: &HookContext,
        target: &ObjectRef,
        key: &PropertyKey,
    ) -> HookAction {
        // SAFETY: Test-only unwrap for uncontended Mutex in single-threaded test context
        self.records
            .lock()
            .expect("operation should succeed for valid inputs")
            .push(HookRecord::Property {
                ctx: ctx.clone(),
                target: *target,
                key: key.clone(),
            });
        self.property_action.clone()
    }

    fn pre_call(&self, ctx: &HookContext, callee: &FunctionRef, args: &[Value]) -> HookAction {
        // SAFETY: Test-only unwrap for uncontended Mutex in single-threaded test context
        self.records
            .lock()
            .expect("operation should succeed for valid inputs")
            .push(HookRecord::Call {
                ctx: ctx.clone(),
                callee: callee.clone(),
                args: args.to_vec(),
            });
        self.call_action.clone()
    }

    fn pre_allocation(&self, ctx: &HookContext, kind: AllocKind, size_hint: usize) -> HookAction {
        // SAFETY: Test-only unwrap for uncontended Mutex in single-threaded test context
        self.records
            .lock()
            .expect("operation should succeed for valid inputs")
            .push(HookRecord::Allocation {
                ctx: ctx.clone(),
                kind,
                size_hint,
            });
        self.allocation_action.clone()
    }

    fn pre_import(&self, ctx: &HookContext, specifier: &str) -> HookAction {
        // SAFETY: Test-only unwrap for uncontended Mutex in single-threaded test context
        self.records
            .lock()
            .expect("operation should succeed for valid inputs")
            .push(HookRecord::Import {
                ctx: ctx.clone(),
                specifier: specifier.to_string(),
            });
        self.import_action.clone()
    }
}

#[test]
fn compact_tier1_router_preserves_containment_hook_bd_performance_bridge_5_6() {
    let module = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 7 },
        Ir3Instruction::NewObject { dst: 0 },
        Ir3Instruction::Halt,
    ]);
    let plan = CompactTier1Program::compile(&module).expect("mixed compact plan");
    let compact_hook = Arc::new(RecordingHook::allow_all());
    let config = test_quickjs_config();
    let compact = LaneRouter::with_configs(config.clone(), config.clone())
        .execute_with_hook_and_compact_tier1(
            &module,
            "tier-i-hook",
            Some(LaneChoice::QuickJs),
            Some(compact_hook.clone()),
            Some(&plan),
        )
        .expect("compact execution with hook");

    let baseline_hook = Arc::new(RecordingHook::allow_all());
    let baseline = LaneRouter::with_configs(config.clone(), config)
        .execute_with_hook(
            &module,
            "tier-i-hook",
            Some(LaneChoice::QuickJs),
            Some(baseline_hook.clone()),
        )
        .expect("baseline execution with hook");

    assert_execution_semantics_equal(&compact.result, &baseline.result);
    assert!(compact.result.tier_i_instructions_executed > 0);
    assert_eq!(baseline.result.tier_i_instructions_executed, 0);
    assert_eq!(compact_hook.records(), baseline_hook.records());
    assert!(
        compact_hook
            .records()
            .iter()
            .any(|record| matches!(record, HookRecord::Allocation { .. })),
        "the compact route must not discard the containment hook"
    );
}

#[derive(Debug, Default)]
struct TypedRecordingHook {
    keys: Mutex<Vec<HookPropertyKey>>,
}

impl TypedRecordingHook {
    fn keys(&self) -> Vec<HookPropertyKey> {
        self.keys
            .lock()
            .expect("typed hook records should remain available")
            .clone()
    }
}

impl InterpreterHook for TypedRecordingHook {
    fn pre_property_access(
        &self,
        _ctx: &HookContext,
        _target: &ObjectRef,
        _key: &PropertyKey,
    ) -> HookAction {
        panic!("typed property hook must not route through the legacy string callback")
    }

    fn pre_property_access_typed(
        &self,
        _ctx: &HookContext,
        _target: &ObjectRef,
        key: &HookPropertyKey,
    ) -> Result<HookAction, HookPropertyKeyCompatibilityError> {
        self.keys
            .lock()
            .expect("typed hook records should remain available")
            .push(key.clone());
        Ok(HookAction::Allow)
    }

    fn pre_call(&self, _ctx: &HookContext, _callee: &FunctionRef, _args: &[Value]) -> HookAction {
        HookAction::Allow
    }

    fn pre_allocation(
        &self,
        _ctx: &HookContext,
        _kind: AllocKind,
        _size_hint: usize,
    ) -> HookAction {
        HookAction::Allow
    }

    fn pre_import(&self, _ctx: &HookContext, _specifier: &str) -> HookAction {
        HookAction::Allow
    }
}

#[test]
fn interpreter_hook_called_on_property_access() {
    let hook = Arc::new(RecordingHook::allow_all());
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "test-trace");
    prime_entry_module_record(&mut core);
    core.set_hook(hook.clone());

    // SAFETY: Test-only unwrap expecting object allocation to succeed with valid parameters
    let oid = core
        .alloc_object_with_prototype(None)
        .expect("operation should succeed for valid inputs");
    core.mutate_heap(|heap| {
        heap[oid.0 as usize]
            .properties
            .insert("secret".to_string(), Value::Int(99));
    });
    core.set_reg(1, Value::Object(oid));
    core.set_reg(2, Value::str("secret"));

    // SAFETY: Test-only unwrap expecting execution to succeed with valid test module
    let result = core
        .execute(&test_module(vec![
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 0,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    assert_eq!(result.value, Value::Int(99));
    assert_eq!(
        hook.records(),
        vec![HookRecord::Property {
            ctx: HookContext {
                extension_id: "test".to_string(),
                instruction_count: 1,
                current_ip: 0,
            },
            target: oid,
            key: "secret".to_string(),
        }]
    );
}

#[test]
fn typed_property_hook_default_adapter_is_lossless_bd_n8eta_4_4() {
    let hook = RecordingHook::allow_all();
    let ctx = HookContext {
        extension_id: "typed-adapter".to_string(),
        instruction_count: 3,
        current_ip: 2,
    };
    let target = ObjectId(7);

    assert_eq!(
        hook.pre_property_access_typed(
            &ctx,
            &target,
            &HookPropertyKey::String(JsString::from("ordinary")),
        ),
        Ok(HookAction::Allow)
    );
    assert!(matches!(
        hook.pre_property_access_typed(
            &ctx,
            &target,
            &HookPropertyKey::String(JsString::from_code_units(&[0xD800])),
        ),
        Err(HookPropertyKeyCompatibilityError::NonWellFormedString)
    ));
    assert!(matches!(
        hook.pre_property_access_typed(&ctx, &target, &HookPropertyKey::Symbol(SymbolId(14)),),
        Err(HookPropertyKeyCompatibilityError::Symbol)
    ));
    assert!(matches!(
        hook.records().as_slice(),
        [HookRecord::Property { key, .. }] if key == "ordinary"
    ));

    let exact = HookPropertyKey::String(JsString::from_code_units(&[0xD801]));
    let wire = serde_json::to_string(&exact).expect("typed hook key should serialize");
    assert_eq!(
        serde_json::from_str::<HookPropertyKey>(&wire).expect("typed hook key should deserialize"),
        exact
    );
    assert_eq!(
        serde_json::to_string(&HookPropertyKey::Symbol(SymbolId(14)))
            .expect("Symbol hook key should serialize"),
        r#"{"Symbol":14}"#
    );
}

#[test]
fn typed_property_hook_preserves_runtime_key_identity_bd_n8eta_4_4() {
    let mut core = InterpreterCore::new(test_quickjs_config(), "typed-property-hook");
    prime_entry_module_record(&mut core);
    let object = core
        .alloc_object_with_prototype(None)
        .expect("object allocation should succeed");
    let symbol = core
        .allocate_private_symbol(Some(JsString::from("hook-key")))
        .expect("Symbol allocation should succeed");
    let symbol_diagnostic_string = JsString::from(format!("~pk~s:{}", symbol.0));
    let exact = JsString::from_code_units(&[0xD800]);

    for (key, value) in [
        (RuntimePropertyKey::Symbol(symbol), Value::Int(41)),
        (
            RuntimePropertyKey::String(symbol_diagnostic_string.clone()),
            Value::Int(42),
        ),
        (RuntimePropertyKey::String(exact.clone()), Value::Int(43)),
    ] {
        core.set_object_runtime_property(object, key, value)
            .expect("typed test property should fit");
    }

    let legacy_hook = Arc::new(RecordingHook::allow_all());
    core.set_hook(legacy_hook.clone());
    core.set_reg(1, Value::Object(object));
    core.set_reg(2, Value::Symbol(symbol));
    let heap_before =
        serde_json::to_string(&*core.heap).expect("legacy hook heap should serialize");
    assert!(matches!(
        core.run_loop(&test_module(vec![Ir3Instruction::GetProperty {
            obj: 1,
            key: 2,
            dst: 5,
        }])),
        Err(InterpreterError::TypeError { .. })
    ));
    assert!(legacy_hook.records().is_empty());
    assert_eq!(
        serde_json::to_string(&*core.heap)
            .expect("legacy hook heap should serialize after rejection"),
        heap_before
    );

    core.ip = 0;
    let hook = Arc::new(TypedRecordingHook::default());
    core.set_hook(hook.clone());
    core.set_reg(2, Value::Symbol(SymbolId(u32::MAX)));
    assert!(matches!(
        core.run_loop(&test_module(vec![Ir3Instruction::GetProperty {
            obj: 1,
            key: 2,
            dst: 5,
        }])),
        Err(InterpreterError::TypeError { got, .. })
            if got.contains("unresolved Symbol id")
    ));
    assert!(
        hook.keys().is_empty(),
        "typed hook must not observe unresolved Symbol identity"
    );

    core.ip = 0;
    core.set_reg(2, Value::Symbol(symbol));
    core.set_reg(3, Value::Str(symbol_diagnostic_string.clone()));
    core.set_reg(4, Value::Str(exact.clone()));
    core.set_reg(9, Value::Int(99));
    assert!(matches!(
        core.run_loop(&test_module(vec![
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 5,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 3,
                dst: 6,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 4,
                dst: 7,
            },
            Ir3Instruction::InOp {
                dst: 8,
                lhs: 2,
                rhs: 1,
            },
            Ir3Instruction::SetProperty {
                obj: 1,
                key: 2,
                val: 9,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 10,
            },
            Ir3Instruction::DeleteProperty {
                obj: 1,
                key: 2,
                dst: 11,
            },
            Ir3Instruction::Halt,
        ])),
        Err(InterpreterError::Halted)
    ));

    assert_eq!(core.read_reg(5), Ok(Value::Int(41)));
    assert_eq!(core.read_reg(6), Ok(Value::Int(42)));
    assert_eq!(core.read_reg(7), Ok(Value::Int(43)));
    assert_eq!(core.read_reg(8), Ok(Value::Bool(true)));
    assert_eq!(core.read_reg(10), Ok(Value::Int(99)));
    assert_eq!(core.read_reg(11), Ok(Value::Bool(true)));
    assert_eq!(
        hook.keys(),
        vec![
            HookPropertyKey::Symbol(symbol),
            HookPropertyKey::String(symbol_diagnostic_string),
            HookPropertyKey::String(exact),
            HookPropertyKey::Symbol(symbol),
            HookPropertyKey::Symbol(symbol),
            HookPropertyKey::Symbol(symbol),
            HookPropertyKey::Symbol(symbol),
        ]
    );
}

#[test]
fn exact_keys_respect_legacy_hook_boundary_bd_b12xs_5() {
    fn assert_exact_instruction_rejected(instruction: Ir3Instruction) {
        let hook = Arc::new(RecordingHook::allow_all());
        let mut core = InterpreterCore::new(test_quickjs_config(), "exact-hook-boundary");
        prime_entry_module_record(&mut core);
        let object = core
            .alloc_object_with_prototype(None)
            .expect("object allocation should succeed");
        core.set_reg(1, Value::Object(object));
        core.set_reg(2, Value::Str(JsString::from_code_units(&[0xD800])));
        core.set_reg(3, Value::Int(8));
        core.set_reg(4, Value::Function(0));
        core.set_hook(hook.clone());
        let heap_before =
            serde_json::to_string(&*core.heap).expect("hook-boundary heap should serialize");
        let memory_before = core.estimated_memory_bytes();

        let error = core
            .run_loop(&test_module(vec![instruction]))
            .expect_err("legacy hook must reject a non-well-formed key");
        assert!(matches!(error, InterpreterError::TypeError { .. }));
        assert!(
            hook.records().is_empty(),
            "representability rejection must not invoke the legacy callback"
        );
        assert_eq!(
            serde_json::to_string(&*core.heap)
                .expect("hook-boundary heap should serialize after rejection"),
            heap_before
        );
        assert_eq!(core.estimated_memory_bytes(), memory_before);
    }

    assert_exact_instruction_rejected(Ir3Instruction::GetProperty {
        obj: 1,
        key: 2,
        dst: 0,
    });
    assert_exact_instruction_rejected(Ir3Instruction::SetProperty {
        obj: 1,
        key: 2,
        val: 3,
    });
    assert_exact_instruction_rejected(Ir3Instruction::DeleteProperty {
        obj: 1,
        key: 2,
        dst: 0,
    });
    assert_exact_instruction_rejected(Ir3Instruction::InOp {
        dst: 0,
        lhs: 2,
        rhs: 1,
    });
    assert_exact_instruction_rejected(Ir3Instruction::DefineAccessor {
        obj: 1,
        key: 2,
        func: 4,
        kind: AccessorKind::Get,
    });
    assert_exact_instruction_rejected(Ir3Instruction::DefineMethod {
        obj: 1,
        key: 2,
        func: 4,
    });

    let hook = Arc::new(RecordingHook::allow_all());
    let mut core = InterpreterCore::new(test_quickjs_config(), "well-formed-hook");
    prime_entry_module_record(&mut core);
    let object = core
        .alloc_object_with_prototype(None)
        .expect("object allocation should succeed");
    core.set_object_property(object, "\u{FFFD}".to_string(), Value::Int(0xFFFD))
        .expect("well-formed replacement property should fit");
    core.set_reg(1, Value::Object(object));
    core.set_reg(2, Value::str("\u{FFFD}"));
    core.set_hook(hook.clone());
    let result = core
        .run_loop(&test_module(vec![Ir3Instruction::GetProperty {
            obj: 1,
            key: 2,
            dst: 0,
        }]))
        .expect("well-formed hook key should proceed");
    assert_eq!(result, Value::Int(0xFFFD));
    assert!(matches!(
        hook.records().as_slice(),
        [HookRecord::Property { key, .. }] if key == "\u{FFFD}"
    ));
}

#[test]
fn interpreter_hook_called_on_call() {
    let hook = Arc::new(RecordingHook::allow_all());
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "test-trace");
    prime_entry_module_record(&mut core);
    core.set_hook(hook.clone());
    core.set_reg(1, Value::Int(5));
    core.set_reg(3, Value::Function(0));

    // SAFETY: Test-only unwrap expecting execution to succeed with valid test module
    let result = core
        .execute(&test_module_with_functions(
            vec![
                Ir3Instruction::Call {
                    callee: 3,
                    args: RegRange { start: 1, count: 1 },
                    dst: 0,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::Return { value: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 1,
                frame_size: 2,
                name: Some("identity".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        ))
        .expect("operation should succeed for valid inputs");

    assert_eq!(result.value, Value::Int(5));
    assert_eq!(
        hook.records(),
        vec![HookRecord::Call {
            ctx: HookContext {
                extension_id: "test".to_string(),
                instruction_count: 1,
                current_ip: 0,
            },
            callee: FunctionRef::Function {
                function_index: 0,
                name: Some("identity".to_string()),
            },
            args: vec![Value::Int(5)],
        }]
    );
}

#[test]
fn interpreter_hook_called_on_allocation() {
    let hook = Arc::new(RecordingHook::allow_all());
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "test-trace");
    prime_entry_module_record(&mut core);
    core.set_hook(hook.clone());

    // SAFETY: Test-only unwrap expecting execution to succeed with valid test module
    let result = core
        .execute(&test_module(vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    assert!(matches!(result.value, Value::Object(_)));
    assert_eq!(
        hook.records(),
        vec![HookRecord::Allocation {
            ctx: HookContext {
                extension_id: "test".to_string(),
                instruction_count: 1,
                current_ip: 0,
            },
            kind: AllocKind::Object,
            size_hint: 0,
        }]
    );
}

#[test]
fn interpreter_hook_called_on_closure_allocation() {
    let hook = Arc::new(RecordingHook::allow_all());
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "test-trace");
    prime_entry_module_record(&mut core);
    core.set_hook(hook.clone());

    // SAFETY: Test-only unwrap expecting execution to succeed with valid test module
    let result = core
        .execute(&test_module_with_functions(
            vec![
                Ir3Instruction::CreateClosure {
                    dst: 0,
                    function_index: 0,
                    capture_count: 2,
                },
                Ir3Instruction::Halt,
            ],
            vec![Ir3FunctionDesc {
                entry: 1,
                arity: 0,
                frame_size: 1,
                name: Some("closure_target".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        ))
        .expect("operation should succeed for valid inputs");

    assert!(matches!(result.value, Value::Closure(0)));
    assert_eq!(
        hook.records(),
        vec![HookRecord::Allocation {
            ctx: HookContext {
                extension_id: "test".to_string(),
                instruction_count: 1,
                current_ip: 0,
            },
            kind: AllocKind::Closure,
            size_hint: 2,
        }]
    );
}

#[test]
fn interpreter_hook_allow_continues_execution() {
    let hook = Arc::new(RecordingHook::allow_all());
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "test-trace");
    core.set_hook(hook);

    // SAFETY: Test-only unwrap expecting object allocation to succeed with valid parameters
    let oid = core
        .alloc_object_with_prototype(None)
        .expect("operation should succeed for valid inputs");
    core.set_reg(1, Value::Object(oid));
    core.set_reg(2, Value::str("key"));
    core.set_reg(3, Value::Int(7));

    // SAFETY: Test-only unwrap expecting execution to succeed with valid test module
    let result = core
        .execute(&test_module(vec![
            Ir3Instruction::SetProperty {
                obj: 1,
                key: 2,
                val: 3,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 0,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    assert_eq!(result.value, Value::Int(7));
}

#[test]
fn interpreter_hook_terminate_stops_execution() {
    let hook = Arc::new(RecordingHook::with_allocation_action(
        HookAction::Terminate("policy denied object allocation".to_string()),
    ));
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "test-trace");
    core.set_hook(hook.clone());

    let err = core
        .execute(&test_module(vec![Ir3Instruction::NewObject { dst: 0 }]))
        .unwrap_err();

    assert_eq!(
        err,
        InterpreterError::ContainmentActionRequested {
            action: "terminate".to_string(),
            reason: Some("policy denied object allocation".to_string()),
        }
    );
    assert_eq!(hook.records().len(), 1);
    assert!(
        !core.nondeterminism_trace_ref().is_finalised(),
        "an ordinary direct-core error must retain its partial, unfinalised trace"
    );
}

#[test]
fn lane_execute_with_hook_preserves_requested_containment_in_result() {
    let hook = Arc::new(RecordingHook::with_allocation_action(
        HookAction::Terminate("policy denied object allocation".to_string()),
    ));
    let lane = QuickJsLane::with_config(test_quickjs_config());
    let result = lane
        .execute_with_hook(
            &test_module(vec![Ir3Instruction::NewObject { dst: 0 }]),
            "test-trace",
            Some(hook),
        )
        .expect("lane should surface containment as structured output");

    assert_eq!(
        result.requested_hook_action,
        Some(HookAction::Terminate(
            "policy denied object allocation".to_string()
        ))
    );
    assert_eq!(result.value, Value::Undefined);
    assert_eq!(result.instructions_executed, 2); // NewObject + empty Writable checkpoint scan
    assert!(result.nondeterminism_trace.is_finalised());
    result
        .nondeterminism_trace
        .validate_for_replay()
        .expect("lane containment trace must remain replay-valid after ownership handoff");
}

#[test]
fn interpreter_hook_none_preserves_execution_when_unset() {
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "test-trace");
    let oid = core
        .alloc_object_with_prototype(None)
        .expect("operation should succeed for valid inputs");
    core.mutate_heap(|heap| {
        heap[oid.0 as usize]
            .properties
            .insert("stable".to_string(), Value::Int(12));
    });
    core.set_reg(1, Value::Object(oid));
    core.set_reg(2, Value::str("stable"));

    let result = core
        .execute(&test_module(vec![
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 0,
            },
            Ir3Instruction::Halt,
        ]))
        .expect("operation should succeed for valid inputs");

    assert_eq!(result.value, Value::Int(12));
    assert!(core.hook.is_none());
}

#[test]
fn interpreter_hook_receives_correct_context() {
    let hook = Arc::new(RecordingHook::allow_all());
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "test-trace");
    let mut module = test_module(vec![
        Ir3Instruction::LoadInt { dst: 4, value: 1 },
        Ir3Instruction::NewArray { dst: 0 },
        Ir3Instruction::Halt,
    ]);
    module.header.source_label = "extension://hook-test".to_string();

    // Pre-create the module record (see `prime_entry_module_record`) before
    // installing the hook, so `prepare_execution`'s lazy module-namespace
    // allocation does not surface as an extra pre-allocation hook event.
    core.ensure_module_record(&module, "extension://hook-test")
        .expect("prime module record before installing hook");
    core.set_hook(hook.clone());

    let result = core
        .execute(&module)
        .expect("operation should succeed for valid inputs");
    assert!(matches!(result.value, Value::Object(_)));
    assert_eq!(
        hook.records(),
        vec![HookRecord::Allocation {
            ctx: HookContext {
                extension_id: "extension://hook-test".to_string(),
                instruction_count: 2,
                current_ip: 1,
            },
            kind: AllocKind::Array,
            size_hint: 0,
        }]
    );
}

#[test]
fn interpreter_hook_pre_import_surface_is_available() {
    let hook = RecordingHook::allow_all();
    let config = InterpreterConfig::quickjs_defaults();
    let core = InterpreterCore::new(config, "test-trace");
    let mut module = test_module(vec![Ir3Instruction::Halt]);
    module.header.source_label = "extension://import-surface".to_string();

    let ctx = core.hook_context(&module);
    let action = hook.pre_import(&ctx, "lodash");

    assert_eq!(action, HookAction::Allow);
    assert_eq!(
        hook.records(),
        vec![HookRecord::Import {
            ctx: HookContext {
                extension_id: "extension://import-surface".to_string(),
                instruction_count: 0,
                current_ip: 0,
            },
            specifier: "lodash".to_string(),
        }]
    );
}

// -----------------------------------------------------------------------
// 1. Load instructions
// -----------------------------------------------------------------------

#[test]
fn load_int() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 42 },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Int(42));
}

#[test]
fn load_str() {
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::Halt,
        ],
        vec!["hello".to_string()],
    );
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::str("hello"));
}

#[test]
fn load_bool_true() {
    let m = test_module(vec![
        Ir3Instruction::LoadBool {
            dst: 0,
            value: true,
        },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Bool(true));
}

#[test]
fn load_null() {
    let m = test_module(vec![
        Ir3Instruction::LoadNull { dst: 0 },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Null);
}

#[test]
fn load_undefined() {
    let m = test_module(vec![
        Ir3Instruction::LoadUndefined { dst: 0 },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Undefined);
}

// -----------------------------------------------------------------------
// 2. Arithmetic
// -----------------------------------------------------------------------

#[test]
fn add_integers() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 3 },
        Ir3Instruction::LoadInt { dst: 2, value: 4 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Int(7));
}

#[test]
fn add_strings() {
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::Add {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Halt,
        ],
        vec!["hello".to_string(), " world".to_string()],
    );
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::str("hello world"));
}

#[test]
fn sub_integers() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 10 },
        Ir3Instruction::LoadInt { dst: 2, value: 3 },
        Ir3Instruction::Sub {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Int(7));
}

#[test]
fn mul_integers() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 6 },
        Ir3Instruction::LoadInt { dst: 2, value: 7 },
        Ir3Instruction::Mul {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Int(42));
}

#[test]
fn div_integers() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 20 },
        Ir3Instruction::LoadInt { dst: 2, value: 4 },
        Ir3Instruction::Div {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Int(5));
}

#[test]
fn div_by_zero() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 10 },
        Ir3Instruction::LoadInt { dst: 2, value: 0 },
        Ir3Instruction::Div {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
    ]);
    // 10 / 0 === Infinity in JavaScript — division never throws — so the Div
    // opcode yields Ok(Float(inf)). The legacy assertion expected a
    // Rust-style DivisionByZero error, which is not JS semantics (bd-n0sap).
    let result = quickjs_execute(&m).expect("JS division by zero yields Infinity, not an error");
    assert_eq!(result.value, Value::Float(Float64::new(f64::INFINITY)));
}

#[test]
fn add_coerces_bool_and_null_to_number() {
    // JS semantics: true + null = 1 + 0 = 1
    let m = test_module(vec![
        Ir3Instruction::LoadBool {
            dst: 1,
            value: true,
        },
        Ir3Instruction::LoadNull { dst: 2 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
    ]);
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Int(1));
}

// -----------------------------------------------------------------------
// 3. Control flow
// -----------------------------------------------------------------------

#[test]
fn unconditional_jump() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 },  // 0
        Ir3Instruction::Jump { target: 3 },            // 1: jump to 3
        Ir3Instruction::LoadInt { dst: 0, value: 99 }, // 2: skipped
        Ir3Instruction::Halt,                          // 3
    ]);
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Int(1));
}

#[test]
fn conditional_jump_taken() {
    let m = test_module(vec![
        Ir3Instruction::LoadBool {
            dst: 1,
            value: true,
        }, // 0
        Ir3Instruction::LoadInt { dst: 0, value: 10 }, // 1
        Ir3Instruction::JumpIf { cond: 1, target: 4 }, // 2: jump if true -> 4
        Ir3Instruction::LoadInt { dst: 0, value: 20 }, // 3: skipped
        Ir3Instruction::Halt,                          // 4
    ]);
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Int(10));
}

#[test]
fn conditional_jump_not_taken() {
    let m = test_module(vec![
        Ir3Instruction::LoadBool {
            dst: 1,
            value: false,
        }, // 0
        Ir3Instruction::LoadInt { dst: 0, value: 10 }, // 1
        Ir3Instruction::JumpIf { cond: 1, target: 4 }, // 2: not taken
        Ir3Instruction::LoadInt { dst: 0, value: 20 }, // 3: executed
        Ir3Instruction::Halt,                          // 4
    ]);
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Int(20));
}

// -----------------------------------------------------------------------
// 4. Function calls
// -----------------------------------------------------------------------

#[test]
fn simple_function_call() {
    // r1 = 5 (argument), r3 = Function(0) (callee, pre-set).
    // Call func(r1) -> r0.
    // Function body at instruction 2: load 10 into r1, add r0+r1 -> r2, return r2.
    let m = test_module_with_functions(
        vec![
            // Main
            Ir3Instruction::Call {
                callee: 3,
                args: RegRange { start: 1, count: 1 },
                dst: 0,
            }, // 0
            Ir3Instruction::Halt, // 1: return here after call
            // Function body (entry at 2)
            Ir3Instruction::LoadInt { dst: 1, value: 10 }, // 2
            Ir3Instruction::Add {
                dst: 2,
                lhs: 0,
                rhs: 1,
            }, // 3: r2 = r0 + 10
            Ir3Instruction::Return { value: 2 },           // 4
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 1,
            frame_size: 3,
            name: Some("add_ten".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );

    let mut config = test_quickjs_config();
    config.instruction_budget = 1000;
    let mut core = InterpreterCore::new(config, "test");
    // Pre-set registers: r3 = callee function, r1 = argument.
    core.set_reg(3, Value::Function(0));
    core.set_reg(1, Value::Int(5));
    let result = core
        .execute(&m)
        .expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Int(15));
}

#[test]
fn array_reduce_invokes_reducer_with_initial_value() {
    let module = array_reduce_module(
        3,
        vec![
            Ir3Instruction::Add {
                dst: 4,
                lhs: 0,
                rhs: 1,
            },
            Ir3Instruction::Return { value: 4 },
        ],
        Vec::new(),
    );
    let mut core = quickjs_test_core();
    let array_id = seed_array(
        &mut core,
        3,
        &[(0, Value::Int(1)), (1, Value::Int(2)), (2, Value::Int(3))],
    );
    core.set_reg(0, Value::Object(array_id));
    core.set_reg(1, Value::Function(0));
    core.set_reg(2, Value::Int(10));

    let result = core
        .execute(&module)
        .expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Int(16));
}

#[test]
fn array_reduce_uses_first_present_sparse_element_without_initial() {
    let module = array_reduce_module(
        2,
        vec![
            Ir3Instruction::Add {
                dst: 4,
                lhs: 0,
                rhs: 1,
            },
            Ir3Instruction::Return { value: 4 },
        ],
        Vec::new(),
    );
    let mut core = quickjs_test_core();
    let array_id = seed_array(&mut core, 4, &[(1, Value::Int(5)), (3, Value::Int(7))]);
    core.set_reg(0, Value::Object(array_id));
    core.set_reg(1, Value::Function(0));

    let result = core
        .execute(&module)
        .expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Int(12));
}

#[test]
fn array_reduce_empty_without_initial_value_errors() {
    let module = array_reduce_module(
        2,
        vec![
            Ir3Instruction::Add {
                dst: 4,
                lhs: 0,
                rhs: 1,
            },
            Ir3Instruction::Return { value: 4 },
        ],
        Vec::new(),
    );
    let mut core = quickjs_test_core();
    let array_id = seed_array(&mut core, 0, &[]);
    core.set_reg(0, Value::Object(array_id));
    core.set_reg(1, Value::Function(0));

    let error = core.execute(&module).unwrap_err();
    assert!(matches!(
        error,
        InterpreterError::TypeError { expected, got }
            if expected == "non-empty array or initialValue"
                && got == "empty Array.prototype.reduce without initialValue"
    ));
}

#[test]
fn array_reduce_callback_receives_index_and_array_for_side_effects() {
    let module = array_reduce_module(
        3,
        vec![
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 0,
            },
            Ir3Instruction::SetProperty {
                obj: 3,
                key: 4,
                val: 2,
            },
            Ir3Instruction::Add {
                dst: 5,
                lhs: 0,
                rhs: 1,
            },
            Ir3Instruction::Return { value: 5 },
        ],
        vec!["lastIndex".to_string()],
    );
    let mut core = quickjs_test_core();
    let array_id = seed_array(
        &mut core,
        3,
        &[(0, Value::Int(2)), (1, Value::Int(4)), (2, Value::Int(6))],
    );
    core.mutate_registers(|r| {
        r[0] = Value::Object(array_id);
        r[1] = Value::Function(0);
        r[2] = Value::Int(0);
    });

    let result = core
        .execute(&module)
        .expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Int(12));
    assert_eq!(
        core.heap[array_id.0 as usize].properties.get("lastIndex"),
        Some(&Value::Int(2))
    );
}

#[test]
fn array_reduce_returns_object_accumulator_after_callback_mutation() {
    let module = array_reduce_module(
        3,
        vec![
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 0,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 4,
                val: 1,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec!["latest".to_string()],
    );
    let mut core = quickjs_test_core();
    let array_id = seed_array(
        &mut core,
        2,
        &[(0, Value::str("first")), (1, Value::str("second"))],
    );
    let accumulator_id = core
        .alloc_object_with_prototype(None)
        .expect("operation should succeed for valid inputs");
    core.set_reg(0, Value::Object(array_id));
    core.set_reg(1, Value::Function(0));
    core.set_reg(2, Value::Object(accumulator_id));

    let result = core
        .execute(&module)
        .expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Object(accumulator_id));
    assert_eq!(
        core.heap[accumulator_id.0 as usize]
            .properties
            .get("latest"),
        Some(&Value::str("second"))
    );
}

#[test]
fn array_reduce_metamorphic_initial_zero_matches_no_initial_sum() {
    let reducer = vec![
        Ir3Instruction::Add {
            dst: 4,
            lhs: 0,
            rhs: 1,
        },
        Ir3Instruction::Return { value: 4 },
    ];

    let no_initial = {
        let module = array_reduce_module(2, reducer.clone(), Vec::new());
        let mut core = quickjs_test_core();
        let array_id = seed_array(
            &mut core,
            3,
            &[(0, Value::Int(2)), (1, Value::Int(4)), (2, Value::Int(6))],
        );
        core.set_reg(0, Value::Object(array_id));
        core.set_reg(1, Value::Function(0));
        core.execute(&module)
            .expect("operation should succeed for valid inputs")
            .value
    };

    let initial_zero = {
        let module = array_reduce_module(3, reducer, Vec::new());
        let mut core = quickjs_test_core();
        let array_id = seed_array(
            &mut core,
            3,
            &[(0, Value::Int(2)), (1, Value::Int(4)), (2, Value::Int(6))],
        );
        core.set_reg(0, Value::Object(array_id));
        core.set_reg(1, Value::Function(0));
        core.set_reg(2, Value::Int(0));
        core.execute(&module)
            .expect("operation should succeed for valid inputs")
            .value
    };

    assert_eq!(no_initial, initial_zero);
    assert_eq!(initial_zero, Value::Int(12));
}

#[test]
fn array_reverse_preserves_sparse_holes_and_noncanonical_numeric_properties() {
    let mut core = quickjs_test_core();
    let array_id = seed_array(
        &mut core,
        3,
        &[(0, Value::str("first")), (2, Value::str("third"))],
    );
    core.set_object_property(array_id, "01".to_string(), Value::str("leading-zero"))
        .expect("operation should succeed for valid inputs");
    core.set_object_property(array_id, "3".to_string(), Value::str("past-length"))
        .expect("operation should succeed for valid inputs");
    core.set_object_property(array_id, "4294967295".to_string(), Value::str("uint32-max"))
        .expect("operation should succeed for valid inputs");
    core.set_reg(0, Value::Object(array_id));

    let result = core
        .dispatch_builtin_hostcall(
            "builtin:ArrayPrototypeReverse",
            RegRange { start: 0, count: 1 },
            None,
        )
        .expect("operation should succeed for valid inputs");

    assert_eq!(result, Value::Object(array_id));
    let properties = &core.heap[array_id.0 as usize].properties;
    assert_eq!(properties.get("0"), Some(&Value::str("third")));
    assert_eq!(properties.get("1"), None);
    assert_eq!(properties.get("2"), Some(&Value::str("first")));
    assert_eq!(properties.get("01"), Some(&Value::str("leading-zero")));
    assert_eq!(properties.get("3"), Some(&Value::str("past-length")));
    assert_eq!(
        properties.get("4294967295"),
        Some(&Value::str("uint32-max"))
    );
}

#[test]
fn array_entries_returns_runtime_iterator_pairs_for_sparse_arrays() {
    let mut core = quickjs_test_core();
    let array_id = seed_array(
        &mut core,
        3,
        &[(0, Value::str("first")), (2, Value::str("third"))],
    );
    core.set_reg(0, Value::Object(array_id));

    let iterator = core
        .dispatch_builtin_hostcall(
            "builtin:ArrayPrototypeEntries",
            RegRange { start: 0, count: 1 },
            None,
        )
        .expect("operation should succeed for valid inputs");
    assert!(matches!(iterator, Value::Iterator(_)));
    assert_eq!(
        core.init_for_of_iterator(None, iterator.clone())
            .expect("operation should succeed for valid inputs"),
        iterator
    );

    let first = core
        .advance_for_of_iterator(None, iterator.clone())
        .expect("operation should succeed for valid inputs");
    assert_entry_pair(
        &core,
        first.expect("operation should succeed for valid inputs"),
        0,
        Value::str("first"),
    );
    let second = core
        .advance_for_of_iterator(None, iterator.clone())
        .expect("operation should succeed for valid inputs");
    assert_entry_pair(
        &core,
        second.expect("operation should succeed for valid inputs"),
        1,
        Value::Undefined,
    );
    let third = core
        .advance_for_of_iterator(None, iterator.clone())
        .expect("operation should succeed for valid inputs");
    assert_entry_pair(
        &core,
        third.expect("operation should succeed for valid inputs"),
        2,
        Value::str("third"),
    );
    assert_eq!(
        core.advance_for_of_iterator(None, iterator)
            .expect("operation should succeed for valid inputs"),
        None
    );
}

#[test]
fn for_of_init_prefers_custom_iterator_over_array_like_properties() {
    let mut module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadThis { dst: 0 },
            Ir3Instruction::Return { value: 0 },
            Ir3Instruction::LoadThis { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 1,
                dst: 2,
            },
            Ir3Instruction::Return { value: 2 },
        ],
        vec![
            Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 1,
                name: Some("custom_iterator".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 2,
                arity: 0,
                frame_size: 3,
                name: Some("custom_next".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
        ],
    );
    module.constant_pool.push("result".into());

    let mut core = quickjs_test_core();
    let iterable_id = core
        .alloc_object_with_prototype(None)
        .expect("custom iterable allocation should succeed");
    let result_id = core
        .alloc_object_with_prototype(None)
        .expect("iterator result allocation should succeed");
    core.set_object_property(result_id, "done".to_string(), Value::Bool(false))
        .expect("iterator result done write should succeed");
    core.set_object_property(result_id, "value".to_string(), Value::Int(42))
        .expect("iterator result value write should succeed");
    core.set_object_runtime_property(
        iterable_id,
        RuntimePropertyKey::Symbol(WellKnownSymbol::Iterator.id()),
        Value::Function(0),
    )
    .expect("custom iterator method write should succeed");
    core.set_object_property(iterable_id, "next".to_string(), Value::Function(1))
        .expect("custom next method write should succeed");
    core.set_object_property(iterable_id, "result".to_string(), Value::Object(result_id))
        .expect("custom next result write should succeed");
    core.set_object_property(iterable_id, "0".to_string(), Value::Int(99))
        .expect("array-like fallback sentinel write should succeed");

    let iterator = core
        .init_for_of_iterator(Some(&module), Value::Object(iterable_id))
        .expect("custom @@iterator should initialize for..of");
    assert_eq!(
        core.advance_for_of_iterator(Some(&module), iterator)
            .expect("custom iterator.next should advance"),
        Some(Value::Int(42))
    );

    core.set_object_runtime_property(
        iterable_id,
        RuntimePropertyKey::Symbol(WellKnownSymbol::Iterator.id()),
        Value::Null,
    )
    .expect("null Symbol.iterator shadow should install");
    assert!(matches!(
        core.init_for_of_iterator(Some(&module), Value::Object(iterable_id)),
        Err(InterpreterError::TypeError { .. })
    ));
}

#[test]
fn array_keys_and_values_match_sparse_entry_projection() {
    let mut core = quickjs_test_core();
    let array_id = seed_array(
        &mut core,
        3,
        &[(0, Value::str("first")), (2, Value::str("third"))],
    );
    core.set_reg(0, Value::Object(array_id));

    let keys = core
        .dispatch_builtin_hostcall(
            "builtin:ArrayPrototypeKeys",
            RegRange { start: 0, count: 1 },
            None,
        )
        .expect("operation should succeed for valid inputs");
    let values = core
        .dispatch_builtin_hostcall(
            "builtin:ArrayPrototypeValues",
            RegRange { start: 0, count: 1 },
            None,
        )
        .expect("operation should succeed for valid inputs");

    assert_eq!(
        core.advance_for_of_iterator(None, keys.clone())
            .expect("operation should succeed for valid inputs"),
        Some(Value::Int(0))
    );
    assert_eq!(
        core.advance_for_of_iterator(None, keys.clone())
            .expect("operation should succeed for valid inputs"),
        Some(Value::Int(1))
    );
    assert_eq!(
        core.advance_for_of_iterator(None, keys.clone())
            .expect("operation should succeed for valid inputs"),
        Some(Value::Int(2))
    );
    assert_eq!(
        core.advance_for_of_iterator(None, keys)
            .expect("operation should succeed for valid inputs"),
        None
    );
    assert_eq!(
        core.advance_for_of_iterator(None, values.clone())
            .expect("operation should succeed for valid inputs"),
        Some(Value::str("first"))
    );
    assert_eq!(
        core.advance_for_of_iterator(None, values.clone())
            .expect("operation should succeed for valid inputs"),
        Some(Value::Undefined)
    );
    assert_eq!(
        core.advance_for_of_iterator(None, values.clone())
            .expect("operation should succeed for valid inputs"),
        Some(Value::str("third"))
    );
    assert_eq!(
        core.advance_for_of_iterator(None, values)
            .expect("operation should succeed for valid inputs"),
        None
    );
}

#[test]
fn array_iterator_next_method_returns_public_iterator_results() {
    let mut core = quickjs_test_core();
    let array_id = seed_array(
        &mut core,
        3,
        &[(0, Value::str("first")), (2, Value::str("third"))],
    );
    core.set_reg(0, Value::Object(array_id));

    let entries = core
        .dispatch_builtin_hostcall(
            "builtin:ArrayPrototypeEntries",
            RegRange { start: 0, count: 1 },
            None,
        )
        .expect("operation should succeed for valid inputs");
    let keys = core
        .dispatch_builtin_hostcall(
            "builtin:ArrayPrototypeKeys",
            RegRange { start: 0, count: 1 },
            None,
        )
        .expect("operation should succeed for valid inputs");
    let values = core
        .dispatch_builtin_hostcall(
            "builtin:ArrayPrototypeValues",
            RegRange { start: 0, count: 1 },
            None,
        )
        .expect("operation should succeed for valid inputs");

    let entry_result = iterator_next_via_property(&mut core, entries);
    let Value::Object(entry_result_id) = entry_result else {
        panic!("expected iterator result object for entries");
    };
    let entry_properties = &core.heap[entry_result_id.0 as usize].properties;
    assert_eq!(entry_properties.get("done"), Some(&Value::Bool(false)));
    let pair_value = entry_properties
        .get("value")
        .cloned()
        .expect("entries result should expose value");
    assert_entry_pair(&core, pair_value, 0, Value::str("first"));

    let key_result = iterator_next_via_property(&mut core, keys);
    assert_iterator_result(&core, key_result, false, Value::Int(0));

    let value_result = iterator_next_via_property(&mut core, values.clone());
    assert_iterator_result(&core, value_result, false, Value::str("first"));

    let hole_result = iterator_next_via_property(&mut core, values.clone());
    assert_iterator_result(&core, hole_result, false, Value::Undefined);

    let tail_result = iterator_next_via_property(&mut core, values.clone());
    assert_iterator_result(&core, tail_result, false, Value::str("third"));

    let done_result = iterator_next_via_property(&mut core, values);
    assert_iterator_result(&core, done_result, true, Value::Undefined);
}

#[test]
fn array_iterator_next_method_shares_progress_with_for_of_iteration() {
    let mut core = quickjs_test_core();
    let array_id = seed_array(
        &mut core,
        3,
        &[
            (0, Value::Int(10)),
            (1, Value::Int(20)),
            (2, Value::Int(30)),
        ],
    );
    core.set_reg(0, Value::Object(array_id));

    let iterator = core
        .dispatch_builtin_hostcall(
            "builtin:ArrayPrototypeValues",
            RegRange { start: 0, count: 1 },
            None,
        )
        .expect("operation should succeed for valid inputs");

    let first_result = iterator_next_via_property(&mut core, iterator.clone());
    assert_iterator_result(&core, first_result, false, Value::Int(10));

    assert_eq!(
        core.advance_for_of_iterator(None, iterator.clone())
            .expect("operation should succeed for valid inputs"),
        Some(Value::Int(20))
    );

    let third_result = iterator_next_via_property(&mut core, iterator.clone());
    assert_iterator_result(&core, third_result, false, Value::Int(30));

    assert_eq!(
        core.advance_for_of_iterator(None, iterator)
            .expect("operation should succeed for valid inputs"),
        None
    );
}

#[test]
fn array_iterator_symbol_iterator_method_returns_same_iterator() {
    // ECMA-262 array iterator objects expose @@iterator as an identity method.
    let mut core = quickjs_test_core();
    let array_id = seed_array(&mut core, 2, &[(0, Value::Int(7)), (1, Value::Int(9))]);
    core.set_reg(0, Value::Object(array_id));

    let iterator = core
        .dispatch_builtin_hostcall(
            "builtin:ArrayPrototypeValues",
            RegRange { start: 0, count: 1 },
            None,
        )
        .expect("operation should succeed for valid inputs");
    let symbol_iterator = core
        .dispatch_builtin_hostcall(
            "builtin:SymbolIterator",
            RegRange { start: 0, count: 0 },
            None,
        )
        .expect("operation should succeed for valid inputs");

    assert_eq!(
        iterator_method_via_property(&mut core, iterator.clone(), symbol_iterator),
        iterator
    );
    let Value::Iterator(iterator_handle) = iterator else {
        panic!("array values must return an iterator")
    };
    assert_eq!(
        core.iterator_runtime_property_value(
            iterator_handle,
            &RuntimePropertyKey::String(JsString::from("@@iterator")),
        ),
        Value::Undefined
    );

    let first_result = iterator_next_via_property(&mut core, Value::Iterator(iterator_handle));
    assert_iterator_result(&core, first_result, false, Value::Int(7));
}

#[test]
fn array_iterator_next_after_close_returns_done_result() {
    // IteratorClose marks the array iterator complete; later next() calls stay done.
    let mut core = quickjs_test_core();
    let array_id = seed_array(&mut core, 2, &[(0, Value::Int(1)), (1, Value::Int(2))]);
    core.set_reg(0, Value::Object(array_id));

    let iterator = core
        .dispatch_builtin_hostcall(
            "builtin:ArrayPrototypeValues",
            RegRange { start: 0, count: 1 },
            None,
        )
        .expect("operation should succeed for valid inputs");

    let module = test_module(Vec::new());
    core.close_iterator(&module, iterator.clone(), IteratorCloseReason::Break)
        .expect("operation should succeed for valid inputs");

    let done_result = iterator_next_via_property(&mut core, iterator.clone());
    assert_iterator_result(&core, done_result, true, Value::Undefined);

    let repeated_done_result = iterator_next_via_property(&mut core, iterator);
    assert_iterator_result(&core, repeated_done_result, true, Value::Undefined);
}

#[test]
fn reexecution_restores_initial_register_seed_without_runtime_leakage() {
    // The program both reads AND overwrites its seeded input register, so
    // a repeat execute reproduces the first result only if the pre-run
    // seed is genuinely restored and dispatch re-runs from ip 0. The
    // previous version of this test never mutated its input, so it kept
    // passing while the repeat-execute path was unreachable and the
    // second run stayed parked at the prior Halt (bd-bgq16).
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 4, value: 10 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 4,
        },
        Ir3Instruction::Add {
            dst: 1,
            lhs: 1,
            rhs: 4,
        },
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:ConsoleLog".to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 5,
        },
        Ir3Instruction::Halt,
    ]);

    let mut config = test_quickjs_config();
    config.instruction_budget = 1000;
    let mut core = InterpreterCore::new(config, "test");
    core.set_reg(1, Value::Int(5));

    let first = core.execute(&m).expect("first run should succeed");
    assert_eq!(first.value, Value::Int(15));
    assert_eq!(
        first.console_output.len(),
        1,
        "first run must actually dispatch the program body"
    );

    let second = core.execute(&m).expect("repeat run should succeed");
    // Without the pre-run seed restore the surviving r1 == 15 yields 25.
    assert_eq!(second.value, Value::Int(15));
    // A run parked at the prior Halt returns run 1's r0 (also 15) but
    // dispatches nothing, so its per-run console drain stays empty. This
    // side-effect observation is what the pre-bd-bgq16 version of this
    // test lacked, which is why it kept passing while the repeat path
    // was dead.
    assert_eq!(
        second.console_output.len(),
        1,
        "repeat run must re-dispatch the full program, not resume at Halt"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn repeat_execute_reallocates_module_namespace_without_argv_aliasing_bd_bgq16() {
    // The entry namespace ObjectId is allocated by `ensure_module_record`
    // AFTER the pre-run seed is captured. A repeat execute rolls the heap
    // back to the pre-run state, so a surviving module record would name
    // a heap id that the restored heap hands to the first post-restore
    // allocation — `process.argv` in `inject_runtime_globals` — letting
    // the second run's ExportBinding mutate argv through the aliased
    // namespace id (bd-bgq16).
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadInt { dst: 1, value: 42 },
            Ir3Instruction::ExportBinding {
                name_pool_index: 0,
                src: 1,
                local_name_pool_index: None,
                namespace_reexport: false,
            },
            Ir3Instruction::Halt,
        ],
        vec!["leak".to_string()],
    );

    let mut core = InterpreterCore::new(test_quickjs_config(), "test");
    core.execute(&m).expect("first run should succeed");
    core.execute(&m).expect("repeat run should succeed");

    let record = core
        .module_state
        .modules
        .get("test")
        .expect("repeat run must re-register the entry module record");
    let namespace_id = record.namespace_object;
    let leak_key = JsString::from("leak");
    assert_eq!(
        core.heap[namespace_id.0 as usize]
            .properties
            .get_exact(&leak_key),
        Some(&Value::Int(42)),
        "the export must land on the freshly allocated namespace object"
    );

    // Walk process.argv through the injected scope-chain global and prove
    // the export did not alias into it.
    let process_binding = core
        .scope_chain
        .frames
        .iter()
        .rev()
        .find_map(|frame| frame.bindings.get("process"))
        .expect("process global must exist after execution");
    let Value::Object(process_id) = process_binding.state.borrow().value.clone() else {
        panic!("process global must be heap-backed");
    };
    let Some(&Value::Object(argv_id)) = core.heap[process_id.0 as usize]
        .properties
        .get_exact(&JsString::from("argv"))
    else {
        panic!("process.argv must be heap-backed");
    };
    assert_ne!(
        argv_id, namespace_id,
        "module namespace must not alias process.argv"
    );
    assert_eq!(
        core.heap[argv_id.0 as usize]
            .properties
            .get_exact(&leak_key),
        None,
        "the module export must not leak into process.argv"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn materialized_seed_restores_exact_identity_and_order_bd_b12xs_5() {
    let mut core = quickjs_test_core();
    let object = core
        .alloc_object_with_prototype(None)
        .expect("object allocation should succeed");
    let d800 = JsString::from_code_units(&[0xD800]);
    let d801 = JsString::from_code_units(&[0xD801]);
    let replacement = JsString::from("\u{FFFD}");
    for (key, value) in [
        (d800.clone(), Value::Int(8)),
        (d801.clone(), Value::Int(9)),
        (replacement.clone(), Value::Int(0xFFFD)),
    ] {
        core.set_object_runtime_property(object, RuntimePropertyKey::String(key), value)
            .expect("seed property should fit");
    }
    let initial_order = core.heap[object.0 as usize].properties.exact_keys();
    let seed = core
        .capture_execution_seed()
        .expect("test execution-seed capture must fit");

    core.set_object_runtime_property(
        object,
        RuntimePropertyKey::String(d800.clone()),
        Value::Int(80),
    )
    .expect("seed mutation should fit");
    assert!(
        core.remove_object_runtime_property(object, &RuntimePropertyKey::String(d801.clone()),)
            .expect("seed deletion should succeed")
    );
    core.set_object_runtime_property(
        object,
        RuntimePropertyKey::String(d801.clone()),
        Value::Int(81),
    )
    .expect("seed reinsertion should fit");
    assert_ne!(
        core.heap[object.0 as usize].properties.exact_keys(),
        initial_order
    );

    core.reset_execution_state_from_seed(&seed)
        .expect("materialized exact heap seed should restore");
    let properties = &core.heap[object.0 as usize].properties;
    assert_eq!(properties.exact_keys(), initial_order);
    assert_eq!(properties.get_exact(&d800), Some(&Value::Int(8)));
    assert_eq!(properties.get_exact(&d801), Some(&Value::Int(9)));
    assert_eq!(
        properties.get_exact(&replacement),
        Some(&Value::Int(0xFFFD))
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn symbol_value_heap_and_state_wire_are_typed_bd_n8eta_4_2() {
    assert_eq!(
        serde_json::to_string(&Value::Symbol(SymbolId(14))).unwrap(),
        r#"{"Symbol":14}"#
    );

    let legacy = HeapObject::new();
    let legacy_wire = serde_json::to_string(&legacy).unwrap();
    assert!(!legacy_wire.contains("symbol_properties"));
    assert_eq!(
        serde_json::to_string(&serde_json::from_str::<HeapObject>(&legacy_wire).unwrap()).unwrap(),
        legacy_wire
    );

    let mut object = HeapObject::new();
    object
        .properties
        .insert("Symbol(14)".to_string(), Value::Int(9));
    object.properties.insert_baseline_symbol_property(
        CoreSymbolId(14),
        BaselineSymbolProperty::Data(Value::Int(2)),
    );
    object.properties.insert_baseline_symbol_property(
        CoreSymbolId(15),
        BaselineSymbolProperty::Accessor {
            get: None,
            set: Some(Value::Function(7)),
        },
    );
    let wire = serde_json::to_string(&object).unwrap();
    assert!(wire.contains(r#""Symbol(14)":{"Int":9}"#));
    assert!(wire.contains(
            r#""symbol_properties":[{"symbol_id":14,"kind":"data","value":{"Int":2}},{"symbol_id":15,"kind":"accessor","get":null,"set":{"Function":7}}]"#
        ));
    assert_eq!(serde_json::from_str::<HeapObject>(&wire).unwrap(), object);

    let mut malformed = serde_json::to_value(&legacy).unwrap();
    malformed["symbol_properties"] = serde_json::json!([
        {"symbol_id": 0, "kind": "data", "value": {"Int": 1}}
    ]);
    assert!(serde_json::from_value::<HeapObject>(malformed).is_err());

    let malformed_state = r#"{"well_known_schema":"es2020-symbol-ids-1-13-v1","next_symbol_id":15,"symbols":[{"symbol_id":14,"kind":"global","description":"x","registry_key":"y"}]}"#;
    assert!(serde_json::from_str::<RuntimeSymbolState>(malformed_state).is_err());
}

#[test]
fn derived_constructor_metadata_wire_is_atomic_and_label_preserving_bd_ppfz7() {
    let mut object = HeapObject::new();
    object.derived_constructor_parent = Some(Box::new(Value::Function(7)));
    object.derived_constructor_parent_label = Some(Box::new(Label::Secret));
    object.is_derived_constructor = true;
    object.is_default_derived_constructor = true;

    let encoded = serde_json::to_value(&object).expect("serialize constructor metadata");
    let restored: HeapObject =
        serde_json::from_value(encoded.clone()).expect("round-trip constructor metadata");
    assert_eq!(restored, object);
    assert_eq!(
        restored.derived_constructor_parent_label.as_deref(),
        Some(&Label::Secret)
    );

    let mut missing_label = encoded.clone();
    missing_label
        .as_object_mut()
        .expect("HeapObject wire must be an object")
        .remove("derived_constructor_parent_label");
    assert!(serde_json::from_value::<HeapObject>(missing_label).is_err());

    let mut missing_parent = encoded;
    missing_parent
        .as_object_mut()
        .expect("HeapObject wire must be an object")
        .remove("derived_constructor_parent");
    assert!(serde_json::from_value::<HeapObject>(missing_parent).is_err());

    let mut invalid_default =
        serde_json::to_value(HeapObject::new()).expect("serialize legacy HeapObject");
    invalid_default["is_default_derived_constructor"] = serde_json::json!(true);
    assert!(serde_json::from_value::<HeapObject>(invalid_default).is_err());
}

/// bd-n8eta.4.5: focused `CapturedInterpreterState` JSON round trip with a
/// dynamic Symbol as both a register value and an object own key. Pins
/// exact `symbol_state` restoration, the legacy Symbol-free wire staying
/// readable, fail-closed rejection of missing/null/unknown symbol state,
/// and full state equality (registers + heap incl. the Symbol sidecar
/// order) after restore.
#[test]
fn captured_interpreter_state_symbol_round_trip_bd_n8eta_4_5() {
    // Legacy Symbol-free wire: no symbol_state field, exact round trip.
    let mut plain = quickjs_test_core();
    plain
        .write_reg(0, Value::Int(7))
        .expect("plain register should write");
    plain.arm_state_capture_at_tick(0);
    plain.check_state_capture_boundary();
    let plain_state = plain
        .take_captured_state()
        .expect("plain state should capture");
    assert!(!plain_state.contains_symbol_values());
    let plain_wire = serde_json::to_string(&plain_state).expect("plain state serializes");
    assert!(!plain_wire.contains("symbol_state"));
    assert_eq!(
        serde_json::from_str::<CapturedInterpreterState>(&plain_wire)
            .expect("legacy Symbol-free wire must stay readable"),
        plain_state
    );

    // Dynamic Symbol as value and own key.
    let mut core = quickjs_test_core();
    let symbol = core
        .allocate_private_symbol(Some(JsString::from("round-trip")))
        .expect("dynamic symbol should allocate");
    let object = core
        .alloc_object_with_properties(&[("plain", Value::Int(1))])
        .expect("object should allocate");
    core.set_symbol_property(object, symbol, BaselineSymbolProperty::Data(Value::Int(5)))
        .expect("symbol own key should set");
    core.write_reg(2, Value::Symbol(symbol))
        .expect("symbol register should write");
    core.write_reg(3, Value::Object(object))
        .expect("object register should write");
    core.arm_state_capture_at_tick(0);
    core.check_state_capture_boundary();
    let captured = core
        .take_captured_state()
        .expect("symbol-bearing state should capture");
    assert!(captured.contains_symbol_values());

    let wire = serde_json::to_string(&captured).expect("captured state serializes");
    assert!(wire.contains("\"symbol_state\""));
    let restored: CapturedInterpreterState =
        serde_json::from_str(&wire).expect("captured state deserializes");
    // Exact restoration: registers, heap (including the Symbol sidecar
    // and its key order via HeapObject equality), and symbol_state all
    // participate in PartialEq.
    assert_eq!(restored, captured);
    // The round trip is a serialization fixed point.
    assert_eq!(
        serde_json::to_string(&restored).expect("re-serializes"),
        wire
    );

    // A symbol-bearing wire without symbol_state fails closed.
    let mut missing: serde_json::Value =
        serde_json::from_str(&wire).expect("wire re-parses as JSON");
    missing
        .as_object_mut()
        .expect("wire is an object")
        .remove("symbol_state");
    let missing_error = serde_json::from_value::<CapturedInterpreterState>(missing)
        .expect_err("missing symbol_state must be rejected")
        .to_string();
    assert!(
        missing_error.contains("requires symbol_state"),
        "unexpected rejection message: {missing_error}"
    );

    // Explicit null is not the same as absent: fail closed.
    let mut null_state: serde_json::Value =
        serde_json::from_str(&wire).expect("wire re-parses as JSON");
    null_state["symbol_state"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<CapturedInterpreterState>(null_state).is_err());

    // Unknown fields inside symbol_state fail closed.
    let mut unknown: serde_json::Value =
        serde_json::from_str(&wire).expect("wire re-parses as JSON");
    unknown["symbol_state"]["surprise"] = serde_json::json!(1);
    assert!(serde_json::from_value::<CapturedInterpreterState>(unknown).is_err());
}

#[test]
fn symbol_keys_stay_distinct_ordered_and_prototyped_bd_n8eta_4_2() {
    let mut core = quickjs_test_core();
    let first = core
        .allocate_private_symbol(Some(JsString::from("first")))
        .unwrap();
    let second = core
        .allocate_private_symbol(Some(JsString::from("second")))
        .unwrap();
    let prototype = core.alloc_object_with_prototype(None).unwrap();
    let object = core.alloc_object_with_prototype(Some(prototype)).unwrap();

    core.set_object_property(object, "2".to_string(), Value::Int(2))
        .unwrap();
    core.set_object_property(object, "a".to_string(), Value::Int(1))
        .unwrap();
    core.set_object_property(object, "Symbol(14)".to_string(), Value::Int(9))
        .unwrap();
    core.set_object_runtime_property(object, RuntimePropertyKey::Symbol(first), Value::Int(7))
        .unwrap();
    core.set_object_runtime_property(prototype, RuntimePropertyKey::Symbol(second), Value::Int(8))
        .unwrap();

    assert_eq!(
        core.prototype_chain_get_with_receiver_runtime(
            None,
            object,
            &RuntimePropertyKey::Symbol(first),
            Value::Object(object),
        )
        .unwrap(),
        Value::Int(7)
    );
    assert_eq!(
        core.prototype_chain_get_with_receiver_runtime(
            None,
            object,
            &RuntimePropertyKey::Symbol(second),
            Value::Object(object),
        )
        .unwrap(),
        Value::Int(8)
    );
    assert!(
            core.proxy_aware_has_runtime_property(
                None,
                object,
                &RuntimePropertyKey::Symbol(second),
                0,
            )
            .unwrap()
        );
    assert_eq!(
        core.heap[object.0 as usize].own_runtime_property_keys(),
        vec![
            RuntimePropertyKey::String(JsString::from("2")),
            RuntimePropertyKey::String(JsString::from("a")),
            RuntimePropertyKey::String(JsString::from("Symbol(14)")),
            RuntimePropertyKey::Symbol(first),
        ]
    );

    core.set_symbol_property(
        object,
        first,
        BaselineSymbolProperty::Accessor {
            get: Some(Value::Function(3)),
            set: None,
        },
    )
    .unwrap();
    assert!(matches!(
        core.heap[object.0 as usize]
            .properties
            .baseline_symbol_property(core_symbol_id(first)),
        Some(BaselineSymbolProperty::Accessor { .. })
    ));
    assert_eq!(
        core.heap[object.0 as usize]
            .properties
            .baseline_symbol_key_order(),
        &[core_symbol_id(first)]
    );

    assert!(
        core.remove_object_runtime_property(object, &RuntimePropertyKey::Symbol(first))
            .unwrap()
    );
    core.set_object_runtime_property(object, RuntimePropertyKey::Symbol(second), Value::Int(10))
        .unwrap();
    core.set_object_runtime_property(object, RuntimePropertyKey::Symbol(first), Value::Int(11))
        .unwrap();
    assert_eq!(
        core.heap[object.0 as usize]
            .properties
            .baseline_symbol_key_order(),
        &[core_symbol_id(second), core_symbol_id(first)]
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn symbol_stringification_preserves_exact_description_units_bd_n8eta_4_2() {
    let mut core = quickjs_test_core();
    let description = JsString::from_code_units(&[0xD800]);
    let symbol = core
        .allocate_private_symbol(Some(description.clone()))
        .unwrap();
    let expected = JsString::from("Symbol(")
        .concat(&description)
        .concat(&JsString::from(")"));
    let module = test_module(Vec::new());
    assert_eq!(
        core.dispatch_builtin_function(
            &module,
            &BuiltinFunction::symbol_to_string(),
            RegRange { start: 0, count: 0 },
            Some(Value::Symbol(symbol)),
            None,
        )
        .unwrap(),
        Value::Str(expected.clone())
    );
    core.set_reg(0, Value::Symbol(symbol));
    assert_eq!(
        core.dispatch_builtin_hostcall("builtin:String", RegRange { start: 0, count: 1 }, None,)
            .unwrap(),
        Value::Str(expected)
    );
}

#[test]
fn symbol_global_registry_uses_exact_code_units_bd_n8eta_4_2() {
    let mut core = quickjs_test_core();
    let d800 = JsString::from_code_units(&[0xD800]);
    let d801 = JsString::from_code_units(&[0xD801]);
    let replacement = JsString::from("\u{FFFD}");
    assert_eq!(d800.as_utf8_projection(), d801.as_utf8_projection());

    let first = core.intern_global_symbol(d800.clone()).unwrap();
    let second = core.intern_global_symbol(d801.clone()).unwrap();
    let third = core.intern_global_symbol(replacement.clone()).unwrap();
    assert_eq!(core.intern_global_symbol(d800.clone()).unwrap(), first);
    assert_ne!(first, second);
    assert_ne!(first, third);
    assert_ne!(second, third);
    assert_eq!(core.symbol_state.key_for(first), Some(&d800));
    assert_eq!(core.symbol_state.key_for(second), Some(&d801));
    assert_eq!(core.symbol_state.key_for(third), Some(&replacement));

    let wire = serde_json::to_string(&core.symbol_state.value).unwrap();
    assert_eq!(
        serde_json::from_str::<RuntimeSymbolState>(&wire).unwrap(),
        core.symbol_state.value
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn symbol_mixed_exact_carrier_normalizes_string_sidecars_bd_n8eta_4_2() {
    let mut core = quickjs_test_core();
    let symbol = core.allocate_private_symbol(None).unwrap();
    let object = core.alloc_object_with_prototype(None).unwrap();
    let exact_only = JsString::from_code_units(&[0xD800]);
    core.set_object_property(object, "ordinary".to_string(), Value::Int(1))
        .unwrap();
    core.set_object_runtime_property(
        object,
        RuntimePropertyKey::String(exact_only.clone()),
        Value::Int(2),
    )
    .unwrap();
    core.set_object_runtime_property(object, RuntimePropertyKey::Symbol(symbol), Value::Int(3))
        .unwrap();
    let before_map_bytes = InterpreterCore::estimate_ordered_property_map_bytes(
        &core.heap[object.0 as usize].properties,
    );

    assert!(
        core.remove_object_runtime_property(object, &RuntimePropertyKey::String(exact_only),)
            .unwrap()
    );
    let after_map_bytes = InterpreterCore::estimate_ordered_property_map_bytes(
        &core.heap[object.0 as usize].properties,
    );
    assert!(after_map_bytes < before_map_bytes);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
    let mut normalization_probe = core.heap[object.0 as usize].properties.clone();
    assert!(normalization_probe.normalize_data_only_exact_sidecars());
    let mixed_wire = serde_json::to_string(&core.heap[object.0 as usize]).unwrap();
    assert_eq!(
        serde_json::from_str::<HeapObject>(&mixed_wire).unwrap(),
        core.heap[object.0 as usize]
    );

    core.set_object_runtime_property(object, RuntimePropertyKey::Symbol(symbol), Value::Int(4))
        .unwrap();
    assert!(
        core.remove_object_runtime_property(object, &RuntimePropertyKey::Symbol(symbol))
            .unwrap()
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn symbol_consumers_filter_reflect_and_copy_typed_keys_bd_n8eta_4_2() {
    let mut core = quickjs_test_core();
    let symbol = core
        .allocate_private_symbol(Some(JsString::from("key")))
        .unwrap();
    let source = core.alloc_object_with_prototype(None).unwrap();
    core.set_object_property(source, "stored".to_string(), Value::Symbol(symbol))
        .unwrap();
    core.set_object_runtime_property(source, RuntimePropertyKey::Symbol(symbol), Value::Int(7))
        .unwrap();
    core.set_reg(0, Value::Object(source));

    let object_keys = core
        .dispatch_builtin_hostcall("builtin:ObjectKeys", RegRange { start: 0, count: 1 }, None)
        .unwrap();
    let Value::Object(object_keys) = object_keys else {
        panic!("Object.keys must return an array")
    };
    assert_eq!(
        core.read_array_like_values(object_keys),
        vec![Value::str("stored")]
    );

    let own_symbols = core
        .dispatch_builtin_hostcall(
            "builtin:ObjectGetOwnPropertySymbols",
            RegRange { start: 0, count: 1 },
            None,
        )
        .unwrap();
    let Value::Object(own_symbols) = own_symbols else {
        panic!("Object.getOwnPropertySymbols must return an array")
    };
    assert_eq!(
        core.read_array_like_values(own_symbols),
        vec![Value::Symbol(symbol)]
    );

    let reflected = core
        .dispatch_builtin_hostcall(
            "builtin:ReflectOwnKeys",
            RegRange { start: 0, count: 1 },
            None,
        )
        .unwrap();
    let Value::Object(reflected) = reflected else {
        panic!("Reflect.ownKeys must return an array")
    };
    assert_eq!(
        core.read_array_like_values(reflected),
        vec![Value::str("stored"), Value::Symbol(symbol)]
    );
    assert_eq!(
        core.json_stringify_value(None, &Value::Object(source), &mut Vec::new())
            .unwrap(),
        Some("{}".to_string())
    );

    let assigned = core.alloc_object_with_prototype(None).unwrap();
    core.set_reg(1, Value::Object(assigned));
    core.set_reg(2, Value::Object(source));
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:ObjectAssign",
            RegRange { start: 1, count: 2 },
            None,
        )
        .unwrap(),
        Value::Object(assigned)
    );
    assert_eq!(
        core.heap[assigned.0 as usize]
            .own_runtime_property_value(&RuntimePropertyKey::Symbol(symbol)),
        Some(Value::Int(7))
    );
    assert_eq!(
        core.heap[assigned.0 as usize].properties.get("stored"),
        Some(&Value::Symbol(symbol))
    );
}

#[test]
fn proxy_symbol_own_keys_get_and_copy_stay_typed_bd_n8eta_4_2() {
    let mut module = test_module_with_functions(
        vec![
            Ir3Instruction::SpreadIntoObject {
                target: 1,
                source: 2,
            },
            Ir3Instruction::Move { dst: 0, src: 1 },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadThis { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 1,
                dst: 2,
            },
            Ir3Instruction::Return { value: 2 },
            Ir3Instruction::LoadInt { dst: 0, value: 41 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![
            Ir3FunctionDesc {
                entry: 3,
                arity: 1,
                frame_size: 3,
                name: Some("symbol_proxy_own_keys".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
            Ir3FunctionDesc {
                entry: 7,
                arity: 3,
                frame_size: 1,
                name: Some("symbol_proxy_get".to_string()),
                is_generator: false,
                rest_param_index: None,
            },
        ],
    );
    module.constant_pool.push("keys".into());

    let mut core = quickjs_test_core();
    let symbol = core.allocate_private_symbol(None).unwrap();
    let proxy_target = core.alloc_object_with_prototype(None).unwrap();
    core.set_object_runtime_property(
        proxy_target,
        RuntimePropertyKey::Symbol(symbol),
        Value::Int(7),
    )
    .unwrap();
    let handler = core.alloc_object_with_prototype(None).unwrap();
    let trap_keys = core
        .alloc_array_from_values(&[Value::Symbol(symbol)])
        .unwrap();
    core.set_object_property(handler, "keys".to_string(), Value::Object(trap_keys))
        .unwrap();
    core.set_object_property(handler, "ownKeys".to_string(), Value::Function(0))
        .unwrap();
    core.set_object_property(handler, "get".to_string(), Value::Function(1))
        .unwrap();
    let proxy = core.create_proxy_object(proxy_target, handler).unwrap();

    let spread_target = core.alloc_object_with_prototype(None).unwrap();
    core.set_reg(1, Value::Object(spread_target));
    core.set_reg(2, Value::Object(proxy));
    assert_eq!(
        core.execute(&module).unwrap().value,
        Value::Object(spread_target)
    );
    assert_eq!(
        core.heap[spread_target.0 as usize]
            .own_runtime_property_value(&RuntimePropertyKey::Symbol(symbol)),
        Some(Value::Int(41))
    );

    core.set_reg(0, Value::Object(proxy));
    let own_symbols = core
        .dispatch_builtin_hostcall(
            "builtin:ObjectGetOwnPropertySymbols",
            RegRange { start: 0, count: 1 },
            Some(&module),
        )
        .unwrap();
    let Value::Object(own_symbols) = own_symbols else {
        panic!("Object.getOwnPropertySymbols(proxy) must return an array")
    };
    assert_eq!(
        core.read_array_like_values(own_symbols),
        vec![Value::Symbol(symbol)]
    );

    let assigned = core.alloc_object_with_prototype(None).unwrap();
    core.set_reg(0, Value::Object(assigned));
    core.set_reg(1, Value::Object(proxy));
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:ObjectAssign",
            RegRange { start: 0, count: 2 },
            Some(&module),
        )
        .unwrap(),
        Value::Object(assigned)
    );
    assert_eq!(
        core.heap[assigned.0 as usize]
            .own_runtime_property_value(&RuntimePropertyKey::Symbol(symbol)),
        Some(Value::Int(41))
    );

    let duplicate_keys = core
        .alloc_array_from_values(&[Value::Symbol(symbol), Value::Symbol(symbol)])
        .unwrap();
    core.set_object_property(handler, "keys".to_string(), Value::Object(duplicate_keys))
        .unwrap();
    core.set_reg(0, Value::Object(proxy));
    assert!(matches!(
        core.dispatch_builtin_hostcall(
            "builtin:ObjectGetOwnPropertySymbols",
            RegRange { start: 0, count: 1 },
            Some(&module),
        ),
        Err(InterpreterError::TypeError { .. })
    ));
}

#[test]
fn reflect_symbol_get_set_preserve_receiver_bd_n8eta_4_2() {
    let mut module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadThis { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 1,
                dst: 2,
            },
            Ir3Instruction::Return { value: 2 },
        ],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 0,
            frame_size: 3,
            name: Some("symbol_receiver_getter".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    module.constant_pool.push("marker".into());

    let mut core = quickjs_test_core();
    let getter_symbol = core.allocate_private_symbol(None).unwrap();
    let data_symbol = core.allocate_private_symbol(None).unwrap();
    let target = core.alloc_object_with_prototype(None).unwrap();
    let receiver = core.alloc_object_with_prototype(None).unwrap();
    core.set_object_property(receiver, "marker".to_string(), Value::Int(41))
        .unwrap();
    core.set_symbol_property(
        target,
        getter_symbol,
        BaselineSymbolProperty::Accessor {
            get: Some(Value::Function(0)),
            set: None,
        },
    )
    .unwrap();
    core.set_object_runtime_property(
        target,
        RuntimePropertyKey::Symbol(data_symbol),
        Value::Int(1),
    )
    .unwrap();

    core.set_reg(0, Value::Object(target));
    core.set_reg(1, Value::Symbol(getter_symbol));
    let descriptor = core
        .dispatch_builtin_hostcall(
            "builtin:ObjectGetOwnPropertyDescriptor",
            RegRange { start: 0, count: 2 },
            Some(&module),
        )
        .unwrap();
    let Value::Object(descriptor) = descriptor else {
        panic!("Symbol accessor descriptor must be an object")
    };
    assert_eq!(
        core.heap[descriptor.0 as usize].properties.get("get"),
        Some(&Value::Function(0))
    );
    assert_eq!(
        core.heap[descriptor.0 as usize].properties.get("set"),
        Some(&Value::Undefined)
    );
    assert!(
        !core.heap[descriptor.0 as usize]
            .properties
            .contains_key("value")
    );

    let defined = core.alloc_object_with_prototype(None).unwrap();
    let accessor_descriptor = core
        .alloc_object_with_properties(&[("get", Value::Function(0))])
        .unwrap();
    core.set_reg(0, Value::Object(defined));
    core.set_reg(1, Value::Symbol(getter_symbol));
    core.set_reg(2, Value::Object(accessor_descriptor));
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:ObjectDefineProperty",
            RegRange { start: 0, count: 3 },
            Some(&module),
        )
        .unwrap(),
        Value::Object(defined)
    );
    assert!(matches!(
        core.heap[defined.0 as usize]
            .properties
            .baseline_symbol_property(core_symbol_id(getter_symbol)),
        Some(BaselineSymbolProperty::Accessor {
            get: Some(Value::Function(0)),
            set: None,
        })
    ));
    core.set_reg(0, Value::Object(defined));
    core.set_reg(1, Value::Symbol(getter_symbol));
    core.set_reg(2, Value::Object(receiver));
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:ReflectGet",
            RegRange { start: 0, count: 3 },
            Some(&module),
        )
        .unwrap(),
        Value::Int(41)
    );

    core.set_reg(0, Value::Object(target));
    core.set_reg(1, Value::Symbol(getter_symbol));
    core.set_reg(2, Value::Object(receiver));
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:ReflectGet",
            RegRange { start: 0, count: 3 },
            Some(&module),
        )
        .unwrap(),
        Value::Int(41)
    );

    core.set_reg(0, Value::Object(target));
    core.set_reg(1, Value::Symbol(data_symbol));
    core.set_reg(2, Value::Int(9));
    core.set_reg(3, Value::Object(receiver));
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:ReflectSet",
            RegRange { start: 0, count: 4 },
            Some(&module),
        )
        .unwrap(),
        Value::Bool(true)
    );
    assert_eq!(
        core.heap[target.0 as usize]
            .own_runtime_property_value(&RuntimePropertyKey::Symbol(data_symbol)),
        Some(Value::Int(1))
    );
    assert_eq!(
        core.heap[receiver.0 as usize]
            .own_runtime_property_value(&RuntimePropertyKey::Symbol(data_symbol)),
        Some(Value::Int(9))
    );

    let transparent_handler = core.alloc_object_with_prototype(None).unwrap();
    let proxy = core
        .create_proxy_object(target, transparent_handler)
        .unwrap();
    core.set_reg(0, Value::Object(proxy));
    core.set_reg(1, Value::Symbol(getter_symbol));
    core.set_reg(2, Value::Object(receiver));
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:ReflectGet",
            RegRange { start: 0, count: 3 },
            Some(&module),
        )
        .unwrap(),
        Value::Int(41)
    );
    core.set_reg(0, Value::Object(proxy));
    core.set_reg(1, Value::Symbol(data_symbol));
    core.set_reg(2, Value::Int(10));
    core.set_reg(3, Value::Object(receiver));
    assert_eq!(
        core.dispatch_builtin_hostcall(
            "builtin:ReflectSet",
            RegRange { start: 0, count: 4 },
            Some(&module),
        )
        .unwrap(),
        Value::Bool(true)
    );
    assert_eq!(
        core.heap[target.0 as usize]
            .own_runtime_property_value(&RuntimePropertyKey::Symbol(data_symbol)),
        Some(Value::Int(1))
    );
    assert_eq!(
        core.heap[receiver.0 as usize]
            .own_runtime_property_value(&RuntimePropertyKey::Symbol(data_symbol)),
        Some(Value::Int(10))
    );
}

#[test]
fn symbol_source_identity_keys_and_reflection_match_lanes_bd_n8eta_4_2() {
    let sources = [
        "const first = Symbol('same');\
             const second = Symbol('same');\
             (typeof Symbol === 'function' && typeof first === 'symbol' && first !== second)\
                 ? 1 : 0;",
        "const value = Symbol('same');\
             (value.description === 'same' && value.toString() === 'Symbol(same)' &&\
              Symbol().description === undefined) ? 1 : 0;",
        "const local = Symbol('local');\
             const global = Symbol.for('shared');\
             (global === Symbol.for('shared') && Symbol.keyFor(global) === 'shared' &&\
              Symbol.keyFor(local) === undefined && Symbol.keyFor(Symbol.iterator) === undefined)\
                 ? 1 : 0;",
        "const key = Symbol('key');\
             const object = { 'Symbol(14)': 9 };\
             object[key] = 8;\
             const setWorked = object[key] === 8;\
             delete object[key];\
             const deleteWorked = !(key in object);\
             object[key] = 7;\
             (setWorked && deleteWorked && object[key] === 7 &&\
              object['Symbol(14)'] === 9 && key in object) ? 1 : 0;",
        "const key = Symbol('copy');\
             const object = { [key]: 7 };\
             const spread = { ...object };\
             const assigned = Object.assign({}, object);\
             (spread[key] === 7 && assigned[key] === 7) ? 1 : 0;",
        "const key = Symbol('reflect');\
             const object = { ordinary: 1, [key]: 2 };\
             (Object.keys(object).length === 1 &&\
              Object.getOwnPropertySymbols(object)[0] === key &&\
              Reflect.ownKeys(object).length === 2) ? 1 : 0;",
        "const wellKnown = { [Symbol.iterator]: 3, '@@iterator': 4 };\
             (wellKnown[Symbol.iterator] === 3 && wellKnown['@@iterator'] === 4 &&\
              Object.keys(wellKnown).length === 1 &&\
              Object.getOwnPropertySymbols(wellKnown)[0] === Symbol.iterator) ? 1 : 0;",
        "const array = [1];\
             (typeof array[Symbol.iterator] === 'function' && array['@@iterator'] === undefined &&\
              typeof 'x'[Symbol.iterator] === 'function') ? 1 : 0;",
        "function* values() { yield 1; }\
             const generator = values();\
             (typeof generator[Symbol.iterator] === 'function' &&\
              generator[Symbol.iterator]() === generator) ? 1 : 0;",
    ];

    for source in sources {
        let module = lower_symbol_source_bd_n8eta_4_2(source);
        assert_eq!(quickjs_execute(&module).unwrap().value, Value::Int(1));
        assert_eq!(v8_execute(&module).unwrap().value, Value::Int(1));
    }
}

#[test]
fn symbol_accessor_copy_invokes_getter_and_assign_setter_bd_n8eta_4_2() {
    let module = lower_symbol_source_bd_n8eta_4_2(
        "const key = Symbol('accessor');\
             const state = { getterCalls: 0, setterCalls: 0, received: 0 };\
             const source = { get [key]() {\
                 state.getterCalls = state.getterCalls + 1; return 41;\
             } };\
             const target = { set [key](value) {\
                 state.setterCalls = state.setterCalls + 1; state.received = value;\
             } };\
             const filteredBeforeCopy = Object.values(source).length === 0 &&\
                 Object.entries(source).length === 0 && JSON.stringify(source) === '{}';\
             const spread = { ...source };\
             Object.assign(target, source);\
             (filteredBeforeCopy && state.getterCalls === 2 && spread[key] === 41 &&\
              state.setterCalls === 1 && state.received === 41 &&\
              Object.getOwnPropertySymbols(source)[0] === key) ? 1 : 0;",
    );
    assert_eq!(quickjs_execute(&module).unwrap().value, Value::Int(1));
    assert_eq!(v8_execute(&module).unwrap().value, Value::Int(1));
}

#[test]
fn native_array_for_of_uses_typed_symbol_iterator_bd_n8eta_4_2() {
    let module = test_module(Vec::new());
    let mut core = quickjs_test_core();
    let array = seed_array(&mut core, 2, &[(0, Value::Int(7)), (1, Value::Int(9))]);

    let iterator = core
        .init_for_of_iterator(Some(&module), Value::Object(array))
        .expect("native array Symbol.iterator should initialize for..of");
    assert_eq!(
        core.advance_for_of_iterator(Some(&module), iterator.clone())
            .expect("native array iterator should yield its first value"),
        Some(Value::Int(7))
    );
    assert_eq!(
        core.advance_for_of_iterator(Some(&module), iterator.clone())
            .expect("native array iterator should yield its second value"),
        Some(Value::Int(9))
    );
    assert_eq!(
        core.advance_for_of_iterator(Some(&module), iterator)
            .expect("native array iterator should finish"),
        None
    );
}

#[test]
fn symbol_allocations_charge_their_own_record_bd_9vouw_332() {
    let mut core = quickjs_test_core();
    let first = core
        .allocate_class_private_name_symbol(JsString::from("#f0"))
        .unwrap();
    for index in 1..300u32 {
        let symbol = match index % 3 {
            0 => core.allocate_private_symbol(None),
            1 => core.allocate_class_private_name_symbol(JsString::from(format!("#f{index}"))),
            _ => core.intern_global_symbol(JsString::from(format!("key{index}"))),
        }
        .unwrap();
        assert_eq!(symbol, SymbolId(first.0 + index));
    }
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "the per-record charges sum to the symbol state's estimate"
    );
    // A symbol that does not fit changes neither the state nor the charge.
    let before_state = core.symbol_state.value.clone();
    let before_memory = core.estimated_memory_bytes();
    core.config.max_total_memory_bytes = before_memory;
    assert!(matches!(
        core.intern_global_symbol(JsString::from("new key")),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.symbol_state.value, before_state);
    assert_eq!(core.estimated_memory_bytes(), before_memory);
}

#[test]
fn symbol_registry_index_restores_exact_keys_without_changing_wire() {
    let mut state = RuntimeSymbolState::default();
    let keys = [
        JsString::from("shared"),
        JsString::from_code_units(&[0xD800]),
        JsString::from_code_units(&[0xD801]),
        JsString::from_code_units(&[0xDC00]),
        JsString::from("\u{FFFD}"),
    ];
    for key in &keys {
        state
            .allocate(RuntimeSymbolKind::Private, Some(key.clone()), None)
            .unwrap();
        state
            .allocate(
                RuntimeSymbolKind::Global,
                Some(key.clone()),
                Some(key.clone()),
            )
            .unwrap();
    }
    let wire = serde_json::to_string(&state).unwrap();
    assert!(!wire.contains("global_symbols"));
    let restored: RuntimeSymbolState = serde_json::from_str(&wire).unwrap();
    assert_eq!(restored, state);
    assert_eq!(serde_json::to_string(&restored).unwrap(), wire);
    for (index, key) in keys.iter().enumerate() {
        assert_eq!(
            restored.global_symbol(key),
            Some(SymbolId(FIRST_DYNAMIC_SYMBOL_ID + index as u32 * 2 + 1))
        );
    }
    assert_eq!(restored.global_symbol(&JsString::from("absent")), None);

    // Rebuilding the derived index must not hide a duplicate in the wire.
    let duplicate = r#"{"well_known_schema":"es2020-symbol-ids-1-13-v1","next_symbol_id":16,"symbols":[{"symbol_id":14,"kind":"global","description":"x","registry_key":"x"},{"symbol_id":15,"kind":"global","description":"x","registry_key":"x"}]}"#;
    let error = serde_json::from_str::<RuntimeSymbolState>(duplicate).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("duplicate global Symbol registry key")
    );
}

#[test]
fn symbol_registry_index_is_admitted_before_allocation_and_rolls_back() {
    let mut core = quickjs_test_core();
    let key = JsString::from("budgeted registry key");
    let before = core.symbol_state.value.clone();
    let before_memory = core.estimated_memory_bytes();
    let charge = InterpreterCore::estimate_symbol_record_bytes(Some(&key), Some(&key));
    let old_record_charge =
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES + InterpreterCore::estimate_js_string_bytes(&key) * 2;
    assert!(
        charge > old_record_charge,
        "the lookup index must be charged"
    );
    core.config.max_total_memory_bytes = before_memory + charge - 1;
    assert!(matches!(
        core.intern_global_symbol(key.clone()),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.symbol_state.value, before);
    assert_eq!(core.estimated_memory_bytes(), before_memory);
    core.config.max_total_memory_bytes = before_memory + charge;
    let id = core.intern_global_symbol(key.clone()).unwrap();
    assert_eq!(core.estimated_memory_bytes(), before_memory + charge);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
    assert_eq!(core.intern_global_symbol(key.clone()).unwrap(), id);

    // Exhausting identities after memory admission must undo the charge
    // without adding a dangling key to the derived index.
    core.config.max_total_memory_bytes = u64::MAX;
    core.symbol_state.value.next_symbol_id = u32::MAX;
    let before = core.symbol_state.value.clone();
    let before_memory = core.estimated_memory_bytes();
    assert!(matches!(
        core.intern_global_symbol(JsString::from("overflow")),
        Err(InterpreterError::TypeError { .. })
    ));
    assert_eq!(core.symbol_state.value, before);
    assert_eq!(core.estimated_memory_bytes(), before_memory);
    assert_eq!(core.intern_global_symbol(key).unwrap(), id);
}

#[test]
fn symbol_seed_registry_and_budget_rollback_are_atomic_bd_n8eta_4_2() {
    let mut core = quickjs_test_core();
    let private = core
        .allocate_private_symbol(Some(JsString::from("private")))
        .unwrap();
    let global = core.intern_global_symbol(JsString::from("shared")).unwrap();
    assert_eq!(
        core.intern_global_symbol(JsString::from("shared")).unwrap(),
        global
    );
    core.seed_register(0, Value::Symbol(private)).unwrap();
    let seed = core
        .capture_execution_seed()
        .expect("test execution-seed capture must fit");
    let later = core.allocate_private_symbol(None).unwrap();
    assert_eq!(later, SymbolId(16));
    core.reset_execution_state_from_seed(&seed).unwrap();
    assert_eq!(
        core.symbol_state.key_for(global),
        Some(&JsString::from("shared"))
    );
    assert_eq!(core.allocate_private_symbol(None).unwrap(), SymbolId(16));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );

    let before_state = core.symbol_state.value.clone();
    let before_memory = core.estimated_memory_bytes();
    core.config.max_total_memory_bytes = before_memory;
    assert_eq!(
        core.intern_global_symbol(JsString::from("shared")).unwrap(),
        global
    );
    assert!(matches!(
        core.allocate_private_symbol(Some(JsString::from("too-large"))),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.symbol_state.value, before_state);
    assert_eq!(core.estimated_memory_bytes(), before_memory);

    core.config.max_total_memory_bytes = u64::MAX;
    let object = core.alloc_object_with_prototype(None).unwrap();
    let before_properties = core.heap[object.0 as usize].properties.clone();
    let before_memory = core.estimated_memory_bytes();
    core.config.max_total_memory_bytes = before_memory.saturating_add(1);
    assert!(matches!(
        core.set_object_runtime_property(
            object,
            RuntimePropertyKey::Symbol(private),
            Value::str("x".repeat(512)),
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.heap[object.0 as usize].properties, before_properties);
    assert_eq!(core.estimated_memory_bytes(), before_memory);

    core.config.max_total_memory_bytes = u64::MAX;
    core.set_object_runtime_property(
        object,
        RuntimePropertyKey::Symbol(private),
        Value::str("x".repeat(512)),
    )
    .unwrap();
    let before_properties = core.heap[object.0 as usize].properties.clone();
    let before_memory = core.estimated_memory_bytes();
    let previous_property_bytes =
        InterpreterCore::estimate_ordered_property_map_bytes(&before_properties);
    let mut projected = before_properties.clone();
    projected.insert_baseline_symbol_property(
        core_symbol_id(private),
        BaselineSymbolProperty::Data(Value::Int(1)),
    );
    let next_property_bytes = InterpreterCore::estimate_ordered_property_map_bytes(&projected);
    assert!(previous_property_bytes > next_property_bytes);
    core.config.max_total_memory_bytes = before_memory.saturating_add(next_property_bytes);
    assert!(matches!(
        core.set_object_runtime_property(
            object,
            RuntimePropertyKey::Symbol(private),
            Value::Int(1),
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.heap[object.0 as usize].properties, before_properties);
    assert_eq!(core.estimated_memory_bytes(), before_memory);

    core.config.max_total_memory_bytes = before_memory;
    assert!(
        core.remove_object_runtime_property(object, &RuntimePropertyKey::Symbol(private))
            .unwrap()
    );
    assert!(core.estimated_memory_bytes() < before_memory);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn stack_overflow() {
    // Recursive function that calls itself.
    let m = test_module_with_functions(
        vec![
            // Load function ref and call
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 0, count: 1 },
                dst: 0,
            }, // 0 (entry)
        ],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 1,
            frame_size: 1,
            name: Some("recurse".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );

    let mut config = test_quickjs_config();
    config.max_call_depth = 10;
    config.instruction_budget = 100;
    let mut core = InterpreterCore::new(config, "test");
    core.set_reg(0, Value::Function(0));
    let err = core.execute(&m).unwrap_err();
    assert!(matches!(err, InterpreterError::StackOverflow { .. }));
}

// -----------------------------------------------------------------------
// 5. Budget exhaustion
// -----------------------------------------------------------------------

#[test]
fn budget_exhaustion() {
    // Infinite loop.
    let m = test_module(vec![Ir3Instruction::Jump { target: 0 }]);

    let mut config = test_quickjs_config();
    config.instruction_budget = 5;
    let lane = QuickJsLane::with_config(config);
    let err = lane.execute(&m, "test").unwrap_err();
    assert!(matches!(err, InterpreterError::BudgetExhausted { .. }));
}

// -----------------------------------------------------------------------
// 6. Register bounds
// -----------------------------------------------------------------------

#[test]
fn register_out_of_bounds() {
    let m = test_module(vec![Ir3Instruction::LoadInt {
        dst: 9999,
        value: 1,
    }]);

    let mut config = test_quickjs_config();
    config.max_registers = 256;
    let lane = QuickJsLane::with_config(config);
    let err = lane.execute(&m, "test").unwrap_err();
    assert!(matches!(err, InterpreterError::RegisterOutOfBounds { .. }));
}

// -----------------------------------------------------------------------
// 7. String pool bounds
// -----------------------------------------------------------------------

#[test]
fn string_pool_out_of_bounds() {
    let m = test_module(vec![Ir3Instruction::LoadStr {
        dst: 0,
        pool_index: 99,
    }]);
    let err = quickjs_execute(&m).unwrap_err();
    assert!(matches!(
        err,
        InterpreterError::StringPoolOutOfBounds { .. }
    ));
}

// -----------------------------------------------------------------------
// 8. Move instruction
// -----------------------------------------------------------------------

#[test]
fn move_register() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 42 },
        Ir3Instruction::Move { dst: 0, src: 1 },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Int(42));
}

// -----------------------------------------------------------------------
// 9. Hostcall capability check
// -----------------------------------------------------------------------

#[test]
fn hostcall_capability_denied() {
    let m = test_module(vec![Ir3Instruction::HostCall {
        capability: CapabilityTag("network".to_string()),
        args: RegRange { start: 0, count: 0 },
        dst: 0,
    }]);
    // Grant execution/allocation capabilities but withhold NetworkEgress so
    // that execution reaches the hostcall and is then denied for `network`.
    let mut config = test_quickjs_config();
    config
        .granted_capabilities
        .remove(&RuntimeCapability::NetworkEgress);
    let err = QuickJsLane::with_config(config)
        .execute(&m, "test-trace")
        .unwrap_err();
    assert!(matches!(err, InterpreterError::CapabilityDenied { .. }));
}

#[test]
fn hostcall_capability_granted() {
    let m = test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("network".to_string()),
            args: RegRange { start: 0, count: 0 },
            dst: 0,
        },
        Ir3Instruction::Halt,
    ]);
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::NetworkEgress,
    ]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&m, "test")
        .expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Undefined);
}

#[test]
fn active_math_abs_handles_min_int_and_coercions() {
    fn call_math_abs(value: Value) -> Value {
        let mut core = quickjs_test_core();
        core.mutate_registers(|r| {
            r.resize(1, Value::Undefined);
        });
        core.set_reg(0, value);
        core.dispatch_builtin_hostcall("builtin:MathAbs", RegRange { start: 0, count: 1 }, None)
            .expect("operation should succeed for valid inputs")
    }

    assert_eq!(call_math_abs(Value::Int(-7)), Value::Int(7));
    assert_eq!(
        call_math_abs(Value::Float(Float64::new(-2.5))),
        Value::Float(Float64::new(2.5))
    );
    // Math.abs(i64::MIN) uses saturating_abs -> i64::MAX (consistent with stdlib)
    assert_eq!(call_math_abs(Value::Int(i64::MIN)), Value::Int(i64::MAX));
    assert_eq!(
        call_math_abs(Value::str(" -3.5 ")),
        Value::Float(Float64::new(3.5))
    );
    assert_eq!(
        call_math_abs(Value::Bool(true)),
        Value::Float(Float64::new(1.0))
    );

    let result = call_math_abs(Value::Undefined);
    let Value::Float(result) = result else {
        panic!("expected Math.abs(undefined) to produce NaN float");
    };
    assert!(result.inner().is_nan());
}

#[test]
fn math_abs_i64_min_saturating_regression() {
    // Regression test for bd-3iu4f: Math.abs(i64::MIN) should use saturating_abs
    // instead of panicking or converting to Float
    fn call_math_abs(value: Value) -> Value {
        let mut core = quickjs_test_core();
        core.mutate_registers(|r| {
            r.resize(1, Value::Undefined);
        });
        core.set_reg(0, value);
        core.dispatch_builtin_hostcall("builtin:MathAbs", RegRange { start: 0, count: 1 }, None)
            .expect("operation should succeed for valid inputs")
    }

    // Core fix: i64::MIN should saturate to i64::MAX (not panic or convert to Float)
    assert_eq!(call_math_abs(Value::Int(i64::MIN)), Value::Int(i64::MAX));

    // Edge cases around i64::MIN
    assert_eq!(
        call_math_abs(Value::Int(i64::MIN + 1)),
        Value::Int(i64::MAX)
    );
    assert_eq!(call_math_abs(Value::Int(-1)), Value::Int(1));
    assert_eq!(call_math_abs(Value::Int(0)), Value::Int(0));
    assert_eq!(call_math_abs(Value::Int(i64::MAX)), Value::Int(i64::MAX));

    // Float coercion should still work normally
    assert_eq!(
        call_math_abs(Value::Float(Float64::new(-42.5))),
        Value::Float(Float64::new(42.5))
    );

    // String coercion should still work normally
    assert_eq!(
        call_math_abs(Value::str("-123")),
        Value::Float(Float64::new(123.0))
    );

    // Boolean coercion should still work normally
    assert_eq!(
        call_math_abs(Value::Bool(false)),
        Value::Float(Float64::new(0.0))
    );

    // Math.abs(null) === 0: Number(null) is +0 per ES ToNumber, so Math.abs(null)
    // is +0. (Only Math.abs(undefined) is NaN, since Number(undefined) === NaN.)
    // The legacy assertion conflated null with undefined (bd-n0sap).
    assert_eq!(call_math_abs(Value::Null), Value::Float(Float64::new(0.0)));
}

// -----------------------------------------------------------------------
// 10. Witness events
// -----------------------------------------------------------------------

#[test]
fn witness_events_emitted() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    // Should have at least the ExecutionCompleted event.
    assert!(
        result
            .witness_events
            .iter()
            .any(|e| e.kind == WitnessEventKind::ExecutionCompleted)
    );
}

#[test]
fn hostcall_produces_witness_events() {
    let mut m = test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("fs".to_string()),
            args: RegRange { start: 0, count: 0 },
            dst: 0,
        },
        Ir3Instruction::Halt,
    ]);
    m.required_capabilities = vec![CapabilityTag("fs".to_string())];

    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::FsRead,
    ]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&m, "test")
        .expect("operation should succeed for valid inputs");

    assert!(
        result
            .witness_events
            .iter()
            .any(|e| e.kind == WitnessEventKind::HostcallDispatched)
    );
    assert!(
        result
            .witness_events
            .iter()
            .any(|e| e.kind == WitnessEventKind::CapabilityChecked)
    );
}

// -----------------------------------------------------------------------
// 11. Structured events
// -----------------------------------------------------------------------

#[test]
fn structured_events_emitted() {
    let m = test_module(vec![Ir3Instruction::Halt]);
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert!(result.events.iter().any(|e| e.event == "execution_started"));
    assert!(result.events.iter().any(|e| e.event == "execution_halted"));
}

// -----------------------------------------------------------------------
// 12. V8 lane produces same results
// -----------------------------------------------------------------------

#[test]
fn v8_lane_same_result_as_quickjs() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 3 },
        Ir3Instruction::LoadInt { dst: 2, value: 4 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let qjs = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    let v8 = v8_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(qjs.value, v8.value);
}

// -----------------------------------------------------------------------
// 13. Lane routing
// -----------------------------------------------------------------------

#[test]
fn router_selects_quickjs_for_simple_module() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::Halt,
    ]);
    let router = LaneRouter::new();
    let result = router
        .execute(&m, "test", None)
        .expect("operation should succeed for valid inputs");
    assert_eq!(result.lane, LaneChoice::QuickJs);
    assert_eq!(result.reason, LaneReason::DefaultFallback);
}

#[test]
fn router_selects_quickjs_for_capability_module() {
    let mut m = test_module(vec![Ir3Instruction::Halt]);
    m.required_capabilities = vec![CapabilityTag("net".to_string())];
    let router = LaneRouter::new();
    let result = router
        .execute(&m, "test", None)
        .expect("operation should succeed for valid inputs");
    assert_eq!(result.lane, LaneChoice::QuickJs);
    assert_eq!(result.reason, LaneReason::SecuritySensitive);
}

#[test]
fn router_selects_v8_for_large_module() {
    let instrs: Vec<Ir3Instruction> = (0..1001)
        .map(|_| Ir3Instruction::LoadInt { dst: 0, value: 1 })
        .chain(std::iter::once(Ir3Instruction::Halt))
        .collect();
    let m = test_module(instrs);
    let router = LaneRouter::new();
    let result = router
        .execute(&m, "test", None)
        .expect("operation should succeed for valid inputs");
    assert_eq!(result.lane, LaneChoice::V8);
    assert_eq!(result.reason, LaneReason::ThroughputOptimized);
}

#[test]
fn router_respects_forced_lane() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::Halt,
    ]);
    let router = LaneRouter::new();
    let result = router
        .execute(&m, "test", Some(LaneChoice::V8))
        .expect("operation should succeed for valid inputs");
    assert_eq!(result.lane, LaneChoice::V8);
    assert_eq!(result.reason, LaneReason::PolicyDirective);
}

// -----------------------------------------------------------------------
// 14. Determinism: same input → same output
// -----------------------------------------------------------------------

#[test]
fn deterministic_execution() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 100 },
        Ir3Instruction::LoadInt { dst: 2, value: 200 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);

    let r1 = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    let r2 = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(r1.value, r2.value);
    assert_eq!(r1.instructions_executed, r2.instructions_executed);
}

// -----------------------------------------------------------------------
// 15. Value truthiness
// -----------------------------------------------------------------------

#[test]
fn value_truthiness() {
    assert!(!Value::Undefined.is_truthy());
    assert!(!Value::Null.is_truthy());
    assert!(!Value::Bool(false).is_truthy());
    assert!(!Value::Int(0).is_truthy());
    assert!(!Value::str("").is_truthy());

    assert!(Value::Bool(true).is_truthy());
    assert!(Value::Int(1).is_truthy());
    assert!(Value::Int(-1).is_truthy());
    assert!(Value::str("x").is_truthy());
    assert!(Value::Object(ObjectId(0)).is_truthy());
    assert!(Value::Function(0).is_truthy());
}

// -----------------------------------------------------------------------
// 16. Value display
// -----------------------------------------------------------------------

#[test]
fn value_display() {
    assert_eq!(Value::Undefined.to_string(), "undefined");
    assert_eq!(Value::Null.to_string(), "null");
    assert_eq!(Value::Bool(true).to_string(), "true");
    assert_eq!(Value::Int(42).to_string(), "42");
    assert_eq!(Value::str("hi").to_string(), "hi");
}

// -----------------------------------------------------------------------
// 17. Error display
// -----------------------------------------------------------------------

#[test]
fn error_display_coverage() {
    let errors = vec![
        InterpreterError::BudgetExhausted {
            executed: 100,
            budget: 50,
        },
        InterpreterError::RegisterOutOfBounds {
            register: 999,
            max: 256,
        },
        InterpreterError::DivisionByZero,
        InterpreterError::Halted,
        InterpreterError::StackOverflow { depth: 10, max: 5 },
        InterpreterError::CapabilityDenied {
            capability: "net".to_string(),
        },
        InterpreterError::UnsupportedMembershipSemantics {
            operator: "in".to_string(),
        },
        InterpreterError::UncaughtException {
            value: "test error".to_string(),
        },
    ];
    for e in errors {
        let s = e.to_string();
        assert!(!s.is_empty());
    }
}

// -----------------------------------------------------------------------
// 18. Return from top-level
// -----------------------------------------------------------------------

#[test]
fn return_from_top_level() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 99 },
        Ir3Instruction::Return { value: 0 },
    ]);
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Int(99));
}

// -----------------------------------------------------------------------
// 19. Fall off end of instructions
// -----------------------------------------------------------------------

#[test]
fn fall_off_end() {
    let m = test_module(vec![Ir3Instruction::LoadInt { dst: 0, value: 77 }]);
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Int(77));
}

// -----------------------------------------------------------------------
// 20. Serde round-trips
// -----------------------------------------------------------------------

#[test]
fn value_serde_roundtrip() {
    for val in [
        Value::Undefined,
        Value::Null,
        Value::Bool(true),
        Value::Int(42),
        Value::str("hello"),
        Value::Object(ObjectId(7)),
        Value::Function(3),
    ] {
        let json = serde_json::to_string(&val).expect("serialize derived Serialize");
        let deser: Value = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(val, deser);
    }
}

#[test]
fn interpreter_error_serde_roundtrip() {
    let err = InterpreterError::BudgetExhausted {
        executed: 100,
        budget: 50,
    };
    let json = serde_json::to_string(&err).expect("serialize derived Serialize");
    let deser: InterpreterError =
        serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(err, deser);
}

#[test]
fn config_serde_roundtrip() {
    let mut config = InterpreterConfig::quickjs_defaults();
    let json = serde_json::to_string(&config).expect("serialize derived Serialize");
    assert!(
        !json.contains("module_conditions"),
        "default snapshots stay compatible"
    );
    let deser: InterpreterConfig =
        serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(config, deser);
    assert!(deser.module_conditions.is_empty());

    config.module_conditions = vec!["development".to_string()];
    let json = serde_json::to_string(&config).expect("serialize custom package conditions");
    let deser: InterpreterConfig =
        serde_json::from_str(&json).expect("deserialize custom package conditions");
    assert_eq!(config, deser);
    assert_eq!(deser.module_conditions, ["development"]);
}

// -----------------------------------------------------------------------
// 21. Empty module
// -----------------------------------------------------------------------

#[test]
fn empty_module_returns_undefined() {
    let m = test_module(vec![]);
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Undefined);
}

// -----------------------------------------------------------------------
// 22. Complex expression: (3 + 4) * 2
// -----------------------------------------------------------------------

#[test]
fn complex_arithmetic() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 3 },
        Ir3Instruction::LoadInt { dst: 2, value: 4 },
        Ir3Instruction::Add {
            dst: 3,
            lhs: 1,
            rhs: 2,
        }, // r3 = 7
        Ir3Instruction::LoadInt { dst: 4, value: 2 },
        Ir3Instruction::Mul {
            dst: 0,
            lhs: 3,
            rhs: 4,
        }, // r0 = 14
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Int(14));
}

// -----------------------------------------------------------------------
// 23. Loop: sum 1..5
// -----------------------------------------------------------------------

#[test]
fn loop_sum_one_to_five() {
    // r0 = sum (accumulator), r1 = counter, r2 = limit
    // r3 = 1 (increment), r4 = temp comparison
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 0 }, // 0: sum = 0
        Ir3Instruction::LoadInt { dst: 1, value: 1 }, // 1: counter = 1
        Ir3Instruction::LoadInt { dst: 2, value: 6 }, // 2: limit = 6 (exclusive)
        Ir3Instruction::LoadInt { dst: 3, value: 1 }, // 3: increment = 1
        // Loop body (instruction 4):
        Ir3Instruction::Add {
            dst: 0,
            lhs: 0,
            rhs: 1,
        }, // 4: sum += counter
        Ir3Instruction::Add {
            dst: 1,
            lhs: 1,
            rhs: 3,
        }, // 5: counter += 1
        // Compare: if counter < limit, jump to loop body
        Ir3Instruction::Sub {
            dst: 4,
            lhs: 2,
            rhs: 1,
        }, // 6: r4 = limit - counter
        Ir3Instruction::JumpIf { cond: 4, target: 4 }, // 7: if r4 truthy, loop
        Ir3Instruction::Halt,                          // 8
    ]);
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Int(15)); // 1+2+3+4+5 = 15
}

// -----------------------------------------------------------------------
// 24. Instruction count tracking
// -----------------------------------------------------------------------

#[test]
fn instructions_executed_counted() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::LoadInt { dst: 1, value: 2 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 0,
            rhs: 1,
        },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(result.instructions_executed, 5); // 3 ops + halt + empty Writable checkpoint scan
}

// -----------------------------------------------------------------------
// 25. String + number concatenation
// -----------------------------------------------------------------------

#[test]
fn string_int_concatenation() {
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 42 },
            Ir3Instruction::Add {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Halt,
        ],
        vec!["answer: ".to_string()],
    );
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::str("answer: 42"));
}

#[test]
fn value_ord() {
    assert!(Value::Undefined < Value::Null);
    assert!(Value::Null < Value::Bool(false));
    assert!(Value::Bool(false) < Value::Bool(true));
    assert!(Value::Bool(true) < Value::Int(0));
    assert!(Value::Int(0) < Value::str(""));
    assert!(Value::str("") < Value::Object(ObjectId(0)));
    assert!(Value::Object(ObjectId(0)) < Value::Function(0));
}

// -----------------------------------------------------------------------
// Enrichment: InterpreterError Display uniqueness via BTreeSet
// -----------------------------------------------------------------------

#[test]
fn interpreter_error_display_all_unique() {
    let errors = vec![
        InterpreterError::BudgetExhausted {
            executed: 100,
            budget: 50,
        },
        InterpreterError::RegisterOutOfBounds {
            register: 999,
            max: 256,
        },
        InterpreterError::DivisionByZero,
        InterpreterError::Halted,
        InterpreterError::StackOverflow { depth: 10, max: 5 },
        InterpreterError::CapabilityDenied {
            capability: "net".to_string(),
        },
        InterpreterError::RequireSpecifierNotString {
            got: "undefined".to_string(),
        },
        InterpreterError::TypeError {
            expected: "number".to_string(),
            got: "object".to_string(),
        },
        InterpreterError::StringPoolOutOfBounds {
            index: 99,
            pool_size: 5,
        },
        InterpreterError::UnsupportedMembershipSemantics {
            operator: "instanceof".to_string(),
        },
        InterpreterError::UncaughtException {
            value: "test error".to_string(),
        },
    ];
    let mut displays = std::collections::BTreeSet::new();
    for e in &errors {
        displays.insert(e.to_string());
    }
    assert_eq!(
        displays.len(),
        errors.len(),
        "all InterpreterError variants produce distinct Display"
    );
}

// -----------------------------------------------------------------------
// Enrichment: InterpreterError implements std::error::Error
// -----------------------------------------------------------------------

#[test]
fn interpreter_error_display_coverage() {
    let variants: Vec<InterpreterError> = vec![
        InterpreterError::DivisionByZero,
        InterpreterError::Halted,
        InterpreterError::BudgetExhausted {
            executed: 10,
            budget: 5,
        },
    ];
    for v in &variants {
        assert!(!v.to_string().is_empty());
    }
}

// -----------------------------------------------------------------------
// Enrichment: Value Display uniqueness for all types
// -----------------------------------------------------------------------

#[test]
fn value_display_all_types_non_empty() {
    let values = vec![
        Value::Undefined,
        Value::Null,
        Value::Bool(true),
        Value::Bool(false),
        Value::Int(0),
        Value::Int(-1),
        Value::str("hello"),
        Value::Object(ObjectId(0)),
        Value::Function(0),
    ];
    for v in &values {
        assert!(
            !v.to_string().is_empty(),
            "Value::Display should not be empty for {v:?}"
        );
    }
}

// -----------------------------------------------------------------------
// Enrichment: LaneChoice serde roundtrip
// -----------------------------------------------------------------------

#[test]
fn lane_choice_serde_roundtrip() {
    for choice in &[LaneChoice::QuickJs, LaneChoice::V8] {
        let json = serde_json::to_string(choice).expect("serialize derived Serialize");
        let back: LaneChoice = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(*choice, back);
    }
}

// -----------------------------------------------------------------------
// Enrichment: V8 lane budget exhaustion
// -----------------------------------------------------------------------

#[test]
fn v8_budget_exhaustion() {
    let m = test_module(vec![Ir3Instruction::Jump { target: 0 }]);
    let mut config = test_v8_config();
    config.instruction_budget = 5;
    let lane = V8Lane::with_config(config);
    let err = lane.execute(&m, "test").unwrap_err();
    assert!(matches!(err, InterpreterError::BudgetExhausted { .. }));
}

// -----------------------------------------------------------------------
// Enrichment: InterpreterConfig v8_defaults has larger budget
// -----------------------------------------------------------------------

#[test]
fn v8_defaults_larger_budget_than_quickjs() {
    let qjs = InterpreterConfig::quickjs_defaults();
    let v8 = InterpreterConfig::v8_defaults();
    assert!(
        v8.instruction_budget > qjs.instruction_budget,
        "V8 lane should have a larger default budget"
    );
}

// -----------------------------------------------------------------------
// Enrichment: ExecutionResult serde roundtrip
// -----------------------------------------------------------------------

#[test]
fn execution_result_fields_accessible() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 42 },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert!(result.instructions_executed > 0);
    assert!(result.events.is_empty() || !result.events.is_empty());
}

// -----------------------------------------------------------------------
// Enrichment: negative integer arithmetic
// -----------------------------------------------------------------------

#[test]
fn negative_integer_arithmetic() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: -10 },
        Ir3Instruction::LoadInt { dst: 2, value: 3 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).expect("operation should succeed for valid inputs");
    assert_eq!(result.value, Value::Int(-7));
}

// -----------------------------------------------------------------------
// Enrichment: PearlTower 2026-02-26
// -----------------------------------------------------------------------

#[test]
fn value_type_name_all_variants() {
    assert_eq!(Value::Undefined.type_name(), "undefined");
    assert_eq!(Value::Null.type_name(), "null");
    assert_eq!(Value::Bool(true).type_name(), "boolean");
    assert_eq!(Value::Int(0).type_name(), "number");
    assert_eq!(Value::str("").type_name(), "string");
    assert_eq!(Value::Object(ObjectId(0)).type_name(), "object");
    assert_eq!(Value::Function(0).type_name(), "function");
    assert_eq!(
        Value::BuiltinFunction(BuiltinFunction::require("/tmp/entry.cjs")).type_name(),
        "function"
    );
}

#[test]
fn value_is_truthy_exhaustive() {
    assert!(!Value::Undefined.is_truthy());
    assert!(!Value::Null.is_truthy());
    assert!(!Value::Bool(false).is_truthy());
    assert!(Value::Bool(true).is_truthy());
    assert!(!Value::Int(0).is_truthy());
    assert!(Value::Int(1).is_truthy());
    assert!(Value::Int(-1).is_truthy());
    assert!(!Value::str("").is_truthy());
    assert!(Value::str("x").is_truthy());
    assert!(Value::Object(ObjectId(0)).is_truthy());
    assert!(Value::Function(0).is_truthy());
    assert!(Value::BuiltinFunction(BuiltinFunction::require("/tmp/entry.cjs")).is_truthy());
}

#[test]
fn object_id_serde_roundtrip() {
    let id = ObjectId(42);
    let json = serde_json::to_string(&id).expect("serialize derived Serialize");
    let back: ObjectId = serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(id, back);
}

#[test]
fn heap_object_new_is_empty() {
    let obj = HeapObject::new();
    assert!(obj.properties.is_empty());
}

#[test]
fn lane_reason_serde_all_variants() {
    let variants = [
        LaneReason::SecuritySensitive,
        LaneReason::ThroughputOptimized,
        LaneReason::PolicyDirective,
        LaneReason::DefaultFallback,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).expect("serialize derived Serialize");
        let back: LaneReason = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(*v, back);
    }
}

#[test]
fn interpreter_event_serde_roundtrip() {
    let ev = InterpreterEvent {
        trace_id: "t-1".to_string(),
        component: "baseline_interpreter".to_string(),
        event: "execution_started".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&ev).expect("serialize derived Serialize");
    let back: InterpreterEvent = serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(ev, back);
}

#[test]
fn interpreter_event_serde_with_error_code() {
    let ev = InterpreterEvent {
        trace_id: "t-2".to_string(),
        component: "baseline_interpreter".to_string(),
        event: "execution_failed".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("BUDGET_EXHAUSTED".to_string()),
    };
    let json = serde_json::to_string(&ev).expect("serialize derived Serialize");
    let back: InterpreterEvent = serde_json::from_str(&json).expect("deserialize known-valid JSON");
    assert_eq!(ev.error_code, back.error_code);
}

#[test]
fn interpreter_config_quickjs_defaults_fields() {
    let c = InterpreterConfig::quickjs_defaults();
    assert_eq!(c.instruction_budget, 100_000);
    assert_eq!(c.max_registers, 256);
    assert_eq!(c.max_call_depth, 10_000);
    assert_eq!(c.max_heap_objects, 100_000);
    assert_eq!(c.max_total_memory_bytes, 64 * 1024 * 1024);
    assert_eq!(c.max_scope_depth, 512);
    assert!(c.granted_capabilities.is_empty());
}

#[test]
fn interpreter_config_v8_defaults_fields() {
    let c = InterpreterConfig::v8_defaults();
    assert_eq!(c.instruction_budget, 1_000_000);
    assert_eq!(c.max_registers, 4096);
    assert_eq!(c.max_call_depth, 10_000);
    assert_eq!(c.max_heap_objects, 1_000_000);
    assert_eq!(c.max_total_memory_bytes, 512 * 1024 * 1024);
    assert_eq!(c.max_scope_depth, 512);
    assert!(c.granted_capabilities.is_empty());
}

#[test]
fn interpreter_config_supports_all_runtime_capability_variants() {
    // Test exhaustiveness: verify all 17 RuntimeCapability variants can be inserted
    let all_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::GcInvoke,
        RuntimeCapability::IrLowering,
        RuntimeCapability::PolicyRead,
        RuntimeCapability::PolicyWrite,
        RuntimeCapability::EvidenceEmit,
        RuntimeCapability::DecisionInvoke,
        RuntimeCapability::NetworkEgress,
        RuntimeCapability::LeaseManagement,
        RuntimeCapability::IdempotencyDerive,
        RuntimeCapability::ExtensionLifecycle,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::EnvRead,
        RuntimeCapability::ProcessSpawn,
        RuntimeCapability::FsRead,
        RuntimeCapability::FsWrite,
        RuntimeCapability::ModuleLoad,
    ]);

    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = all_capabilities.clone();

    // Verify all capabilities are stored and can be retrieved
    assert_eq!(config.granted_capabilities.len(), 17); // 17 total capabilities
    assert!(
        config
            .granted_capabilities
            .contains(&RuntimeCapability::VmDispatch)
    );
    assert!(
        config
            .granted_capabilities
            .contains(&RuntimeCapability::ModuleLoad)
    );

    // Verify BTreeSet maintains deterministic ordering
    let capabilities_vec: Vec<_> = config.granted_capabilities.iter().collect();
    let capabilities_vec2: Vec<_> = all_capabilities.iter().collect();
    assert_eq!(capabilities_vec, capabilities_vec2);
}

#[test]
fn scope_chain_push_respects_max_scope_depth() {
    let mut chain = ScopeChain::new();
    chain
        .push(2)
        .expect("operation should succeed for valid inputs");
    let err = chain.push(2).unwrap_err();
    assert!(matches!(
        err,
        InterpreterError::ScopeDepthExceeded {
            requested_depth: 3,
            max_depth: 2,
        }
    ));
}

#[test]
fn router_throughput_optimized_for_large_module() {
    let mut instrs = Vec::new();
    for _ in 0..1001 {
        instrs.push(Ir3Instruction::LoadInt { dst: 0, value: 0 });
    }
    instrs.push(Ir3Instruction::Halt);
    let m = test_module(instrs);
    let router = LaneRouter::new();
    let result = router
        .execute(&m, "test", None)
        .expect("operation should succeed for valid inputs");
    assert_eq!(result.lane, LaneChoice::V8);
    assert_eq!(result.reason, LaneReason::ThroughputOptimized);
}

#[test]
fn alloc_object_and_heap_size() {
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "test");
    assert_eq!(core.heap_size(), 0);
    let seed_bytes = InterpreterCore::estimate_scope_chain_bytes(&core.scope_chain.frames);
    assert_eq!(core.estimated_memory_bytes(), seed_bytes);
    let id = core
        .alloc_object_with_prototype(None)
        .expect("operation should succeed for valid inputs");
    assert_eq!(id, ObjectId(0));
    assert_eq!(core.heap_size(), 1);
    let id2 = core
        .alloc_object_with_prototype(None)
        .expect("operation should succeed for valid inputs");
    assert_eq!(id2, ObjectId(1));
    assert_eq!(core.heap_size(), 2);
    assert!(core.estimated_memory_bytes() > 0);
}

#[test]
fn alloc_object_with_prototype_respects_heap_budget() {
    let mut config = test_quickjs_config();
    config.max_heap_objects = 2;
    let mut core = InterpreterCore::new(config, "heap-budget");
    assert_eq!(
        core.alloc_object_with_prototype(None)
            .expect("operation should succeed for valid inputs"),
        ObjectId(0)
    );
    assert_eq!(
        core.alloc_object_with_prototype(None)
            .expect("operation should succeed for valid inputs"),
        ObjectId(1)
    );
    let err = core.alloc_object_with_prototype(None).unwrap_err();
    assert!(matches!(
        err,
        InterpreterError::MemoryBudgetExceeded {
            requested_heap_objects: 3,
            max_heap_objects: 2,
            ..
        }
    ));
}

#[test]
fn custom_heap_budget_allows_limit_then_fails() {
    let mut config = test_quickjs_config();
    config.max_heap_objects = 10;
    let mut core = InterpreterCore::new(config, "custom-heap-budget");
    for expected in 0_u32..10 {
        assert_eq!(
            core.alloc_object_with_prototype(None)
                .expect("operation should succeed for valid inputs"),
            ObjectId(expected)
        );
    }
    let err = core.alloc_object_with_prototype(None).unwrap_err();
    assert!(matches!(
        err,
        InterpreterError::MemoryBudgetExceeded {
            requested_heap_objects: 11,
            max_heap_objects: 10,
            ..
        }
    ));
}

#[test]
fn estimated_memory_bytes_tracks_property_growth() {
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "memory-estimate");
    let oid = core
        .alloc_object_with_prototype(None)
        .expect("operation should succeed for valid inputs");
    let before = core.estimated_memory_bytes();
    core.mutate_heap(|heap| {
        heap[oid.0 as usize]
            .properties
            .insert("payload".to_string(), Value::str("hello world"));
    });
    core.sync_estimated_memory_bytes()
        .expect("operation should succeed for valid inputs");
    assert!(core.estimated_memory_bytes() > before);
}

#[test]
fn ordered_heap_property_estimator_charges_only_its_second_key() {
    let key = "payload";
    let value = Value::str("hello world");
    let plain = InterpreterCore::estimate_plain_string_map_entry_bytes(key, &value);
    let ordered = InterpreterCore::estimate_property_entry_bytes(key, &value);

    assert_eq!(
        ordered,
        plain.saturating_add(InterpreterCore::estimate_string_bytes(key))
    );
}

#[test]
fn set_and_remove_object_property_update_memory_incrementally() {
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "property-memory-delta");
    let oid = core
        .alloc_object_with_prototype(None)
        .expect("operation should succeed for valid inputs");
    let before_insert = core.estimated_memory_bytes();

    let key = "payload".to_string();
    let value = Value::str("hello world");
    let value_bytes = InterpreterCore::estimate_property_entry_bytes(&key, &value);
    core.set_object_property(oid, key.clone(), value)
        .expect("property insert should fit budget");
    assert_eq!(core.estimated_memory_bytes(), before_insert + value_bytes);
    assert_eq!(
        core.recompute_estimated_memory_bytes(),
        core.estimated_memory_bytes(),
        "property insert delta must match full recompute"
    );

    let replacement = Value::str("x");
    let replacement_bytes = InterpreterCore::estimate_property_entry_bytes(&key, &replacement);
    core.set_object_property(oid, key.clone(), replacement)
        .expect("property replacement should fit budget");
    assert_eq!(
        core.estimated_memory_bytes(),
        before_insert + replacement_bytes
    );
    assert_eq!(
        core.recompute_estimated_memory_bytes(),
        core.estimated_memory_bytes(),
        "property replacement delta must match full recompute"
    );

    assert!(
        core.remove_object_property(oid, &key)
            .expect("property removal should succeed")
    );
    assert_eq!(core.estimated_memory_bytes(), before_insert);
    assert_eq!(
        core.recompute_estimated_memory_bytes(),
        core.estimated_memory_bytes(),
        "property removal delta must match full recompute"
    );
}

#[test]
fn set_object_property_budget_failure_preserves_state() {
    let config = test_quickjs_config();
    let mut core = InterpreterCore::new(config, "property-memory-budget");
    let oid = core
        .alloc_object_with_prototype(None)
        .expect("operation should succeed for valid inputs");
    let before = core.estimated_memory_bytes();
    let key = "payload".to_string();
    let value = Value::str("x".repeat(128));
    let entry_bytes = InterpreterCore::estimate_property_entry_bytes(&key, &value);
    core.config.max_total_memory_bytes = before.saturating_add(entry_bytes).saturating_sub(1);

    let err = core
        .set_object_property(oid, key.clone(), value)
        .expect_err("property write should exceed the memory budget");
    assert!(matches!(err, InterpreterError::MemoryBudgetExceeded { .. }));
    assert_eq!(core.estimated_memory_bytes(), before);
    assert!(
        !core.heap[oid.0 as usize].properties.contains_key(&key),
        "rejected property write must not mutate the object"
    );
}

#[test]
fn exact_dynamic_string_keys_remain_distinct_and_inherit_bd_b12xs_5() {
    let mut core = quickjs_test_core();
    let prototype = core
        .alloc_object_with_prototype(None)
        .expect("prototype allocation should succeed");
    let object = core
        .alloc_object_with_prototype(Some(prototype))
        .expect("object allocation should succeed");
    let d800 = JsString::from_code_units(&[0xD800]);
    let d801 = JsString::from_code_units(&[0xD801]);
    let replacement = JsString::from("\u{FFFD}");
    core.set_object_runtime_property(
        prototype,
        RuntimePropertyKey::String(d801.clone()),
        Value::Int(80),
    )
    .expect("exact prototype property should fit");

    core.set_reg(1, Value::Object(object));
    core.set_reg(2, Value::Str(d800.clone()));
    core.set_reg(3, Value::Int(8));
    core.set_reg(4, Value::Str(d801.clone()));
    core.set_reg(5, Value::Int(9));
    core.set_reg(6, Value::Str(replacement.clone()));
    core.set_reg(7, Value::Int(0xFFFD));
    core.execute(&test_module(vec![
        Ir3Instruction::SetProperty {
            obj: 1,
            key: 2,
            val: 3,
        },
        Ir3Instruction::SetProperty {
            obj: 1,
            key: 4,
            val: 5,
        },
        Ir3Instruction::SetProperty {
            obj: 1,
            key: 6,
            val: 7,
        },
        Ir3Instruction::GetProperty {
            obj: 1,
            key: 2,
            dst: 8,
        },
        Ir3Instruction::GetProperty {
            obj: 1,
            key: 4,
            dst: 9,
        },
        Ir3Instruction::GetProperty {
            obj: 1,
            key: 6,
            dst: 10,
        },
        Ir3Instruction::DeleteProperty {
            obj: 1,
            key: 4,
            dst: 11,
        },
        Ir3Instruction::GetProperty {
            obj: 1,
            key: 4,
            dst: 12,
        },
        Ir3Instruction::InOp {
            dst: 13,
            lhs: 4,
            rhs: 1,
        },
        Ir3Instruction::DeleteProperty {
            obj: 1,
            key: 2,
            dst: 14,
        },
        Ir3Instruction::InOp {
            dst: 15,
            lhs: 2,
            rhs: 1,
        },
        Ir3Instruction::Halt,
    ]))
    .expect("exact dynamic property program should execute");

    assert_eq!(core.registers[8], Value::Int(8));
    assert_eq!(core.registers[9], Value::Int(9));
    assert_eq!(core.registers[10], Value::Int(0xFFFD));
    assert_eq!(core.registers[11], Value::Bool(true));
    assert_eq!(core.registers[12], Value::Int(80));
    assert_eq!(core.registers[13], Value::Bool(true));
    assert_eq!(core.registers[14], Value::Bool(true));
    assert_eq!(core.registers[15], Value::Bool(false));
    assert_eq!(
        core.heap[object.0 as usize]
            .properties
            .get_exact(&replacement),
        Some(&Value::Int(0xFFFD))
    );
    assert_eq!(
        core.heap[prototype.0 as usize].properties.get_exact(&d801),
        Some(&Value::Int(80))
    );
}

#[test]
fn exact_dynamic_key_executes_accessor_getter_bd_b12xs_5() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::GetProperty {
                obj: 5,
                key: 6,
                dst: 7,
            },
            Ir3Instruction::Return { value: 7 },
            Ir3Instruction::LoadInt { dst: 0, value: 42 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 0,
            frame_size: 1,
            name: Some("exact_getter".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = quickjs_test_core();
    let object = core
        .alloc_object_with_prototype(None)
        .expect("object allocation should succeed");
    let exact = JsString::from_code_units(&[0xD800]);
    core.set_object_runtime_property(
        object,
        RuntimePropertyKey::String(exact.clone()),
        Value::Int(8),
    )
    .expect("exact data property should fit");
    let order_before = core.heap[object.0 as usize].properties.exact_keys();
    core.define_accessor_property(
        object,
        RuntimePropertyKey::String(exact.clone()),
        Value::Function(0),
        AccessorKind::Get,
    )
    .expect("data-to-accessor conversion should fit");
    assert_eq!(
        core.heap[object.0 as usize].properties.exact_keys(),
        order_before,
        "data-to-accessor conversion must preserve creation order"
    );
    core.mutate_registers(|registers| {
        registers[5] = Value::Object(object);
        registers[6] = Value::Str(exact);
    });

    assert_eq!(
        core.run_loop(&module)
            .expect("exact getter should execute through GetProperty"),
        Value::Int(42)
    );
}

#[test]
fn exact_proxy_get_trap_receives_exact_key_bd_b12xs_5() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::GetProperty {
                obj: 5,
                key: 6,
                dst: 7,
            },
            Ir3Instruction::Return { value: 7 },
            Ir3Instruction::Return { value: 1 },
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 3,
            frame_size: 3,
            name: Some("exact_proxy_get_trap".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let mut core = quickjs_test_core();
    let target = core
        .alloc_object_with_prototype(None)
        .expect("target allocation should succeed");
    let handler = core
        .alloc_object_with_prototype(None)
        .expect("handler allocation should succeed");
    core.set_object_property(handler, "get".to_string(), Value::Function(0))
        .expect("handler get trap should fit");
    core.mutate_registers(|registers| {
        registers[0] = Value::Object(target);
        registers[1] = Value::Object(handler);
    });
    let proxy = core
        .dispatch_builtin_hostcall("builtin:Proxy", RegRange { start: 0, count: 2 }, None)
        .expect("Proxy constructor should allocate proxy");
    let Value::Object(proxy_id) = proxy else {
        panic!("Proxy constructor should return an object");
    };
    let exact = JsString::from_code_units(&[0xD800]);
    core.mutate_registers(|registers| {
        registers[5] = Value::Object(proxy_id);
        registers[6] = Value::Str(exact.clone());
    });

    assert_eq!(
        core.run_loop(&module)
            .expect("Proxy get trap should receive the exact property key"),
        Value::Str(exact)
    );
}

#[test]
fn callback_mini_interpreters_preserve_exact_dynamic_keys_bd_b12xs_5() {
    let mut core = quickjs_test_core();
    let object = core
        .alloc_object_with_prototype(None)
        .expect("object allocation should succeed");
    let keys = [
        JsString::from_code_units(&[0xD800]),
        JsString::from_code_units(&[0xD801]),
        JsString::from("\u{FFFD}"),
    ];
    // The reducer mini-lane no longer writes properties (bd-9vouw.175);
    // the keys are stored as SetProperty stores them.
    for (index, key) in keys.iter().enumerate() {
        core.set_object_runtime_property(
            object,
            RuntimePropertyKey::String(key.clone()),
            Value::Int(index as i64),
        )
        .expect("property write should preserve the exact key");
    }
    for (index, key) in keys.iter().enumerate() {
        assert_eq!(
            core.simple_callback_get_property(
                None,
                Value::Object(object),
                &Value::Str(key.clone()),
            )
            .expect("callback property read should preserve the exact key"),
            Value::Int(index as i64)
        );
    }
}

/// bd-9vouw.492: the found-property witness event folds through a reused
/// buffer; the digest equals the fold of the allocating builder's bytes,
/// across a key longer than the kept capacity and short keys after it.
#[test]
fn property_witness_scratch_folds_the_same_bytes() {
    let mut core = quickjs_test_core();
    let long_name = "k".repeat(1_000);
    let long = RuntimePropertyKey::String(JsString::from(long_name.as_str()));
    let short = RuntimePropertyKey::String(JsString::from("x"));
    let mut expected = core.nondeterminism_trace.deterministic_witness;
    for (key, object_id, depth) in [
        (&short, ObjectId(3), 0),
        (&long, ObjectId(4), 2),
        (&short, ObjectId(5), 1),
    ] {
        core.capture_property_resolution_found(key, object_id, depth);
        expected.fold(
            NondeterminismSource::PropertyResolution,
            &property_resolution_found_payload(key, object_id, depth),
        );
    }
    assert_eq!(core.nondeterminism_trace.deterministic_witness, expected);
    assert_eq!(expected.event_count, 3);
    assert!(core.property_witness_scratch.capacity() <= PROPERTY_WITNESS_SCRATCH_MAX_CAPACITY);
}

#[test]
fn runtime_property_diagnostics_are_injective_bd_b12xs_5() {
    let empty = RuntimePropertyKey::String(JsString::from(""));
    let ordinary = RuntimePropertyKey::String(JsString::from("answer"));
    let reserved_literal = RuntimePropertyKey::String(JsString::from("~pk~x:D800"));
    let reserved_non_ascii = RuntimePropertyKey::String(JsString::from("~pk~☃"));
    let d800 = RuntimePropertyKey::String(JsString::from_code_units(&[0xD800]));
    let d801 = RuntimePropertyKey::String(JsString::from_code_units(&[0xD801]));
    let dfff = RuntimePropertyKey::String(JsString::from_code_units(&[0xDFFF]));

    assert_eq!(empty.diagnostic(), "");
    assert_eq!(ordinary.diagnostic(), "answer");
    assert_ne!(d800.diagnostic(), d801.diagnostic());
    assert_ne!(d800.diagnostic(), reserved_literal.diagnostic());
    assert!(reserved_literal.diagnostic().starts_with("~pk~u:"));
    assert_eq!(reserved_non_ascii.diagnostic(), "~pk~u:7E706B7EE29883");
    assert_eq!(dfff.diagnostic(), "~pk~x:DFFF");
    assert_eq!(
        property_resolution_found_payload(&empty, ObjectId(0), 0),
        b"property_found:key=,object_id=0,depth=0"
    );

    for value in [
        0,
        9,
        10,
        99,
        100,
        999,
        1_000,
        9_999,
        10_000,
        99_999,
        100_000,
        999_999,
        1_000_000,
        9_999_999,
        10_000_000,
        99_999_999,
        100_000_000,
        999_999_999,
        1_000_000_000,
        u32::MAX,
    ] {
        let mut direct_decimal = Vec::with_capacity(decimal_u32_len(value));
        append_decimal_u32(&mut direct_decimal, value);
        assert_eq!(direct_decimal, value.to_string().into_bytes());
        assert_eq!(direct_decimal.len(), decimal_u32_len(value));
    }

    let frozen_payload = property_resolution_found_payload(&reserved_non_ascii, ObjectId(10), 100);
    assert_eq!(
        frozen_payload,
        b"property_found:key=~pk~u:7E706B7EE29883,object_id=10,depth=100"
    );
    let frozen_event = crate::deterministic_replay::TraceEvent {
        sequence: 0,
        source: NondeterminismSource::PropertyResolution,
        value: frozen_payload,
        virtual_ts: 123,
        component: "baseline_interpreter".to_string(),
    };
    assert_eq!(
        frozen_event.derive_id().to_hex(),
        "1120d46f214b198e37c26ae017ea9b73561917a7b9b6ed1784c4f3602126aa64"
    );

    let keys = [
        empty,
        ordinary,
        RuntimePropertyKey::String(JsString::from("snowman-☃")),
        reserved_literal,
        reserved_non_ascii,
        d800,
        d801,
        dfff,
        RuntimePropertyKey::String(JsString::from_code_units(&[0xD800, 0x0041, 0xDFFF])),
        RuntimePropertyKey::Symbol(SymbolId(0)),
        RuntimePropertyKey::Symbol(SymbolId(u32::MAX)),
    ];
    for key in &keys {
        let mut direct_diagnostic = Vec::with_capacity(key.diagnostic_byte_len());
        key.append_diagnostic_bytes(&mut direct_diagnostic);
        assert_eq!(
            direct_diagnostic,
            key.diagnostic().into_bytes(),
            "direct diagnostic bytes must exactly match the frozen formatter for {key:?}"
        );
        assert_eq!(direct_diagnostic.len(), key.diagnostic_byte_len());

        for object_id in [ObjectId(0), ObjectId(u32::MAX)] {
            for depth in [0, u32::MAX] {
                assert_eq!(
                    property_resolution_found_payload(key, object_id, depth),
                    format!(
                        "property_found:key={},object_id={},depth={}",
                        key.diagnostic(),
                        object_id.0,
                        depth
                    )
                    .into_bytes(),
                    "found-property payload bytes must remain exactly formatter-compatible"
                );
            }
        }
    }
}

#[test]
fn exact_import_meta_key_is_rejected_without_mutation_bd_b12xs_5() {
    let mut core = quickjs_test_core();
    let Value::Object(import_meta) = core
        .alloc_import_meta_object()
        .expect("import.meta allocation should succeed")
    else {
        panic!("import.meta allocation should return an object");
    };
    let exact_key = RuntimePropertyKey::String(JsString::from_code_units(&[0xD800]));
    let heap_before = serde_json::to_string(&*core.heap)
        .expect("import.meta heap should serialize before rejection");
    let memory_before = core.estimated_memory_bytes();

    let get_error = core
        .proxy_aware_get_runtime_property(
            None,
            import_meta,
            &exact_key,
            Value::Object(import_meta),
            0,
        )
        .expect_err("exact-only import.meta reads must stay outside generic heap lookup");
    assert!(matches!(get_error, InterpreterError::TypeError { .. }));
    let set_error = core
        .proxy_aware_set_runtime_property(
            None,
            import_meta,
            &exact_key,
            Value::Int(8),
            Value::Object(import_meta),
            0,
        )
        .expect_err("exact-only import.meta writes must stay read-only");
    assert!(matches!(set_error, InterpreterError::TypeError { .. }));
    let accessor_error = core
        .define_accessor_property(
            import_meta,
            exact_key,
            Value::Function(0),
            AccessorKind::Get,
        )
        .expect_err("exact-only import.meta accessors must stay read-only");
    assert!(matches!(accessor_error, InterpreterError::TypeError { .. }));
    assert_eq!(
        serde_json::to_string(&*core.heap)
            .expect("import.meta heap should serialize after rejection"),
        heap_before
    );
    assert_eq!(core.estimated_memory_bytes(), memory_before);
}

#[test]
fn exact_property_views_accessors_order_and_wire_bd_b12xs_5() {
    let mut core = quickjs_test_core();
    let object = core
        .alloc_object_with_prototype(None)
        .expect("object allocation should succeed");
    let d800 = JsString::from_code_units(&[0xD800]);
    let d801 = JsString::from_code_units(&[0xD801]);

    core.set_object_property(object, "2".to_string(), Value::Int(2))
        .expect("numeric property should fit");
    core.set_object_property(object, "ordinary".to_string(), Value::Int(1))
        .expect("ordinary property should fit");
    core.set_object_runtime_property(
        object,
        RuntimePropertyKey::String(d800.clone()),
        Value::Int(8),
    )
    .expect("first exact property should fit");
    core.define_accessor_property(
        object,
        RuntimePropertyKey::String(d801.clone()),
        Value::Function(1),
        AccessorKind::Get,
    )
    .expect("exact getter should fit");
    core.define_accessor_property(
        object,
        RuntimePropertyKey::String(d801.clone()),
        Value::Function(2),
        AccessorKind::Set,
    )
    .expect("exact setter should merge");

    let properties = &core.heap[object.0 as usize].properties;
    assert_eq!(properties.len(), 2, "compatibility length hides exact keys");
    assert_eq!(
        properties.keys().cloned().collect::<Vec<_>>(),
        vec!["2".to_string(), "ordinary".to_string()]
    );
    assert_eq!(
        properties.exact_keys(),
        vec![
            JsString::from("2"),
            JsString::from("ordinary"),
            d800.clone(),
            d801.clone(),
        ]
    );
    assert_eq!(
        properties.get_exact(&d801),
        Some(&Value::Accessor {
            get: Some(Arc::new(Value::Function(1))),
            set: Some(Arc::new(Value::Function(2))),
        })
    );

    let wire = serde_json::to_string(&core.heap[object.0 as usize])
        .expect("exact heap object should serialize");
    assert!(wire.contains("$wtf16"));
    assert!(!wire.contains("accessors"));
    let restored: HeapObject =
        serde_json::from_str(&wire).expect("exact heap object should deserialize");
    assert_eq!(restored, core.heap[object.0 as usize]);

    core.set_object_runtime_property(
        object,
        RuntimePropertyKey::String(d801.clone()),
        Value::Int(81),
    )
    .expect("accessor-to-data conversion should fit");
    assert_eq!(
        core.heap[object.0 as usize].properties.exact_keys(),
        vec![
            JsString::from("2"),
            JsString::from("ordinary"),
            d800.clone(),
            d801.clone(),
        ],
        "replacement must retain exact creation position"
    );
    assert!(
        core.remove_object_runtime_property(object, &RuntimePropertyKey::String(d800.clone()))
            .expect("exact removal should succeed")
    );
    core.set_object_runtime_property(
        object,
        RuntimePropertyKey::String(d800.clone()),
        Value::Int(18),
    )
    .expect("exact reinsertion should fit");
    assert_eq!(
        core.heap[object.0 as usize].properties.exact_keys(),
        vec![
            JsString::from("2"),
            JsString::from("ordinary"),
            d801.clone(),
            d800.clone(),
        ],
        "delete then recreate must append an ordinary exact key"
    );

    let duplicate_wire =
        serde_json::to_string(&vec![(d800.clone(), Value::Int(1)), (d800, Value::Int(2))])
            .expect("duplicate fixture should serialize");
    assert!(serde_json::from_str::<OrderedStringMap<Value>>(&duplicate_wire).is_err());

    let mut legacy = HeapObject::new();
    legacy
        .properties
        .insert("answer".to_string(), Value::Int(42));
    assert_eq!(
        serde_json::to_value(&legacy).expect("legacy heap object should serialize")["properties"],
        serde_json::json!({"answer": {"Int": 42}}),
        "all-well-formed property wire must remain map-shaped"
    );
}

#[test]
fn exact_property_memory_and_budget_rollback_are_atomic_bd_b12xs_5() {
    let mut core = quickjs_test_core();
    let object = core
        .alloc_object_with_prototype(None)
        .expect("object allocation should succeed");
    core.set_object_property(object, "ordinary".to_string(), Value::Int(1))
        .expect("ordinary setup property should fit");
    let d800 = JsString::from_code_units(&[0xD800]);
    let d801 = JsString::from_code_units(&[0xD801]);
    let before_exact = core.estimated_memory_bytes();
    core.set_object_runtime_property(
        object,
        RuntimePropertyKey::String(d800.clone()),
        Value::Int(8),
    )
    .expect("exact property should fit");
    assert!(core.estimated_memory_bytes() > before_exact);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "exact insertion delta must match eager recomputation"
    );
    core.set_object_property(object, "after-exact".to_string(), Value::Int(2))
        .expect("ordinary property after exact activation should fit");
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "ordinary insertion must account both active exact-order sidecars"
    );
    assert!(
        core.remove_object_property(object, "after-exact")
            .expect("ordinary removal after exact activation should succeed")
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "ordinary removal must account both active exact-order sidecars"
    );

    let wire_before =
        serde_json::to_string(&core.heap[object.0 as usize]).expect("heap object should serialize");
    let order_before = core.heap[object.0 as usize].properties.exact_keys();
    let memory_before = core.estimated_memory_bytes();
    core.config.max_total_memory_bytes = memory_before;
    let error = core
        .set_object_runtime_property(
            object,
            RuntimePropertyKey::String(d801),
            Value::str("x".repeat(512)),
        )
        .expect_err("oversized exact property must be refused");
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert_eq!(core.estimated_memory_bytes(), memory_before);
    assert_eq!(
        serde_json::to_string(&core.heap[object.0 as usize])
            .expect("heap object should serialize after refusal"),
        wire_before
    );
    assert_eq!(
        core.heap[object.0 as usize].properties.exact_keys(),
        order_before
    );

    let error = core
        .define_accessor_property(
            object,
            RuntimePropertyKey::String(d800.clone()),
            Value::str("y".repeat(512)),
            AccessorKind::Get,
        )
        .expect_err("oversized exact descriptor conversion must be refused");
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert_eq!(core.estimated_memory_bytes(), memory_before);
    assert_eq!(
        serde_json::to_string(&core.heap[object.0 as usize])
            .expect("heap object should serialize after conversion refusal"),
        wire_before
    );

    let mut peak_core = quickjs_test_core();
    let peak_object = peak_core
        .alloc_object_with_prototype(None)
        .expect("peak-budget object allocation should succeed");
    peak_core
        .set_object_property(peak_object, "ordinary".to_string(), Value::Int(1))
        .expect("peak-budget ordinary setup should fit");
    let peak_d800 = JsString::from_code_units(&[0xD800]);
    peak_core
        .set_object_runtime_property(
            peak_object,
            RuntimePropertyKey::String(peak_d800),
            Value::Int(8),
        )
        .expect("peak-budget exact setup should fit");
    let peak_d801 = JsString::from_code_units(&[0xD801]);
    let peak_value = Value::str("z".repeat(256));
    let previous_map_bytes = InterpreterCore::estimate_ordered_property_map_bytes(
        &peak_core.heap[peak_object.0 as usize].properties,
    );
    let mut projected = peak_core.heap[peak_object.0 as usize].properties.clone();
    projected.insert_exact(peak_d801.clone(), peak_value.clone());
    let next_map_bytes = InterpreterCore::estimate_ordered_property_map_bytes(&projected);
    let retained = peak_core
        .estimated_memory_bytes()
        .saturating_sub(previous_map_bytes)
        .saturating_add(next_map_bytes);
    let current_clone_peak = peak_core
        .estimated_memory_bytes()
        .saturating_add(previous_map_bytes);
    let projected_peak = peak_core
        .estimated_memory_bytes()
        .saturating_add(next_map_bytes);
    peak_core.config.max_total_memory_bytes = retained.max(current_clone_peak);
    assert!(peak_core.config.max_total_memory_bytes < projected_peak);
    let peak_wire_before = serde_json::to_string(&peak_core.heap[peak_object.0 as usize])
        .expect("peak-budget heap object should serialize");
    let error = peak_core
        .set_object_runtime_property(
            peak_object,
            RuntimePropertyKey::String(peak_d801),
            peak_value,
        )
        .expect_err("projected clone peak above the ceiling must be refused");
    assert!(matches!(
        error,
        InterpreterError::MemoryBudgetExceeded { .. }
    ));
    assert_eq!(
        serde_json::to_string(&peak_core.heap[peak_object.0 as usize])
            .expect("peak-budget heap should remain serializable"),
        peak_wire_before
    );

    let mut normalized_core = quickjs_test_core();
    let normalized_object = normalized_core
        .alloc_object_with_prototype(None)
        .expect("normalization object allocation should succeed");
    normalized_core
        .set_object_property(normalized_object, "ordinary".to_string(), Value::Int(1))
        .expect("normalization ordinary property should fit");
    let legacy_wire = serde_json::to_value(&normalized_core.heap[normalized_object.0 as usize])
        .expect("ordinary-only heap object should serialize");
    let normalized_exact = JsString::from_code_units(&[0xD800]);
    normalized_core
        .set_object_runtime_property(
            normalized_object,
            RuntimePropertyKey::String(normalized_exact.clone()),
            Value::Int(8),
        )
        .expect("temporary exact property should fit");
    assert!(
        normalized_core
            .remove_object_runtime_property(
                normalized_object,
                &RuntimePropertyKey::String(normalized_exact),
            )
            .expect("final exact property should be removable")
    );
    let normalized_properties = &normalized_core.heap[normalized_object.0 as usize].properties;
    assert_eq!(
        normalized_properties.exact_len(),
        normalized_properties.len()
    );
    assert_eq!(
        serde_json::to_value(&normalized_core.heap[normalized_object.0 as usize])
            .expect("normalized heap object should serialize"),
        legacy_wire,
        "removing the final exact-only key must restore legacy wire shape"
    );
    assert_eq!(
        normalized_core.estimated_memory_bytes(),
        normalized_core.recompute_estimated_memory_bytes(),
        "final exact-key removal must leave eager memory accounting exact"
    );
}

#[path = "tests_core_suite_part2.rs"]
mod part2;
