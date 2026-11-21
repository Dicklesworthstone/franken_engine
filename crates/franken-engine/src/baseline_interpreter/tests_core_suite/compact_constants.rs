use super::*;

fn assert_state_matches(compact: &InterpreterCore, baseline: &InterpreterCore) {
    assert_eq!(compact.ip, baseline.ip);
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
    assert_eq!(
        baseline.estimated_memory_bytes(),
        baseline.recompute_estimated_memory_bytes()
    );
}

#[test]
fn compact_string_constants_preserve_exact_units_in_both_lanes() {
    let strings = [
        JsString::from(""),
        JsString::from("ordinary property name"),
        JsString::from("\0\u{1f680}\u{2028}"),
        JsString::from_code_units(&[0xd800, 0x61, 0xdc00]),
    ];
    for value in strings {
        let mut module = test_module(vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::Halt,
        ]);
        module.constant_pool.push(value.clone());
        let plan = CompactTier1Program::compile(&module).expect("string-only Tier-I plan");
        assert_eq!(plan.compact_instruction_count(), 2);
        for config in [test_quickjs_config(), test_v8_config()] {
            let mut compact = InterpreterCore::new(config.clone(), "compact-constant");
            let mut baseline = InterpreterCore::new(config, "compact-constant");
            let actual = compact
                .execute_with_trace_handoff(&module, Some(&plan), TraceHandoff::RetainInCore)
                .expect("compact constant");
            let expected = baseline.execute(&module).expect("baseline constant");
            assert_execution_semantics_equal(&actual, &expected);
            assert_eq!(actual.value, Value::Str(value.clone()));
            assert_eq!(actual.tier_i_instructions_executed, 2);
            assert_state_matches(&compact, &baseline);
        }
    }
}

#[test]
fn compact_typeof_and_void_preserve_labels_and_register_aliases() {
    let values = [
        (Value::Undefined, "undefined"),
        (Value::Null, "object"),
        (Value::Bool(false), "boolean"),
        (Value::Int(42), "number"),
        (Value::Float(Float64::new(-0.0)), "number"),
        (Value::Float(Float64::new(f64::NAN)), "number"),
        (Value::BigInt(Arc::from("9007199254740993")), "bigint"),
        (Value::Str(JsString::from_code_units(&[0xd800])), "string"),
        (Value::Symbol(SymbolId(1)), "symbol"),
        (Value::Function(0), "function"),
    ];
    for (value, typeof_name) in values {
        for dst in [0, 1] {
            for is_void in [false, true] {
                let instruction = if is_void {
                    Ir3Instruction::Void { dst, src: 1 }
                } else {
                    Ir3Instruction::TypeOf { dst, src: 1 }
                };
                let module = test_module(vec![instruction, Ir3Instruction::Return { value: dst }]);
                let plan = CompactTier1Program::compile(&module).expect("unary Tier-I plan");
                for label in [
                    Label::Public,
                    Label::Secret,
                    Label::Custom {
                        name: "source-provenance".to_string(),
                        level: 3,
                    },
                ] {
                    let make_core = || {
                        let mut core = quickjs_test_core();
                        core.set_reg(1, value.clone());
                        core.set_register_label(1, label.clone())
                            .expect("source label");
                        core.sync_estimated_memory_bytes()
                            .expect("fixture accounting");
                        core
                    };
                    let mut compact = make_core();
                    let mut baseline = make_core();
                    let actual = compact
                        .run_loop_labeled_with_compact_tier1(&module, Some(&plan))
                        .expect("compact unary");
                    let expected = baseline.run_loop_labeled(&module).expect("baseline unary");
                    assert_eq!(actual.value, expected.value);
                    assert_eq!(actual.label, expected.label);
                    assert_eq!(actual.label, label);
                    assert_eq!(
                        actual.value,
                        if is_void {
                            Value::Undefined
                        } else {
                            Value::str(typeof_name)
                        }
                    );
                    assert_eq!(compact.tier_i_instructions_executed, 1);
                    assert_state_matches(&compact, &baseline);
                }
            }
        }
    }
}

#[test]
fn compact_constant_failures_keep_error_order_and_state() {
    // A malformed pool index must be reported before an invalid destination,
    // while typeof/void preserve the canonical source-label/read error order.
    let max = test_quickjs_config().max_registers;
    let cases = [
        Ir3Instruction::LoadStr {
            dst: 0,
            pool_index: 7,
        },
        Ir3Instruction::LoadStr {
            dst: max,
            pool_index: 7,
        },
        Ir3Instruction::LoadStr {
            dst: max,
            pool_index: 0,
        },
        Ir3Instruction::TypeOf { dst: 0, src: max },
        Ir3Instruction::Void { dst: 0, src: max },
        Ir3Instruction::TypeOf { dst: max, src: 0 },
        Ir3Instruction::Void { dst: max, src: 0 },
    ];
    for instruction in cases {
        let module = test_module_with_pool(
            vec![instruction, Ir3Instruction::Halt],
            vec!["x".to_string()],
        );
        let plan = CompactTier1Program::compile(&module).expect("error-path Tier-I plan");
        let mut compact = quickjs_test_core();
        let mut baseline = quickjs_test_core();
        let actual = compact
            .run_loop_labeled_with_compact_tier1(&module, Some(&plan))
            .expect_err("invalid operand");
        let expected = baseline
            .run_loop_labeled(&module)
            .expect_err("invalid operand");
        assert_eq!(actual, expected);
        assert_eq!(compact.tier_i_instructions_executed, 1);
        assert_state_matches(&compact, &baseline);
    }
}

#[test]
fn compact_string_and_typeof_writes_preserve_memory_refusal_and_live_seed() {
    for typeof_source in [false, true] {
        for refuse in [false, true] {
            let instruction = if typeof_source {
                Ir3Instruction::TypeOf { dst: 0, src: 1 }
            } else {
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                }
            };
            let module = test_module_with_pool(
                vec![instruction, Ir3Instruction::Return { value: 0 }],
                vec!["a sufficiently long property constant".to_string()],
            );
            let plan = CompactTier1Program::compile(&module).expect("accounted Tier-I plan");
            let make_core = || {
                let mut core = quickjs_test_core();
                core.set_reg(1, Value::Int(17));
                core.sync_estimated_memory_bytes()
                    .expect("fixture accounting");
                let seed = core.capture_execution_seed().expect("live seed");
                if refuse {
                    core.config.max_total_memory_bytes = core.estimated_memory_bytes();
                }
                (core, seed)
            };
            let (mut compact, compact_seed) = make_core();
            let (mut baseline, baseline_seed) = make_core();
            let before = compact.registers.value.clone();
            let actual = compact.run_loop_labeled_with_compact_tier1(&module, Some(&plan));
            let expected = baseline.run_loop_labeled(&module);
            match (actual, expected) {
                (Err(actual), Err(expected)) if refuse => {
                    assert_eq!(actual, expected);
                    assert!(matches!(
                        actual,
                        InterpreterError::MemoryBudgetExceeded { .. }
                    ));
                    assert_eq!(compact.registers.value, before);
                }
                (Ok(actual), Ok(expected)) if !refuse => {
                    assert_eq!(actual.value, expected.value);
                    assert_eq!(actual.label, expected.label);
                    for seed in [&compact_seed, &baseline_seed] {
                        seed.inspect(|state| match state {
                            ExecutionSeed::Materialized { registers, .. } => {
                                assert_eq!(registers, &before)
                            }
                            ExecutionSeed::Lazy { .. } => {
                                panic!("write must preserve the pre-write seed")
                            }
                        });
                    }
                }
                _ => panic!("Tier-I memory boundary differs"),
            }
            assert_eq!(
                compact.live_execution_seed_reserved_bytes(),
                baseline.live_execution_seed_reserved_bytes()
            );
            assert_state_matches(&compact, &baseline);
        }
    }
}

#[test]
fn compact_string_loop_preserves_exact_budget_and_cancellation_boundaries() {
    let module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::TypeOf { dst: 1, src: 0 },
            Ir3Instruction::Void { dst: 0, src: 0 },
            Ir3Instruction::Jump { target: 0 },
        ],
        vec!["property".to_string()],
    );
    let plan = CompactTier1Program::compile(&module).expect("compact constant loop");
    assert_eq!(plan.compact_instruction_count(), 4);
    assert!(
        plan.loop_quantum_at(0).is_some(),
        "string constants no longer split a compact loop"
    );
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
            let mut compact = InterpreterCore::new(config.clone(), "constant-boundary");
            let mut baseline = InterpreterCore::new(config, "constant-boundary");
            let actual = compact
                .run_loop_labeled_with_compact_tier1(&module, Some(&plan))
                .expect_err("bounded loop");
            let expected = baseline
                .run_loop_labeled(&module)
                .expect_err("bounded loop");
            assert_eq!(actual, expected);
            assert_state_matches(&compact, &baseline);
        }
    }
}
