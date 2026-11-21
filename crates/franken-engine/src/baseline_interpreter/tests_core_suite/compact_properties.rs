use super::*;

fn ordinary_read_core(config: InterpreterConfig) -> (InterpreterCore, ObjectId) {
    let mut core = InterpreterCore::new(config, "compact-property");
    let object = core
        .alloc_object_with_properties(&[("data", Value::Int(41))])
        .expect("ordinary object");
    core.set_reg(1, Value::Object(object));
    core.set_reg(2, Value::str("data"));
    core.sync_estimated_memory_bytes()
        .expect("fixture accounting");
    (core, object)
}

fn read_module(dst: u32) -> Ir3Module {
    test_module(vec![
        Ir3Instruction::GetProperty {
            obj: 1,
            key: 2,
            dst,
        },
        Ir3Instruction::Return { value: dst },
    ])
}

fn assert_property_state_matches(compact: &InterpreterCore, baseline: &InterpreterCore) {
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
        compact.pending_hostcall_result_label,
        baseline.pending_hostcall_result_label
    );
    assert_eq!(
        compact.legacy_regexp_read_label,
        baseline.legacy_regexp_read_label
    );
    assert_eq!(
        compact.active_inline_callback_context_label,
        baseline.active_inline_callback_context_label
    );
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

fn assert_property_outcomes_match(
    actual: Result<LabeledReturn, InterpreterError>,
    expected: Result<LabeledReturn, InterpreterError>,
) {
    match (actual, expected) {
        (Ok(actual), Ok(expected)) => {
            assert_eq!(actual.value, expected.value);
            assert_eq!(actual.label, expected.label);
        }
        (Err(actual), Err(expected)) => assert_eq!(actual, expected),
        (actual, expected) => panic!("property outcomes differ: {actual:?}, {expected:?}"),
    }
}

#[test]
fn compact_own_property_reads_preserve_exact_keys_values_and_aliases_in_both_lanes() {
    let keys = [
        JsString::from("data"),
        JsString::from_code_units(&[0xd800, 0x61]),
    ];
    let values = [
        Value::Undefined,
        Value::Null,
        Value::Bool(false),
        Value::Int(41),
        Value::Float(Float64::new(-0.0)),
        Value::Float(Float64::new(f64::NAN)),
        Value::Function(0),
        Value::Symbol(SymbolId(7)),
    ];
    for key in keys {
        for value in &values {
            // An aliased receiver remains static. Replacing the owned key
            // string must use the accounted Tier-R write instead.
            for dst in [0, 1, 2] {
                let module = read_module(dst);
                let plan = CompactTier1Program::compile(&module).expect("property plan");
                for config in [test_quickjs_config(), test_v8_config()] {
                    let make_core = || {
                        let (mut core, object) = ordinary_read_core(config.clone());
                        let prototype = core
                            .alloc_object_with_properties(&[("inherited", Value::Int(99))])
                            .expect("prototype");
                        core.mutate_heap(|heap| {
                            heap[object.0 as usize].prototype = Some(prototype);
                        });
                        core.set_object_runtime_property(
                            object,
                            RuntimePropertyKey::String(key.clone()),
                            value.clone(),
                        )
                        .expect("exact own property");
                        core.set_reg(2, Value::Str(key.clone()));
                        core.sync_estimated_memory_bytes()
                            .expect("fixture accounting");
                        core
                    };
                    let mut compact = make_core();
                    let mut baseline = make_core();
                    let actual = compact
                        .run_loop_labeled_with_compact_tier1(&module, Some(&plan))
                        .expect("compact property");
                    let expected = baseline.run_loop_labeled(&module).expect("Tier-R property");
                    assert_eq!(&actual.value, value);
                    assert_eq!(actual.value, expected.value);
                    assert_eq!(actual.label, Label::Public);
                    assert_eq!(actual.label, expected.label);
                    assert_eq!(
                        compact.tier_i_specialized_instructions_executed,
                        u64::from(dst != 2)
                    );
                    assert_property_state_matches(&compact, &baseline);
                }
            }
        }
    }
}

#[test]
fn compact_own_property_reads_fall_back_before_observable_or_accounted_work() {
    let cases = [
        "receiver label",
        "key label",
        "stored label",
        "seeded destination",
        "owned destination",
        "string result",
        "bigint result",
        "accessor",
        "closure definition",
        "public callback",
        "secret callback",
        "pending provenance",
        "legacy provenance",
        "missing",
        "inherited",
        "proto accessor",
        "proxy",
        "wrapper",
    ];
    let module = read_module(0);
    let plan = CompactTier1Program::compile(&module).expect("property plan");
    let cell = plan.instruction_at(0).expect("property cell");
    for case in cases {
        let make_core = || {
            let (mut core, object) = ordinary_read_core(test_quickjs_config());
            match case {
                "receiver label" => core.set_register_label(1, Label::Secret).unwrap(),
                "key label" => core.set_register_label(2, Label::Confidential).unwrap(),
                "stored label" => core
                    .set_own_property_label(object, "data", &Label::Secret)
                    .unwrap(),
                "seeded destination" => core
                    .set_register_label(
                        0,
                        Label::Custom {
                            name: "destination provenance".to_string(),
                            level: 3,
                        },
                    )
                    .unwrap(),
                "owned destination" => core.set_reg(0, Value::str("previous owned value")),
                "string result" => core
                    .set_object_property(object, "data".to_string(), Value::str("value"))
                    .unwrap(),
                "bigint result" => core
                    .set_object_property(
                        object,
                        "data".to_string(),
                        Value::BigInt(Arc::from("9007199254740993")),
                    )
                    .unwrap(),
                "accessor" => core
                    .set_object_property(
                        object,
                        "data".to_string(),
                        Value::Accessor {
                            get: None,
                            set: None,
                        },
                    )
                    .unwrap(),
                "closure definition" => {
                    core.set_object_property(object, "data".to_string(), Value::Closure(0))
                        .unwrap();
                    core.closure_method_metadata.insert(
                        0,
                        ClosureMethodMetadata {
                            home_object: object,
                            name: JsString::from("data"),
                            definition_label: Label::Secret,
                        },
                    );
                }
                "public callback" => {
                    core.active_inline_callback_context_label = Some(Label::Public)
                }
                "secret callback" => {
                    core.active_inline_callback_context_label = Some(Label::Secret)
                }
                "pending provenance" => core
                    .replace_pending_hostcall_result_label(Some(Label::Secret))
                    .unwrap(),
                "legacy provenance" => core.legacy_regexp_read_label = Some(Label::Secret),
                "missing" => core.set_reg(2, Value::str("absent")),
                "inherited" => {
                    let prototype = core
                        .alloc_object_with_properties(&[("inherited", Value::Int(73))])
                        .unwrap();
                    core.mutate_heap(|heap| heap[object.0 as usize].prototype = Some(prototype));
                    core.set_reg(2, Value::str("inherited"));
                }
                "proto accessor" => core.set_reg(2, Value::str("__proto__")),
                "proxy" => core.set_object_brand(object, PROXY_TYPE_TAG).unwrap(),
                "wrapper" => core.mutate_heap(|heap| {
                    heap[object.0 as usize].primitive_value = Some(Value::str("wrapped"))
                }),
                _ => unreachable!(),
            }
            core.sync_estimated_memory_bytes()
                .expect("fallback accounting");
            core
        };
        let mut compact = make_core();
        let mut baseline = make_core();
        let before_epoch = compact.seed_epoch;
        let before_memory = compact.estimated_memory_bytes();
        let before_trace = compact.nondeterminism_trace.clone();
        assert!(compact.compact_instruction_needs_baseline(&cell), "{case}");
        assert_eq!(
            compact.seed_epoch, before_epoch,
            "guard must be read-only: {case}"
        );
        assert_eq!(compact.estimated_memory_bytes(), before_memory);
        assert_eq!(compact.nondeterminism_trace, before_trace);
        let actual = compact.run_loop_labeled_with_compact_tier1(&module, Some(&plan));
        let expected = baseline.run_loop_labeled(&module);
        assert_property_outcomes_match(actual, expected);
        assert_eq!(
            compact.tier_i_specialized_instructions_executed, 0,
            "{case}"
        );
        assert_eq!(compact.tier_i_instructions_executed, 0, "{case}");
        assert_property_state_matches(&compact, &baseline);
    }
}

#[test]
fn compact_own_property_reads_keep_hooks_and_denials_exact() {
    let module = read_module(0);
    let plan = CompactTier1Program::compile(&module).expect("property plan");
    for action in [
        HookAction::Allow,
        HookAction::Terminate("property denied".to_string()),
    ] {
        let make_core = || {
            let (mut core, _) = ordinary_read_core(test_quickjs_config());
            let hook = Arc::new(RecordingHook {
                property_action: action.clone(),
                ..RecordingHook::allow_all()
            });
            core.set_hook(hook.clone());
            (core, hook)
        };
        let (mut compact, compact_hook) = make_core();
        let (mut baseline, baseline_hook) = make_core();
        let actual = compact.run_loop_labeled_with_compact_tier1(&module, Some(&plan));
        let expected = baseline.run_loop_labeled(&module);
        assert_property_outcomes_match(actual, expected);
        assert_eq!(compact_hook.records(), baseline_hook.records());
        assert_eq!(
            compact_hook.records().len(),
            1,
            "one property decision per read"
        );
        assert_eq!(compact.tier_i_instructions_executed, 0);
        assert_property_state_matches(&compact, &baseline);
    }
}

#[test]
fn compact_own_property_reads_preserve_memory_refusal_and_live_seed() {
    let module = read_module(1);
    let plan = CompactTier1Program::compile(&module).expect("property plan");
    for over_budget in [false, true] {
        let make_core = || {
            let (mut core, _) = ordinary_read_core(test_quickjs_config());
            let seed = core.capture_execution_seed().expect("live seed");
            core.config.max_total_memory_bytes = core
                .estimated_memory_bytes()
                .saturating_sub(u64::from(over_budget));
            (core, seed)
        };
        let (mut compact, compact_seed) = make_core();
        let (mut baseline, baseline_seed) = make_core();
        let before_registers = compact.registers.value.clone();
        let before_epoch = compact.seed_epoch;
        let actual = compact.run_loop_labeled_with_compact_tier1(&module, Some(&plan));
        let expected = baseline.run_loop_labeled(&module);
        if over_budget {
            assert!(matches!(
                actual,
                Err(InterpreterError::MemoryBudgetExceeded { .. })
            ));
            assert_eq!(compact.registers.value, before_registers);
            assert_eq!(compact.seed_epoch, before_epoch);
            assert_eq!(compact.tier_i_specialized_instructions_executed, 0);
        } else {
            assert_eq!(compact.tier_i_specialized_instructions_executed, 1);
            for seed in [&compact_seed, &baseline_seed] {
                seed.inspect(|state| match state {
                    ExecutionSeed::Materialized { registers, .. } => {
                        assert_eq!(registers, &before_registers)
                    }
                    ExecutionSeed::Lazy { .. } => {
                        panic!("property write must retain the pre-write seed")
                    }
                });
            }
        }
        assert_property_outcomes_match(actual, expected);
        assert_property_state_matches(&compact, &baseline);
        assert_eq!(
            compact.live_execution_seed_reserved_bytes(),
            baseline.live_execution_seed_reserved_bytes()
        );
    }
}

#[test]
fn compact_property_loop_keeps_budget_and_cancellation_boundaries() {
    let module = test_module(vec![
        Ir3Instruction::GetProperty {
            obj: 1,
            key: 2,
            dst: 0,
        },
        Ir3Instruction::Jump { target: 0 },
    ]);
    let plan = CompactTier1Program::compile(&module).expect("property loop plan");
    for cancelled in [false, true] {
        for budget in 0..=13 {
            let mut config = test_quickjs_config();
            config.instruction_budget = budget;
            config.checkpoint_density = 3;
            if cancelled {
                let token = CancellationToken::new();
                token.cancel();
                config.cancellation_token = Some(token);
            }
            let (mut compact, _) = ordinary_read_core(config.clone());
            let (mut baseline, _) = ordinary_read_core(config);
            let actual = compact.run_loop_labeled_with_compact_tier1(&module, Some(&plan));
            let expected = baseline.run_loop_labeled(&module);
            assert!(actual.is_err(), "loop must terminate at its boundary");
            assert_property_outcomes_match(actual, expected);
            assert_property_state_matches(&compact, &baseline);
        }
    }
}

#[test]
fn compact_property_guards_recheck_receivers_inside_blocks_and_loops() {
    for is_loop in [false, true] {
        let module = if is_loop {
            test_module(vec![
                Ir3Instruction::GetProperty {
                    obj: 1,
                    key: 2,
                    dst: 0,
                },
                Ir3Instruction::Move { dst: 1, src: 3 },
                Ir3Instruction::Jump { target: 0 },
            ])
        } else {
            test_module(vec![
                Ir3Instruction::GetProperty {
                    obj: 1,
                    key: 2,
                    dst: 1,
                },
                Ir3Instruction::GetProperty {
                    obj: 1,
                    key: 2,
                    dst: 0,
                },
                Ir3Instruction::Return { value: 0 },
            ])
        };
        let plan = CompactTier1Program::compile(&module).expect("changing-receiver plan");
        let make_core = || {
            let (mut core, object) = ordinary_read_core(test_quickjs_config());
            if is_loop {
                let accessor = core
                    .alloc_object_with_properties(&[(
                        "data",
                        Value::Accessor {
                            get: None,
                            set: None,
                        },
                    )])
                    .expect("fallback receiver");
                core.set_reg(3, Value::Object(accessor));
                core.config.instruction_budget = 11;
            } else {
                core.set_object_property(object, "data".to_string(), Value::Null)
                    .expect("receiver-overwriting value");
            }
            core.sync_estimated_memory_bytes()
                .expect("fixture accounting");
            core
        };
        let mut compact = make_core();
        let mut baseline = make_core();
        let actual = compact.run_loop_labeled_with_compact_tier1(&module, Some(&plan));
        let expected = baseline.run_loop_labeled(&module);
        assert!(
            actual.is_err(),
            "invalid receiver or loop budget must stop execution"
        );
        assert_property_outcomes_match(actual, expected);
        assert_eq!(compact.tier_i_specialized_instructions_executed, 1);
        assert_property_state_matches(&compact, &baseline);
    }
}

#[test]
fn compact_property_fallbacks_in_real_programs_run_guest_effects_once() {
    let cases = [
        (
            "let calls = 0; const o = {get x() { calls++; return 7; }}; let total = 0; for (let i = 0; i < 4; i++) total += o.x; console.log(total, calls);",
            "28 4",
        ),
        (
            "let calls = 0; const o = new Proxy({x: 7}, {get(target, key) { calls++; return target[key] + 1; }}); let total = 0; for (let i = 0; i < 4; i++) total += o.x; console.log(total, calls);",
            "32 4",
        ),
        (
            "let calls = 0; const o = {x: 3}; let total = 0; for (let i = 0; i < 4; i++) { if (i === 1) Object.defineProperty(o, 'x', {get() { calls++; return 7; }}); total += o.x; } console.log(total, calls);",
            "24 3",
        ),
        (
            "let calls = 0; const key = {toString() { calls++; return 'x'; }}; const o = Object.create({x: 9}); let total = 0; for (let i = 0; i < 4; i++) total += o[key]; console.log(total, calls);",
            "36 4",
        ),
        (
            "let calls = 0; const o = {get x() { calls++; throw 11; }}; let caught = 0; for (let i = 0; i < 3; i++) { try { o.x; } catch (e) { caught += e; } } console.log(caught, calls);",
            "33 3",
        ),
        (
            "const o = {x: 3, method() { return this.x; }}; const method = o.method; console.log(method.call(o));",
            "3",
        ),
    ];
    for (source, output) in cases {
        let module = lower_symbol_source_bd_n8eta_4_2(source);
        let plan = CompactTier1Program::compile(&module).expect("source property plan");
        for config in [test_quickjs_config(), test_v8_config()] {
            let mut compact = InterpreterCore::new(config.clone(), "compact-property-source");
            let mut baseline = InterpreterCore::new(config, "compact-property-source");
            let actual = compact
                .execute_with_trace_handoff(&module, Some(&plan), TraceHandoff::RetainInCore)
                .expect("compact source");
            let expected = baseline.execute(&module).expect("Tier-R source");
            assert_eq!(actual.console_output, vec![output.to_string()], "{source}");
            assert_execution_semantics_equal(&actual, &expected);
            assert_property_state_matches(&compact, &baseline);
        }
    }
}
