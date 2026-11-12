#[allow(unused_imports)]
use super::*;

#[cfg(test)]
mod class_feature_bd_bg9l1_16_tests {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::baseline_interpreter::*;

    fn eval_class_source(source: &str) -> Result<String, String> {
        let mut engine = crate::HybridRouter::default();
        engine
            .eval(source)
            .map(|outcome| outcome.value)
            .map_err(|error| error.to_string())
    }

    #[test]
    fn execution_rejects_unsupported_ir_schema_before_dispatch_bd_ppfz7() {
        for schema_version in [
            crate::ir_contract::IrSchemaVersion {
                major: 0,
                minor: crate::ir_contract::IrSchemaVersion::CURRENT.minor + 1,
                patch: 0,
            },
            crate::ir_contract::IrSchemaVersion {
                major: 0,
                minor: 11,
                patch: 0,
            },
        ] {
            let mut module = Ir3Module::new(
                ContentHash::compute(b"unsupported-engine-ir"),
                "unsupported-engine-ir.js",
            );
            module.header.schema_version = schema_version;
            module.instructions = vec![Ir3Instruction::Halt];

            let mut core = InterpreterCore::new(
                InterpreterConfig::quickjs_defaults(),
                "unsupported-engine-ir",
            );
            let initial_events = core.events.len();
            let initial_memory = core.estimated_memory_bytes();
            let error = core
                .execute(&module)
                .expect_err("unsupported IR schema must reject before dispatch");
            assert!(matches!(
                error,
                InterpreterError::TypeError { expected, got }
                    if expected.contains("structurally valid engine IR3")
                        && got.contains("IR_SCHEMA_VERSION_MISMATCH")
            ));
            assert_eq!(core.instructions_executed, 0);
            assert_eq!(core.events.len(), initial_events);
            assert_eq!(core.estimated_memory_bytes(), initial_memory);
            assert!(core.entry_module_specifier.is_none());
        }
    }

    #[test]
    fn super_call_constructs_parent_and_initializes_this_bd_ppfz7() {
        let value = eval_class_source(concat!(
            "class Parent { constructor(){ this.base = 41; } }\n",
            "class Child extends Parent { constructor(){ super(); this.answer = this.base + 1; } }\n",
            "let child = new Child(); child.answer;\n",
        ))
        .expect("super() must construct the parent and initialize the derived this binding");
        assert_eq!(value, "42");
    }

    #[test]
    fn derived_constructor_completion_matrix_bd_ppfz7() {
        for (case, source, expected) in [
            (
                "explicit object without super",
                "class Base {} class Child extends Base { constructor(){ return { value: 7 }; } } new Child().value;",
                "7",
            ),
            (
                "primitive without super",
                "class Base {} class Child extends Base { constructor(){ return 7; } } let kind; try { new Child(); } catch (error) { kind = error.name; } kind;",
                "TypeError",
            ),
            (
                "undefined without super",
                "class Base {} class Child extends Base { constructor(){ return undefined; } } let kind; try { new Child(); } catch (error) { kind = error.name; } kind;",
                "ReferenceError",
            ),
            (
                "fallthrough without super",
                "class Base {} class Child extends Base { constructor(){} } let kind; try { new Child(); } catch (error) { kind = error.name; } kind;",
                "ReferenceError",
            ),
            (
                "primitive after super",
                "class Base {} class Child extends Base { constructor(){ super(); return 7; } } let kind; try { new Child(); } catch (error) { kind = error.name; } kind;",
                "TypeError",
            ),
            (
                "primitive return through finally",
                "class Base {} class Child extends Base { constructor(){ super(); try { return 7; } finally {} } } let kind; try { new Child(); } catch (error) { kind = error.name; } kind;",
                "TypeError",
            ),
            (
                "guest instance marker collision cannot declassify a derived constructor",
                "class Base {} class Child extends Base { __franken_ir_derived_constructor__(){ return false; } constructor(){ return 7; } } let kind; try { new Child(); } catch (error) { kind = error.name; } kind;",
                "TypeError",
            ),
            (
                "undefined after super",
                "class Base { constructor(){ this.value = 8; } } class Child extends Base { constructor(){ super(); return undefined; } } new Child().value;",
                "8",
            ),
            (
                "fallthrough after super",
                "class Base { constructor(){ this.value = 9; } } class Child extends Base { constructor(){ super(); } } new Child().value;",
                "9",
            ),
        ] {
            assert_eq!(
                eval_class_source(source)
                    .unwrap_or_else(|error| panic!("{case} should execute: {error}")),
                expected,
                "derived constructor completion mismatch for {case}",
            );
        }
    }

    #[test]
    fn base_constructor_completion_matrix_bd_ppfz7() {
        for (case, source, expected) in [
            (
                "explicit object",
                "class Base { constructor(){ return { value: 7 }; } } new Base().value;",
                "7",
            ),
            (
                "primitive falls back to allocated this",
                "class Base { constructor(){ return 7; } } new Base() instanceof Base;",
                "true",
            ),
            (
                "undefined falls back to allocated this",
                "class Base { constructor(){ return undefined; } } new Base() instanceof Base;",
                "true",
            ),
            (
                "fallthrough falls back to allocated this",
                "class Base { constructor(){} } new Base() instanceof Base;",
                "true",
            ),
        ] {
            assert_eq!(
                eval_class_source(source)
                    .unwrap_or_else(|error| panic!("{case} should execute: {error}")),
                expected,
                "base constructor completion mismatch for {case}",
            );
        }
    }

    #[test]
    fn derived_construction_forwards_and_preserves_new_target_bd_ppfz7() {
        for (case, source, expected) in [
            (
                "default constructor forwards every argument",
                "class Base { constructor(left, right){ this.total = left + right; } } class Child extends Base {} new Child(20, 22).total;",
                "42",
            ),
            (
                "parent replacement object becomes derived result",
                "class Base { constructor(){ return { value: 42 }; } } class Child extends Base { constructor(){ super(); } } new Child().value;",
                "42",
            ),
            (
                "parent observes child new.target",
                "class Base { constructor(){ this.target = new.target; } } class Child extends Base { constructor(){ super(); } } new Child().target === Child;",
                "true",
            ),
            (
                "class expression has matching super semantics",
                "class Base { constructor(value){ this.value = value; } } let Child = class extends Base { constructor(value){ super(value); } }; new Child(42).value;",
                "42",
            ),
            (
                "default class expression forwards every argument",
                "class Base { constructor(left, right){ this.total = left + right; } } let Child = class extends Base {}; new Child(20, 22).total;",
                "42",
            ),
            (
                "repeated class expressions retain distinct parent constructors",
                "class A { constructor(){ this.value = 1; } } class B { constructor(){ this.value = 2; } } function make(Parent){ return class extends Parent {}; } let First = make(A); let Second = make(B); new First().value * 10 + new Second().value;",
                "12",
            ),
        ] {
            assert_eq!(
                eval_class_source(source)
                    .unwrap_or_else(|error| panic!("{case} should execute: {error}")),
                expected,
                "derived construction mismatch for {case}",
            );
        }
    }

    /// `super.method()` calls the parent's method (Node: 42). This test once
    /// pinned the refusal from before super property lowering existed.
    #[test]
    fn super_method_calls_the_parent_method() {
        let value = eval_class_source(concat!(
            "class Parent { value(){ return 40; } }\n",
            "class Child extends Parent { value(){ return super.value() + 2; } }\n",
            "let child = new Child(); child.value();\n",
        ))
        .expect("super.method() calls the parent's method");
        assert_eq!(value, "42");
    }

    /// A static method is a property of the constructor (Node: "static
    /// called"). This test once pinned the refusal from before constructor
    /// properties existed.
    #[test]
    fn static_method_on_constructor_is_callable() {
        let value = eval_class_source(concat!(
            "class TestClass { static staticMethod(){ return \"static called\"; } }\n",
            "TestClass.staticMethod();\n",
        ))
        .expect("a static method is callable on its class");
        assert_eq!(value, "static called");
    }

    #[test]
    fn computed_string_literal_method_name_executes() {
        let value = eval_class_source(concat!(
            "class WithComputed { [\"answer\"](){ return 42; } }\n",
            "let value = new WithComputed(); value.answer();\n",
        ))
        .expect("computed string-literal method names must lower to their static property key");
        assert_eq!(value, "42");
    }

    #[test]
    fn getter_setter_invokes_accessors_and_preserves_instance_state() {
        let value = eval_class_source(concat!(
            "class Box { set value(next){ this.raw = next; } get value(){ return this.raw + 1; } }\n",
            "let box = new Box(); box.value = 42; box.value;\n",
        ))
        .expect("class getter/setter accessors must invoke functions from real source");
        assert_eq!(value, "43");
    }

    #[test]
    fn class_expression_constructs_and_preserves_instance_state() {
        let value = eval_class_source(concat!(
            "let Widget = class { constructor(){ this.answer = 42; } };\n",
            "let widget = new Widget(); widget.answer;\n",
        ))
        .expect("class expressions must construct instances from real source");
        assert_eq!(value, "42");
    }

    #[test]
    fn constructor_preserves_explicit_object_like_returns_bd_ptu9m() {
        let value = eval_class_source(concat!(
            "let callable = function(){ return 7; };\n",
            "let promise = Promise.resolve(9);\n",
            "let builtin = Array.isArray;\n",
            "function* make(){ yield 1; } let generator = make();\n",
            "function ReturnCallable(){ return callable; }\n",
            "function ReturnPromise(){ return promise; }\n",
            "function ReturnBuiltin(){ return builtin; }\n",
            "function ReturnGenerator(){ return generator; }\n",
            "new ReturnCallable() === callable && ",
            "new ReturnPromise() === promise && ",
            "new ReturnBuiltin() === builtin && ",
            "new ReturnGenerator() === generator;",
        ))
        .expect("constructors must preserve explicit ECMAScript object-like returns");
        assert_eq!(value, "true");
    }

    #[test]
    fn constructor_primitive_return_keeps_allocated_instance_bd_ptu9m() {
        let value = eval_class_source(concat!(
            "function KeepThis(){ this.value = 4; return 7; }\n",
            "let instance = new KeepThis(); instance.value === 4;",
        ))
        .expect("a primitive constructor return must fall back to the allocated instance");
        assert_eq!(value, "true");
    }

    #[test]
    fn new_target_reports_constructor_in_constructor_body() {
        let value = eval_class_source(concat!(
            "class TargetProbe { constructor(){ this.target = typeof new.target; } }\n",
            "let probe = new TargetProbe(); probe.target;\n",
        ))
        .expect("new.target should evaluate inside constructor bodies");
        assert_eq!(value, "function");
    }
}

// ---------------------------------------------------------------------------
// PERF-H2.3: Unit tests for lazy seed write tracking (bd-o4cbn.6.3)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod lazy_seed_tests {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::baseline_interpreter::*;

    fn test_core() -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.max_registers = 32;
        InterpreterCore::new(config, "lazy-seed-test")
    }

    fn test_core_with_registers(regs: Vec<Value>) -> InterpreterCore {
        let mut core = test_core();
        core.mutate_registers(|r| *r = regs);
        core
    }

    fn static_register_write_core() -> InterpreterCore {
        let mut core = test_core_with_registers(vec![Value::Int(1)]);
        core.register_labels[0] = Label::Internal;
        core.all_register_labels_public = false;
        core.sync_estimated_memory_bytes()
            .expect("static register-write fixture must fit");
        core
    }

    fn push_plain_test_call_frame(core: &mut InterpreterCore) {
        let saved_scope_depth = core.scope_chain.depth();
        core.scope_chain
            .push(core.config.max_scope_depth)
            .expect("plain call-frame local scope must fit");
        let pushed_frame = CallFrame {
            return_ip: 1,
            return_reg: 0,
            register_base: 0,
            register_width: core.config.max_registers as usize,
            function_index: Some(1),
            this_value: Value::Undefined,
            this_label: Label::Public,
            new_target_value: Value::Undefined,
            new_target_label: Label::Public,
            super_value: Value::Undefined,
            super_label: Label::Public,
            super_home_object: None,
            construct_this: None,
            derived_constructor: false,
            this_initialized: true,
            initialize_derived_this_on_return: false,
            class_instance_fields: None,
            saved_pending_exception: None,
            saved_pending_exception_label: Label::Public,
            saved_pending_return: None,
            saved_suspended_abrupt_depth: 0,
            saved_finally_mode_depth: 0,
            saved_scope_depth,
            saved_scope_chain: None,
            scope_inert_virtual_scope_bytes: 0,
            async_function_id: None,
            native_boundary: false,
        };
        core.call_stack
            .push(pushed_frame, &mut core.closures.cold_cells);
        core.sync_estimated_memory_bytes()
            .expect("plain call-frame fixture must fit");
    }

    fn capture_execution_seed_eager_for_test(core: &mut InterpreterCore) -> ExecutionSeedHandle {
        let seed = core
            .capture_execution_seed()
            .expect("eager test execution-seed capture must fit");
        core.materialize_pending_lazy_seeds_with_current_state();
        seed
    }

    #[test]
    fn static_register_write_matches_accounted_path_and_seed_state() {
        let mut fast = static_register_write_core();
        let mut accounted = static_register_write_core();
        let fast_seed = fast
            .capture_execution_seed()
            .expect("fast-path seed reservation must fit");
        let accounted_seed = accounted
            .capture_execution_seed()
            .expect("accounted-path seed reservation must fit");
        let fast_epoch_before = fast.seed_epoch;
        let accounted_epoch_before = accounted.seed_epoch;

        assert!(fast.static_register_write_eligible(0, &Value::Int(9), &Label::Secret));
        fast.write_reg_with_label(0, Value::Int(9), Label::Secret)
            .expect("eligible static write must succeed");
        accounted
            .write_reg_with_label_accounted(0, Value::Int(9), Label::Secret)
            .expect("reference accounted write must succeed");

        assert_eq!(fast.registers.value, accounted.registers.value);
        assert_eq!(fast.register_labels, accounted.register_labels);
        assert_eq!(fast.register_labels[0], Label::Secret);
        assert_eq!(
            fast.estimated_memory_bytes,
            accounted.estimated_memory_bytes
        );
        assert_eq!(
            fast.live_execution_seed_reserved_bytes(),
            accounted.live_execution_seed_reserved_bytes()
        );
        assert_eq!(fast.seed_epoch, fast_epoch_before.wrapping_add(1));
        assert_eq!(accounted.seed_epoch, accounted_epoch_before.wrapping_add(1));
        assert_eq!(fast.seed_epoch, accounted.seed_epoch);
        assert_eq!(
            fast.estimated_memory_bytes(),
            fast.recompute_estimated_memory_bytes()
        );
        assert_eq!(
            accounted.estimated_memory_bytes(),
            accounted.recompute_estimated_memory_bytes()
        );
        for seed in [&fast_seed, &accounted_seed] {
            seed.inspect(|state| match state {
                ExecutionSeed::Materialized { registers, .. } => {
                    assert_eq!(registers, &vec![Value::Int(1)]);
                }
                ExecutionSeed::Lazy { .. } => {
                    panic!("the pre-write seed must be materialized")
                }
            });
        }
    }

    #[test]
    fn static_register_write_inside_plain_call_matches_accounted_path() {
        let mut fast = static_register_write_core();
        let mut accounted = static_register_write_core();
        push_plain_test_call_frame(&mut fast);
        push_plain_test_call_frame(&mut accounted);

        assert!(fast.static_register_write_eligible(0, &Value::Int(9), &Label::Secret));
        fast.write_reg_with_label(0, Value::Int(9), Label::Secret)
            .expect("plain call-frame static write must succeed");
        accounted
            .write_reg_with_label_accounted(0, Value::Int(9), Label::Secret)
            .expect("plain call-frame accounted reference must succeed");

        assert_eq!(fast.registers.value, accounted.registers.value);
        assert_eq!(fast.register_labels, accounted.register_labels);
        assert_eq!(fast.seed_epoch, accounted.seed_epoch);
        assert_eq!(
            fast.estimated_memory_bytes,
            accounted.estimated_memory_bytes
        );
        assert_eq!(
            fast.estimated_memory_bytes(),
            fast.recompute_estimated_memory_bytes()
        );
        assert_eq!(
            accounted.estimated_memory_bytes(),
            accounted.recompute_estimated_memory_bytes()
        );

        let frame = fast.call_stack.last_mut().expect("plain call frame");
        frame.super_home_object = Some(ObjectId(0));
        frame.super_label = Label::Secret;
        assert!(
            !fast.static_register_write_eligible(0, &Value::Int(10), &Label::Public),
            "HomeObject-bound execution context must retain the IFC-aware path"
        );
    }

    #[test]
    fn static_register_write_preserves_label_and_accounted_refusals() {
        let mut fast = static_register_write_core();
        let mut accounted = static_register_write_core();

        let accounted_reg = accounted.register_base;
        assert!(fast.static_register_write_eligible(0, &Value::Bool(true), &Label::Internal));
        fast.write_reg(0, Value::Bool(true))
            .expect("eligible value-only write must succeed");
        accounted
            .write_reg_accounted(accounted_reg, Value::Bool(true))
            .expect("reference accounted value-only write must succeed");
        assert_eq!(fast.registers.value, accounted.registers.value);
        assert_eq!(fast.register_labels, accounted.register_labels);
        assert_eq!(fast.register_labels[0], Label::Internal);
        assert_eq!(
            fast.estimated_memory_bytes,
            accounted.estimated_memory_bytes
        );

        assert!(!fast.static_register_write_eligible(0, &Value::str("dynamic"), &Label::Internal));
        assert!(!fast.static_register_write_eligible(
            0,
            &Value::BigInt(Arc::from("12345678901234567890")),
            &Label::Internal
        ));
        assert!(!fast.static_register_write_eligible(
            0,
            &Value::Int(10),
            &Label::Custom {
                name: "tenant".to_string(),
                level: 3,
            }
        ));
        assert!(!fast.static_register_write_eligible(1, &Value::Int(10), &Label::Public));
        fast.active_inline_callback_context_label = Some(Label::Secret);
        assert!(!fast.static_register_write_eligible(0, &Value::Int(10), &Label::Public));
        fast.active_inline_callback_context_label = None;

        fast.config.max_total_memory_bytes = fast.estimated_memory_bytes().saturating_sub(1);
        let before_value = fast.registers[0].clone();
        let before_label = fast.register_labels[0].clone();
        let before_epoch = fast.seed_epoch;
        let error = fast
            .write_reg_with_label(0, Value::Int(11), Label::Public)
            .expect_err("an over-budget static replacement must retain accounted refusal");
        assert!(matches!(
            error,
            InterpreterError::MemoryBudgetExceeded { .. }
        ));
        assert_eq!(fast.registers[0], before_value);
        assert_eq!(fast.register_labels[0], before_label);
        assert_eq!(fast.seed_epoch, before_epoch);
    }

    #[test]
    fn lazy_seed_remains_lazy_with_no_writes() {
        let mut core = test_core();
        let seed = core
            .capture_execution_seed()
            .expect("test execution-seed capture must fit");
        assert!(seed.is_lazy());
        core.reset_execution_state_from_seed(&seed)
            .expect("matching-epoch lazy seed must reset cleanly");
        assert!(seed.is_lazy());
    }

    #[test]
    fn write_to_register_materializes_outstanding_lazy_seed() {
        let mut core = test_core_with_registers(vec![Value::Int(1), Value::Int(2)]);
        let seed = core
            .capture_execution_seed()
            .expect("test execution-seed capture must fit");
        let pre_epoch = core.seed_epoch;
        // Force a write.
        core.mutate_registers(|r| r[0] = Value::Int(99));
        // Seed must now be Materialized with the PRE-write registers.
        seed.inspect(|state| match state {
            ExecutionSeed::Materialized { registers, .. } => {
                assert_eq!(registers, &vec![Value::Int(1), Value::Int(2)]);
            }
            ExecutionSeed::Lazy { .. } => panic!("write should have materialized the seed"),
        });
        assert!(core.seed_epoch > pre_epoch);
    }

    #[test]
    fn reset_byte_identical_vs_eager() {
        let initial_regs = vec![Value::Int(1)];
        let mut eager = test_core_with_registers(initial_regs.clone());
        let mut lazy = test_core_with_registers(initial_regs);

        let seed_e = capture_execution_seed_eager_for_test(&mut eager);
        let seed_l = lazy
            .capture_execution_seed()
            .expect("test execution-seed capture must fit");

        // Apply same write sequence to both cores
        for v in (0..16).map(Value::Int) {
            eager.mutate_registers(|r| r[0] = v.clone());
            lazy.mutate_registers(|r| r[0] = v);
        }

        eager
            .reset_execution_state_from_seed(&seed_e)
            .expect("eager materialized seed must reset without invariant violation");
        lazy.reset_execution_state_from_seed(&seed_l)
            .expect("materialized seed must reset without invariant violation");

        // Eager core's original state should match lazy core's reset state
        assert_eq!(eager.registers.len(), lazy.registers.len());
        assert_eq!(eager.heap.len(), lazy.heap.len());
        assert_eq!(
            eager.function_prototypes.len(),
            lazy.function_prototypes.len()
        );
        assert_eq!(
            eager.builtin_prototypes.len(),
            lazy.builtin_prototypes.len()
        );

        // Check register values specifically
        for i in 0..eager.registers.len().min(lazy.registers.len()) {
            assert_eq!(
                eager.registers[i], lazy.registers[i],
                "register {i} mismatch"
            );
        }
    }

    #[test]
    fn heap_mutation_also_materializes() {
        let mut core = test_core();
        let seed = core
            .capture_execution_seed()
            .expect("test execution-seed capture must fit");
        let pre_epoch = core.seed_epoch;
        // Force a heap write.
        core.mutate_heap(|h| h.push(HeapObject::new()));
        // Seed must now be Materialized.
        seed.inspect(|state| match state {
            ExecutionSeed::Materialized { heap, .. } => {
                assert!(heap.is_empty()); // Pre-write heap was empty
            }
            ExecutionSeed::Lazy { .. } => panic!("heap write should have materialized the seed"),
        });
        assert!(core.seed_epoch > pre_epoch);
    }

    #[test]
    fn function_prototypes_mutation_also_materializes() {
        let mut core = test_core();
        let seed = core
            .capture_execution_seed()
            .expect("test execution-seed capture must fit");
        let pre_epoch = core.seed_epoch;
        // Force a function_prototypes write.
        core.mutate_function_prototypes(|fp| {
            fp.insert(
                (ContentHash::compute(b"lazy-seed-owner"), 42),
                ObjectId(123),
            );
        });
        // Seed must now be Materialized.
        seed.inspect(|state| match state {
            ExecutionSeed::Materialized {
                function_prototypes,
                ..
            } => {
                assert!(function_prototypes.is_empty()); // Pre-write prototypes was empty
            }
            ExecutionSeed::Lazy { .. } => {
                panic!("function_prototypes write should have materialized the seed")
            }
        });
        assert!(core.seed_epoch > pre_epoch);
    }

    #[test]
    fn builtin_prototypes_mutation_also_materializes() {
        let mut core = test_core();
        let seed = core
            .capture_execution_seed()
            .expect("test execution-seed capture must fit");
        let pre_epoch = core.seed_epoch;
        core.mutate_builtin_prototypes(|bp| {
            bp.insert("Error".to_string(), ObjectId(123));
        });
        seed.inspect(|state| match state {
            ExecutionSeed::Materialized {
                builtin_prototypes, ..
            } => {
                assert!(builtin_prototypes.is_empty());
            }
            ExecutionSeed::Lazy { .. } => {
                panic!("builtin_prototypes write should have materialized the seed")
            }
        });
        assert!(core.seed_epoch > pre_epoch);
    }

    #[test]
    fn multiple_pending_seeds_all_materialize_once() {
        let mut core = test_core_with_registers(vec![Value::Int(1)]);
        core.sync_estimated_memory_bytes()
            .expect("multiple-seed fixture must fit");
        let s1 = core
            .capture_execution_seed()
            .expect("test execution-seed capture must fit");
        let s2 = core
            .capture_execution_seed()
            .expect("test execution-seed capture must fit");
        let s3 = core
            .capture_execution_seed()
            .expect("test execution-seed capture must fit");
        core.write_reg(0, Value::Int(2))
            .expect("normal first write must fit reserved seed ownership");
        for seed in [&s1, &s2, &s3] {
            seed.inspect(|state| {
                assert!(matches!(state, ExecutionSeed::Materialized { .. }));
            });
        }
        assert!(core.estimated_memory_bytes() <= core.config.max_total_memory_bytes);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn dropped_seed_does_not_force_materialization() {
        let mut core = test_core_with_registers(vec![Value::Int(1)]);
        core.sync_estimated_memory_bytes()
            .expect("dropped-seed fixture must fit");
        {
            let _seed = core
                .capture_execution_seed()
                .expect("test execution-seed capture must fit");
            // seed drops here
        }
        assert_eq!(
            core.live_execution_seed_reserved_bytes(),
            InterpreterCore::pending_execution_seed_entry_bytes()
        );
        let pre_epoch = core.seed_epoch;
        core.write_reg(0, Value::Int(2))
            .expect("dead weak cleanup must not block a normal write");
        // No keepers (the Weak upgrade returns None); pending_lazy_seeds drains to empty.
        assert!(
            core.pending_lazy_seeds.is_empty()
                || core
                    .pending_lazy_seeds
                    .iter()
                    .all(|w| w.upgrade().is_none())
        );
        // Epoch still advances due to the write
        assert!(core.seed_epoch > pre_epoch);
        assert_eq!(core.live_execution_seed_reserved_bytes(), 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    /// bd-ytaa7: simulate the chokepoint failure (lazy seed with a
    /// different epoch than the core, never materialized) and confirm
    /// `reset_execution_state_from_seed` returns `InterpreterError::
    /// InternalError` instead of panicking. This is the
    /// security-incident path the run loop must propagate as a
    /// fail-closed witness — a panic here would let extension code
    /// abort the host process via any embedder.
    #[test]
    fn lazy_seed_epoch_divergence_returns_internal_error() {
        let mut core = test_core();
        let seed = core
            .capture_execution_seed()
            .expect("test execution-seed capture must fit");
        // Without going through `before_seed_surface_write`, bump the
        // core epoch to model a missed chokepoint — the seed stays
        // Lazy at the old epoch.
        core.seed_epoch = core.seed_epoch.wrapping_add(1);
        assert!(seed.is_lazy());

        let err = core
            .reset_execution_state_from_seed(&seed)
            .expect_err("epoch-divergent lazy seed must error, not panic");

        assert!(
            matches!(
                &err,
                InterpreterError::InternalError { details }
                    if details.contains("lazy seed survived a write")
                        && details.contains("chokepoint missed a write site")
            ),
            "expected InternalError with chokepoint-miss detail, got: {err:?}"
        );
    }

    fn expected_capture_total(core: &InterpreterCore) -> u64 {
        core.estimated_memory_bytes()
            .saturating_add(InterpreterCore::pending_execution_seed_entry_bytes())
            .saturating_add(core.estimate_execution_seed_snapshot_bytes())
            .saturating_add(u64::try_from(std::mem::size_of::<ExecutionSeed>()).unwrap_or(u64::MAX))
    }

    #[test]
    fn execution_seed_register_reservation_is_exact_and_drop_aware_bd_x6010() {
        let mut core = test_core_with_registers(vec![Value::str("reserved-register-payload")]);
        core.sync_estimated_memory_bytes()
            .expect("register fixture must fit before seed admission");
        let baseline = core.estimated_memory_bytes();
        let exact_total = expected_capture_total(&core);

        core.config.max_total_memory_bytes = exact_total.saturating_sub(1);
        assert!(matches!(
            core.capture_execution_seed(),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(core.estimated_memory_bytes(), baseline);
        assert!(core.pending_lazy_seeds.is_empty());

        core.config.max_total_memory_bytes = exact_total;
        let seed = core
            .capture_execution_seed()
            .expect("exact execution-seed reservation ceiling must succeed");
        assert_eq!(core.estimated_memory_bytes(), exact_total);
        let alias = seed.clone();
        let reserved = core.live_execution_seed_reserved_bytes();
        drop(seed);
        assert_eq!(core.live_execution_seed_reserved_bytes(), reserved);
        core.write_reg(0, Value::str("reserved-register-payload"))
            .expect("same-size normal first write must fit the exact capture ceiling");
        assert!(core.estimated_memory_bytes() <= core.config.max_total_memory_bytes);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
        drop(alias);
        assert_eq!(core.live_execution_seed_reserved_bytes(), 0);
        core.prune_dead_pending_execution_seeds();
        assert_eq!(core.estimated_memory_bytes(), baseline);
        assert_eq!(core.recompute_estimated_memory_bytes(), baseline);
    }

    #[test]
    fn execution_seed_reserves_heap_prototypes_symbols_and_property_labels_bd_x6010() {
        let mut core = test_core();
        let mut object = HeapObject::new();
        object
            .properties
            .insert("payload".to_string(), Value::str("heap-owned-seed-payload"));
        object.property_labels.insert(
            "payload".to_string(),
            Label::Custom {
                name: "seed-property-label".repeat(4),
                level: 7,
            },
        );
        object.array_buffer = Some(Box::new(ArrayBufferBacking {
            label: Label::Secret,
            ..ArrayBufferBacking::with_bytes(vec![0xA5; 257])
        }));
        core.mutate_heap(|heap| heap.push(object));
        core.mutate_function_prototypes(|prototypes| {
            prototypes.insert((ContentHash::compute(b"seed-owner"), 3), ObjectId(0));
        });
        core.mutate_builtin_prototypes(|prototypes| {
            prototypes.insert("SeedBuiltin".to_string(), ObjectId(0));
        });
        core.allocate_private_symbol(Some(JsString::from("seed-symbol")))
            .expect("symbol fixture must fit");
        core.sync_estimated_memory_bytes()
            .expect("composite seed fixture must fit");

        let baseline = core.estimated_memory_bytes();
        let exact_total = expected_capture_total(&core);
        core.config.max_total_memory_bytes = exact_total.saturating_sub(1);
        assert!(matches!(
            core.capture_execution_seed(),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(core.estimated_memory_bytes(), baseline);

        core.config.max_total_memory_bytes = exact_total;
        let seed = core
            .capture_execution_seed()
            .expect("composite snapshot must fit its exact reservation");
        assert_eq!(core.estimated_memory_bytes(), exact_total);
        core.write_reg(0, Value::Int(1))
            .expect("normal write must consume the pre-admitted composite reservation");
        assert!(!seed.is_lazy());
        assert!(core.pending_lazy_seeds.is_empty());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
        drop(seed);
        assert_eq!(core.live_execution_seed_reserved_bytes(), 0);
    }

    #[test]
    fn execution_seed_reset_peak_refusal_is_atomic_bd_x6010() {
        let mut core = test_core_with_registers(vec![Value::str("seed-state")]);
        core.sync_estimated_memory_bytes()
            .expect("initial reset fixture must fit");
        let seed = core
            .capture_execution_seed()
            .expect("reset fixture capture must fit");
        core.mutate_registers(|registers| registers[0] = Value::str("mutated-state"));
        core.active_inline_callback_context_label = Some(Label::Custom {
            name: "transient-reset-label".repeat(4),
            level: 5,
        });
        core.sync_estimated_memory_bytes()
            .expect("mutated reset fixture must fit");
        let before_total = core.estimated_memory_bytes();
        let before_registers = core.registers.value.clone();
        let before_label = core.active_inline_callback_context_label.clone();

        core.config.max_total_memory_bytes = before_total
            .saturating_add(seed.0.snapshot_bytes)
            .saturating_sub(1);
        assert!(matches!(
            core.reset_execution_state_from_seed(&seed),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(core.registers.value, before_registers);
        assert_eq!(core.active_inline_callback_context_label, before_label);
        assert_eq!(core.estimated_memory_bytes(), before_total);

        core.config.max_total_memory_bytes = before_total.saturating_add(seed.0.snapshot_bytes);
        core.reset_execution_state_from_seed(&seed)
            .expect("exact reset clone peak must succeed");
        assert_eq!(core.registers[0], Value::str("seed-state"));
        assert!(core.active_inline_callback_context_label.is_none());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn execution_seed_owner_and_epoch_wrap_fail_closed_bd_x6010() {
        let mut owner = test_core();
        owner.seed_epoch = u64::MAX;
        let seed = owner
            .capture_execution_seed()
            .expect("owner seed capture must fit");
        owner.last_pre_run_seed = Some(seed.clone());
        owner.last_post_run_epoch = Some(u64::MAX);
        owner.mutate_registers(|registers| registers[0] = Value::Int(7));
        assert_eq!(owner.seed_epoch, 0);
        assert_eq!(owner.last_post_run_epoch, None);

        let mut foreign = test_core();
        assert!(matches!(
            foreign.reset_execution_state_from_seed(&seed),
            Err(InterpreterError::InternalError { details })
                if details.contains("different interpreter core")
        ));
    }

    #[test]
    fn execution_seed_accessor_estimator_is_bounded_bd_x6010() {
        let mut value = Value::Undefined;
        for _ in 0..300 {
            value = Value::Accessor {
                get: Some(Arc::new(value)),
                set: None,
            };
        }
        let mut core = test_core_with_registers(vec![value]);
        core.config.max_total_memory_bytes = u64::MAX;
        assert_eq!(core.estimate_execution_seed_snapshot_bytes(), u64::MAX);
        assert!(matches!(
            core.capture_execution_seed(),
            Err(InterpreterError::MemoryBudgetExceeded {
                requested_bytes: u64::MAX,
                ..
            })
        ));
        assert!(core.pending_lazy_seeds.is_empty());
    }
}

#[cfg(test)]
mod json_stringify_bd9a8cz3_tests {
    //! bd-9a8cz.3: `JSON.stringify` object/array serialization (was a `"{}"` stub
    //! for every object). Reachable from eval because lowering recognizes
    //! `JSON.stringify` as a builtin call (`object_json_builtin_call_capability`)
    //! with no eval-scope global binding required. Keys serialize in ECMAScript
    //! own-key order.
    fn eval_value(source: &str) -> String {
        let mut engine = crate::HybridRouter::default();
        match engine.eval(source) {
            Ok(outcome) => outcome.value,
            Err(err) => format!("ERR:{err}"),
        }
    }

    #[test]
    fn stringify_plain_object_serializes_properties() {
        assert_eq!(
            eval_value("JSON.stringify({a: 1, b: 2});"),
            r#"{"a":1,"b":2}"#
        );
    }

    #[test]
    fn stringify_array_serializes_elements() {
        assert_eq!(eval_value("JSON.stringify([1, 2, 3]);"), "[1,2,3]");
    }

    #[test]
    fn stringify_nested_object_and_array() {
        assert_eq!(
            eval_value(r#"JSON.stringify({arr: [1, 2], obj: {k: 3}, s: "x"});"#),
            r#"{"arr":[1,2],"obj":{"k":3},"s":"x"}"#
        );
    }

    #[test]
    fn stringify_empty_object_and_array() {
        assert_eq!(eval_value("JSON.stringify({});"), "{}");
        assert_eq!(eval_value("JSON.stringify([]);"), "[]");
    }

    #[test]
    fn stringify_primitives_unchanged() {
        assert_eq!(eval_value("JSON.stringify(5);"), "5");
        assert_eq!(eval_value("JSON.stringify(true);"), "true");
        assert_eq!(eval_value(r#"JSON.stringify("x");"#), r#""x""#);
        assert_eq!(eval_value("JSON.stringify(null);"), "null");
    }
}

/// E4.T3 (`bd-fqlfw.4.3`): parity proof between the legacy
/// `BuiltinFunctionKind::String*` dispatch arms and the intrinsic-table
/// generated path (`dispatch_string_intrinsic`). Both routes must agree on
/// every (receiver, args) case — including TypeError cases — before the
/// family can flip to table-only dispatch (migration-plan step 5).
#[cfg(test)]
mod string_intrinsic_table_parity_tests {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::baseline_interpreter::*;
    use crate::intrinsics_codegen::{DispatchTarget, generate_glue};
    use crate::intrinsics_table::string_prototype;
    use crate::ir_contract::{IrHeader, IrLevel, IrSchemaVersion, RegRange};

    fn parity_test_config() -> InterpreterConfig {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]);
        config
    }

    fn parity_test_core() -> InterpreterCore {
        InterpreterCore::new(parity_test_config(), "string-intrinsic-parity-test")
    }

    fn halted_module() -> Ir3Module {
        Ir3Module {
            header: IrHeader {
                schema_version: IrSchemaVersion::CURRENT,
                level: IrLevel::Ir3,
                source_hash: None,
                source_label: "string-intrinsic-parity".to_string(),
            },
            instructions: vec![Ir3Instruction::Halt],
            constant_pool: Vec::new(),
            function_table: Vec::new(),
            specialization: None,
            required_capabilities: Vec::new(),
            function_lengths: Default::default(),
            function_sources: Default::default(),
            sloppy_functions: Default::default(),
        }
    }

    fn load_args(core: &mut InterpreterCore, args: &[Value]) -> RegRange {
        core.mutate_registers(|registers| {
            for (index, value) in args.iter().enumerate() {
                registers[index] = value.clone();
            }
        });
        RegRange {
            start: 0,
            count: u32::try_from(args.len()).expect("test arg count fits u32"),
        }
    }

    fn run_legacy(
        core: &mut InterpreterCore,
        kind: BuiltinFunctionKind,
        receiver: &Value,
        args: &[Value],
    ) -> Result<Value, InterpreterError> {
        let range = load_args(core, args);
        let builtin = BuiltinFunction {
            kind,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        };
        let module = halted_module();
        core.dispatch_builtin_function(&module, &builtin, range, Some(receiver.clone()), None)
    }

    fn run_generated(
        core: &mut InterpreterCore,
        method_key: &str,
        receiver: &Value,
        args: &[Value],
    ) -> Result<Value, InterpreterError> {
        let range = load_args(core, args);
        core.dispatch_string_intrinsic(&halted_module(), method_key, receiver.clone(), range)
            .unwrap_or_else(|| {
                panic!("String.prototype.{method_key} must be served by the generated path")
            })
    }

    /// Object results (e.g. `split`) allocate fresh ids per call, so parity is
    /// asserted on the materialized property maps rather than the ids.
    fn assert_outcome_parity(
        core: &InterpreterCore,
        legacy: Result<Value, InterpreterError>,
        generated: Result<Value, InterpreterError>,
        context: &str,
    ) {
        match (&legacy, &generated) {
            (Ok(Value::Object(a)), Ok(Value::Object(b))) => {
                let legacy_object = core
                    .heap
                    .get(a.0 as usize)
                    .unwrap_or_else(|| panic!("legacy object missing: {context}"));
                let generated_object = core
                    .heap
                    .get(b.0 as usize)
                    .unwrap_or_else(|| panic!("generated object missing: {context}"));
                assert_eq!(
                    legacy_object.properties, generated_object.properties,
                    "object-result parity: {context}"
                );
            }
            _ => assert_eq!(legacy, generated, "result parity: {context}"),
        }
    }

    fn assert_method_parity(
        kind: BuiltinFunctionKind,
        method_key: &str,
        cases: &[(Value, Vec<Value>)],
    ) {
        let mut core = parity_test_core();
        for (receiver, args) in cases {
            let legacy = run_legacy(&mut core, kind, receiver, args);
            let generated = run_generated(&mut core, method_key, receiver, args);
            let context =
                format!("String.prototype.{method_key} receiver={receiver:?} args={args:?}");
            assert_outcome_parity(&core, legacy, generated, &context);
        }
    }

    /// Receivers exercised for every method: plain, unicode (astral plane),
    /// non-string coercibles, and the TypeError pair (null / undefined).
    fn common_receivers() -> Vec<Value> {
        vec![
            Value::str("  Héllo wörld  "),
            Value::str("a😀b"),
            Value::str(""),
            Value::Int(12345),
            Value::Bool(true),
            Value::Null,
            Value::Undefined,
        ]
    }

    fn cases_with_arg_sets(arg_sets: &[Vec<Value>]) -> Vec<(Value, Vec<Value>)> {
        let mut cases = Vec::new();
        for receiver in common_receivers() {
            for args in arg_sets {
                cases.push((receiver.clone(), args.clone()));
            }
        }
        cases
    }

    #[test]
    fn string_family_glue_builds_and_verifies() {
        let glue = generate_glue(string_prototype::ROWS)
            .expect("String.prototype family table must generate glue");
        glue.verify()
            .expect("String.prototype family glue must verify");
        assert_eq!(glue.registry.len(), 26);
        assert!(
            InterpreterCore::string_family_glue().is_some(),
            "interpreter-side glue accessor must build the family glue"
        );
    }

    #[test]
    fn every_generated_row_resolves_to_an_impl_fn() {
        let glue = generate_glue(string_prototype::ROWS).expect("glue");
        for entry in &glue.dispatch {
            match &entry.target {
                DispatchTarget::Generated { impl_fn } => {
                    assert!(
                        InterpreterCore::string_intrinsic_impl_binding(impl_fn).is_some(),
                        "{}: row declares impl fn `{impl_fn}` but the binding does not \
                         resolve it — row/impl drift",
                        entry.name
                    );
                }
                DispatchTarget::Manual { site } => {
                    panic!(
                        "{}: the String family must be fully generated, found manual site {site}",
                        entry.name
                    );
                }
            }
        }
    }

    #[test]
    fn generated_path_declines_unknown_methods() {
        let mut core = parity_test_core();
        let range = load_args(&mut core, &[]);
        assert!(
            core.dispatch_string_intrinsic(
                &halted_module(),
                "noSuchMethod",
                Value::str("abc"),
                range
            )
            .is_none(),
            "unknown method names must fall back to the legacy seam"
        );
    }

    #[test]
    fn parity_char_at_family() {
        let index_args: Vec<Vec<Value>> = vec![
            vec![],
            vec![Value::Int(0)],
            vec![Value::Int(2)],
            vec![Value::Int(-1)],
            vec![Value::Int(99)],
            vec![Value::str("1")],
            vec![Value::Undefined],
        ];
        assert_method_parity(
            BuiltinFunctionKind::StringCharAt,
            "charAt",
            &cases_with_arg_sets(&index_args),
        );
        assert_method_parity(
            BuiltinFunctionKind::StringCharCodeAt,
            "charCodeAt",
            &cases_with_arg_sets(&index_args),
        );
        assert_method_parity(
            BuiltinFunctionKind::StringAt,
            "at",
            &cases_with_arg_sets(&index_args),
        );
        assert_method_parity(
            BuiltinFunctionKind::StringCodePointAt,
            "codePointAt",
            &cases_with_arg_sets(&index_args),
        );
    }

    #[test]
    fn parity_case_and_trim_family() {
        let no_args: Vec<Vec<Value>> = vec![vec![]];
        assert_method_parity(
            BuiltinFunctionKind::StringToUpperCase,
            "toUpperCase",
            &cases_with_arg_sets(&no_args),
        );
        assert_method_parity(
            BuiltinFunctionKind::StringToLowerCase,
            "toLowerCase",
            &cases_with_arg_sets(&no_args),
        );
        assert_method_parity(
            BuiltinFunctionKind::StringTrim,
            "trim",
            &cases_with_arg_sets(&no_args),
        );
        assert_method_parity(
            BuiltinFunctionKind::StringTrimStart,
            "trimStart",
            &cases_with_arg_sets(&no_args),
        );
        assert_method_parity(
            BuiltinFunctionKind::StringTrimEnd,
            "trimEnd",
            &cases_with_arg_sets(&no_args),
        );
    }

    #[test]
    fn parity_search_family() {
        let search_args: Vec<Vec<Value>> = vec![
            vec![],
            vec![Value::str("l")],
            vec![Value::str("")],
            vec![Value::str("l"), Value::Int(3)],
            vec![Value::str("l"), Value::Int(-5)],
            vec![Value::str("l"), Value::Undefined],
            vec![Value::str("zz"), Value::Int(0)],
            vec![Value::Int(2)],
        ];
        assert_method_parity(
            BuiltinFunctionKind::StringIncludes,
            "includes",
            &cases_with_arg_sets(&search_args),
        );
        assert_method_parity(
            BuiltinFunctionKind::StringStartsWith,
            "startsWith",
            &cases_with_arg_sets(&search_args),
        );
        assert_method_parity(
            BuiltinFunctionKind::StringEndsWith,
            "endsWith",
            &cases_with_arg_sets(&search_args),
        );
        assert_method_parity(
            BuiltinFunctionKind::StringIndexOf,
            "indexOf",
            &cases_with_arg_sets(&search_args),
        );
        assert_method_parity(
            BuiltinFunctionKind::StringLastIndexOf,
            "lastIndexOf",
            &cases_with_arg_sets(&search_args),
        );
    }

    #[test]
    fn parity_slice_family() {
        let range_args: Vec<Vec<Value>> = vec![
            vec![],
            vec![Value::Int(1)],
            vec![Value::Int(1), Value::Int(3)],
            vec![Value::Int(-2)],
            vec![Value::Int(3), Value::Int(1)],
            vec![Value::Undefined, Value::Int(2)],
            vec![Value::Int(0), Value::Int(99)],
        ];
        assert_method_parity(
            BuiltinFunctionKind::StringSlice,
            "slice",
            &cases_with_arg_sets(&range_args),
        );
        assert_method_parity(
            BuiltinFunctionKind::StringSubstring,
            "substring",
            &cases_with_arg_sets(&range_args),
        );
    }

    #[test]
    fn parity_replace_family() {
        let replace_args: Vec<Vec<Value>> = vec![
            vec![],
            vec![Value::str("l")],
            vec![Value::str("l"), Value::str("_")],
            vec![Value::str("zz"), Value::str("X")],
            vec![Value::str(""), Value::str("@")],
        ];
        assert_method_parity(
            BuiltinFunctionKind::StringReplace,
            "replace",
            &cases_with_arg_sets(&replace_args),
        );
        assert_method_parity(
            BuiltinFunctionKind::StringReplaceAll,
            "replaceAll",
            &cases_with_arg_sets(&replace_args),
        );
    }

    #[test]
    fn parity_split() {
        let split_args: Vec<Vec<Value>> = vec![
            vec![],
            vec![Value::Undefined],
            vec![Value::str(" ")],
            vec![Value::str("")],
            vec![Value::str("ö")],
        ];
        assert_method_parity(
            BuiltinFunctionKind::StringSplit,
            "split",
            &cases_with_arg_sets(&split_args),
        );
    }

    #[test]
    fn parity_match_search_locale_normalize() {
        let pattern_args: Vec<Vec<Value>> =
            vec![vec![], vec![Value::str("l")], vec![Value::str("zz")]];
        assert_method_parity(
            BuiltinFunctionKind::StringMatch,
            "match",
            &cases_with_arg_sets(&pattern_args),
        );
        assert_method_parity(
            BuiltinFunctionKind::StringSearch,
            "search",
            &cases_with_arg_sets(&pattern_args),
        );
        assert_method_parity(
            BuiltinFunctionKind::StringLocaleCompare,
            "localeCompare",
            &cases_with_arg_sets(&pattern_args),
        );
        let normalize_args: Vec<Vec<Value>> = vec![
            vec![],
            vec![Value::str("NFC")],
            vec![Value::str("NFD")],
            vec![Value::str("BOGUS")],
            vec![Value::Undefined],
        ];
        assert_method_parity(
            BuiltinFunctionKind::StringNormalize,
            "normalize",
            &cases_with_arg_sets(&normalize_args),
        );
    }

    #[test]
    fn parity_repeat_and_pad() {
        let repeat_args: Vec<Vec<Value>> = vec![
            vec![],
            vec![Value::Int(0)],
            vec![Value::Int(3)],
            vec![Value::Int(-2)],
            // Size-guard RangeError must reproduce identically on both routes.
            vec![Value::Int(10_000_000)],
        ];
        assert_method_parity(
            BuiltinFunctionKind::StringRepeat,
            "repeat",
            &cases_with_arg_sets(&repeat_args),
        );
        let pad_args: Vec<Vec<Value>> = vec![
            vec![],
            vec![Value::Int(8)],
            vec![Value::Int(8), Value::str("ab")],
            vec![Value::Int(8), Value::str("")],
            vec![Value::Int(2)],
            vec![Value::Int(-3)],
        ];
        assert_method_parity(
            BuiltinFunctionKind::StringPadStart,
            "padStart",
            &cases_with_arg_sets(&pad_args),
        );
        assert_method_parity(
            BuiltinFunctionKind::StringPadEnd,
            "padEnd",
            &cases_with_arg_sets(&pad_args),
        );
    }

    // =====================================================================
    // E4.T4 (`bd-fqlfw.4.4`): uniform per-row IFC propagation through the
    // generated dispatch path. The legacy seam never propagated labels for
    // these methods (the bd-0zybl hand-wiring-omission class); the table
    // path derives the dst label from each row's DECLARED `IfcPropagation`
    // policy, so propagation cannot be forgotten per-site.
    // =====================================================================

    /// Acceptance for bd-fqlfw.4.4: a Secret receiver's `trim()` result is
    /// Secret on the table path. Previously this required hand-wiring a join
    /// at the dispatch site (and the legacy seam in fact has none — dst kept
    /// its stale label), the exact under-tainting class bd-0zybl documented
    /// for GetProperty.
    #[test]
    fn table_dispatch_propagates_secret_receiver_label_to_dst() {
        let mut core = parity_test_core();
        core.mutate_registers(|registers| {
            registers[0] = Value::str("  classified  ");
        });
        core.set_register_label(0, Label::Secret).unwrap();
        let args = RegRange { start: 1, count: 0 };
        core.dispatch_string_intrinsic_to_reg(&halted_module(), "trim", 0, args, 2)
            .expect("trim is a generated row of the String family")
            .expect("trim dispatch succeeds");
        assert_eq!(core.read_reg(2).unwrap(), Value::str("classified"));
        assert_eq!(
            core.get_register_label(2).unwrap(),
            &Label::Secret,
            "PropagateReceiverLabel: a Secret receiver must taint the result"
        );
    }

    /// JoinReceiverAndArgs: a sensitive ARGUMENT also taints the result (a
    /// Confidential index selecting into a Public string reveals the index).
    #[test]
    fn table_dispatch_joins_argument_labels_into_dst() {
        let mut core = parity_test_core();
        core.mutate_registers(|registers| {
            registers[0] = Value::str("abcdef");
            registers[1] = Value::Int(2);
        });
        core.set_register_label(1, Label::Confidential).unwrap();
        let args = RegRange { start: 1, count: 1 };
        core.dispatch_string_intrinsic_to_reg(&halted_module(), "charAt", 0, args, 3)
            .expect("charAt is a generated row of the String family")
            .expect("charAt dispatch succeeds");
        assert_eq!(core.read_reg(3).unwrap(), Value::str("c"));
        assert_eq!(
            core.get_register_label(3).unwrap(),
            &Label::Confidential,
            "JoinReceiverAndArgs: a Confidential argument must taint the result"
        );
    }

    /// JoinReceiverAndArgs is a least-upper-bound: the highest label among
    /// receiver and arguments wins.
    #[test]
    fn table_dispatch_join_takes_least_upper_bound() {
        let mut core = parity_test_core();
        core.mutate_registers(|registers| {
            registers[0] = Value::str("classified payload");
            registers[1] = Value::str("payload");
        });
        core.set_register_label(0, Label::Secret).unwrap();
        core.set_register_label(1, Label::Internal).unwrap();
        let args = RegRange { start: 1, count: 1 };
        core.dispatch_string_intrinsic_to_reg(&halted_module(), "indexOf", 0, args, 3)
            .expect("indexOf is a generated row of the String family")
            .expect("indexOf dispatch succeeds");
        assert_eq!(core.read_reg(3).unwrap(), Value::Int(11));
        assert_eq!(
            core.get_register_label(3).unwrap(),
            &Label::Secret,
            "join(Secret receiver, Internal arg) = Secret"
        );
    }

    /// A dispatch fully overwrites dst's value, so its label is the policy
    /// result alone — a stale high label on the dead prior value does not
    /// stick to the fresh Public result. Matches the BinaryOp / UnaryOp /
    /// HostCall register-label convention.
    #[test]
    fn table_dispatch_overwrites_stale_dst_label_with_policy_result() {
        let mut core = parity_test_core();
        core.mutate_registers(|registers| {
            registers[0] = Value::str("  public  ");
        });
        core.set_register_label(2, Label::Secret).unwrap();
        let args = RegRange { start: 1, count: 0 };
        core.dispatch_string_intrinsic_to_reg(&halted_module(), "trim", 0, args, 2)
            .expect("trim is a generated row of the String family")
            .expect("trim dispatch succeeds");
        assert_eq!(core.read_reg(2).unwrap(), Value::str("public"));
        assert_eq!(
            core.get_register_label(2).unwrap(),
            &Label::Public,
            "a Public-derived result overwrites the dead value's stale label"
        );
    }

    /// A failed dispatch (TypeError receiver) must leave dst's value AND
    /// label untouched — the error propagates before any write.
    #[test]
    fn table_dispatch_error_leaves_dst_label_untouched() {
        let mut core = parity_test_core();
        core.mutate_registers(|registers| {
            registers[0] = Value::Null;
            registers[2] = Value::Int(7);
        });
        core.set_register_label(2, Label::Internal).unwrap();
        let args = RegRange { start: 1, count: 0 };
        let outcome = core
            .dispatch_string_intrinsic_to_reg(&halted_module(), "trim", 0, args, 2)
            .expect("trim is a generated row of the String family");
        assert!(outcome.is_err(), "null receiver must TypeError");
        assert_eq!(core.read_reg(2).unwrap(), Value::Int(7));
        assert_eq!(core.get_register_label(2).unwrap(), &Label::Internal);
    }

    /// Unknown methods still decline (caller falls back to the legacy seam)
    /// and touch neither dst's value nor its label.
    #[test]
    fn table_dispatch_to_reg_declines_unknown_methods() {
        let mut core = parity_test_core();
        core.mutate_registers(|registers| {
            registers[0] = Value::str("abc");
        });
        core.set_register_label(2, Label::Confidential).unwrap();
        let args = RegRange { start: 1, count: 0 };
        assert!(
            core.dispatch_string_intrinsic_to_reg(&halted_module(), "noSuchMethod", 0, args, 2)
                .is_none(),
            "unknown method names must fall back to the legacy seam"
        );
        assert_eq!(core.get_register_label(2).unwrap(), &Label::Confidential);
    }

    /// The policy evaluator covers every declared `IfcPropagation` variant,
    /// including the ones the String family does not use yet (`JoinArgs`,
    /// `Constant`) and the `Custom` escape hatch (which yields `None`: the
    /// row's documented manual site owns irregular propagation).
    #[test]
    fn policy_evaluator_covers_every_declared_policy() {
        use crate::flow_lattice::LabelClass;
        let mut core = parity_test_core();
        core.mutate_registers(|registers| {
            registers[0] = Value::Int(1);
            registers[1] = Value::Int(2);
        });
        core.set_register_label(0, Label::Internal).unwrap();
        core.set_register_label(1, Label::Secret).unwrap();
        let args = RegRange { start: 0, count: 2 };
        let empty = RegRange { start: 0, count: 0 };
        let receiver = Label::Confidential;
        let eval = |core: &InterpreterCore, policy: &IfcPropagation, args: RegRange| {
            core.intrinsic_result_label(policy, &receiver, args)
                .expect("in-bounds registers")
        };
        assert_eq!(
            eval(&core, &IfcPropagation::PropagateReceiverLabel, args),
            Some(Label::Confidential)
        );
        assert_eq!(
            eval(&core, &IfcPropagation::JoinReceiverAndArgs, args),
            Some(Label::Secret),
            "join(Confidential receiver, Internal, Secret) = Secret"
        );
        assert_eq!(
            eval(&core, &IfcPropagation::JoinArgs, args),
            Some(Label::Secret),
            "JoinArgs ignores the receiver label"
        );
        assert_eq!(
            eval(&core, &IfcPropagation::JoinArgs, empty),
            Some(Label::Public),
            "empty arg range joins to Public (the join identity)"
        );
        assert_eq!(
            eval(&core, &IfcPropagation::Constant(LabelClass::Public), args),
            Some(Label::Public),
            "Constant ignores all inputs"
        );
        assert_eq!(
            eval(&core, &IfcPropagation::Custom("array_reduce_ifc"), args),
            None,
            "Custom policies are owned by their documented manual site"
        );
    }

    /// E4.T4 audit: every String-family row declares an auto-generated
    /// (non-Custom) policy, and the policy matches the row's data flow —
    /// arg-less methods propagate the receiver label; methods with arguments
    /// join receiver and args. Locks the family against a row regressing to
    /// hand-wired (or forgotten) propagation.
    #[test]
    fn string_family_ifc_policies_are_uniform_and_auto_generated() {
        use crate::intrinsics_table::Arity;
        let core = parity_test_core();
        let args = RegRange { start: 0, count: 0 };
        for row in string_prototype::ROWS {
            match &row.arity {
                Arity::Exact(0) => assert_eq!(
                    row.ifc,
                    IfcPropagation::PropagateReceiverLabel,
                    "{}: arg-less methods propagate the receiver label",
                    row.name
                ),
                _ => assert_eq!(
                    row.ifc,
                    IfcPropagation::JoinReceiverAndArgs,
                    "{}: methods with arguments join receiver and args",
                    row.name
                ),
            }
            assert!(
                core.intrinsic_result_label(&row.ifc, &Label::Public, args)
                    .expect("in-bounds registers")
                    .is_some(),
                "{}: a fully-generated family must auto-propagate (no Custom rows)",
                row.name
            );
        }
    }
}

// Relocated current-API memory-accounting tests (bd-n0sap partial fix ->
// unblocks bd-o4cbn.13.2). These exercise only the current InterpreterCore
// memory-accounting API (write_reg / alloc_* / set_object_property /
// recompute_estimated_memory_bytes / estimated_memory_bytes) and were trapped
// behind the `legacy_lib_tests_bd_2j7uk` opt-in gate purely by sharing `mod
// tests` with the then-not-yet-ported legacy tests. They were relocated here so
// they would run in default validation ahead of the full port; the legacy `mod
// tests` has since been fully ported and un-gated (bd-n0sap), so both modules
// now run under the default `cargo test`.
#[cfg(test)]
mod memory_accounting_tests {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::baseline_interpreter::*;
    use proptest::prelude::*;
    use proptest::strategy::BoxedStrategy;

    fn test_quickjs_config() -> InterpreterConfig {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]);
        config
    }

    #[derive(Clone, Debug)]
    enum H8MemoryValue {
        Undefined,
        Int(i64),
        Str(String),
    }

    impl H8MemoryValue {
        fn to_runtime_value(&self) -> Value {
            match self {
                Self::Undefined => Value::Undefined,
                Self::Int(value) => Value::Int(*value),
                Self::Str(value) => Value::str(value.clone()),
            }
        }
    }

    #[derive(Clone, Debug)]
    enum H8MemoryAccountingOp {
        WriteReg {
            reg: u32,
            value: H8MemoryValue,
        },
        SetRegisterLabel {
            reg: u32,
            name: String,
            level: u32,
        },
        AllocObject,
        SetProperty {
            object_slot: usize,
            key: String,
            value: H8MemoryValue,
        },
        RemoveProperty {
            object_slot: usize,
            key: String,
        },
        AllocForInIterator {
            keys: Vec<String>,
        },
        AllocForOfIterator {
            values: Vec<H8MemoryValue>,
            next_method: H8MemoryValue,
        },
        PushScope,
        BindCurrentScope {
            name: String,
            value: H8MemoryValue,
        },
        PopScope,
        AllocateClosure {
            function_index: u32,
        },
    }

    impl H8MemoryAccountingOp {
        fn apply(
            &self,
            core: &mut InterpreterCore,
            object_ids: &mut Vec<ObjectId>,
        ) -> Result<(), InterpreterError> {
            match self {
                Self::WriteReg { reg, value } => core.write_reg(*reg, value.to_runtime_value()),
                Self::SetRegisterLabel { reg, name, level } => core.set_register_label(
                    *reg,
                    Label::Custom {
                        name: name.clone(),
                        level: *level,
                    },
                ),
                Self::AllocObject => {
                    let id = core.alloc_object_with_prototype(None)?;
                    object_ids.push(id);
                    Ok(())
                }
                Self::SetProperty {
                    object_slot,
                    key,
                    value,
                } => {
                    let object_id = object_id_for_slot(core, object_ids, *object_slot)?;
                    core.set_object_property(object_id, key.clone(), value.to_runtime_value())
                }
                Self::RemoveProperty { object_slot, key } => {
                    let Some(object_id) = object_ids.get(*object_slot % object_ids.len().max(1))
                    else {
                        return Ok(());
                    };
                    core.remove_object_property(*object_id, key)?;
                    Ok(())
                }
                Self::AllocForInIterator { keys } => {
                    let object_id = object_id_for_slot(core, object_ids, 0)?;
                    core.alloc_iterator(RuntimeIteratorState::ForIn(RuntimeForInState {
                        object_id,
                        keys: keys
                            .iter()
                            .map(|key| JsString::from(key.as_str()))
                            .collect(),
                        next_index: 0,
                        deleted_keys: BTreeSet::new(),
                        done: false,
                        closed: false,
                        trace_index: 0,
                    }))?;
                    Ok(())
                }
                Self::AllocForOfIterator {
                    values,
                    next_method,
                } => {
                    core.alloc_iterator(RuntimeIteratorState::ForOf(RuntimeForOfState {
                        values: values.iter().map(H8MemoryValue::to_runtime_value).collect(),
                        next_index: 0,
                        array: None,
                        typed_array: None,
                        collection: None,
                        iterator_receiver: None,
                        next_method: Some(next_method.to_runtime_value()),
                        timers_interval: None,
                        done: false,
                        closed: false,
                        return_called: false,
                        trace_index: 0,
                    }))?;
                    Ok(())
                }
                Self::PushScope => {
                    let previous_scope_bytes = core.scope_chain_memory_bytes();
                    core.scope_chain.push(core.config.max_scope_depth)?;
                    core.apply_scope_chain_memory_delta(previous_scope_bytes)?;
                    Ok(())
                }
                Self::BindCurrentScope { name, value } => {
                    let previous_scope_bytes = core.scope_chain_memory_bytes();
                    let previous_closure_bytes = core.closures_memory_bytes();
                    let previous_call_stack_bytes = core.call_stack_memory_bytes();
                    let replacement = value.to_runtime_value();
                    let binding = if let Some((_, binding)) = core.scope_chain.resolve(name) {
                        binding.clone()
                    } else {
                        let current = core.scope_chain.current_mut()?;
                        current.declare(name.clone(), BindingKind::Let);
                        current.get(name).cloned().ok_or_else(|| {
                            InterpreterError::InternalError {
                                details: format!("missing declared test binding {name}"),
                            }
                        })?
                    };
                    binding.set_state(replacement, true)?;
                    core.closures.refresh_cell(&binding.state);
                    core.apply_scope_closure_call_stack_memory_delta(
                        previous_scope_bytes,
                        previous_closure_bytes,
                        previous_call_stack_bytes,
                    )?;
                    Ok(())
                }
                Self::PopScope => {
                    if core.scope_chain.depth() > 1 {
                        let previous_scope_bytes = core.scope_chain_memory_bytes();
                        core.scope_chain.pop();
                        core.apply_scope_chain_memory_delta(previous_scope_bytes)?;
                    }
                    Ok(())
                }
                Self::AllocateClosure { function_index } => {
                    let previous_closure_bytes = core.closures_memory_bytes();
                    core.closures.push(ClosureValue {
                        function_index: *function_index,
                        captured_env: core.scope_chain.snapshot(),
                    });
                    core.apply_closures_memory_delta(previous_closure_bytes)?;
                    Ok(())
                }
            }
        }
    }

    fn object_id_for_slot(
        core: &mut InterpreterCore,
        object_ids: &mut Vec<ObjectId>,
        object_slot: usize,
    ) -> Result<ObjectId, InterpreterError> {
        if object_ids.is_empty() {
            let id = core.alloc_object_with_prototype(None)?;
            object_ids.push(id);
        }
        Ok(object_ids[object_slot % object_ids.len()])
    }

    // These sub-strategies are `.clone()`d across several `prop_oneof!` arms in
    // `h8_memory_accounting_op_strategy`, so they must be `Clone`. An opaque
    // `impl Strategy` return type is not `Clone`; `BoxedStrategy<T>` is.
    fn h8_memory_value_strategy() -> BoxedStrategy<H8MemoryValue> {
        prop_oneof![
            Just(H8MemoryValue::Undefined),
            (0_i64..4096).prop_map(H8MemoryValue::Int),
            "[a-z]{0,24}".prop_map(H8MemoryValue::Str),
        ]
        .boxed()
    }

    fn h8_memory_key_strategy() -> BoxedStrategy<String> {
        "[a-z][a-z0-9]{0,8}".prop_map(|value| value).boxed()
    }

    fn h8_memory_accounting_op_strategy() -> impl Strategy<Value = H8MemoryAccountingOp> {
        let value = h8_memory_value_strategy();
        let key = h8_memory_key_strategy();
        prop_oneof![
            (0_u32..16, value.clone())
                .prop_map(|(reg, value)| { H8MemoryAccountingOp::WriteReg { reg, value } }),
            (0_u32..16, "[a-z]{0,32}", 0_u32..16).prop_map(|(reg, name, level)| {
                H8MemoryAccountingOp::SetRegisterLabel { reg, name, level }
            }),
            Just(H8MemoryAccountingOp::AllocObject),
            (0_usize..32, key.clone(), value.clone()).prop_map(|(object_slot, key, value)| {
                H8MemoryAccountingOp::SetProperty {
                    object_slot,
                    key,
                    value,
                }
            }),
            (0_usize..32, key.clone()).prop_map(|(object_slot, key)| {
                H8MemoryAccountingOp::RemoveProperty { object_slot, key }
            }),
            prop::collection::vec(key.clone(), 0..6)
                .prop_map(|keys| H8MemoryAccountingOp::AllocForInIterator { keys }),
            (prop::collection::vec(value.clone(), 0..6), value.clone(),).prop_map(
                |(values, next_method)| H8MemoryAccountingOp::AllocForOfIterator {
                    values,
                    next_method,
                }
            ),
            Just(H8MemoryAccountingOp::PushScope),
            (key, value.clone()).prop_map(|(name, value)| {
                H8MemoryAccountingOp::BindCurrentScope { name, value }
            }),
            Just(H8MemoryAccountingOp::PopScope),
            (0_u32..64).prop_map(|function_index| H8MemoryAccountingOp::AllocateClosure {
                function_index,
            }),
        ]
    }

    #[test]
    fn loopback_net_retains_ifc_labels_in_socket_and_queued_data_bd_7qwej() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "loopback-ifc-accounting");
        let sender = core
            .construct_loopback_socket(true, Some(41_000), Label::Public)
            .expect("sender socket");
        let receiver = core
            .construct_loopback_socket(true, Some(41_000), Label::Public)
            .expect("receiver socket");
        core.loopback_sockets
            .get_mut(&sender)
            .expect("sender state")
            .peer = Some(receiver);
        core.loopback_sockets
            .get_mut(&receiver)
            .expect("receiver state")
            .peer = Some(sender);
        core.write_reg_with_label(0, Value::str("classified"), Label::Secret)
            .expect("secret chunk register");

        assert_eq!(
            core.loopback_socket_write(Value::Object(sender), RegRange { start: 0, count: 1 },)
                .expect("secret loopback write"),
            Value::Bool(true)
        );
        assert_eq!(core.loopback_socket_label(sender), Label::Secret);
        let task = core
            .pending_loopback_tasks
            .values()
            .next()
            .expect("queued data task");
        assert!(matches!(
            task,
            PendingLoopbackTask::Data {
                target,
                bytes,
                label: Label::Secret,
            } if *target == receiver && bytes == b"classified"
        ));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "loopback labels and queued bytes must be fully accounted"
        );
    }

    #[test]
    fn net_implicit_callbacks_publish_once_wrappers_bd_asw4m5() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "bd-asw4m5-net-wrappers");
        let callback = Value::Function(7);

        // Connect site: the callback registers as a stable once wrapper with
        // .listener identity, not a bare one-shot record.
        core.write_reg(0, Value::Int(41_000))
            .expect("port register");
        core.write_reg(1, callback.clone())
            .expect("connect callback");
        let client = core
            .connect_loopback_socket_with_tls(RegRange { start: 0, count: 2 }, false)
            .expect("loopback connect");
        let Value::Object(client) = client else {
            panic!("loopback connect must return the socket object");
        };
        let connect_records = core.event_listener_records_for(client, "connect");
        assert_eq!(connect_records.len(), 1, "connect registers one record");
        assert!(connect_records[0].once);
        let wrapper_property = core
            .event_once_wrapper_listener_property(&connect_records[0].listener)
            .expect("connect record is a stable once wrapper");
        assert_eq!(wrapper_property, callback, "wrapper .listener identity");

        // Listen site: same publication shape on the server lifecycle event.
        let server = core
            .construct_loopback_server(RegRange { start: 0, count: 0 })
            .expect("loopback server");
        let Value::Object(server_id) = server else {
            panic!("loopback server must return the server object");
        };
        core.write_reg(0, Value::Int(0)).expect("wildcard port");
        core.write_reg(1, callback.clone())
            .expect("listen callback");
        core.loopback_server_listen(Value::Object(server_id), RegRange { start: 0, count: 2 })
            .expect("loopback listen");
        let listen_records = core.event_listener_records_for(server_id, "listening");
        assert!(listen_records[0].once);
        let listen_property = core
            .event_once_wrapper_listener_property(&listen_records[0].listener)
            .expect("listen record is a stable once wrapper");
        assert_eq!(listen_property, callback, "wrapper .listener identity");

        // Close site: same publication shape, and the wrapper is live before
        // the scheduled ServerClose task fires.
        core.write_reg(1, callback.clone()).expect("close callback");
        core.loopback_server_close(Value::Object(server_id), RegRange { start: 0, count: 2 })
            .expect("loopback close");
        let close_records = core.event_listener_records_for(server_id, "close");
        assert_eq!(close_records.len(), 1, "close registers one record");
        assert!(close_records[0].once);
        let close_property = core
            .event_once_wrapper_listener_property(&close_records[0].listener)
            .expect("close record is a stable once wrapper");
        assert_eq!(close_property, callback, "wrapper .listener identity");
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "wrapper publication must stay fully memory-accounted"
        );
    }

    #[test]
    fn socket_end_completion_carrier_stays_outside_finish_listeners_bd_asw4m5() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "bd-asw4m5-end-carrier");
        let mut module = Ir3Module::new(
            ContentHash::compute(b"bd-asw4m5-end-carrier"),
            "bd_asw4m5_end_carrier.js",
        );
        // A minimal executable callback body: invocation success is proven by
        // the emission returning Ok with the carrier consumed.
        module.instructions = vec![
            Ir3Instruction::LoadInt { dst: 0, value: 42 },
            Ir3Instruction::Return { value: 0 },
        ];

        use crate::ir_contract::Ir3FunctionDesc;
        module.function_table.push(Ir3FunctionDesc {
            entry: 0,
            arity: 0,
            frame_size: 2,
            name: Some("on_end".to_string()),
            is_generator: false,
            rest_param_index: None,
        });
        let sender = core
            .construct_loopback_socket(false, Some(41_000), Label::Public)
            .expect("sender socket");
        core.write_reg(0, Value::Function(0)).expect("end callback");
        core.loopback_socket_end(
            &module,
            Value::Object(sender),
            RegRange { start: 0, count: 1 },
        )
        .expect("socket end with completion callback");

        // The completion is a dedicated carrier: invisible to the finish
        // listener set, and consumed by the finish emission (a second end on
        // the already-ended socket cannot re-fire it).
        assert!(
            core.event_listener_records_for(sender, "finish").is_empty(),
            "socket.end(callback) must not register a finish listener"
        );
        assert_eq!(
            core.loopback_socket_end(
                &module,
                Value::Object(sender),
                RegRange { start: 0, count: 1 },
            )
            .expect("second end returns the socket"),
            Value::Object(sender),
            "double end must stay a no-op on the consumed carrier"
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "carrier publication and consumption must stay memory-accounted"
        );
    }

    fn loopback_write_atomicity_fixture(
        linked_peer: bool,
    ) -> (InterpreterCore, ObjectId, ObjectId, ObjectId) {
        let mut core = InterpreterCore::new(test_quickjs_config(), "bd-0hpr0-write-atomicity");
        let sender = core
            .construct_loopback_socket(true, Some(41_000), Label::Public)
            .expect("sender socket");
        let receiver = core
            .construct_loopback_socket(true, Some(41_000), Label::Public)
            .expect("receiver socket");
        if linked_peer {
            core.loopback_sockets
                .get_mut(&sender)
                .expect("sender state")
                .peer = Some(receiver);
            core.loopback_sockets
                .get_mut(&receiver)
                .expect("receiver state")
                .peer = Some(sender);
        }
        let chunk = core
            .alloc_buffer_from_bytes(b"classified")
            .expect("write Buffer");
        core.join_binary_storage_label(chunk, &Label::Secret)
            .expect("classified Buffer label");
        core.write_reg(0, Value::Object(chunk))
            .expect("write argument");
        (core, sender, receiver, chunk)
    }

    fn activate_exact_loopback_mirror_carrier(core: &mut InterpreterCore, object: ObjectId) {
        core.set_object_runtime_property(
            object,
            RuntimePropertyKey::String(JsString::from_code_units(&[0xD800])),
            Value::str("rollback-peak".repeat(512)),
        )
        .expect("exact-property rollback carrier");
        let properties = &core.heap[object.0 as usize].properties;
        assert_ne!(properties.exact_len(), properties.len());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn loopback_write_preflight_is_failure_atomic_at_exact_ceiling_bd_0hpr0() {
        for linked_peer in [false, true] {
            let (mut probe, probe_sender, _probe_receiver, _) =
                loopback_write_atomicity_fixture(linked_peer);
            probe.config.max_total_memory_bytes = u64::MAX;
            assert_eq!(
                probe
                    .loopback_socket_write(
                        Value::Object(probe_sender),
                        RegRange { start: 0, count: 1 },
                    )
                    .expect("unbounded write probe"),
                Value::Bool(true)
            );
            let exact_ceiling = probe.estimated_memory_bytes();
            let probe_registration = probe.pending_loopback_tasks.keys().next().copied();
            assert_eq!(
                exact_ceiling,
                probe.recompute_estimated_memory_bytes(),
                "probe accounting must be exact"
            );

            let (mut core, sender, receiver, chunk) = loopback_write_atomicity_fixture(linked_peer);
            let baseline = core.estimated_memory_bytes();
            let baseline_receiver = core.loopback_sockets[&receiver].clone();
            core.config.max_total_memory_bytes = exact_ceiling.saturating_sub(1);
            let error = core
                .loopback_socket_write(Value::Object(sender), RegRange { start: 0, count: 1 })
                .expect_err("one byte below the projected write must refuse");
            assert!(matches!(
                error,
                InterpreterError::MemoryBudgetExceeded {
                    requested_bytes,
                    ..
                } if requested_bytes == exact_ceiling
            ));
            let sender_state = &core.loopback_sockets[&sender];
            assert_eq!(sender_state.lifecycle_label, Label::Public);
            assert_eq!(sender_state.bytes_written, 0);
            assert!(sender_state.pending_outbound.is_empty());
            assert_eq!(
                core.loopback_sockets[&receiver].lifecycle_label,
                baseline_receiver.lifecycle_label
            );
            assert_eq!(
                core.loopback_sockets[&receiver].bytes_read,
                baseline_receiver.bytes_read
            );
            assert!(core.pending_loopback_tasks.is_empty());
            assert!(!core.event_loop.has_pending_work());
            assert_eq!(
                core.fs_object_property(&Value::Object(sender), "bytesWritten"),
                Some(Value::Int(0))
            );
            assert_eq!(core.binary_storage_label(chunk), Label::Secret);
            assert_eq!(core.estimated_memory_bytes(), baseline);
            assert_eq!(baseline, core.recompute_estimated_memory_bytes());

            core.config.max_total_memory_bytes = exact_ceiling;
            assert_eq!(
                core.loopback_socket_write(Value::Object(sender), RegRange { start: 0, count: 1 },)
                    .expect("exact projected write ceiling"),
                Value::Bool(true)
            );
            let sender_state = &core.loopback_sockets[&sender];
            assert_eq!(sender_state.lifecycle_label, Label::Secret);
            assert_eq!(sender_state.bytes_written, b"classified".len() as u64);
            assert_eq!(
                core.fs_object_property(&Value::Object(sender), "bytesWritten"),
                Some(Value::Int(b"classified".len() as i64))
            );
            assert_eq!(
                core.pending_loopback_tasks.keys().next().copied(),
                probe_registration,
                "a refused preflight must not consume a registration sequence"
            );
            if linked_peer {
                assert!(sender_state.pending_outbound.is_empty());
                assert!(matches!(
                    core.pending_loopback_tasks.values().next(),
                    Some(PendingLoopbackTask::Data {
                        target,
                        bytes,
                        label: Label::Secret,
                    }) if *target == receiver && bytes == b"classified"
                ));
            } else {
                assert!(core.pending_loopback_tasks.is_empty());
                assert!(matches!(
                    sender_state.pending_outbound.front(),
                    Some(LoopbackBufferedData {
                        bytes,
                        label: Label::Secret,
                    }) if bytes == b"classified"
                ));
            }
            assert_eq!(core.estimated_memory_bytes(), exact_ceiling);
            assert_eq!(exact_ceiling, core.recompute_estimated_memory_bytes());
        }
    }

    #[test]
    fn loopback_write_after_end_preflight_is_failure_atomic_bd_0hpr0() {
        let (mut probe, probe_sender, _probe_receiver, _) = loopback_write_atomicity_fixture(false);
        probe
            .loopback_sockets
            .get_mut(&probe_sender)
            .expect("probe sender state")
            .local_ended = true;
        probe.config.max_total_memory_bytes = u64::MAX;
        assert_eq!(
            probe
                .loopback_socket_write(
                    Value::Object(probe_sender),
                    RegRange { start: 0, count: 1 },
                )
                .expect("unbounded write-after-end probe"),
            Value::Bool(false)
        );
        let exact_ceiling = probe.estimated_memory_bytes();
        let probe_registration = *probe
            .pending_loopback_tasks
            .keys()
            .next()
            .expect("write-after-end error registration");
        assert!(matches!(
            probe.pending_loopback_tasks.values().next(),
            Some(PendingLoopbackTask::Error {
                target,
                code,
                label: Label::Secret,
                close_after: false,
            }) if *target == probe_sender && code == "ERR_STREAM_WRITE_AFTER_END"
        ));
        assert_eq!(exact_ceiling, probe.recompute_estimated_memory_bytes());

        let (mut core, sender, _receiver, chunk) = loopback_write_atomicity_fixture(false);
        core.loopback_sockets
            .get_mut(&sender)
            .expect("sender state")
            .local_ended = true;
        let baseline = core.estimated_memory_bytes();
        core.config.max_total_memory_bytes = exact_ceiling.saturating_sub(1);
        let error = core
            .loopback_socket_write(Value::Object(sender), RegRange { start: 0, count: 1 })
            .expect_err("one byte below the error-task projection must refuse");
        assert!(matches!(
            error,
            InterpreterError::MemoryBudgetExceeded {
                requested_bytes,
                ..
            } if requested_bytes == exact_ceiling
        ));
        let state = &core.loopback_sockets[&sender];
        assert_eq!(state.lifecycle_label, Label::Public);
        assert_eq!(state.bytes_written, 0);
        assert!(state.pending_outbound.is_empty());
        assert!(core.pending_loopback_tasks.is_empty());
        assert!(!core.event_loop.has_pending_work());
        assert_eq!(
            core.fs_object_property(&Value::Object(sender), "bytesWritten"),
            Some(Value::Int(0))
        );
        assert_eq!(core.binary_storage_label(chunk), Label::Secret);
        assert_eq!(core.estimated_memory_bytes(), baseline);
        assert_eq!(baseline, core.recompute_estimated_memory_bytes());

        core.config.max_total_memory_bytes = exact_ceiling;
        assert_eq!(
            core.loopback_socket_write(Value::Object(sender), RegRange { start: 0, count: 1 })
                .expect("exact write-after-end task ceiling"),
            Value::Bool(false)
        );
        assert_eq!(core.loopback_socket_label(sender), Label::Secret);
        assert_eq!(core.loopback_sockets[&sender].bytes_written, 0);
        assert_eq!(
            core.pending_loopback_tasks.keys().next().copied(),
            Some(probe_registration)
        );
        assert_eq!(core.estimated_memory_bytes(), exact_ceiling);
        assert_eq!(exact_ceiling, core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn loopback_write_late_mirror_refusal_rolls_back_task_bd_0hpr0() {
        let (mut probe, probe_sender, _probe_receiver, _) = loopback_write_atomicity_fixture(true);
        activate_exact_loopback_mirror_carrier(&mut probe, probe_sender);
        probe.config.max_total_memory_bytes = u64::MAX;
        probe
            .loopback_socket_write(Value::Object(probe_sender), RegRange { start: 0, count: 1 })
            .expect("unbounded exact-carrier write probe");
        let final_ceiling = probe.estimated_memory_bytes();
        let probe_registration = *probe
            .pending_loopback_tasks
            .keys()
            .next()
            .expect("probe data registration");
        assert_eq!(final_ceiling, probe.recompute_estimated_memory_bytes());

        let (mut core, sender, receiver, _) = loopback_write_atomicity_fixture(true);
        activate_exact_loopback_mirror_carrier(&mut core, sender);
        let baseline = core.estimated_memory_bytes();
        let heap_before = serde_json::to_string(&core.heap[sender.0 as usize])
            .expect("serialize exact socket carrier");
        core.config.max_total_memory_bytes = final_ceiling;
        let error = core
            .loopback_socket_write(Value::Object(sender), RegRange { start: 0, count: 1 })
            .expect_err("heap-mirror clone peak must refuse after task admission");
        assert!(matches!(
            error,
            InterpreterError::MemoryBudgetExceeded {
                requested_bytes,
                ..
            } if requested_bytes > final_ceiling
        ));
        let state = &core.loopback_sockets[&sender];
        assert_eq!(state.lifecycle_label, Label::Public);
        assert_eq!(state.bytes_written, 0);
        assert!(state.pending_outbound.is_empty());
        assert!(core.pending_loopback_tasks.is_empty());
        assert!(!core.event_loop.has_pending_work());
        assert_eq!(
            core.fs_object_property(&Value::Object(sender), "bytesWritten"),
            Some(Value::Int(0))
        );
        assert_eq!(
            serde_json::to_string(&core.heap[sender.0 as usize])
                .expect("serialize rolled-back socket carrier"),
            heap_before
        );
        assert_eq!(core.estimated_memory_bytes(), baseline);
        assert_eq!(baseline, core.recompute_estimated_memory_bytes());

        core.config.max_total_memory_bytes = u64::MAX;
        core.loopback_socket_write(Value::Object(sender), RegRange { start: 0, count: 1 })
            .expect("retry after exact-carrier refusal");
        assert_eq!(
            core.pending_loopback_tasks.keys().next().copied(),
            Some(probe_registration),
            "late rollback must restore the scheduler registration sequence"
        );
        assert!(matches!(
            core.pending_loopback_tasks.values().next(),
            Some(PendingLoopbackTask::Data {
                target,
                label: Label::Secret,
                ..
            }) if *target == receiver
        ));
        assert_eq!(core.estimated_memory_bytes(), final_ceiling);
        assert_eq!(final_ceiling, core.recompute_estimated_memory_bytes());
    }

    fn loopback_listen_atomicity_fixture() -> (InterpreterCore, ObjectId) {
        let mut core = InterpreterCore::new(test_quickjs_config(), "bd-0hpr0-listen-atomicity");
        let Value::Object(server) = core
            .construct_loopback_server(RegRange { start: 0, count: 0 })
            .expect("loopback server")
        else {
            panic!("expected loopback server object")
        };
        core.write_reg(0, Value::Int(42_360)).expect("listen port");
        core.write_reg_with_label(1, Value::Closure(7), Label::Secret)
            .expect("classified listen callback");
        (core, server)
    }

    #[test]
    fn loopback_listen_preflight_is_failure_atomic_at_exact_ceiling_bd_0hpr0() {
        let listen_args = RegRange { start: 0, count: 2 };
        let (mut probe, probe_server) = loopback_listen_atomicity_fixture();
        probe.config.max_total_memory_bytes = u64::MAX;
        probe
            .loopback_server_listen(Value::Object(probe_server), listen_args)
            .expect("unbounded listen probe");
        let exact_ceiling = probe.estimated_memory_bytes();
        let probe_registration = *probe
            .pending_loopback_tasks
            .keys()
            .next()
            .expect("listening task registration");
        assert_eq!(exact_ceiling, probe.recompute_estimated_memory_bytes());

        let (mut core, server) = loopback_listen_atomicity_fixture();
        let baseline = core.estimated_memory_bytes();
        let baseline_port_cursor = core.next_loopback_port;
        let baseline_generation = core.next_loopback_listener_generation;
        core.config.max_total_memory_bytes = exact_ceiling.saturating_sub(1);
        let error = core
            .loopback_server_listen(Value::Object(server), listen_args)
            .expect_err("one byte below the projected listen must refuse");
        assert!(matches!(
            error,
            InterpreterError::MemoryBudgetExceeded {
                requested_bytes,
                ..
            } if requested_bytes == exact_ceiling
        ));
        let state = &core.loopback_servers[&server];
        assert!(!state.listening);
        assert_eq!(state.port, None);
        assert_eq!(state.generation, 0);
        assert_eq!(state.lifecycle_label, Label::Public);
        assert!(core.loopback_ports.is_empty());
        assert!(core.pending_loopback_tasks.is_empty());
        assert!(!core.event_loop.has_pending_work());
        assert!(
            core.event_listener_records_for(server, "listening")
                .is_empty()
        );
        assert_eq!(
            core.fs_object_property(&Value::Object(server), "listening"),
            Some(Value::Bool(false))
        );
        assert_eq!(core.next_loopback_port, baseline_port_cursor);
        assert_eq!(core.next_loopback_listener_generation, baseline_generation);
        assert_eq!(core.estimated_memory_bytes(), baseline);
        assert_eq!(baseline, core.recompute_estimated_memory_bytes());

        core.config.max_total_memory_bytes = exact_ceiling;
        assert_eq!(
            core.loopback_server_listen(Value::Object(server), listen_args)
                .expect("exact projected listen ceiling"),
            Value::Object(server)
        );
        let state = &core.loopback_servers[&server];
        assert!(state.listening);
        assert_eq!(state.port, Some(42_360));
        assert_eq!(state.generation, baseline_generation);
        assert_eq!(state.lifecycle_label, Label::Secret);
        assert_eq!(
            core.loopback_ports.get(&42_360),
            Some(&LoopbackPortState::Live {
                server,
                generation: baseline_generation,
            })
        );
        assert_eq!(
            core.pending_loopback_tasks.keys().next().copied(),
            Some(probe_registration),
            "a refused preflight must not consume a registration sequence"
        );
        assert_eq!(
            core.event_listener_records_for(server, "listening").len(),
            1
        );
        assert_eq!(
            core.fs_object_property(&Value::Object(server), "listening"),
            Some(Value::Bool(true))
        );
        assert_eq!(core.estimated_memory_bytes(), exact_ceiling);
        assert_eq!(exact_ceiling, core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn loopback_listen_late_mirror_refusal_rolls_back_task_and_listener_bd_0hpr0() {
        let listen_args = RegRange { start: 0, count: 2 };
        let (mut probe, probe_server) = loopback_listen_atomicity_fixture();
        activate_exact_loopback_mirror_carrier(&mut probe, probe_server);
        probe.config.max_total_memory_bytes = u64::MAX;
        probe
            .loopback_server_listen(Value::Object(probe_server), listen_args)
            .expect("unbounded exact-carrier listen probe");
        let final_ceiling = probe.estimated_memory_bytes();
        let probe_registration = *probe
            .pending_loopback_tasks
            .keys()
            .next()
            .expect("probe listening registration");
        assert_eq!(final_ceiling, probe.recompute_estimated_memory_bytes());

        let (mut core, server) = loopback_listen_atomicity_fixture();
        activate_exact_loopback_mirror_carrier(&mut core, server);
        let baseline = core.estimated_memory_bytes();
        let baseline_port_cursor = core.next_loopback_port;
        let baseline_generation = core.next_loopback_listener_generation;
        let heap_before = serde_json::to_string(&core.heap[server.0 as usize])
            .expect("serialize exact server carrier");
        core.config.max_total_memory_bytes = final_ceiling;
        let error = core
            .loopback_server_listen(Value::Object(server), listen_args)
            .expect_err("heap-mirror clone peak must refuse after listen admission");
        assert!(matches!(
            error,
            InterpreterError::MemoryBudgetExceeded {
                requested_bytes,
                ..
            } if requested_bytes > final_ceiling
        ));
        let state = &core.loopback_servers[&server];
        assert!(!state.listening);
        assert_eq!(state.port, None);
        assert_eq!(state.generation, 0);
        assert_eq!(state.lifecycle_label, Label::Public);
        assert!(core.loopback_ports.is_empty());
        assert!(core.pending_loopback_tasks.is_empty());
        assert!(!core.event_loop.has_pending_work());
        assert!(
            core.event_listener_records_for(server, "listening")
                .is_empty()
        );
        assert_eq!(
            core.fs_object_property(&Value::Object(server), "listening"),
            Some(Value::Bool(false))
        );
        assert_eq!(
            serde_json::to_string(&core.heap[server.0 as usize])
                .expect("serialize rolled-back server carrier"),
            heap_before
        );
        assert_eq!(core.next_loopback_port, baseline_port_cursor);
        assert_eq!(core.next_loopback_listener_generation, baseline_generation);
        assert_eq!(core.estimated_memory_bytes(), baseline);
        assert_eq!(baseline, core.recompute_estimated_memory_bytes());

        core.config.max_total_memory_bytes = u64::MAX;
        core.loopback_server_listen(Value::Object(server), listen_args)
            .expect("retry after exact-carrier refusal");
        assert_eq!(
            core.pending_loopback_tasks.keys().next().copied(),
            Some(probe_registration),
            "late rollback must restore the scheduler registration sequence"
        );
        assert_eq!(
            core.event_listener_records_for(server, "listening").len(),
            1
        );
        assert_eq!(core.estimated_memory_bytes(), final_ceiling);
        assert_eq!(final_ceiling, core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn loopback_listen_preserves_numeric_backlog_position_bd_0hpr0() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "bd-0hpr0-listen-backlog");
        let Value::Object(server) = core
            .construct_loopback_server(RegRange { start: 0, count: 0 })
            .expect("loopback server")
        else {
            panic!("expected loopback server object")
        };
        core.write_reg(0, Value::Int(42_361)).expect("listen port");
        core.write_reg(1, Value::Int(128)).expect("listen backlog");
        core.write_reg_with_label(2, Value::Closure(7), Label::Secret)
            .expect("classified listen callback");

        assert_eq!(
            core.loopback_server_listen(Value::Object(server), RegRange { start: 0, count: 3 },)
                .expect("numeric backlog must not be parsed as a host"),
            Value::Object(server)
        );
        let state = &core.loopback_servers[&server];
        assert!(state.listening);
        assert_eq!(state.address, "127.0.0.1");
        assert_eq!(state.port, Some(42_361));
        assert_eq!(state.lifecycle_label, Label::Secret);
        assert_eq!(
            core.event_listener_records_for(server, "listening").len(),
            1
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn loopback_listen_rejects_invalid_ports_without_ephemeral_fallback_bd_0hpr0() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "bd-0hpr0-invalid-port");
        let Value::Object(server) = core
            .construct_loopback_server(RegRange { start: 0, count: 0 })
            .expect("loopback server")
        else {
            panic!("expected loopback server object")
        };
        let invalid_options = core
            .alloc_object_with_properties(&[("port", Value::Bool(false))])
            .expect("invalid listen options");
        let invalid_ports = [
            Value::Int(-1),
            Value::Int(65_536),
            Value::Float(Float64::new(f64::NAN)),
            Value::Float(Float64::new(f64::INFINITY)),
            Value::Float(Float64::new(1.5)),
            Value::str(""),
            Value::str("not-a-port"),
            Value::str("12.5"),
            Value::Bool(false),
            Value::Null,
            Value::BigInt(Arc::from("42360")),
            Value::Object(invalid_options),
        ];

        for candidate in invalid_ports {
            core.write_reg(0, candidate).expect("invalid port argument");
            let baseline = core.estimated_memory_bytes();
            let baseline_port_cursor = core.next_loopback_port;
            let baseline_generation = core.next_loopback_listener_generation;
            let error = core
                .loopback_server_listen(Value::Object(server), RegRange { start: 0, count: 1 })
                .expect_err("invalid port must not select an ephemeral listener");
            assert!(matches!(error, InterpreterError::RangeError { .. }));
            let state = &core.loopback_servers[&server];
            assert!(!state.listening);
            assert_eq!(state.port, None);
            assert_eq!(state.generation, 0);
            assert_eq!(state.lifecycle_label, Label::Public);
            assert!(core.loopback_ports.is_empty());
            assert!(core.pending_loopback_tasks.is_empty());
            assert!(
                core.event_listener_records_for(server, "listening")
                    .is_empty()
            );
            assert_eq!(core.next_loopback_port, baseline_port_cursor);
            assert_eq!(core.next_loopback_listener_generation, baseline_generation);
            assert_eq!(core.estimated_memory_bytes(), baseline);
            assert_eq!(baseline, core.recompute_estimated_memory_bytes());
        }
        assert_eq!(
            core.loopback_listen_port_from_value(&Value::Undefined),
            Ok(0)
        );
        assert_eq!(
            core.loopback_listen_port_from_value(&Value::str("65535")),
            Ok(65_535)
        );
    }

    #[test]
    fn loopback_reset_cancels_sentinel_io_registrations_bd_7qwej() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "loopback-reset-accounting");
        let socket = core
            .construct_loopback_socket(true, Some(41_000), Label::Public)
            .expect("loopback socket");
        core.schedule_loopback_task(PendingLoopbackTask::Data {
            target: socket,
            bytes: b"orphan-candidate".to_vec(),
            label: Label::Public,
        })
        .expect("queued I/O-completion task");
        let registration = *core
            .pending_loopback_tasks
            .keys()
            .next()
            .expect("sentinel registration");

        core.clear_loopback_execution_state();

        assert!(core.pending_loopback_tasks.is_empty());
        assert!(core.event_loop.cancel_registration(registration).is_none());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "reset must release both side-table and event-loop ownership"
        );
    }

    #[test]
    fn http_known_closed_port_is_refused_without_external_capability_bd_d0n7u() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "http-known-closed");
        let server = match core
            .construct_http_server(RegRange { start: 0, count: 0 })
            .expect("HTTP server")
        {
            Value::Object(server) => server,
            other => panic!("expected server object, got {other:?}"),
        };
        core.write_reg(0, Value::Int(42_321)).expect("port");
        core.write_reg(1, Value::str("127.0.0.1")).expect("host");
        core.loopback_server_listen(Value::Object(server), RegRange { start: 0, count: 2 })
            .expect("listen");
        let generation = core.loopback_servers[&server].generation;
        core.loopback_server_close(Value::Object(server), RegRange { start: 2, count: 0 })
            .expect("close");
        assert_eq!(
            core.loopback_ports.get(&42_321),
            Some(&LoopbackPortState::Closed { generation })
        );

        let options = core
            .alloc_object_with_properties(&[
                ("host", Value::str("127.0.0.1")),
                ("port", Value::Int(42_321)),
                ("path", Value::str("/known-internal")),
            ])
            .expect("request options");
        core.write_reg(3, Value::Object(options)).expect("options");
        let request = core
            .construct_http_client_request(RegRange { start: 3, count: 1 }, true)
            .expect("known-closed request needs no NetworkEgress grant");
        let Value::Object(request) = request else {
            panic!("expected request object")
        };
        assert!(core.pending_http_tasks.values().any(|task| matches!(
            task,
            PendingHttpTask::ClientError {
                request: queued,
                code,
                ..
            } if *queued == request && code == "ECONNREFUSED"
        )));
        assert!(!core.pending_http_tasks.values().any(|task| matches!(
            task,
            PendingHttpTask::DispatchRequest { request: queued, .. } if *queued == request
        )));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn http_external_transport_and_host_framing_are_independent_bd_d0n7u() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "http-external-transport");
        core.write_reg(0, Value::str("http://example.test:8080/plain"))
            .expect("plain URL");
        let mut plain = core
            .resolve_http_request(RegRange { start: 0, count: 1 }, true)
            .expect("plain external request");
        assert!(!plain.use_tls);
        assert!(!plain.internal_loopback_candidate);
        assert!(InterpreterCore::http_effect_headers(&plain.headers).is_empty());

        plain.headers.insert(
            "x-trace".to_string(),
            HttpHeaderValue {
                original_name: "X-Trace".to_string(),
                array_values: None,
                value: "one".to_string(),
            },
        );
        assert_eq!(
            InterpreterCore::http_effect_headers(&plain.headers),
            vec![("X-Trace".to_string(), "one".to_string())]
        );

        core.write_reg(0, Value::str("https://example.test/secure"))
            .expect("TLS URL");
        let tls = core
            .resolve_http_request_for_protocol(RegRange { start: 0, count: 1 }, true, true)
            .expect("TLS external request");
        assert!(tls.use_tls);
        assert!(!tls.internal_loopback_candidate);
        assert_eq!(tls.port, 443);
        assert!(
            core.resolve_http_request(RegRange { start: 0, count: 1 }, true)
                .is_err()
        );
    }

    #[test]
    fn http_header_arrays_and_body_ceiling_are_bounded_atomically_bd_d0n7u() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "http-bounds");
        let array = core
            .alloc_array_from_values(&[Value::str("a"), Value::str("b")])
            .expect("header array");
        assert_eq!(
            core.http_header_value_from_value(&Value::Object(array)),
            Ok((
                "a, b".to_string(),
                Some(vec!["a".to_string(), "b".to_string()])
            ))
        );

        let options = core
            .alloc_object_with_properties(&[
                ("host", Value::str("127.0.0.1")),
                ("port", Value::Int(42_322)),
                ("path", Value::str("/bounded")),
            ])
            .expect("request options");
        core.write_reg(0, Value::Object(options)).expect("options");
        let Value::Object(request) = core
            .construct_http_client_request(RegRange { start: 0, count: 1 }, false)
            .expect("client request")
        else {
            panic!("expected request object")
        };
        core.write_reg(1, Value::str("x".repeat(MAX_HTTP_BODY_BYTES + 1)))
            .expect("oversize chunk");
        let before = core.estimated_memory_bytes();
        let error = core
            .http_client_write(
                Some(Value::Object(request)),
                RegRange { start: 1, count: 1 },
                None,
            )
            .expect_err("body ceiling");
        assert!(matches!(error, InterpreterError::RangeError { .. }));
        assert!(core.http_client_requests[&request].body.is_empty());
        assert_eq!(core.estimated_memory_bytes(), before);
        assert_eq!(before, core.recompute_estimated_memory_bytes());

        let oversized_header_bytes = vec![b'h'; MAX_HTTP_HEADER_VALUE_BYTES + 1];
        let oversized_header_buffer = core
            .alloc_buffer_from_bytes(&oversized_header_bytes)
            .expect("oversized header Buffer");
        core.write_reg(2, Value::str("X-Oversized"))
            .expect("header name");
        core.write_reg(3, Value::Object(oversized_header_buffer))
            .expect("header value");
        let before_header = core.estimated_memory_bytes();
        let before_work = core.instructions_executed;
        let error = core
            .http_set_header(
                Some(Value::Object(request)),
                RegRange { start: 2, count: 2 },
                true,
                None,
            )
            .expect_err("Buffer header coercion must stay outside the bounded subset");
        assert!(matches!(error, InterpreterError::TypeError { .. }));
        assert!(
            !core.http_client_requests[&request]
                .headers
                .contains_key("x-oversized")
        );
        assert_eq!(core.instructions_executed, before_work);
        assert_eq!(core.estimated_memory_bytes(), before_header);
        assert_eq!(before_header, core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn http_reset_clears_all_side_tables_but_not_generation_nonce_bd_d0n7u() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "http-reset");
        let server = match core
            .construct_http_server(RegRange { start: 0, count: 0 })
            .expect("HTTP server")
        {
            Value::Object(server) => server,
            other => panic!("expected server object, got {other:?}"),
        };
        core.write_reg(0, Value::Int(42_323)).expect("port");
        core.loopback_server_listen(Value::Object(server), RegRange { start: 0, count: 1 })
            .expect("listen");
        let next_generation = core.next_loopback_listener_generation;
        core.clear_http_execution_state();
        core.clear_loopback_execution_state();
        assert!(core.http_servers.is_empty());
        assert!(core.http_client_requests.is_empty());
        assert!(core.http_incoming_messages.is_empty());
        assert!(core.http_server_responses.is_empty());
        assert!(core.pending_http_tasks.is_empty());
        assert!(core.loopback_ports.is_empty());
        assert_eq!(core.next_loopback_listener_generation, next_generation);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]

        #[test]
        fn incremental_memory_estimate_matches_eager(
            ops in prop::collection::vec(h8_memory_accounting_op_strategy(), 0..=256),
        ) {
            let mut config = test_quickjs_config();
            config.max_heap_objects = 10_000;
            config.max_total_memory_bytes = 256 * 1024 * 1024;
            config.max_scope_depth = 1024;
            let mut core = InterpreterCore::new(config, "h8-memory-proptest");
            let mut object_ids = Vec::new();

            for (index, op) in ops.iter().enumerate() {
                let result = op.apply(&mut core, &mut object_ids);
                prop_assert!(
                    result.is_ok(),
                    "memory accounting op {} failed unexpectedly: {:?}; error={:?}",
                    index,
                    op,
                    result,
                );
                let eager = core.recompute_estimated_memory_bytes();
                let incremental = core.estimated_memory_bytes();
                prop_assert_eq!(
                    incremental,
                    eager,
                    "incremental memory estimate drift after op {}: {:?}",
                    index,
                    op,
                );
            }
        }
    }
}

#[cfg(test)]
mod object_copy_runtime_regression {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::baseline_interpreter::*;

    /// Same grants as the shared `test_interpreter` fixture: object
    /// allocation needs HeapAllocate, execution needs VmDispatch.
    fn copy_config() -> InterpreterConfig {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities.extend([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]);
        config
    }

    #[test]
    fn copy_preserves_stored_property_labels() {
        let mut core = InterpreterCore::new(copy_config(), "copy-property-label");
        let source = core.alloc_object_with_prototype(None).unwrap();
        let target = core.alloc_object_with_prototype(None).unwrap();
        let key = RuntimePropertyKey::String("secret".into());
        core.set_object_runtime_property(source, key.clone(), Value::Int(7))
            .unwrap();
        core.set_own_runtime_property_label(source, &key, &Label::Secret)
            .unwrap();
        core.copy_data_properties(None, target, Value::Object(source), &BTreeSet::new(), false)
            .unwrap();
        assert_eq!(
            core.own_stored_runtime_property_label(target, &key),
            Label::Secret
        );
        assert_eq!(
            core.heap[target.0 as usize].own_runtime_property_value(&key),
            Some(Value::Int(7))
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn excluded_property_is_not_copied_or_read() {
        let mut core = InterpreterCore::new(copy_config(), "copy-excluded-accessor");
        let source = core.alloc_object_with_prototype(None).unwrap();
        let target = core.alloc_object_with_prototype(None).unwrap();
        let key = RuntimePropertyKey::String("excluded".into());
        // Without exclusion this needs a real module-backed invocation and
        // fails; no fabricated accessor result is installed in the test.
        core.set_object_runtime_property(
            source,
            key.clone(),
            Value::Accessor {
                get: Some(Arc::new(Value::Function(u32::MAX))),
                set: None,
            },
        )
        .unwrap();
        core.copy_data_properties(
            None,
            target,
            Value::Object(source),
            &BTreeSet::from([key.clone()]),
            false,
        )
        .unwrap();
        assert!(!core.heap[target.0 as usize].contains_own_runtime_property(&key));
    }

    #[test]
    fn native_copy_charges_work_and_stops_at_budget() {
        let mut config = copy_config();
        config.instruction_budget = 1;
        let mut core = InterpreterCore::new(config, "copy-instruction-budget");
        let target = core.alloc_object_with_prototype(None).unwrap();
        let result =
            core.copy_data_properties(None, target, Value::str("abc"), &BTreeSet::new(), false);
        assert!(matches!(
            result,
            Err(InterpreterError::BudgetExhausted { .. })
        ));
        assert_eq!(core.instructions_executed, 1);
        assert!(core.heap[target.0 as usize].properties.contains_key("0"));
        assert!(!core.heap[target.0 as usize].properties.contains_key("1"));
    }
}

/// bd-9vouw.167: what a pending async call holds, on both lanes.
#[cfg(test)]
mod pending_async_register_cost_bd_9vouw_167 {
    #[allow(unused_imports)]
    use super::*;
    use crate::ast::ParseGoal;
    #[allow(unused_imports)]
    use crate::baseline_interpreter::*;
    use crate::ir_contract::Ir0Module;
    use crate::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

    pub(super) fn module_for(source: &str) -> Ir3Module {
        let tree = CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "pending.js".into(),
                    text: source.into(),
                },
                ParseGoal::Script,
                &ParserOptions::default(),
            )
            .expect("source parses");
        lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "pending.js"),
            &LoweringContext::new("pending-trace", "pending-decision", "pending-policy"),
        )
        .expect("source lowers")
        .ir3
    }

    /// The estimate after `n` async calls parked on a promise that never
    /// settles, checked against the full walk.
    fn parked_estimate(config: &InterpreterConfig, n: usize) -> u64 {
        let module = module_for(&format!(
            "var never = new Promise(function () {{}}); var ps = [];\n\
             async function wait(i) {{ var a = i, b = 'k' + i; await never; return a + b.length; }}\n\
             for (var i = 0; i < {n}; i++) ps.push(wait(i));\n\
             ps.length;"
        ));
        let mut config = config.clone();
        config.instruction_budget = 1_000_000_000;
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "pending");
        let result = core.execute(&module).expect("the calls park");
        assert_eq!(result.value, Value::Int(n as i64));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "estimate after {n} parked calls"
        );
        core.estimated_memory_bytes()
    }

    /// A parked async call held three register windows: its isolated
    /// activation's file (the wrapper's window and its own) and the copy of
    /// its window it saved at the await, about 55 KB on the deterministic
    /// lane and 885 KB on the throughput lane. It now holds its live
    /// registers: each extra pending call costs less than 8 KiB on either.
    #[test]
    fn a_pending_async_call_holds_its_live_registers() {
        for (lane, config) in [
            ("deterministic", InterpreterConfig::quickjs_defaults()),
            ("throughput", InterpreterConfig::v8_defaults()),
        ] {
            let ten = parked_estimate(&config, 10);
            let twenty = parked_estimate(&config, 20);
            let per_call = (twenty - ten) / 10;
            eprintln!("bd-9vouw.167 {lane}: {per_call} bytes per pending async call");
            assert!(
                per_call < 8 * 1024,
                "{lane}: a pending async call costs {per_call} bytes"
            );
        }
    }
}

/// bd-9vouw.497: a call fills reused argument vectors, and the call stack
/// measures its top frame at most once between changes.
#[cfg(test)]
mod call_setup_reuse_bd_9vouw_497 {
    use super::pending_async_register_cost_bd_9vouw_167::module_for;
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::baseline_interpreter::*;

    fn run(source: &str) -> (InterpreterCore, Value) {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.instruction_budget = 1_000_000_000;
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "call-setup-reuse");
        let value = core
            .execute(&module_for(source))
            .expect("the program runs")
            .value;
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
        (core, value)
    }

    /// Calls and method calls with no, fewer, more, rest and 70 arguments;
    /// a 70-argument call drops its vectors and the next call keeps new ones.
    /// Node v22.2.0 and Bun 1.4.3 print the value, as did the n66 frankenctl.
    #[test]
    fn calls_reuse_their_argument_vectors() {
        let wide_arguments = (0..70)
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let wide_parameters = (0..70).map(|i| format!("p{i}")).collect::<Vec<_>>();
        let source = format!(
            "function zero() {{ return 0; }}\n\
             function one(a) {{ return a; }}\n\
             function three(a, b, c) {{ return a + b + c; }}\n\
             function fewer(a, b, c) {{ return String(c) + String(a); }}\n\
             function more(a) {{ return a + arguments.length; }}\n\
             function rest(a, ...r) {{ return a + r.length * 10; }}\n\
             const o = {{ m(a, b) {{ return a * b; }} }};\n\
             function wide({}) {{ return {}; }}\n\
             let t = 0, s = '';\n\
             for (let i = 0; i < 3; i++) {{\n\
               t += zero() + one(i) + three(i, 1, 2) + more(i, 7, 8) + rest(i, 1, 2, 3) + o.m(i, 3) + wide({wide_arguments});\n\
               s += fewer(i) + '|';\n\
             }}\n\
             t + ':' + s + ':' + three(1, 2, 3);",
            wide_parameters.join(", "),
            wide_parameters.join(" + "),
        );
        let (core, value) = run(&source);
        assert_eq!(
            value,
            Value::str("7374:undefined0|undefined1|undefined2|:6")
        );
        for capacity in [
            core.call_argument_value_scratch.capacity(),
            core.call_argument_label_scratch.capacity(),
        ] {
            assert!(
                (1..=CALL_ARGUMENT_SCRATCH_MAX_CAPACITY).contains(&capacity),
                "the last call kept its vectors: capacity {capacity}"
            );
        }
        assert!(core.call_argument_value_scratch.is_empty());
        assert!(core.call_argument_label_scratch.is_empty());
    }

    /// The top frame changes in place when super() initializes a derived
    /// constructor's `this`, when its instance fields run and when a sloppy
    /// callee boxes a primitive `this`; recursion and try/finally returns
    /// push and pop frames over it. The test build checks the call stack's
    /// total against a full walk at every measurement and each popped-to
    /// frame's kept estimate against a new one. Node v22.2.0 prints the
    /// value, as did the n66 frankenctl (Bun runs the file as a module, where
    /// `this` stays a string).
    #[test]
    fn the_top_frame_estimate_follows_its_changes() {
        let (core, value) = run("class Base { constructor(n) { this.n = n; } }\n\
             class Derived extends Base {\n\
               label = 'field-' + this.n;\n\
               constructor(n) { super(n * 2); this.extra = 'x'.repeat(n); }\n\
             }\n\
             function sloppy() { return typeof this + this.length; }\n\
             String.prototype.sloppy = sloppy;\n\
             function rec(d, s) { return d === 0 ? s.length : rec(d - 1, s + 'ab'); }\n\
             function tf(n) { try { if (n > 1) return 'early' + n; } finally { var z = n; } return 'late' + z; }\n\
             const out = [];\n\
             for (let i = 0; i < 4; i++) {\n\
               const d = new Derived(i);\n\
               out.push(d.n + d.label + d.extra.length, 'str'.sloppy(), rec(i, 'q'), tf(i));\n\
             }\n\
             out.join(',');");
        assert_eq!(
            value,
            Value::str(
                "0field-00,object3,1,late0,2field-21,object3,3,late1,\
                 4field-42,object3,5,early2,6field-63,object3,7,early3"
            )
        );
        assert!(core.call_stack.is_empty());
        assert!(core.call_stack.below_top_frame_bytes.is_empty());
    }
}

#[cfg(test)]
mod ifc_taint_closures_rc_c1 {
    use super::pending_async_register_cost_bd_9vouw_167::module_for;
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::baseline_interpreter::*;
    use crate::ir_contract::CapabilityTag;

    fn ifc_test_config() -> InterpreterConfig {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.instruction_budget = 10_000_000;
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
            RuntimeCapability::NetworkEgress,
        ]
        .into_iter()
        .collect();
        config
    }

    fn core_with_secret_box(secret_value: &str) -> InterpreterCore {
        let mut core = InterpreterCore::new(ifc_test_config(), "rc-c1-ifc");
        let box_id = core
            .alloc_object_with_prototype(None)
            .expect("alloc secret box");
        core.set_object_property(box_id, "payload".to_string(), Value::str(secret_value))
            .expect("set secret payload");
        core.set_own_property_label(box_id, "payload", &Label::Secret)
            .expect("label secret payload");
        let global_scope = core.scope_chain.current_mut().expect("global scope");
        global_scope.insert_binding(
            "__secretBox".to_string(),
            ScopeBinding::with_labeled_state(
                BindingKind::Const,
                Value::Object(box_id),
                Label::Public,
                true,
            ),
        );
        global_scope.insert_binding(
            "__secretPayload".to_string(),
            ScopeBinding::with_labeled_state(
                BindingKind::Const,
                Value::str(secret_value),
                Label::Secret,
                true,
            ),
        );
        core.sync_estimated_memory_bytes()
            .expect("secret fixture fits memory budget");
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
        core
    }

    #[test]
    fn generator_yield_and_return_preserve_value_property_taint_label() {
        let mut core = core_with_secret_box("classified-token");
        let yield_err = core
            .execute(&module_for(
                "function* gen() { yield __secretBox.payload; return 'ok'; }\n\
                 const it = gen();\n\
                 const step1 = it.next();\n\
                 console.log(step1.value);",
            ))
            .expect_err("generator yield .value must retain Secret taint at console sink");
        assert!(
            matches!(
                &yield_err,
                InterpreterError::CapabilityDenied { capability }
                    if capability == "console:log:confidentiality"
            ),
            "unexpected error for yielded value: {yield_err:?}"
        );
        assert!(core.console_output.is_empty());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );

        let mut core_ret = core_with_secret_box("classified-return");
        let return_err = core_ret
            .execute(&module_for(
                "function* gen() { return __secretBox.payload; }\n\
                 const step = gen().next();\n\
                 console.log(step.value);",
            ))
            .expect_err("generator return .value must retain Secret taint at console sink");
        assert!(
            matches!(
                &return_err,
                InterpreterError::CapabilityDenied { capability }
                    if capability == "console:log:confidentiality"
            ),
            "unexpected error for returned value: {return_err:?}"
        );
        assert!(core_ret.console_output.is_empty());
        assert_eq!(
            core_ret.estimated_memory_bytes(),
            core_ret.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn dynamic_function_and_nested_closure_preserve_secret_source_label() {
        let mut core = core_with_secret_box("return () => 'derived-from-secret';");
        let err = core
            .execute(&module_for(
                "const outer = Function(__secretPayload);\n\
                 const nested = outer();\n\
                 const leaked = nested();\n\
                 console.log(leaked);",
            ))
            .expect_err("Function(secret) and its nested closure must preserve Secret taint");
        assert!(
            matches!(
                &err,
                InterpreterError::CapabilityDenied { capability }
                    if capability == "console:log:confidentiality"
            ),
            "unexpected error for dynamic function nested closure: {err:?}"
        );
        assert!(core.console_output.is_empty());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn ifc_check_flow_blocks_secret_flow_to_public_network_sink() {
        let mut core = InterpreterCore::new(ifc_test_config(), "rc-c1-ifc-check-flow");
        let mut module = Ir3Module::new(ContentHash::compute(b"ifc-check-flow-test"), "ifc.js");
        module.required_capabilities.push(CapabilityTag(
            crate::lowering_pipeline::IFC_RUNTIME_GUARD_CAPABILITY.to_string(),
        ));
        module
            .required_capabilities
            .push(CapabilityTag("net:request".to_string()));
        module.instructions = vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag(
                    crate::lowering_pipeline::IFC_RUNTIME_GUARD_CAPABILITY.to_string(),
                ),
                args: RegRange { start: 1, count: 1 },
                dst: 0,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("net:request".to_string()),
                args: RegRange { start: 1, count: 1 },
                dst: 0,
            },
            Ir3Instruction::Return { value: 0 },
        ];
        core.write_reg_with_label(1, Value::str("secret-payload"), Label::Secret)
            .expect("seed secret register");
        let err = core
            .run_loop(&module)
            .expect_err("ifc.check_flow must enforce confidentiality before sink hostcall");
        assert!(
            matches!(
                &err,
                InterpreterError::CapabilityDenied { capability }
                    if capability == "net:request:confidentiality"
            ),
            "unexpected error from ifc.check_flow guard: {err:?}"
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn pooled_baseline_worker_reuses_provisioned_os_thread_and_fast_path_tracks_taint() {
        #[derive(Default)]
        struct ThreadIdHook {
            seen: std::sync::Mutex<Vec<std::thread::ThreadId>>,
        }
        impl InterpreterHook for ThreadIdHook {
            fn pre_property_access(
                &self,
                _ctx: &HookContext,
                _target: &ObjectRef,
                _key: &PropertyKey,
            ) -> HookAction {
                HookAction::Allow
            }
            fn pre_call(
                &self,
                _ctx: &HookContext,
                _callee: &FunctionRef,
                _args: &[Value],
            ) -> HookAction {
                HookAction::Allow
            }
            fn pre_allocation(
                &self,
                _ctx: &HookContext,
                _kind: AllocKind,
                _size_hint: usize,
            ) -> HookAction {
                if let Ok(mut seen) = self.seen.lock() {
                    seen.push(std::thread::current().id());
                }
                HookAction::Allow
            }
            fn pre_import(&self, _ctx: &HookContext, _specifier: &str) -> HookAction {
                HookAction::Allow
            }
        }

        // Clear any idle workers first so the two sequential runs deterministically
        // exercise the same pooled OS thread when concurrency == 1.
        if let Ok(mut pool) = baseline_worker_pool().lock() {
            pool.clear();
        }
        let mut module = Ir3Module::new(ContentHash::compute(b"pooled-worker-test"), "pool.js");
        module.instructions = vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::LoadInt { dst: 1, value: 42 },
            Ir3Instruction::Return { value: 1 },
        ];
        let hook = Arc::new(ThreadIdHook::default());
        let lane = QuickJsLane::new();
        let first = lane
            .execute_with_hook(&module, "pool-1", Some(hook.clone()))
            .expect("first pooled run");
        let second = lane
            .execute_with_hook(&module, "pool-2", Some(hook.clone()))
            .expect("second pooled run");
        assert_eq!(first.value, Value::Int(42));
        assert_eq!(second.value, Value::Int(42));
        let seen = hook.seen.lock().expect("hook lock");
        assert_eq!(seen.len(), 2);
        assert_eq!(
            seen[0], seen[1],
            "consecutive single-threaded lane executions must reuse the pooled OS worker thread"
        );

        let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "fast-flag");
        assert!(core.all_register_labels_public);
        core.write_reg(0, Value::Int(7)).expect("public write");
        assert!(core.all_register_labels_public);
        core.write_reg_with_label(1, Value::Int(9), Label::Secret)
            .expect("secret write");
        assert!(!core.all_register_labels_public);
        assert_eq!(
            core.binary_operation_label(0, 1).expect("join label"),
            Label::Secret
        );
    }

    #[test]
    fn console_sink_clearance_is_internal_and_network_is_public() {
        assert_eq!(
            crate::lowering_pipeline::sink_clearance_from_capability("console:log"),
            Label::Internal
        );
        assert_eq!(
            crate::lowering_pipeline::sink_clearance_from_capability("console"),
            Label::Internal
        );
        assert_eq!(
            crate::lowering_pipeline::sink_clearance_from_capability("net:request"),
            Label::Public
        );
    }

    #[test]
    fn disallow_dynamic_codegen_refuses_function_constructor_at_runtime() {
        let mut config = ifc_test_config();
        config.disallow_dynamic_codegen = true;
        for snippet in [
            r#"Function("return 1")();"#,
            r#"new Function("return 1")();"#,
        ] {
            let mut core = InterpreterCore::new(config.clone(), "rc-c1-no-codegen");
            let err = core
                .execute(&module_for(snippet))
                .expect_err("disallow_dynamic_codegen must refuse Function constructor");
            assert!(
                matches!(
                    &err,
                    InterpreterError::CapabilityDenied { capability } if capability == "eval"
                ),
                "expected CapabilityDenied(eval) for `{snippet}`, got: {err:?}"
            );
        }
    }

    #[test]
    fn tainted_callee_and_constructor_propagate_secret_label_to_results() {
        let mut core = core_with_secret_box("top-secret-token");
        let err = core
            .execute(&module_for(
                "const f = () => 'alpha';\n\
                 const g = () => 'beta';\n\
                 const pick = __secretPayload ? f : g;\n\
                 const leaked = pick();\n\
                 console.log(leaked);",
            ))
            .expect_err("calling a Secret-selected callee must taint the return value");
        assert!(
            matches!(
                &err,
                InterpreterError::CapabilityDenied { capability }
                    if capability == "console:log:confidentiality"
            ),
            "unexpected error for tainted callee: {err:?}"
        );

        let mut ctor_core = core_with_secret_box("top-secret-token");
        let ctor_err = ctor_core
            .execute(&module_for(
                "function A() { this.tag = 'a'; }\n\
                 function B() { this.tag = 'b'; }\n\
                 const Ctor = __secretPayload ? A : B;\n\
                 const inst = new Ctor();\n\
                 console.log(inst.tag);",
            ))
            .expect_err(
                "constructing via a Secret-selected constructor must taint instance properties",
            );
        assert!(
            matches!(
                &ctor_err,
                InterpreterError::CapabilityDenied { capability }
                    if capability == "console:log:confidentiality"
            ),
            "unexpected error for tainted constructor: {ctor_err:?}"
        );
    }

    #[test]
    fn implicit_flow_branch_pc_taint_blocks_leaks_and_reconverges_at_ipdom() {
        // 1. Direct conditional mutation under Secret branch condition -> blocked at sink.
        let mut core = core_with_secret_box("top-secret-token");
        let err = core
            .execute(&module_for(
                "let out = 'no';\n\
                 if (__secretPayload === 'top-secret-token') { out = 'yes'; }\n\
                 console.log(out);",
            ))
            .expect_err("implicit flow through Secret branch must taint mutated binding");
        assert!(
            matches!(
                &err,
                InterpreterError::CapabilityDenied { capability }
                    if capability == "console:log:confidentiality"
            ),
            "unexpected error for implicit branch flow: {err:?}"
        );

        // 2. Early-return implicit flow inside helper function -> return value carries Secret!
        let mut early_core = core_with_secret_box("top-secret-token");
        let early_err = early_core
            .execute(&module_for(
                "function probe(s) {\n\
                   if (s === 'top-secret-token') { return 1; }\n\
                   return 0;\n\
                 }\n\
                 const bit = probe(__secretPayload);\n\
                 console.log(bit);",
            ))
            .expect_err("early return conditioned on Secret must taint return value");
        assert!(
            matches!(
                &early_err,
                InterpreterError::CapabilityDenied { capability }
                    if capability == "console:log:confidentiality"
            ),
            "unexpected error for early-return implicit flow: {early_err:?}"
        );

        // 3. Post-dominator reconvergence: code AFTER the Secret branch merges stays Public!
        let post_module = module_for(
            "let secretBit = 0;\n\
             if (__secretPayload === 'top-secret-token') { secretBit = 1; }\n\
             let publicAfter = 42;\n\
             console.log(publicAfter);\n\
             publicAfter;",
        );
        let compact_plan =
            CompactTier1Program::compile(&post_module).expect("compile compact tier1");
        for compact in [false, true] {
            let mut post_core = core_with_secret_box("top-secret-token");
            let result = if compact {
                post_core.execute_ephemeral_with_compact_tier1(&post_module, &compact_plan)
            } else {
                post_core.execute(&post_module)
            }
            .expect("post-dominator reconvergence must not overtaint subsequent Public code");
            assert_eq!(result.value, Value::Int(42));
            assert_eq!(result.completion_label, Label::Public);
            assert_eq!(result.console_output.len(), 1);
        }
    }

    #[test]
    fn runtime_flow_policy_enforces_signed_declassification_receipt_and_records_audit() {
        use crate::ifc_artifacts::{
            ContentBinding, DeclassificationDecision, DeclassificationReceipt,
            DeclassificationRoute, FlowPolicy, FlowPolicyEnforcement, IfcSchemaVersion,
        };
        use crate::signature_preimage::{SIGNATURE_SENTINEL, Signature, SigningKey};

        let signing_key = SigningKey::from_bytes([7u8; 32]).expect("deterministic signing key");
        let policy = FlowPolicy {
            policy_id: "policy-rc-c1".to_string(),
            extension_id: "ext-rc-c1".to_string(),
            label_classes: [Label::Public, Label::Internal, Label::Secret]
                .into_iter()
                .collect(),
            clearance_classes: [Label::Public, Label::Internal].into_iter().collect(),
            allowed_flows: vec![],
            prohibited_flows: vec![],
            declassification_routes: vec![DeclassificationRoute {
                route_id: "route-secret-console".to_string(),
                source_label: Label::Secret,
                target_clearance: Label::Internal,
                conditions: vec!["audit_logged".to_string()],
            }],
            enforcement_mode: FlowPolicyEnforcement::LatticeOpen,
            epoch_id: 1,
            schema_version: IfcSchemaVersion::CURRENT,
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };

        // Case A: Policy requires declassification route, but no receipt is supplied -> DENIED + audited.
        let mut denied_core = core_with_secret_box("top-secret-token");
        denied_core.config.ifc_flow_policy = Some(policy.clone());
        let err = denied_core
            .execute(&module_for("console.log(__secretPayload);"))
            .expect_err("missing declassification receipt must deny Secret -> console:log");
        assert!(matches!(
            &err,
            InterpreterError::CapabilityDenied { capability }
                if capability == "console:log:confidentiality"
        ));
        let denied_audit = denied_core.ifc_runtime_flow_audit();
        assert_eq!(denied_audit.len(), 1);
        assert_eq!(denied_audit[0].decision, IfcRuntimeFlowDecision::Denied);
        assert_eq!(
            denied_audit[0].route_id.as_deref(),
            Some("route-secret-console")
        );
        assert_eq!(denied_audit[0].receipt_id, None);

        // Build a valid signed DeclassificationReceipt.
        let binding =
            ContentBinding::new(b"top-secret-token", Label::Secret, &signing_key).expect("binding");
        let mut valid_receipt = DeclassificationReceipt {
            receipt_id: "rcpt-secret-console-1".to_string(),
            source_label: Label::Secret,
            sink_clearance: Label::Internal,
            content_binding: Some(binding),
            declassification_route_ref: "route-secret-console".to_string(),
            decision_contract_id: "contract-rc-c1".to_string(),
            policy_evaluation_summary: "approved console diagnostic redaction".to_string(),
            loss_assessment_milli: 100,
            decision: DeclassificationDecision::Allow,
            authorized_by: signing_key.verification_key(),
            replay_linkage: "trace-rc-c1".to_string(),
            timestamp_ms: 1_700_000_000_000,
            not_before_ms: 1_699_000_000_000,
            not_after_ms: 1_701_000_000_000,
            schema_version: IfcSchemaVersion::CURRENT,
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };
        valid_receipt.sign(&signing_key).expect("sign receipt");

        // Case B: Tampered signature receipt -> DENIED.
        let mut forged_receipt = valid_receipt.clone();
        forged_receipt.signature = Signature::from_bytes([0xAA; 64]);
        let mut forged_core = core_with_secret_box("top-secret-token");
        forged_core.config.ifc_flow_policy = Some(policy.clone());
        forged_core.config.declassification_receipts = vec![forged_receipt];
        assert!(
            forged_core
                .execute(&module_for("console.log(__secretPayload);"))
                .is_err(),
            "forged signature on DeclassificationReceipt must fail closed"
        );
        assert_eq!(
            forged_core.ifc_runtime_flow_audit()[0].decision,
            IfcRuntimeFlowDecision::Denied
        );

        // Case C: Valid cryptographically signed receipt -> ALLOWED + audited as Declassified!
        let mut allowed_core = core_with_secret_box("top-secret-token");
        allowed_core.config.ifc_flow_policy = Some(policy);
        allowed_core.config.declassification_receipts = vec![valid_receipt];
        let allowed_res = allowed_core
            .execute(&module_for("console.log(__secretPayload);"))
            .expect("valid signed DeclassificationReceipt must authorize route-secret-console");
        assert_eq!(allowed_res.console_output.len(), 1);
        let allowed_audit = allowed_core.ifc_runtime_flow_audit();
        assert_eq!(allowed_audit.len(), 1);
        assert_eq!(
            allowed_audit[0].decision,
            IfcRuntimeFlowDecision::Declassified
        );
        assert_eq!(
            allowed_audit[0].receipt_id.as_deref(),
            Some("rcpt-secret-console-1")
        );
    }

    #[test]
    fn typescript_typed_hostcall_executes_with_exact_capability_and_ifc_sink_enforcement() {
        use crate::ast::ParseGoal;
        use crate::parser::ParserOptions;
        use crate::ts_normalization::{
            TsIngestionProvenance, TsNormalizationConfig, ingest_typescript_to_pipeline_artifacts,
        };

        let read_artifacts = ingest_typescript_to_pipeline_artifacts(
            r#"hostcall<"env.has">("HOME");"#,
            &TsNormalizationConfig::default(),
            "ts-env-test.ts",
            ParseGoal::Script,
            &ParserOptions::default(),
            TsIngestionProvenance::new("trace-ts-exec", "decision-ts-exec", "policy-ts-exec"),
        )
        .expect("ingest env.has TS");

        // Without EnvRead -> CapabilityDenied.
        let mut ungranted = InterpreterCore::new(ifc_test_config(), "ts-env-denied");
        let denied_err = ungranted
            .execute(&read_artifacts.lowering_output.ir3)
            .expect_err("env.has without RuntimeCapability::EnvRead must fail closed");
        assert!(matches!(
            denied_err,
            InterpreterError::CapabilityDenied { .. }
        ));

        // With EnvRead -> executes cleanly through HostcallDispatchBinding::HostIo!
        #[derive(Debug)]
        struct TestEnvHostIo;
        impl frankenengine_extension_host::host_io::HostIoProvider for TestEnvHostIo {
            fn name(&self) -> &str {
                "test-env-host-io"
            }
            fn perform(
                &self,
                request: &frankenengine_extension_host::host_io::HostIoRequest,
                granted: &[frankenengine_extension_host::host_io::HostIoCapability],
            ) -> frankenengine_extension_host::host_io::HostIoOutcome {
                use frankenengine_extension_host::host_io::{
                    HostIoCapability, HostIoError, HostIoRequest, HostIoResponse,
                };
                if !granted.contains(&HostIoCapability::EnvRead) {
                    return Err(HostIoError::Denied {
                        reason: "missing env_read".to_string(),
                    });
                }
                match request {
                    HostIoRequest::EnvRead { name } => Ok(HostIoResponse::EnvRead {
                        value: (name == "HOME").then(|| "/sandbox".to_string()),
                    }),
                    other => Err(HostIoError::NotImplemented {
                        what: format!("{other:?}"),
                    }),
                }
            }
        }
        let mut granted_cfg = ifc_test_config();
        granted_cfg
            .granted_capabilities
            .insert(RuntimeCapability::EnvRead);
        let mut granted = InterpreterCore::new(granted_cfg, "ts-env-allowed");
        granted.set_host_io(std::sync::Arc::new(TestEnvHostIo), None);
        let res = granted
            .execute(&read_artifacts.lowering_output.ir3)
            .expect("env.has with EnvRead granted should execute cleanly");
        assert_eq!(res.value, Value::Bool(true));

        // Non-public binding flowing into typed `hostcall<"net.send">` (Public sink)
        // must fail closed statically during lowering (`Internal -> Public`).
        let net_err = ingest_typescript_to_pipeline_artifacts(
            r#"hostcall<"net.send">(__secretPayload);"#,
            &TsNormalizationConfig::default(),
            "ts-net-test.ts",
            ParseGoal::Script,
            &ParserOptions::default(),
            TsIngestionProvenance::new("trace-ts-net", "decision-ts-net", "policy-ts-net"),
        )
        .expect_err(
            "non-public argument to typed hostcall<\"net.send\"> must be blocked statically",
        );
        assert!(
            net_err.to_string().contains("unauthorized flow"),
            "unexpected lowering error for __secretPayload -> net.send: {net_err}"
        );

        // Runtime Secret property flowing into typed `hostcall<"fs.write">` (Internal sink)
        // passes static `Internal -> Internal` lowering and is blocked at runtime by IFC!
        let fs_artifacts = ingest_typescript_to_pipeline_artifacts(
            r#"hostcall<"fs.write">("/tmp/out", __secretBox.payload);"#,
            &TsNormalizationConfig::default(),
            "ts-fs-test.ts",
            ParseGoal::Script,
            &ParserOptions::default(),
            TsIngestionProvenance::new("trace-ts-fs", "decision-ts-fs", "policy-ts-fs"),
        )
        .expect("ingest fs.write TS");
        let mut secret_fs_core = core_with_secret_box("top-secret-token");
        secret_fs_core
            .config
            .granted_capabilities
            .insert(RuntimeCapability::FsWrite);
        let fs_err = secret_fs_core
            .execute(&fs_artifacts.lowering_output.ir3)
            .expect_err("Secret argument to typed hostcall<\"fs.write\"> must be blocked by IFC");
        assert!(
            matches!(
                &fs_err,
                InterpreterError::CapabilityDenied { capability }
                    if capability == "fs.write:confidentiality"
            ),
            "unexpected error for Secret -> fs.write: {fs_err:?}"
        );
    }

    #[test]
    fn compact_tier1_aara_block_hoisting_preserves_exact_budget_and_loop_semantics_rc_e1() {
        let mut module = Ir3Module::new(ContentHash::compute(b"rc-e1-aara"), "rc-e1.js");
        // Tight loop: r0 = 0; r1 = 0; r2 = 10; loop: r0 = r0 + r1; r1 = r1 + 1; r3 = r1 < r2; JumpIf r3 -> 3; Return r0
        module.instructions = vec![
            Ir3Instruction::LoadInt { dst: 0, value: 0 },
            Ir3Instruction::LoadInt { dst: 1, value: 0 },
            Ir3Instruction::LoadInt { dst: 2, value: 10 },
            Ir3Instruction::Add {
                dst: 0,
                lhs: 0,
                rhs: 1,
            },
            Ir3Instruction::Inc { dst: 1, src: 1 },
            Ir3Instruction::Lt {
                dst: 3,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::JumpIf { cond: 3, target: 3 },
            Ir3Instruction::Return { value: 0 },
        ];
        let program = CompactTier1Program::compile(&module).expect("compact program compiles");
        assert_eq!(program.instructions[0].aara_block_run, 7);
        assert_eq!(program.instructions[3].aara_block_run, 4);
        assert_eq!(program.instructions[6].aara_block_run, 1);

        let mut full_cfg = ifc_test_config();
        full_cfg.instruction_budget = 1_000;
        let compact = QuickJsLane::with_config(full_cfg.clone())
            .execute_with_compact_tier1(&module, "rc-e1-compact", &program)
            .expect("compact loop completes");
        let baseline = QuickJsLane::with_config(full_cfg)
            .execute(&module, "rc-e1-baseline")
            .expect("baseline loop completes");
        assert_eq!(compact.value, Value::Int(45));
        assert_eq!(baseline.value, Value::Int(45));
        assert_eq!(
            compact.instructions_executed,
            baseline.instructions_executed
        );
        // 3 init + 10 * 4 loop ops = 43 compact Tier-I ops; Return + Writable drain stay Tier-R.
        assert_eq!(compact.tier_i_instructions_executed, 43);

        // Mid-block budget expiry must fail at exact budget count (budget = 9, inside IP 3..7).
        let mut tight_cfg = ifc_test_config();
        tight_cfg.instruction_budget = 9;
        let compact_err = QuickJsLane::with_config(tight_cfg.clone())
            .execute_with_compact_tier1(&module, "rc-e1-tight-compact", &program)
            .expect_err("compact mid-block budget must exhaust at exact boundary");
        let baseline_err = QuickJsLane::with_config(tight_cfg)
            .execute(&module, "rc-e1-tight-baseline")
            .expect_err("baseline mid-block budget must exhaust at exact boundary");
        assert_eq!(
            compact_err,
            InterpreterError::BudgetExhausted {
                executed: 9,
                budget: 9,
            }
        );
        assert_eq!(compact_err, baseline_err);
    }

    #[test]
    fn compact_tier1_tarjan_loop_quantum_hoists_multi_chunk_loops_with_exact_budget_g2vrp_15() {
        let mut module = Ir3Module::new(
            ContentHash::compute(b"g2vrp-15-tarjan-single"),
            "g2vrp-15-single.js",
        );
        // Canonical while-loop:
        // 0: r0 = 0 (acc)
        // 1: r1 = 0 (i)
        // 2: r2 = 5000 (limit)
        // 3: r3 = r1 >= r2   [header]
        // 4: JumpIf r3 -> 8  [exit if i >= 5000]
        // 5: r0 = r0 + r1
        // 6: r1 = r1 + 1
        // 7: Jump -> 3
        // 8: Return r0
        module.instructions = vec![
            Ir3Instruction::LoadInt { dst: 0, value: 0 },
            Ir3Instruction::LoadInt { dst: 1, value: 0 },
            Ir3Instruction::LoadInt {
                dst: 2,
                value: 5_000,
            },
            Ir3Instruction::Gte {
                dst: 3,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::JumpIf { cond: 3, target: 8 },
            Ir3Instruction::Add {
                dst: 0,
                lhs: 0,
                rhs: 1,
            },
            Ir3Instruction::Inc { dst: 1, src: 1 },
            Ir3Instruction::Jump { target: 3 },
            Ir3Instruction::Return { value: 0 },
        ];
        let program = CompactTier1Program::compile(&module).expect("compact program compiles");
        assert!(program.loop_quantum_at(0).is_none());
        assert!(program.loop_quantum_at(5).is_none());
        let header_q = program
            .loop_quantum_at(3)
            .expect("Tarjan SCC pass must discover single-entry loop header at IP 3");
        assert_eq!(header_q.max_iter_cost, 5);
        for ip in 3..=7 {
            assert!(program.ip_in_loop_scc(header_q.header_scc_id, ip));
        }
        assert!(!program.ip_in_loop_scc(header_q.header_scc_id, 8));

        let mut full_cfg = ifc_test_config();
        full_cfg.instruction_budget = 100_000;
        let compact = QuickJsLane::with_config(full_cfg.clone())
            .execute_with_compact_tier1(&module, "g2vrp-15-compact", &program)
            .expect("multi-chunk hoisted loop completes");
        let baseline = QuickJsLane::with_config(full_cfg)
            .execute(&module, "g2vrp-15-baseline")
            .expect("baseline loop completes");
        // sum(0..5000) = 4999 * 5000 / 2 = 12_497_500
        assert_eq!(compact.value, Value::Int(12_497_500));
        assert_eq!(baseline.value, Value::Int(12_497_500));
        assert_eq!(
            compact.instructions_executed,
            baseline.instructions_executed
        );

        // Cross two 2048-iteration chunks (2 * 2048 * 5 = 20_480) plus partial tail:
        let mut cross_chunk_cfg = ifc_test_config();
        cross_chunk_cfg.instruction_budget = 20_492;
        let compact_err = QuickJsLane::with_config(cross_chunk_cfg.clone())
            .execute_with_compact_tier1(&module, "g2vrp-15-tight-compact", &program)
            .expect_err("compact must exhaust at exact instruction boundary");
        let baseline_err = QuickJsLane::with_config(cross_chunk_cfg)
            .execute(&module, "g2vrp-15-tight-baseline")
            .expect_err("baseline must exhaust at exact instruction boundary");
        assert_eq!(
            compact_err,
            InterpreterError::BudgetExhausted {
                executed: 20_492,
                budget: 20_492,
            }
        );
        assert_eq!(compact_err, baseline_err);
    }

    #[test]
    fn compact_tier1_tarjan_nested_loop_decomposes_outer_scc_to_hoist_innermost_header_g2vrp_15() {
        let mut module = Ir3Module::new(
            ContentHash::compute(b"g2vrp-15-tarjan-nested"),
            "g2vrp-15-nested.js",
        );
        // 2D nested loop:
        // 0: r0 = 0 (acc)
        // 1: r1 = 0 (i)
        // 2: r2 = 20 (outer_limit)
        // 3: r3 = 30 (inner_limit)
        // 4: r4 = r1 >= r2        [outer header]
        // 5: JumpIf r4 -> 14      [exit outer]
        // 6: r5 = 0 (j)
        // 7: r6 = r5 >= r3        [inner header]
        // 8: JumpIf r6 -> 12      [exit inner]
        // 9: r0 = r0 + r5
        // 10: r5 = r5 + 1
        // 11: Jump -> 7           [inner backedge]
        // 12: r1 = r1 + 1
        // 13: Jump -> 4           [outer backedge]
        // 14: Return r0
        module.instructions = vec![
            Ir3Instruction::LoadInt { dst: 0, value: 0 },
            Ir3Instruction::LoadInt { dst: 1, value: 0 },
            Ir3Instruction::LoadInt { dst: 2, value: 20 },
            Ir3Instruction::LoadInt { dst: 3, value: 30 },
            Ir3Instruction::Gte {
                dst: 4,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::JumpIf {
                cond: 4,
                target: 14,
            },
            Ir3Instruction::LoadInt { dst: 5, value: 0 },
            Ir3Instruction::Gte {
                dst: 6,
                lhs: 5,
                rhs: 3,
            },
            Ir3Instruction::JumpIf {
                cond: 6,
                target: 12,
            },
            Ir3Instruction::Add {
                dst: 0,
                lhs: 0,
                rhs: 5,
            },
            Ir3Instruction::Inc { dst: 5, src: 5 },
            Ir3Instruction::Jump { target: 7 },
            Ir3Instruction::Inc { dst: 1, src: 1 },
            Ir3Instruction::Jump { target: 4 },
            Ir3Instruction::Return { value: 0 },
        ];
        let program = CompactTier1Program::compile(&module).expect("compact program compiles");
        assert!(
            program.loop_quantum_at(4).is_none(),
            "outer loop body contains inner cycle and must decompose rather than claim flat bound"
        );
        let inner_q = program
            .loop_quantum_at(7)
            .expect("recursive Tarjan decomposition must isolate and hoist innermost header IP 7");
        assert_eq!(inner_q.max_iter_cost, 5);

        let mut full_cfg = ifc_test_config();
        full_cfg.instruction_budget = 50_000;
        let compact = QuickJsLane::with_config(full_cfg.clone())
            .execute_with_compact_tier1(&module, "g2vrp-15-nested-compact", &program)
            .expect("nested loop completes");
        let baseline = QuickJsLane::with_config(full_cfg)
            .execute(&module, "g2vrp-15-nested-baseline")
            .expect("baseline nested loop completes");
        // 20 * (29 * 30 / 2) = 20 * 435 = 8700
        assert_eq!(compact.value, Value::Int(8_700));
        assert_eq!(baseline.value, Value::Int(8_700));
        assert_eq!(
            compact.instructions_executed,
            baseline.instructions_executed
        );
    }
}
