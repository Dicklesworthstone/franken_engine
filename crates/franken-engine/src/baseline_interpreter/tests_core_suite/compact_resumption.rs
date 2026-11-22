use super::*;

fn lower_entry(source: &str, goal: ParseGoal, commonjs: bool) -> Ir3Module {
    let label = "/compact/entry.js";
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: label.to_string(),
                text: source.to_string(),
            },
            goal,
            &ParserOptions::default(),
        )
        .expect("resumption fixture parses");
    let mut context = LoweringContext::new("compact-resume", "compact-resume", "compact-resume");
    if commonjs {
        context = context.with_authenticated_commonjs_runtime_bindings();
    }
    lower_ir0_to_ir3(&Ir0Module::from_syntax_tree(tree, label), &context)
        .expect("resumption fixture lowers")
        .ir3
}

fn assert_scope_restored(core: &InterpreterCore) {
    assert!(core.top_level_compact_tier1.is_none());
    assert!(core.entry_frame_widths.is_none());
}

#[test]
fn commonjs_and_retained_entry_continuations_execute_compact_cells_in_both_lanes() {
    let cases = [
        (
            "CommonJS entry",
            "let total = 0; for (let i = 0; i < 64; i++) total += i;
             module.exports = total; console.log(module.exports);",
            ParseGoal::Script,
            true,
            "2016",
        ),
        (
            "generator next and completion",
            "function* stream() {
                 let total = 0; for (let i = 0; i < 64; i++) total += i;
                 yield total;
                 for (let i = 0; i < 64; i++) total += i;
                 return total;
             }
             const iterator = stream();
             console.log(iterator.next().value, iterator.next().value, iterator.next().done);",
            ParseGoal::Script,
            false,
            "2016 4032 true",
        ),
        (
            "generator after the entry body",
            "function* stream() {
                 let total = 0; for (let i = 0; i < 64; i++) total += i;
                 yield total;
             }
             const iterator = stream();
             Promise.resolve().then(() => console.log(iterator.next().value));",
            ParseGoal::Script,
            false,
            "2016",
        ),
        (
            "top-level await",
            "await Promise.resolve(1).then(value => value);
             let total = 0; for (let i = 0; i < 64; i++) total += i;
             console.log(total);",
            ParseGoal::Module,
            false,
            "2016",
        ),
        (
            "async function after await",
            "async function work() {
                 await Promise.resolve(1).then(value => value);
                 let total = 0; for (let i = 0; i < 64; i++) total += i;
                 console.log(total);
             }
             work();",
            ParseGoal::Script,
            false,
            "2016",
        ),
        (
            "Promise callback after the entry body",
            "Promise.resolve().then(() => {
                 let total = 0; for (let i = 0; i < 64; i++) total += i;
                 console.log(total);
             });",
            ParseGoal::Script,
            false,
            "2016",
        ),
    ];
    for (name, source, goal, commonjs, expected_output) in cases {
        let module = lower_entry(source, goal, commonjs);
        let plan = CompactTier1Program::compile(&module).expect("entry plan");
        for mut config in [test_quickjs_config(), test_v8_config()] {
            config.commonjs_entry = commonjs;
            let mut compact = InterpreterCore::new(config.clone(), "compact-resume");
            let mut baseline = InterpreterCore::new(config, "compact-resume");
            let actual = compact
                .execute_with_trace_handoff(&module, Some(&plan), TraceHandoff::RetainInCore)
                .unwrap_or_else(|error| panic!("compact {name}: {error:?}"));
            let expected = baseline
                .execute(&module)
                .unwrap_or_else(|error| panic!("baseline {name}: {error:?}"));
            assert_execution_semantics_equal(&actual, &expected);
            let output: Vec<_> = actual
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect();
            assert_eq!(output, [expected_output], "{name}");
            assert!(
                actual.tier_i_instructions_executed >= 64,
                "{name} must dispatch its repeated body through Tier I, not just the entry prologue"
            );
            assert_eq!(expected.tier_i_instructions_executed, 0, "{name}");
            assert_eq!(
                compact.estimated_memory_bytes(),
                baseline.estimated_memory_bytes(),
                "{name} must keep the reference path's frame-budget semantics"
            );
            assert_scope_restored(&compact);
            assert_scope_restored(&baseline);

            let repeated = compact.execute(&module).expect("explicit Tier-R repeat");
            assert_eq!(repeated.tier_i_instructions_executed, 0, "{name}");
            assert_execution_semantics_equal(&repeated, &expected);
            assert_scope_restored(&compact);
        }
    }
}

#[test]
fn failed_commonjs_generator_and_await_runs_restore_the_scoped_plan() {
    let cases = [
        (
            "let total = 0; for (let i = 0; i < 64; i++) total += i; null.missing;",
            ParseGoal::Script,
            true,
        ),
        (
            "function* fail() {
                 let total = 0; for (let i = 0; i < 64; i++) total += i;
                 null.missing;
             }
             fail().next();",
            ParseGoal::Script,
            false,
        ),
        (
            "await Promise.resolve(1).then(value => value);
             let total = 0; for (let i = 0; i < 64; i++) total += i;
             null.missing;",
            ParseGoal::Module,
            false,
        ),
    ];
    for (source, goal, commonjs) in cases {
        let module = lower_entry(source, goal, commonjs);
        let plan = CompactTier1Program::compile(&module).expect("failure-prefix plan");
        for mut config in [test_quickjs_config(), test_v8_config()] {
            config.commonjs_entry = commonjs;
            let mut compact = InterpreterCore::new(config.clone(), "compact-resume-error");
            let mut baseline = InterpreterCore::new(config, "compact-resume-error");
            let actual = compact
                .execute_with_trace_handoff(&module, Some(&plan), TraceHandoff::RetainInCore)
                .expect_err("the native TypeError must survive dispatch");
            let expected = baseline.execute(&module).expect_err("baseline failure");
            assert_eq!(actual, expected);
            assert!(compact.tier_i_instructions_executed >= 64);
            assert_eq!(baseline.tier_i_instructions_executed, 0);
            assert_eq!(
                compact.instructions_executed,
                baseline.instructions_executed
            );
            assert_eq!(compact.nondeterminism_trace, baseline.nondeterminism_trace);
            assert_eq!(compact.witness_events, baseline.witness_events);
            assert_scope_restored(&compact);
            assert_scope_restored(&baseline);
        }
    }
}

#[test]
fn explicit_reference_execution_restores_an_outer_plan_after_success_or_error() {
    for (source, fails) in [
        (
            "function* values() { yield 7; } values().next().value;",
            false,
        ),
        (
            "function* values() { null.missing; } values().next().value;",
            true,
        ),
    ] {
        let module = lower_entry(source, ParseGoal::Script, false);
        let plan = CompactTier1Program::compile(&module).expect("outer plan");
        let retained = Arc::new(module.clone());
        let identity = EntryModuleIdentity::new(&module, Some(retained.clone()));
        let widths = plan.verified_function_frame_clear_widths.clone();
        let mut core = quickjs_test_core();
        core.top_level_compact_tier1 = Some((identity.clone(), plan));
        core.entry_frame_widths = Some((identity, widths.clone()));

        let result = core.execute(&module);
        if fails {
            result.expect_err("reference generator failure");
        } else {
            assert_eq!(
                result.expect("reference generator value").value,
                Value::Int(7)
            );
        }
        assert_eq!(core.tier_i_instructions_executed, 0);
        assert!(core.top_level_compact_tier1_for(&module).is_some());
        assert!(
            core.top_level_compact_tier1_for(retained.as_ref())
                .is_some()
        );
        let (_, restored_widths) = core
            .entry_frame_widths
            .as_ref()
            .expect("outer frame widths");
        assert!(Arc::ptr_eq(restored_widths, &widths));
    }
}

#[test]
fn only_the_exact_retained_owner_inherits_plan_and_frame_widths() {
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 7 },
            Ir3Instruction::Halt,
        ],
        vec![Ir3FunctionDesc {
            entry: 0,
            arity: 0,
            frame_size: 1,
            name: Some("owner".to_string()),
            is_generator: false,
            rest_param_index: None,
        }],
    );
    let plan = CompactTier1Program::compile(&module).expect("identity fixture plan");
    let retained = Arc::new(module.clone());
    let identity = EntryModuleIdentity::new(&module, Some(retained.clone()));
    assert!(identity.matches(&module));
    assert!(identity.matches(retained.as_ref()));
    assert!(!identity.matches(&module.clone()));

    let mut changed_rest = module.clone();
    changed_rest.function_table[0].rest_param_index = Some(0);
    let changed_rest = Arc::new(changed_rest);
    let rejected = EntryModuleIdentity::new(&module, Some(changed_rest.clone()));
    assert!(rejected.retained_module.is_none());
    assert!(!rejected.matches(changed_rest.as_ref()));

    for label in ["/compact/imported.mjs", "generated:Function", "test"] {
        let mut foreign = module.clone();
        foreign.header.source_label = label.to_string();
        foreign.instructions[0] = Ir3Instruction::LoadInt { dst: 0, value: 99 };
        assert_eq!(foreign.instructions.len(), module.instructions.len());
        let foreign = Arc::new(foreign);
        let rejected = EntryModuleIdentity::new(&module, Some(foreign.clone()));
        assert!(rejected.retained_module.is_none());
        let mut core = quickjs_test_core();
        core.top_level_compact_tier1 = Some((identity.clone(), plan.clone()));
        core.entry_frame_widths = Some((identity.clone(), Arc::from([1])));
        assert_eq!(core.entry_frame_width(retained.as_ref(), 0), Some(1));
        assert_eq!(core.entry_frame_width(foreign.as_ref(), 0), None);
        let completion = core
            .run_loop_labeled(foreign.as_ref())
            .expect("foreign module must dispatch its own IR");
        assert_eq!(completion.value, Value::Int(99));
        assert_eq!(core.tier_i_instructions_executed, 0);
    }
}

#[test]
fn imported_generator_and_generated_function_keep_their_own_reference_dispatch() {
    use crate::module_resolver::{AllowAllPolicy, DeterministicModuleResolver, ModuleDefinition};

    let imported_source = "export function* values() {
        let total = 0; for (let i = 0; i < 64; i++) total += i;
        yield total;
    }";
    let imported_entry = "import { values } from './foreign.mjs'; values().next().value;";
    let generated_entry = "const foreign = Function(
        'let total = 0; for (let i = 0; i < 64; i++) total += i; return total;'
    ); foreign();";
    for (source, imported) in [(imported_entry, true), (generated_entry, false)] {
        let module = lower_entry(source, ParseGoal::Module, false);
        let plan = CompactTier1Program::compile(&module).expect("entry plan");
        let installed_resolver = if imported {
            let mut resolver = DeterministicModuleResolver::new("/compact");
            resolver
                .register_workspace_module(
                    "/compact/entry.js",
                    ModuleDefinition::new(ModuleSyntax::EsModule, source),
                )
                .expect("entry source registration");
            resolver
                .register_workspace_module(
                    "/compact/foreign.mjs",
                    ModuleDefinition::new(ModuleSyntax::EsModule, imported_source),
                )
                .expect("foreign source registration");
            Some(InstalledModuleResolver {
                resolver: ExecutionModuleResolver::new(
                    "/compact/entry.js",
                    Arc::new(resolver),
                    Arc::new(AllowAllPolicy),
                ),
                entry_hash: ContentHash::compute(source.as_bytes()),
                context: ResolutionContext::new("foreign", "foreign", "foreign"),
            })
        } else {
            None
        };
        for config in [test_quickjs_config(), test_v8_config()] {
            let mut compact = InterpreterCore::new(config.clone(), "compact-foreign");
            let mut baseline = InterpreterCore::new(config, "compact-foreign");
            compact.module_resolver = installed_resolver.clone();
            baseline.module_resolver = installed_resolver.clone();
            let actual = compact
                .execute_with_trace_handoff(&module, Some(&plan), TraceHandoff::RetainInCore)
                .expect("entry must not lend its plan to foreign code");
            let expected = baseline
                .execute(&module)
                .expect("foreign reference execution");
            assert_execution_semantics_equal(&actual, &expected);
            assert_eq!(actual.value, Value::Int(2016));
            assert!(actual.instructions_executed > 64);
            assert!(actual.tier_i_instructions_executed > 0);
            assert!(
                actual.tier_i_instructions_executed < 64,
                "the foreign loop must keep reference dispatch"
            );
            assert_eq!(expected.tier_i_instructions_executed, 0);
            assert_scope_restored(&compact);
        }
    }
}
