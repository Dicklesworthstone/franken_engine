#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterError, LaneChoice};
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, OrchestratorError,
};
use frankenengine_engine::module_compatibility_matrix::CompatibilityMode;
use frankenengine_engine::module_resolver::{
    AllowAllPolicy, DeterministicModuleResolver, ImportStyle, ModuleDefinition, ModuleRequest,
    ModuleResolver, ModuleSyntax, ResolutionContext, ResolutionOutcome,
};
use frankenengine_engine::profiling::{ProfilingConfig, ProfilingReport};

fn orchestrator(lane: LaneChoice, syntax: Option<ModuleSyntax>) -> ExecutionOrchestrator {
    // The public lab constructor explicitly selects the fixture signer; these
    // tests do not infer production signing authority from a known test key.
    ExecutionOrchestrator::new_lab(OrchestratorConfig {
        force_lane: Some(lane),
        parse_goal: if syntax == Some(ModuleSyntax::EsModule) {
            ParseGoal::Module
        } else {
            ParseGoal::Script
        },
        commonjs_entry: syntax == Some(ModuleSyntax::CommonJs),
        ..OrchestratorConfig::default()
    })
}

fn package(id: &str, source: &str) -> ExtensionPackage {
    ExtensionPackage {
        extension_id: id.to_string(),
        source: source.to_string(),
        source_file: None,
        module_root: None,
        capabilities: vec!["builtin".to_string(), "module_load".to_string()],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    }
}

fn count_config() -> ProfilingConfig {
    ProfilingConfig {
        enable_instruction_profiling: true,
        enable_hotspot_profiling: false,
        enable_memory_profiling: false,
        enable_call_stack_profiling: false,
        hotspot_sampling_interval: 0,
    }
}

fn report(orchestrator: &ExecutionOrchestrator) -> ProfilingReport {
    orchestrator
        .profiling_data()
        .expect("enabled profiling session")
        .generate_report("orchestrator-program".to_string())
}

fn counts(report: &ProfilingReport) -> BTreeMap<String, u64> {
    report
        .instruction_stats
        .iter()
        .map(|(name, stats)| (name.clone(), stats.count))
        .collect()
}

fn count(report: &ProfilingReport, opcode: &str) -> u64 {
    report
        .instruction_stats
        .get(opcode)
        .map_or(0, |stats| stats.count)
}

fn resolved(syntax: ModuleSyntax, source: &str) -> ResolutionOutcome {
    let mut resolver = DeterministicModuleResolver::new("/profile");
    resolver
        .register_workspace_module("/profile/entry.js", ModuleDefinition::new(syntax, source))
        .expect("register exact source");
    resolver
        .resolve(
            &ModuleRequest::new("/profile/entry.js", ImportStyle::Import)
                .with_compatibility_mode(CompatibilityMode::NodeCompat),
            &ResolutionContext::new("profile-trace", "profile-decision", "profile-policy"),
            &AllowAllPolicy,
        )
        .expect("resolve exact source")
}

#[test]
fn completed_programs_accumulate_once_across_fresh_lane_cores() {
    let source = "let total = 0; for (let i = 0; i < 4; i++) total += i; total;";
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let mut engine = orchestrator(lane, None);
        assert!(engine.profiling_data().is_none());
        engine.enable_profiling(count_config());
        assert!(report(&engine).instruction_stats.is_empty());

        let first = engine
            .execute(&package("profile-first", source))
            .expect("first real execution");
        assert_eq!(first.lane, lane);
        assert_eq!(first.execution_value, "6");
        assert_eq!(first.tier_i_instructions_executed, 0);
        let first_report = report(&engine);
        assert_eq!(count(&first_report, "Add"), 4);
        assert_eq!(count(&first_report, "Lt"), 5);
        assert_eq!(count(&first_report, "Halt"), 1);
        assert!(
            first_report
                .instruction_stats
                .values()
                .all(|stats| { stats.total_time_ns == 0 && stats.average_time_ns == 0 })
        );

        let second = engine
            .execute(&package("profile-second", source))
            .expect("second real execution");
        assert_eq!(second.execution_value, first.execution_value);
        assert_eq!(second.completion_label, first.completion_label);
        assert_eq!(second.instructions_executed, first.instructions_executed);
        let doubled = counts(&first_report)
            .into_iter()
            .map(|(opcode, count)| (opcode, count * 2))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(counts(&report(&engine)), doubled);

        let completed = engine.disable_profiling().expect("completed session");
        let frozen = serde_json::to_value(completed.generate_report("frozen".to_string()))
            .expect("serialize completed report");
        assert!(engine.profiling_data().is_none());
        assert!(engine.disable_profiling().is_none());
        let unprofiled = engine
            .execute(&package("profile-disabled", source))
            .expect("disabled execution");
        assert_eq!(unprofiled.execution_value, first.execution_value);
        assert_eq!(unprofiled.completion_label, first.completion_label);
        assert_eq!(
            unprofiled.instructions_executed,
            first.instructions_executed
        );
        assert!(unprofiled.tier_i_instructions_executed > 0);
        assert_eq!(
            serde_json::to_value(completed.generate_report("frozen".to_string())).unwrap(),
            frozen
        );

        engine.enable_profiling(count_config());
        assert!(report(&engine).instruction_stats.is_empty());
        engine
            .execute(&package("profile-restarted", source))
            .expect("restarted execution");
        assert_eq!(counts(&report(&engine)), counts(&first_report));
    }
}

#[test]
fn failed_execution_keeps_the_faulting_opcode_and_excludes_unexecuted_tail() {
    let source = "const before = 1; null.missing; before * 9;";
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for syntax in [None, Some(ModuleSyntax::EsModule)] {
            let mut engine = orchestrator(lane, syntax);
            engine.enable_profiling(count_config());
            let input = package("profile-failure", source);
            let outcome = if let Some(syntax) = syntax {
                engine.execute_resolved_entry(&input, &resolved(syntax, source))
            } else {
                engine.execute(&input)
            };
            let error = outcome.expect_err("property access must fail at runtime");
            assert!(matches!(
                error.primary_error(),
                OrchestratorError::Interpreter(InterpreterError::TypeError { .. })
            ));
            let failed = report(&engine);
            assert!(count(&failed, "LoadInt") > 0);
            assert_eq!(count(&failed, "LoadNull"), 1);
            assert_eq!(count(&failed, "GetProperty"), 1);
            assert_eq!(count(&failed, "Mul"), 0);
            assert_eq!(count(&failed, "Halt"), 0);

            let rejected = engine
                .execute(&package("profile-parse-refusal", "const = ;"))
                .expect_err("invalid source must be refused before dispatch");
            assert!(matches!(
                rejected.primary_error(),
                OrchestratorError::Parse(_) | OrchestratorError::Lowering(_)
            ));
            assert_eq!(counts(&report(&engine)), counts(&failed));
        }
    }
}

#[test]
fn resolved_esm_and_commonjs_entries_publish_real_allocation_and_opcode_counts() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for syntax in [ModuleSyntax::EsModule, ModuleSyntax::CommonJs] {
            let mut engine = orchestrator(lane, Some(syntax));
            engine.enable_profiling(ProfilingConfig {
                enable_memory_profiling: true,
                ..count_config()
            });
            let entry = resolved(
                syntax,
                "const values = [2, 3]; const box = {value: values[0] + values[1]}; console.log(box.value);",
            );
            let result = engine
                .execute_resolved_entry(&package("profile-resolved", "throw 99;"), &entry)
                .expect("delivered module executes");
            assert_eq!(result.lane, lane);
            assert_eq!(result.console_output[0].message, "5");
            assert_eq!(result.source_label, "/profile/entry.js");
            assert_eq!(result.tier_i_instructions_executed, 0);
            let observed = report(&engine);
            assert_eq!(count(&observed, "Add"), 1);
            assert!(count(&observed, "GetProperty") >= 3);
            assert!(count(&observed, "HostCall") >= 1);
            assert!(observed.memory_stats.objects_allocated >= 1);
            assert!(observed.memory_stats.arrays_allocated >= 1);
        }
    }
}

#[test]
fn enabling_again_replaces_counters_and_applies_the_new_configuration() {
    let mut engine = orchestrator(LaneChoice::QuickJs, None);
    engine.enable_profiling(count_config());
    engine
        .execute(&package("profile-old", "1 + 2;"))
        .expect("initial execution");
    assert!(!report(&engine).instruction_stats.is_empty());

    engine.enable_profiling(ProfilingConfig {
        enable_instruction_profiling: false,
        enable_memory_profiling: true,
        ..count_config()
    });
    assert!(report(&engine).instruction_stats.is_empty());
    assert_eq!(report(&engine).memory_stats.objects_allocated, 0);
    engine
        .execute(&package(
            "profile-memory",
            "const object = {}; const array = [];",
        ))
        .expect("allocation program");
    let observed = report(&engine);
    assert!(observed.instruction_stats.is_empty());
    assert!(observed.memory_stats.objects_allocated >= 1);
    assert!(observed.memory_stats.arrays_allocated >= 1);
}
