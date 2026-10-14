#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, OrchestratorError,
};
use frankenengine_engine::module_compatibility_matrix::CompatibilityMode;
use frankenengine_engine::module_resolver::{
    AllowAllPolicy, DeterministicModuleResolver, ImportStyle, ModuleDefinition, ModuleDependency,
    ModuleRequest, ModuleResolver, ModuleSyntax, ResolutionContext,
};

fn outcome(
    syntax: ModuleSyntax,
    source: &str,
    dependency: Option<ModuleDependency>,
) -> frankenengine_engine::module_resolver::ResolutionOutcome {
    let mut resolver = DeterministicModuleResolver::new("/app");
    let mut definition = ModuleDefinition::new(syntax, source);
    if let Some(dependency) = dependency {
        definition = definition.with_dependency(dependency);
    }
    resolver
        .register_workspace_module("/app/entry.js", definition)
        .expect("register resolver entry");
    resolver
        .resolve(
            &ModuleRequest::new("/app/entry.js", ImportStyle::Import)
                .with_compatibility_mode(CompatibilityMode::NodeCompat),
            &ResolutionContext::new("trace-resolved", "decision-resolved", "policy-resolved"),
            &AllowAllPolicy,
        )
        .expect("resolve entry")
}

fn package() -> ExtensionPackage {
    ExtensionPackage {
        extension_id: "resolved-entry".to_string(),
        source: "throw new Error('caller source must be ignored');".to_string(),
        source_file: None,
        module_root: None,
        capabilities: vec!["module_load".to_string(), "builtin".to_string()],
        version: "1.0.0".to_string(),
        metadata: Default::default(),
    }
}

#[test]
fn resolved_esm_entry_executes_delivered_source_on_both_profiles() {
    let resolved = outcome(
        ModuleSyntax::EsModule,
        "export const answer = 42; console.log(answer);",
        None,
    );
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let mut orchestrator = ExecutionOrchestrator::new_lab(OrchestratorConfig {
            force_lane: Some(lane),
            parse_goal: ParseGoal::Module,
            ..OrchestratorConfig::default()
        });
        let result = orchestrator
            .execute_resolved_entry(&package(), &resolved)
            .unwrap_or_else(|error| panic!("{lane:?}: {error}"));
        assert_eq!(
            result
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect::<Vec<_>>(),
            ["42"],
            "{lane:?}"
        );
        assert_eq!(result.source_label, "/app/entry.js");
    }
}

#[test]
fn resolved_commonjs_entry_uses_commonjs_runtime_bindings() {
    let resolved = outcome(
        ModuleSyntax::CommonJs,
        "module.exports = { answer: 43 }; console.log(module.exports.answer);",
        None,
    );
    let mut orchestrator = ExecutionOrchestrator::new_lab(OrchestratorConfig {
        parse_goal: ParseGoal::Script,
        commonjs_entry: true,
        ..OrchestratorConfig::default()
    });
    let result = orchestrator
        .execute_resolved_entry(&package(), &resolved)
        .expect("resolved CommonJS entry executes");
    assert_eq!(result.console_output[0].message, "43");
}

#[test]
fn dependency_graph_is_rejected_before_ambient_fallback() {
    let resolved = outcome(
        ModuleSyntax::EsModule,
        "import './dep.js';",
        Some(ModuleDependency::new("./dep.js", ImportStyle::Import)),
    );
    let mut orchestrator = ExecutionOrchestrator::new_lab(OrchestratorConfig {
        parse_goal: ParseGoal::Module,
        ..OrchestratorConfig::default()
    });
    let error = orchestrator
        .execute_resolved_entry(&package(), &resolved)
        .expect_err("dependency graph must fail closed");
    assert!(matches!(error, OrchestratorError::ResolvedEntryRejected { .. }));
    assert!(error.to_string().contains("runtime resolver injection"));
}

#[test]
fn resolved_entry_rechecks_execution_capability_grants() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_workspace_module(
            "/app/entry.js",
            ModuleDefinition::new(ModuleSyntax::EsModule, "console.log('never');")
                .require_capability(RuntimeCapability::NetworkEgress),
        )
        .expect("register entry");
    let resolved = resolver
        .resolve(
            &ModuleRequest::new("/app/entry.js", ImportStyle::Import)
                .with_compatibility_mode(CompatibilityMode::NodeCompat),
            &ResolutionContext::new("trace-resolved", "decision-resolved", "policy-resolved"),
            &AllowAllPolicy,
        )
        .expect("resolve with permissive source-delivery policy");

    let mut orchestrator = ExecutionOrchestrator::new_lab(OrchestratorConfig {
        parse_goal: ParseGoal::Module,
        ..OrchestratorConfig::default()
    });
    let error = orchestrator
        .execute_resolved_entry(&package(), &resolved)
        .expect_err("execution package did not grant network egress");
    assert!(error.to_string().contains("network_egress"));
}
