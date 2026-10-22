#![forbid(unsafe_code)]

use std::cell::RefCell;
use frankenengine_engine::module_compatibility_matrix::CompatibilityMode;
use frankenengine_engine::module_resolver::{
    DeterministicModuleResolver, ImportStyle, ModuleDefinition, ModuleDependency, ModulePolicyHook,
    ModuleRequest, ModuleResolver, ModuleSyntax, ResolutionContext, ResolutionResult,
};

#[derive(Default)]
struct AuditPolicy {
    calls: RefCell<Vec<(String, Option<String>, String)>>,
}
impl ModulePolicyHook for AuditPolicy {
    fn authorize(
        &self,
        request: &ModuleRequest,
        resolved: &frankenengine_engine::module_resolver::ModuleRecord,
        _context: &ResolutionContext,
    ) -> ResolutionResult<()> {
        self.calls.borrow_mut().push((
            request.specifier.clone(),
            request.referrer.clone(),
            resolved.id.clone(),
        ));
        Ok(())
    }
}
fn context() -> ResolutionContext {
    ResolutionContext::new("graph-trace", "graph-decision", "graph-policy")
}
fn fan_in(branches: usize, copies: usize) -> DeterministicModuleResolver {
    let mut resolver = DeterministicModuleResolver::new("/graph");
    let mut entry = ModuleDefinition::new(ModuleSyntax::CommonJs, "entry");
    for branch in 0..branches {
        entry.dependencies.push(ModuleDependency::new(
            format!("./branch-{branch}.cjs"), ImportStyle::Require));
        let mut definition = ModuleDefinition::new(ModuleSyntax::CommonJs, "branch");
        for _ in 0..copies {
            definition.dependencies.push(ModuleDependency::new(
                "./shared.cjs", ImportStyle::Require));
        }
        resolver.register_workspace_module(format!("branch-{branch}.cjs"), definition).unwrap();
    }
    resolver.register_workspace_module("entry.cjs", entry).unwrap();
    resolver.register_workspace_module(
        "shared.cjs", ModuleDefinition::new(ModuleSyntax::CommonJs, "shared")).unwrap();
    resolver
}

#[test]
fn shared_targets_authorize_every_edge_but_return_once() {
    const BRANCHES: usize = 32;
    const COPIES: usize = 8;
    let resolver = fan_in(BRANCHES, COPIES);
    let policy = AuditPolicy::default();
    let request = ModuleRequest::new("/graph/entry.cjs", ImportStyle::Require)
        .with_compatibility_mode(CompatibilityMode::NodeCompat);
    let outcomes = resolver.resolve_chain(&request, &context(), &policy).unwrap();
    assert_eq!(outcomes.len(), BRANCHES + 2);
    assert_eq!(outcomes[0].module.record.id, "/graph/entry.cjs");
    assert_eq!(outcomes.last().unwrap().module.record.id, "/graph/shared.cjs");
    let calls = policy.calls.borrow();
    assert_eq!(calls.len(), 1 + BRANCHES + BRANCHES * COPIES);
    assert_eq!(calls.iter().filter(|(_, _, id)| id == "/graph/shared.cjs").count(),
        BRANCHES * COPIES);
    for outcome in &outcomes {
        assert_eq!(outcome.module.content_hash, outcome.module.record.canonical_hash());
    }
}

#[test]
fn cycle_back_edges_still_authorize_without_duplicate_outputs() {
    let mut resolver = DeterministicModuleResolver::new("/graph");
    resolver.register_workspace_module(
        "a.cjs",
        ModuleDefinition::new(ModuleSyntax::CommonJs, "a")
            .with_dependency(ModuleDependency::new("./b.cjs", ImportStyle::Require))).unwrap();
    resolver.register_workspace_module(
        "b.cjs",
        ModuleDefinition::new(ModuleSyntax::CommonJs, "b")
            .with_dependency(ModuleDependency::new("./a.cjs", ImportStyle::Require))).unwrap();
    let policy = AuditPolicy::default();
    let request = ModuleRequest::new("/graph/a.cjs", ImportStyle::Require)
        .with_compatibility_mode(CompatibilityMode::NodeCompat);
    let outcomes = resolver.resolve_chain(&request, &context(), &policy).unwrap();
    assert_eq!(outcomes.iter().map(|o| o.module.record.id.as_str()).collect::<Vec<_>>(),
        ["/graph/a.cjs", "/graph/b.cjs"]);
    let calls = policy.calls.borrow();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[2].2, "/graph/a.cjs");
}
