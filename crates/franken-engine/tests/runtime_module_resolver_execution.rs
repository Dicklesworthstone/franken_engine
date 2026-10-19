#![forbid(unsafe_code)]
//! Execute delivered module graphs through both real interpreter lanes.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::execution_cell::CellError;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, OrchestratorError,
    OrchestratorResult,
};
use frankenengine_engine::module_compatibility_matrix::CompatibilityMode;
use frankenengine_engine::module_resolver::{
    AllowAllPolicy, CapabilityPolicyHook, DeterministicModuleResolver, ExecutionModuleResolver,
    ImportStyle, ModuleDefinition, ModuleDependency, ModulePolicyHook, ModuleRecord, ModuleRequest,
    ModuleResolver, ModuleSourceLocation, ModuleSyntax, NativeBuiltinModule, ResolutionContext,
    ResolutionOutcome, ResolutionResult,
};
use frankenengine_engine::runtime_config::RuntimeConfig;

const ROOT: &str = "/captured-module-test";
const ID_PREFIX: &str = "captured:";

#[derive(Clone, Copy, Default)]
enum Corruption {
    #[default]
    None,
    StaleHash,
    ChangeCachedSource,
    ForgeBuiltin,
    MalformedBuiltinMarker,
    ChangeBuiltinProvider,
    BuiltinAliasesEntry,
    Panic,
}

/// The real deterministic resolver supplies source and package resolution.
/// This adapter gives its records opaque identities to exercise the runtime
/// boundary; it does not parse, lower, cache values, or execute JavaScript.
struct OpaqueResolver {
    inner: DeterministicModuleResolver,
    requests: Mutex<Vec<ModuleRequest>>,
    corruption: Corruption,
}

impl OpaqueResolver {
    fn new(modules: Vec<(&str, ModuleDefinition)>) -> Self {
        let mut inner = DeterministicModuleResolver::new(ROOT);
        for (name, module) in modules {
            inner
                .register_workspace_module(name, module)
                .expect("fixture source");
        }
        Self {
            inner,
            requests: Mutex::new(Vec::new()),
            corruption: Corruption::None,
        }
    }

    fn with_native_builtins(mut self) -> Self {
        for native in [
            NativeBuiltinModule::Buffer,
            NativeBuiltinModule::Events,
            NativeBuiltinModule::Os,
            NativeBuiltinModule::Querystring,
            NativeBuiltinModule::Url,
            NativeBuiltinModule::Timers,
            NativeBuiltinModule::PerfHooks,
        ] {
            let canonical = native.canonical_specifier();
            for name in [canonical, canonical.strip_prefix("node:").expect("core prefix")] {
                let record = native.record(format!("builtin:{name}"));
                self.inner
                    .register_builtin(
                        name,
                        ModuleDefinition {
                            syntax: record.syntax,
                            source: record.source,
                            dependencies: record.dependencies,
                            required_capabilities: record.required_capabilities,
                            provenance_origin: record.provenance.origin,
                        },
                    )
                    .expect("real native provider descriptor");
            }
        }
        self
    }
}

impl ModuleResolver for OpaqueResolver {
    fn resolve(
        &self,
        request: &ModuleRequest,
        context: &ResolutionContext,
        policy: &dyn ModulePolicyHook,
    ) -> ResolutionResult<ResolutionOutcome> {
        let occurrence = {
            let mut requests = self.requests.lock().expect("request log");
            requests.push(request.clone());
            requests.iter().filter(|prior| *prior == request).count()
        };
        let mut translated = request.clone();
        if let Some(referrer) = translated.referrer.as_mut()
            && let Some(path) = referrer.strip_prefix(ID_PREFIX)
        {
            *referrer = path.to_string();
        }
        let mut outcome = self.inner.resolve(&translated, context, &AllowAllPolicy)?;
        outcome.module.record.id = format!("{ID_PREFIX}{}", outcome.module.record.id);
        outcome.module.canonical_specifier = outcome.module.record.id.clone();
        outcome.module.content_hash = outcome.module.record.canonical_hash();
        policy.authorize(request, &outcome.module.record, context)?;
        if request.specifier == "./dep.cjs" {
            match self.corruption {
                Corruption::StaleHash => {
                    outcome.module.record.source = "module.exports = { answer: 99 };".to_string();
                }
                Corruption::ChangeCachedSource if occurrence > 1 => {
                    outcome.module.record.source = "module.exports = { answer: 99 };".to_string();
                    outcome.module.content_hash = outcome.module.record.canonical_hash();
                }
                Corruption::Panic => panic!("injected resolver panic"),
                _ => {}
            }
        }
        if NativeBuiltinModule::from_record(&outcome.module.record).is_some() {
            match self.corruption {
                Corruption::ForgeBuiltin => {
                    outcome.module.record.source =
                        "throw new Error('a builtin descriptor must never execute source');"
                            .to_string();
                    outcome.module.content_hash = outcome.module.record.canonical_hash();
                }
                Corruption::MalformedBuiltinMarker => {
                    outcome.module.record.provenance.origin =
                        "franken-engine/native-builtin/v99:node:querystring".to_string();
                    outcome.module.content_hash = outcome.module.record.canonical_hash();
                }
                Corruption::ChangeBuiltinProvider if occurrence > 1 => {
                    outcome.module.record =
                        NativeBuiltinModule::Buffer.record(outcome.module.record.id.clone());
                    outcome.module.content_hash = outcome.module.record.canonical_hash();
                }
                Corruption::BuiltinAliasesEntry => {
                    outcome.module.record.id = format!("{ID_PREFIX}{ROOT}/entry.cjs");
                    outcome.module.canonical_specifier = outcome.module.record.id.clone();
                    outcome.module.content_hash = outcome.module.record.canonical_hash();
                }
                _ => {}
            }
        }
        Ok(outcome)
    }

    fn resolve_chain(
        &self,
        entry: &ModuleRequest,
        context: &ResolutionContext,
        policy: &dyn ModulePolicyHook,
    ) -> ResolutionResult<Vec<ResolutionOutcome>> {
        let mut queue = VecDeque::from([entry.clone()]);
        let mut seen = BTreeSet::new();
        let mut output = Vec::new();
        while let Some(request) = queue.pop_front() {
            let outcome = self.resolve(&request, context, policy)?;
            if seen.insert(outcome.module.record.id.clone()) {
                for dependency in &outcome.module.record.dependencies {
                    queue.push_back(
                        ModuleRequest::new(&dependency.specifier, dependency.style)
                            .with_referrer(&outcome.module.record.id)
                            .with_compatibility_mode(CompatibilityMode::NodeCompat),
                    );
                }
                output.push(outcome);
            }
        }
        Ok(output)
    }
}

#[derive(Default)]
struct RecordingPolicy {
    requests: Mutex<Vec<(ModuleRequest, ResolutionContext)>>,
    denied: Option<(String, usize)>,
    allow_native_builtins: bool,
}

impl ModulePolicyHook for RecordingPolicy {
    fn authorize(
        &self,
        request: &ModuleRequest,
        record: &ModuleRecord,
        context: &ResolutionContext,
    ) -> ResolutionResult<()> {
        let count = {
            let mut calls = self.requests.lock().expect("policy log");
            calls.push((request.clone(), context.clone()));
            calls
                .iter()
                .filter(|(prior, _)| prior.specifier == request.specifier)
                .count()
        };
        let mut grants = BTreeSet::from([RuntimeCapability::ModuleLoad]);
        if self.allow_native_builtins {
            grants.extend([RuntimeCapability::Builtin, RuntimeCapability::Timer]);
        }
        let mut policy = CapabilityPolicyHook::new(grants);
        if self
            .denied
            .as_ref()
            .is_some_and(|(specifier, after)| request.specifier == *specifier && count >= *after)
        {
            policy.denied_specifiers.insert(request.specifier.clone());
        }
        policy.authorize(request, record, context)
    }
}

fn definition(syntax: ModuleSyntax, source: &str) -> ModuleDefinition {
    ModuleDefinition::new(syntax, source).require_capability(RuntimeCapability::ModuleLoad)
}

fn entry(resolver: &OpaqueResolver, name: &str, syntax: ModuleSyntax) -> ResolutionOutcome {
    let style = if syntax == ModuleSyntax::CommonJs {
        ImportStyle::Require
    } else {
        ImportStyle::Import
    };
    resolver
        .resolve(
            &ModuleRequest::new(format!("./{name}"), style)
                .with_compatibility_mode(CompatibilityMode::NodeCompat),
            &ResolutionContext::new("admission", "admission-decision", "admission-policy"),
            &AllowAllPolicy,
        )
        .expect("authorized source entry")
}

fn package() -> ExtensionPackage {
    ExtensionPackage {
        extension_id: "delivered-source-test".to_string(),
        // The admitted resolver source must replace this unexecuted payload.
        source: "throw new Error('wrong source');".to_string(),
        source_file: Some("/this/path/must/not/be/opened.js".to_string()),
        module_root: None,
        capabilities: vec![
            "module_load".to_string(),
            "builtin".to_string(),
            "timer".to_string(),
        ],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    }
}

fn orchestrator(lane: LaneChoice, syntax: ModuleSyntax) -> ExecutionOrchestrator {
    ExecutionOrchestrator::try_new_lab_with_runtime_config(
        OrchestratorConfig {
            force_lane: Some(lane),
            parse_goal: if syntax == ModuleSyntax::CommonJs {
                ParseGoal::Script
            } else {
                ParseGoal::Module
            },
            commonjs_entry: syntax == ModuleSyntax::CommonJs,
            policy_id: "runtime-source-policy".to_string(),
            ..OrchestratorConfig::default()
        },
        RuntimeConfig::default(),
    )
    .expect("native test runtime")
}

fn lines(result: &OrchestratorResult) -> Vec<&str> {
    result
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect()
}

#[test]
fn delivered_commonjs_graph_preserves_cycles_cache_and_per_edge_authorization() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let resolver = Arc::new(OpaqueResolver::new(vec![
            ("entry.cjs", definition(ModuleSyntax::CommonJs,
                "exports.name = 'entry'; const a = require('./child.cjs'); const b = require('./child.cjs'); console.log(a.name, a.parent, a === b);")
                .with_dependency(ModuleDependency::new("./child.cjs", ImportStyle::Require))),
            ("child.cjs", definition(ModuleSyntax::CommonJs,
                "exports.name = 'child'; exports.parent = require('./entry.cjs').name;")
                .with_dependency(ModuleDependency::new("./entry.cjs", ImportStyle::Require))),
        ]));
        let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
        let policy = Arc::new(RecordingPolicy::default());
        let installed =
            ExecutionModuleResolver::new(&source.module.record.id, resolver, policy.clone());
        let result = orchestrator(lane, ModuleSyntax::CommonJs)
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect("the native runtime executes the delivered CommonJS cycle");
        assert_eq!(lines(&result), ["child entry true"]);
        let calls = policy.requests.lock().expect("policy log");
        assert_eq!(
            calls
                .iter()
                .map(|(request, _)| request.specifier.as_str())
                .collect::<Vec<_>>(),
            ["./child.cjs", "./entry.cjs", "./child.cjs"]
        );
        assert!(calls.iter().all(|(request, context)| {
            request
                .referrer
                .as_deref()
                .is_some_and(|id| id.starts_with(ID_PREFIX))
                && request.compatibility_mode == CompatibilityMode::NodeCompat
                && context.trace_id == result.trace_id
                && context.policy_id == "runtime-source-policy"
        }));
    }
}

#[test]
fn delivered_esm_graph_retains_live_bindings_dynamic_import_and_source_metadata() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let resolver = Arc::new(OpaqueResolver::new(vec![
            ("entry.mjs", definition(ModuleSyntax::EsModule,
                "import { count, inc, meta } from './dep.mjs'; console.log(count); inc(); console.log(count); console.log(meta.url, meta.dirname); console.log(import.meta.url); import('./dep.mjs').then(m => console.log(m.count, m.meta === meta));")
                .with_dependency(ModuleDependency::new("./dep.mjs", ImportStyle::Import))),
            ("dep.mjs", definition(ModuleSyntax::EsModule,
                "export let count = 1; export function inc() { count = count + 1; } export const meta = import.meta;")),
        ]));
        let source = entry(&resolver, "entry.mjs", ModuleSyntax::EsModule);
        let policy = Arc::new(RecordingPolicy::default());
        let installed =
            ExecutionModuleResolver::new(&source.module.record.id, resolver, policy.clone())
                .with_source_locations(BTreeMap::from([
                    (
                        format!("{ID_PREFIX}{ROOT}/entry.mjs"),
                        ModuleSourceLocation {
                            filename: PathBuf::from("/original project/entry.mjs"),
                            url: "file:///original%20project/entry.mjs".to_string(),
                        },
                    ),
                    (
                        format!("{ID_PREFIX}{ROOT}/dep.mjs"),
                        ModuleSourceLocation {
                            filename: PathBuf::from("/original project/dep.mjs"),
                            url: "file:///original%20project/dep.mjs?instance=1#kept".to_string(),
                        },
                    ),
                ]));
        let result = orchestrator(lane, ModuleSyntax::EsModule)
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect("real ESM evaluation over supplied sources");
        assert_eq!(
            lines(&result),
            [
                "1",
                "2",
                "file:///original%20project/dep.mjs?instance=1#kept /original project",
                "file:///original%20project/entry.mjs",
                "2 true"
            ]
        );
        assert_eq!(
            policy.requests.lock().expect("policy log").len(),
            2,
            "the cached dynamic import must authorize its route again"
        );
    }
}

#[test]
fn delivered_commonjs_metadata_and_require_resolve_use_captured_origin() {
    let resolver = Arc::new(OpaqueResolver::new(vec![
        (
            "entry.cjs",
            definition(
                ModuleSyntax::CommonJs,
                "console.log(__filename, __dirname); console.log(require.resolve('./dep.cjs')); console.log(require('./dep.cjs').file);",
            ),
        ),
        (
            "dep.cjs",
            definition(ModuleSyntax::CommonJs, "exports.file = __filename;"),
        ),
    ]));
    let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
    let policy = Arc::new(RecordingPolicy::default());
    let locations = ["entry.cjs", "dep.cjs"]
        .into_iter()
        .map(|name| {
            (
                format!("{ID_PREFIX}{ROOT}/{name}"),
                ModuleSourceLocation {
                    filename: PathBuf::from(format!("/original/{name}")),
                    url: format!("file:///original/{name}"),
                },
            )
        })
        .collect();
    let installed =
        ExecutionModuleResolver::new(&source.module.record.id, resolver, policy.clone())
            .with_source_locations(locations);
    let result = orchestrator(LaneChoice::QuickJs, ModuleSyntax::CommonJs)
        .execute_resolved_entry_with_resolver(&package(), &source, installed)
        .expect("captured metadata is usable without reopening its paths");
    assert_eq!(
        lines(&result),
        [
            "/original/entry.cjs /original",
            "/original/dep.cjs",
            "/original/dep.cjs"
        ]
    );
    assert_eq!(policy.requests.lock().expect("policy log").len(), 2);
}

#[test]
fn delivered_entry_identity_does_not_trigger_source_renormalization() {
    let resolver = Arc::new(OpaqueResolver::new(vec![(
        "entry.ts",
        definition(
            ModuleSyntax::CommonJs,
            "console.log('exact prepared bytes');",
        ),
    )]));
    let source = entry(&resolver, "entry.ts", ModuleSyntax::CommonJs);
    let installed =
        ExecutionModuleResolver::new(&source.module.record.id, resolver, Arc::new(AllowAllPolicy));
    let result = orchestrator(LaneChoice::QuickJs, ModuleSyntax::CommonJs)
        .execute_resolved_entry_with_resolver(&package(), &source, installed)
        .expect("record syntax and delivered bytes override the opaque id's suffix");
    assert_eq!(lines(&result), ["exact prepared bytes"]);
    assert!(!result.source_ingestion.normalization_applied);
    assert_eq!(
        result.source_ingestion.original_source_hash,
        result.source_ingestion.normalized_source_hash
    );
}

#[test]
fn delivered_cache_hit_cannot_bypass_a_changed_policy() {
    let resolver = Arc::new(OpaqueResolver::new(vec![
        (
            "entry.cjs",
            definition(
                ModuleSyntax::CommonJs,
                "console.log(require('./dep.cjs').answer); console.log(require('./dep.cjs').answer);",
            ),
        ),
        (
            "dep.cjs",
            definition(ModuleSyntax::CommonJs, "exports.answer = 42;"),
        ),
    ]));
    let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
    let policy = Arc::new(RecordingPolicy {
        denied: Some(("./dep.cjs".to_string(), 2)),
        ..RecordingPolicy::default()
    });
    let installed =
        ExecutionModuleResolver::new(&source.module.record.id, resolver, policy.clone());
    let mut engine = orchestrator(LaneChoice::QuickJs, ModuleSyntax::CommonJs);
    let error = engine
        .execute_resolved_entry_with_resolver(&package(), &source, installed)
        .expect_err("the second, cached require is denied");
    assert!(
        error
            .to_string()
            .contains("closed-world module resolution refused"),
        "{error}"
    );
    assert_eq!(policy.requests.lock().expect("policy log").len(), 2);
    assert_eq!(
        engine
            .last_failed_console_output()
            .iter()
            .map(|entry| entry.message.as_str())
            .collect::<Vec<_>>(),
        ["42"]
    );
    assert!(
        error
            .post_cell_failure()
            .expect("runtime cleanup")
            .cleanup
            .close_succeeded()
    );
}

#[test]
fn delivered_sources_reject_stale_hashes_and_changed_cached_records() {
    for corruption in [Corruption::StaleHash, Corruption::ChangeCachedSource] {
        let mut resolver = OpaqueResolver::new(vec![
            (
                "entry.cjs",
                definition(
                    ModuleSyntax::CommonJs,
                    "require('./dep.cjs'); require('./dep.cjs');",
                ),
            ),
            (
                "dep.cjs",
                definition(ModuleSyntax::CommonJs, "exports.answer = 42;"),
            ),
        ]);
        resolver.corruption = corruption;
        let resolver = Arc::new(resolver);
        let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
        let installed = ExecutionModuleResolver::new(
            &source.module.record.id,
            resolver,
            Arc::new(AllowAllPolicy),
        );
        let error = orchestrator(LaneChoice::QuickJs, ModuleSyntax::CommonJs)
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect_err("source authentication must precede cached execution");
        let expected = match corruption {
            Corruption::StaleHash => "canonical content hash is inconsistent",
            _ => "changed after its first authorized load",
        };
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
fn delivered_sources_keep_package_capabilities_and_parser_budgets() {
    let resolver = Arc::new(OpaqueResolver::new(vec![
        (
            "entry.cjs",
            definition(ModuleSyntax::CommonJs, "require('./dep.cjs');"),
        ),
        (
            "dep.cjs",
            definition(ModuleSyntax::CommonJs, "console.log('must not execute');")
                .require_capability(RuntimeCapability::FsRead),
        ),
    ]));
    let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
    let installed =
        ExecutionModuleResolver::new(&source.module.record.id, resolver, Arc::new(AllowAllPolicy));
    let mut engine = orchestrator(LaneChoice::QuickJs, ModuleSyntax::CommonJs);
    let error = engine
        .execute_resolved_entry_with_resolver(&package(), &source, installed)
        .expect_err("an admitting resolver cannot add package capabilities");
    assert!(error.to_string().contains("fs_read"), "{error}");
    assert!(engine.last_failed_console_output().is_empty());

    let long_source = format!("{}exports.answer = 42;", " ".repeat(128));
    let resolver = Arc::new(OpaqueResolver::new(vec![
        (
            "entry.cjs",
            definition(ModuleSyntax::CommonJs, "require('./dep.cjs');"),
        ),
        ("dep.cjs", definition(ModuleSyntax::CommonJs, &long_source)),
    ]));
    let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
    let installed =
        ExecutionModuleResolver::new(&source.module.record.id, resolver, Arc::new(AllowAllPolicy));
    let mut config = OrchestratorConfig {
        force_lane: Some(LaneChoice::QuickJs),
        parse_goal: ParseGoal::Script,
        commonjs_entry: true,
        ..OrchestratorConfig::default()
    };
    config.parser_options.budget.max_source_bytes = 64;
    let mut engine =
        ExecutionOrchestrator::try_new_lab_with_runtime_config(config, RuntimeConfig::default())
            .expect("native test runtime");
    let error = engine
        .execute_resolved_entry_with_resolver(&package(), &source, installed)
        .expect_err("delivered dependencies must retain parser admission budgets");
    assert!(
        error.to_string().contains("parser source-byte budget"),
        "{error}"
    );
}

#[test]
fn delivered_unknown_routes_fail_closed_and_installation_does_not_leak() {
    let resolver = Arc::new(OpaqueResolver::new(vec![(
        "entry.cjs",
        definition(
            ModuleSyntax::CommonJs,
            "try { require('./not-captured.cjs'); } catch (e) { console.log('must not hide refusal'); }",
        ),
    )]));
    let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
    let installed =
        ExecutionModuleResolver::new(&source.module.record.id, resolver, Arc::new(AllowAllPolicy));
    let mut engine = orchestrator(LaneChoice::QuickJs, ModuleSyntax::CommonJs);
    let error = engine
        .execute_resolved_entry_with_resolver(&package(), &source, installed)
        .expect_err("an uncaptured route must not reach ambient filesystem resolution");
    assert!(
        error
            .to_string()
            .contains("closed-world module resolution refused"),
        "{error}"
    );
    assert!(engine.last_failed_console_output().is_empty());
    let mut ordinary = package();
    ordinary.source = "console.log('ordinary');".to_string();
    ordinary.source_file = None;
    let result = engine
        .execute(&ordinary)
        .expect("later ordinary execution has no stale installation");
    assert_eq!(lines(&result), ["ordinary"]);
}

#[test]
fn delivered_resolver_panic_preserves_cell_cleanup_and_restores_installation() {
    let mut resolver = OpaqueResolver::new(vec![
        (
            "entry.cjs",
            definition(ModuleSyntax::CommonJs, "require('./dep.cjs');"),
        ),
        (
            "dep.cjs",
            definition(ModuleSyntax::CommonJs, "exports.answer = 42;"),
        ),
    ]);
    resolver.corruption = Corruption::Panic;
    let resolver = Arc::new(resolver);
    let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
    let installed =
        ExecutionModuleResolver::new(&source.module.record.id, resolver, Arc::new(AllowAllPolicy));
    let mut engine = orchestrator(LaneChoice::QuickJs, ModuleSyntax::CommonJs);
    let error = engine
        .execute_resolved_entry_with_resolver(&package(), &source, installed)
        .expect_err("the execution cell must classify a resolver panic");
    assert!(
        matches!(
            error.primary_error(),
            OrchestratorError::Cell(CellError::InterpreterPanicked { .. })
        ),
        "{error}"
    );
    assert!(
        error
            .post_cell_failure()
            .expect("panic still follows cell cleanup")
            .cleanup
            .close_succeeded()
    );
    let mut ordinary = package();
    ordinary.source = "console.log('after panic');".to_string();
    ordinary.source_file = None;
    let result = engine
        .execute(&ordinary)
        .expect("a classified resolver panic cannot contaminate an ordinary run");
    assert_eq!(lines(&result), ["after panic"]);
}

#[test]
fn delivered_native_builtins_execute_real_providers_and_preserve_alias_identity() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let resolver = Arc::new(
            OpaqueResolver::new(vec![(
                "entry.cjs",
                definition(
                    ModuleSyntax::CommonJs,
                    r#"
const load = require;
const q = load('querystring');
q.marker = 17;
console.log(require('node:querystring') === q, require('querystring').marker);
console.log(q.stringify({ a: 'x y' }));
console.log(load('buffer').Buffer.from('abc').length);
console.log(typeof load('events'), typeof load('os').EOL,
    typeof load('url').URL, typeof load('timers').setTimeout,
    typeof load('perf_hooks').performance.now);
console.log(require.resolve('querystring'), require.resolve('node:querystring'));
"#,
                ),
            )])
            .with_native_builtins(),
        );
        let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
        let policy = Arc::new(RecordingPolicy {
            allow_native_builtins: true,
            ..RecordingPolicy::default()
        });
        let installed =
            ExecutionModuleResolver::new(&source.module.record.id, resolver, policy.clone());
        let result = orchestrator(lane, ModuleSyntax::CommonJs)
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect("admitted descriptors dispatch the engine's real core providers");
        assert_eq!(
            lines(&result),
            [
                "true 17",
                "a=x%20y",
                "3",
                "function string function function function",
                "querystring node:querystring"
            ]
        );
        assert_eq!(
            policy.requests.lock().expect("policy log").len(),
            11,
            "aliases, cached objects and require.resolve must all authorize their route"
        );
    }
}

#[test]
fn delivered_native_builtin_cache_cannot_bypass_policy_in_nested_source() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let resolver = Arc::new(
            OpaqueResolver::new(vec![
                (
                    "entry.cjs",
                    definition(
                        ModuleSyntax::CommonJs,
                        "const q = require('querystring'); console.log(q.stringify({ a: 'x' })); require('./child.cjs');",
                    )
                    .with_dependency(ModuleDependency::new("./child.cjs", ImportStyle::Require)),
                ),
                (
                    "child.cjs",
                    definition(
                        ModuleSyntax::CommonJs,
                        "const q = require('querystring'); console.log(q.stringify({ blocked: 'x' }));",
                    ),
                ),
            ])
            .with_native_builtins(),
        );
        let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
        let policy = Arc::new(RecordingPolicy {
            denied: Some(("querystring".to_string(), 2)),
            allow_native_builtins: true,
            ..RecordingPolicy::default()
        });
        let installed =
            ExecutionModuleResolver::new(&source.module.record.id, resolver, policy.clone());
        let mut engine = orchestrator(lane, ModuleSyntax::CommonJs);
        let error = engine
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect_err("nested literal require must authorize before returning a cached core object");
        assert!(
            error
                .to_string()
                .contains("closed-world module resolution refused"),
            "{error}"
        );
        assert_eq!(
            engine
                .last_failed_console_output()
                .iter()
                .map(|entry| entry.message.as_str())
                .collect::<Vec<_>>(),
            ["a=x"]
        );
        assert_eq!(
            policy
                .requests
                .lock()
                .expect("policy log")
                .iter()
                .filter(|(request, _)| request.specifier == "querystring")
                .count(),
            2
        );
    }
}

#[test]
fn delivered_native_descriptors_reject_forgery_and_cached_provider_substitution() {
    for corruption in [
        Corruption::ForgeBuiltin,
        Corruption::MalformedBuiltinMarker,
        Corruption::ChangeBuiltinProvider,
        Corruption::BuiltinAliasesEntry,
    ] {
        let mut resolver = OpaqueResolver::new(vec![(
            "entry.cjs",
            definition(
                ModuleSyntax::CommonJs,
                "require('querystring'); require('querystring');",
            ),
        )])
        .with_native_builtins();
        resolver.corruption = corruption;
        let resolver = Arc::new(resolver);
        let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
        let installed = ExecutionModuleResolver::new(
            &source.module.record.id,
            resolver,
            Arc::new(AllowAllPolicy),
        );
        let error = orchestrator(LaneChoice::QuickJs, ModuleSyntax::CommonJs)
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect_err("native descriptor validation and identity pinning precede provider dispatch");
        let expected = match corruption {
            Corruption::ChangeBuiltinProvider | Corruption::BuiltinAliasesEntry => {
                "changed after its first authorized load"
            }
            _ => "not an authenticated native provider descriptor",
        };
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
fn delivered_source_defined_builtins_keep_ordinary_source_execution() {
    let mut resolver = OpaqueResolver::new(vec![(
        "entry.cjs",
        definition(
            ModuleSyntax::CommonJs,
            "console.log(require('source-builtin'));",
        ),
    )]);
    resolver
        .inner
        .register_builtin(
            "source-builtin",
            definition(ModuleSyntax::CommonJs, "module.exports = 17;")
                .with_provenance("application/builtin-source"),
        )
        .expect("ordinary source-defined builtin");
    let resolver = Arc::new(resolver);
    let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
    let installed =
        ExecutionModuleResolver::new(&source.module.record.id, resolver, Arc::new(AllowAllPolicy));
    let result = orchestrator(LaneChoice::QuickJs, ModuleSyntax::CommonJs)
        .execute_resolved_entry_with_resolver(&package(), &source, installed)
        .expect("the reserved native descriptor contract does not replace source-defined builtins");
    assert_eq!(lines(&result), ["17"]);
}

#[test]
fn delivered_unknown_native_alias_cannot_use_an_already_cached_provider() {
    let mut resolver = OpaqueResolver::new(vec![(
        "entry.cjs",
        definition(
            ModuleSyntax::CommonJs,
            "console.log(require('querystring').stringify({ a: 'x' })); require('node:querystring');",
        ),
    )]);
    let record = NativeBuiltinModule::Querystring.record("builtin:querystring");
    resolver
        .inner
        .register_builtin(
            "querystring",
            ModuleDefinition {
                syntax: record.syntax,
                source: record.source,
                dependencies: record.dependencies,
                required_capabilities: record.required_capabilities,
                provenance_origin: record.provenance.origin,
            },
        )
        .expect("only the bare querystring route is admitted");
    let resolver = Arc::new(resolver);
    let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
    let installed =
        ExecutionModuleResolver::new(&source.module.record.id, resolver, Arc::new(AllowAllPolicy));
    let mut engine = orchestrator(LaneChoice::QuickJs, ModuleSyntax::CommonJs);
    let error = engine
        .execute_resolved_entry_with_resolver(&package(), &source, installed)
        .expect_err("an uncaptured alias must not inherit another route's authorization");
    assert!(
        error
            .to_string()
            .contains("closed-world module resolution refused"),
        "{error}"
    );
    assert_eq!(
        engine
            .last_failed_console_output()
            .iter()
            .map(|entry| entry.message.as_str())
            .collect::<Vec<_>>(),
        ["a=x"]
    );
}
