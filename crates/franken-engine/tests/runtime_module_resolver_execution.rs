#![forbid(unsafe_code)]
//! Execute delivered module graphs through both real interpreter lanes.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterError, LaneChoice};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::execution_cell::CellError;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, OrchestratorError,
    OrchestratorResult,
};
use frankenengine_engine::lowering_pipeline::AmbientAuthorityGrant;
use frankenengine_engine::module_compatibility_matrix::CompatibilityMode;
use frankenengine_engine::module_resolver::{
    AllowAllPolicy, CapabilityPolicyHook, DeterministicModuleResolver, ExecutionModuleResolver,
    ImportStyle, ModuleDefinition, ModuleDependency, ModulePolicyHook, ModuleRecord, ModuleRequest,
    ModuleResolver, ModuleSourceLocation, ModuleSyntax, NativeBuiltinModule, ResolutionContext,
    ResolutionErrorCode, ResolutionOutcome, ResolutionResult,
};
use frankenengine_engine::runtime_config::RuntimeConfig;
use frankenengine_extension_host::host_io::{
    HostIoCapability, HostIoControl, HostIoError, HostIoExceptionProvenance, HostIoOutcome,
    HostIoProvider, HostIoRecorder, HostIoRequest, InMemoryHostIoTranscript, SandboxedHostIo,
};

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
    ChangePathProvider,
    BuiltinAliasesEntry,
    BuiltinAliasesFactory(&'static str),
    Panic,
}

/// The real deterministic resolver supplies source and package resolution.
/// This adapter gives its records opaque identities to exercise the runtime
/// boundary; it does not parse, lower, cache values, or execute JavaScript.
struct OpaqueResolver {
    inner: DeterministicModuleResolver,
    requests: Mutex<Vec<ModuleRequest>>,
    corruption: Corruption,
    missing_routes: BTreeSet<String>,
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
            missing_routes: BTreeSet::new(),
        }
    }

    fn with_missing_route(mut self, specifier: &str) -> Self {
        self.missing_routes.insert(specifier.to_string());
        self
    }

    fn with_native_builtins(mut self) -> Self {
        for native in [
            NativeBuiltinModule::Buffer,
            NativeBuiltinModule::Crypto,
            NativeBuiltinModule::Zlib,
            NativeBuiltinModule::Module,
            NativeBuiltinModule::Events,
            NativeBuiltinModule::Os,
            NativeBuiltinModule::Querystring,
            NativeBuiltinModule::Url,
            NativeBuiltinModule::Timers,
            NativeBuiltinModule::PerfHooks,
            NativeBuiltinModule::Path,
            NativeBuiltinModule::PathPosix,
            NativeBuiltinModule::PathWin32,
            NativeBuiltinModule::Util,
            NativeBuiltinModule::UtilTypes,
            NativeBuiltinModule::Assert,
            NativeBuiltinModule::AssertStrict,
            NativeBuiltinModule::StringDecoder,
            NativeBuiltinModule::TimersPromises,
            NativeBuiltinModule::Stream,
            NativeBuiltinModule::StreamPromises,
        ] {
            let canonical = native.canonical_specifier();
            let names = [
                canonical,
                canonical.strip_prefix("node:").expect("core prefix"),
            ];
            for name in names {
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
        let mut outcome = self
            .inner
            .resolve(&translated, context, &AllowAllPolicy)
            .map_err(|mut error| {
                // This fixture models a closed graph, rather than an open
                // package resolver: only explicitly captured negative routes
                // represent catchable absence. Unknown routes stay refused.
                if error.code == ResolutionErrorCode::ModuleNotFound
                    && !self.missing_routes.contains(&request.specifier)
                {
                    error.code = ResolutionErrorCode::UnsupportedSpecifier;
                }
                error
            })?;
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
                Corruption::ChangePathProvider if occurrence > 1 => {
                    outcome.module.record =
                        NativeBuiltinModule::PathWin32.record(outcome.module.record.id.clone());
                    outcome.module.content_hash = outcome.module.record.canonical_hash();
                }
                Corruption::BuiltinAliasesEntry => {
                    outcome.module.record.id = format!("{ID_PREFIX}{ROOT}/entry.cjs");
                    outcome.module.canonical_specifier = outcome.module.record.id.clone();
                    outcome.module.content_hash = outcome.module.record.canonical_hash();
                }
                Corruption::BuiltinAliasesFactory(id) => {
                    outcome.module.record.id = id.into();
                    outcome.module.canonical_specifier = id.into();
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
    denial_code: Option<ResolutionErrorCode>,
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
        policy.authorize(request, record, context).map_err(|mut error| {
            if let Some(code) = self.denial_code {
                error.code = code;
                error.event.error_code = code.stable_code().to_string();
            }
            error
        })
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
            &ModuleRequest::new(format!("{ROOT}/{name}"), style)
                .with_compatibility_mode(CompatibilityMode::NodeCompat),
            &ResolutionContext::new("admission", "admission-decision", "admission-policy"),
            &AllowAllPolicy,
        )
        .expect("authorized source entry")
}

#[test]
fn relative_entry_without_referrer_still_fails_before_source_execution() {
    let resolver = OpaqueResolver::new(vec![(
        "entry.cjs",
        definition(
            ModuleSyntax::CommonJs,
            "throw new Error('must not execute');",
        ),
    )]);
    let error = resolver
        .resolve(
            &ModuleRequest::new("./entry.cjs", ImportStyle::Require)
                .with_compatibility_mode(CompatibilityMode::NodeCompat),
            &ResolutionContext::new("admission", "admission-decision", "admission-policy"),
            &AllowAllPolicy,
        )
        .expect_err("relative entry admission needs an authenticated referrer");
    assert_eq!(error.code, ResolutionErrorCode::InvalidReferrer);
    assert!(error.probe_sequence.is_empty());
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
fn delivered_create_require_retains_origin_and_shared_native_provider() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let resolver = Arc::new(
            OpaqueResolver::new(vec![
                (
                    "entry.mjs",
                    definition(
                        ModuleSyntax::EsModule,
                        r#"
                        import bare, { createRequire as make } from 'module';
                        import native from 'node:module';
                        import { requireHere, resolveHere, factory } from './nested/loader.mjs';
                        const rootRequire = factory(import.meta.url);
                        console.log(bare === native, make === native.createRequire, make.name, make.length);
                        console.log(rootRequire('./dep.cjs').value, requireHere('./dep.cjs').value);
                        console.log(resolveHere('./throw.cjs'));
                        console.log(requireHere.resolve('./throw.cjs'));
                        console.log(rootRequire('./dep.cjs').value);
                        "#,
                    ),
                ),
                (
                    "nested/loader.mjs",
                    definition(
                        ModuleSyntax::EsModule,
                        r#"
                        import { createRequire } from 'node:module';
                        export const requireHere = createRequire(import.meta.url);
                        export const resolveHere = requireHere.resolve;
                        export const factory = createRequire;
                        "#,
                    ),
                ),
                (
                    "dep.cjs",
                    definition(ModuleSyntax::CommonJs, "exports.value = 'root';"),
                ),
                (
                    "nested/dep.cjs",
                    definition(ModuleSyntax::CommonJs, "exports.value = 'nested';"),
                ),
                (
                    "nested/throw.cjs",
                    definition(
                        ModuleSyntax::CommonJs,
                        "throw new Error('resolve must not evaluate this source');",
                    ),
                ),
            ])
            .with_native_builtins(),
        );
        let source = entry(&resolver, "entry.mjs", ModuleSyntax::EsModule);
        let policy = Arc::new(RecordingPolicy {
            allow_native_builtins: true,
            ..RecordingPolicy::default()
        });
        let mut locations: BTreeMap<_, _> = [
            "entry.mjs",
            "nested/loader.mjs",
            "dep.cjs",
            "nested/dep.cjs",
            "nested/throw.cjs",
        ]
        .into_iter()
        .map(|name| {
            (
                format!("{ID_PREFIX}{ROOT}/{name}"),
                ModuleSourceLocation {
                    filename: PathBuf::from(format!("/original project/{name}")),
                    url: format!("file:///original%20project/{name}"),
                },
            )
        })
        .collect();
        locations
            .get_mut(&format!("{ID_PREFIX}{ROOT}/nested/loader.mjs"))
            .unwrap()
            .url
            .push_str("?instance=2#kept");
        let installed =
            ExecutionModuleResolver::new(&source.module.record.id, resolver, policy.clone())
                .with_source_locations(locations);
        let result = orchestrator(lane, ModuleSyntax::EsModule)
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect("created require and resolve retain the creator's captured identity");
        assert_eq!(
            lines(&result),
            [
                "true true createRequire 1",
                "root nested",
                "/original project/nested/throw.cjs",
                "/original project/nested/throw.cjs",
                "root",
            ]
        );
        let calls = policy.requests.lock().expect("policy log");
        let dependency_calls: Vec<_> = calls
            .iter()
            .filter(|(request, _)| request.specifier == "./dep.cjs")
            .map(|(request, _)| {
                assert_eq!(request.style, ImportStyle::Require);
                request.referrer.as_deref().unwrap()
            })
            .collect();
        assert_eq!(
            dependency_calls,
            [
                format!("{ID_PREFIX}{ROOT}/entry.mjs"),
                format!("{ID_PREFIX}{ROOT}/nested/loader.mjs"),
                format!("{ID_PREFIX}{ROOT}/entry.mjs"),
            ]
        );
        let resolve_calls: Vec<_> = calls
            .iter()
            .filter(|(request, _)| request.specifier == "./throw.cjs")
            .collect();
        assert_eq!(resolve_calls.len(), 2);
        assert!(resolve_calls.iter().all(|(request, _)| {
            request.style == ImportStyle::Require
                && request.referrer.as_deref()
                    == Some(format!("{ID_PREFIX}{ROOT}/nested/loader.mjs").as_str())
        }));
    }
}

#[test]
fn delivered_create_require_validates_every_origin_without_coercion_or_foreign_routes() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let resolver = Arc::new(
            OpaqueResolver::new(vec![
                (
                    "entry.cjs",
                    definition(
                        ModuleSyntax::CommonJs,
                        r#"
                        const { createRequire } = require('node:module');
                        const req = createRequire(__filename);
                        const other = createRequire(__filename);
                        const ordinary = require;
                        const resolve = req.resolve;
                        req.marker = 'first';
                        resolve.marker = 'first resolve';
                        console.log(req !== other, req.resolve !== other.resolve,
                            req.resolve === resolve, other.marker === undefined,
                            other.resolve.marker === undefined, require.marker === undefined,
                            req !== require, require.resolve === require.resolve,
                            ordinary === require);
                        console.log(req('./dep.cjs').answer);
                        const origins = [undefined, null, 3, './entry.cjs',
                            '/original/foreign.cjs', 'file:///original/foreign.cjs',
                            'file:///original/entry.cjs?changed', '\ud800',
                            { toString() { throw new Error('must not coerce'); } }];
                        for (const origin of origins) {
                            try { createRequire(origin); console.log('unexpected origin'); }
                            catch (error) { console.log(error instanceof TypeError); }
                        }
                        console.log(req.resolve('./dep.cjs'));
                        "#,
                    ),
                ),
                (
                    "dep.cjs",
                    definition(ModuleSyntax::CommonJs, "exports.answer = 42;"),
                ),
                (
                    "foreign.cjs",
                    definition(
                        ModuleSyntax::CommonJs,
                        "throw new Error('foreign origin must not execute');",
                    ),
                ),
            ])
            .with_native_builtins(),
        );
        let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
        let policy = Arc::new(RecordingPolicy {
            allow_native_builtins: true,
            ..RecordingPolicy::default()
        });
        let locations = ["entry.cjs", "dep.cjs", "foreign.cjs"]
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
        let result = orchestrator(lane, ModuleSyntax::CommonJs)
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect("invalid createRequire bases are catchable TypeErrors");
        let mut expected = vec!["true true true true true true true true true", "42"];
        expected.extend(["true"; 9]);
        expected.push("/original/dep.cjs");
        assert_eq!(lines(&result), expected);
        let calls = policy.requests.lock().expect("policy log");
        assert_eq!(
            calls
                .iter()
                .map(|(request, _)| request.specifier.as_str())
                .collect::<Vec<_>>(),
            ["node:module", "./dep.cjs", "./dep.cjs"],
            "invalid bases must not resolve or gain another module's routes"
        );
    }
}

#[test]
fn delivered_create_require_and_resolve_reauthorize_after_policy_revocation() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for (operation, first_output) in [
            ("req('./dep.cjs').answer", "42"),
            ("req.resolve('./dep.cjs')", "/original/dep.cjs"),
        ] {
            let entry_source = format!(
                "const {{ createRequire }} = require('module'); \
                 const req = createRequire(__filename); \
                 console.log({operation}); \
                 try {{ console.log({operation}); }} \
                 catch (error) {{ console.log('policy denial escaped'); }}"
            );
            let resolver = Arc::new(
                OpaqueResolver::new(vec![
                    (
                        "entry.cjs",
                        definition(ModuleSyntax::CommonJs, &entry_source),
                    ),
                    (
                        "dep.cjs",
                        definition(ModuleSyntax::CommonJs, "exports.answer = 42;"),
                    ),
                ])
                .with_native_builtins(),
            );
            let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
            let policy = Arc::new(RecordingPolicy {
                allow_native_builtins: true,
                denied: Some(("./dep.cjs".to_string(), 2)),
                ..RecordingPolicy::default()
            });
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
            let mut engine = orchestrator(lane, ModuleSyntax::CommonJs);
            let error = engine
                .execute_resolved_entry_with_resolver(&package(), &source, installed)
                .expect_err("created require cannot retain a revoked route grant");
            assert!(
                error
                    .to_string()
                    .contains("closed-world module resolution refused"),
                "{operation}: {error}"
            );
            assert_eq!(
                engine
                    .last_failed_console_output()
                    .iter()
                    .map(|entry| entry.message.as_str())
                    .collect::<Vec<_>>(),
                [first_output]
            );
            assert_eq!(policy.requests.lock().expect("policy log").len(), 3);
        }
    }
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
fn delivered_missing_routes_are_catchable_without_filesystem_fallback() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let resolver = Arc::new(
            OpaqueResolver::new(vec![
                (
                    "entry.cjs",
                    definition(
                        ModuleSyntax::CommonJs,
                        r#"
try { require('./optional.cjs'); } catch (error) {
    console.log(error.code, error.message.indexOf('./optional.cjs') >= 0);
}
try { require.resolve('./optional.cjs'); } catch (error) {
    console.log(error.code, error.message.indexOf('./optional.cjs') >= 0);
}
console.log(require('./fallback.cjs').answer);
"#,
                    ),
                ),
                (
                    "fallback.cjs",
                    definition(ModuleSyntax::CommonJs, "module.exports = { answer: 42 };"),
                ),
            ])
            .with_missing_route("./optional.cjs"),
        );
        let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
        let installed = ExecutionModuleResolver::new(
            &source.module.record.id,
            resolver.clone(),
            Arc::new(AllowAllPolicy),
        );
        let result = orchestrator(lane, ModuleSyntax::CommonJs)
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect("an admitted absent optional dependency permits the program's fallback");
        assert_eq!(lines(&result), ["MODULE_NOT_FOUND true", "MODULE_NOT_FOUND true", "42"]);
        assert_eq!(
            resolver
                .requests
                .lock()
                .expect("request log")
                .iter()
                .filter(|request| request.specifier == "./optional.cjs")
                .count(),
            2,
            "both loading and resolving must consult the installed resolver"
        );
    }
}

#[test]
fn delivered_policy_refusals_are_not_optional_dependency_fallbacks() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for operation in ["require", "require.resolve"] {
            for denial_code in [
                ResolutionErrorCode::PolicyDenied,
                ResolutionErrorCode::ModuleNotFound,
                ResolutionErrorCode::UnsupportedSpecifier,
                ResolutionErrorCode::InvalidReferrer,
                ResolutionErrorCode::EmptySpecifier,
            ] {
                let code = format!(
                    "try {{ {operation}('./dep.cjs'); }} catch (error) {{ console.log('must not catch policy'); }}"
                );
                let resolver = Arc::new(OpaqueResolver::new(vec![
                    ("entry.cjs", definition(ModuleSyntax::CommonJs, &code)),
                    ("dep.cjs", definition(ModuleSyntax::CommonJs, "module.exports = 42;")),
                ]));
                let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
                let policy = Arc::new(RecordingPolicy {
                    denied: Some(("./dep.cjs".to_string(), 1)),
                    denial_code: Some(denial_code),
                    ..RecordingPolicy::default()
                });
                let installed =
                    ExecutionModuleResolver::new(&source.module.record.id, resolver, policy);
                let mut engine = orchestrator(lane, ModuleSyntax::CommonJs);
                let error = engine
                    .execute_resolved_entry_with_resolver(&package(), &source, installed)
                    .expect_err("guest catch blocks cannot suppress a load-policy refusal");
                assert!(error.to_string().contains("closed-world module resolution refused"), "{error}");
                assert!(error.to_string().contains("FE-MODRES-0005"), "{error}");
                assert!(engine.last_failed_console_output().is_empty());
            }
        }
    }
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
fn delivered_crypto_and_zlib_are_first_class_modules_without_entropy_authority() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let resolver = Arc::new(
            OpaqueResolver::new(vec![
                (
                    "entry.cjs",
                    definition(
                        ModuleSyntax::CommonJs,
                        r#"
const crypto = require('crypto');
const zlib = require('zlib');
const child = require('./child.cjs');
console.log(crypto === child.crypto, zlib === child.zlib);
const createHash = crypto.createHash;
const gzip = zlib.gzipSync;
const gunzip = zlib.gunzipSync;
console.log(createHash('sha256').update('abc').digest('hex'));
console.log(gunzip(gzip('native codecs')).toString());
console.log(typeof crypto.randomBytes, typeof crypto.generateKeyPairSync);
try { crypto.randomInt(0); } catch (error) { console.log(error.code); }
crypto.createHash = function() { return 'replacement'; };
zlib.gzipSync = function() { return 'changed'; };
console.log(crypto.createHash(), zlib.gzipSync());
console.log(createHash('sha256').update('abc').digest('hex'));
console.log(gunzip(gzip('retained callable')).toString());
console.log(require('node:crypto') === crypto, require('node:zlib') === zlib);
"#,
                    )
                    .with_dependency(ModuleDependency::new("./child.cjs", ImportStyle::Require)),
                ),
                (
                    "child.cjs",
                    definition(
                        ModuleSyntax::CommonJs,
                        "exports.crypto = require('node:crypto'); exports.zlib = require('node:zlib');",
                    ),
                ),
            ])
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
            .expect("deterministic crypto and codecs need no entropy grant");
        assert_eq!(
            lines(&result),
            [
                "true true",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "native codecs",
                "function function",
                "ERR_OUT_OF_RANGE",
                "replacement changed",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "retained callable",
                "true true",
            ]
        );
        let requests = policy.requests.lock().expect("policy log");
        assert!(
            requests
                .iter()
                .any(|(request, _)| request.specifier == "crypto")
        );
        assert!(requests.iter().any(|(request, _)| request.specifier == "zlib"));
    }
}

#[test]
fn delivered_crypto_and_zlib_esm_names_and_async_codecs_use_native_providers() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let resolver = Arc::new(
            OpaqueResolver::new(vec![(
                "entry.mjs",
                definition(
                    ModuleSyntax::EsModule,
                    r#"
import crypto, { createHash, constants as cryptoConstants } from 'node:crypto';
import zlib, { gzip, gunzipSync, constants as zlibConstants } from 'node:zlib';
console.log(createHash === crypto.createHash, gzip === zlib.gzip);
console.log(cryptoConstants === crypto.constants, zlibConstants === zlib.constants);
console.log(createHash('sha256').update('abc').digest('hex'));
gzip('async native codec', function(error, compressed) {
    console.log(error === null, gunzipSync(compressed).toString());
});
console.log('scheduled');
"#,
                ),
            )])
            .with_native_builtins(),
        );
        let source = entry(&resolver, "entry.mjs", ModuleSyntax::EsModule);
        let policy = Arc::new(RecordingPolicy {
            allow_native_builtins: true,
            ..RecordingPolicy::default()
        });
        let installed = ExecutionModuleResolver::new(&source.module.record.id, resolver, policy);
        let result = orchestrator(lane, ModuleSyntax::EsModule)
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect("ESM imports expose the same native callable values");
        assert_eq!(
            lines(&result),
            [
                "true true",
                "true true",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "scheduled",
                "true async native codec",
            ]
        );
    }
}

#[test]
fn delivered_crypto_callable_values_cannot_acquire_entropy_authority() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for invocation in [
            "const f = crypto.randomBytes; f(16);",
            "const f = crypto.randomUUID; f();",
            "const f = crypto.randomInt; f(10);",
            "const f = crypto.randomFillSync; f(Buffer.alloc(16));",
            "const f = crypto.generateKeyPairSync; f('ed25519');",
        ] {
            let resolver = Arc::new(
                OpaqueResolver::new(vec![(
                    "entry.cjs",
                    definition(
                        ModuleSyntax::CommonJs,
                        &format!(
                            "const crypto = require('crypto'); console.log('loaded'); {invocation} console.log('escaped');"
                        ),
                    ),
                )])
                .with_native_builtins(),
            );
            let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
            let policy = Arc::new(RecordingPolicy {
                allow_native_builtins: true,
                ..RecordingPolicy::default()
            });
            let installed = ExecutionModuleResolver::new(&source.module.record.id, resolver, policy);
            let mut engine = orchestrator(lane, ModuleSyntax::CommonJs);
            let error = engine
                .execute_resolved_entry_with_resolver(&package(), &source, installed)
                .expect_err("an extracted native function cannot grant RandomRead");
            assert!(
                error.to_string().contains("capability denied"),
                "{invocation}: {error}"
            );
            assert_eq!(
                engine
                    .last_failed_console_output()
                    .iter()
                    .map(|entry| entry.message.as_str())
                    .collect::<Vec<_>>(),
                ["loaded"],
                "import succeeds; the effectful invocation is denied"
            );
        }
    }
}

#[test]
fn delivered_source_factories_preserve_cross_module_closures_aliases_and_submodules() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let resolver = Arc::new(
            OpaqueResolver::new(vec![
                (
                    "entry.cjs",
                    definition(
                        ModuleSyntax::CommonJs,
                        r#"
const util = require('util');
const types = require('node:util/types');
const strict = require('assert/strict');
const assert = require('node:assert');
const decoder = require('string_decoder');
const child = require('./child.cjs');
console.log(util === child.util, types === util.types,
    strict === assert.strict, decoder.StringDecoder === child.Decoder);
console.log(child.format('answer', 42), types.isMap(new Map()));
assert.deepStrictEqual({a: [1, 2]}, {a: [1, 2]});
try { strict.equal(1, '1'); } catch (error) { console.log(error.code, error.operator); }
const d = new child.Decoder('utf8');
console.log(d.write(Buffer.from([226, 130])) === '', d.end(Buffer.from([172])));
util.marker = 17;
console.log(child.util.marker, new util.MIMEType('Text/Plain; charset=utf-8').essence);
console.log(require('node:util') === util, require('node:assert/strict') === strict);
util.types = {};
assert.strict = {};
console.log(require('util/types') === types, require('assert/strict') === strict);
"#,
                    )
                    .with_dependency(ModuleDependency::new("./child.cjs", ImportStyle::Require)),
                ),
                (
                    "child.cjs",
                    definition(
                        ModuleSyntax::CommonJs,
                        r#"
const util = require('node:util');
const Decoder = require('node:string_decoder').StringDecoder;
module.exports = {
    util: util, Decoder: Decoder,
    format: function(name, value) { return util.format('%s=%d', name, value); }
};
"#,
                    ),
                ),
            ])
            .with_native_builtins(),
        );
        let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
        let policy = Arc::new(RecordingPolicy {
            allow_native_builtins: true,
            ..RecordingPolicy::default()
        });
        let installed = ExecutionModuleResolver::new(&source.module.record.id, resolver, policy);
        let result = orchestrator(lane, ModuleSyntax::CommonJs)
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect("captured modules execute retained canonical builtin factories");
        assert_eq!(
            lines(&result),
            [
                "true true true true",
                "answer=42 true",
                "ERR_ASSERTION strictEqual",
                "true €",
                "17 text/plain",
                "true true",
                "true true",
            ]
        );
    }
}

#[test]
fn delivered_builtin_submodules_keep_node_initialization_and_cache_identity() {
    let resolver = Arc::new(
        OpaqueResolver::new(vec![(
            "entry.cjs",
            definition(
                ModuleSyntax::CommonJs,
                r#"
const util = require('util');
const originalTypes = util.types;
util.types = {};
console.log(require('node:util/types') === originalTypes);
const assert = require('assert');
const replacement = function () { return 17; };
assert.strict = replacement;
console.log(require('assert/strict') === replacement);
assert.strict = undefined;
console.log(require('node:assert/strict') === replacement);
"#,
            ),
        )])
        .with_native_builtins(),
    );
    let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
    let installed =
        ExecutionModuleResolver::new(&source.module.record.id, resolver, Arc::new(AllowAllPolicy));
    let result = orchestrator(LaneChoice::QuickJs, ModuleSyntax::CommonJs)
        .execute_resolved_entry_with_resolver(&package(), &source, installed)
        .expect("native submodule identity is independent of later parent property writes");
    assert_eq!(lines(&result), ["true", "true", "true"]);
}

#[test]
fn delivered_source_factories_share_esm_namespaces_with_commonjs_values() {
    let resolver = Arc::new(OpaqueResolver::new(vec![
        ("entry.mjs", definition(ModuleSyntax::EsModule, r#"
import util, {format, MIMEType} from 'node:util';
import types, {isSet} from 'util/types';
import assert, {strictEqual} from 'assert';
import strict from 'node:assert/strict';
import {StringDecoder} from 'node:string_decoder';
import * as utilNamespace from 'util';
import * as typesNamespace from 'util/types';
import * as assertNamespace from 'assert';
import * as strictNamespace from 'assert/strict';
import * as decoderNamespace from 'string_decoder';
import child from './child.cjs';
strictEqual(child.util, util);
for (const namespace of [utilNamespace, typesNamespace, assertNamespace, strictNamespace, decoderNamespace]) {
    const original = namespace.default;
    strictEqual(Reflect.set(namespace, 'default', null), false);
    strictEqual(Reflect.defineProperty(namespace, 'default', {value: null}), false);
    strictEqual(namespace.default, original);
    strictEqual(Object.getOwnPropertyDescriptor(namespace, 'default').writable, true);
}
console.log(format('%s:%d', 'esm', 7), isSet(new Set()), types === util.types);
console.log(strict === assert.strict, StringDecoder === child.Decoder,
    new MIMEType('Application/JSON').essence);
const decoder = new StringDecoder('utf8');
decoder.write(Buffer.from([226]));
console.log(decoder.lastNeed, decoder.end(Buffer.from([130, 172])));
import('util').then(function(ns) { console.log(ns.default === util, ns.format === format); });
"#).with_dependency(ModuleDependency::new("./child.cjs", ImportStyle::Import))),
        ("child.cjs", definition(ModuleSyntax::CommonJs,
            "module.exports = {util: require('util'), Decoder: require('string_decoder').StringDecoder};")),
    ]).with_native_builtins());
    let source = entry(&resolver, "entry.mjs", ModuleSyntax::EsModule);
    let installed =
        ExecutionModuleResolver::new(&source.module.record.id, resolver, Arc::new(AllowAllPolicy));
    let result = orchestrator(LaneChoice::QuickJs, ModuleSyntax::EsModule)
        .execute_resolved_entry_with_resolver(&package(), &source, installed)
        .expect("native source providers supply real ESM named and default exports");
    assert_eq!(
        lines(&result),
        [
            "esm:7 true true",
            "true true application/json",
            "2 €",
            "true true"
        ]
    );
}

#[test]
fn delivered_source_factory_esm_does_not_admit_guest_or_snapshot_getters() {
    for mutation in [
        "Object.defineProperty(util.inspect.colors, 'gray', { get: function () { console.log('guest getter ran'); return [1, 2]; } });",
        "const wrapped = util.deprecate(function () { console.log('wrapped getter ran'); return [1, 2]; }); Object.defineProperty(wrapped, 'name', {value: 'get'}); Object.defineProperty(util.inspect.colors, 'gray', { get: wrapped });",
        "const get = Object.getOwnPropertyDescriptor(util.inspect.colors, 'grey').get; Object.defineProperty(util, 'format', { get: get });",
        "const get = Object.getOwnPropertyDescriptor(util.inspect.colors, 'grey').get; const proto = {}; Object.defineProperty(proto, 'format', { get: get }); delete util.format; Object.setPrototypeOf(util, proto);",
    ] {
        let resolver = Arc::new(
            OpaqueResolver::new(vec![
                (
                    "entry.mjs",
                    definition(
                        ModuleSyntax::EsModule,
                        "import './mutator.cjs'; import {format} from 'node:util'; console.log(format('%s', 'must not run'));",
                    )
                    .with_dependency(ModuleDependency::new("./mutator.cjs", ImportStyle::Import)),
                ),
                (
                    "mutator.cjs",
                    definition(
                        ModuleSyntax::CommonJs,
                        &format!("const util = require('util'); {mutation}"),
                    ),
                ),
            ])
            .with_native_builtins(),
        );
        let source = entry(&resolver, "entry.mjs", ModuleSyntax::EsModule);
        let installed = ExecutionModuleResolver::new(
            &source.module.record.id,
            resolver,
            Arc::new(AllowAllPolicy),
        );
        let mut engine = orchestrator(LaneChoice::QuickJs, ModuleSyntax::EsModule);
        let error = engine
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect_err("only deferred, authenticated accessor code is admitted");
        assert!(
            error.to_string().contains("bounded-import contract"),
            "{mutation}: {error}"
        );
        assert!(error.to_string().contains("'node:util'"), "{mutation}: {error}");
        assert!(engine.last_failed_console_output().is_empty(), "{mutation}");
    }
}

#[test]
fn delivered_strict_alias_bounds_first_getter_but_keeps_cached_identity() {
    for cached in [false, true] {
        let initialize_alias = if cached {
            "require('assert/strict');"
        } else {
            ""
        };
        let resolver = Arc::new(
            OpaqueResolver::new(vec![
                (
                    "entry.mjs",
                    definition(
                        ModuleSyntax::EsModule,
                        "import './mutator.cjs'; import strict from 'node:assert/strict'; console.log(strict.equal(7, 7) || typeof strict);",
                    )
                    .with_dependency(ModuleDependency::new("./mutator.cjs", ImportStyle::Import)),
                ),
                (
                    "mutator.cjs",
                    definition(
                        ModuleSyntax::CommonJs,
                        // Isolate cached alias selection from the mutable parent
                        // that the strict export normally exposes through `.ok`.
                        &format!(
                            "const assert = require('assert'); const original = assert.strict; \
                             original.ok = original; \
                             {initialize_alias} \
                             Object.defineProperty(assert, 'strict', {{ get: function () {{ \
                                 console.log('strict getter ran'); return original; \
                             }} }});"
                        ),
                    ),
                ),
            ])
            .with_native_builtins(),
        );
        let source = entry(&resolver, "entry.mjs", ModuleSyntax::EsModule);
        let installed = ExecutionModuleResolver::new(
            &source.module.record.id,
            resolver,
            Arc::new(AllowAllPolicy),
        );
        let mut engine = orchestrator(LaneChoice::QuickJs, ModuleSyntax::EsModule);
        let outcome = engine.execute_resolved_entry_with_resolver(&package(), &source, installed);
        if cached {
            let result = outcome.expect("a cached alias never rereads the mutable parent property");
            assert_eq!(lines(&result), ["function"]);
        } else {
            let error = outcome.expect_err("bound admission precedes the first strict getter");
            assert!(
                error.to_string().contains("bounded-import contract"),
                "{error}"
            );
            assert!(error.to_string().contains("'node:assert/strict'"), "{error}");
            assert!(engine.last_failed_console_output().is_empty());
        }
    }
}

#[test]
fn delivered_builtin_submodule_cannot_rebind_its_initializing_factory() {
    for (specifier, factory) in [
        ("util/types", "\0franken-engine/native-util"),
        ("assert/strict", "\0franken-engine/native-assert"),
        ("stream/promises", "\0franken-engine/native-stream"),
    ] {
        let mut resolver = OpaqueResolver::new(vec![(
            "entry.cjs",
            definition(
                ModuleSyntax::CommonJs,
                &format!("require('{specifier}'); console.log('must not run');"),
            ),
        )])
        .with_native_builtins();
        resolver.corruption = Corruption::BuiltinAliasesFactory(factory);
        let resolver = Arc::new(resolver);
        let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
        let installed = ExecutionModuleResolver::new(
            &source.module.record.id,
            resolver,
            Arc::new(AllowAllPolicy),
        );
        let mut engine = orchestrator(LaneChoice::QuickJs, ModuleSyntax::CommonJs);
        let error = engine
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect_err("a new private factory record cannot be rebound by the outer descriptor");
        assert!(
            error
                .to_string()
                .contains("changed during native provider initialization"),
            "{specifier}: {error}"
        );
        assert!(engine.last_failed_console_output().is_empty());
    }
}

#[test]
fn delivered_source_factory_alias_cannot_bypass_policy_after_initialization() {
    let resolver = Arc::new(OpaqueResolver::new(vec![
        ("entry.cjs", definition(ModuleSyntax::CommonJs,
            "console.log(require('util').format('%s', 'allowed')); try { require('node:util'); } catch (_) { console.log('caught'); }")),
    ]).with_native_builtins());
    let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
    let policy = Arc::new(RecordingPolicy {
        denied: Some(("node:util".to_string(), 1)),
        allow_native_builtins: true,
        ..RecordingPolicy::default()
    });
    let installed = ExecutionModuleResolver::new(&source.module.record.id, resolver, policy);
    let mut engine = orchestrator(LaneChoice::QuickJs, ModuleSyntax::CommonJs);
    let error = engine
        .execute_resolved_entry_with_resolver(&package(), &source, installed)
        .expect_err("native factory cache is not a grant to an alias route");
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
        ["allowed"]
    );
}

#[test]
fn delivered_path_modules_reuse_complete_namespaces_across_package_boundaries() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let resolver = Arc::new(
            OpaqueResolver::new(vec![
                (
                    "entry.cjs",
                    definition(
                        ModuleSyntax::CommonJs,
                        r#"
const windows = require('node:path/win32');
const path = require('path');
const child = require('./child.cjs');
console.log(windows.posix === path, path.win32 === windows,
    path === require('path/posix'), path === child.path);
console.log(child.make('file.txt'), windows.join('C:\\root', '..', 'out'));
console.log(windows.resolve('D:\\ignored', 'C:\\base', '..', 'out'));
console.log(windows.format(windows.parse('C:\\base\\file.txt')));
const oldJoin = path.join;
path.join = function() { return 'patched'; };
console.log(child.make('ignored'), require('node:path').join('ignored'));
console.log(child.join('one', 'two'));
path.join = oldJoin;
console.log(child.make('restored'), windows.posix.win32 === windows);
"#,
                    )
                    .with_dependency(ModuleDependency::new("./child.cjs", ImportStyle::Require)),
                ),
                (
                    "child.cjs",
                    definition(
                        ModuleSyntax::CommonJs,
                        r#"
const path = require('node:path/posix');
module.exports = {
    path: path,
    join: path.join,
    make: function(value) { return path.join('root', value); }
};
"#,
                    ),
                ),
            ])
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
            .expect("captured packages execute the engine-owned path factory");
        assert_eq!(
            lines(&result),
            [
                "true true true true",
                "root/file.txt C:\\out",
                "C:\\out",
                "C:\\base\\file.txt",
                "patched patched",
                "one/two",
                "root/restored true",
            ]
        );
        assert!(
            policy
                .requests
                .lock()
                .expect("policy log")
                .iter()
                .all(|(request, _)| !request.specifier.starts_with('\0')),
            "engine implementation must not request an uncaptured source route"
        );
    }
}

#[test]
fn delivered_native_esm_imports_and_reexports_execute_shared_providers() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let resolver = Arc::new(
            OpaqueResolver::new(vec![
                ("entry.mjs", definition(ModuleSyntax::EsModule, r#"
import buffer, { Buffer as NativeBuffer } from 'buffer';
import * as bufferNamespace from 'node:buffer';
import events, { EventEmitter, once } from 'node:events';
import os, { EOL } from 'os';
import querystring, { stringify } from 'node:querystring';
import url, { URL, URLSearchParams } from 'url';
import timers, { setTimeout, clearTimeout } from 'node:timers';
import perf, { performance } from 'perf_hooks';
import { join, encode } from './barrel.mjs';
import commonjs from './consumer.cjs';
console.log(NativeBuffer.from('bridge').length, buffer.Buffer === NativeBuffer,
    bufferNamespace.default === buffer, commonjs.buffer === buffer);
console.log(events === EventEmitter, commonjs.events === events, typeof once);
console.log(os.EOL === EOL, typeof EOL, querystring === commonjs.querystring);
console.log(stringify({ a: 'x y' }), encode({ a: 1 }), join('root', 'file'));
console.log(url.URL === URL, typeof URLSearchParams, new URL('https://example.com/a').pathname);
console.log(timers.setTimeout === setTimeout, timers.clearTimeout === clearTimeout,
    perf.performance === performance, typeof performance.now);
import('buffer').then(function(again) {
    console.log(again === bufferNamespace, again.Buffer === NativeBuffer);
});
"#)),
                ("barrel.mjs", definition(ModuleSyntax::EsModule,
                    "export { join } from 'node:path'; export { stringify as encode } from 'querystring';")),
                ("consumer.cjs", definition(ModuleSyntax::CommonJs,
                    "module.exports = { buffer: require('node:buffer'), events: require('events'), querystring: require('querystring') };")),
            ]).with_native_builtins(),
        );
        let source = entry(&resolver, "entry.mjs", ModuleSyntax::EsModule);
        let policy = Arc::new(RecordingPolicy {
            allow_native_builtins: true,
            ..RecordingPolicy::default()
        });
        let installed =
            ExecutionModuleResolver::new(&source.module.record.id, resolver, policy.clone());
        let result = orchestrator(lane, ModuleSyntax::EsModule)
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect("bounded static imports and reexports call the actual native providers");
        assert_eq!(
            lines(&result),
            [
                "6 true true true",
                "true true function",
                "true string true",
                "a=x%20y a=1 root/file",
                "true function /a",
                "true true true function",
                "true true",
            ]
        );
        assert!(
            policy
                .requests
                .lock()
                .expect("policy log")
                .iter()
                .all(|(request, _)| !request.specifier.starts_with('\0'))
        );
    }
}

#[test]
fn delivered_native_esm_snapshots_do_not_export_guest_added_names() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let resolver = Arc::new(
            OpaqueResolver::new(vec![(
                "entry.cjs",
                definition(
                    ModuleSyntax::CommonJs,
                    r#"
const q = require('querystring');
q.added = 42;
const original = q.stringify;
import('node:querystring').then(function(first) {
    console.log(first.default === q, 'added' in first, first.stringify === original);
    q.stringify = function() { return 'changed'; };
    return import('querystring').then(function(second) {
        console.log(second === first, second.stringify({ a: 1 }), second.default.stringify());
    });
});
"#,
                ),
            )])
            .with_native_builtins(),
        );
        let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
        let installed = ExecutionModuleResolver::new(
            &source.module.record.id,
            resolver,
            Arc::new(AllowAllPolicy),
        );
        let result = orchestrator(lane, ModuleSyntax::CommonJs)
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect("named exports snapshot the fixed provider surface and default stays live");
        assert_eq!(lines(&result), ["true false true", "true a=1 changed"]);
    }
}

#[test]
fn delivered_path_esm_namespaces_share_the_native_commonjs_objects() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let resolver = Arc::new(
            OpaqueResolver::new(vec![
                (
                    "entry.mjs",
                    definition(
                        ModuleSyntax::EsModule,
                        r#"
import path, { join, win32 } from 'node:path';
import * as namespace from 'path';
import windows, { posix, join as windowsJoin } from 'path/win32';
import * as canonical from 'path/posix';
import * as prefixed from 'node:path/posix';
import consumer from './consumer.cjs';
console.log(path === consumer.path, windows === consumer.windows,
    path.win32 === windows, windows.posix === path,
    canonical === prefixed, canonical !== namespace);
console.log(join('root', 'file.txt'), windowsJoin('C:\\root', '..', 'out'));
console.log(win32 === windows, posix === path,
    Object.getPrototypeOf(canonical) === null, Object.isExtensible(canonical));
path.join = function() { return 'shared mutation'; };
console.log(join('one', 'two'), path.join('ignored'), consumer.path.join('ignored'));
import('path').then(function(again) {
    console.log(again === namespace, again.default === path,
        again.join === join, again !== canonical);
});
"#,
                    )
                    .with_dependency(ModuleDependency::new("./consumer.cjs", ImportStyle::Import)),
                ),
                (
                    "consumer.cjs",
                    definition(
                        ModuleSyntax::CommonJs,
                        "module.exports = { path: require('path'), windows: require('node:path/win32') };",
                    ),
                ),
            ])
            .with_native_builtins(),
        );
        let source = entry(&resolver, "entry.mjs", ModuleSyntax::EsModule);
        let policy = Arc::new(RecordingPolicy {
            allow_native_builtins: true,
            ..RecordingPolicy::default()
        });
        let installed =
            ExecutionModuleResolver::new(&source.module.record.id, resolver, policy.clone());
        let result = orchestrator(lane, ModuleSyntax::EsModule)
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect("native Path namespaces are shared across static, dynamic and CommonJS loads");
        assert_eq!(
            lines(&result),
            [
                "true true true true true true",
                "root/file.txt C:\\out",
                "true true true false",
                "one/two shared mutation shared mutation",
                "true true true true",
            ]
        );
        assert!(
            policy
                .requests
                .lock()
                .expect("policy log")
                .iter()
                .all(|(request, _)| !request.specifier.starts_with('\0')),
            "namespace materialization must not request a new captured source route"
        );
    }
}

#[test]
fn delivered_path_esm_snapshots_fixed_names_after_prior_commonjs_mutations() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let resolver = Arc::new(
            OpaqueResolver::new(vec![(
                "entry.cjs",
                definition(
                    ModuleSyntax::CommonJs,
                    r#"
const path = require('path');
const windows = require('path/win32');
let getters = 0;
path.join = function() { return 'before import'; };
Object.defineProperty(path, 'basename', {
    get: function() { getters++; return 'snapshot'; },
    configurable: true, enumerable: true
});
delete path.dirname;
path.added = 42;
import('node:path').then(function(first) {
    console.log(first.default === path, first.join === path.join,
        first.basename, first.dirname === undefined, 'added' in first, getters);
    path.join = function() { return 'after import'; };
    console.log(first.join('x'), first.default.join('x'));
    return import('path/posix').then(function(second) {
        console.log(second === first, second.default === first.default,
            second.join('x'), getters);
        return import('node:path/posix').then(function(alias) {
            console.log(alias === second, getters);
            return import('path').then(function(cached) {
                console.log(cached === first, cached.join('x'), getters);
                return import('node:path/win32').then(function(win) {
                    console.log(win.default === windows, win.posix === path,
                        win.win32 === windows, win.resolve('C:\\base', '..', 'out'));
                });
            });
        });
    });
});
"#,
                ),
            )])
            .with_native_builtins(),
        );
        let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
        let installed = ExecutionModuleResolver::new(
            &source.module.record.id,
            resolver,
            Arc::new(AllowAllPolicy),
        );
        let result = orchestrator(lane, ModuleSyntax::CommonJs)
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect("each native Path facade snapshots the supported properties once");
        assert_eq!(
            lines(&result),
            [
                "true true snapshot true false 1",
                "before import after import",
                "false true after import 2",
                "true 2",
                "true before import 2",
                "true true true C:\\out",
            ]
        );
    }
}

#[test]
fn delivered_path_esm_failed_snapshot_preserves_the_thrown_object() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let resolver = Arc::new(
            OpaqueResolver::new(vec![(
                "entry.cjs",
                definition(
                    ModuleSyntax::CommonJs,
                    r#"
const path = require('path');
const originalBasename = path.basename;
const marker = { message: 'namespace getter' };
let getters = 0;
Object.defineProperty(path, 'basename', {
    get: function() { getters++; throw marker; },
    configurable: true, enumerable: true
});
import('node:path').then(function() {
    console.log('unexpected success');
}, function(first) {
    console.log('rejected', first === marker, getters, typeof require('path').join);
    Object.defineProperty(path, 'basename', {
        value: originalBasename,
        writable: true, configurable: true, enumerable: true
    });
    return import('path').then(function() {
        console.log('unexpected retry');
    }, function(second) {
        console.log('cached rejection', second === marker, second === first,
            getters, require('node:path') === path);
        return import('path/posix').then(function(posix) {
            console.log(posix.default === path, posix.basename('/root/child'), getters);
        });
    });
});
"#,
                ),
            )])
            .with_native_builtins(),
        );
        let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
        let installed = ExecutionModuleResolver::new(
            &source.module.record.id,
            resolver,
            Arc::new(AllowAllPolicy),
        );
        let result = orchestrator(lane, ModuleSyntax::CommonJs)
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect("the failed native facade rethrows the original value without poisoning CJS or Posix");
        assert_eq!(
            lines(&result),
            [
                "rejected true 1 function",
                "cached rejection true true 1 true",
                "true child 1",
            ]
        );
    }
}

#[test]
fn delivered_path_esm_reentrant_imports_wait_for_the_initial_snapshot() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let resolver = Arc::new(
            OpaqueResolver::new(vec![(
                "entry.cjs",
                definition(
                    ModuleSyntax::CommonJs,
                    r#"
const path = require('path');
const originalBasename = path.basename;
const marker = { message: 'recursive namespace getter' };
let getters = 0;
let nested;
Object.defineProperty(path, 'basename', {
    get: function() {
        getters++;
        nested = import('node:path');
        return originalBasename;
    },
    configurable: true, enumerable: true
});
import('path').then(function(first) {
    return nested.then(function(second) {
        console.log(first === second, second.default === path,
            second.basename === originalBasename, getters);
        Object.defineProperty(path, 'basename', {
            get: function() {
                getters++;
                nested = import('node:path/posix');
                throw marker;
            },
            configurable: true, enumerable: true
        });
        return import('path/posix').then(function() {
            console.log('unexpected outer success');
        }, function(outerError) {
            return nested.then(function() {
                console.log('unexpected inner success');
            }, function(innerError) {
                console.log(outerError === marker, innerError === marker,
                    innerError === outerError, getters);
            });
        });
    });
});
"#,
                ),
            )])
            .with_native_builtins(),
        );
        let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
        let installed = ExecutionModuleResolver::new(
            &source.module.record.id,
            resolver,
            Arc::new(AllowAllPolicy),
        );
        let result = orchestrator(lane, ModuleSyntax::CommonJs)
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect("recursive native imports settle only after the original facade initializes");
        assert_eq!(lines(&result), ["true true true 1", "true true true 2"]);
    }
}

#[test]
fn delivered_path_esm_cache_cannot_skip_authorization_or_provider_binding() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let source_text = "import('path').then(function(p) { console.log(p.default.sep); return import('path'); });";
        let resolver = Arc::new(
            OpaqueResolver::new(vec![(
                "entry.cjs",
                definition(ModuleSyntax::CommonJs, source_text),
            )])
            .with_native_builtins(),
        );
        let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
        let policy = Arc::new(RecordingPolicy {
            denied: Some(("path".to_string(), 2)),
            allow_native_builtins: true,
            ..RecordingPolicy::default()
        });
        let installed =
            ExecutionModuleResolver::new(&source.module.record.id, resolver, policy.clone());
        let mut engine = orchestrator(lane, ModuleSyntax::CommonJs);
        let error = engine
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect_err("a cached native ESM namespace is not a cached policy grant");
        assert!(
            error
                .to_string()
                .contains("closed-world module resolution refused"),
            "{error}"
        );
        assert_eq!(
            policy
                .requests
                .lock()
                .expect("policy log")
                .iter()
                .filter(|(request, _)| request.specifier == "path")
                .count(),
            2
        );
        for corruption in [
            Corruption::ForgeBuiltin,
            Corruption::MalformedBuiltinMarker,
            Corruption::ChangeBuiltinProvider,
            Corruption::ChangePathProvider,
            Corruption::BuiltinAliasesEntry,
        ] {
            let mut resolver = OpaqueResolver::new(vec![(
                "entry.cjs",
                definition(ModuleSyntax::CommonJs, source_text),
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
            assert!(
                orchestrator(lane, ModuleSyntax::CommonJs)
                    .execute_resolved_entry_with_resolver(&package(), &source, installed)
                    .is_err(),
                "forged or substituted providers must not reach the native namespace cache"
            );
        }
    }
}

#[test]
fn delivered_path_cache_still_authorizes_each_request() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let resolver = Arc::new(
            OpaqueResolver::new(vec![(
                "entry.cjs",
                definition(
                    ModuleSyntax::CommonJs,
                    "const p=require('path'); console.log(p.join('a','b')); require('path');",
                ),
            )])
            .with_native_builtins(),
        );
        let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
        let policy = Arc::new(RecordingPolicy {
            denied: Some(("path".to_string(), 2)),
            allow_native_builtins: true,
            ..RecordingPolicy::default()
        });
        let installed =
            ExecutionModuleResolver::new(&source.module.record.id, resolver, policy.clone());
        let mut engine = orchestrator(lane, ModuleSyntax::CommonJs);
        let error = engine
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect_err("a retained path namespace is not a cached policy grant");
        assert!(
            error
                .to_string()
                .contains("closed-world module resolution refused"),
            "{error}"
        );
        assert_eq!(
            policy
                .requests
                .lock()
                .expect("policy log")
                .iter()
                .filter(|(request, _)| request.specifier == "path")
                .count(),
            2
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
    for (builtin, corruption) in [
        "crypto",
        "zlib",
        "querystring",
        "path",
        "util",
        "util/types",
        "assert",
        "assert/strict",
        "string_decoder",
        "timers/promises",
        "stream",
        "stream/promises",
    ]
    .into_iter()
    .flat_map(|builtin| {
        [
            Corruption::ForgeBuiltin,
            Corruption::MalformedBuiltinMarker,
            Corruption::ChangeBuiltinProvider,
            Corruption::BuiltinAliasesEntry,
        ]
        .into_iter()
        .map(move |corruption| (builtin, corruption))
    }) {
        let mut resolver = OpaqueResolver::new(vec![(
            "entry.cjs",
            definition(
                ModuleSyntax::CommonJs,
                &format!("require('{builtin}'); require('{builtin}');"),
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
            .expect_err(
                "native descriptor validation and identity pinning precede provider dispatch",
            );
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

#[test]
fn delivered_timer_promises_share_parent_aliases_and_retained_closures() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for first in ["timers", "timers/promises"] {
            let source_text = r#"
const load = require;
load('__FIRST__');
const promises = load('node:timers/promises');
const timers = load('node:timers');
const util = load('util');
const child = load('./timer-child.cjs');
console.log(promises === load('timers/promises'), timers.promises === promises,
    child.promises === promises, child.timers === timers,
    timers.setTimeout === setTimeout, timers.setImmediate === setImmediate);
const parentDescriptor = Object.getOwnPropertyDescriptor(timers, 'promises');
console.log(parentDescriptor.get.name, parentDescriptor.get.length,
    parentDescriptor.enumerable, parentDescriptor.configurable,
    parentDescriptor.set === undefined, parentDescriptor.get.call(null) === promises,
    Object.keys(parentDescriptor.get).length === 0);
const descriptor = Object.getOwnPropertyDescriptor(timers.setTimeout, util.promisify.custom);
console.log(descriptor.get.name, descriptor.get.length, descriptor.enumerable,
    descriptor.configurable, descriptor.set === undefined,
    descriptor.get() === promises.setTimeout);
console.log(util.promisify(timers.setTimeout) === promises.setTimeout,
    util.promisify(timers.setImmediate) === promises.setImmediate,
    timers.setInterval[util.promisify.custom] === undefined);
promises.setTimeout = function changedTimeout() { return 'shared'; };
console.log(child.promises.setTimeout(), timers.setTimeout[util.promisify.custom] === promises.setTimeout,
    timers.promises.setTimeout === promises.setTimeout);
"#
            .replace("__FIRST__", first);
            let resolver = Arc::new(
                OpaqueResolver::new(vec![
                    (
                        "entry.cjs",
                        definition(ModuleSyntax::CommonJs, &source_text).with_dependency(
                            ModuleDependency::new("./timer-child.cjs", ImportStyle::Require),
                        ),
                    ),
                    (
                        "timer-child.cjs",
                        definition(
                            ModuleSyntax::CommonJs,
                            "module.exports = { promises: require('timers/promises'), timers: require('timers') };",
                        ),
                    ),
                ])
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
                .unwrap_or_else(|error| panic!("first={first}, lane={lane:?}: {error}"));
            assert_eq!(
                lines(&result),
                [
                    "true true true true true true",
                    "get 0 true true true true true",
                    "get 0 true false true true",
                    "true true true",
                    "shared true true",
                ]
            );
            assert!(
                policy
                    .requests
                    .lock()
                    .expect("policy log")
                    .iter()
                    .all(|(request, _)| !request.specifier.starts_with('\0')),
                "the private timer factory is not a new captured source route"
            );
        }
    }
}

#[test]
fn delivered_timer_esm_imports_preserve_promisify_getter_identity() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let resolver = Arc::new(
            OpaqueResolver::new(vec![(
                "entry.mjs",
                definition(
                    ModuleSyntax::EsModule,
                    r#"
import timers, { setTimeout, setImmediate } from 'node:timers';
import promises, { setTimeout as delay, setImmediate as immediate } from 'timers/promises';
import util, { promisify } from 'node:util';
console.log(timers.setTimeout === setTimeout, timers.setImmediate === setImmediate,
    timers.promises === promises, util.promisify === promisify);
for (const pair of [[setTimeout, delay], [setImmediate, immediate]]) {
    const descriptor = Object.getOwnPropertyDescriptor(pair[0], promisify.custom);
    console.log(descriptor.get.name, descriptor.get.length, descriptor.enumerable,
        descriptor.configurable, descriptor.set === undefined,
        descriptor.get.call(null) === pair[1], promisify(pair[0]) === pair[1]);
}
"#,
                ),
            )])
            .with_native_builtins(),
        );
        let source = entry(&resolver, "entry.mjs", ModuleSyntax::EsModule);
        let installed = ExecutionModuleResolver::new(
            &source.module.record.id,
            resolver,
            Arc::new(RecordingPolicy {
                allow_native_builtins: true,
                ..RecordingPolicy::default()
            }),
        );
        let result = orchestrator(lane, ModuleSyntax::EsModule)
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect("bounded timer imports admit the canonical factory's deferred getters");
        assert_eq!(
            lines(&result),
            [
                "true true true true",
                "get 0 true false true true true",
                "get 0 true false true true true",
            ],
            "lane={lane:?}"
        );
    }
}

#[test]
fn delivered_timer_esm_imports_refuse_guest_promisify_getters_with_native_names() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let resolver = Arc::new(
            OpaqueResolver::new(vec![
                (
                    "entry.mjs",
                    definition(
                        ModuleSyntax::EsModule,
                        "import './mutate.cjs'; import {setTimeout as schedule} from 'node:timers'; \
                         console.log(schedule());",
                    )
                    .with_dependency(ModuleDependency::new("./mutate.cjs", ImportStyle::Import)),
                ),
                (
                    "mutate.cjs",
                    definition(
                        ModuleSyntax::CommonJs,
                        r#"
const timers = require('timers');
const fake = function setTimeout() { return 'guest timer result'; };
Object.defineProperty(fake, Symbol.for('nodejs.util.promisify.custom'), {
    get: function get() { console.log('guest getter ran'); return function () {}; },
    enumerable: true,
    configurable: false
});
timers.setTimeout = fake;
"#,
                    ),
                ),
            ])
            .with_native_builtins(),
        );
        let source = entry(&resolver, "entry.mjs", ModuleSyntax::EsModule);
        let installed = ExecutionModuleResolver::new(
            &source.module.record.id,
            resolver,
            Arc::new(RecordingPolicy {
                allow_native_builtins: true,
                ..RecordingPolicy::default()
            }),
        );
        let mut engine = orchestrator(lane, ModuleSyntax::EsModule);
        let error = engine
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect_err("the name get does not give a guest closure native accessor authority");
        assert!(
            error.to_string().contains("bounded-import contract"),
            "lane={lane:?}: {error}"
        );
        assert!(
            error.to_string().contains("'node:timers'"),
            "lane={lane:?}: {error}"
        );
        assert!(engine.last_failed_console_output().is_empty());
    }
}

#[test]
fn delivered_timer_promises_esm_runs_timers_scheduler_and_interval_return() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let resolver = Arc::new(
            OpaqueResolver::new(vec![(
                "entry.mjs",
                definition(
                    ModuleSyntax::EsModule,
                    r#"
import promises, { setTimeout as delay, setImmediate as immediate,
    setInterval as interval, scheduler } from 'node:timers/promises';
import * as namespace from 'timers/promises';
import timers, { promises as parentPromises } from 'node:timers';
console.log(namespace.default === promises, parentPromises === promises,
    timers.promises === promises, namespace.setTimeout === delay,
    namespace.scheduler === scheduler);
let readonly = false;
try { namespace.setTimeout = function() {}; } catch (error) { readonly = error instanceof TypeError; }
console.log(Object.getPrototypeOf(namespace) === null, Object.isExtensible(namespace), readonly);
delay(1, 'timeout').then(async function(value) {
    console.log(value, await immediate('immediate'));
    const ticks = interval(1, 'tick');
    const first = await ticks.next();
    const stopped = await ticks.return();
    const done = await ticks.next();
    console.log(first.value, first.done, stopped.done, done.done);
    console.log((await scheduler.yield()) === undefined, (await scheduler.wait(1)) === undefined);
    promises.added = true;
    promises.setTimeout = function replacement() { return 'changed'; };
    const again = await import('node:timers/promises');
    console.log(again === namespace, again.setTimeout === delay,
        again.default.setTimeout(), 'added' in again);
});
"#,
                ),
            )])
            .with_native_builtins(),
        );
        let source = entry(&resolver, "entry.mjs", ModuleSyntax::EsModule);
        let installed = ExecutionModuleResolver::new(
            &source.module.record.id,
            resolver,
            Arc::new(RecordingPolicy {
                allow_native_builtins: true,
                ..RecordingPolicy::default()
            }),
        );
        let result = orchestrator(lane, ModuleSyntax::EsModule)
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect("delivered ESM timer methods execute their retained native factory");
        assert_eq!(
            lines(&result),
            [
                "true true true true true",
                "true false true",
                "timeout immediate",
                "tick false true true",
                "true true",
                "true true changed false",
            ]
        );
    }
}

#[test]
fn delivered_timer_promises_requires_timer_authority_at_policy_and_runtime() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for deny_in_policy in [false, true] {
            let resolver = Arc::new(
                OpaqueResolver::new(vec![(
                    "entry.cjs",
                    definition(
                        ModuleSyntax::CommonJs,
                        "const load = require; console.log('before'); load('timers/promises'); console.log('after');",
                    ),
                )])
                .with_native_builtins(),
            );
            let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
            let mut grants =
                BTreeSet::from([RuntimeCapability::ModuleLoad, RuntimeCapability::Builtin]);
            let mut extension = package();
            // Exercise resolver policy and runtime authority independently.
            if !deny_in_policy {
                grants.insert(RuntimeCapability::Timer);
                extension.capabilities.retain(|grant| grant != "timer");
            }
            let installed = ExecutionModuleResolver::new(
                &source.module.record.id,
                resolver,
                Arc::new(CapabilityPolicyHook::new(grants)),
            );
            let mut engine = orchestrator(lane, ModuleSyntax::CommonJs);
            let error = engine
                .execute_resolved_entry_with_resolver(&extension, &source, installed)
                .expect_err("a source-free descriptor does not confer Timer authority");
            assert!(
                error.to_string().to_ascii_lowercase().contains("timer"),
                "policy={deny_in_policy}: {error}"
            );
            assert_eq!(
                engine
                    .last_failed_console_output()
                    .iter()
                    .map(|entry| entry.message.as_str())
                    .collect::<Vec<_>>(),
                ["before"],
                "native initialization must not run past the denied load"
            );
        }
    }
}

#[test]
fn delivered_timer_promises_cache_reauthorizes_commonjs_and_esm_requests() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for source_text in [
            "const load = require; const p = load('timers/promises'); console.log(typeof p.scheduler.wait); load('timers/promises');",
            "import('timers/promises').then(function(p) { console.log(typeof p.scheduler.wait); return import('timers/promises'); });",
        ] {
            let resolver = Arc::new(
                OpaqueResolver::new(vec![(
                    "entry.cjs",
                    definition(ModuleSyntax::CommonJs, source_text),
                )])
                .with_native_builtins(),
            );
            let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
            let policy = Arc::new(RecordingPolicy {
                denied: Some(("timers/promises".to_string(), 2)),
                allow_native_builtins: true,
                ..RecordingPolicy::default()
            });
            let installed =
                ExecutionModuleResolver::new(&source.module.record.id, resolver, policy.clone());
            let mut engine = orchestrator(lane, ModuleSyntax::CommonJs);
            let error = engine
                .execute_resolved_entry_with_resolver(&package(), &source, installed)
                .expect_err("timer singleton and ESM namespace caches cannot cache authorization");
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
                ["function"]
            );
            assert_eq!(
                policy
                    .requests
                    .lock()
                    .expect("policy log")
                    .iter()
                    .filter(|(request, _)| request.specifier == "timers/promises")
                    .count(),
                2
            );
        }
    }
}

// Require one engine-owned provider even when promises loads first. Cold
// Node v22.16.0/v24.19.0 can retain an empty circular export in that order;
// the promises-first identity checks express this engine contract and are
// not counted as reference-runtime differential passes.
#[test]
fn delivered_streams_share_factories_and_execute_cross_module_callbacks() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for first in ["stream", "stream/promises"] {
            let source_text = r#"
const load = require;
load('__FIRST__');
const stream = load('node:stream');
const promises = load('stream/promises');
const child = load('./stream-child.cjs');
console.log(stream === load('stream'), promises === load('node:stream/promises'),
    stream.promises === promises, child.stream === stream, child.promises === promises);
console.log(stream.Stream === stream, child.Transform === stream.Transform,
    child.pipeline === promises.pipeline,
    stream.pipeline[Symbol.for('nodejs.util.promisify.custom')] === promises.pipeline,
    stream.finished[Symbol.for('nodejs.util.promisify.custom')] === promises.finished);
const transformed = new child.Twice();
console.log(transformed instanceof stream.Transform, transformed instanceof stream.Duplex,
    transformed instanceof stream.Readable);
const values = [];
let active = 0;
let maximum = 0;
const sink = new stream.Writable({
    objectMode: true,
    highWaterMark: 1,
    write: function(value, encoding, done) {
        active++;
        maximum = Math.max(maximum, active);
        values.push(value);
        Promise.resolve().then(function() { active--; done(); });
    }
});
child.pipeline(stream.Readable.from([1, 2, 3]), transformed, sink).then(async function() {
    console.log(values.join(','), maximum, sink.writableFinished, sink.destroyed);
    const input = stream.Readable.from([
        Buffer.from([226]), Buffer.from([130]), Buffer.from([172, 33])
    ], { objectMode: false });
    input.setEncoding('utf8');
    let text = '';
    for await (const chunk of input) text += chunk;
    console.log(text);
    const mapped = await stream.Readable.from([1, 2, 3, 4])
        .map(async function(value) { return value * 3; }, { concurrency: 2 })
        .filter(function(value) { return value % 2 === 0; }).toArray();
    console.log(mapped.join(','));
});
"#
            .replace("__FIRST__", first);
            let resolver = Arc::new(
                OpaqueResolver::new(vec![
                    (
                        "entry.cjs",
                        definition(ModuleSyntax::CommonJs, &source_text).with_dependency(
                            ModuleDependency::new("./stream-child.cjs", ImportStyle::Require),
                        ),
                    ),
                    (
                        "stream-child.cjs",
                        definition(
                            ModuleSyntax::CommonJs,
                            r#"
const load = require;
const stream = load('stream');
const promises = load('node:stream/promises');
class Twice extends stream.Transform {
    constructor() { super({ objectMode: true, highWaterMark: 1 }); }
    _transform(value, encoding, done) { done(null, value * 2); }
}
module.exports = {
    stream: stream, promises: promises, Transform: stream.Transform,
    pipeline: promises.pipeline, Twice: Twice
};
"#,
                        ),
                    ),
                ])
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
                .expect("captured packages execute the retained stream implementation");
            assert_eq!(
                lines(&result),
                [
                    "true true true true true",
                    "true true true true true",
                    "true true true",
                    "2,4,6 1 true true",
                    "\u{20ac}!",
                    "6,12",
                ],
                "first={first}, lane={lane:?}"
            );
            assert!(
                policy
                    .requests
                    .lock()
                    .expect("policy log")
                    .iter()
                    .all(|(request, _)| !request.specifier.starts_with('\0')),
                "private stream dependencies do not introduce uncaptured source requests"
            );
        }
    }
}

#[test]
fn delivered_stream_promises_keeps_original_exports_after_parent_replacement() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let resolver = Arc::new(
            OpaqueResolver::new(vec![(
                "entry.cjs",
                definition(
                    ModuleSyntax::CommonJs,
                    r#"
const load = require;
const stream = load('stream');
const original = stream.promises;
let reads = 0;
Object.defineProperty(stream, 'promises', {
    configurable: true,
    get: function() { reads++; throw new Error('must not read guest replacement'); }
});
const promises = load('node:stream/promises');
console.log(promises === original, load('stream/promises') === original, reads);
console.log(stream.pipeline[Symbol.for('nodejs.util.promisify.custom')] === promises.pipeline,
    stream.finished[Symbol.for('nodejs.util.promisify.custom')] === promises.finished);
const output = [];
promises.pipeline([20, 22], new stream.Writable({
    objectMode: true,
    write: function(value, encoding, done) { output.push(value); done(); }
})).then(function() { console.log(output.join(','), reads); });
"#,
                ),
            )])
            .with_native_builtins(),
        );
        let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
        let installed = ExecutionModuleResolver::new(
            &source.module.record.id,
            resolver,
            Arc::new(RecordingPolicy {
                allow_native_builtins: true,
                ..RecordingPolicy::default()
            }),
        );
        let result = orchestrator(lane, ModuleSyntax::CommonJs)
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect("stream/promises selects the original private carrier without a guest getter");
        assert_eq!(
            lines(&result),
            ["true true 0", "true true", "20,22 0"],
            "lane={lane:?}"
        );
    }
}

#[test]
fn delivered_module_and_stream_namespaces_reject_export_replacement() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for (alias, key) in [
            ("module", "createRequire"),
            ("stream", "Readable"),
            ("stream/promises", "pipeline"),
        ] {
            let source_text = format!(
                r#"
import * as namespace from '{alias}';
import * as nativeNamespace from 'node:{alias}';
const key = '{key}';
const original = namespace[key];
const replacement = function replacement() {{ return 'guest'; }};
let readonly = false;
try {{ namespace[key] = replacement; }} catch (error) {{ readonly = error instanceof TypeError; }}
console.log(readonly, Reflect.set(namespace, key, replacement),
    Reflect.defineProperty(namespace, key, {{value: replacement}}),
    namespace[key] === original, nativeNamespace === namespace,
    Object.getOwnPropertyDescriptor(namespace, key).writable);
const fake = {{}};
fake[Symbol.toStringTag] = 'Module';
fake[key] = original;
fake[key] = replacement;
console.log(fake[key] === replacement, Reflect.set(fake, key, original),
    Reflect.defineProperty(fake, key, {{value: replacement}}), fake[key] === replacement);
"#
            );
            let resolver = Arc::new(
                OpaqueResolver::new(vec![(
                    "entry.mjs",
                    definition(ModuleSyntax::EsModule, &source_text),
                )])
                .with_native_builtins(),
            );
            let source = entry(&resolver, "entry.mjs", ModuleSyntax::EsModule);
            let installed = ExecutionModuleResolver::new(
                &source.module.record.id,
                resolver,
                Arc::new(AllowAllPolicy),
            );
            let result = orchestrator(lane, ModuleSyntax::EsModule)
                .execute_resolved_entry_with_resolver(&package(), &source, installed)
                .expect("native module namespaces reject export replacement without trusting a tag");
            assert_eq!(
                lines(&result),
                ["true false false true true true", "true true true true"],
                "lane={lane:?}, alias={alias}"
            );
        }
    }
}

#[test]
fn delivered_stream_esm_namespaces_share_defaults_and_keep_named_snapshots() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let resolver = Arc::new(
            OpaqueResolver::new(vec![(
                "entry.mjs",
                definition(
                    ModuleSyntax::EsModule,
                    r#"
import stream, { Stream, Readable, Writable, Transform, pipeline, finished, promises } from 'stream';
import * as namespace from 'node:stream';
import promiseModule, { pipeline as pipe } from 'node:stream/promises';
import * as promiseNamespace from 'stream/promises';
console.log(stream === Stream, namespace.default === stream, promises === promiseModule,
    promiseNamespace.default === promiseModule, promiseNamespace.pipeline === pipe);
console.log(Readable === stream.Readable, Writable === stream.Writable,
    Transform === stream.Transform, pipeline === stream.pipeline, finished === stream.finished);
let readonly = false;
try { namespace.Readable = function() {}; } catch (error) { readonly = error instanceof TypeError; }
console.log(Object.getPrototypeOf(namespace) === null, Object.isExtensible(namespace), readonly);
const output = [];
pipe(Readable.from([3, 4]), new Writable({
    objectMode: true,
    write: function(value, encoding, done) { output.push(value); done(); }
})).then(async function() {
    console.log(output.join(','));
    stream.pipeline = function replacement() { return 'changed'; };
    stream.added = true;
    const again = await import('stream');
    const againPromises = await import('node:stream/promises');
    console.log(again === namespace, again.pipeline === pipeline,
        again.default.pipeline(), 'added' in again,
        againPromises === promiseNamespace, againPromises.pipeline === pipe);
});
"#,
                ),
            )])
            .with_native_builtins(),
        );
        let source = entry(&resolver, "entry.mjs", ModuleSyntax::EsModule);
        let installed = ExecutionModuleResolver::new(
            &source.module.record.id,
            resolver,
            Arc::new(RecordingPolicy {
                allow_native_builtins: true,
                ..RecordingPolicy::default()
            }),
        );
        let result = orchestrator(lane, ModuleSyntax::EsModule)
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect("the delivered stream ESM facade executes the shared runtime provider");
        assert_eq!(
            lines(&result),
            [
                "true true true true true",
                "true true true true true",
                "true false true",
                "3,4",
                "true true changed false true true",
            ],
            "lane={lane:?}"
        );
    }
}

#[test]
fn delivered_stream_pipeline_cancellation_retains_the_caller_cause() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let resolver = Arc::new(
            OpaqueResolver::new(vec![(
                "entry.cjs",
                definition(
                    ModuleSyntax::CommonJs,
                    r#"
const load = require;
const stream = load('stream');
const pipeline = load('node:stream/promises').pipeline;
const source = new stream.Readable({ objectMode: true, read: function() {} });
const sink = new stream.Writable({
    objectMode: true,
    write: function(value, encoding, done) { done(); }
});
const controller = new AbortController();
const reason = { marker: 'stream cancellation' };
pipeline(source, sink, { signal: controller.signal }).then(
    function() { console.log('unexpected success'); },
    function(error) {
        console.log(error.name, error.code, error.cause === reason,
            source.destroyed, sink.destroyed);
    }
);
controller.abort(reason);
"#,
                ),
            )])
            .with_native_builtins(),
        );
        let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
        let installed = ExecutionModuleResolver::new(
            &source.module.record.id,
            resolver,
            Arc::new(RecordingPolicy {
                allow_native_builtins: true,
                ..RecordingPolicy::default()
            }),
        );
        let result = orchestrator(lane, ModuleSyntax::CommonJs)
            .execute_resolved_entry_with_resolver(&package(), &source, installed)
            .expect("delivered stream cancellation uses the retained event-loop owner");
        assert_eq!(
            lines(&result),
            ["AbortError ABORT_ERR true true true"],
            "lane={lane:?}"
        );
    }
}

#[test]
fn delivered_streams_require_timer_authority_at_policy_and_runtime() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for specifier in ["stream", "stream/promises"] {
            for deny_in_policy in [false, true] {
                let resolver = Arc::new(
                    OpaqueResolver::new(vec![(
                        "entry.cjs",
                        definition(
                            ModuleSyntax::CommonJs,
                            &format!(
                                "const load = require; console.log('before'); load('{specifier}'); console.log('after');"
                            ),
                        ),
                    )])
                    .with_native_builtins(),
                );
                let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
                let mut grants =
                    BTreeSet::from([RuntimeCapability::ModuleLoad, RuntimeCapability::Builtin]);
                let mut extension = package();
                if !deny_in_policy {
                    grants.insert(RuntimeCapability::Timer);
                    extension.capabilities.retain(|grant| grant != "timer");
                }
                let installed = ExecutionModuleResolver::new(
                    &source.module.record.id,
                    resolver,
                    Arc::new(CapabilityPolicyHook::new(grants)),
                );
                let mut engine = orchestrator(lane, ModuleSyntax::CommonJs);
                let error = engine
                    .execute_resolved_entry_with_resolver(&extension, &source, installed)
                    .expect_err("stream module delivery does not confer nextTick authority");
                assert!(
                    error.to_string().to_ascii_lowercase().contains("timer"),
                    "{specifier}, policy={deny_in_policy}: {error}"
                );
                assert_eq!(
                    engine
                        .last_failed_console_output()
                        .iter()
                        .map(|entry| entry.message.as_str())
                        .collect::<Vec<_>>(),
                    ["before"]
                );
            }
        }
    }
}

#[test]
fn delivered_stream_caches_reauthorize_each_commonjs_and_esm_request() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for specifier in ["stream", "stream/promises"] {
            for source_text in [
                format!(
                    "const load = require; console.log(typeof load('{specifier}').pipeline); load('{specifier}');"
                ),
                format!(
                    "import('{specifier}').then(function(module) {{ console.log(typeof module.pipeline); return import('{specifier}'); }});"
                ),
            ] {
                let resolver = Arc::new(
                    OpaqueResolver::new(vec![(
                        "entry.cjs",
                        definition(ModuleSyntax::CommonJs, &source_text),
                    )])
                    .with_native_builtins(),
                );
                let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
                let policy = Arc::new(RecordingPolicy {
                    denied: Some((specifier.to_string(), 2)),
                    allow_native_builtins: true,
                    ..RecordingPolicy::default()
                });
                let installed = ExecutionModuleResolver::new(
                    &source.module.record.id,
                    resolver,
                    policy.clone(),
                );
                let mut engine = orchestrator(lane, ModuleSyntax::CommonJs);
                let error = engine
                    .execute_resolved_entry_with_resolver(&package(), &source, installed)
                    .expect_err("stream instance and namespace caches never cache authorization");
                assert!(
                    error
                        .to_string()
                        .contains("closed-world module resolution refused"),
                    "{specifier}: {error}"
                );
                assert_eq!(
                    engine
                        .last_failed_console_output()
                        .iter()
                        .map(|entry| entry.message.as_str())
                        .collect::<Vec<_>>(),
                    ["function"]
                );
                assert_eq!(
                    policy
                        .requests
                        .lock()
                        .expect("policy log")
                        .iter()
                        .filter(|(request, _)| request.specifier == specifier)
                        .count(),
                    2
                );
            }
        }
    }
}

#[test]
fn delivered_streams_share_the_canonical_string_decoder_dependency() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for first in ["string_decoder", "stream", "stream/promises"] {
            let source_text = r#"
const load = require;
load('__FIRST__');
const stream = load('node:stream');
const decoder = load('node:string_decoder');
const input = new stream.Readable({ read: function() {} });
input.setEncoding('utf8');
const state = input._readableState.decoder;
console.log(decoder === load('string_decoder'),
    state instanceof decoder.StringDecoder, state.constructor === decoder.StringDecoder);
const lastNeed = Object.getOwnPropertyDescriptor(decoder.StringDecoder.prototype, 'lastNeed').get;
console.log(lastNeed.call(state));
state.write(Buffer.from([226]));
console.log(lastNeed.call(state), state.end(Buffer.from([130, 172])));
"#
            .replace("__FIRST__", first);
            let resolver = Arc::new(
                OpaqueResolver::new(vec![(
                    "entry.cjs",
                    definition(ModuleSyntax::CommonJs, &source_text),
                )])
                .with_native_builtins(),
            );
            let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
            let installed = ExecutionModuleResolver::new(
                &source.module.record.id,
                resolver,
                Arc::new(RecordingPolicy {
                    allow_native_builtins: true,
                    ..RecordingPolicy::default()
                }),
            );
            let result = orchestrator(lane, ModuleSyntax::CommonJs)
                .execute_resolved_entry_with_resolver(&package(), &source, installed)
                .expect("stream retains the public decoder constructor and its branded state");
            assert_eq!(
                lines(&result),
                ["true true true", "0", "2 \u{20ac}"],
                "first={first}, lane={lane:?}"
            );
        }
    }
}

#[test]
fn delivered_streams_preserve_the_canonical_events_dependency() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for first in ["events", "stream", "stream/promises"] {
            let source_text = r#"
const load = require;
load('__FIRST__');
const events = load('node:events');
const constructor = events.EventEmitter;
const once = events.once;
const emit = constructor.prototype.emit;
const monitor = Symbol('shared stream monitor');
events.defaultMaxListeners = 23;
events.errorMonitor = monitor;
const stream = load('node:stream');
load('node:stream/promises');
console.log(events === load('events'), events.EventEmitter === constructor,
    events.once === once, constructor.prototype.emit === emit);
console.log(events.defaultMaxListeners, events.errorMonitor === monitor);
console.log(Object.getPrototypeOf(stream.Stream.prototype) === constructor.prototype,
    new stream.Readable({ read: function() {} }) instanceof constructor);
"#
            .replace("__FIRST__", first);
            let resolver = Arc::new(
                OpaqueResolver::new(vec![(
                    "entry.cjs",
                    definition(ModuleSyntax::CommonJs, &source_text),
                )])
                .with_native_builtins(),
            );
            let source = entry(&resolver, "entry.cjs", ModuleSyntax::CommonJs);
            let installed = ExecutionModuleResolver::new(
                &source.module.record.id,
                resolver,
                Arc::new(RecordingPolicy {
                    allow_native_builtins: true,
                    ..RecordingPolicy::default()
                }),
            );
            let result = orchestrator(lane, ModuleSyntax::CommonJs)
                .execute_resolved_entry_with_resolver(&package(), &source, installed)
                .expect("stream reuses events without reinitializing its shared public state");
            assert_eq!(
                lines(&result),
                ["true true true true", "23 true", "true true"],
                "first={first}, lane={lane:?}"
            );
        }
    }
}

#[test]
fn delivered_transitive_dependencies_preserve_the_explicit_process_shape_grant() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for syntax in [ModuleSyntax::CommonJs, ModuleSyntax::EsModule] {
            let (
                entry_name,
                middle_name,
                leaf_name,
                entry_source,
                middle_source,
                leaf_source,
                style,
            ) = if syntax == ModuleSyntax::CommonJs {
                (
                    "entry.cjs",
                    "middle.cjs",
                    "leaf.cjs",
                    "console.log(require('./middle.cjs'));",
                    "module.exports = require('./leaf.cjs');",
                    "module.exports = typeof process.platform + ' ' + typeof process.arch + ' ' + process.argv[2];",
                    ImportStyle::Require,
                )
            } else {
                (
                    "entry.mjs",
                    "middle.mjs",
                    "leaf.mjs",
                    "import value from './middle.mjs'; console.log(value);",
                    "export { default } from './leaf.mjs';",
                    "export default typeof process.platform + ' ' + typeof process.arch + ' ' + process.argv[2];",
                    ImportStyle::Import,
                )
            };
            for grant in [
                AmbientAuthorityGrant::DenyAll,
                AmbientAuthorityGrant::TrustedProcessShape,
            ] {
                let resolver =
                    Arc::new(OpaqueResolver::new(vec![
                        (
                            entry_name,
                            definition(syntax, entry_source).with_dependency(
                                ModuleDependency::new(format!("./{middle_name}"), style),
                            ),
                        ),
                        (
                            middle_name,
                            definition(syntax, middle_source).with_dependency(
                                ModuleDependency::new(format!("./{leaf_name}"), style),
                            ),
                        ),
                        (leaf_name, definition(syntax, leaf_source)),
                    ]));
                let source = entry(&resolver, entry_name, syntax);
                let installed = ExecutionModuleResolver::new(
                    &source.module.record.id,
                    resolver,
                    Arc::new(RecordingPolicy::default()),
                );
                let mut engine =
                    ExecutionOrchestrator::try_new_lab_with_runtime_config_and_ambient_authority_grant(
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
                        grant,
                    )
                    .expect("native runtime with explicit ambient grant");
                engine.set_process_argv(vec![
                    "franken-node".to_string(),
                    entry_name.to_string(),
                    "package-argument".to_string(),
                ]);
                let result =
                    engine.execute_resolved_entry_with_resolver(&package(), &source, installed);
                if grant == AmbientAuthorityGrant::TrustedProcessShape {
                    assert_eq!(
                        lines(&result.expect("the admitted grant reaches transitive dependencies")),
                        ["string string package-argument"],
                    );
                } else {
                    result.expect_err("source modules cannot introduce process-shape authority");
                    assert!(engine.last_failed_console_output().is_empty());
                }
            }
        }
    }
}

/// Transparent I/O decorator: every effect still uses the real sandbox and
/// forwards the supervisor control. Only the declared exception contract varies.
#[derive(Debug)]
struct DependencyProvenanceHostIo {
    inner: SandboxedHostIo,
    provenance: HostIoExceptionProvenance,
    calls: AtomicUsize,
}

impl HostIoProvider for DependencyProvenanceHostIo {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
        self.provenance
    }

    fn perform(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.perform(request, granted)
    }

    fn perform_controlled(
        &self,
        request: &HostIoRequest,
        granted: &[HostIoCapability],
        control: Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.perform_controlled(request, granted, control)
    }
}

/// An otherwise transparent recording source deliberately retains the trait's
/// fail-high default. It must not inherit trust merely from the live provider.
#[derive(Debug)]
struct UnknownDependencyRecorder {
    inner: Arc<InMemoryHostIoTranscript>,
}

impl HostIoRecorder for UnknownDependencyRecorder {
    fn begin_execution(&self) -> Result<(), HostIoError> {
        self.inner.begin_execution()
    }

    fn replay(&self, request: &HostIoRequest) -> Option<HostIoOutcome> {
        self.inner.replay(request)
    }

    fn record(&self, request: &HostIoRequest, outcome: &HostIoOutcome) {
        self.inner.record(request, outcome);
    }

    fn finish_execution(&self) -> Result<Vec<(HostIoRequest, HostIoOutcome)>, HostIoError> {
        self.inner.finish_execution()
    }

    fn recorded_entries(&self) -> Vec<(HostIoRequest, HostIoOutcome)> {
        self.inner.recorded_entries()
    }
}

#[test]
fn filesystem_dependencies_use_effective_provider_and_recorder_exception_provenance() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for syntax in [ModuleSyntax::CommonJs, ModuleSyntax::EsModule] {
            for (provider_trusted, recorder_trusted) in [
                (true, None),
                (true, Some(true)),
                (false, None),
                (true, Some(false)),
            ] {
                let root = tempfile::tempdir().expect("module and I/O sandbox");
                let (entry_name, dependency_name, entry_source, dependency_source) =
                    if syntax == ModuleSyntax::CommonJs {
                        (
                            "entry.cjs",
                            "dependency.cjs",
                            "require('./dependency.cjs');",
                            "const fs = require('fs'); \
                             try { fs.readFileSync('absent.txt', 'utf8'); } \
                             catch (error) { console.log(error.code); } \
                             console.log(fs.readFileSync('input.txt', 'utf8'));",
                        )
                    } else {
                        (
                            "entry.mjs",
                            "dependency.mjs",
                            "import './dependency.mjs';",
                            "import fs from 'node:fs'; \
                             try { fs.readFileSync('absent.txt', 'utf8'); } \
                             catch (error) { console.log(error.code); } \
                             console.log(fs.readFileSync('input.txt', 'utf8'));",
                        )
                    };
                let entry_path = root.path().join(entry_name);
                std::fs::write(&entry_path, entry_source).expect("entry module");
                std::fs::write(root.path().join(dependency_name), dependency_source)
                    .expect("dependency module");
                std::fs::write(root.path().join("input.txt"), "dependency bytes")
                    .expect("real provider input");
                let provider = Arc::new(DependencyProvenanceHostIo {
                    inner: SandboxedHostIo::with_root(root.path()).expect("real sandbox provider"),
                    provenance: if provider_trusted {
                        HostIoExceptionProvenance::ProviderInternal
                    } else {
                        HostIoExceptionProvenance::Unknown
                    },
                    calls: AtomicUsize::new(0),
                });
                let transcript = Arc::new(InMemoryHostIoTranscript::recording());
                let recorder: Option<Arc<dyn HostIoRecorder>> = match recorder_trusted {
                    None => None,
                    Some(true) => Some(transcript.clone()),
                    Some(false) => Some(Arc::new(UnknownDependencyRecorder {
                        inner: transcript.clone(),
                    })),
                };
                let mut engine = orchestrator(lane, syntax);
                engine.set_host_io(provider.clone(), recorder);
                let mut execution = package();
                execution.source = entry_source.to_string();
                execution.source_file = Some(entry_path.display().to_string());
                execution.module_root = Some(root.path().display().to_string());
                execution.capabilities = [
                    "module_load",
                    "builtin",
                    "console",
                    "heap_allocate",
                    "vm_dispatch",
                    "fs_read",
                ]
                .into_iter()
                .map(str::to_string)
                .collect();
                let result = engine.execute(&execution);
                if provider_trusted && recorder_trusted != Some(false) {
                    let result = result.expect(
                        "a dependency inherits the execution's authenticated exception contract",
                    );
                    assert_eq!(lines(&result), ["ENOENT", "dependency bytes"]);
                    assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
                    let recorded = if recorder_trusted.is_some() { 2 } else { 0 };
                    assert_eq!(result.host_effect_transcript.len(), recorded);
                    assert_eq!(transcript.len(), recorded);
                } else {
                    let error = result.expect_err(
                        "an unknown provider or effect source keeps dependency exceptions high",
                    );
                    assert!(
                        matches!(
                            error.primary_error(),
                            OrchestratorError::Interpreter(
                                InterpreterError::ModuleLoweringFailed { .. }
                            )
                        ),
                        "must reject dependency lowering, not fail later in the host: {error}",
                    );
                    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
                    assert!(engine.last_failed_console_output().is_empty());
                    assert!(transcript.is_empty());
                }
            }
        }
    }
}
