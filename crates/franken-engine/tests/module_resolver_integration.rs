//! Integration tests for the `module_resolver` module.
//!
//! Covers: ModuleSyntax/ImportStyle/ModuleSourceKind enums, ModuleDefinition
//! builder, DeterministicModuleResolver registration and resolution, policy
//! hooks (AllowAllPolicy, CapabilityPolicyHook), resolution error codes,
//! HostApi authorization, ModuleRecord canonical hashing, serde roundtrips,
//! dependency chain resolution, and determinism guarantees.

#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeSet;

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::module_resolver::{
    AllowAllPolicy, CapabilityPolicyHook, CapabilitySafeHostApiSurface,
    DeterministicModuleResolver, HostApiErrorCode, HostApiRequest, ImportStyle,
    MODULE_RESOLUTION_TRACE_SCHEMA_VERSION, ModuleDefinition, ModuleDependency, ModuleRequest,
    ModuleResolver, ModuleSourceKind, ModuleSyntax, ResolutionContext, ResolutionErrorCode,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_context() -> ResolutionContext {
    ResolutionContext::new("trace-1", "decision-1", "policy-1")
}

fn allow_all() -> AllowAllPolicy {
    AllowAllPolicy
}

fn esm_def(source: &str) -> ModuleDefinition {
    ModuleDefinition::new(ModuleSyntax::EsModule, source)
}

fn cjs_def(source: &str) -> ModuleDefinition {
    ModuleDefinition::new(ModuleSyntax::CommonJs, source)
}

// =========================================================================
// A. ModuleSyntax — ordering, Copy, Display, serde
// =========================================================================

#[test]
fn module_syntax_ordering() {
    assert!(ModuleSyntax::EsModule < ModuleSyntax::CommonJs);
}

#[test]
fn module_syntax_copy() {
    let s = ModuleSyntax::EsModule;
    let s2 = s;
    assert_eq!(s, s2);
}

#[test]
fn module_syntax_as_str() {
    assert_eq!(ModuleSyntax::EsModule.as_str(), "esm");
    assert_eq!(ModuleSyntax::CommonJs.as_str(), "cjs");
}

#[test]
fn module_syntax_serde_all() {
    for s in [ModuleSyntax::EsModule, ModuleSyntax::CommonJs] {
        let json = serde_json::to_string(&s).unwrap();
        let restored: ModuleSyntax = serde_json::from_str(&json).unwrap();
        assert_eq!(s, restored);
    }
}

// =========================================================================
// B. ImportStyle — ordering, Copy, as_str, serde
// =========================================================================

#[test]
fn import_style_ordering() {
    assert!(ImportStyle::Import < ImportStyle::Require);
}

#[test]
fn import_style_as_str() {
    assert_eq!(ImportStyle::Import.as_str(), "import");
    assert_eq!(ImportStyle::Require.as_str(), "require");
}

#[test]
fn import_style_serde_all() {
    for s in [ImportStyle::Import, ImportStyle::Require] {
        let json = serde_json::to_string(&s).unwrap();
        let restored: ImportStyle = serde_json::from_str(&json).unwrap();
        assert_eq!(s, restored);
    }
}

// =========================================================================
// C. ModuleSourceKind — ordering, Copy, as_str, serde
// =========================================================================

#[test]
fn module_source_kind_ordering() {
    assert!(ModuleSourceKind::BuiltIn < ModuleSourceKind::Workspace);
    assert!(ModuleSourceKind::Workspace < ModuleSourceKind::ExternalRegistry);
}

#[test]
fn module_source_kind_as_str() {
    assert_eq!(ModuleSourceKind::BuiltIn.as_str(), "builtin");
    assert_eq!(ModuleSourceKind::Workspace.as_str(), "workspace");
    assert_eq!(
        ModuleSourceKind::ExternalRegistry.as_str(),
        "external_registry"
    );
}

#[test]
fn module_source_kind_serde_all() {
    for k in [
        ModuleSourceKind::BuiltIn,
        ModuleSourceKind::Workspace,
        ModuleSourceKind::ExternalRegistry,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let restored: ModuleSourceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, restored);
    }
}

// =========================================================================
// D. ModuleDefinition — builder
// =========================================================================

#[test]
fn module_definition_new_defaults() {
    let def = esm_def("export default 42;");
    assert_eq!(def.syntax, ModuleSyntax::EsModule);
    assert_eq!(def.source, "export default 42;");
    assert!(def.dependencies.is_empty());
    assert!(def.required_capabilities.is_empty());
    assert_eq!(def.provenance_origin, "<unspecified>");
}

#[test]
fn module_definition_with_dependency() {
    let dep = ModuleDependency::new("lodash", ImportStyle::Import);
    let def = esm_def("import _ from 'lodash';").with_dependency(dep);
    assert_eq!(def.dependencies.len(), 1);
    assert_eq!(def.dependencies[0].specifier, "lodash");
    assert_eq!(def.dependencies[0].style, ImportStyle::Import);
}

#[test]
fn module_definition_require_capability() {
    let def = esm_def("fs.readFileSync('x')").require_capability(RuntimeCapability::FsRead);
    assert!(
        def.required_capabilities
            .contains(&RuntimeCapability::FsRead)
    );
}

#[test]
fn module_definition_with_provenance() {
    let def = esm_def("x").with_provenance("npm:lodash@4.17.21");
    assert_eq!(def.provenance_origin, "npm:lodash@4.17.21");
}

// =========================================================================
// E. ModuleDependency — serde
// =========================================================================

#[test]
fn module_dependency_serde_roundtrip() {
    let dep = ModuleDependency::new("react", ImportStyle::Import);
    let json = serde_json::to_string(&dep).unwrap();
    let restored: ModuleDependency = serde_json::from_str(&json).unwrap();
    assert_eq!(dep, restored);
}

// =========================================================================
// F. DeterministicModuleResolver — creation and root_dir
// =========================================================================

#[test]
fn resolver_default_root() {
    let resolver = DeterministicModuleResolver::default();
    assert_eq!(resolver.root_dir(), "/");
}

#[test]
fn resolver_custom_root() {
    let resolver = DeterministicModuleResolver::new("/app/src");
    assert_eq!(resolver.root_dir(), "/app/src");
}

// =========================================================================
// G. Builtin registration and resolution
// =========================================================================

#[test]
fn register_and_resolve_builtin() {
    let mut resolver = DeterministicModuleResolver::default();
    resolver
        .register_builtin("node:fs", esm_def("builtin fs"))
        .unwrap();
    let request = ModuleRequest::new("node:fs", ImportStyle::Import);
    let outcome = resolver
        .resolve(&request, &test_context(), &allow_all())
        .unwrap();
    assert_eq!(outcome.module.record.syntax, ModuleSyntax::EsModule);
    assert_eq!(
        outcome.module.record.provenance.kind,
        ModuleSourceKind::BuiltIn
    );
}

#[test]
fn register_builtin_empty_key_fails() {
    let mut resolver = DeterministicModuleResolver::default();
    let result = resolver.register_builtin("", esm_def("x"));
    assert!(result.is_err());
}

#[test]
fn register_builtin_whitespace_key_fails() {
    let mut resolver = DeterministicModuleResolver::default();
    let result = resolver.register_builtin("   ", esm_def("x"));
    assert!(result.is_err());
}

// =========================================================================
// H. Workspace module registration and resolution
// =========================================================================

#[test]
fn register_and_resolve_workspace_module() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_workspace_module("src/index.js", esm_def("console.log('hello');"))
        .unwrap();
    let request = ModuleRequest::new("/app/src/index.js", ImportStyle::Import);
    let outcome = resolver
        .resolve(&request, &test_context(), &allow_all())
        .unwrap();
    assert_eq!(
        outcome.module.record.provenance.kind,
        ModuleSourceKind::Workspace
    );
}

#[test]
fn register_workspace_empty_path_fails() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    let result = resolver.register_workspace_module("", esm_def("x"));
    assert!(result.is_err());
}

// =========================================================================
// I. External module registration and resolution
// =========================================================================

#[test]
fn register_and_resolve_external_module() {
    let mut resolver = DeterministicModuleResolver::default();
    resolver
        .register_external_module("lodash", esm_def("export default {};"))
        .unwrap();
    let request = ModuleRequest::new("lodash", ImportStyle::Import);
    let outcome = resolver
        .resolve(&request, &test_context(), &allow_all())
        .unwrap();
    assert_eq!(
        outcome.module.record.provenance.kind,
        ModuleSourceKind::ExternalRegistry
    );
}

#[test]
fn register_external_empty_key_fails() {
    let mut resolver = DeterministicModuleResolver::default();
    let result = resolver.register_external_module("", esm_def("x"));
    assert!(result.is_err());
}

// =========================================================================
// J. Resolution errors
// =========================================================================

#[test]
fn resolve_empty_specifier_error() {
    let resolver = DeterministicModuleResolver::default();
    let request = ModuleRequest::new("", ImportStyle::Import);
    let err = resolver
        .resolve(&request, &test_context(), &allow_all())
        .unwrap_err();
    assert_eq!(err.code, ResolutionErrorCode::EmptySpecifier);
}

#[test]
fn resolve_module_not_found_error() {
    let resolver = DeterministicModuleResolver::default();
    let request = ModuleRequest::new("nonexistent", ImportStyle::Import);
    let err = resolver
        .resolve(&request, &test_context(), &allow_all())
        .unwrap_err();
    assert_eq!(err.code, ResolutionErrorCode::ModuleNotFound);
}

#[test]
fn resolve_relative_without_referrer_error() {
    let resolver = DeterministicModuleResolver::default();
    let request = ModuleRequest::new("./local", ImportStyle::Import);
    let err = resolver
        .resolve(&request, &test_context(), &allow_all())
        .unwrap_err();
    assert_eq!(err.code, ResolutionErrorCode::InvalidReferrer);
}

// =========================================================================
// K. ResolutionErrorCode — stable_code
// =========================================================================

#[test]
fn resolution_error_code_stable_codes_unique() {
    let codes = [
        ResolutionErrorCode::EmptySpecifier,
        ResolutionErrorCode::InvalidReferrer,
        ResolutionErrorCode::UnsupportedSpecifier,
        ResolutionErrorCode::ModuleNotFound,
        ResolutionErrorCode::PolicyDenied,
    ];
    let stable: BTreeSet<&str> = codes.iter().map(|c| c.stable_code()).collect();
    assert_eq!(stable.len(), codes.len());
    for code in &codes {
        assert!(code.stable_code().starts_with("FE-MODRES-"));
    }
}

// =========================================================================
// L. AllowAllPolicy — allows everything
// =========================================================================

#[test]
fn allow_all_policy_permits_resolution() {
    let mut resolver = DeterministicModuleResolver::default();
    resolver
        .register_builtin(
            "node:fs",
            esm_def("fs").require_capability(RuntimeCapability::FsRead),
        )
        .unwrap();
    let request = ModuleRequest::new("node:fs", ImportStyle::Import);
    let result = resolver.resolve(&request, &test_context(), &allow_all());
    assert!(result.is_ok());
}

// =========================================================================
// M. CapabilityPolicyHook — deny by missing capability
// =========================================================================

#[test]
fn capability_policy_denies_missing_capability() {
    let mut resolver = DeterministicModuleResolver::default();
    resolver
        .register_builtin(
            "node:fs",
            esm_def("fs").require_capability(RuntimeCapability::FsRead),
        )
        .unwrap();
    let policy = CapabilityPolicyHook::new(BTreeSet::new()); // no capabilities
    let request = ModuleRequest::new("node:fs", ImportStyle::Import);
    let err = resolver
        .resolve(&request, &test_context(), &policy)
        .unwrap_err();
    assert_eq!(err.code, ResolutionErrorCode::PolicyDenied);
}

#[test]
fn capability_policy_allows_with_capability() {
    let mut resolver = DeterministicModuleResolver::default();
    resolver
        .register_builtin(
            "node:fs",
            esm_def("fs").require_capability(RuntimeCapability::FsRead),
        )
        .unwrap();
    let mut caps = BTreeSet::new();
    caps.insert(RuntimeCapability::FsRead);
    let policy = CapabilityPolicyHook::new(caps);
    let request = ModuleRequest::new("node:fs", ImportStyle::Import);
    let result = resolver.resolve(&request, &test_context(), &policy);
    assert!(result.is_ok());
}

// =========================================================================
// N. CapabilityPolicyHook — deny-list
// =========================================================================

#[test]
fn capability_policy_deny_specifier() {
    let mut resolver = DeterministicModuleResolver::default();
    resolver
        .register_builtin("node:crypto", esm_def("crypto"))
        .unwrap();
    let policy = CapabilityPolicyHook::new(BTreeSet::new()).deny_specifier("node:crypto");
    let request = ModuleRequest::new("node:crypto", ImportStyle::Import);
    let err = resolver
        .resolve(&request, &test_context(), &policy)
        .unwrap_err();
    assert_eq!(err.code, ResolutionErrorCode::PolicyDenied);
}

// =========================================================================
// O. ModuleRecord — canonical hash determinism
// =========================================================================

#[test]
fn module_record_canonical_hash_deterministic() {
    let mut resolver1 = DeterministicModuleResolver::default();
    let mut resolver2 = DeterministicModuleResolver::default();
    let def = esm_def("export const x = 1;");
    resolver1.register_builtin("test", def.clone()).unwrap();
    resolver2.register_builtin("test", def).unwrap();
    let request = ModuleRequest::new("test", ImportStyle::Import);
    let ctx = test_context();
    let outcome1 = resolver1.resolve(&request, &ctx, &allow_all()).unwrap();
    let outcome2 = resolver2.resolve(&request, &ctx, &allow_all()).unwrap();
    assert_eq!(
        outcome1.module.record.canonical_hash(),
        outcome2.module.record.canonical_hash()
    );
}

#[test]
fn module_record_canonical_hash_sensitive_to_source() {
    let mut resolver = DeterministicModuleResolver::default();
    resolver.register_builtin("a", esm_def("source_a")).unwrap();
    resolver.register_builtin("b", esm_def("source_b")).unwrap();
    let ctx = test_context();
    let ra = ModuleRequest::new("a", ImportStyle::Import);
    let rb = ModuleRequest::new("b", ImportStyle::Import);
    let oa = resolver.resolve(&ra, &ctx, &allow_all()).unwrap();
    let ob = resolver.resolve(&rb, &ctx, &allow_all()).unwrap();
    assert_ne!(
        oa.module.record.canonical_hash(),
        ob.module.record.canonical_hash()
    );
}

// =========================================================================
// P. ResolutionOutcome — trace_record
// =========================================================================

#[test]
fn resolution_outcome_trace_record_schema_version() {
    let mut resolver = DeterministicModuleResolver::default();
    resolver.register_builtin("test", esm_def("x")).unwrap();
    let request = ModuleRequest::new("test", ImportStyle::Import);
    let outcome = resolver
        .resolve(&request, &test_context(), &allow_all())
        .unwrap();
    let trace = outcome.trace_record();
    assert_eq!(trace.schema_version, MODULE_RESOLUTION_TRACE_SCHEMA_VERSION);
}

#[test]
fn resolution_outcome_trace_record_to_json() {
    let mut resolver = DeterministicModuleResolver::default();
    resolver.register_builtin("test", esm_def("x")).unwrap();
    let request = ModuleRequest::new("test", ImportStyle::Import);
    let outcome = resolver
        .resolve(&request, &test_context(), &allow_all())
        .unwrap();
    let trace = outcome.trace_record();
    let json = trace.to_json_line().unwrap();
    assert!(json.contains("trace-1"));
}

// =========================================================================
// Q. ModuleRequest — builder
// =========================================================================

#[test]
fn module_request_with_referrer() {
    let req = ModuleRequest::new("./utils", ImportStyle::Import).with_referrer("/app/src/index.js");
    assert_eq!(req.referrer.as_deref(), Some("/app/src/index.js"));
}

#[test]
fn module_request_serde_roundtrip() {
    let req = ModuleRequest::new("lodash", ImportStyle::Require);
    let json = serde_json::to_string(&req).unwrap();
    let restored: ModuleRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req.specifier, restored.specifier);
    assert_eq!(req.style, restored.style);
}

// =========================================================================
// R. ResolutionContext — serde
// =========================================================================

#[test]
fn resolution_context_serde_roundtrip() {
    let ctx = test_context();
    let json = serde_json::to_string(&ctx).unwrap();
    let restored: ResolutionContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, restored);
}

// =========================================================================
// S. HostApi surface — standard descriptors
// =========================================================================

#[test]
fn host_api_surface_standard_has_modules() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let modules = surface.supported_modules();
    assert!(modules.contains(&"node:fs".to_string()));
    assert!(modules.contains(&"node:net".to_string()));
    assert!(modules.contains(&"node:process".to_string()));
    assert!(modules.contains(&"node:crypto".to_string()));
}

#[test]
fn host_api_surface_descriptor_lookup() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let desc = surface.descriptor("node:fs", "read_file");
    assert!(desc.is_some());
    let desc = desc.unwrap();
    assert!(
        desc.required_capabilities
            .contains(&RuntimeCapability::FsRead)
    );
}

#[test]
fn host_api_surface_unsupported_module_error() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let req = HostApiRequest::new("node:invalid", "do_thing");
    let ctx = test_context();
    let mut caps = BTreeSet::new();
    caps.insert(RuntimeCapability::FsRead);
    let policy = CapabilityPolicyHook::new(caps);
    let err = surface.authorize(&req, &ctx, &policy).unwrap_err();
    assert_eq!(err.code, HostApiErrorCode::UnsupportedModule);
}

#[test]
fn host_api_surface_unsupported_operation_error() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let req = HostApiRequest::new("node:fs", "nonexistent_op");
    let ctx = test_context();
    let mut caps = BTreeSet::new();
    caps.insert(RuntimeCapability::FsRead);
    let policy = CapabilityPolicyHook::new(caps);
    let err = surface.authorize(&req, &ctx, &policy).unwrap_err();
    assert_eq!(err.code, HostApiErrorCode::UnsupportedOperation);
}

#[test]
fn host_api_surface_policy_denied_error() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let req = HostApiRequest::new("node:fs", "read_file");
    let ctx = test_context();
    let policy = CapabilityPolicyHook::new(BTreeSet::new()); // no caps
    let err = surface.authorize(&req, &ctx, &policy).unwrap_err();
    assert_eq!(err.code, HostApiErrorCode::PolicyDenied);
}

#[test]
fn host_api_surface_authorization_success() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let req = HostApiRequest::new("node:fs", "read_file");
    let ctx = test_context();
    let mut caps = BTreeSet::new();
    caps.insert(RuntimeCapability::FsRead);
    let policy = CapabilityPolicyHook::new(caps);
    let outcome = surface.authorize(&req, &ctx, &policy).unwrap();
    assert_eq!(outcome.event.outcome, "allow");
}

// =========================================================================
// T. HostApiErrorCode — stable_code unique
// =========================================================================

#[test]
fn host_api_error_code_stable_codes_unique() {
    let codes = [
        HostApiErrorCode::UnsupportedModule,
        HostApiErrorCode::UnsupportedOperation,
        HostApiErrorCode::PolicyDenied,
    ];
    let stable: BTreeSet<&str> = codes.iter().map(|c| c.stable_code()).collect();
    assert_eq!(stable.len(), codes.len());
    for code in &codes {
        assert!(code.stable_code().starts_with("FE-HOSTAPI-"));
    }
}

// =========================================================================
// U. HostApiErrorCode — serde
// =========================================================================

#[test]
fn host_api_error_code_serde() {
    for code in [
        HostApiErrorCode::UnsupportedModule,
        HostApiErrorCode::UnsupportedOperation,
        HostApiErrorCode::PolicyDenied,
    ] {
        let json = serde_json::to_string(&code).unwrap();
        let restored: HostApiErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(code, restored);
    }
}

// =========================================================================
// V. DeterministicModuleResolver — serde roundtrip
// =========================================================================

#[test]
fn resolver_serde_roundtrip() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver.register_builtin("node:fs", esm_def("fs")).unwrap();
    let json = serde_json::to_string(&resolver).unwrap();
    let restored: DeterministicModuleResolver = serde_json::from_str(&json).unwrap();
    assert_eq!(resolver, restored);
}

// =========================================================================
// W. CommonJs resolution
// =========================================================================

#[test]
fn resolve_commonjs_module() {
    let mut resolver = DeterministicModuleResolver::default();
    resolver
        .register_builtin("node:path", cjs_def("module.exports = {};"))
        .unwrap();
    let request = ModuleRequest::new("node:path", ImportStyle::Require);
    let outcome = resolver
        .resolve(&request, &test_context(), &allow_all())
        .unwrap();
    assert_eq!(outcome.module.record.syntax, ModuleSyntax::CommonJs);
}

// =========================================================================
// X. ResolutionError — Display and trace_record
// =========================================================================

#[test]
fn resolution_error_display_contains_stable_code() {
    let resolver = DeterministicModuleResolver::default();
    let request = ModuleRequest::new("", ImportStyle::Import);
    let err = resolver
        .resolve(&request, &test_context(), &allow_all())
        .unwrap_err();
    let display = err.to_string();
    assert!(display.contains("FE-MODRES-"));
}

#[test]
fn resolution_error_trace_record() {
    let resolver = DeterministicModuleResolver::default();
    let request = ModuleRequest::new("missing", ImportStyle::Import);
    let err = resolver
        .resolve(&request, &test_context(), &allow_all())
        .unwrap_err();
    let trace = err.trace_record();
    assert_eq!(trace.schema_version, MODULE_RESOLUTION_TRACE_SCHEMA_VERSION);
    assert_eq!(trace.trace_id, "trace-1");
}

// =========================================================================
// Y. HostApi — canonicalization (fs -> node:fs)
// =========================================================================

#[test]
fn host_api_canonicalization_short_names() {
    let surface = CapabilitySafeHostApiSurface::standard();
    // "fs" should canonicalize to "node:fs"
    let desc = surface.descriptor("fs", "read_file");
    assert!(desc.is_some());
}

// =========================================================================
// Z. CapabilityPolicyHook — deny_host_api_descriptor
// =========================================================================

#[test]
fn capability_policy_deny_host_api_descriptor() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let req = HostApiRequest::new("node:fs", "read_file");
    let ctx = test_context();
    let mut caps = BTreeSet::new();
    caps.insert(RuntimeCapability::FsRead);
    let policy =
        CapabilityPolicyHook::new(caps).deny_host_api_descriptor("hostapi.node-fs.read-file.v1");
    let err = surface.authorize(&req, &ctx, &policy).unwrap_err();
    assert_eq!(err.code, HostApiErrorCode::PolicyDenied);
}

// =========================================================================
// AA. ModuleRecord — canonical_bytes non-empty
// =========================================================================

#[test]
fn module_record_canonical_bytes_nonempty() {
    let mut resolver = DeterministicModuleResolver::default();
    resolver.register_builtin("test", esm_def("x")).unwrap();
    let request = ModuleRequest::new("test", ImportStyle::Import);
    let outcome = resolver
        .resolve(&request, &test_context(), &allow_all())
        .unwrap();
    assert!(!outcome.module.record.canonical_bytes().is_empty());
}

// =========================================================================
// BB. Debug formatting
// =========================================================================

#[test]
fn debug_nonempty_all_types() {
    assert!(!format!("{:?}", ModuleSyntax::EsModule).is_empty());
    assert!(!format!("{:?}", ImportStyle::Import).is_empty());
    assert!(!format!("{:?}", ModuleSourceKind::BuiltIn).is_empty());
    assert!(!format!("{:?}", AllowAllPolicy).is_empty());
    assert!(!format!("{:?}", ResolutionErrorCode::EmptySpecifier).is_empty());
    assert!(!format!("{:?}", HostApiErrorCode::UnsupportedModule).is_empty());
}

// =========================================================================
// CC. resolve_chain — dependency chain resolution
// =========================================================================

#[test]
fn resolve_chain_single_module() {
    let mut resolver = DeterministicModuleResolver::default();
    resolver
        .register_builtin("node:fs", esm_def("builtin fs"))
        .unwrap();
    let request = ModuleRequest::new("node:fs", ImportStyle::Import);
    let chain = resolver
        .resolve_chain(&request, &test_context(), &allow_all())
        .unwrap();
    assert!(!chain.is_empty());
}

// =========================================================================
// DD. CapabilityPolicyHook — serde roundtrip
// =========================================================================

#[test]
fn capability_policy_hook_serde_roundtrip() {
    let mut caps = BTreeSet::new();
    caps.insert(RuntimeCapability::FsRead);
    caps.insert(RuntimeCapability::NetworkEgress);
    let policy = CapabilityPolicyHook::new(caps)
        .deny_specifier("evil_module")
        .deny_host_api_descriptor("hostapi.test.v1");
    let json = serde_json::to_string(&policy).unwrap();
    let restored: CapabilityPolicyHook = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, restored);
}

// =========================================================================
// EE. HostApiAuthorizationError — Display
// =========================================================================

#[test]
fn host_api_authorization_error_display() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let req = HostApiRequest::new("node:invalid", "x");
    let ctx = test_context();
    let policy = CapabilityPolicyHook::new(BTreeSet::new());
    let err = surface.authorize(&req, &ctx, &policy).unwrap_err();
    let display = err.to_string();
    assert!(display.contains("FE-HOSTAPI-"));
    assert!(display.contains("trace-1"));
}

// =========================================================================
// FF. HostApiPermissionDescriptor — fields
// =========================================================================

#[test]
fn host_api_permission_descriptor_fields() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let desc = surface.descriptor("node:net", "connect").unwrap();
    assert_eq!(desc.module_specifier, "node:net");
    assert_eq!(desc.operation, "connect");
    assert!(
        desc.required_capabilities
            .contains(&RuntimeCapability::NetworkEgress)
    );
    assert!(!desc.remediation.is_empty());
    assert!(!desc.descriptor_id.is_empty());
}

// =========================================================================
// GG. HostApiDecisionEvent — allow outcome fields
// =========================================================================

#[test]
fn host_api_allow_event_fields() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let req = HostApiRequest::new("node:net", "connect");
    let ctx = test_context();
    let mut caps = BTreeSet::new();
    caps.insert(RuntimeCapability::NetworkEgress);
    let policy = CapabilityPolicyHook::new(caps);
    let outcome = surface.authorize(&req, &ctx, &policy).unwrap();
    assert_eq!(outcome.event.outcome, "allow");
    assert_eq!(outcome.event.error_code, "none");
    assert_eq!(outcome.event.trace_id, "trace-1");
    assert!(outcome.event.descriptor_id.is_some());
}

// =========================================================================
// HH. RegistryError — Display
// =========================================================================

#[test]
fn registry_error_display() {
    let mut resolver = DeterministicModuleResolver::default();
    let err = resolver.register_builtin("", esm_def("x")).unwrap_err();
    let display = err.to_string();
    assert!(display.contains("empty"));
}

// =========================================================================
// II. CapabilitySafeHostApiSurface — default equals standard
// =========================================================================

#[test]
fn host_api_surface_default_is_standard() {
    let default_surface = CapabilitySafeHostApiSurface::default();
    let standard_surface = CapabilitySafeHostApiSurface::standard();
    assert_eq!(default_surface, standard_surface);
}

// =========================================================================
// JJ. HostApiRequest — serde
// =========================================================================

#[test]
fn host_api_request_serde_roundtrip() {
    let req = HostApiRequest::new("node:fs", "read_file");
    let json = serde_json::to_string(&req).unwrap();
    let restored: HostApiRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, restored);
}
