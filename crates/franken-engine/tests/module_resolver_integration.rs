#![forbid(unsafe_code)]

//! Integration tests for `module_resolver` — deterministic module resolution
//! with policy hooks, capability gating, and dependency chain traversal.

use std::collections::BTreeSet;
use std::fs;

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::module_compatibility_matrix::CompatibilityMode;
use frankenengine_engine::module_resolver::*;
use frankenengine_engine::rgc_test_harness::{
    DeterministicTestContext, EventInput, HarnessLane, HarnessRunManifest, write_artifact_triad,
};

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn ctx() -> ResolutionContext {
    ResolutionContext::new("trace-int", "decision-int", "policy-int")
}

fn ctx_named(trace: &str, decision: &str, policy: &str) -> ResolutionContext {
    ResolutionContext::new(trace, decision, policy)
}

fn esm(source: &str) -> ModuleDefinition {
    ModuleDefinition::new(ModuleSyntax::EsModule, source)
}

fn cjs(source: &str) -> ModuleDefinition {
    ModuleDefinition::new(ModuleSyntax::CommonJs, source)
}

fn grant(caps: &[RuntimeCapability]) -> CapabilityPolicyHook {
    let set: BTreeSet<RuntimeCapability> = caps.iter().copied().collect();
    CapabilityPolicyHook::new(set)
}

// -----------------------------------------------------------------------
// Section 1: Enum as_str coverage
// -----------------------------------------------------------------------

#[test]
fn module_syntax_as_str_values() {
    assert_eq!(ModuleSyntax::EsModule.as_str(), "esm");
    assert_eq!(ModuleSyntax::CommonJs.as_str(), "cjs");
}

#[test]
fn import_style_as_str_values() {
    assert_eq!(ImportStyle::Import.as_str(), "import");
    assert_eq!(ImportStyle::Require.as_str(), "require");
}

#[test]
fn module_source_kind_as_str_values() {
    assert_eq!(ModuleSourceKind::BuiltIn.as_str(), "builtin");
    assert_eq!(ModuleSourceKind::Workspace.as_str(), "workspace");
    assert_eq!(
        ModuleSourceKind::ExternalRegistry.as_str(),
        "external_registry"
    );
}

// -----------------------------------------------------------------------
// Section 2: Ordering (Ord derives)
// -----------------------------------------------------------------------

#[test]
fn module_syntax_ordering() {
    assert!(ModuleSyntax::EsModule < ModuleSyntax::CommonJs);
}

#[test]
fn import_style_ordering() {
    assert!(ImportStyle::Import < ImportStyle::Require);
}

#[test]
fn module_source_kind_ordering() {
    assert!(ModuleSourceKind::BuiltIn < ModuleSourceKind::Workspace);
    assert!(ModuleSourceKind::Workspace < ModuleSourceKind::ExternalRegistry);
}

// -----------------------------------------------------------------------
// Section 3: Constructor / builder patterns
// -----------------------------------------------------------------------

#[test]
fn module_dependency_new() {
    let dep = ModuleDependency::new("./lib", ImportStyle::Import);
    assert_eq!(dep.specifier, "./lib");
    assert_eq!(dep.style, ImportStyle::Import);
}

#[test]
fn module_definition_builder_chain() {
    let def = esm("import 'x'; export default 1;")
        .with_dependency(ModuleDependency::new("x", ImportStyle::Import))
        .require_capability(RuntimeCapability::FsRead)
        .require_capability(RuntimeCapability::NetworkEgress)
        .with_provenance("test:origin");

    assert_eq!(def.syntax, ModuleSyntax::EsModule);
    assert_eq!(def.dependencies.len(), 1);
    assert_eq!(def.dependencies[0].specifier, "x");
    assert!(
        def.required_capabilities
            .contains(&RuntimeCapability::FsRead)
    );
    assert!(
        def.required_capabilities
            .contains(&RuntimeCapability::NetworkEgress)
    );
    assert_eq!(def.provenance_origin, "test:origin");
}

#[test]
fn module_definition_default_provenance_is_unspecified() {
    let def = esm("export default 1;");
    assert_eq!(def.provenance_origin, "<unspecified>");
}

#[test]
fn module_definition_multiple_dependencies() {
    let def = esm("source")
        .with_dependency(ModuleDependency::new("a", ImportStyle::Import))
        .with_dependency(ModuleDependency::new("b", ImportStyle::Require))
        .with_dependency(ModuleDependency::new("c", ImportStyle::Import));
    assert_eq!(def.dependencies.len(), 3);
}

#[test]
fn module_request_new_without_referrer() {
    let req = ModuleRequest::new("./dep", ImportStyle::Import);
    assert_eq!(req.specifier, "./dep");
    assert!(req.referrer.is_none());
    assert_eq!(req.style, ImportStyle::Import);
}

#[test]
fn module_request_with_referrer() {
    let req = ModuleRequest::new("lodash", ImportStyle::Require).with_referrer("/app/main.js");
    assert_eq!(req.referrer.as_deref(), Some("/app/main.js"));
}

#[test]
fn resolution_context_new() {
    let ctx = ctx_named("t1", "d1", "p1");
    assert_eq!(ctx.trace_id, "t1");
    assert_eq!(ctx.decision_id, "d1");
    assert_eq!(ctx.policy_id, "p1");
}

// -----------------------------------------------------------------------
// Section 4: DeterministicModuleResolver construction
// -----------------------------------------------------------------------

#[test]
fn default_resolver_has_root_slash() {
    let r = DeterministicModuleResolver::default();
    assert_eq!(r.root_dir(), "/");
}

#[test]
fn resolver_normalizes_root_dir() {
    let r = DeterministicModuleResolver::new("/app/sub/../");
    assert_eq!(r.root_dir(), "/app");
}

// -----------------------------------------------------------------------
// Section 5: Registration — empty key rejection
// -----------------------------------------------------------------------

#[test]
fn register_builtin_empty_key_error() {
    let mut r = DeterministicModuleResolver::new("/app");
    let err = r.register_builtin("", esm("")).unwrap_err();
    assert_eq!(err.code, RegistryErrorCode::EmptyKey);
}

#[test]
fn register_builtin_whitespace_key_error() {
    let mut r = DeterministicModuleResolver::new("/app");
    let err = r.register_builtin("   ", esm("")).unwrap_err();
    assert_eq!(err.code, RegistryErrorCode::EmptyKey);
}

#[test]
fn register_workspace_empty_path_error() {
    let mut r = DeterministicModuleResolver::new("/app");
    let err = r.register_workspace_module("", esm("")).unwrap_err();
    assert_eq!(err.code, RegistryErrorCode::EmptyKey);
}

#[test]
fn register_external_empty_specifier_error() {
    let mut r = DeterministicModuleResolver::new("/app");
    let err = r.register_external_module("", cjs("")).unwrap_err();
    assert_eq!(err.code, RegistryErrorCode::EmptyKey);
}

// -----------------------------------------------------------------------
// Section 6: Builtin resolution
// -----------------------------------------------------------------------

#[test]
fn builtin_resolves_with_deterministic_hash() {
    let mut r = DeterministicModuleResolver::new("/workspace");
    r.register_builtin(
        "franken:std/fs",
        esm("export const read = true;")
            .require_capability(RuntimeCapability::FsRead)
            .with_provenance("builtin:franken:std/fs"),
    )
    .unwrap();

    let policy = grant(&[RuntimeCapability::FsRead]);
    let req = ModuleRequest::new("franken:std/fs", ImportStyle::Import);
    let o1 = r.resolve(&req, &ctx(), &policy).unwrap();
    let o2 = r.resolve(&req, &ctx(), &policy).unwrap();

    assert_eq!(o1.module.canonical_specifier, "franken:std/fs");
    assert_eq!(o1.module.record.id, "builtin:franken:std/fs");
    assert_eq!(o1.module.content_hash, o2.module.content_hash);
    assert_eq!(o1.event.component, "module_resolver");
    assert_eq!(o1.event.outcome, "allow");
    assert_eq!(o1.event.error_code, "none");
}

#[test]
fn builtin_has_priority_over_workspace_and_external() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_builtin("shared", esm("builtin")).unwrap();
    r.register_workspace_module("/app/shared", esm("workspace"))
        .unwrap();
    r.register_external_module("shared", cjs("external"))
        .unwrap();

    let req = ModuleRequest::new("shared", ImportStyle::Import);
    let outcome = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap();
    assert_eq!(outcome.module.record.id, "builtin:shared");
}

#[test]
fn duplicate_builtin_registration_overwrites() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_builtin("franken:util", esm("export const v = 1;"))
        .unwrap();
    r.register_builtin("franken:util", esm("export const v = 2;"))
        .unwrap();

    let req = ModuleRequest::new("franken:util", ImportStyle::Import);
    let outcome = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap();
    assert_eq!(outcome.module.record.source, "export const v = 2;");
}

// -----------------------------------------------------------------------
// Section 7: Workspace resolution — absolute / relative / bare
// -----------------------------------------------------------------------

#[test]
fn absolute_specifier_resolves_workspace_module() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_workspace_module("/app/lib/util.js", esm("export const x = 1;"))
        .unwrap();

    let req = ModuleRequest::new("/app/lib/util.js", ImportStyle::Import);
    let outcome = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap();
    assert_eq!(outcome.module.canonical_specifier, "/app/lib/util.js");
}

#[test]
fn relative_specifier_resolves_with_referrer() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_workspace_module("/app/main.mjs", esm("import './lib';"))
        .unwrap();
    r.register_workspace_module("/app/lib.mjs", esm("export default 1;"))
        .unwrap();

    let req = ModuleRequest::new("./lib", ImportStyle::Import).with_referrer("/app/main.mjs");
    let outcome = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap();
    assert_eq!(outcome.module.canonical_specifier, "/app/lib.mjs");
}

#[test]
fn bare_specifier_resolves_from_workspace_with_extension_probing() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_workspace_module("/app/utils.js", esm("export default 42;"))
        .unwrap();

    let req = ModuleRequest::new("utils", ImportStyle::Import);
    let outcome = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap();
    assert_eq!(outcome.module.canonical_specifier, "/app/utils.js");
}

#[test]
fn register_workspace_relative_path_normalizes_to_absolute() {
    let mut r = DeterministicModuleResolver::new("/workspace");
    r.register_workspace_module("src/lib.js", esm("export default 1;"))
        .unwrap();

    let req = ModuleRequest::new("/workspace/src/lib.js", ImportStyle::Import);
    let outcome = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap();
    assert_eq!(outcome.module.canonical_specifier, "/workspace/src/lib.js");
}

// -----------------------------------------------------------------------
// Section 8: Import vs Require style-specific extension probing
// -----------------------------------------------------------------------

#[test]
fn import_probes_mjs_then_js() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_workspace_module("/app/lib.mjs", esm("esm"))
        .unwrap();
    r.register_workspace_module("/app/lib.cjs", cjs("cjs"))
        .unwrap();

    let req = ModuleRequest::new("./lib", ImportStyle::Import).with_referrer("/app/main.js");
    let outcome = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap();
    assert_eq!(outcome.module.canonical_specifier, "/app/lib.mjs");
}

#[test]
fn require_probes_cjs_then_js() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_workspace_module("/app/lib.mjs", esm("esm"))
        .unwrap();
    r.register_workspace_module("/app/lib.cjs", cjs("cjs"))
        .unwrap();

    let req = ModuleRequest::new("./lib", ImportStyle::Require).with_referrer("/app/main.js");
    let outcome = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap();
    assert_eq!(outcome.module.canonical_specifier, "/app/lib.cjs");
}

#[test]
fn import_probes_index_mjs_for_directory() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_workspace_module("/app/lib/index.mjs", esm("export default 1;"))
        .unwrap();

    let req = ModuleRequest::new("./lib", ImportStyle::Import).with_referrer("/app/main.js");
    let outcome = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap();
    assert_eq!(outcome.module.canonical_specifier, "/app/lib/index.mjs");
}

#[test]
fn require_probes_index_cjs_for_directory() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_workspace_module("/app/lib/index.cjs", cjs("module.exports = 1;"))
        .unwrap();

    let req = ModuleRequest::new("./lib", ImportStyle::Require).with_referrer("/app/main.js");
    let outcome = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap();
    assert_eq!(outcome.module.canonical_specifier, "/app/lib/index.cjs");
}

#[test]
fn import_falls_through_to_js_extension() {
    let mut r = DeterministicModuleResolver::new("/app");
    // Only .js registered, no .mjs — should still resolve via fallback
    r.register_workspace_module("/app/utils.js", esm("export default 1;"))
        .unwrap();

    let req = ModuleRequest::new("./utils", ImportStyle::Import).with_referrer("/app/entry.js");
    let outcome = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap();
    assert_eq!(outcome.module.canonical_specifier, "/app/utils.js");
}

#[test]
fn require_falls_through_to_js_extension() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_workspace_module("/app/utils.js", cjs("module.exports = 1;"))
        .unwrap();

    let req = ModuleRequest::new("./utils", ImportStyle::Require).with_referrer("/app/entry.js");
    let outcome = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap();
    assert_eq!(outcome.module.canonical_specifier, "/app/utils.js");
}

#[test]
fn require_of_explicit_esm_path_returns_err_require_esm() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_workspace_module("/app/esm_only.mjs", esm("export default 1;"))
        .unwrap();

    let req =
        ModuleRequest::new("./esm_only.mjs", ImportStyle::Require).with_referrer("/app/main.cjs");
    let err = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap_err();

    assert_eq!(err.code, ResolutionErrorCode::UnsupportedSpecifier);
    assert_eq!(
        err.event.error_code,
        ResolutionErrorCode::UnsupportedSpecifier.stable_code()
    );
    assert!(err.message.contains("ERR_REQUIRE_ESM"));
    assert!(err.message.contains("/app/esm_only.mjs"));
}

#[test]
fn require_of_explicit_esm_path_succeeds_in_bun_compat_mode() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_workspace_module("/app/esm_only.mjs", esm("export default 1;"))
        .unwrap();

    let req = ModuleRequest::new("./esm_only.mjs", ImportStyle::Require)
        .with_referrer("/app/main.cjs")
        .with_compatibility_mode(CompatibilityMode::BunCompat);
    let outcome = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap();

    assert_eq!(outcome.module.canonical_specifier, "/app/esm_only.mjs");
    assert_eq!(outcome.module.record.syntax, ModuleSyntax::EsModule);
}

// -----------------------------------------------------------------------
// Section 9: External module resolution
// -----------------------------------------------------------------------

#[test]
fn external_resolution_preserves_provenance() {
    let mut r = DeterministicModuleResolver::new("/workspace");
    r.register_external_module(
        "left-pad",
        cjs("module.exports = function(){};").with_provenance("registry:npm:left-pad@1.3.0"),
    )
    .unwrap();

    let req = ModuleRequest::new("left-pad", ImportStyle::Require);
    let outcome = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap();
    assert_eq!(
        outcome.module.record.provenance.kind,
        ModuleSourceKind::ExternalRegistry
    );
    assert_eq!(
        outcome.module.record.provenance.origin,
        "registry:npm:left-pad@1.3.0"
    );
    assert_eq!(outcome.module.record.id, "external:left-pad");
}

#[test]
fn external_has_priority_over_workspace_for_bare_specifier() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_external_module("lodash", cjs("external"))
        .unwrap();
    r.register_workspace_module("/app/lodash.js", esm("workspace"))
        .unwrap();

    let req = ModuleRequest::new("lodash", ImportStyle::Import);
    let outcome = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap();
    assert_eq!(outcome.module.record.id, "external:lodash");
}

// -----------------------------------------------------------------------
// Section 10: Error paths — empty/missing specifiers
// -----------------------------------------------------------------------

#[test]
fn empty_specifier_returns_empty_specifier_error() {
    let r = DeterministicModuleResolver::default();
    let req = ModuleRequest::new("", ImportStyle::Import);
    let err = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap_err();
    assert_eq!(err.code, ResolutionErrorCode::EmptySpecifier);
    assert_eq!(err.code.stable_code(), "FE-MODRES-0001");
}

#[test]
fn whitespace_only_specifier_returns_empty_specifier_error() {
    let r = DeterministicModuleResolver::default();
    let req = ModuleRequest::new("   ", ImportStyle::Import);
    let err = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap_err();
    assert_eq!(err.code, ResolutionErrorCode::EmptySpecifier);
}

#[test]
fn relative_specifier_without_referrer_returns_invalid_referrer() {
    let r = DeterministicModuleResolver::default();
    let req = ModuleRequest::new("./dep", ImportStyle::Import);
    let err = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap_err();
    assert_eq!(err.code, ResolutionErrorCode::InvalidReferrer);
    assert_eq!(err.code.stable_code(), "FE-MODRES-0002");
}

#[test]
fn dotdot_relative_without_referrer_returns_invalid_referrer() {
    let r = DeterministicModuleResolver::default();
    let req = ModuleRequest::new("../dep", ImportStyle::Import);
    let err = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap_err();
    assert_eq!(err.code, ResolutionErrorCode::InvalidReferrer);
}

#[test]
fn relative_from_builtin_referrer_returns_unsupported() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_builtin("franken:fs", esm("export const read = true;"))
        .unwrap();

    let req = ModuleRequest::new("./sub", ImportStyle::Import).with_referrer("builtin:franken:fs");
    let err = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap_err();
    assert_eq!(err.code, ResolutionErrorCode::UnsupportedSpecifier);
    assert_eq!(err.code.stable_code(), "FE-MODRES-0003");
}

#[test]
fn relative_from_external_referrer_returns_unsupported() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_external_module("ext-mod", esm("export default 1;"))
        .unwrap();

    let req = ModuleRequest::new("./sub", ImportStyle::Import).with_referrer("external:ext-mod");
    let err = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap_err();
    assert_eq!(err.code, ResolutionErrorCode::UnsupportedSpecifier);
}

#[test]
fn unresolvable_bare_specifier_returns_module_not_found() {
    let r = DeterministicModuleResolver::new("/workspace");
    let req = ModuleRequest::new("nonexistent-package", ImportStyle::Import);
    let err = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap_err();
    assert_eq!(err.code, ResolutionErrorCode::ModuleNotFound);
    assert_eq!(err.code.stable_code(), "FE-MODRES-0004");
}

#[test]
fn unresolvable_relative_specifier_returns_module_not_found() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_workspace_module("/app/main.js", esm(""))
        .unwrap();

    let req = ModuleRequest::new("./missing", ImportStyle::Import).with_referrer("/app/main.js");
    let err = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap_err();
    assert_eq!(err.code, ResolutionErrorCode::ModuleNotFound);
}

#[test]
fn unresolvable_absolute_specifier_returns_module_not_found() {
    let r = DeterministicModuleResolver::new("/app");
    let req = ModuleRequest::new("/app/does_not_exist.js", ImportStyle::Import);
    let err = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap_err();
    assert_eq!(err.code, ResolutionErrorCode::ModuleNotFound);
}

// -----------------------------------------------------------------------
// Section 11: Policy — AllowAllPolicy
// -----------------------------------------------------------------------

#[test]
fn allow_all_policy_permits_any_capabilities() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_workspace_module(
        "/app/anything.js",
        esm("export default 1;")
            .require_capability(RuntimeCapability::FsWrite)
            .require_capability(RuntimeCapability::NetworkEgress),
    )
    .unwrap();

    let req = ModuleRequest::new("/app/anything.js", ImportStyle::Import);
    let outcome = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap();
    assert_eq!(outcome.event.outcome, "allow");
}

// -----------------------------------------------------------------------
// Section 12: Policy — CapabilityPolicyHook
// -----------------------------------------------------------------------

#[test]
fn capability_policy_denies_missing_capability() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_workspace_module(
        "/app/secure.js",
        cjs("module.exports = 7;").require_capability(RuntimeCapability::FsWrite),
    )
    .unwrap();

    let policy = grant(&[RuntimeCapability::FsRead]); // grant FsRead, not FsWrite
    let req = ModuleRequest::new("/app/secure.js", ImportStyle::Require);
    let err = r.resolve(&req, &ctx(), &policy).unwrap_err();
    assert_eq!(err.code, ResolutionErrorCode::PolicyDenied);
    assert_eq!(err.code.stable_code(), "FE-MODRES-0005");
    assert!(err.message.contains("fs_write"));
}

#[test]
fn capability_policy_grants_multiple_caps() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_workspace_module(
        "/app/multi.js",
        esm("export default 1;")
            .require_capability(RuntimeCapability::FsRead)
            .require_capability(RuntimeCapability::FsWrite),
    )
    .unwrap();

    let policy = grant(&[RuntimeCapability::FsRead, RuntimeCapability::FsWrite]);
    let req = ModuleRequest::new("/app/multi.js", ImportStyle::Import);
    let outcome = r.resolve(&req, &ctx(), &policy).unwrap();
    assert_eq!(outcome.event.outcome, "allow");
}

#[test]
fn capability_policy_deny_list_blocks_specifier() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_workspace_module("/app/blocked.js", esm("export default 1;"))
        .unwrap();

    let policy = CapabilityPolicyHook::new(BTreeSet::new()).deny_specifier("/app/blocked.js");
    let req = ModuleRequest::new("/app/blocked.js", ImportStyle::Import);
    let err = r.resolve(&req, &ctx(), &policy).unwrap_err();
    assert_eq!(err.code, ResolutionErrorCode::PolicyDenied);
}

#[test]
fn capability_policy_deny_list_blocks_by_module_id() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_builtin("franken:net", esm("export const net = true;"))
        .unwrap();

    // Deny by module id (builtin:franken:net), not specifier
    let policy = CapabilityPolicyHook::new(BTreeSet::new()).deny_specifier("builtin:franken:net");
    let req = ModuleRequest::new("franken:net", ImportStyle::Import);
    let err = r.resolve(&req, &ctx(), &policy).unwrap_err();
    assert_eq!(err.code, ResolutionErrorCode::PolicyDenied);
}

#[test]
fn capability_policy_multiple_deny_specifiers() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_workspace_module("/app/a.js", esm("a")).unwrap();
    r.register_workspace_module("/app/b.js", esm("b")).unwrap();

    let policy = CapabilityPolicyHook::new(BTreeSet::new())
        .deny_specifier("/app/a.js")
        .deny_specifier("/app/b.js");

    let req_a = ModuleRequest::new("/app/a.js", ImportStyle::Import);
    assert_eq!(
        r.resolve(&req_a, &ctx(), &policy).unwrap_err().code,
        ResolutionErrorCode::PolicyDenied
    );

    let req_b = ModuleRequest::new("/app/b.js", ImportStyle::Import);
    assert_eq!(
        r.resolve(&req_b, &ctx(), &policy).unwrap_err().code,
        ResolutionErrorCode::PolicyDenied
    );
}

// -----------------------------------------------------------------------
// Section 13: ResolutionErrorCode stable codes
// -----------------------------------------------------------------------

#[test]
fn all_error_codes_have_fe_modres_prefix() {
    let codes = [
        ResolutionErrorCode::EmptySpecifier,
        ResolutionErrorCode::InvalidReferrer,
        ResolutionErrorCode::UnsupportedSpecifier,
        ResolutionErrorCode::ModuleNotFound,
        ResolutionErrorCode::PolicyDenied,
    ];
    for code in &codes {
        assert!(
            code.stable_code().starts_with("FE-MODRES-"),
            "stable_code {} should start with FE-MODRES-",
            code.stable_code()
        );
    }
}

#[test]
fn error_codes_are_unique() {
    let codes = [
        ResolutionErrorCode::EmptySpecifier.stable_code(),
        ResolutionErrorCode::InvalidReferrer.stable_code(),
        ResolutionErrorCode::UnsupportedSpecifier.stable_code(),
        ResolutionErrorCode::ModuleNotFound.stable_code(),
        ResolutionErrorCode::PolicyDenied.stable_code(),
    ];
    let unique: BTreeSet<&str> = codes.iter().copied().collect();
    assert_eq!(unique.len(), codes.len());
}

// -----------------------------------------------------------------------
// Section 14: ResolutionError Display and Error trait
// -----------------------------------------------------------------------

#[test]
fn resolution_error_display_includes_stable_code_and_trace() {
    let r = DeterministicModuleResolver::default();
    let req = ModuleRequest::new("", ImportStyle::Import);
    let err = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap_err();
    let display = format!("{err}");
    assert!(display.contains("FE-MODRES-0001"));
    assert!(display.contains("trace-int"));
    assert!(display.contains("decision-int"));
    assert!(display.contains("policy-int"));
}

#[test]
fn resolution_error_event_has_deny_outcome() {
    let r = DeterministicModuleResolver::default();
    let req = ModuleRequest::new("", ImportStyle::Import);
    let err = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap_err();
    assert_eq!(err.event.outcome, "deny");
    assert_eq!(err.event.component, "module_resolver");
    assert_eq!(err.event.event, "module_resolution");
}

#[test]
fn resolution_error_implements_std_error() {
    let r = DeterministicModuleResolver::default();
    let req = ModuleRequest::new("", ImportStyle::Import);
    let err = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap_err();
    let e: Box<dyn std::error::Error> = err;
    assert!(!e.to_string().is_empty());
}

#[test]
fn registry_error_display_contains_code_and_message() {
    let mut r = DeterministicModuleResolver::new("/app");
    let err = r.register_builtin("", esm("")).unwrap_err();
    let display = format!("{err}");
    assert!(display.contains("EmptyKey"));
    assert!(display.contains("must not be empty"));
}

#[test]
fn registry_error_implements_std_error() {
    let mut r = DeterministicModuleResolver::new("/app");
    let err = r.register_builtin("", esm("")).unwrap_err();
    let e: Box<dyn std::error::Error> = Box::new(err);
    assert!(!e.to_string().is_empty());
}

// -----------------------------------------------------------------------
// Section 15: resolve_chain
// -----------------------------------------------------------------------

#[test]
fn resolve_chain_traverses_dependencies() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_workspace_module(
        "/app/entry.js",
        esm("import './dep';").with_dependency(ModuleDependency::new("./dep", ImportStyle::Import)),
    )
    .unwrap();
    r.register_workspace_module("/app/dep.js", esm("export default 1;"))
        .unwrap();

    let req = ModuleRequest::new("/app/entry.js", ImportStyle::Import);
    let chain = r.resolve_chain(&req, &ctx(), &AllowAllPolicy).unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].module.canonical_specifier, "/app/entry.js");
    assert_eq!(chain[1].module.canonical_specifier, "/app/dep.js");
}

#[test]
fn resolve_chain_handles_circular_dependencies() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_workspace_module(
        "/app/a.js",
        esm("import './b';").with_dependency(ModuleDependency::new("./b", ImportStyle::Import)),
    )
    .unwrap();
    r.register_workspace_module(
        "/app/b.js",
        esm("import './a';").with_dependency(ModuleDependency::new("./a", ImportStyle::Import)),
    )
    .unwrap();

    let req = ModuleRequest::new("/app/a.js", ImportStyle::Import);
    let chain = r.resolve_chain(&req, &ctx(), &AllowAllPolicy).unwrap();
    assert_eq!(chain.len(), 2);
}

#[test]
fn resolve_chain_single_module_no_deps() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_workspace_module("/app/leaf.js", esm("export const x = 1;"))
        .unwrap();

    let req = ModuleRequest::new("/app/leaf.js", ImportStyle::Import);
    let chain = r.resolve_chain(&req, &ctx(), &AllowAllPolicy).unwrap();
    assert_eq!(chain.len(), 1);
}

#[test]
fn resolve_chain_fails_on_policy_denial() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_workspace_module(
        "/app/restricted.js",
        esm("export default 1;").require_capability(RuntimeCapability::FsWrite),
    )
    .unwrap();

    let policy = CapabilityPolicyHook::new(BTreeSet::new());
    let req = ModuleRequest::new("/app/restricted.js", ImportStyle::Import);
    let err = r.resolve_chain(&req, &ctx(), &policy).unwrap_err();
    assert_eq!(err.code, ResolutionErrorCode::PolicyDenied);
}

#[test]
fn resolve_chain_diamond_dependency() {
    // entry -> a, entry -> b, a -> shared, b -> shared
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_workspace_module(
        "/app/entry.js",
        esm("")
            .with_dependency(ModuleDependency::new("./a", ImportStyle::Import))
            .with_dependency(ModuleDependency::new("./b", ImportStyle::Import)),
    )
    .unwrap();
    r.register_workspace_module(
        "/app/a.js",
        esm("").with_dependency(ModuleDependency::new("./shared", ImportStyle::Import)),
    )
    .unwrap();
    r.register_workspace_module(
        "/app/b.js",
        esm("").with_dependency(ModuleDependency::new("./shared", ImportStyle::Import)),
    )
    .unwrap();
    r.register_workspace_module("/app/shared.js", esm(""))
        .unwrap();

    let req = ModuleRequest::new("/app/entry.js", ImportStyle::Import);
    let chain = r.resolve_chain(&req, &ctx(), &AllowAllPolicy).unwrap();
    // entry + a + b + shared = 4, shared deduplicated
    assert_eq!(chain.len(), 4);
    // Verify no duplicate IDs
    let ids: BTreeSet<String> = chain.iter().map(|o| o.module.record.id.clone()).collect();
    assert_eq!(ids.len(), 4);
}

#[test]
fn resolve_chain_deep_linear() {
    let mut r = DeterministicModuleResolver::new("/app");
    // Chain: entry -> a -> b -> c
    r.register_workspace_module(
        "/app/entry.js",
        esm("").with_dependency(ModuleDependency::new("./a", ImportStyle::Import)),
    )
    .unwrap();
    r.register_workspace_module(
        "/app/a.js",
        esm("").with_dependency(ModuleDependency::new("./b", ImportStyle::Import)),
    )
    .unwrap();
    r.register_workspace_module(
        "/app/b.js",
        esm("").with_dependency(ModuleDependency::new("./c", ImportStyle::Import)),
    )
    .unwrap();
    r.register_workspace_module("/app/c.js", esm("leaf"))
        .unwrap();

    let req = ModuleRequest::new("/app/entry.js", ImportStyle::Import);
    let chain = r.resolve_chain(&req, &ctx(), &AllowAllPolicy).unwrap();
    assert_eq!(chain.len(), 4);
    assert_eq!(chain[3].module.record.source, "leaf");
}

// -----------------------------------------------------------------------
// Section 16: ModuleRecord canonical_value / canonical_bytes / canonical_hash
// -----------------------------------------------------------------------

#[test]
fn canonical_hash_determinism() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_workspace_module(
        "/app/det.js",
        esm("export default 1;").with_provenance("workspace:/app/det.js"),
    )
    .unwrap();

    let req = ModuleRequest::new("/app/det.js", ImportStyle::Import);
    let o1 = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap();
    let o2 = r.resolve(&req, &ctx(), &AllowAllPolicy).unwrap();
    assert_eq!(o1.module.content_hash, o2.module.content_hash);
    assert_eq!(
        o1.module.record.canonical_bytes(),
        o2.module.record.canonical_bytes()
    );
}

#[test]
fn different_sources_yield_different_hashes() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_workspace_module("/app/a.js", esm("source A"))
        .unwrap();
    r.register_workspace_module("/app/b.js", esm("source B"))
        .unwrap();

    let req_a = ModuleRequest::new("/app/a.js", ImportStyle::Import);
    let req_b = ModuleRequest::new("/app/b.js", ImportStyle::Import);
    let h_a = r
        .resolve(&req_a, &ctx(), &AllowAllPolicy)
        .unwrap()
        .module
        .content_hash;
    let h_b = r
        .resolve(&req_b, &ctx(), &AllowAllPolicy)
        .unwrap()
        .module
        .content_hash;
    assert_ne!(h_a, h_b);
}

// -----------------------------------------------------------------------
// Section 17: Serde round-trips
// -----------------------------------------------------------------------

#[test]
fn module_syntax_serde_round_trip() {
    for syntax in &[ModuleSyntax::EsModule, ModuleSyntax::CommonJs] {
        let json = serde_json::to_string(syntax).unwrap();
        let decoded: ModuleSyntax = serde_json::from_str(&json).unwrap();
        assert_eq!(&decoded, syntax);
    }
}

#[test]
fn import_style_serde_round_trip() {
    for style in &[ImportStyle::Import, ImportStyle::Require] {
        let json = serde_json::to_string(style).unwrap();
        let decoded: ImportStyle = serde_json::from_str(&json).unwrap();
        assert_eq!(&decoded, style);
    }
}

#[test]
fn module_source_kind_serde_round_trip() {
    for kind in [
        ModuleSourceKind::BuiltIn,
        ModuleSourceKind::Workspace,
        ModuleSourceKind::ExternalRegistry,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let decoded: ModuleSourceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, decoded);
    }
}

#[test]
fn resolution_error_code_serde_round_trip() {
    let codes = [
        ResolutionErrorCode::EmptySpecifier,
        ResolutionErrorCode::InvalidReferrer,
        ResolutionErrorCode::UnsupportedSpecifier,
        ResolutionErrorCode::ModuleNotFound,
        ResolutionErrorCode::PolicyDenied,
    ];
    for code in &codes {
        let json = serde_json::to_string(code).unwrap();
        let decoded: ResolutionErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(&decoded, code);
    }
}

#[test]
fn registry_error_code_serde_round_trip() {
    let code = RegistryErrorCode::EmptyKey;
    let json = serde_json::to_string(&code).unwrap();
    let decoded: RegistryErrorCode = serde_json::from_str(&json).unwrap();
    assert_eq!(code, decoded);
}

#[test]
fn module_provenance_serde_round_trip() {
    let mp = ModuleProvenance {
        kind: ModuleSourceKind::ExternalRegistry,
        origin: "npm:lodash@4.17.21".to_string(),
    };
    let json = serde_json::to_string(&mp).unwrap();
    let restored: ModuleProvenance = serde_json::from_str(&json).unwrap();
    assert_eq!(mp, restored);
}

#[test]
fn module_dependency_serde_round_trip() {
    let md = ModuleDependency::new("./utils.js", ImportStyle::Import);
    let json = serde_json::to_string(&md).unwrap();
    let restored: ModuleDependency = serde_json::from_str(&json).unwrap();
    assert_eq!(md, restored);
}

#[test]
fn module_request_serde_round_trip() {
    let mr = ModuleRequest::new("franken:core", ImportStyle::Import)
        .with_referrer("/app/main.js")
        .with_compatibility_mode(CompatibilityMode::BunCompat);
    let json = serde_json::to_string(&mr).unwrap();
    let restored: ModuleRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(mr, restored);
    assert_eq!(restored.compatibility_mode, CompatibilityMode::BunCompat);
}

#[test]
fn module_request_legacy_json_defaults_to_native_compat_mode() {
    let restored: ModuleRequest =
        serde_json::from_str(r#"{"specifier":"pkg","referrer":"/app/main.js","style":"require"}"#)
            .unwrap();
    assert_eq!(restored.compatibility_mode, CompatibilityMode::Native);
}

#[test]
fn resolution_context_serde_round_trip() {
    let ctx = ResolutionContext::new("t1", "d1", "p1");
    let json = serde_json::to_string(&ctx).unwrap();
    let restored: ResolutionContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, restored);
}

#[test]
fn allow_all_policy_serde_round_trip() {
    let p = AllowAllPolicy;
    let json = serde_json::to_string(&p).unwrap();
    let restored: AllowAllPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, restored);
}

#[test]
fn capability_policy_hook_serde_round_trip() {
    let policy = grant(&[RuntimeCapability::FsRead, RuntimeCapability::NetworkEgress])
        .deny_specifier("evil-module")
        .deny_specifier("also-evil");
    let json = serde_json::to_string(&policy).unwrap();
    let restored: CapabilityPolicyHook = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, restored);
}

#[test]
fn deterministic_module_resolver_serde_round_trip() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_builtin("franken:fs", esm("export const read = true;"))
        .unwrap();
    r.register_workspace_module("/app/lib.js", esm("export default 1;"))
        .unwrap();
    r.register_external_module("lodash", cjs("module.exports = {};"))
        .unwrap();

    let json = serde_json::to_string(&r).unwrap();
    let restored: DeterministicModuleResolver = serde_json::from_str(&json).unwrap();
    assert_eq!(r, restored);

    // Verify resolution still works after round-trip
    let req = ModuleRequest::new("franken:fs", ImportStyle::Import);
    let outcome = restored.resolve(&req, &ctx(), &AllowAllPolicy).unwrap();
    assert_eq!(outcome.module.record.id, "builtin:franken:fs");
}

#[test]
fn resolution_event_serde_round_trip() {
    let event = ResolutionEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "module_resolver".to_string(),
        event: "module_resolution".to_string(),
        outcome: "allow".to_string(),
        error_code: "none".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: ResolutionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn registry_error_serde_round_trip() {
    let err = RegistryError {
        code: RegistryErrorCode::EmptyKey,
        message: "key must not be empty".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: RegistryError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

// -----------------------------------------------------------------------
// Section 18: End-to-end scenario — mixed module types with chain
// -----------------------------------------------------------------------

#[test]
fn end_to_end_mixed_module_chain() {
    let mut r = DeterministicModuleResolver::new("/project");

    // Builtin
    r.register_builtin(
        "franken:path",
        esm("export function join() {}").with_provenance("builtin:franken:path"),
    )
    .unwrap();

    // Workspace entry that depends on builtin and an external
    r.register_workspace_module(
        "/project/src/main.js",
        esm("import 'franken:path'; import 'express';")
            .with_dependency(ModuleDependency::new("franken:path", ImportStyle::Import))
            .with_dependency(ModuleDependency::new("express", ImportStyle::Require))
            .with_provenance("workspace:/project/src/main.js"),
    )
    .unwrap();

    // External
    r.register_external_module(
        "express",
        cjs("module.exports = {};").with_provenance("npm:express@4.18.0"),
    )
    .unwrap();

    let req = ModuleRequest::new("/project/src/main.js", ImportStyle::Import);
    let chain = r.resolve_chain(&req, &ctx(), &AllowAllPolicy).unwrap();

    assert_eq!(chain.len(), 3);
    // Verify all three provenance kinds present
    let kinds: BTreeSet<ModuleSourceKind> = chain
        .iter()
        .map(|o| o.module.record.provenance.kind)
        .collect();
    assert!(kinds.contains(&ModuleSourceKind::Workspace));
    assert!(kinds.contains(&ModuleSourceKind::BuiltIn));
    assert!(kinds.contains(&ModuleSourceKind::ExternalRegistry));
}

#[test]
fn resolve_with_custom_context_propagates_ids() {
    let mut r = DeterministicModuleResolver::new("/app");
    r.register_workspace_module("/app/x.js", esm("")).unwrap();

    let custom_ctx = ctx_named("trace-42", "decision-99", "policy-alpha");
    let req = ModuleRequest::new("/app/x.js", ImportStyle::Import);
    let outcome = r.resolve(&req, &custom_ctx, &AllowAllPolicy).unwrap();
    assert_eq!(outcome.event.trace_id, "trace-42");
    assert_eq!(outcome.event.decision_id, "decision-99");
    assert_eq!(outcome.event.policy_id, "policy-alpha");
}

#[test]
fn error_context_propagates_ids() {
    let r = DeterministicModuleResolver::default();
    let custom_ctx = ctx_named("trace-err", "decision-err", "policy-err");
    let req = ModuleRequest::new("missing", ImportStyle::Import);
    let err = r.resolve(&req, &custom_ctx, &AllowAllPolicy).unwrap_err();
    assert_eq!(err.trace_id, "trace-err");
    assert_eq!(err.decision_id, "decision-err");
    assert_eq!(err.policy_id, "policy-err");
}

// -----------------------------------------------------------------------
// Section 19: Capability-safe host API surface (RGC-403)
// -----------------------------------------------------------------------

#[test]
fn host_api_surface_emits_deterministic_allow_and_deny_telemetry() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let policy = grant(&[RuntimeCapability::FsRead]);

    let harness_ctx = DeterministicTestContext::new(
        "rgc-403-host-api-surface",
        "host-api-surface-fixture",
        HarnessLane::Security,
        403,
    );
    let resolver_ctx = ResolutionContext::new(
        harness_ctx.trace_id.clone(),
        harness_ctx.decision_id.clone(),
        harness_ctx.policy_id.clone(),
    );

    let allow = surface
        .authorize(
            &HostApiRequest::new("node:fs", "read_file"),
            &resolver_ctx,
            &policy,
        )
        .expect("fs read should be allowed");
    let deny = surface
        .authorize(
            &HostApiRequest::new("node:process", "spawn"),
            &resolver_ctx,
            &policy,
        )
        .expect_err("process spawn should fail without process capability");

    assert_eq!(allow.event.outcome, "allow");
    assert_eq!(allow.event.error_code, "none");
    assert_eq!(deny.event.outcome, "deny");
    assert_eq!(deny.event.error_code, "FE-HOSTAPI-0003");
    assert!(allow.event.decision_stable_id.starts_with("hostapi-dec-"));
    assert!(deny.event.decision_stable_id.starts_with("hostapi-dec-"));
    assert_ne!(
        allow.event.decision_stable_id,
        deny.event.decision_stable_id
    );

    let events = vec![
        harness_ctx.event(EventInput {
            sequence: 1,
            component: "host_api_surface",
            event: "host_api_authorization",
            outcome: "allow",
            error_code: None,
            timing_us: 11,
            timestamp_unix_ms: 1_700_000_000_001,
        }),
        harness_ctx.event(EventInput {
            sequence: 2,
            component: "host_api_surface",
            event: "host_api_authorization",
            outcome: "deny",
            error_code: Some("FE-HOSTAPI-0003"),
            timing_us: 17,
            timestamp_unix_ms: 1_700_000_000_002,
        }),
    ];
    let commands = vec![
        format!(
            "authorize {} {} decision_stable_id={}",
            allow.event.module_specifier, allow.event.operation, allow.event.decision_stable_id
        ),
        format!(
            "authorize {} {} error_code={} decision_stable_id={}",
            deny.event.module_specifier,
            deny.event.operation,
            deny.event.error_code,
            deny.event.decision_stable_id
        ),
    ];

    let run_id = harness_ctx.default_run_id();
    let manifest = HarnessRunManifest::from_context(
        &harness_ctx,
        &run_id,
        events.len(),
        commands.len(),
        "./scripts/e2e/rgc_runtime_semantics_verification_pack_replay.sh ci",
        1_700_000_000_099,
    );

    let artifact_root = std::env::temp_dir().join(format!(
        "module_resolver_host_api_surface_{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&artifact_root);
    let triad = write_artifact_triad(&artifact_root, &manifest, &events, &commands)
        .expect("artifact triad should be written");
    assert!(triad.manifest_path.exists());
    assert!(triad.events_path.exists());
    assert!(triad.commands_path.exists());

    let commands_text = fs::read_to_string(&triad.commands_path).expect("read commands");
    assert!(commands_text.contains(&allow.event.decision_stable_id));
    assert!(commands_text.contains(&deny.event.decision_stable_id));
    assert!(commands_text.contains("error_code=FE-HOSTAPI-0003"));

    let events_text = fs::read_to_string(&triad.events_path).expect("read events");
    assert!(events_text.contains("\"event\":\"host_api_authorization\""));
    assert!(events_text.contains("\"error_code\":\"FE-HOSTAPI-0003\""));

    let _ = fs::remove_dir_all(&artifact_root);
}

#[test]
fn host_api_surface_fail_closed_for_unsupported_node_like_requests() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let policy = grant(&[
        RuntimeCapability::FsRead,
        RuntimeCapability::FsWrite,
        RuntimeCapability::NetworkEgress,
        RuntimeCapability::ProcessSpawn,
        RuntimeCapability::IdempotencyDerive,
    ]);

    let err = surface
        .authorize(
            &HostApiRequest::new("node:fs/../../net", "connect"),
            &ctx(),
            &policy,
        )
        .expect_err("unknown module form must deny");
    assert_eq!(err.code, HostApiErrorCode::UnsupportedModule);
    assert_eq!(err.event.error_code, "FE-HOSTAPI-0001");
    assert!(err.event.remediation.contains("node:net"));

    let err = surface
        .authorize(
            &HostApiRequest::new("node:crypto", "rm -rf"),
            &ctx(),
            &policy,
        )
        .expect_err("unsupported operation must deny");
    assert_eq!(err.code, HostApiErrorCode::UnsupportedOperation);
    assert_eq!(err.event.error_code, "FE-HOSTAPI-0002");
    assert!(err.event.remediation.contains("register a new descriptor"));
}
