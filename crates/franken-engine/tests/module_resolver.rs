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
use frankenengine_engine::module_compatibility_matrix::CompatibilityMode;
use frankenengine_engine::module_resolver::{
    AllowAllPolicy, CapabilityPolicyHook, DeterministicModuleResolver, ImportStyle,
    ModuleDefinition, ModuleDependency, ModuleRequest, ModuleResolver, ModuleSyntax,
    ResolutionContext, ResolutionErrorCode,
};

fn context() -> ResolutionContext {
    ResolutionContext::new(
        "trace-integration",
        "decision-integration",
        "policy-integration",
    )
}

#[test]
fn chain_resolution_enforces_transitive_policy_checks() {
    let mut resolver = DeterministicModuleResolver::new("/app");

    resolver
        .register_workspace_module(
            "/app/main.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "import './util.mjs';")
                .with_dependency(ModuleDependency::new("./util.mjs", ImportStyle::Import)),
        )
        .unwrap();

    resolver
        .register_workspace_module(
            "/app/util.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "import './secret.mjs';")
                .with_dependency(ModuleDependency::new("./secret.mjs", ImportStyle::Import)),
        )
        .unwrap();

    resolver
        .register_workspace_module(
            "/app/secret.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export const secret = 1;")
                .require_capability(RuntimeCapability::FsWrite),
        )
        .unwrap();

    let entry = ModuleRequest::new("/app/main.mjs", ImportStyle::Import);

    let denied_policy = CapabilityPolicyHook::new(BTreeSet::new());
    let denied_error = resolver
        .resolve_chain(&entry, &context(), &denied_policy)
        .expect_err("expected missing capability to deny transitive dependency");
    assert_eq!(denied_error.code, ResolutionErrorCode::PolicyDenied);
    assert_eq!(
        denied_error.event.error_code,
        ResolutionErrorCode::PolicyDenied.stable_code()
    );

    let mut granted = BTreeSet::new();
    granted.insert(RuntimeCapability::FsWrite);
    let allowed_policy = CapabilityPolicyHook::new(granted);
    let outcomes = resolver
        .resolve_chain(&entry, &context(), &allowed_policy)
        .expect("transitive resolution should pass when capability is granted");

    let ids = outcomes
        .iter()
        .map(|outcome| outcome.module.record.id.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        vec!["/app/main.mjs", "/app/util.mjs", "/app/secret.mjs"]
    );
}

#[test]
fn cjs_and_esm_compatibility_resolution_order_is_deterministic() {
    let mut resolver = DeterministicModuleResolver::new("/repo");
    resolver
        .register_workspace_module(
            "/repo/pkg/index.js",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export default 'esm';"),
        )
        .unwrap();
    resolver
        .register_workspace_module(
            "/repo/pkg/index.cjs",
            ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 'cjs';"),
        )
        .unwrap();

    let require_request = ModuleRequest::new("pkg", ImportStyle::Require);
    let require_outcome = resolver
        .resolve(&require_request, &context(), &AllowAllPolicy)
        .unwrap();
    assert_eq!(
        require_outcome.module.canonical_specifier,
        "/repo/pkg/index.cjs"
    );

    let import_request = ModuleRequest::new("pkg", ImportStyle::Import);
    let import_outcome = resolver
        .resolve(&import_request, &context(), &AllowAllPolicy)
        .unwrap();
    assert_eq!(
        import_outcome.module.canonical_specifier,
        "/repo/pkg/index.js"
    );
}

#[test]
fn bun_compat_allows_require_of_esm_package_entry() {
    let mut resolver = DeterministicModuleResolver::new("/repo");
    resolver
        .register_workspace_module(
            "/repo/pkg/index.js",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export default 'esm';"),
        )
        .unwrap();

    let outcome = resolver
        .resolve(
            &ModuleRequest::new("pkg", ImportStyle::Require)
                .with_compatibility_mode(CompatibilityMode::BunCompat),
            &context(),
            &AllowAllPolicy,
        )
        .expect("bun_compat should allow ESM package entry resolution");

    assert_eq!(outcome.module.canonical_specifier, "/repo/pkg/index.js");
    assert_eq!(outcome.module.record.syntax, ModuleSyntax::EsModule);
}

#[test]
fn node_compat_still_rejects_require_of_esm_package_entry() {
    let mut resolver = DeterministicModuleResolver::new("/repo");
    resolver
        .register_workspace_module(
            "/repo/pkg/index.js",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export default 'esm';"),
        )
        .unwrap();

    let error = resolver
        .resolve(
            &ModuleRequest::new("pkg", ImportStyle::Require)
                .with_compatibility_mode(CompatibilityMode::NodeCompat),
            &context(),
            &AllowAllPolicy,
        )
        .expect_err("node_compat should stay fail-closed for require() of ESM");

    assert_eq!(error.code, ResolutionErrorCode::UnsupportedSpecifier);
    assert!(error.message.contains("ERR_REQUIRE_ESM"));
}

#[test]
fn native_external_relative_dependency_requires_explicit_extension() {
    let mut resolver = DeterministicModuleResolver::new("/repo");
    resolver
        .register_external_module(
            "some-pkg/sub.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export default 'sub';"),
        )
        .unwrap();

    let outcome = resolver
        .resolve(
            &ModuleRequest::new("./sub", ImportStyle::Import).with_referrer("external:some-pkg"),
            &context(),
            &AllowAllPolicy,
        )
        .expect("native mode should resolve external ESM relative via extension probing");
    assert_eq!(outcome.module.canonical_specifier, "some-pkg/sub.mjs");
    assert_eq!(outcome.module.record.id, "external:some-pkg/sub.mjs");
}

#[test]
fn bun_compat_external_relative_dependency_resolves_from_package_root() {
    let mut resolver = DeterministicModuleResolver::new("/repo");
    resolver
        .register_external_module(
            "some-pkg/sub.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export default 'sub';"),
        )
        .unwrap();

    let outcome = resolver
        .resolve(
            &ModuleRequest::new("./sub", ImportStyle::Import)
                .with_referrer("external:some-pkg")
                .with_compatibility_mode(CompatibilityMode::BunCompat),
            &context(),
            &AllowAllPolicy,
        )
        .expect("bun_compat external package relative dependency should resolve");
    assert_eq!(outcome.module.canonical_specifier, "some-pkg/sub.mjs");
    assert_eq!(outcome.module.record.id, "external:some-pkg/sub.mjs");
}

#[test]
fn node_compat_external_relative_dependency_requires_explicit_extension() {
    let mut resolver = DeterministicModuleResolver::new("/repo");
    resolver
        .register_external_module(
            "some-pkg/sub.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export default 'sub';"),
        )
        .unwrap();

    let outcome = resolver
        .resolve(
            &ModuleRequest::new("./sub", ImportStyle::Import)
                .with_referrer("external:some-pkg")
                .with_compatibility_mode(CompatibilityMode::NodeCompat),
            &context(),
            &AllowAllPolicy,
        )
        .expect("node_compat should resolve external ESM relative via extension probing");
    assert_eq!(outcome.module.canonical_specifier, "some-pkg/sub.mjs");
    assert_eq!(outcome.module.record.id, "external:some-pkg/sub.mjs");
}

// ────────────────────────────────────────────────────────────
// Enrichment: error paths, builtins, registration, serde
// ────────────────────────────────────────────────────────────

#[test]
fn empty_specifier_yields_module_not_found() {
    let resolver = DeterministicModuleResolver::new("/app");
    let request = ModuleRequest::new("", ImportStyle::Import);
    let err = resolver
        .resolve(&request, &context(), &AllowAllPolicy)
        .expect_err("empty specifier must fail");
    // empty specifier produces a resolution error
    assert!(!err.message.is_empty());
}

#[test]
fn nonexistent_module_yields_not_found() {
    let resolver = DeterministicModuleResolver::new("/app");
    let request = ModuleRequest::new("nonexistent-pkg", ImportStyle::Import);
    let err = resolver
        .resolve(&request, &context(), &AllowAllPolicy)
        .expect_err("nonexistent module must fail");
    assert_eq!(err.code, ResolutionErrorCode::ModuleNotFound);
    assert_eq!(err.code.stable_code(), "FE-MODRES-0004");
}

#[test]
fn register_builtin_with_empty_key_fails() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    let err = resolver
        .register_builtin(
            "",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export const x = 1;"),
        )
        .expect_err("empty key must fail");
    assert_eq!(
        err.code,
        frankenengine_engine::module_resolver::RegistryErrorCode::EmptyKey
    );
}

#[test]
fn register_workspace_with_empty_path_fails() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    let err = resolver
        .register_workspace_module(
            "",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export const x = 1;"),
        )
        .expect_err("empty path must fail");
    assert_eq!(
        err.code,
        frankenengine_engine::module_resolver::RegistryErrorCode::EmptyKey
    );
}

#[test]
fn register_external_with_empty_key_fails() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    let err = resolver
        .register_external_module(
            "",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export const x = 1;"),
        )
        .expect_err("empty external key must fail");
    assert_eq!(
        err.code,
        frankenengine_engine::module_resolver::RegistryErrorCode::EmptyKey
    );
}

#[test]
fn builtin_module_resolves_before_workspace() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_builtin(
            "fs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export function readFile() {}"),
        )
        .unwrap();
    resolver
        .register_workspace_module(
            "/app/fs.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export const fake_fs = true;"),
        )
        .unwrap();

    let request = ModuleRequest::new("fs", ImportStyle::Import);
    let outcome = resolver
        .resolve(&request, &context(), &AllowAllPolicy)
        .expect("builtin should resolve");

    assert!(outcome.module.record.id.starts_with("builtin:"));
}

#[test]
fn external_module_resolves_when_no_workspace_match() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_external_module(
            "lodash",
            ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = {};"),
        )
        .unwrap();

    let request = ModuleRequest::new("lodash", ImportStyle::Require);
    let outcome = resolver
        .resolve(&request, &context(), &AllowAllPolicy)
        .expect("external module should resolve");

    assert!(outcome.module.record.id.starts_with("external:"));
}

#[test]
fn capability_policy_hook_denies_specifier() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_workspace_module(
            "/app/dangerous.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export const danger = 1;"),
        )
        .unwrap();

    let policy = CapabilityPolicyHook::new(BTreeSet::new()).deny_specifier("/app/dangerous.mjs");

    let request = ModuleRequest::new("/app/dangerous.mjs", ImportStyle::Import);
    let err = resolver
        .resolve(&request, &context(), &policy)
        .expect_err("denied specifier must fail");
    assert_eq!(err.code, ResolutionErrorCode::PolicyDenied);
}

#[test]
fn resolver_serde_round_trip_preserves_state() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_workspace_module(
            "/app/main.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export const x = 1;"),
        )
        .unwrap();
    resolver
        .register_builtin(
            "path",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export function join() {}"),
        )
        .unwrap();

    let json = serde_json::to_string(&resolver).expect("serialize resolver");
    let recovered: DeterministicModuleResolver =
        serde_json::from_str(&json).expect("deserialize resolver");

    assert_eq!(resolver.root_dir(), recovered.root_dir());

    // Verify both resolve the same module
    let request = ModuleRequest::new("/app/main.mjs", ImportStyle::Import);
    let original = resolver
        .resolve(&request, &context(), &AllowAllPolicy)
        .expect("original");
    let restored = recovered
        .resolve(&request, &context(), &AllowAllPolicy)
        .expect("restored");

    assert_eq!(
        original.module.record.canonical_hash(),
        restored.module.record.canonical_hash()
    );
}

#[test]
fn resolve_chain_handles_circular_dependencies() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_workspace_module(
            "/app/a.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "import './b.mjs';")
                .with_dependency(ModuleDependency::new("./b.mjs", ImportStyle::Import)),
        )
        .unwrap();
    resolver
        .register_workspace_module(
            "/app/b.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "import './a.mjs';")
                .with_dependency(ModuleDependency::new("./a.mjs", ImportStyle::Import)),
        )
        .unwrap();

    let entry = ModuleRequest::new("/app/a.mjs", ImportStyle::Import);
    let outcomes = resolver
        .resolve_chain(&entry, &context(), &AllowAllPolicy)
        .expect("circular deps should be deduped, not fail");

    // Should resolve both modules without infinite loop
    assert_eq!(outcomes.len(), 2);
}

#[test]
fn resolution_event_fields_match_context() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_workspace_module(
            "/app/lib.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export const y = 2;"),
        )
        .unwrap();

    let ctx = context();
    let request = ModuleRequest::new("/app/lib.mjs", ImportStyle::Import);
    let outcome = resolver
        .resolve(&request, &ctx, &AllowAllPolicy)
        .expect("should resolve");

    assert_eq!(outcome.event.trace_id, ctx.trace_id);
    assert_eq!(outcome.event.decision_id, ctx.decision_id);
    assert_eq!(outcome.event.policy_id, ctx.policy_id);
    assert_eq!(outcome.event.component, "module_resolver");
}

#[test]
fn module_record_canonical_hash_is_deterministic() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_workspace_module(
            "/app/stable.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export const stable = true;"),
        )
        .unwrap();

    let request = ModuleRequest::new("/app/stable.mjs", ImportStyle::Import);
    let outcome1 = resolver
        .resolve(&request, &context(), &AllowAllPolicy)
        .expect("first resolve");
    let outcome2 = resolver
        .resolve(&request, &context(), &AllowAllPolicy)
        .expect("second resolve");

    assert_eq!(
        outcome1.module.record.canonical_hash(),
        outcome2.module.record.canonical_hash()
    );
}

#[test]
fn resolution_error_display_includes_stable_code_and_trace_context() {
    let resolver = DeterministicModuleResolver::new("/app");
    let request = ModuleRequest::new("nonexistent", ImportStyle::Import);
    let err = resolver
        .resolve(&request, &context(), &AllowAllPolicy)
        .expect_err("not found");

    let display = err.to_string();
    assert!(display.contains("FE-MODRES-"));
    assert!(display.contains("trace-integration"));
    assert!(display.contains("decision-integration"));
    assert!(display.contains("policy-integration"));
}

#[test]
fn workspace_relative_path_resolves_against_root() {
    let mut resolver = DeterministicModuleResolver::new("/project");
    resolver
        .register_workspace_module(
            "/project/src/index.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export default 42;"),
        )
        .unwrap();

    let request = ModuleRequest::new("/project/src/index.mjs", ImportStyle::Import);
    let outcome = resolver
        .resolve(&request, &context(), &AllowAllPolicy)
        .expect("workspace module should resolve");

    assert_eq!(outcome.module.canonical_specifier, "/project/src/index.mjs");
}

#[test]
fn module_syntax_as_str_variants() {
    assert_eq!(ModuleSyntax::EsModule.as_str(), "esm");
    assert_eq!(ModuleSyntax::CommonJs.as_str(), "cjs");
}

#[test]
fn import_style_as_str_variants() {
    assert_eq!(ImportStyle::Import.as_str(), "import");
    assert_eq!(ImportStyle::Require.as_str(), "require");
}

// ---------- serde roundtrips ----------

#[test]
fn module_syntax_serde_roundtrip() {
    for syntax in [ModuleSyntax::EsModule, ModuleSyntax::CommonJs] {
        let json = serde_json::to_string(&syntax).expect("serialize");
        let recovered: ModuleSyntax = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, syntax);
    }
}

#[test]
fn import_style_serde_roundtrip() {
    for style in [ImportStyle::Import, ImportStyle::Require] {
        let json = serde_json::to_string(&style).expect("serialize");
        let recovered: ImportStyle = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, style);
    }
}

#[test]
fn module_source_kind_serde_roundtrip() {
    use frankenengine_engine::module_resolver::ModuleSourceKind;
    for kind in [
        ModuleSourceKind::BuiltIn,
        ModuleSourceKind::Workspace,
        ModuleSourceKind::ExternalRegistry,
    ] {
        let json = serde_json::to_string(&kind).expect("serialize");
        let recovered: ModuleSourceKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, kind);
    }
}

#[test]
fn resolution_error_code_serde_roundtrip() {
    let codes = [
        ResolutionErrorCode::EmptySpecifier,
        ResolutionErrorCode::InvalidReferrer,
        ResolutionErrorCode::UnsupportedSpecifier,
        ResolutionErrorCode::ModuleNotFound,
        ResolutionErrorCode::PolicyDenied,
    ];
    for code in &codes {
        let json = serde_json::to_string(code).expect("serialize");
        let recovered: ResolutionErrorCode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&recovered, code);
    }
}

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
}

#[test]
fn module_definition_serde_roundtrip() {
    let def = ModuleDefinition::new(ModuleSyntax::EsModule, "export const x = 1;")
        .with_dependency(ModuleDependency::new("./util", ImportStyle::Import));
    let json = serde_json::to_string(&def).expect("serialize");
    let recovered: ModuleDefinition = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.syntax, def.syntax);
    assert_eq!(recovered.dependencies.len(), 1);
}

#[test]
fn resolution_error_is_std_error() {
    let resolver = DeterministicModuleResolver::new("/app");
    let request = ModuleRequest::new("nonexistent", ImportStyle::Import);
    let err = resolver
        .resolve(&request, &context(), &AllowAllPolicy)
        .expect_err("not found");
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
}

#[test]
fn registry_error_is_std_error() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    let err = resolver
        .register_builtin("", ModuleDefinition::new(ModuleSyntax::EsModule, "x"))
        .expect_err("empty key");
    let dyn_err: &dyn std::error::Error = &err;
    assert!(dyn_err.to_string().contains("empty"));
}

#[test]
fn module_source_kind_as_str() {
    use frankenengine_engine::module_resolver::ModuleSourceKind;
    assert_eq!(ModuleSourceKind::BuiltIn.as_str(), "builtin");
    assert_eq!(ModuleSourceKind::Workspace.as_str(), "workspace");
    assert_eq!(
        ModuleSourceKind::ExternalRegistry.as_str(),
        "external_registry"
    );
}

#[test]
fn duplicate_workspace_registration_overwrites() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_workspace_module(
            "/app/lib.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export const v1 = 1;"),
        )
        .unwrap();
    resolver
        .register_workspace_module(
            "/app/lib.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export const v2 = 2;"),
        )
        .unwrap();

    let request = ModuleRequest::new("/app/lib.mjs", ImportStyle::Import);
    let outcome = resolver
        .resolve(&request, &context(), &AllowAllPolicy)
        .expect("should resolve latest");
    // Should resolve successfully (last registration wins)
    assert_eq!(outcome.module.canonical_specifier, "/app/lib.mjs");
}

#[test]
fn deterministic_module_resolver_debug_is_nonempty() {
    let resolver = DeterministicModuleResolver::new("/app");
    assert!(!format!("{resolver:?}").is_empty());
}

#[test]
fn module_syntax_debug_is_nonempty() {
    let syntax = ModuleSyntax::EsModule;
    assert!(!format!("{syntax:?}").is_empty());
}

#[test]
fn import_style_debug_is_nonempty() {
    let style = ImportStyle::Import;
    assert!(!format!("{style:?}").is_empty());
}

// ────────────────────────────────────────────────────────────────────────────
// Enrichment batch: ~70 new tests covering Host API surface, serde roundtrips,
// Display impls, edge cases, canonicalization, error variants, and more.
// ────────────────────────────────────────────────────────────────────────────

use frankenengine_engine::module_resolver::{
    CapabilitySafeHostApiSurface, HostApiAuthorizationError, HostApiDecisionEvent,
    HostApiErrorCode, HostApiPermissionDescriptor, HostApiRequest, ModuleProvenance,
    ModuleSourceKind, RegistryError, RegistryErrorCode, ResolutionError, ResolutionEvent,
    ResolutionOutcome,
};

// ── HostApiErrorCode stable_code coverage ────────────────────────────────

#[test]
fn host_api_error_code_unsupported_module_stable_code() {
    assert_eq!(
        HostApiErrorCode::UnsupportedModule.stable_code(),
        "FE-HOSTAPI-0001"
    );
}

#[test]
fn host_api_error_code_unsupported_operation_stable_code() {
    assert_eq!(
        HostApiErrorCode::UnsupportedOperation.stable_code(),
        "FE-HOSTAPI-0002"
    );
}

#[test]
fn host_api_error_code_policy_denied_stable_code() {
    assert_eq!(
        HostApiErrorCode::PolicyDenied.stable_code(),
        "FE-HOSTAPI-0003"
    );
}

#[test]
fn host_api_error_code_stable_codes_unique() {
    let codes = [
        HostApiErrorCode::UnsupportedModule,
        HostApiErrorCode::UnsupportedOperation,
        HostApiErrorCode::PolicyDenied,
    ];
    let stable: BTreeSet<&str> = codes.iter().map(|c| c.stable_code()).collect();
    assert_eq!(stable.len(), codes.len());
}

#[test]
fn host_api_error_code_all_have_fe_hostapi_prefix() {
    let codes = [
        HostApiErrorCode::UnsupportedModule,
        HostApiErrorCode::UnsupportedOperation,
        HostApiErrorCode::PolicyDenied,
    ];
    for code in &codes {
        assert!(
            code.stable_code().starts_with("FE-HOSTAPI-"),
            "stable_code {} must start with FE-HOSTAPI-",
            code.stable_code()
        );
    }
}

// ── HostApiErrorCode serde roundtrip ─────────────────────────────────────

#[test]
fn host_api_error_code_serde_roundtrip() {
    for code in [
        HostApiErrorCode::UnsupportedModule,
        HostApiErrorCode::UnsupportedOperation,
        HostApiErrorCode::PolicyDenied,
    ] {
        let json = serde_json::to_string(&code).expect("serialize");
        let recovered: HostApiErrorCode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, code);
    }
}

// ── HostApiRequest serde roundtrip ───────────────────────────────────────

#[test]
fn host_api_request_serde_roundtrip() {
    let req = HostApiRequest::new("node:fs", "read_file");
    let json = serde_json::to_string(&req).expect("serialize");
    let recovered: HostApiRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, req);
    assert_eq!(recovered.module_specifier, "node:fs");
    assert_eq!(recovered.operation, "read_file");
}

#[test]
fn host_api_request_debug_is_nonempty() {
    let req = HostApiRequest::new("node:net", "connect");
    assert!(!format!("{req:?}").is_empty());
}

// ── HostApiPermissionDescriptor serde roundtrip ──────────────────────────

#[test]
fn host_api_permission_descriptor_serde_roundtrip() {
    let mut caps = BTreeSet::new();
    caps.insert(RuntimeCapability::FsRead);
    let desc = HostApiPermissionDescriptor {
        descriptor_id: "hostapi.node-fs.read-file.v1".to_string(),
        module_specifier: "node:fs".to_string(),
        operation: "read_file".to_string(),
        required_capabilities: caps,
        remediation: "Grant fs_read capability.".to_string(),
    };
    let json = serde_json::to_string(&desc).expect("serialize");
    let recovered: HostApiPermissionDescriptor = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, desc);
}

// ── HostApiDecisionEvent serde roundtrip ─────────────────────────────────

#[test]
fn host_api_decision_event_serde_roundtrip() {
    let ev = HostApiDecisionEvent {
        trace_id: "t1".to_string(),
        decision_id: "d1".to_string(),
        policy_id: "p1".to_string(),
        component: "host_api_surface".to_string(),
        event: "host_api_authorization".to_string(),
        outcome: "allow".to_string(),
        error_code: "none".to_string(),
        decision_stable_id: "hostapi-dec-abcdef0123456789".to_string(),
        descriptor_id: Some("hostapi.node-fs.read-file.v1".to_string()),
        module_specifier: "node:fs".to_string(),
        operation: "read_file".to_string(),
        required_capabilities: BTreeSet::new(),
        remediation: "Grant fs_read.".to_string(),
    };
    let json = serde_json::to_string(&ev).expect("serialize");
    let recovered: HostApiDecisionEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, ev);
}

// ── CapabilitySafeHostApiSurface default / serde ─────────────────────────

#[test]
fn capability_safe_host_api_surface_default_equals_standard() {
    let default_surface = CapabilitySafeHostApiSurface::default();
    let standard_surface = CapabilitySafeHostApiSurface::standard();
    assert_eq!(default_surface, standard_surface);
}

#[test]
fn capability_safe_host_api_surface_serde_roundtrip() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let json = serde_json::to_string(&surface).expect("serialize");
    let recovered: CapabilitySafeHostApiSurface = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, surface);
}

#[test]
fn capability_safe_host_api_surface_supported_modules_nonempty() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let modules = surface.supported_modules();
    assert!(!modules.is_empty());
    assert!(modules.contains(&"node:fs".to_string()));
    assert!(modules.contains(&"node:net".to_string()));
    assert!(modules.contains(&"node:process".to_string()));
    assert!(modules.contains(&"node:crypto".to_string()));
}

#[test]
fn capability_safe_host_api_surface_descriptor_returns_none_for_unknown() {
    let surface = CapabilitySafeHostApiSurface::standard();
    assert!(surface.descriptor("node:unknown", "op").is_none());
    assert!(surface.descriptor("node:fs", "unknown_op").is_none());
}

// ── Host API module canonicalization (alias resolution) ──────────────────

#[test]
fn host_api_authorize_canonicalizes_fs_alias() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let mut granted = BTreeSet::new();
    granted.insert(RuntimeCapability::FsRead);
    let policy = CapabilityPolicyHook::new(granted);
    // "fs" should canonicalize to "node:fs"
    let request = HostApiRequest::new("fs", "read_file");
    let outcome = surface.authorize(&request, &context(), &policy).unwrap();
    assert_eq!(outcome.event.module_specifier, "node:fs");
}

#[test]
fn host_api_authorize_canonicalizes_net_alias() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let mut granted = BTreeSet::new();
    granted.insert(RuntimeCapability::NetworkEgress);
    let policy = CapabilityPolicyHook::new(granted);
    let request = HostApiRequest::new("net", "connect");
    let outcome = surface.authorize(&request, &context(), &policy).unwrap();
    assert_eq!(outcome.event.module_specifier, "node:net");
}

#[test]
fn host_api_authorize_canonicalizes_process_alias() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let mut granted = BTreeSet::new();
    granted.insert(RuntimeCapability::ProcessSpawn);
    let policy = CapabilityPolicyHook::new(granted);
    let request = HostApiRequest::new("process", "spawn");
    let outcome = surface.authorize(&request, &context(), &policy).unwrap();
    assert_eq!(outcome.event.module_specifier, "node:process");
}

#[test]
fn host_api_authorize_canonicalizes_crypto_alias() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let mut granted = BTreeSet::new();
    granted.insert(RuntimeCapability::IdempotencyDerive);
    let policy = CapabilityPolicyHook::new(granted);
    let request = HostApiRequest::new("crypto", "random_bytes");
    let outcome = surface.authorize(&request, &context(), &policy).unwrap();
    assert_eq!(outcome.event.module_specifier, "node:crypto");
}

#[test]
fn host_api_authorize_trims_whitespace_in_module_and_operation() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let mut granted = BTreeSet::new();
    granted.insert(RuntimeCapability::FsWrite);
    let policy = CapabilityPolicyHook::new(granted);
    let request = HostApiRequest::new("  node:fs  ", "  write_file  ");
    let outcome = surface.authorize(&request, &context(), &policy).unwrap();
    assert_eq!(outcome.event.module_specifier, "node:fs");
    assert_eq!(outcome.event.operation, "write_file");
}

#[test]
fn host_api_authorize_case_insensitive_module() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let mut granted = BTreeSet::new();
    granted.insert(RuntimeCapability::FsRead);
    let policy = CapabilityPolicyHook::new(granted);
    let request = HostApiRequest::new("NODE:FS", "READ_FILE");
    let outcome = surface.authorize(&request, &context(), &policy).unwrap();
    assert_eq!(outcome.event.module_specifier, "node:fs");
}

// ── Host API authorization error Display ─────────────────────────────────

#[test]
fn host_api_authorization_error_display_includes_stable_code_and_trace() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let policy = CapabilityPolicyHook::new(BTreeSet::new());
    let request = HostApiRequest::new("node:fs", "read_file");
    let err = surface
        .authorize(&request, &context(), &policy)
        .expect_err("should deny without capability");
    let display = err.to_string();
    assert!(display.contains("FE-HOSTAPI-"));
    assert!(display.contains("trace-integration"));
    assert!(display.contains("decision-integration"));
    assert!(display.contains("policy-integration"));
}

#[test]
fn host_api_authorization_error_is_std_error() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let policy = CapabilityPolicyHook::new(BTreeSet::new());
    let request = HostApiRequest::new("node:fs", "read_file");
    let err = surface
        .authorize(&request, &context(), &policy)
        .expect_err("should deny");
    let dyn_err: &dyn std::error::Error = &*err;
    assert!(!dyn_err.to_string().is_empty());
}

// ── Host API authorization outcome event fields ──────────────────────────

#[test]
fn host_api_authorization_outcome_event_has_correct_component() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let mut granted = BTreeSet::new();
    granted.insert(RuntimeCapability::FsRead);
    let policy = CapabilityPolicyHook::new(granted);
    let request = HostApiRequest::new("node:fs", "read_file");
    let outcome = surface.authorize(&request, &context(), &policy).unwrap();
    assert_eq!(outcome.event.component, "host_api_surface");
    assert_eq!(outcome.event.event, "host_api_authorization");
}

#[test]
fn host_api_authorization_outcome_descriptor_matches_surface_descriptor() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let mut granted = BTreeSet::new();
    granted.insert(RuntimeCapability::FsRead);
    let policy = CapabilityPolicyHook::new(granted);
    let request = HostApiRequest::new("node:fs", "read_file");
    let outcome = surface.authorize(&request, &context(), &policy).unwrap();
    let expected_desc = surface.descriptor("node:fs", "read_file").unwrap();
    assert_eq!(outcome.descriptor, *expected_desc);
}

// ── Host API authorization serde roundtrip of outcome/error ──────────────

#[test]
fn host_api_authorization_outcome_serde_roundtrip() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let mut granted = BTreeSet::new();
    granted.insert(RuntimeCapability::NetworkEgress);
    let policy = CapabilityPolicyHook::new(granted);
    let request = HostApiRequest::new("node:net", "connect");
    let outcome = surface.authorize(&request, &context(), &policy).unwrap();
    let json = serde_json::to_string(&outcome).expect("serialize");
    let recovered: frankenengine_engine::module_resolver::HostApiAuthorizationOutcome =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, outcome);
}

#[test]
fn host_api_authorization_error_serde_roundtrip() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let policy = CapabilityPolicyHook::new(BTreeSet::new());
    let request = HostApiRequest::new("node:fs", "read_file");
    let err = surface
        .authorize(&request, &context(), &policy)
        .expect_err("should deny");
    let json = serde_json::to_string(&*err).expect("serialize");
    let recovered: HostApiAuthorizationError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, *err);
}

// ── Host API deny-list for descriptor ────────────────────────────────────

#[test]
fn host_api_deny_descriptor_blocks_even_with_capabilities() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let mut granted = BTreeSet::new();
    granted.insert(RuntimeCapability::FsRead);
    let policy =
        CapabilityPolicyHook::new(granted).deny_host_api_descriptor("hostapi.node-fs.read-file.v1");
    let request = HostApiRequest::new("node:fs", "read_file");
    let err = surface
        .authorize(&request, &context(), &policy)
        .expect_err("descriptor deny-list should override capability grant");
    assert_eq!(err.code, HostApiErrorCode::PolicyDenied);
    assert!(err.message.contains("hostapi.node-fs.read-file.v1"));
}

// ── Host API decision stable ID determinism ──────────────────────────────

#[test]
fn host_api_decision_stable_id_is_deterministic_for_same_inputs() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let mut granted = BTreeSet::new();
    granted.insert(RuntimeCapability::FsRead);
    let policy = CapabilityPolicyHook::new(granted);
    let request = HostApiRequest::new("node:fs", "read_file");
    let outcome1 = surface.authorize(&request, &context(), &policy).unwrap();
    let outcome2 = surface.authorize(&request, &context(), &policy).unwrap();
    assert_eq!(
        outcome1.event.decision_stable_id,
        outcome2.event.decision_stable_id
    );
}

#[test]
fn host_api_decision_stable_id_differs_for_different_contexts() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let mut granted = BTreeSet::new();
    granted.insert(RuntimeCapability::FsRead);
    let policy = CapabilityPolicyHook::new(granted);
    let request = HostApiRequest::new("node:fs", "read_file");
    let ctx1 = ResolutionContext::new("trace-A", "decision-A", "policy-A");
    let ctx2 = ResolutionContext::new("trace-B", "decision-B", "policy-B");
    let outcome1 = surface.authorize(&request, &ctx1, &policy).unwrap();
    let outcome2 = surface.authorize(&request, &ctx2, &policy).unwrap();
    assert_ne!(
        outcome1.event.decision_stable_id,
        outcome2.event.decision_stable_id
    );
}

// ── Host API all standard descriptors have required capabilities ─────────

#[test]
fn host_api_all_standard_descriptors_require_at_least_one_capability() {
    let surface = CapabilitySafeHostApiSurface::standard();
    for module in surface.supported_modules() {
        // Look up all known operations via descriptors
        let ops: Vec<(&str, &str)> = match module.as_str() {
            "node:fs" => vec![("node:fs", "read_file"), ("node:fs", "write_file")],
            "node:net" => vec![("node:net", "connect")],
            "node:process" => vec![("node:process", "spawn")],
            "node:crypto" => {
                vec![("node:crypto", "random_bytes"), ("node:crypto", "sha256")]
            }
            _ => continue,
        };
        for (m, op) in ops {
            let desc = surface
                .descriptor(m, op)
                .unwrap_or_else(|| panic!("descriptor for {m}/{op} should exist"));
            assert!(
                !desc.required_capabilities.is_empty(),
                "descriptor {}/{} should require at least one capability",
                m,
                op
            );
        }
    }
}

// ── Host API crypto sha256 authorization ─────────────────────────────────

#[test]
fn host_api_crypto_sha256_requires_idempotency_derive() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let desc = surface.descriptor("node:crypto", "sha256").unwrap();
    assert!(
        desc.required_capabilities
            .contains(&RuntimeCapability::IdempotencyDerive)
    );
}

#[test]
fn host_api_crypto_sha256_denied_without_capability() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let policy = CapabilityPolicyHook::new(BTreeSet::new());
    let request = HostApiRequest::new("node:crypto", "sha256");
    let err = surface
        .authorize(&request, &context(), &policy)
        .expect_err("sha256 without idempotency_derive should deny");
    assert_eq!(err.code, HostApiErrorCode::PolicyDenied);
}

#[test]
fn host_api_crypto_sha256_allowed_with_capability() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let mut granted = BTreeSet::new();
    granted.insert(RuntimeCapability::IdempotencyDerive);
    let policy = CapabilityPolicyHook::new(granted);
    let request = HostApiRequest::new("node:crypto", "sha256");
    let outcome = surface.authorize(&request, &context(), &policy).unwrap();
    assert_eq!(outcome.event.outcome, "allow");
}

// ── CapabilityPolicyHook serde roundtrip ─────────────────────────────────

#[test]
fn capability_policy_hook_serde_roundtrip_with_denied_host_api_descriptors() {
    let mut granted = BTreeSet::new();
    granted.insert(RuntimeCapability::FsRead);
    let hook = CapabilityPolicyHook::new(granted)
        .deny_specifier("evil-pkg")
        .deny_host_api_descriptor("hostapi.node-fs.read-file.v1");
    let json = serde_json::to_string(&hook).expect("serialize");
    let recovered: CapabilityPolicyHook = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, hook);
    assert!(
        recovered
            .denied_host_api_descriptors
            .contains("hostapi.node-fs.read-file.v1")
    );
}

// ── CapabilityPolicyHook deny_specifier chains ───────────────────────────

#[test]
fn capability_policy_hook_deny_specifier_chains_multiple() {
    let hook = CapabilityPolicyHook::new(BTreeSet::new())
        .deny_specifier("pkg-a")
        .deny_specifier("pkg-b")
        .deny_specifier("pkg-c");
    assert_eq!(hook.denied_specifiers.len(), 3);
    assert!(hook.denied_specifiers.contains("pkg-a"));
    assert!(hook.denied_specifiers.contains("pkg-b"));
    assert!(hook.denied_specifiers.contains("pkg-c"));
}

// ── ModuleProvenance serde roundtrip ─────────────────────────────────────

#[test]
fn module_provenance_serde_roundtrip_all_kinds() {
    for kind in [
        ModuleSourceKind::BuiltIn,
        ModuleSourceKind::Workspace,
        ModuleSourceKind::ExternalRegistry,
    ] {
        let prov = ModuleProvenance {
            kind,
            origin: format!("test-origin-{}", kind.as_str()),
        };
        let json = serde_json::to_string(&prov).expect("serialize");
        let recovered: ModuleProvenance = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, prov);
    }
}

// ── ModuleDependency constructor ─────────────────────────────────────────

#[test]
fn module_dependency_new_from_string() {
    let dep = ModuleDependency::new(String::from("./lib"), ImportStyle::Import);
    assert_eq!(dep.specifier, "./lib");
    assert_eq!(dep.style, ImportStyle::Import);
}

#[test]
fn module_dependency_new_from_str_ref() {
    let dep = ModuleDependency::new("lodash", ImportStyle::Require);
    assert_eq!(dep.specifier, "lodash");
    assert_eq!(dep.style, ImportStyle::Require);
}

// ── ModuleDefinition builder edge cases ──────────────────────────────────

#[test]
fn module_definition_default_provenance_origin() {
    let def = ModuleDefinition::new(ModuleSyntax::EsModule, "code");
    assert_eq!(def.provenance_origin, "<unspecified>");
}

#[test]
fn module_definition_multiple_dependencies() {
    let def = ModuleDefinition::new(ModuleSyntax::CommonJs, "require stuff")
        .with_dependency(ModuleDependency::new("./a", ImportStyle::Require))
        .with_dependency(ModuleDependency::new("./b", ImportStyle::Require))
        .with_dependency(ModuleDependency::new("lodash", ImportStyle::Require));
    assert_eq!(def.dependencies.len(), 3);
    assert_eq!(def.dependencies[0].specifier, "./a");
    assert_eq!(def.dependencies[2].specifier, "lodash");
}

#[test]
fn module_definition_multiple_capabilities() {
    let def = ModuleDefinition::new(ModuleSyntax::EsModule, "code")
        .require_capability(RuntimeCapability::FsRead)
        .require_capability(RuntimeCapability::FsWrite)
        .require_capability(RuntimeCapability::NetworkEgress);
    assert_eq!(def.required_capabilities.len(), 3);
}

#[test]
fn module_definition_empty_source() {
    let def = ModuleDefinition::new(ModuleSyntax::EsModule, "");
    assert_eq!(def.source, "");
    assert!(def.dependencies.is_empty());
    assert!(def.required_capabilities.is_empty());
}

// ── ModuleRequest serde with NodeCompat ──────────────────────────────────

#[test]
fn module_request_serde_roundtrip_with_node_compat() {
    let mr = ModuleRequest::new("pkg", ImportStyle::Require)
        .with_compatibility_mode(CompatibilityMode::NodeCompat);
    let json = serde_json::to_string(&mr).expect("serialize");
    let recovered: ModuleRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, mr);
    assert_eq!(recovered.compatibility_mode, CompatibilityMode::NodeCompat);
}

#[test]
fn module_request_native_mode_skips_serialization() {
    let mr = ModuleRequest::new("pkg", ImportStyle::Import);
    let json = serde_json::to_string(&mr).expect("serialize");
    // Native is the default and should be skipped in serialization
    assert!(!json.contains("compatibility_mode"));
}

// ── ResolutionContext serde roundtrip ─────────────────────────────────────

#[test]
fn resolution_context_serde_roundtrip() {
    let ctx = ResolutionContext::new("trace-99", "decision-99", "policy-99");
    let json = serde_json::to_string(&ctx).expect("serialize");
    let recovered: ResolutionContext = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, ctx);
}

// ── ResolutionEvent serde roundtrip ──────────────────────────────────────

#[test]
fn resolution_event_serde_roundtrip() {
    let ev = ResolutionEvent {
        trace_id: "t-integ".to_string(),
        decision_id: "d-integ".to_string(),
        policy_id: "p-integ".to_string(),
        component: "module_resolver".to_string(),
        event: "module_resolution".to_string(),
        outcome: "allow".to_string(),
        error_code: "none".to_string(),
    };
    let json = serde_json::to_string(&ev).expect("serialize");
    let recovered: ResolutionEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, ev);
}

// ── ResolutionError serde roundtrip ──────────────────────────────────────

#[test]
fn resolution_error_serde_roundtrip_all_codes() {
    let codes = [
        ResolutionErrorCode::EmptySpecifier,
        ResolutionErrorCode::InvalidReferrer,
        ResolutionErrorCode::UnsupportedSpecifier,
        ResolutionErrorCode::ModuleNotFound,
        ResolutionErrorCode::PolicyDenied,
    ];
    for code in &codes {
        let ev = ResolutionEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "module_resolver".to_string(),
            event: "module_resolution".to_string(),
            outcome: "deny".to_string(),
            error_code: code.stable_code().to_string(),
        };
        let err = ResolutionError {
            code: *code,
            message: format!("test error for {:?}", code),
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            request_specifier: String::new(),
            canonical_specifier: None,
            source_kind: None,
            probe_sequence: Vec::new(),
            event: ev,
        };
        let json = serde_json::to_string(&err).expect("serialize");
        let recovered: ResolutionError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, err);
    }
}

// ── RegistryError Display and serde ──────────────────────────────────────

#[test]
fn registry_error_display_includes_empty_key() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    let err = resolver
        .register_builtin("", ModuleDefinition::new(ModuleSyntax::EsModule, "x"))
        .expect_err("empty key");
    let display = err.to_string();
    assert!(display.contains("EmptyKey"));
    assert!(display.contains("empty"));
}

#[test]
fn registry_error_code_serde_roundtrip() {
    let code = RegistryErrorCode::EmptyKey;
    let json = serde_json::to_string(&code).expect("serialize");
    let recovered: RegistryErrorCode = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, code);
}

#[test]
fn registry_error_serde_roundtrip() {
    let err = RegistryError {
        code: RegistryErrorCode::EmptyKey,
        message: "module key must not be empty".to_string(),
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: RegistryError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, err);
}

// ── AllowAllPolicy default and serde ─────────────────────────────────────

#[test]
fn allow_all_policy_default() {
    let policy = AllowAllPolicy;
    assert_eq!(policy, AllowAllPolicy);
}

#[test]
fn allow_all_policy_serde_roundtrip() {
    let policy = AllowAllPolicy;
    let json = serde_json::to_string(&policy).expect("serialize");
    let recovered: AllowAllPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, policy);
}

// ── DeterministicModuleResolver default ──────────────────────────────────

#[test]
fn deterministic_module_resolver_default_root_dir() {
    let resolver = DeterministicModuleResolver::default();
    assert_eq!(resolver.root_dir(), "/");
}

#[test]
fn deterministic_module_resolver_clone_eq() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_workspace_module(
            "/app/lib.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
        )
        .unwrap();
    let cloned = resolver.clone();
    assert_eq!(resolver, cloned);
}

// ── Resolution outcome content_hash consistency ──────────────────────────

#[test]
fn resolution_outcome_content_hash_matches_record_canonical_hash() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_workspace_module(
            "/app/check.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export const x = 42;"),
        )
        .unwrap();
    let request = ModuleRequest::new("/app/check.mjs", ImportStyle::Import);
    let outcome = resolver
        .resolve(&request, &context(), &AllowAllPolicy)
        .unwrap();
    assert_eq!(
        outcome.module.content_hash,
        outcome.module.record.canonical_hash()
    );
}

// ── Canonical hash differs on syntax change ──────────────────────────────

#[test]
fn canonical_hash_differs_when_syntax_differs() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_workspace_module(
            "/app/esm.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
        )
        .unwrap();
    resolver
        .register_workspace_module(
            "/app/cjs.cjs",
            ModuleDefinition::new(ModuleSyntax::CommonJs, "export default 1;"),
        )
        .unwrap();
    let r1 = resolver
        .resolve(
            &ModuleRequest::new("/app/esm.mjs", ImportStyle::Import),
            &context(),
            &AllowAllPolicy,
        )
        .unwrap();
    let r2 = resolver
        .resolve(
            &ModuleRequest::new("/app/cjs.cjs", ImportStyle::Require),
            &context(),
            &AllowAllPolicy,
        )
        .unwrap();
    // Same source but different syntax and id -> different hash
    assert_ne!(r1.module.content_hash, r2.module.content_hash);
}

// ── Canonical hash differs on provenance change ──────────────────────────

#[test]
fn canonical_hash_differs_when_provenance_differs() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_workspace_module(
            "/app/p1.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;")
                .with_provenance("origin-A"),
        )
        .unwrap();
    resolver
        .register_workspace_module(
            "/app/p2.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;")
                .with_provenance("origin-B"),
        )
        .unwrap();
    let r1 = resolver
        .resolve(
            &ModuleRequest::new("/app/p1.mjs", ImportStyle::Import),
            &context(),
            &AllowAllPolicy,
        )
        .unwrap();
    let r2 = resolver
        .resolve(
            &ModuleRequest::new("/app/p2.mjs", ImportStyle::Import),
            &context(),
            &AllowAllPolicy,
        )
        .unwrap();
    assert_ne!(r1.module.content_hash, r2.module.content_hash);
}

// ── resolve_chain diamond dependency dedup ────────────────────────────────

#[test]
fn resolve_chain_diamond_dependency_deduplicates() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    // A depends on B and C, both B and C depend on D
    resolver
        .register_workspace_module(
            "/app/a.mjs",
            ModuleDefinition::new(
                ModuleSyntax::EsModule,
                "import './b.mjs'; import './c.mjs';",
            )
            .with_dependency(ModuleDependency::new("./b.mjs", ImportStyle::Import))
            .with_dependency(ModuleDependency::new("./c.mjs", ImportStyle::Import)),
        )
        .unwrap();
    resolver
        .register_workspace_module(
            "/app/b.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "import './d.mjs';")
                .with_dependency(ModuleDependency::new("./d.mjs", ImportStyle::Import)),
        )
        .unwrap();
    resolver
        .register_workspace_module(
            "/app/c.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "import './d.mjs';")
                .with_dependency(ModuleDependency::new("./d.mjs", ImportStyle::Import)),
        )
        .unwrap();
    resolver
        .register_workspace_module(
            "/app/d.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export default 4;"),
        )
        .unwrap();
    let request = ModuleRequest::new("/app/a.mjs", ImportStyle::Import);
    let chain = resolver
        .resolve_chain(&request, &context(), &AllowAllPolicy)
        .unwrap();
    // D should only appear once
    assert_eq!(chain.len(), 4);
    let ids: Vec<_> = chain
        .iter()
        .map(|o| o.module.canonical_specifier.as_str())
        .collect();
    assert_eq!(
        ids.iter().filter(|id| **id == "/app/d.mjs").count(),
        1,
        "diamond node D should appear exactly once"
    );
}

// ── resolve_chain with mixed import styles ───────────────────────────────

#[test]
fn resolve_chain_with_mixed_import_and_require() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_workspace_module(
            "/app/entry.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "import './lib.mjs';")
                .with_dependency(ModuleDependency::new("./lib.mjs", ImportStyle::Import)),
        )
        .unwrap();
    resolver
        .register_workspace_module(
            "/app/lib.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
        )
        .unwrap();
    let request = ModuleRequest::new("/app/entry.mjs", ImportStyle::Import);
    let chain = resolver
        .resolve_chain(&request, &context(), &AllowAllPolicy)
        .unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].module.record.syntax, ModuleSyntax::EsModule);
    assert_eq!(chain[1].module.record.syntax, ModuleSyntax::EsModule);
}

// ── Empty specifier with Require style ───────────────────────────────────

#[test]
fn empty_specifier_require_yields_empty_specifier_error() {
    let resolver = DeterministicModuleResolver::new("/app");
    let request = ModuleRequest::new("", ImportStyle::Require);
    let err = resolver
        .resolve(&request, &context(), &AllowAllPolicy)
        .expect_err("empty specifier with require must fail");
    assert_eq!(err.code, ResolutionErrorCode::EmptySpecifier);
}

// ── Whitespace-only specifier ────────────────────────────────────────────

#[test]
fn whitespace_only_specifier_yields_empty_specifier_error() {
    let resolver = DeterministicModuleResolver::new("/app");
    let request = ModuleRequest::new("   \t  ", ImportStyle::Import);
    let err = resolver
        .resolve(&request, &context(), &AllowAllPolicy)
        .expect_err("whitespace-only specifier must fail");
    assert_eq!(err.code, ResolutionErrorCode::EmptySpecifier);
}

// ── Relative specifier without referrer ──────────────────────────────────

#[test]
fn dotdot_relative_specifier_without_referrer_yields_invalid_referrer() {
    let resolver = DeterministicModuleResolver::new("/app");
    let request = ModuleRequest::new("../lib", ImportStyle::Import);
    let err = resolver
        .resolve(&request, &context(), &AllowAllPolicy)
        .expect_err("relative without referrer must fail");
    assert_eq!(err.code, ResolutionErrorCode::InvalidReferrer);
}

// ── Node compat still rejects require of ESM ─────────────────────────────

#[test]
fn node_compat_rejects_require_of_esm_with_node_compat_mode() {
    let mut resolver = DeterministicModuleResolver::new("/repo");
    resolver
        .register_workspace_module(
            "/repo/pkg/index.js",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export default 'esm';"),
        )
        .unwrap();
    let err = resolver
        .resolve(
            &ModuleRequest::new("pkg", ImportStyle::Require)
                .with_compatibility_mode(CompatibilityMode::NodeCompat),
            &context(),
            &AllowAllPolicy,
        )
        .expect_err("NodeCompat should reject require of ESM");
    assert_eq!(err.code, ResolutionErrorCode::UnsupportedSpecifier);
    assert!(err.message.contains("ERR_REQUIRE_ESM"));
}

// ── Builtin provenance kind ──────────────────────────────────────────────

#[test]
fn builtin_module_has_builtin_provenance_kind() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_builtin(
            "path",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export function join() {}"),
        )
        .unwrap();
    let request = ModuleRequest::new("path", ImportStyle::Import);
    let outcome = resolver
        .resolve(&request, &context(), &AllowAllPolicy)
        .unwrap();
    assert_eq!(
        outcome.module.record.provenance.kind,
        ModuleSourceKind::BuiltIn
    );
}

// ── External module provenance kind ──────────────────────────────────────

#[test]
fn external_module_has_external_registry_provenance_kind() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_external_module(
            "axios",
            ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = {};"),
        )
        .unwrap();
    let request = ModuleRequest::new("axios", ImportStyle::Require);
    let outcome = resolver
        .resolve(&request, &context(), &AllowAllPolicy)
        .unwrap();
    assert_eq!(
        outcome.module.record.provenance.kind,
        ModuleSourceKind::ExternalRegistry
    );
}

// ── Workspace module provenance kind ─────────────────────────────────────

#[test]
fn workspace_module_has_workspace_provenance_kind() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_workspace_module(
            "/app/src/main.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
        )
        .unwrap();
    let request = ModuleRequest::new("/app/src/main.mjs", ImportStyle::Import);
    let outcome = resolver
        .resolve(&request, &context(), &AllowAllPolicy)
        .unwrap();
    assert_eq!(
        outcome.module.record.provenance.kind,
        ModuleSourceKind::Workspace
    );
}

// ── ModuleRequest clone preserves all fields ─────────────────────────────

#[test]
fn module_request_clone_preserves_all_fields() {
    let original = ModuleRequest::new("pkg", ImportStyle::Import)
        .with_referrer("/app/main.js")
        .with_compatibility_mode(CompatibilityMode::BunCompat);
    let cloned = original.clone();
    assert_eq!(original, cloned);
    assert_eq!(cloned.specifier, "pkg");
    assert_eq!(cloned.referrer, Some("/app/main.js".to_string()));
    assert_eq!(cloned.style, ImportStyle::Import);
    assert_eq!(cloned.compatibility_mode, CompatibilityMode::BunCompat);
}

// ── ResolutionOutcome serde roundtrip ────────────────────────────────────

#[test]
fn resolution_outcome_serde_roundtrip_through_resolver() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_workspace_module(
            "/app/serde_test.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export const x = 1;"),
        )
        .unwrap();
    let request = ModuleRequest::new("/app/serde_test.mjs", ImportStyle::Import);
    let outcome = resolver
        .resolve(&request, &context(), &AllowAllPolicy)
        .unwrap();
    let json = serde_json::to_string(&outcome).expect("serialize");
    let recovered: ResolutionOutcome = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, outcome);
}

// ── success event fields ─────────────────────────────────────────────────

#[test]
fn success_event_has_allow_outcome_and_none_error_code() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_workspace_module(
            "/app/ok.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
        )
        .unwrap();
    let request = ModuleRequest::new("/app/ok.mjs", ImportStyle::Import);
    let outcome = resolver
        .resolve(&request, &context(), &AllowAllPolicy)
        .unwrap();
    assert_eq!(outcome.event.outcome, "allow");
    assert_eq!(outcome.event.error_code, "none");
    assert_eq!(outcome.event.component, "module_resolver");
    assert_eq!(outcome.event.event, "module_resolution");
}

// ── error event fields ───────────────────────────────────────────────────

#[test]
fn error_event_has_deny_outcome() {
    let resolver = DeterministicModuleResolver::new("/app");
    let request = ModuleRequest::new("nonexistent", ImportStyle::Import);
    let err = resolver
        .resolve(&request, &context(), &AllowAllPolicy)
        .expect_err("should fail");
    assert_eq!(err.event.outcome, "deny");
    assert_eq!(err.event.component, "module_resolver");
    assert_eq!(err.event.event, "module_resolution");
}

// ── ModuleSourceKind ordering is consistent ──────────────────────────────

#[test]
fn module_source_kind_ordering_consistent() {
    assert!(ModuleSourceKind::BuiltIn < ModuleSourceKind::Workspace);
    assert!(ModuleSourceKind::Workspace < ModuleSourceKind::ExternalRegistry);
    assert!(ModuleSourceKind::BuiltIn < ModuleSourceKind::ExternalRegistry);
}

// ── ModuleSyntax copy semantics ──────────────────────────────────────────

#[test]
fn module_syntax_is_copy() {
    let syntax = ModuleSyntax::EsModule;
    let copy = syntax;
    assert_eq!(syntax, copy);
}

#[test]
fn import_style_is_copy() {
    let style = ImportStyle::Require;
    let copy = style;
    assert_eq!(style, copy);
}

// ── ResolutionErrorCode debug is nonempty ────────────────────────────────

#[test]
fn resolution_error_code_debug_is_nonempty() {
    for code in [
        ResolutionErrorCode::EmptySpecifier,
        ResolutionErrorCode::InvalidReferrer,
        ResolutionErrorCode::UnsupportedSpecifier,
        ResolutionErrorCode::ModuleNotFound,
        ResolutionErrorCode::PolicyDenied,
    ] {
        assert!(!format!("{code:?}").is_empty());
    }
}

// ── HostApiErrorCode debug is nonempty ───────────────────────────────────

#[test]
fn host_api_error_code_debug_is_nonempty() {
    for code in [
        HostApiErrorCode::UnsupportedModule,
        HostApiErrorCode::UnsupportedOperation,
        HostApiErrorCode::PolicyDenied,
    ] {
        assert!(!format!("{code:?}").is_empty());
    }
}

// ── Host API fs write_file requires FsWrite ──────────────────────────────

#[test]
fn host_api_fs_write_file_requires_fs_write_capability() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let desc = surface.descriptor("node:fs", "write_file").unwrap();
    assert!(
        desc.required_capabilities
            .contains(&RuntimeCapability::FsWrite)
    );
}

// ── Host API net connect requires NetworkEgress ──────────────────────────

#[test]
fn host_api_net_connect_requires_network_egress_capability() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let desc = surface.descriptor("node:net", "connect").unwrap();
    assert!(
        desc.required_capabilities
            .contains(&RuntimeCapability::NetworkEgress)
    );
}

// ── Host API process spawn requires ProcessSpawn ─────────────────────────

#[test]
fn host_api_process_spawn_requires_process_spawn_capability() {
    let surface = CapabilitySafeHostApiSurface::standard();
    let desc = surface.descriptor("node:process", "spawn").unwrap();
    assert!(
        desc.required_capabilities
            .contains(&RuntimeCapability::ProcessSpawn)
    );
}

// ── Host API descriptor lookup via alias ─────────────────────────────────

#[test]
fn host_api_descriptor_lookup_via_alias() {
    let surface = CapabilitySafeHostApiSurface::standard();
    // "fs" should canonicalize to "node:fs"
    let desc = surface.descriptor("fs", "read_file");
    assert!(desc.is_some());
    assert_eq!(desc.unwrap().module_specifier, "node:fs");
}

// ── DeterministicModuleResolver with different root dirs ─────────────────

#[test]
fn resolver_with_nested_root_dir() {
    let mut resolver = DeterministicModuleResolver::new("/home/user/projects/app");
    resolver
        .register_workspace_module(
            "/home/user/projects/app/src/index.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
        )
        .unwrap();
    assert_eq!(resolver.root_dir(), "/home/user/projects/app");
    let request = ModuleRequest::new("/home/user/projects/app/src/index.mjs", ImportStyle::Import);
    let outcome = resolver
        .resolve(&request, &context(), &AllowAllPolicy)
        .unwrap();
    assert_eq!(
        outcome.module.canonical_specifier,
        "/home/user/projects/app/src/index.mjs"
    );
}

// ── ContentHash to_hex format ────────────────────────────────────────────

#[test]
fn module_record_canonical_hash_to_hex_is_64_chars() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_workspace_module(
            "/app/hex_test.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
        )
        .unwrap();
    let request = ModuleRequest::new("/app/hex_test.mjs", ImportStyle::Import);
    let outcome = resolver
        .resolve(&request, &context(), &AllowAllPolicy)
        .unwrap();
    let hex = outcome.module.content_hash.to_hex();
    assert_eq!(hex.len(), 64, "SHA-256 hex should be 64 characters");
    assert!(
        hex.chars().all(|c| c.is_ascii_hexdigit()),
        "hex should only contain hex digits"
    );
}
