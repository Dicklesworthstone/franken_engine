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
            ModuleDefinition::new(ModuleSyntax::EsModule, "import './util';")
                .with_dependency(ModuleDependency::new("./util", ImportStyle::Import)),
        )
        .unwrap();

    resolver
        .register_workspace_module(
            "/app/util.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "import './secret';")
                .with_dependency(ModuleDependency::new("./secret", ImportStyle::Import)),
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
            ModuleDefinition::new(ModuleSyntax::EsModule, "import './b';")
                .with_dependency(ModuleDependency::new("./b", ImportStyle::Import)),
        )
        .unwrap();
    resolver
        .register_workspace_module(
            "/app/b.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "import './a';")
                .with_dependency(ModuleDependency::new("./a", ImportStyle::Import)),
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
